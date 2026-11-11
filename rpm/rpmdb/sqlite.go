package rpmdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"modernc.org/sqlite" // CGO-free SQLite driver; linked by this package only.
)

// SQLiteMode selects how [Open] gets at a SQLite database.
type SQLiteMode int

// The ways of opening a SQLite database.
const (
	// SQLiteAuto opens the file in place, read-only. When SQLite cannot do
	// that because the directory is not writable and holds no write-ahead log
	// index (the usual state of a database on read-only media, of an image
	// layer, or of a root's database read by an unprivileged user), it falls
	// back: to [SQLiteImmutable] when no log is pending, and to
	// [SQLiteSnapshot] when a write-ahead log or a rollback journal holds
	// transactions that a read has to see. It never creates a file next to a
	// database it could not otherwise open.
	SQLiteAuto SQLiteMode = iota
	// SQLiteInPlace opens the file in place and fails when SQLite cannot, as
	// SQLite would. A read-only connection of a write-ahead log database
	// still needs to create or to write its shared-memory index, "-shm", next
	// to the file.
	SQLiteInPlace
	// SQLiteImmutable opens the file with immutable=1: SQLite takes no lock,
	// writes nothing next to the file and ignores any "-wal" or "-journal".
	// Use it for media or a snapshot that nothing writes. On a live database
	// it can miss what rpm has not checkpointed yet, or read a torn state.
	SQLiteImmutable
	// SQLiteSnapshot copies the database with its "-wal" and "-journal" into a
	// private temporary directory and opens the copy, which SQLite recovers
	// as it would the original. The original is only read, and no file is
	// created next to it. The copy is removed on [DB.Close]. See
	// [Options.TempDir] and [Options.MaxSnapshotBytes].
	SQLiteSnapshot
)

// String returns "auto", "in-place", "immutable" or "snapshot".
func (m SQLiteMode) String() string {
	switch m {
	case SQLiteAuto:
		return "auto"
	case SQLiteInPlace:
		return "in-place"
	case SQLiteImmutable:
		return "immutable"
	case SQLiteSnapshot:
		return "snapshot"
	default:
		return "unknown"
	}
}

// Defaults of the SQLite options.
const (
	// DefaultBusyTimeout is how long a read waits for a writer that holds the
	// database, such as rpm in the middle of an exclusive transaction.
	DefaultBusyTimeout = 5 * time.Second
	// DefaultLockRetries is how many times a read is repeated after SQLite
	// reports the database locked despite the busy timeout.
	DefaultLockRetries = 2
	// DefaultMaxSnapshotBytes bounds the files copied by [SQLiteSnapshot].
	DefaultMaxSnapshotBytes = 1 << 30

	lockRetryDelay = 25 * time.Millisecond
	maxLockDelay   = time.Second
)

// SQLite result codes, the primary ones, that the opening logic looks at.
const (
	sqliteBusy     = 5
	sqliteLocked   = 6
	sqliteReadonly = 8
	sqliteIOErr    = 10
	sqliteCantOpen = 14
	sqliteCodeMask = 0xff
)

// sqliteStore reads rpmdb.sqlite. The database has one table of interest,
// Packages(hnum INTEGER PRIMARY KEY, blob BLOB): the header image of each
// package under its record number. The other tables are indexes of it.
type sqliteStore struct {
	db      *sql.DB
	maxBlob int
	retries int
	log     *slog.Logger
	// dir is the private directory of a snapshot, removed on close.
	dir string
}

// sqliteCode returns the primary SQLite result code of err, 0 for an error
// that is not SQLite's.
func sqliteCode(err error) int {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code() & sqliteCodeMask
	}

	return 0
}

// isLocked reports whether err says the database is busy or locked.
func isLocked(err error) bool {
	c := sqliteCode(err)

	return c == sqliteBusy || c == sqliteLocked
}

// needsFallback reports whether SQLite could not open the database in place
// for a reason a read-only fallback may get around: the shared-memory index
// or the log cannot be created or written, or a hot journal cannot be rolled
// back.
func needsFallback(err error) bool {
	switch sqliteCode(err) {
	case sqliteCantOpen, sqliteReadonly, sqliteIOErr:
		return true
	default:
		return false
	}
}

// wrapSQLite classifies a SQLite error: busy and locked ones match
// [ErrLocked], the others pass through.
func wrapSQLite(err error) error {
	if isLocked(err) {
		return fmt.Errorf("%w: %w", ErrLocked, err)
	}

	return err
}

// dsn builds the connection string of the file at abs.
func dsn(abs string, immutable bool, busy time.Duration) string {
	u := url.URL{Scheme: "file", Path: abs}
	s := u.String() + "?mode=ro"

	if immutable {
		s += "&immutable=1"
	}

	return s + fmt.Sprintf("&_pragma=busy_timeout(%d)&_pragma=query_only(1)", busy.Milliseconds())
}

func openSQLite(path string, opts Options) (*sqliteStore, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	switch opts.SQLite {
	case SQLiteAuto:
		st, err := dialSQLite(abs, false, opts)
		if err == nil || !needsFallback(err) {
			return st, err
		}

		if pendingLog(abs) {
			opts.Logger.Debug("rpmdb: sqlite cannot be opened in place with a log pending, reading a snapshot", "error", err)

			return snapshotSQLite(abs, opts)
		}

		opts.Logger.Debug("rpmdb: sqlite cannot be opened in place, reading it as immutable", "error", err)

		return dialSQLite(abs, true, opts)
	case SQLiteInPlace:
		return dialSQLite(abs, false, opts)
	case SQLiteImmutable:
		return dialSQLite(abs, true, opts)
	case SQLiteSnapshot:
		return snapshotSQLite(abs, opts)
	default:
		return nil, fmt.Errorf("rpmdb: unknown SQLite mode %d", int(opts.SQLite))
	}
}

// sidecars are the files SQLite keeps next to a database that can hold
// transactions not yet in the main file.
var sidecars = [...]string{"-wal", "-journal"}

// pendingLog reports whether a write-ahead log or a rollback journal next to
// the database at abs is not empty, so that an immutable read could miss
// committed transactions.
func pendingLog(abs string) bool {
	for _, suffix := range sidecars {
		if fi, err := os.Stat(abs + suffix); err == nil && fi.Size() > 0 {
			return true
		}
	}

	return false
}

// dialSQLite opens the database at abs and checks that it holds rpm's table,
// retrying while it is locked.
func dialSQLite(abs string, immutable bool, opts Options) (*sqliteStore, error) {
	db, err := sql.Open("sqlite", dsn(abs, immutable, opts.BusyTimeout))
	if err != nil {
		return nil, err
	}

	st := &sqliteStore{db: db, maxBlob: opts.MaxBlobBytes, retries: opts.LockRetries, log: opts.Logger}

	// Fail now, and say so in the package's terms, when the file is not an rpm
	// database.
	err = st.retry(context.Background(), func() error {
		var probe int

		return db.QueryRowContext(context.Background(),
			"SELECT count(*) FROM (SELECT hnum FROM Packages LIMIT 1)").Scan(&probe)
	})
	if err != nil {
		_ = db.Close()

		if isLocked(err) || needsFallback(err) {
			return nil, wrapSQLite(err)
		}

		return nil, fmt.Errorf("%w: sqlite: %w", ErrCorrupt, err)
	}

	return st, nil
}

// retry runs op, repeating it up to the configured number of times, with a
// growing pause, while it fails because the database is locked.
func (s *sqliteStore) retry(ctx context.Context, op func() error) error {
	delay := lockRetryDelay

	for attempt := 0; ; attempt++ {
		err := op()
		if err == nil || !isLocked(err) || attempt >= s.retries {
			return err
		}

		s.log.Debug("rpmdb: sqlite is locked, retrying", "attempt", attempt+1, "error", err)

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()

			return ctx.Err()
		case <-timer.C:
		}

		delay = min(delay*2, maxLockDelay)
	}
}

func (s *sqliteStore) close() error {
	err := s.db.Close()

	if s.dir != "" {
		if rerr := os.RemoveAll(s.dir); err == nil {
			err = rerr
		}
	}

	return err
}

// snapshotSQLite copies the database at abs, with its log and journal, into a
// private directory and opens the copy.
func snapshotSQLite(abs string, opts Options) (*sqliteStore, error) {
	var lastErr error

	// A writer that changes the files while they are copied makes a torn
	// copy; the copy is repeated while the sizes and times move.
	for attempt := 0; attempt <= opts.LockRetries; attempt++ {
		st, err := copySnapshot(abs, opts)
		if err == nil || !errors.Is(err, ErrLocked) {
			return st, err
		}

		lastErr = err
	}

	return nil, lastErr
}

func copySnapshot(abs string, opts Options) (_ *sqliteStore, err error) {
	files := []string{abs}

	for _, suffix := range sidecars {
		if fi, serr := os.Stat(abs + suffix); serr == nil && fi.Size() > 0 {
			files = append(files, abs+suffix)
		}
	}

	var (
		total int64
		infos = make([]os.FileInfo, len(files))
	)

	for i, f := range files {
		fi, serr := os.Stat(f)
		if serr != nil {
			return nil, fmt.Errorf("rpmdb: %w", serr)
		}

		infos[i] = fi
		total += fi.Size()
	}

	if total > opts.MaxSnapshotBytes {
		return nil, fmt.Errorf("%w: a snapshot of %d bytes exceeds Options.MaxSnapshotBytes (%d)", ErrTooLarge, total, opts.MaxSnapshotBytes)
	}

	dir, err := os.MkdirTemp(opts.TempDir, "rpmdb-snapshot-")
	if err != nil {
		return nil, fmt.Errorf("rpmdb: %w", err)
	}

	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()

	target := filepath.Join(dir, filepath.Base(abs))

	for i, f := range files {
		suffix := f[len(abs):]
		if err := copyFile(f, target+suffix, infos[i].Size()); err != nil {
			return nil, err
		}
	}

	// Anything that moved while it was copied makes the copy torn.
	for i, f := range files {
		if fi, serr := os.Stat(f); serr != nil || fi.Size() != infos[i].Size() || !fi.ModTime().Equal(infos[i].ModTime()) {
			return nil, fmt.Errorf("%w: %s changed while it was copied", ErrLocked, f)
		}
	}

	st, err := dialSQLite(target, false, opts)
	if err != nil {
		return nil, err
	}

	st.dir = dir

	return st, nil
}

// copyFile copies n bytes of src to a new file dst.
func copyFile(src, dst string, n int64) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("rpmdb: %w", err)
	}

	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("rpmdb: %w", err)
	}

	if _, err := io.Copy(out, io.LimitReader(in, n)); err != nil {
		_ = out.Close()

		return fmt.Errorf("rpmdb: copying %s: %w", src, err)
	}

	if err := out.Close(); err != nil {
		return fmt.Errorf("rpmdb: %w", err)
	}

	return nil
}

func (s *sqliteStore) blobs(ctx context.Context) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		// A record over the limit reads as NULL: SQLite does not hand over its
		// bytes.
		var rows *sql.Rows

		err := s.retry(ctx, func() (err error) {
			rows, err = s.db.QueryContext(ctx,
				"SELECT hnum, CASE WHEN length(blob) <= ? THEN blob END FROM Packages ORDER BY hnum", s.maxBlob)

			return err
		})
		if err != nil {
			yield(nil, fmt.Errorf("rpmdb: reading sqlite: %w", wrapSQLite(err)))

			return
		}

		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var (
				hnum int64
				blob sql.RawBytes
			)

			if err := rows.Scan(&hnum, &blob); err != nil {
				yield(nil, fmt.Errorf("rpmdb: reading sqlite: %w", wrapSQLite(err)))

				return
			}

			if blob == nil {
				s.log.Debug("rpmdb: skipping an oversized or empty record", "hnum", hnum)

				continue
			}

			if !yield(blob, nil) {
				return
			}
		}

		if err := rows.Err(); err != nil {
			yield(nil, fmt.Errorf("rpmdb: reading sqlite: %w", wrapSQLite(err)))
		}
	}
}
