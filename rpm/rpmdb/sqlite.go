package rpmdb

import (
	"context"
	"database/sql"
	"fmt"
	"iter"
	"log/slog"
	"net/url"
	"path/filepath"

	_ "modernc.org/sqlite" // CGO-free SQLite driver; linked by this package only.
)

// sqliteStore reads rpmdb.sqlite. The database has one table of interest,
// Packages(hnum INTEGER PRIMARY KEY, blob BLOB): the header image of each
// package under its record number. The other tables are indexes of it.
type sqliteStore struct {
	db      *sql.DB
	maxBlob int
	log     *slog.Logger
}

// busyTimeoutMillis is how long a read waits for a writer that holds the
// database, such as rpm in the middle of a transaction.
const busyTimeoutMillis = 5000

func openSQLite(path string, opts Options) (*sqliteStore, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	u := url.URL{Scheme: "file", Path: abs}
	dsn := u.String() + "?mode=ro"

	if opts.Immutable {
		dsn += "&immutable=1"
	}

	dsn += fmt.Sprintf("&_pragma=busy_timeout(%d)&_pragma=query_only(1)", busyTimeoutMillis)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	// Fail now, and say so in the package's terms, when the file is not an rpm
	// database.
	var probe int
	if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM (SELECT hnum FROM Packages LIMIT 1)").Scan(&probe); err != nil {
		_ = db.Close()

		return nil, fmt.Errorf("%w: sqlite: %w", ErrCorrupt, err)
	}

	return &sqliteStore{db: db, maxBlob: opts.MaxBlobBytes, log: opts.Logger}, nil
}

func (s *sqliteStore) close() error { return s.db.Close() }

func (s *sqliteStore) blobs(ctx context.Context) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		// A record over the limit reads as NULL: SQLite does not hand over its
		// bytes.
		rows, err := s.db.QueryContext(ctx,
			"SELECT hnum, CASE WHEN length(blob) <= ? THEN blob END FROM Packages ORDER BY hnum", s.maxBlob)
		if err != nil {
			yield(nil, fmt.Errorf("rpmdb: reading sqlite: %w", err))

			return
		}

		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var (
				hnum int64
				blob sql.RawBytes
			)

			if err := rows.Scan(&hnum, &blob); err != nil {
				yield(nil, fmt.Errorf("rpmdb: reading sqlite: %w", err))

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
			yield(nil, fmt.Errorf("rpmdb: reading sqlite: %w", err))
		}
	}
}
