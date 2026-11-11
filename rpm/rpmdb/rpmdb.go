package rpmdb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/safepath"
)

// Errors of the package. Test with errors.Is.
var (
	// ErrNotFound means [Find] met no rpm database under the root.
	ErrNotFound = errors.New("rpmdb: no rpm database found")
	// ErrFormat means a file is not an rpm database of a known format.
	ErrFormat = errors.New("rpmdb: not an rpm database")
	// ErrUnsupported means a database uses a feature the reader does not
	// handle, such as an encrypted or checksummed BerkeleyDB file.
	ErrUnsupported = errors.New("rpmdb: unsupported database")
	// ErrCorrupt means the container of a database is damaged: a page, slot
	// or overflow chain points outside the file or contradicts itself.
	ErrCorrupt = errors.New("rpmdb: corrupt database")
	// ErrTooLarge means a database, or what a read of it would have to keep
	// in memory, exceeds a limit: [Options.MaxRecords] records,
	// [Options.MaxIndexEntries] indexed entries or
	// [Options.MaxSnapshotBytes] bytes of snapshot.
	ErrTooLarge = errors.New("rpmdb: too many records")
	// ErrLocked means a SQLite database stayed busy or locked, for example
	// under an exclusive transaction of rpm, for longer than
	// [Options.BusyTimeout] and [Options.LockRetries] allow. Reading again
	// later may succeed.
	ErrLocked = errors.New("rpmdb: database is locked")
	// ErrInvalidQuery means the argument of a query is not one: an empty name
	// or path, or a capability that does not parse.
	ErrInvalidQuery = errors.New("rpmdb: invalid query")
)

// Format is the storage format of an rpm database.
type Format int

// The formats of rpm databases.
const (
	// FormatUnknown is the zero value: no format.
	FormatUnknown Format = iota
	// FormatSQLite is rpmdb.sqlite, the default of rpm 4.16 and later on most
	// distributions.
	FormatSQLite
	// FormatBDB is the BerkeleyDB hash database "Packages" of rpm 4.15 and
	// earlier.
	FormatBDB
	// FormatNDB is the native database "Packages.db" that openSUSE and SUSE
	// Linux Enterprise use.
	FormatNDB
)

// String returns "sqlite", "bdb", "ndb" or "unknown".
func (f Format) String() string {
	switch f {
	case FormatSQLite:
		return "sqlite"
	case FormatBDB:
		return "bdb"
	case FormatNDB:
		return "ndb"
	default:
		return "unknown"
	}
}

// Default limits, applied where an [Options] field is zero.
const (
	// DefaultMaxRecords bounds the records of a database.
	DefaultMaxRecords = 1 << 20
	// DefaultMaxBlobBytes bounds one record: the header image of a package.
	// rpm itself refuses headers whose data is larger than 256 MiB.
	DefaultMaxBlobBytes = 1 << 28
	// DefaultMaxIndexEntries bounds what the query index keeps: about 16
	// million files and dependency entries, several times what the largest
	// installations hold.
	DefaultMaxIndexEntries = 1 << 24
	// defaultMaxArrayEntries and defaultMaxFileListBytes bound the arrays of
	// one header: the header size already bounds them, these only keep the
	// file list of a very large package from being cut short.
	defaultMaxArrayEntries  = 1 << 22
	defaultMaxFileListBytes = 1 << 28
	// sniffBytes is how much of a file tells its format.
	sniffBytes = 32
)

// databaseFiles are the places rpm keeps its database relative to the root of
// the system, in the order [Find] tries them: the newer formats first, and the
// traditional directory before the one of the distributions that moved the
// database to /usr.
var databaseFiles = [...]string{
	"var/lib/rpm/rpmdb.sqlite",
	"usr/lib/sysimage/rpm/rpmdb.sqlite",
	"var/lib/rpm/Packages.db",
	"usr/lib/sysimage/rpm/Packages.db",
	"var/lib/rpm/Packages",
	"usr/lib/sysimage/rpm/Packages",
}

// Options configures [Open]. The zero value is usable.
type Options struct {
	// Logger receives debug messages about skipped records. Optional: nil
	// discards them.
	Logger *slog.Logger
	// SQLite selects how a SQLite database is opened: in place, immutable or
	// from a private snapshot. The zero value, [SQLiteAuto], opens in place
	// and falls back when the directory is read-only. It has no effect on the
	// other formats.
	SQLite SQLiteMode
	// BusyTimeout is how long one SQLite operation waits for a writer that
	// holds the database before it reports it locked. Zero selects
	// [DefaultBusyTimeout].
	BusyTimeout time.Duration
	// LockRetries is how many times a SQLite read is repeated, with a growing
	// pause, after it reported the database locked. Zero selects
	// [DefaultLockRetries], a negative value disables the retries. When they
	// are used up the error matches [ErrLocked].
	LockRetries int
	// TempDir is where [SQLiteSnapshot] makes its copy. Empty selects
	// os.TempDir.
	TempDir string
	// MaxSnapshotBytes bounds the files [SQLiteSnapshot] copies; a larger
	// database fails with [ErrTooLarge]. Zero selects
	// [DefaultMaxSnapshotBytes].
	MaxSnapshotBytes int64
	// MaxIndexEntries bounds what the query methods keep in memory: the
	// number of files and dependency entries of all packages together. A
	// database that holds more makes them fail with [ErrTooLarge]. Zero
	// selects [DefaultMaxIndexEntries].
	MaxIndexEntries int
	// IncludeUninstalledFiles makes the file queries also match files that a
	// package lists but did not install, those that --excludedocs or a
	// replacement by another package left out. rpm -qf skips them, and so do
	// the file queries by default; ghost files are matched either way.
	IncludeUninstalledFiles bool
	// MaxRecords bounds the number of records read from a database; reading
	// more fails with [ErrTooLarge]. Zero selects [DefaultMaxRecords].
	MaxRecords int
	// MaxBlobBytes is the largest record, the header image of one package,
	// that is read; a larger one is skipped. Zero selects
	// [DefaultMaxBlobBytes].
	MaxBlobBytes int
	// Package bounds the decoding of each header. Zero fields select limits
	// as large as rpm allows a header to be.
	Package rpm.PackageLimits
}

func (o Options) normalized() Options {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}

	if o.BusyTimeout <= 0 {
		o.BusyTimeout = DefaultBusyTimeout
	}

	switch {
	case o.LockRetries == 0:
		o.LockRetries = DefaultLockRetries
	case o.LockRetries < 0:
		o.LockRetries = 0
	}

	if o.MaxSnapshotBytes <= 0 {
		o.MaxSnapshotBytes = DefaultMaxSnapshotBytes
	}

	if o.MaxIndexEntries <= 0 {
		o.MaxIndexEntries = DefaultMaxIndexEntries
	}

	if o.MaxRecords <= 0 {
		o.MaxRecords = DefaultMaxRecords
	}

	if o.MaxBlobBytes <= 0 {
		o.MaxBlobBytes = DefaultMaxBlobBytes
	}

	if o.Package.Header.MaxDataSize <= 0 {
		o.Package.Header.MaxDataSize = rpm.MaxHeaderDataSize
	}

	if o.Package.MaxArrayEntries <= 0 {
		o.Package.MaxArrayEntries = defaultMaxArrayEntries
	}

	if o.Package.MaxFileListBytes <= 0 {
		o.Package.MaxFileListBytes = defaultMaxFileListBytes
	}

	return o
}

// store is one storage format: it yields the records of a database.
type store interface {
	// blobs yields the value of every record, in storage order. A value is
	// valid until the next iteration. Records that are damaged on their own
	// are skipped; an error ends the iteration.
	blobs(ctx context.Context) iter.Seq2[[]byte, error]
	close() error
}

// DB is an open rpm database. It is safe for concurrent use.
type DB struct {
	format Format
	opts   Options
	st     store

	// ix is the query index, nil until a query needs it; building holds a
	// token while one is built, so that callers wait for it with their ctx.
	ix       atomic.Pointer[queryIndex]
	building chan struct{}
}

// Find looks for an rpm database under root, the directory that holds the
// system's /var and /usr: "/" for the running host, or the root of an image or
// an install directory. It tries var/lib/rpm and usr/lib/sysimage/rpm for
// rpmdb.sqlite, Packages.db and Packages, in that order, and returns the first
// file with the signature of a database, with its format. Symbolic links are
// followed only inside root. It returns [ErrNotFound] when there is none.
func Find(root string) (path string, format Format, err error) {
	if root == "" {
		return "", FormatUnknown, fmt.Errorf("%w: empty root", ErrNotFound)
	}

	for _, rel := range databaseFiles {
		p, err := safepath.ResolveInRoot(root, rel)
		if err != nil {
			continue
		}

		f, err := os.Open(p)
		if err != nil {
			continue
		}

		head, err := sniff(f)
		_ = f.Close()

		if err != nil {
			continue
		}

		if format, err := detect(head); err == nil {
			return p, format, nil
		}
	}

	return "", FormatUnknown, fmt.Errorf("%w under %s", ErrNotFound, root)
}

// sniff reads the leading bytes of a regular file.
func sniff(f *os.File) ([]byte, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrFormat, f.Name())
	}

	head := make([]byte, sniffBytes)
	n, err := io.ReadFull(f, head)

	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}

	return head[:n], nil
}

// Magic numbers of the formats.
const (
	sqliteMagic    = "SQLite format 3\x00"
	ndbMagic       = 'R' | 'p'<<8 | 'm'<<16 | 'P'<<24
	bdbHashMagic   = 0x00061561
	bdbBtreeMagic  = 0x00053162
	bdbMagicOffset = 12
)

// detect tells the format of a file from its first bytes.
func detect(head []byte) (Format, error) {
	if bytes.HasPrefix(head, []byte(sqliteMagic)) {
		return FormatSQLite, nil
	}

	if len(head) >= 4 && binary.LittleEndian.Uint32(head) == ndbMagic {
		return FormatNDB, nil
	}

	if len(head) >= bdbMagicOffset+4 {
		magic := head[bdbMagicOffset : bdbMagicOffset+4]

		switch le, be := binary.LittleEndian.Uint32(magic), binary.BigEndian.Uint32(magic); {
		case le == bdbHashMagic || be == bdbHashMagic:
			return FormatBDB, nil
		case le == bdbBtreeMagic || be == bdbBtreeMagic:
			return FormatUnknown, fmt.Errorf("%w: a BerkeleyDB btree, rpm uses a hash database", ErrUnsupported)
		}
	}

	return FormatUnknown, ErrFormat
}

// Open opens the rpm database at path read-only, whatever its format.
func Open(path string, opts Options) (*DB, error) {
	opts = opts.normalized()

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("rpmdb: %w", err)
	}

	head, err := sniff(f)
	if err != nil {
		_ = f.Close()

		return nil, fmt.Errorf("rpmdb: %w", err)
	}

	format, err := detect(head)
	if err != nil {
		_ = f.Close()

		return nil, fmt.Errorf("rpmdb: %s: %w", path, err)
	}

	var st store

	if format == FormatSQLite {
		// SQLite opens the file itself.
		_ = f.Close()
		st, err = openSQLite(path, opts)
	} else {
		var fi os.FileInfo

		if fi, err = f.Stat(); err == nil {
			if format == FormatBDB {
				st, err = newBDB(f, fi.Size(), opts)
			} else {
				st, err = newNDB(f, fi.Size(), opts)
			}
		}

		if err != nil {
			_ = f.Close()
		}
	}

	if err != nil {
		return nil, fmt.Errorf("rpmdb: %s: %w", path, err)
	}

	return &DB{format: format, opts: opts, st: st, building: make(chan struct{}, 1)}, nil
}

// Format returns the storage format of the database.
func (db *DB) Format() Format { return db.format }

// Close releases the database. Reads after Close fail.
func (db *DB) Close() error { return db.st.close() }

// headers yields the decoded header of every record that holds a package.
func (db *DB) headers(ctx context.Context) iter.Seq2[*rpm.RpmHeader, error] {
	return func(yield func(*rpm.RpmHeader, error) bool) {
		records := 0

		for blob, err := range db.st.blobs(ctx) {
			if err == nil {
				err = ctx.Err()
			}

			if err != nil {
				yield(nil, err)

				return
			}

			if records++; records > db.opts.MaxRecords {
				yield(nil, fmt.Errorf("%w: more than %d", ErrTooLarge, db.opts.MaxRecords))

				return
			}

			hdr, err := rpm.ReadHeaderBlob(blob, db.opts.Package.Header)
			if err != nil {
				db.opts.Logger.Debug("rpmdb: skipping a record that is not a header image", "record", records, "error", err)

				continue
			}

			if !yield(hdr, nil) {
				return
			}
		}
	}
}

// Packages iterates over the installed packages, in the order the database
// stores them. A record whose header does not decode into a package is
// skipped. The iteration ends with an error when the database is damaged, when
// it holds more than [Options.MaxRecords] records, or when ctx is done; the
// error is the last pair it yields. Stopping early releases everything.
func (db *DB) Packages(ctx context.Context) iter.Seq2[*rpm.Package, error] {
	return func(yield func(*rpm.Package, error) bool) {
		for rec, err := range db.records(ctx) {
			if err != nil {
				yield(nil, err)

				return
			}

			if !yield(rec.pkg, nil) {
				return
			}
		}
	}
}

// record is an installed package with the header it was decoded from.
type record struct {
	hdr *rpm.RpmHeader
	pkg *rpm.Package
}

// records yields the packages of the database with their headers; a header
// that is not a package is skipped.
func (db *DB) records(ctx context.Context) iter.Seq2[record, error] {
	return func(yield func(record, error) bool) {
		for hdr, err := range db.headers(ctx) {
			if err != nil {
				yield(record{}, err)

				return
			}

			pkg, err := hdr.InstalledPackage(db.opts.Package)
			if err != nil {
				db.opts.Logger.Debug("rpmdb: skipping a record that is not a package", "error", err)

				continue
			}

			if !yield(record{hdr: hdr, pkg: pkg}, nil) {
				return
			}
		}
	}
}

// List returns every installed package: [DB.Packages] collected into a slice.
func (db *DB) List(ctx context.Context) ([]*rpm.Package, error) {
	var pkgs []*rpm.Package

	for pkg, err := range db.Packages(ctx) {
		if err != nil {
			return nil, err
		}

		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}
