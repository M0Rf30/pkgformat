package apk

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/M0Rf30/pkgformat/internal/limitio"
	"github.com/M0Rf30/pkgformat/internal/pathseg"
	"github.com/M0Rf30/pkgformat/safepath"
)

// Errors of the installed-database reader. Test with errors.Is.
var (
	// ErrInstalledNotFound means [FindInstalled] met no installed database
	// under the root.
	ErrInstalledNotFound = errors.New("apk: no installed database found")
	// ErrInvalidInstalled means a file is not an installed database, or cannot
	// be read as one.
	ErrInvalidInstalled = errors.New("apk: invalid installed database")
	// ErrInstalledTooLarge means an installed database is over one of the
	// limits of [InstalledOptions].
	ErrInstalledTooLarge = errors.New("apk: installed database exceeds a limit")
)

// Default limits of the installed-database reader, applied where an
// [InstalledOptions] field is zero.
const (
	// DefaultMaxInstalledPackages bounds the package records of a database.
	DefaultMaxInstalledPackages = 1 << 20
	// DefaultMaxInstalledFiles bounds the file and directory records of one
	// package.
	DefaultMaxInstalledFiles = 1 << 21
	// DefaultMaxInstalledBytes bounds the size of the database file. A system
	// with a thousand packages has a few megabytes.
	DefaultMaxInstalledBytes int64 = 1 << 30
)

// installedFile is where apk keeps its database, relative to the root of the
// system.
const installedFile = "lib/apk/db/installed"

// maxChecksumLen bounds a file checksum or a package checksum.
const maxChecksumLen = 128

// InstalledFile is a file or directory record of an installed package.
type InstalledFile struct {
	// Path is relative to the root of the system, without a leading slash:
	// "usr/lib/libz.so.1".
	Path string
	// Dir is true for a directory the package owns, and false for a file.
	Dir bool
	// Checksum is the "Z:" value of a file, "Q1" and the base64 of its SHA-1
	// (or, for an install made by a newer apk, the algorithm's own prefix).
	// It is empty for a directory.
	Checksum string
	// HasACL reports that the record carries an "a:" (file) or "M:"
	// (directory) line, which gives the owner and the mode.
	HasACL bool
	// UID and GID are the owner and group of the file, and Mode its
	// permission bits, from the ACL line. They are zero without one.
	UID, GID uint32
	Mode     uint32
}

// InstalledPackage is a package record of the installed database: the fields
// of an index entry, the files the package owns and what apk adds for an
// installed package.
type InstalledPackage struct {
	// Package holds the index fields, P, V, A, S, I, T, U, L, o, m, t, c, D,
	// p, i and k, "r" (Replaces) and "q" (ReplacesPriority). Checksum is the "C:" value; it is empty
	// for a package without one.
	Package
	// Files are the directories and files of the package, in the order of the
	// database: a directory, then the files in it.
	Files []InstalledFile
}

// FilePaths returns the paths of the regular files of the package, as
// "apk info -L" lists them.
func (p *InstalledPackage) FilePaths() []string {
	var paths []string

	for i := range p.Files {
		if !p.Files[i].Dir {
			paths = append(paths, p.Files[i].Path)
		}
	}

	return paths
}

// InstalledOptions configures [OpenInstalled], [NewInstalledDB]. The zero
// value is usable.
type InstalledOptions struct {
	// Logger receives debug messages about skipped records. Optional: nil
	// discards them.
	Logger *slog.Logger
	// MaxPackages bounds the package records read; reading more fails with
	// [ErrInstalledTooLarge]. Zero selects [DefaultMaxInstalledPackages].
	MaxPackages int
	// MaxFiles bounds the file and directory records of one package; a
	// package with more is skipped. Zero selects [DefaultMaxInstalledFiles].
	MaxFiles int
	// MaxBytes bounds the size of the database; a larger one fails with
	// [ErrInstalledTooLarge]. Zero selects [DefaultMaxInstalledBytes].
	MaxBytes int64
	// SkipFiles leaves the file records out of the packages. The names and
	// the metadata of a large database are then read without keeping the
	// lists.
	SkipFiles bool
}

func (o InstalledOptions) normalized() InstalledOptions {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}

	if o.MaxPackages <= 0 {
		o.MaxPackages = DefaultMaxInstalledPackages
	}

	if o.MaxFiles <= 0 {
		o.MaxFiles = DefaultMaxInstalledFiles
	}

	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxInstalledBytes
	}

	return o
}

// FindInstalled looks for the installed database under root, the directory
// that holds the system's /lib: "/" for the running host, or the root of an
// image or an install directory. Symbolic links are followed only inside root.
// It returns [ErrInstalledNotFound] when there is no regular file.
func FindInstalled(root string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("%w: empty root", ErrInstalledNotFound)
	}

	p, err := safepath.ResolveInRoot(root, installedFile)
	if err == nil {
		var fi os.FileInfo

		if fi, err = os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
	}

	return "", fmt.Errorf("%w under %s", ErrInstalledNotFound, root)
}

// InstalledDB is an apk installed database: the file /lib/apk/db/installed.
// It is read-only and safe for concurrent use: every call reads the file
// again.
type InstalledDB struct {
	ra     io.ReaderAt
	size   int64
	closer io.Closer
	opts   InstalledOptions
}

// OpenInstalled opens the installed database at path. The file is only read
// and not locked, so apk can run at the same time; each call reads it as of
// that moment.
func OpenInstalled(path string, opts InstalledOptions) (*InstalledDB, error) {
	opts = opts.normalized()

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("apk: %w", err)
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()

		return nil, fmt.Errorf("apk: %w", err)
	}

	if !fi.Mode().IsRegular() {
		_ = f.Close()

		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInvalidInstalled, path)
	}

	if fi.Size() > opts.MaxBytes {
		_ = f.Close()

		return nil, fmt.Errorf("%w: %s is %d bytes, the limit is %d", ErrInstalledTooLarge, path, fi.Size(), opts.MaxBytes)
	}

	return &InstalledDB{ra: f, size: fi.Size(), closer: f, opts: opts}, nil
}

// NewInstalledDB reads the database text that r holds, size bytes. Close does
// not close r. A size over [InstalledOptions.MaxBytes] makes every read fail
// with [ErrInstalledTooLarge].
func NewInstalledDB(r io.ReaderAt, size int64, opts InstalledOptions) *InstalledDB {
	return &InstalledDB{ra: r, size: size, opts: opts.normalized()}
}

// Close releases the file of a database opened with [OpenInstalled].
func (db *InstalledDB) Close() error {
	if db.closer == nil {
		return nil
	}

	return db.closer.Close()
}

// Packages iterates over the installed packages in the order of the database.
// A record that is not valid is skipped and reported at debug level to
// [InstalledOptions.Logger]: a missing P, V or A line, a repeated field, a
// value that is not valid, a path that climbs out of the root, a package with
// more than [InstalledOptions.MaxFiles] file records. The iteration ends with
// an error when the file is over its limits, cannot be read, or when ctx is
// done; the error is the last pair it yields. Stopping early releases
// everything.
func (db *InstalledDB) Packages(ctx context.Context) iter.Seq2[*InstalledPackage, error] {
	return func(yield func(*InstalledPackage, error) bool) {
		if db.size > db.opts.MaxBytes {
			yield(nil, fmt.Errorf("%w: %d bytes, the limit is %d", ErrInstalledTooLarge, db.size, db.opts.MaxBytes))

			return
		}

		r := limitio.Capped(io.NewSectionReader(db.ra, 0, db.size), db.opts.MaxBytes, ErrInstalledTooLarge)

		db.read(ctx, r, yield)
	}
}

// read scans the records of r and yields the valid packages. Every return ends
// the iteration, and yield is not called again after it returned false.
func (db *InstalledDB) read(ctx context.Context, r io.Reader, yield func(*InstalledPackage, error) bool) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxIndexLine+2)
	sc.Split(scanLines)

	var (
		cur     = newInstalledStanza(db.opts)
		records int
		line    int
	)

	// flush ends the record, and reports false when the iteration must stop.
	flush := func() bool {
		if cur.lines == 0 {
			return true
		}

		records++

		pkg, err := cur.finish()
		cur = newInstalledStanza(db.opts)

		switch {
		case records > db.opts.MaxPackages:
			yield(nil, fmt.Errorf("%w: more than %d packages", ErrInstalledTooLarge, db.opts.MaxPackages))

			return false
		case err != nil:
			db.opts.Logger.Debug("apk: skipping an installed record", "record", records, "line", line, "error", err)

			return true
		}

		return yield(pkg, nil)
	}

	for sc.Scan() {
		line++

		if line&0xfff == 0 {
			if err := ctx.Err(); err != nil {
				yield(nil, err)

				return
			}
		}

		text := sc.Bytes()
		if len(text) == 0 {
			if err := ctx.Err(); err != nil {
				yield(nil, err)

				return
			}

			if !flush() {
				return
			}

			continue
		}

		cur.add(text)
	}

	if err := sc.Err(); err != nil {
		switch {
		case errors.Is(err, ErrInstalledTooLarge):
			yield(nil, fmt.Errorf("%w: more than %d bytes", ErrInstalledTooLarge, db.opts.MaxBytes))
		case errors.Is(err, bufio.ErrTooLong):
			yield(nil, fmt.Errorf("%w: a line is longer than %d bytes", ErrInstalledTooLarge, maxIndexLine))
		default:
			yield(nil, fmt.Errorf("%w: reading: %w", ErrInvalidInstalled, err))
		}

		return
	}

	flush()
}

// installedStanza collects the lines of the record being read. It reads the
// index fields with the stanza of ParseIndex.
type installedStanza struct {
	stanza
	opts  InstalledOptions
	lines int
	// bad is the first problem of the record: the record is dropped when it
	// ends, but its lines are still consumed.
	bad error
	// dir is the directory the next "R:" lines are in.
	dir string
	// files are the records so far, and last the one an "a:", "M:" or "Z:" line
	// belongs to, or -1.
	files            []InstalledFile
	last             int
	replacesPriority int
}

func newInstalledStanza(opts InstalledOptions) *installedStanza {
	return &installedStanza{opts: opts, last: -1}
}

// add stores one line of the record.
func (s *installedStanza) add(line []byte) {
	s.lines++

	if s.bad != nil {
		return
	}

	if len(line) < 2 || line[1] != ':' {
		s.bad = fmt.Errorf("%w: not of the form X:value", errIndexLine)

		return
	}

	val := string(line[2:])

	switch line[0] {
	case 'F', 'R', 'a', 'M', 'Z':
		s.bad = s.addFileLine(line[0], val)
	case 'r':
		s.pkg.Replaces = strings.Fields(val)
	case 'q':
		n, ok := parseCount(val)
		if !ok || n > maxProviderPrio {
			s.bad = fmt.Errorf("%w: field q is not a valid number", errIndexLine)

			return
		}

		s.replacesPriority = int(n)
	default:
		s.bad = s.stanza.add(line)
	}
}

func (s *installedStanza) addFileLine(key byte, val string) error {
	if s.opts.SkipFiles {
		return nil
	}

	switch key {
	case 'F':
		if val != "" && !pathseg.Path(val) {
			return fmt.Errorf("%w: %q is not a path inside the root", errIndexLine, short(val))
		}

		s.dir = val

		return s.addFile(InstalledFile{Path: val, Dir: true})
	case 'R':
		if !pathseg.Name(val) {
			return fmt.Errorf("%w: %q is not a file name", errIndexLine, short(val))
		}

		path := val
		if s.dir != "" {
			path = s.dir + "/" + val
		}

		return s.addFile(InstalledFile{Path: path})
	}

	if s.last < 0 {
		return fmt.Errorf("%w: %c line before any F or R line", errIndexLine, key)
	}

	f := &s.files[s.last]

	switch {
	case key == 'Z' && !f.Dir:
		if val == "" || len(val) > maxChecksumLen || !cleanText(val) {
			return fmt.Errorf("%w: invalid checksum", errIndexLine)
		}

		f.Checksum = val
	case key == 'a' && !f.Dir, key == 'M' && f.Dir:
		return f.setACL(val)
	case f.Dir:
		return fmt.Errorf("%w: %c line after a directory", errIndexLine, key)
	default:
		return fmt.Errorf("%w: %c line after a file", errIndexLine, key)
	}

	return nil
}

// addFile appends a record, within the limit of the package.
func (s *installedStanza) addFile(f InstalledFile) error {
	if len(s.files) >= s.opts.MaxFiles {
		return fmt.Errorf("%w: more than %d file records", ErrInstalledTooLarge, s.opts.MaxFiles)
	}

	s.files = append(s.files, f)
	s.last = len(s.files) - 1

	return nil
}

// setACL reads "uid:gid:mode[:xattrs]", the mode in octal.
func (f *InstalledFile) setACL(val string) error {
	fields := strings.SplitN(val, ":", 4)
	if len(fields) < 3 {
		return fmt.Errorf("%w: ACL %q is not uid:gid:mode", errIndexLine, short(val))
	}

	uid, ok1 := parseCount(fields[0])
	gid, ok2 := parseCount(fields[1])
	mode, err := strconv.ParseUint(fields[2], 8, 32)

	if !ok1 || !ok2 || err != nil || uid > 1<<32-1 || gid > 1<<32-1 || mode > 0o7777 {
		return fmt.Errorf("%w: ACL %q is not uid:gid:mode", errIndexLine, short(val))
	}

	f.HasACL = true
	f.UID, f.GID, f.Mode = uint32(uid), uint32(gid), uint32(mode)

	return nil
}

// finish checks the record and returns the package. The name, version and
// architecture must be there and be plain tokens; unlike an index entry, a
// name may start with a dot (apk add --virtual .build-deps), and a checksum
// may be of any algorithm.
func (s *installedStanza) finish() (*InstalledPackage, error) {
	if s.bad != nil {
		return nil, s.bad
	}

	for _, key := range [...]byte{'P', 'V', 'A'} {
		if !s.seen[key] {
			return nil, fmt.Errorf("%w: missing field %c", errIndexLine, key)
		}
	}

	p := &s.pkg

	for _, f := range [...]struct {
		name, val string
		max       int
	}{
		{"name", p.Name, maxNameLen}, {"version", p.Version, maxVersionLen}, {"arch", p.Arch, maxArchLen},
	} {
		if f.val == "" || len(f.val) > f.max || !cleanText(f.val) || strings.IndexFunc(f.val, unicode.IsSpace) >= 0 {
			return nil, fmt.Errorf("%w: invalid %s %q", errIndexLine, f.name, short(f.val))
		}
	}

	if p.Checksum != "" && (len(p.Checksum) > maxChecksumLen || !cleanText(p.Checksum)) {
		return nil, fmt.Errorf("%w: invalid checksum", errIndexLine)
	}

	if err := p.validateRest(); err != nil {
		return nil, err
	}

	p.ReplacesPriority = s.replacesPriority

	return &InstalledPackage{Package: *p, Files: s.files}, nil
}

// List returns every installed package: [InstalledDB.Packages] collected into
// a slice.
func (db *InstalledDB) List(ctx context.Context) ([]*InstalledPackage, error) {
	var pkgs []*InstalledPackage

	for pkg, err := range db.Packages(ctx) {
		if err != nil {
			return nil, err
		}

		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

// InstalledNames returns the names of the installed packages, sorted and
// without duplicates. It does not keep the file lists.
func (db *InstalledDB) InstalledNames(ctx context.Context) ([]string, error) {
	var names []string

	for pkg, err := range db.light().Packages(ctx) {
		if err != nil {
			return nil, err
		}

		names = append(names, pkg.Name)
	}

	return sortedUnique(names), nil
}

// InstalledProvides returns the capabilities the installed packages provide
// ("so:libc.musl-x86_64.so.1", "cmd:sh", "/bin/sh"), as names without version
// constraints, sorted and without duplicates. The name of each package is
// included, as it provides itself. It does not keep the file lists.
func (db *InstalledDB) InstalledProvides(ctx context.Context) ([]string, error) {
	var provides []string

	for pkg, err := range db.light().Packages(ctx) {
		if err != nil {
			return nil, err
		}

		provides = append(provides, pkg.Name)

		for _, p := range pkg.Provides {
			if name := DependencyName(p); name != "" {
				provides = append(provides, name)
			}
		}
	}

	return sortedUnique(provides), nil
}

// light is the database read without the file lists.
func (db *InstalledDB) light() *InstalledDB {
	l := *db
	l.opts.SkipFiles = true

	return &l
}

func sortedUnique(s []string) []string {
	slices.Sort(s)

	return slices.Compact(s)
}
