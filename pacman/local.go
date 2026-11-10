package pacman

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/limitio"
	"github.com/M0Rf30/pkgformat/internal/pathseg"
	"github.com/M0Rf30/pkgformat/safepath"
)

// Errors of the local-database reader. Test with errors.Is.
var (
	// ErrLocalDBNotFound means [FindLocalDB] met no local database under the
	// root.
	ErrLocalDBNotFound = errors.New("pacman: no local database found")
	// ErrInvalidLocalDB means a directory is not a local database, or cannot
	// be read as one.
	ErrInvalidLocalDB = errors.New("pacman: invalid local database")
	// ErrLocalDBTooLarge means a local database is over one of the limits of
	// [LocalDBOptions].
	ErrLocalDBTooLarge = errors.New("pacman: local database exceeds a limit")
	// ErrUnsupportedLocalDB means the ALPM_DB_VERSION file names a layout this
	// package does not read.
	ErrUnsupportedLocalDB = errors.New("pacman: unsupported local database version")
)

// Default limits of the local-database reader, applied where a
// [LocalDBOptions] field is zero.
const (
	// DefaultMaxLocalPackages bounds the package directories of a database.
	DefaultMaxLocalPackages = MaxDBEntries
	// DefaultMaxLocalFiles bounds the file records of one package.
	DefaultMaxLocalFiles = 1 << 21
)

const (
	// localDBFile is where pacman keeps its local database, relative to the
	// root of the system.
	localDBFile = "var/lib/pacman/local"
	// localDBVersion is the layout this package reads: one directory per
	// package with desc and files members (pacman 4.0 and later).
	localDBVersion = "9"
	// maxFileLine bounds a line of a files member: a path is at most 4096
	// bytes, and a backup line adds a tab and a digest.
	maxFileLine = 8192
	// dirChunk is how many directory entries are read at a time from the database directory.
	dirChunk = 256
)

// Reason is why a package was installed: the "%REASON%" of its desc.
type Reason int

// The reasons pacman records.
const (
	// ReasonExplicit means the user asked for the package. It is also the
	// reason of a package whose desc has no %REASON%.
	ReasonExplicit Reason = 0
	// ReasonDependency means the package came in to satisfy another one.
	ReasonDependency Reason = 1
)

// BackupFile is a "%BACKUP%" line: a file pacman keeps a checksum of so that
// it can tell a user's edit from the packaged file on upgrade.
type BackupFile struct {
	// Path is relative to the root of the system: "etc/pacman.conf".
	Path string
	// MD5 is the hex digest of the file as installed. pacman writes the text
	// "(null)" where it has none; it is kept as it is.
	MD5 string
}

// InstalledPackage is an entry of the local database: the desc and files
// members of one package directory.
type InstalledPackage struct {
	// Dir is the name of the package's directory, "<name>-<version>" in a
	// database pacman wrote. The package's name is Name, not a part of Dir.
	Dir         string
	Name        string
	Base        string
	Version     string
	Description string
	URL         string
	Arch        string
	Packager    string
	// BuildDate and InstallDate are Unix seconds, zero when absent.
	BuildDate   int64
	InstallDate int64
	// Size is the installed size in bytes.
	Size   int64
	Reason Reason

	Groups     []string
	Licenses   []string
	Validation []string
	Replaces   []string
	Conflicts  []string
	Provides   []string
	Depends    []string
	OptDepends []string
	// XData holds the "%XDATA%" lines, "key=value" ("pkgtype=pkg").
	XData []string

	// Files are the "%FILES%" of the package, relative to the root of the
	// system. A directory has a trailing slash: "usr/bin/".
	Files []string
	// Backup are the "%BACKUP%" entries of the files member.
	Backup []BackupFile
}

// LocalDBOptions configures [OpenLocalDB] and [NewLocalDB]. The zero value is
// usable.
type LocalDBOptions struct {
	// Logger receives debug messages about skipped packages. Optional: nil
	// discards them.
	Logger *slog.Logger
	// MaxPackages bounds the entries of the database directory; one with more
	// fails with [ErrLocalDBTooLarge]. Zero selects [DefaultMaxLocalPackages].
	MaxPackages int
	// MaxFiles bounds the file records of one package; a package with more is
	// skipped. Zero selects [DefaultMaxLocalFiles].
	MaxFiles int
	// SkipFiles leaves the files members unread: the packages come without
	// Files and Backup.
	SkipFiles bool
}

func (o LocalDBOptions) normalized() LocalDBOptions {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}

	if o.MaxPackages <= 0 {
		o.MaxPackages = DefaultMaxLocalPackages
	}

	if o.MaxFiles <= 0 {
		o.MaxFiles = DefaultMaxLocalFiles
	}

	return o
}

// FindLocalDB looks for the local database under root, the directory that
// holds the system's /var: "/" for the running host, or the root of an image
// or an install directory. Symbolic links are followed only inside root. It
// returns [ErrLocalDBNotFound] when there is no directory.
func FindLocalDB(root string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("%w: empty root", ErrLocalDBNotFound)
	}

	p, err := safepath.ResolveInRoot(root, localDBFile)
	if err == nil {
		var fi os.FileInfo

		if fi, err = os.Stat(p); err == nil && fi.IsDir() {
			return p, nil
		}
	}

	return "", fmt.Errorf("%w under %s", ErrLocalDBNotFound, root)
}

// LocalDB is the pacman local database: the directory /var/lib/pacman/local.
// It is read-only and safe for concurrent use: every call reads the directory
// again.
type LocalDB struct {
	fsys   fs.FS
	closer io.Closer
	opts   LocalDBOptions
}

// OpenLocalDB opens the local database in dir. The directory is only read and
// not locked, so pacman can run at the same time; each call reads it as of
// that moment. Links inside the database that point out of dir are not
// followed.
func OpenLocalDB(dir string, opts LocalDBOptions) (*LocalDB, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("pacman: %w", err)
	}

	return &LocalDB{fsys: root.FS(), closer: root, opts: opts.normalized()}, nil
}

// NewLocalDB reads the local database that fsys holds at its top level: the
// package directories and ALPM_DB_VERSION. Close does nothing.
func NewLocalDB(fsys fs.FS, opts LocalDBOptions) *LocalDB {
	return &LocalDB{fsys: fsys, opts: opts.normalized()}
}

// Close releases the directory of a database opened with [OpenLocalDB].
func (db *LocalDB) Close() error {
	if db.closer == nil {
		return nil
	}

	return db.closer.Close()
}

// Packages iterates over the installed packages, in the order of their
// directory names. A package whose directory has no valid desc, whose name or
// version is not valid, whose desc or files member is over its limit or has a
// malformed value is skipped and reported at debug level to
// [LocalDBOptions.Logger]. The name of a package is the %NAME% of its desc,
// whatever its directory is called. The iteration ends with an error when the
// directory is over its limit, cannot be read, has a version this package does
// not read, or when ctx is done; the error is the last pair it yields.
// Stopping early releases everything.
func (db *LocalDB) Packages(ctx context.Context) iter.Seq2[*InstalledPackage, error] {
	return func(yield func(*InstalledPackage, error) bool) {
		names, err := db.packageDirs(ctx)
		if err != nil {
			yield(nil, err)

			return
		}

		for _, dir := range names {
			if err := ctx.Err(); err != nil {
				yield(nil, err)

				return
			}

			pkg, err := db.readPackage(dir)
			if err != nil {
				db.opts.Logger.Debug("pacman: skipping a local package", "dir", dir, "error", err)

				continue
			}

			if !yield(pkg, nil) {
				return
			}
		}
	}
}

// packageDirs checks the version of the database and lists its package
// directories, sorted.
func (db *LocalDB) packageDirs(ctx context.Context) ([]string, error) {
	if err := db.checkVersion(); err != nil {
		return nil, err
	}

	d, err := db.fsys.Open(".")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidLocalDB, err)
	}

	defer func() { _ = d.Close() }()

	rd, ok := d.(fs.ReadDirFile)
	if !ok {
		return nil, fmt.Errorf("%w: not a directory", ErrInvalidLocalDB)
	}

	var (
		names []string
		seen  int
	)

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		entries, err := rd.ReadDir(dirChunk)

		for _, e := range entries {
			if seen++; seen > db.opts.MaxPackages {
				return nil, fmt.Errorf("%w: more than %d entries", ErrLocalDBTooLarge, db.opts.MaxPackages)
			}

			if !e.IsDir() || !pathseg.Name(e.Name()) {
				continue
			}

			names = append(names, e.Name())
		}

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidLocalDB, err)
		}
	}

	slices.Sort(names)

	return names, nil
}

// checkVersion reads ALPM_DB_VERSION. A database without one is read as the
// current layout.
func (db *LocalDB) checkVersion() error {
	data, err := readLimited(db.fsys, "ALPM_DB_VERSION", 64)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("%w: ALPM_DB_VERSION: %w", ErrInvalidLocalDB, err)
	}

	if v := strings.TrimSpace(string(data)); v != localDBVersion {
		return fmt.Errorf("%w: %q, this package reads %s", ErrUnsupportedLocalDB, v, localDBVersion)
	}

	return nil
}

// readLimited reads a regular file of at most limit bytes.
func readLimited(fsys fs.FS, name string, limit int64) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}

	if fi.Size() > limit {
		return nil, fmt.Errorf("%w: %d bytes, the limit is %d", ErrLocalDBTooLarge, fi.Size(), limit)
	}

	return io.ReadAll(limitio.Capped(f, limit+1, ErrLocalDBTooLarge))
}

// readPackage reads and checks the desc, and the files when wanted, of one
// package directory.
func (db *LocalDB) readPackage(dir string) (*InstalledPackage, error) {
	body, err := readLimited(db.fsys, dir+"/desc", MaxDescBytes)
	if err != nil {
		return nil, err
	}

	pkg := &InstalledPackage{Dir: dir}

	if err := scanBlocks(body, pkg.setField); err != nil {
		return nil, err
	}

	if !ValidName(pkg.Name) || !ValidVersion(pkg.Version) || pkg.Arch != "" && !ValidArch(pkg.Arch) {
		return nil, fmt.Errorf("%w: invalid name, version or architecture", errSkippedEntry)
	}

	if db.opts.SkipFiles {
		return pkg, nil
	}

	if err := db.readFiles(dir, pkg); err != nil {
		return nil, err
	}

	return pkg, nil
}

// setField stores one block of a desc member. Unknown fields are ignored.
func (p *InstalledPackage) setField(key string, values []string) error {
	// DBEntry carries the checks and the fields a local desc shares with a
	// repository one.
	var e DBEntry

	if err := e.setField(key, values); err != nil {
		return err
	}

	switch key {
	case "NAME":
		p.Name = e.Name
	case "BASE":
		p.Base = e.Base
	case "VERSION":
		p.Version = e.Version
	case "DESC":
		p.Description = e.Description
	case "URL":
		p.URL = e.URL
	case "ARCH":
		p.Arch = e.Arch
	case "PACKAGER":
		p.Packager = e.Packager
	case "BUILDDATE":
		p.BuildDate = e.BuildDate
	case "INSTALLDATE", "SIZE", "REASON":
		return p.setNumber(key, values)
	case "VALIDATION":
		p.Validation = values
	case "XDATA":
		p.XData = values
	case "GROUPS":
		p.Groups = values
	case "LICENSE":
		p.Licenses = values
	case "REPLACES":
		p.Replaces = values
	case "CONFLICTS":
		p.Conflicts = values
	case "PROVIDES":
		p.Provides = values
	case "DEPENDS":
		p.Depends = values
	case "OPTDEPENDS":
		p.OptDepends = values
	}

	return nil
}

func (p *InstalledPackage) setNumber(key string, values []string) error {
	if len(values) == 0 {
		return nil
	}

	n, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || n < 0 {
		return errSkippedEntry
	}

	switch key {
	case "INSTALLDATE":
		p.InstallDate = n
	case "SIZE":
		p.Size = n
	case "REASON":
		p.Reason = Reason(n)
	}

	return nil
}

// readFiles reads the %FILES% and %BACKUP% blocks of the files member of dir,
// which a package without files does not have.
func (db *LocalDB) readFiles(dir string, pkg *InstalledPackage) error {
	f, err := db.fsys.Open(dir + "/files")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	if !fi.Mode().IsRegular() {
		return errors.New("files: not a regular file")
	}

	if fi.Size() > MaxDBFileListBytes {
		return fmt.Errorf("%w: files is %d bytes", ErrLocalDBTooLarge, fi.Size())
	}

	sc := bufio.NewScanner(limitio.Capped(f, MaxDBFileListBytes+1, ErrLocalDBTooLarge))
	sc.Buffer(make([]byte, 0, 4<<10), maxFileLine)

	key := ""

	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")

		switch {
		case len(line) > 2 && line[0] == '%' && line[len(line)-1] == '%':
			key = line[1 : len(line)-1]
		case line == "":
			key = ""
		case key == "FILES" || key == "BACKUP":
			if len(pkg.Files)+len(pkg.Backup) >= db.opts.MaxFiles {
				return fmt.Errorf("%w: more than %d file records", ErrLocalDBTooLarge, db.opts.MaxFiles)
			}

			if err := pkg.addFile(key, line); err != nil {
				return err
			}
		}
	}

	if err := sc.Err(); err != nil {
		return fmt.Errorf("files: %w", err)
	}

	return nil
}

// addFile stores a line of the %FILES% or %BACKUP% block, after checking that
// the path is a plain relative one.
func (p *InstalledPackage) addFile(key, line string) error {
	path, md5, _ := strings.Cut(line, "\t")

	if !pathseg.Path(strings.TrimSuffix(path, "/")) {
		return fmt.Errorf("%w: %q is not a path inside the root", errSkippedEntry, short(path))
	}

	if key == "FILES" {
		p.Files = append(p.Files, path)

		return nil
	}

	if strings.HasSuffix(path, "/") || len(md5) > MaxNameLen {
		return fmt.Errorf("%w: invalid backup line", errSkippedEntry)
	}

	p.Backup = append(p.Backup, BackupFile{Path: path, MD5: md5})

	return nil
}

func short(s string) string {
	const limit = 64

	if len(s) > limit {
		return s[:limit] + "..."
	}

	return s
}

// List returns every installed package: [LocalDB.Packages] collected into a
// slice.
func (db *LocalDB) List(ctx context.Context) ([]*InstalledPackage, error) {
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
// without duplicates. It does not read the files members.
func (db *LocalDB) InstalledNames(ctx context.Context) ([]string, error) {
	var names []string

	for pkg, err := range db.light().Packages(ctx) {
		if err != nil {
			return nil, err
		}

		names = append(names, pkg.Name)
	}

	slices.Sort(names)

	return slices.Compact(names), nil
}

// InstalledProvides returns the names the installed packages answer to: their
// own and what they provide, without version constraints ("libacl.so=1-64"
// gives "libacl.so"), sorted and without duplicates. It does not read the
// files members.
func (db *LocalDB) InstalledProvides(ctx context.Context) ([]string, error) {
	var provides []string

	for pkg, err := range db.light().Packages(ctx) {
		if err != nil {
			return nil, err
		}

		provides = append(provides, pkg.Name)

		for _, p := range pkg.Provides {
			if d, err := ParseDependency(p); err == nil {
				provides = append(provides, d.Name)
			}
		}
	}

	slices.Sort(provides)

	return slices.Compact(provides), nil
}

// light is the database read without the files members.
func (db *LocalDB) light() *LocalDB {
	l := *db
	l.opts.SkipFiles = true

	return &l
}
