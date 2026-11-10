package deb

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
	"strings"

	"github.com/M0Rf30/pkgformat/internal/limitio"
	"github.com/M0Rf30/pkgformat/safepath"
)

// Errors of the dpkg status reader, besides [ErrTooLarge]. Test with errors.Is.
var (
	// ErrStatusNotFound means [FindStatus] met no dpkg status database under
	// the root.
	ErrStatusNotFound = errors.New("deb: no dpkg status database found")
	// ErrInvalidStatus means a Status field, or a status file, is not what
	// dpkg writes.
	ErrInvalidStatus = errors.New("deb: invalid dpkg status")
)

// Want is the first word of a dpkg Status field: what the administrator
// wants done with the package.
type Want string

// The values dpkg writes.
const (
	WantUnknown   Want = "unknown"
	WantInstall   Want = "install"
	WantHold      Want = "hold"
	WantDeinstall Want = "deinstall"
	WantPurge     Want = "purge"
)

// Flag is the second word of a dpkg Status field: the error flag.
type Flag string

// The values dpkg writes.
const (
	FlagOK            Flag = "ok"
	FlagReinstReq     Flag = "reinstreq"
	FlagHold          Flag = "hold"
	FlagHoldReinstReq Flag = "hold-reinstreq"
)

// State is the third word of a dpkg Status field: how far the package got.
type State string

// The values dpkg writes.
const (
	StateNotInstalled    State = "not-installed"
	StateConfigFiles     State = "config-files"
	StateHalfInstalled   State = "half-installed"
	StateUnpacked        State = "unpacked"
	StateHalfConfigured  State = "half-configured"
	StateTriggersAwaited State = "triggers-awaited"
	StateTriggersPending State = "triggers-pending"
	StateInstalled       State = "installed"
)

// Status is a parsed dpkg Status field, "install ok installed". The zero
// value is the status of a stanza that has none.
type Status struct {
	Want  Want
	Flag  Flag
	State State
}

// ParseStatus parses the value of a Status field: three words, each one of the
// values dpkg writes. Anything else fails with [ErrInvalidStatus].
func ParseStatus(value string) (Status, error) {
	words := strings.Fields(value)
	if len(words) != 3 {
		return Status{}, fmt.Errorf("%w: %q is not \"want flag state\"", ErrInvalidStatus, clip(value))
	}

	s := Status{Want: Want(words[0]), Flag: Flag(words[1]), State: State(words[2])}

	switch s.Want {
	case WantUnknown, WantInstall, WantHold, WantDeinstall, WantPurge:
	default:
		return Status{}, fmt.Errorf("%w: unknown want %q", ErrInvalidStatus, clip(words[0]))
	}

	switch s.Flag {
	case FlagOK, FlagReinstReq, FlagHold, FlagHoldReinstReq:
	default:
		return Status{}, fmt.Errorf("%w: unknown flag %q", ErrInvalidStatus, clip(words[1]))
	}

	switch s.State {
	case StateNotInstalled, StateConfigFiles, StateHalfInstalled, StateUnpacked,
		StateHalfConfigured, StateTriggersAwaited, StateTriggersPending, StateInstalled:
	default:
		return Status{}, fmt.Errorf("%w: unknown state %q", ErrInvalidStatus, clip(words[2]))
	}

	return s, nil
}

func clip(s string) string {
	const limit = 48

	if len(s) > limit {
		return s[:limit] + "..."
	}

	return s
}

// String renders the status as dpkg writes it, "install ok installed", or ""
// for the zero value.
func (s Status) String() string {
	if s == (Status{}) {
		return ""
	}

	return string(s.Want) + " " + string(s.Flag) + " " + string(s.State)
}

// Installed reports whether the package is installed: its state is
// "installed", whatever the administrator wants done with it (a held package,
// "hold ok installed", is installed, and so is one marked for removal).
//
// The states before it are not counted: "unpacked" and "half-configured" are
// a package whose configuration did not finish, "half-installed" one whose
// unpacking did not, "config-files" a removed package whose configuration
// files remain, and "triggers-awaited" and "triggers-pending" one that waits
// for a trigger to run. dpkg-query lists the first and last of these with the
// abbreviations "iU", "iF", "iH", "rc", "iW" and "it".
func (s Status) Installed() bool { return s.State == StateInstalled }

// StatusEntry is one stanza of the dpkg status file.
type StatusEntry struct {
	// Status is the parsed Status field. It is the zero value when the stanza
	// has none or the field is not valid.
	Status Status
	// Package holds the typed fields of the stanza. Unlike a package read with
	// [ControlFile.ParsePackage], Version and Architecture may be empty: dpkg
	// keeps stanzas for packages that were purged, or that only have a
	// configuration.
	Package *Package
	// Control is the stanza as written: every field, in document order, with
	// logical values (see [ControlFile]). Rendering it with [ControlFile.String]
	// gives a stanza dpkg reads back.
	Control *ControlFile
}

// Default limits of the status reader, applied where a [StatusOptions] field
// is zero.
const (
	// DefaultMaxStatusEntries bounds the stanzas of a status file.
	DefaultMaxStatusEntries = 1 << 20
	// DefaultMaxStatusBytes bounds the size of a status file, and of one
	// package's list file. A system with thousands of packages has a few
	// megabytes.
	DefaultMaxStatusBytes int64 = 256 << 20
	// maxListPaths bounds the paths of one package's list file.
	maxListPaths = 1 << 22
)

// StatusOptions configures [OpenStatus], [NewStatusDB] and [ReadInfoList]. The
// zero value is usable.
type StatusOptions struct {
	// Logger receives debug messages about skipped stanzas. Optional: nil
	// discards them.
	Logger *slog.Logger
	// MaxEntries bounds the stanzas read from a status file; reading more
	// fails with [ErrTooLarge]. Zero selects [DefaultMaxStatusEntries].
	MaxEntries int
	// MaxBytes bounds the size of the file read; a larger one fails with
	// [ErrTooLarge]. Zero selects [DefaultMaxStatusBytes].
	MaxBytes int64
}

func (o StatusOptions) normalized() StatusOptions {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}

	if o.MaxEntries <= 0 {
		o.MaxEntries = DefaultMaxStatusEntries
	}

	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxStatusBytes
	}

	return o
}

// statusFile is where dpkg keeps its database, relative to the root of the
// system.
const statusFile = "var/lib/dpkg/status"

// FindStatus looks for the dpkg status file under root, the directory that
// holds the system's /var: "/" for the running host, or the root of an image
// or an install directory. Symbolic links are followed only inside root. It
// returns [ErrStatusNotFound] when there is no regular file.
func FindStatus(root string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("%w: empty root", ErrStatusNotFound)
	}

	p, err := safepath.ResolveInRoot(root, statusFile)
	if err == nil {
		var fi os.FileInfo

		if fi, err = os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
	}

	return "", fmt.Errorf("%w under %s", ErrStatusNotFound, root)
}

// StatusDB is a dpkg status file. It is read-only and safe for concurrent use:
// every call reads the file again.
type StatusDB struct {
	ra     io.ReaderAt
	size   int64
	closer io.Closer
	opts   StatusOptions
}

// OpenStatus opens the dpkg status file at path. The file is only read, and
// not kept locked, so dpkg can run at the same time; a file that dpkg is
// rewriting is read as of the moment of each call.
func OpenStatus(path string, opts StatusOptions) (*StatusDB, error) {
	opts = opts.normalized()

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("deb: %w", err)
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()

		return nil, fmt.Errorf("deb: %w", err)
	}

	if !fi.Mode().IsRegular() {
		_ = f.Close()

		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInvalidStatus, path)
	}

	if fi.Size() > opts.MaxBytes {
		_ = f.Close()

		return nil, fmt.Errorf("%w: %s is %d bytes, the limit is %d", ErrTooLarge, path, fi.Size(), opts.MaxBytes)
	}

	return &StatusDB{ra: f, size: fi.Size(), closer: f, opts: opts}, nil
}

// NewStatusDB reads the status text that r holds, size bytes. Close does not
// close r. A size over [StatusOptions.MaxBytes] makes every read fail with
// [ErrTooLarge].
func NewStatusDB(r io.ReaderAt, size int64, opts StatusOptions) *StatusDB {
	return &StatusDB{ra: r, size: size, opts: opts.normalized()}
}

// Close releases the file of a database opened with [OpenStatus].
func (db *StatusDB) Close() error {
	if db.closer == nil {
		return nil
	}

	return db.closer.Close()
}

// Entries iterates over the stanzas of the file in order, installed or not. A
// stanza without a Package field is skipped, and reported at debug level to
// [StatusOptions.Logger]; a Status field that is not valid leaves the
// entry's Status at its zero value. The iteration ends with an error when the
// file is over its limits, cannot be read, or when ctx is done; the error is
// the last pair it yields. Stopping early releases everything.
func (db *StatusDB) Entries(ctx context.Context) iter.Seq2[*StatusEntry, error] {
	return func(yield func(*StatusEntry, error) bool) {
		if db.size > db.opts.MaxBytes {
			yield(nil, fmt.Errorf("%w: %d bytes, the limit is %d", ErrTooLarge, db.size, db.opts.MaxBytes))

			return
		}

		r := limitio.Capped(io.NewSectionReader(db.ra, 0, db.size), db.opts.MaxBytes, ErrTooLarge)

		seen := 0

		err := ScanControl(r, func(cf *ControlFile) error {
			if err := ctx.Err(); err != nil {
				return err
			}

			if seen++; seen > db.opts.MaxEntries {
				return fmt.Errorf("%w: more than %d stanzas", ErrTooLarge, db.opts.MaxEntries)
			}

			entry, ok := db.entry(cf, seen)
			if !ok {
				return nil
			}

			if !yield(entry, nil) {
				return errStopScan
			}

			return nil
		})
		if err != nil && !errors.Is(err, errStopScan) {
			yield(nil, err)
		}
	}
}

// entry builds the entry of stanza number n.
func (db *StatusDB) entry(cf *ControlFile, n int) (*StatusEntry, bool) {
	if cf.Get("Package") == "" {
		db.opts.Logger.Debug("deb: skipping a status stanza without a Package field", "stanza", n)

		return nil, false
	}

	e := &StatusEntry{Control: cf, Package: cf.parsePackage()}

	if value, ok := cf.Lookup("Status"); ok {
		status, err := ParseStatus(value)
		if err != nil {
			db.opts.Logger.Debug("deb: a status stanza has no valid Status", "stanza", n, "package", e.Package.Package, "error", err)
		} else {
			e.Status = status
		}
	}

	return e, true
}

// List returns every stanza: [StatusDB.Entries] collected into a slice.
func (db *StatusDB) List(ctx context.Context) ([]*StatusEntry, error) {
	var entries []*StatusEntry

	for e, err := range db.Entries(ctx) {
		if err != nil {
			return nil, err
		}

		entries = append(entries, e)
	}

	return entries, nil
}

// InstalledNames returns the names of the installed packages (see
// [Status.Installed]), sorted and without duplicates. A name has no
// architecture qualifier and counts once however many architectures of the
// package are installed.
func (db *StatusDB) InstalledNames(ctx context.Context) ([]string, error) {
	var names []string

	for e, err := range db.Entries(ctx) {
		if err != nil {
			return nil, err
		}

		if e.Status.Installed() {
			names = append(names, e.Package.Package)
		}
	}

	return sortedUnique(names), nil
}

// InstalledProvides returns the capabilities the installed packages provide
// (see [Status.Installed]), as names without version constraint or
// architecture qualifier, sorted and without duplicates. The name of each
// package is included, as it provides itself.
func (db *StatusDB) InstalledProvides(ctx context.Context) ([]string, error) {
	var provides []string

	for e, err := range db.Entries(ctx) {
		if err != nil {
			return nil, err
		}

		if !e.Status.Installed() {
			continue
		}

		provides = append(provides, e.Package.Package)
		provides = append(provides, DependencyNames(e.Package.Provides)...)
	}

	return sortedUnique(provides), nil
}

func sortedUnique(s []string) []string {
	slices.Sort(s)

	return slices.Compact(s)
}

// ReadInfoList returns the paths dpkg recorded for an installed package, from
// its "<name>.list" file in fsys, which is the directory /var/lib/dpkg/info
// (os.DirFS of it, or of a root's copy). dpkg qualifies the file name with the
// architecture for a package that is installed for several, "<name>:<arch>.list";
// that name is tried first when arch is not empty. The paths are as dpkg writes
// them, absolute ("/usr/bin/tool"), directories included, and in file order.
// The file is bounded by [StatusOptions.MaxBytes], and its paths by an entry
// limit; a larger list fails with [ErrTooLarge]. A package without a list
// returns an error that matches [fs.ErrNotExist].
func ReadInfoList(fsys fs.FS, name, arch string, opts StatusOptions) ([]string, error) {
	opts = opts.normalized()

	if name == "" || strings.ContainsAny(name, "/\x00") || strings.ContainsAny(arch, "/\x00") {
		return nil, fmt.Errorf("%w: %q:%q is not a package name", ErrInvalidStatus, clip(name), clip(arch))
	}

	candidates := []string{name + ".list"}
	if arch != "" {
		candidates = []string{name + ":" + arch + ".list", name + ".list"}
	}

	var err error

	for _, file := range candidates {
		var paths []string

		if paths, err = readList(fsys, file, opts); !errors.Is(err, fs.ErrNotExist) {
			return paths, err
		}
	}

	return nil, err
}

func readList(fsys fs.FS, file string, opts StatusOptions) ([]string, error) {
	f, err := fsys.Open(file)
	if err != nil {
		return nil, fmt.Errorf("deb: %w", err)
	}

	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(limitio.Capped(f, opts.MaxBytes, ErrTooLarge))
	sc.Buffer(make([]byte, 0, 4<<10), MaxLineBytes)

	var paths []string

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}

		if len(paths) >= maxListPaths {
			return nil, fmt.Errorf("%w: %s lists more than %d paths", ErrTooLarge, file, maxListPaths)
		}

		paths = append(paths, line)
	}

	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("%w: a line of %s is over %d bytes", ErrTooLarge, file, MaxLineBytes)
		}

		return nil, fmt.Errorf("deb: reading %s: %w", file, err)
	}

	return paths, nil
}
