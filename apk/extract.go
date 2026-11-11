package apk

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/M0Rf30/pkgformat/safepath"
)

// Errors of [Archive.Extract].
var (
	// ErrUnsafeEntry is returned for an entry whose path or link would leave
	// the destination directory.
	ErrUnsafeEntry = errors.New("apk: unsafe entry")
	// ErrExtractLimit is returned when the entries or bytes of a package
	// exceed the limits of [ExtractOptions].
	ErrExtractLimit = errors.New("apk: extraction limit reached")
	// ErrUnsupported is returned when an option asks for something the
	// platform cannot do (device nodes, extended attributes or owners).
	ErrUnsupported = errors.New("apk: not supported on this platform")
)

// Defaults of the limits of [ExtractOptions].
const (
	DefaultMaxExtractBytes   int64 = 16 << 30
	DefaultMaxExtractEntries       = 1 << 20
)

// ExtractOptions tunes [Archive.Extract]. The zero value extracts regular
// files, directories, symbolic links, hard links and FIFOs as the current
// user, with the permission bits and modification times of the package, and
// without the setuid, setgid and sticky bits, owners, device nodes and
// extended attributes.
type ExtractOptions struct {
	// MaxBytes bounds the content bytes written. Zero is
	// [DefaultMaxExtractBytes].
	MaxBytes int64
	// MaxEntries bounds the entries processed. Zero is
	// [DefaultMaxExtractEntries].
	MaxEntries int
	// Owners applies the numeric owner of each entry (it needs the
	// privilege to chown) and keeps the setuid, setgid and sticky bits.
	Owners bool
	// Devices creates character and block device nodes (it needs the
	// privilege to mknod). Without it a device entry is skipped.
	Devices bool
	// Xattrs sets the extended attributes of each entry, such as the file
	// capabilities in security.capability. Setting that attribute needs
	// CAP_SETFCAP.
	Xattrs bool
}

// Extract unpacks the data segment into dir, which must exist. Every path is
// confined to dir: a name or a symbolic link that would leave it fails with
// [ErrUnsafeEntry], and an existing symbolic link in the way is never
// followed out of dir. The checksum of every regular file is verified as it is
// written ([ErrChecksum]); a file that fails is removed. Directory modes and
// times are applied after their content, so a read-only directory can be
// filled.
func (a *Archive) Extract(dir string, opts ExtractOptions) error {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxExtractBytes
	}

	if opts.MaxEntries <= 0 {
		opts.MaxEntries = DefaultMaxExtractEntries
	}

	if info, err := os.Stat(dir); err != nil {
		return fmt.Errorf("apk: extraction directory: %w", err)
	} else if !info.IsDir() {
		return fmt.Errorf("apk: extraction directory %q is not a directory", short(dir))
	}

	x := &extractor{dir: dir, opts: opts, left: opts.MaxBytes}

	n := 0

	err := a.Walk(func(e *Entry, content io.Reader) error {
		n++
		if n > opts.MaxEntries {
			return fmt.Errorf("%w: more than %d entries", ErrExtractLimit, opts.MaxEntries)
		}

		return x.entry(e, content)
	})
	if err != nil {
		if errors.Is(err, ErrChecksum) && x.last != "" {
			_ = os.Remove(x.last)
		}

		return err
	}

	return x.finishDirs()
}

type extractor struct {
	dir  string
	opts ExtractOptions
	left int64
	dirs []dirMeta
	// last is the regular file written most recently: the one a checksum
	// failure, which Walk reports after the content is written, concerns.
	last string
}

// dirMeta is what is applied to a directory once its content is in place.
type dirMeta struct {
	path  string
	mode  fs.FileMode
	mtime time.Time
}

func (x *extractor) entry(e *Entry, content io.Reader) error {
	switch e.Type {
	case TypeDir:
		return x.dir1(e)
	case TypeRegular:
		return x.file(e, content)
	case TypeSymlink:
		return x.symlink(e)
	case TypeHardlink:
		return x.hardlink(e)
	case TypeFIFO:
		return x.fifo(e)
	case TypeCharDevice, TypeBlockDevice:
		if !x.opts.Devices {
			return nil
		}

		return x.device(e)
	default:
		return nil
	}
}

// resolve maps an archive path onto a host path inside dir, following the
// symbolic links of its directories only while they stay inside dir.
func (x *extractor) resolve(name string) (string, error) {
	if _, err := safepath.Join(x.dir, name); err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrUnsafeEntry, short(name), err)
	}

	target, err := safepath.ResolveInRoot(x.dir, name)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrUnsafeEntry, short(name), err)
	}

	return target, nil
}

// resolveNew maps the path of an entry that is created itself, resolving only
// its directory so that an existing symbolic link at the last element is
// replaced and not followed.
func (x *extractor) resolveNew(name string) (string, error) {
	parent, err := x.resolve(filepath.Dir(filepath.Clean("/" + name)))
	if err != nil {
		return "", err
	}

	base := filepath.Base(filepath.Clean("/" + name))
	if base == "/" || base == "." {
		return "", fmt.Errorf("%w: %q", ErrUnsafeEntry, short(name))
	}

	if _, err := safepath.Join(x.dir, name); err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrUnsafeEntry, short(name), err)
	}

	return filepath.Join(parent, base), nil
}

// mode returns the permission bits to apply to an entry.
func (x *extractor) mode(e *Entry) fs.FileMode {
	if x.opts.Owners {
		return e.Mode
	}

	return e.Mode.Perm()
}

// prepare creates the parent directory of target and removes what is there.
func (x *extractor) prepare(e *Entry, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil { //nolint:gosec // the path was confined to the extraction directory by safepath
		return fmt.Errorf("apk: creating directory for %q: %w", short(e.Name), err)
	}

	if info, err := os.Lstat(target); err == nil { //nolint:gosec // the path was confined to the extraction directory by safepath
		if info.IsDir() {
			return fmt.Errorf("%w: %q replaces a directory", ErrUnsafeEntry, short(e.Name))
		}

		if err := os.Remove(target); err != nil { //nolint:gosec // the path was confined to the extraction directory by safepath
			return fmt.Errorf("apk: replacing %q: %w", short(e.Name), err)
		}
	}

	return nil
}

func (x *extractor) dir1(e *Entry) error {
	target, err := x.resolve(e.Name)
	if err != nil {
		return err
	}

	// The owner keeps full access until the content is in; the real mode is
	// applied by finishDirs.
	if err := os.MkdirAll(target, 0o700); err != nil { //nolint:gosec // the path was confined to the extraction directory by safepath
		return fmt.Errorf("apk: creating directory %q: %w", short(e.Name), err)
	}

	if err := x.own(e, target); err != nil {
		return err
	}

	if err := x.attrs(e, target); err != nil {
		return err
	}

	x.dirs = append(x.dirs, dirMeta{path: target, mode: x.mode(e), mtime: e.ModTime})

	return nil
}

func (x *extractor) finishDirs() error {
	// Deepest first, so a directory's own time is not disturbed by its
	// children.
	sort.SliceStable(x.dirs, func(i, j int) bool { return len(x.dirs[i].path) > len(x.dirs[j].path) })

	for _, d := range x.dirs {
		if err := os.Chmod(d.path, d.mode); err != nil {
			return fmt.Errorf("apk: setting the mode of %q: %w", d.path, err)
		}

		if err := os.Chtimes(d.path, d.mtime, d.mtime); err != nil {
			return fmt.Errorf("apk: setting the time of %q: %w", d.path, err)
		}
	}

	return nil
}

func (x *extractor) file(e *Entry, content io.Reader) error {
	target, err := x.resolveNew(e.Name)
	if err != nil {
		return err
	}

	if e.Size > x.left {
		return fmt.Errorf("%w: byte limit reached at %q", ErrExtractLimit, short(e.Name))
	}

	if err := x.prepare(e, target); err != nil {
		return err
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the path was confined to the extraction directory by safepath
	if err != nil {
		return fmt.Errorf("apk: creating %q: %w", short(e.Name), err)
	}

	n, copyErr := io.Copy(out, content)
	x.left -= n

	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}

	if copyErr != nil {
		_ = os.Remove(target) //nolint:gosec // the path was confined to the extraction directory by safepath

		return fmt.Errorf("apk: writing %q: %w", short(e.Name), copyErr)
	}

	// Walk checks the checksum when this call returns; Extract then removes
	// the file named by last if it fails.
	x.last = target

	return x.finishFile(e, target)
}

// finishFile applies mode, owner, attributes and time to a created file.
func (x *extractor) finishFile(e *Entry, target string) error {
	if err := x.own(e, target); err != nil {
		return err
	}

	// chmod after chown: chown clears setuid and setgid.
	if err := os.Chmod(target, x.mode(e)); err != nil { //nolint:gosec // the path was confined to the extraction directory by safepath
		return fmt.Errorf("apk: setting the mode of %q: %w", short(e.Name), err)
	}

	if err := x.attrs(e, target); err != nil {
		return err
	}

	if err := os.Chtimes(target, e.ModTime, e.ModTime); err != nil {
		return fmt.Errorf("apk: setting the time of %q: %w", short(e.Name), err)
	}

	return nil
}

func (x *extractor) symlink(e *Entry) error {
	if err := safepath.EntrySymlinkTarget(e.Name, e.LinkTarget); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeEntry, err)
	}

	target, err := x.resolveNew(e.Name)
	if err != nil {
		return err
	}

	if err := x.prepare(e, target); err != nil {
		return err
	}

	if err := os.Symlink(e.LinkTarget, target); err != nil {
		return fmt.Errorf("apk: creating symbolic link %q: %w", short(e.Name), err)
	}

	if err := x.own(e, target); err != nil {
		return err
	}

	return x.attrs(e, target)
}

func (x *extractor) hardlink(e *Entry) error {
	source, err := x.resolve(e.LinkTarget)
	if err != nil {
		return err
	}

	target, err := x.resolveNew(e.Name)
	if err != nil {
		return err
	}

	info, err := os.Lstat(source) //nolint:gosec // the path was confined to the extraction directory by safepath
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: hard link %q: %q is not an extracted regular file",
			ErrUnsafeEntry, short(e.Name), short(e.LinkTarget))
	}

	if err := x.prepare(e, target); err != nil {
		return err
	}

	if err := os.Link(source, target); err != nil {
		return fmt.Errorf("apk: creating hard link %q: %w", short(e.Name), err)
	}

	return nil
}

func (x *extractor) fifo(e *Entry) error {
	target, err := x.resolveNew(e.Name)
	if err != nil {
		return err
	}

	if err := x.prepare(e, target); err != nil {
		return err
	}

	if err := mkfifo(target, uint32(x.mode(e).Perm())); err != nil {
		return fmt.Errorf("apk: creating FIFO %q: %w", short(e.Name), err)
	}

	if err := x.own(e, target); err != nil {
		return err
	}

	return x.attrs(e, target)
}

func (x *extractor) device(e *Entry) error {
	target, err := x.resolveNew(e.Name)
	if err != nil {
		return err
	}

	if err := x.prepare(e, target); err != nil {
		return err
	}

	if err := mknod(target, e.Type == TypeCharDevice, uint32(x.mode(e).Perm()), e.DevMajor, e.DevMinor); err != nil {
		return fmt.Errorf("apk: creating device %q: %w", short(e.Name), err)
	}

	if err := x.own(e, target); err != nil {
		return err
	}

	return x.attrs(e, target)
}

// own applies the owner of e when asked.
func (x *extractor) own(e *Entry, target string) error {
	if !x.opts.Owners {
		return nil
	}

	if err := lchown(target, e.UID, e.GID); err != nil {
		return fmt.Errorf("apk: setting the owner of %q: %w", short(e.Name), err)
	}

	return nil
}

// attrs sets the extended attributes of e when asked, names in order.
func (x *extractor) attrs(e *Entry, target string) error {
	if !x.opts.Xattrs || len(e.Xattrs) == 0 {
		return nil
	}

	names := make([]string, 0, len(e.Xattrs))
	for k := range e.Xattrs {
		names = append(names, k)
	}

	sort.Strings(names)

	for _, k := range names {
		if err := lsetxattr(target, k, e.Xattrs[k]); err != nil {
			return fmt.Errorf("apk: setting %s on %q: %w", k, short(e.Name), err)
		}
	}

	return nil
}
