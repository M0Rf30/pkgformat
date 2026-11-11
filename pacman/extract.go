package pacman

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/M0Rf30/pkgformat/safepath"
)

const (
	// DefaultMaxExtractBytes is the default limit on the bytes Extract writes.
	DefaultMaxExtractBytes int64 = 16 << 30
	// DefaultMaxExtractEntries is the default limit on the archive entries
	// Extract processes.
	DefaultMaxExtractEntries = 1 << 20
)

// ExtractOptions tunes Extract. The zero value applies the defaults: the
// modes and modification times of the package, the owner of the extracting
// user, no special files and no extended attributes.
type ExtractOptions struct {
	// MaxBytes bounds the total size of the regular files written. Zero means
	// DefaultMaxExtractBytes.
	MaxBytes int64
	// MaxEntries bounds the number of archive entries. Zero means
	// DefaultMaxExtractEntries.
	MaxEntries int
	// Umask clears the given bits of every file and directory mode, as a unix
	// mask over the permission bits (0777) and the special bits: 07000 drops
	// setuid, setgid and sticky. The default applies the modes of the package
	// unchanged, as pacman does.
	Umask uint32
	// Chown applies the numeric owner of each entry. It needs the privilege to
	// chown; a failure is an error.
	Chown bool
	// SpecialFiles allows creating named pipes and device nodes. They are
	// skipped, with a logged warning, unless set. Device nodes need privileges.
	SpecialFiles bool
	// Xattrs applies the extended attributes of each entry, such as
	// security.capability for file capabilities. Without it they are dropped
	// with a logged warning. Only Linux supports them; elsewhere, setting them
	// fails.
	Xattrs bool
	// Metadata also writes the dot files that describe the package (.PKGINFO,
	// .BUILDINFO, .MTREE, .INSTALL, .CHANGELOG), which pacman does not
	// extract.
	Metadata bool
	// Verify checks what was written against the .MTREE of the package, as
	// VerifyPackage does, and fails with a *MtreeError or ErrNoMtree after the
	// extraction. The files stay in place. Owners and modes are compared with
	// what the package says, not with what the extraction could apply, so
	// IgnoreOwner is usually wanted when Chown is off.
	Verify bool
	// VerifyOptions tunes Verify.
	VerifyOptions VerifyOptions
	// Logger receives a warning for everything that is skipped. Nil discards.
	Logger *slog.Logger
}

// Extract unpacks a package into dir, which must exist, and returns what
// ReadPackage would: the .PKGINFO and the file list.
//
// Entry paths are confined to dir: they are resolved the way a chroot would,
// so a symbolic link of the package (an absolute "lib -> /usr/lib" included)
// cannot redirect a later entry out of dir, and a hard link or symbolic link
// that names something outside fails with ErrUnsafeEntry. A regular file
// replaces whatever is at its path; directories already there are kept and
// given the mode and time of the package at the end. Reaching a limit fails
// with ErrPackageTooLarge or ErrExtractTooLarge.
func Extract(r io.Reader, dir string, opts ExtractOptions) (*Package, error) {
	maxBytes, maxEntries := opts.MaxBytes, opts.MaxEntries
	if maxBytes <= 0 {
		maxBytes = DefaultMaxExtractBytes
	}

	if maxEntries <= 0 {
		maxEntries = DefaultMaxExtractEntries
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	x := &extractor{dir: dir, opts: opts, left: maxBytes, log: logger}

	var (
		verifier *packageVerifier
		pkg      = &Package{}
		count    int
	)

	if opts.Verify {
		verifier = newPackageVerifier(nil, opts.VerifyOptions)
	}

	err := WalkPackage(r, func(e *Entry, body io.Reader) error {
		if count++; count > maxEntries {
			return fmt.Errorf("%w: more than %d entries", ErrExtractTooLarge, maxEntries)
		}

		if e.IsMetadata() {
			return x.metadata(e, body, pkg, verifier)
		}

		name := e.Path
		if e.IsDir() {
			name += "/"
		}

		pkg.Files = append(pkg.Files, name)

		if verifier != nil {
			return x.entryVerified(e, body, verifier)
		}

		return x.entry(e, body)
	})
	if err != nil {
		return nil, err
	}

	if err := x.finishDirs(); err != nil {
		return nil, err
	}

	if pkg.Info == nil {
		return nil, ErrNoPkgInfo
	}

	if verifier != nil {
		if err := verifier.result(); err != nil {
			return nil, err
		}
	}

	return pkg, nil
}

// ErrExtractTooLarge reports that an extraction reached the limit of
// ExtractOptions.
var ErrExtractTooLarge = errors.New("pacman: extraction exceeds the limit")

type dirFixup struct {
	path string
	e    *Entry
}

type extractor struct {
	dir  string
	opts ExtractOptions
	left int64
	log  *slog.Logger
	dirs []dirFixup
}

// skipped logs the entry that is not extracted.
func (x *extractor) skipped(e *Entry, what string) {
	x.log.Warn("pacman: skipping entry", "path", e.Path, "reason", what)
}

// MaxMetadataBytes bounds one metadata member that Extract keeps in memory.
const MaxMetadataBytes = 1 << 30

// metadata handles a dot file: it is parsed for the result, fed to the
// verifier, and written when asked.
func (x *extractor) metadata(e *Entry, body io.Reader, pkg *Package, v *packageVerifier) error {
	if !e.IsRegular() {
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(body, MaxMetadataBytes+1))
	if err != nil {
		return fmt.Errorf("pacman: reading %s: %w", e.Path, err)
	}

	if int64(len(data)) > MaxMetadataBytes {
		return fmt.Errorf("%w: %s over %d bytes", ErrMetadataTooLarge, e.Path, MaxMetadataBytes)
	}

	switch {
	case e.Path == FilePkgInfo:
		if pkg.Info != nil {
			return fmt.Errorf("%w: duplicate .PKGINFO", ErrInvalidField)
		}

		if pkg.Info, err = ParsePkgInfo(bytes.NewReader(data)); err != nil {
			return err
		}
	case e.Path == FileMtree && v != nil:
		if v.mt, err = ParseMtree(bytes.NewReader(data)); err != nil {
			return err
		}
	}

	if v != nil && e.Path != FileMtree {
		if err := v.observe(e, bytes.NewReader(data)); err != nil {
			return err
		}
	}

	if !x.opts.Metadata {
		return nil
	}

	e.Size = int64(len(data))

	return x.entry(e, bytes.NewReader(data))
}

// entryVerified writes the entry while the verifier hashes what is written.
func (x *extractor) entryVerified(e *Entry, body io.Reader, v *packageVerifier) error {
	if !e.IsRegular() {
		v.record(e, 0, digestSums{})

		return x.entry(e, body)
	}

	d := newDigester(v.keys())

	if err := x.entry(e, io.TeeReader(body, d.w)); err != nil {
		return err
	}

	v.record(e, e.Size, d.sums())

	return nil
}

// resolve maps an archive path onto a host path inside dir, following the
// symbolic links that exist the way a chroot does.
func (x *extractor) resolve(name string) (string, error) {
	if _, err := safepath.Join(x.dir, name); err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrUnsafeEntry, name, err)
	}

	target, err := safepath.ResolveInRoot(x.dir, name)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrUnsafeEntry, name, err)
	}

	return target, nil
}

// resolveNew maps the path of an entry that is itself created, resolving only
// its directory so that what is at the final component is replaced and not
// followed.
func (x *extractor) resolveNew(name string) (string, error) {
	dir, base := filepath.Split(filepath.Clean("/" + name))
	if base == "" || base == "." || base == ".." {
		return "", fmt.Errorf("%w: %q", ErrUnsafeEntry, name)
	}

	parent, err := x.resolve(dir)
	if err != nil {
		return "", err
	}

	return filepath.Join(parent, base), nil
}

func (x *extractor) mode(m fs.FileMode) fs.FileMode {
	mask := fs.FileMode(x.opts.Umask & 0o777)
	out := m.Perm() &^ mask

	for _, b := range []struct {
		bit  fs.FileMode
		mask uint32
	}{{fs.ModeSetuid, 0o4000}, {fs.ModeSetgid, 0o2000}, {fs.ModeSticky, 0o1000}} {
		if m&b.bit != 0 && x.opts.Umask&b.mask == 0 {
			out |= b.bit
		}
	}

	return out
}

func (x *extractor) entry(e *Entry, body io.Reader) error {
	if e.Hardlink != "" {
		return x.hardlink(e)
	}

	switch typ := e.Mode.Type(); {
	case typ == fs.ModeDir:
		return x.mkdir(e)
	case typ == 0:
		return x.file(e, body)
	case typ == fs.ModeSymlink:
		return x.symlink(e)
	case typ == fs.ModeNamedPipe || typ&fs.ModeDevice != 0:
		return x.special(e)
	}

	x.skipped(e, "unsupported type")

	return nil
}

func (x *extractor) prepare(target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil { //nolint:gosec // target is resolved inside the root
		return fmt.Errorf("pacman: creating directory: %w", err)
	}

	if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) { //nolint:gosec // target is resolved inside the root
		var pe *fs.PathError

		// A directory in the way cannot be replaced by a file.
		if errors.As(err, &pe) {
			return fmt.Errorf("pacman: replacing %q: %w", target, err)
		}

		return err
	}

	return nil
}

// mkdir creates a directory. The mode and time are applied at the end, once
// nothing is written below it.
func (x *extractor) mkdir(e *Entry) error {
	target, err := x.resolve(e.Path)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(target, 0o700); err != nil { //nolint:gosec // target is resolved inside the root
		return fmt.Errorf("pacman: creating directory: %w", err)
	}

	x.dirs = append(x.dirs, dirFixup{target, e})

	return nil
}

func (x *extractor) file(e *Entry, body io.Reader) error {
	target, err := x.resolveNew(e.Path)
	if err != nil {
		return err
	}

	if e.Size > x.left {
		return fmt.Errorf("%w: byte limit reached at %q", ErrExtractTooLarge, e.Path)
	}

	if err := x.prepare(target); err != nil {
		return err
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // target is resolved inside the root
	if err != nil {
		return fmt.Errorf("pacman: creating file: %w", err)
	}

	n, copyErr := io.Copy(out, io.LimitReader(body, e.Size))
	x.left -= n

	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}

	if copyErr != nil {
		return fmt.Errorf("pacman: writing %q: %w", e.Path, copyErr)
	}

	return x.apply(target, e, true)
}

func (x *extractor) symlink(e *Entry) error {
	if err := safepath.EntrySymlinkTarget(e.Path, e.Linkname); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeEntry, err)
	}

	target, err := x.resolveNew(e.Path)
	if err != nil {
		return err
	}

	if err := x.prepare(target); err != nil {
		return err
	}

	if err := os.Symlink(e.Linkname, target); err != nil {
		return fmt.Errorf("pacman: creating symlink: %w", err)
	}

	return x.apply(target, e, false)
}

func (x *extractor) hardlink(e *Entry) error {
	source, err := x.resolveNew(e.Hardlink)
	if err != nil {
		return err
	}

	target, err := x.resolveNew(e.Path)
	if err != nil {
		return err
	}

	if err := x.prepare(target); err != nil {
		return err
	}

	if err := os.Link(source, target); err != nil {
		return fmt.Errorf("pacman: creating link: %w", err)
	}

	// The inode, and so its mode, owner, time and attributes, is the one of the
	// file it links to.
	return nil
}

func (x *extractor) special(e *Entry) error {
	if !x.opts.SpecialFiles {
		x.skipped(e, "special files are not enabled")

		return nil
	}

	target, err := x.resolveNew(e.Path)
	if err != nil {
		return err
	}

	if err := x.prepare(target); err != nil {
		return err
	}

	if err := mknod(target, e.Mode, e.DevMajor, e.DevMinor); err != nil {
		return fmt.Errorf("pacman: creating %q: %w", e.Path, err)
	}

	return x.apply(target, e, true)
}

// apply sets the owner, mode, extended attributes and time of an entry
// already created at path. Order matters: chown clears setuid and file
// capabilities, so it comes first.
func (x *extractor) apply(path string, e *Entry, follow bool) error {
	if x.opts.Chown {
		if err := os.Lchown(path, e.UID, e.GID); err != nil {
			return fmt.Errorf("pacman: chown %q: %w", e.Path, err)
		}
	}

	if follow {
		if err := os.Chmod(path, x.mode(e.Mode)); err != nil { //nolint:gosec // path is resolved inside the root
			return fmt.Errorf("pacman: chmod %q: %w", e.Path, err)
		}
	}

	if err := x.setXattrs(path, e); err != nil {
		return err
	}

	if !e.ModTime.IsZero() {
		if err := setLinkTimes(path, e.ModTime); err != nil {
			return fmt.Errorf("pacman: setting the time of %q: %w", e.Path, err)
		}
	}

	return nil
}

func (x *extractor) setXattrs(path string, e *Entry) error {
	if len(e.Xattrs) == 0 {
		return nil
	}

	if !x.opts.Xattrs {
		x.log.Warn("pacman: dropping extended attributes", "path", e.Path, "count", len(e.Xattrs))

		return nil
	}

	for _, name := range slices.Sorted(mapKeys(e.Xattrs)) {
		if err := setXattr(path, name, e.Xattrs[name]); err != nil {
			return fmt.Errorf("pacman: setting %s on %q: %w", name, e.Path, err)
		}
	}

	return nil
}

func mapKeys(m map[string][]byte) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// finishDirs gives the directories their modes, owners and times, deepest
// first so that setting a mode never blocks a later entry.
func (x *extractor) finishDirs() error {
	for _, d := range slices.Backward(x.dirs) {
		if x.opts.Chown {
			if err := os.Lchown(d.path, d.e.UID, d.e.GID); err != nil {
				return fmt.Errorf("pacman: chown %q: %w", d.e.Path, err)
			}
		}

		if err := os.Chmod(d.path, x.mode(d.e.Mode)); err != nil {
			return fmt.Errorf("pacman: chmod %q: %w", d.e.Path, err)
		}

		if err := x.setXattrs(d.path, d.e); err != nil {
			return err
		}

		if !d.e.ModTime.IsZero() {
			if err := setLinkTimes(d.path, d.e.ModTime); err != nil {
				return fmt.Errorf("pacman: setting the time of %q: %w", d.e.Path, err)
			}
		}
	}

	return nil
}
