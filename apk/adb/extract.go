package adb

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/M0Rf30/pkgformat/safepath"
)

const (
	// DefaultMaxExtractBytes is the default limit on the bytes Extract writes.
	DefaultMaxExtractBytes int64 = 16 << 30
	// DefaultMaxExtractEntries is the default limit on the entries Extract
	// processes.
	DefaultMaxExtractEntries = 1 << 20
)

// ExtractOptions tunes [Extract]. A package is only unpacked once its
// signature has been checked, or once the caller has said that an unchecked
// package is acceptable.
type ExtractOptions struct {
	// Keyring holds the trusted public keys. The signatures of the package
	// are checked against it.
	Keyring *Keyring
	// AllowUntrusted accepts a package that carries no signature, or none by
	// a key of the keyring (or when there is no keyring). A signature of a
	// trusted key that does not verify is never accepted.
	AllowUntrusted bool
	// MaxBytes bounds the total size of the regular files written. Zero means
	// DefaultMaxExtractBytes.
	MaxBytes int64
	// MaxEntries bounds the number of entries. Zero means
	// DefaultMaxExtractEntries.
	MaxEntries int
	// Read bounds what is read.
	Read ReadOptions
}

// Extract unpacks the package read from r into dir, which must exist. Every
// path is confined to dir, symbolic links that point outside it are rejected,
// and devices and named pipes are skipped. Owners are not applied and the
// setuid, setgid and sticky bits are dropped. The content of every file is
// checked against the digest in the package. It returns the metadata of the
// package.
//
// Reaching a limit fails with [ErrDataTooLarge]; an entry that would leave dir
// fails with [ErrUnsafeEntry]; a package that is not trusted fails with
// [ErrUnsigned], [ErrUntrusted], [ErrNoKeyring] or [ErrBadSignature].
func Extract(r io.Reader, dir string, opts ExtractOptions) (*Package, error) {
	maxBytes, maxEntries := opts.MaxBytes, opts.MaxEntries
	if maxBytes <= 0 {
		maxBytes = DefaultMaxExtractBytes
	}

	if maxEntries <= 0 {
		maxEntries = DefaultMaxExtractEntries
	}

	if fi, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("adb: extraction directory: %w", err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("adb: extraction directory %q is not a directory", dir)
	}

	rd, err := NewReader(r, opts.Read)
	if err != nil {
		return nil, err
	}

	defer func() { _ = rd.Close() }()

	if err := checkTrust(rd, opts); err != nil {
		return nil, err
	}

	pkg, err := rd.Package()
	if err != nil {
		return nil, err
	}

	e := extractor{dir: dir, left: maxBytes}

	for n := 0; ; n++ {
		ent, err := rd.Next()
		if errors.Is(err, io.EOF) {
			return pkg, nil
		}

		if err != nil {
			return nil, err
		}

		if n >= maxEntries {
			return nil, fmt.Errorf("%w: more than %d entries", ErrDataTooLarge, maxEntries)
		}

		if err := e.entry(ent, rd); err != nil {
			return nil, err
		}
	}
}

func checkTrust(rd *Reader, opts ExtractOptions) error {
	if opts.Keyring == nil {
		if opts.AllowUntrusted {
			return nil
		}

		return ErrNoKeyring
	}

	_, err := rd.Verify(opts.Keyring)

	switch {
	case err == nil:
		return nil
	case opts.AllowUntrusted && (errors.Is(err, ErrUnsigned) || errors.Is(err, ErrUntrusted) || errors.Is(err, ErrNoKeyring)):
		return nil
	default:
		return err
	}
}

type extractor struct {
	dir  string
	left int64
}

func (e *extractor) entry(ent *Entry, body io.Reader) error {
	switch ent.Kind {
	case KindDir:
		target, err := e.resolve(ent.Name)
		if err != nil {
			return err
		}

		return mkdir(target, ent.Mode)
	case KindFile:
		return e.file(ent, body)
	case KindSymlink:
		return e.symlink(ent)
	case KindHardlink:
		return e.hardlink(ent)
	default:
		return nil
	}
}

// resolve maps a package path onto a host path inside dir.
func (e *extractor) resolve(name string) (string, error) {
	if _, err := safepath.Join(e.dir, name); err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrUnsafeEntry, name, err)
	}

	target, err := safepath.ResolveInRoot(e.dir, name)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrUnsafeEntry, name, err)
	}

	return target, nil
}

// resolveNew maps the path of an entry that is itself created (a symlink or
// link), resolving only its directory so that an existing symlink at the final
// component is replaced and not followed.
func (e *extractor) resolveNew(name string) (string, error) {
	if _, err := safepath.Join(e.dir, name); err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrUnsafeEntry, name, err)
	}

	dir, err := e.resolve(filepath.Dir(filepath.Clean("/" + name)))
	if err != nil {
		return "", err
	}

	base := filepath.Base(filepath.Clean("/" + name))
	if base == "/" || base == "." {
		return "", fmt.Errorf("%w: %q", ErrUnsafeEntry, name)
	}

	return filepath.Join(dir, base), nil
}

func mkdir(path string, mode fs.FileMode) error {
	// The owner keeps full access so that entries below can be written.
	if err := os.MkdirAll(path, mode.Perm()|0o700); err != nil {
		return fmt.Errorf("adb: creating directory: %w", err)
	}

	return nil
}

func (e *extractor) file(ent *Entry, body io.Reader) error {
	target, err := e.resolve(ent.Name)
	if err != nil {
		return err
	}

	if ent.Size > e.left {
		return fmt.Errorf("%w: byte limit reached at %q", ErrDataTooLarge, ent.Name)
	}

	if err := mkdir(filepath.Dir(target), 0o755); err != nil {
		return err
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, ent.Mode.Perm())
	if err != nil {
		return fmt.Errorf("adb: creating file: %w", err)
	}

	n, copyErr := io.Copy(out, body)
	e.left -= n

	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}

	if copyErr != nil {
		return fmt.Errorf("adb: writing %q: %w", ent.Name, copyErr)
	}

	return nil
}

func (e *extractor) symlink(ent *Entry) error {
	if err := safepath.EntrySymlinkTarget(ent.Name, ent.LinkTarget); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeEntry, err)
	}

	target, err := e.resolveNew(ent.Name)
	if err != nil {
		return err
	}

	if err := mkdir(filepath.Dir(target), 0o755); err != nil {
		return err
	}

	if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("adb: replacing %q: %w", ent.Name, err)
	}

	if err := os.Symlink(ent.LinkTarget, target); err != nil {
		return fmt.Errorf("adb: creating symlink: %w", err)
	}

	return nil
}

func (e *extractor) hardlink(ent *Entry) error {
	source, err := e.resolve(ent.LinkTarget)
	if err != nil {
		return err
	}

	target, err := e.resolveNew(ent.Name)
	if err != nil {
		return err
	}

	if err := mkdir(filepath.Dir(target), 0o755); err != nil {
		return err
	}

	if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("adb: replacing %q: %w", ent.Name, err)
	}

	if err := os.Link(source, target); err != nil {
		return fmt.Errorf("adb: creating link: %w", err)
	}

	return nil
}
