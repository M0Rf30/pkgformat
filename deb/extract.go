package deb

import (
	"archive/tar"
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
	// DefaultMaxExtractEntries is the default limit on the archive entries
	// Extract processes.
	DefaultMaxExtractEntries = 1 << 20
)

// ExtractOptions tunes DebFile.Extract. The zero value applies the defaults.
type ExtractOptions struct {
	// MaxBytes bounds the total size of the regular files written. Zero means
	// DefaultMaxExtractBytes.
	MaxBytes int64
	// MaxEntries bounds the number of archive entries. Zero means
	// DefaultMaxExtractEntries.
	MaxEntries int
}

// Extract unpacks the data archive of the package into dir, which must exist.
// Entry paths are confined to dir, symlinks that point outside it are
// rejected, and device nodes and FIFOs are skipped. Owners are not applied and
// the setuid, setgid and sticky bits are dropped. Reaching a limit fails with
// ErrDataTooLarge; an entry that would leave dir fails with ErrUnsafeEntry.
func (d *DebFile) Extract(dir string, opts ExtractOptions) error {
	maxBytes, maxEntries := opts.MaxBytes, opts.MaxEntries
	if maxBytes <= 0 {
		maxBytes = DefaultMaxExtractBytes
	}

	if maxEntries <= 0 {
		maxEntries = DefaultMaxExtractEntries
	}

	rc, err := d.OpenData()
	if err != nil {
		return err
	}

	defer func() { _ = rc.Close() }()

	tr := tar.NewReader(rc)
	e := extractor{dir: dir, left: maxBytes}

	for n := 0; ; n++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("deb: reading data archive: %w", err)
		}

		if n >= maxEntries {
			return fmt.Errorf("%w: more than %d entries", ErrDataTooLarge, maxEntries)
		}

		if err := e.entry(hdr, tr); err != nil {
			return err
		}
	}
}

type extractor struct {
	dir  string
	left int64
}

func (e *extractor) entry(hdr *tar.Header, body io.Reader) error {
	switch hdr.Typeflag {
	case tar.TypeDir:
		target, err := e.resolve(hdr.Name)
		if err != nil {
			return err
		}

		return mkdir(target, hdr.FileInfo().Mode())
	case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // old archives use the NUL type
		return e.file(hdr, body)
	case tar.TypeSymlink:
		return e.symlink(hdr)
	case tar.TypeLink:
		return e.hardlink(hdr)
	default:
		return nil
	}
}

// resolve maps an archive path onto a host path inside dir.
func (e *extractor) resolve(name string) (string, error) {
	// ResolveInRoot clamps a ".." that climbs above dir; a hostile name is
	// an error here, not a silent relocation.
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
		return fmt.Errorf("deb: creating directory: %w", err)
	}

	return nil
}

func (e *extractor) file(hdr *tar.Header, body io.Reader) error {
	target, err := e.resolve(hdr.Name)
	if err != nil {
		return err
	}

	if hdr.Size > e.left {
		return fmt.Errorf("%w: byte limit reached at %q", ErrDataTooLarge, hdr.Name)
	}

	if err := mkdir(filepath.Dir(target), 0o755); err != nil {
		return err
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, hdr.FileInfo().Mode().Perm())
	if err != nil {
		return fmt.Errorf("deb: creating file: %w", err)
	}

	n, copyErr := io.Copy(out, io.LimitReader(body, hdr.Size))
	e.left -= n

	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}

	if copyErr != nil {
		return fmt.Errorf("deb: writing %q: %w", hdr.Name, copyErr)
	}

	return nil
}

func (e *extractor) symlink(hdr *tar.Header) error {
	if err := safepath.EntrySymlinkTarget(hdr.Name, hdr.Linkname); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeEntry, err)
	}

	target, err := e.resolveNew(hdr.Name)
	if err != nil {
		return err
	}

	if err := mkdir(filepath.Dir(target), 0o755); err != nil {
		return err
	}

	if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("deb: replacing %q: %w", hdr.Name, err)
	}

	if err := os.Symlink(hdr.Linkname, target); err != nil {
		return fmt.Errorf("deb: creating symlink: %w", err)
	}

	return nil
}

func (e *extractor) hardlink(hdr *tar.Header) error {
	source, err := e.resolve(hdr.Linkname)
	if err != nil {
		return err
	}

	target, err := e.resolveNew(hdr.Name)
	if err != nil {
		return err
	}

	if err := mkdir(filepath.Dir(target), 0o755); err != nil {
		return err
	}

	if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("deb: replacing %q: %w", hdr.Name, err)
	}

	if err := os.Link(source, target); err != nil {
		return fmt.Errorf("deb: creating link: %w", err)
	}

	return nil
}
