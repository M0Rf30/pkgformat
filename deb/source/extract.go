package source

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/safepath"
)

// Default limits of [Unpack].
const (
	// DefaultMaxEntries bounds the archive entries of one source package.
	DefaultMaxEntries = 1 << 20
	// DefaultMaxBytes bounds the file bytes extracted from one source package.
	DefaultMaxBytes int64 = 8 << 30
)

// budget accounts the entries and the bytes extracted from a source package.
type budget struct {
	maxEntries int
	maxBytes   int64
	entries    int
	bytes      int64
}

func (b *budget) entry() error {
	b.entries++
	if b.entries > b.maxEntries {
		return fmt.Errorf("%w: more than %d archive entries", ErrTooLarge, b.maxEntries)
	}

	return nil
}

func (b *budget) data(n int64) error {
	b.bytes += n
	if b.bytes > b.maxBytes || b.bytes < 0 {
		return fmt.Errorf("%w: more than %d bytes extracted", ErrTooLarge, b.maxBytes)
	}

	return nil
}

// fixedDirMode and the file modes are what dpkg-source leaves after it fixes
// the permissions of an extracted tree under a 022 umask: owners can write,
// nobody else, and the execute bits are all or nothing.
const (
	fixedDirMode  fs.FileMode = 0o755
	fixedFileMode fs.FileMode = 0o644
	fixedExecMode fs.FileMode = 0o755
)

// extractTar extracts the tar file archive (compressed according to its name)
// below root. skip, when set, is asked about every cleaned entry name and
// drops the entries it accepts (with everything below a skipped directory).
func extractTar(archive, root string, skip func(name string) bool, b *budget) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}

	rc, err := openCompressed(f, archive)
	if err != nil {
		return err
	}

	defer rc.Close()

	tr := tar.NewReader(rc)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("source: %s: %w", filepath.Base(archive), err)
		}

		if err := extractEntry(tr, hdr, root, skip, b); err != nil {
			return fmt.Errorf("source: %s: %w", filepath.Base(archive), err)
		}
	}
}

func cleanEntryName(name string) string {
	name = strings.TrimLeft(name, "/")

	return path.Clean(name)
}

func extractEntry(tr *tar.Reader, hdr *tar.Header, root string, skip func(string) bool, b *budget) error {
	if hdr.Typeflag == tar.TypeXGlobalHeader {
		return nil
	}

	if err := b.entry(); err != nil {
		return err
	}

	name := cleanEntryName(hdr.Name)
	if name == "." {
		return nil
	}

	if skip != nil && skip(name) {
		return nil
	}

	target, err := safepath.JoinStrict(root, name)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafe, err)
	}

	switch hdr.Typeflag {
	case tar.TypeDir:
		return makeDir(root, name)
	case tar.TypeReg:
		if err := b.data(hdr.Size); err != nil {
			return err
		}

		return writeFile(root, name, target, tr, hdr)
	case tar.TypeSymlink:
		if err := safepath.EntrySymlinkTarget(name, hdr.Linkname); err != nil {
			return fmt.Errorf("%w: %w", ErrUnsafe, err)
		}

		if err := prepareParent(root, name); err != nil {
			return err
		}

		if err := removeExisting(target); err != nil {
			return err
		}

		return os.Symlink(hdr.Linkname, target)
	case tar.TypeLink:
		return makeHardLink(root, name, target, hdr.Linkname)
	}

	return fmt.Errorf("%w: %q is a special file (type %q)", ErrUnsafe, hdr.Name, string(hdr.Typeflag))
}

// prepareParent creates the parent directories of root/name and refuses to
// walk through a symlink: a link that an archive planted must not redirect a
// later entry.
func prepareParent(root, name string) error {
	dir := path.Dir(name)
	if dir == "." {
		return nil
	}

	return walkDirs(root, dir)
}

// walkDirs creates the directories of rel below root one component at a time.
func walkDirs(root, rel string) error {
	cur := root

	for _, part := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, part)

		st, err := os.Lstat(cur)

		switch {
		case err == nil && st.IsDir():
			continue
		case err == nil:
			return fmt.Errorf("%w: %q is not a directory", ErrUnsafe, rel)
		case !errors.Is(err, fs.ErrNotExist):
			return err
		}

		if err := os.Mkdir(cur, fixedDirMode); err != nil {
			return err
		}
	}

	return nil
}

func makeDir(root, name string) error {
	if err := prepareParent(root, name); err != nil {
		return err
	}

	dir := filepath.Join(root, filepath.FromSlash(name))

	st, err := os.Lstat(dir)

	switch {
	case err == nil && st.IsDir():
		return os.Chmod(dir, fixedDirMode)
	case err == nil:
		if err := os.Remove(dir); err != nil {
			return err
		}
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}

	return os.Mkdir(dir, fixedDirMode)
}

// removeExisting removes a file or symlink in the way of a new entry. A
// directory is not removed: an archive that replaces a directory by a file is
// refused.
func removeExisting(p string) error {
	st, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return err
	}

	if st.IsDir() {
		return fmt.Errorf("%w: a directory is in the way of %q", ErrUnsafe, filepath.Base(p))
	}

	return os.Remove(p)
}

func writeFile(root, name, target string, r io.Reader, hdr *tar.Header) error {
	if err := prepareParent(root, name); err != nil {
		return err
	}

	if err := removeExisting(target); err != nil {
		return err
	}

	mode := fixedFileMode
	if hdr.Mode&0o111 != 0 {
		mode = fixedExecMode
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}

	if _, err := io.CopyN(out, r, hdr.Size); err != nil {
		_ = out.Close()

		return err
	}

	if err := out.Close(); err != nil {
		return err
	}

	if err := os.Chmod(target, mode); err != nil {
		return err
	}

	if !hdr.ModTime.IsZero() {
		return os.Chtimes(target, hdr.ModTime, hdr.ModTime)
	}

	return nil
}

func makeHardLink(root, name, target, linkname string) error {
	ln := cleanEntryName(linkname)

	src, err := safepath.JoinStrict(root, ln)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafe, err)
	}

	if err := prepareParent(root, ln); err != nil {
		return err
	}

	st, err := os.Lstat(src)
	if err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%w: hard link %q to %q, which is not an extracted file", ErrUnsafe, name, linkname)
	}

	if err := prepareParent(root, name); err != nil {
		return err
	}

	if err := removeExisting(target); err != nil {
		return err
	}

	return os.Link(src, target)
}

// extractReplacing extracts archive into dest, which is replaced: dest is
// extracted to a scratch directory first, and when the archive holds a single
// top-level directory that directory becomes dest, as dpkg-source does.
func extractReplacing(archive, dest string, skip func(string) bool, b *budget) error {
	tmp, err := os.MkdirTemp(filepath.Dir(dest), ".extract-*")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tmp)

	if err := extractTar(archive, tmp, skip, b); err != nil {
		return err
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		return err
	}

	src := tmp

	if len(entries) == 1 && entries[0].Type().IsDir() {
		src = filepath.Join(tmp, entries[0].Name())
	}

	if err := os.RemoveAll(dest); err != nil {
		return err
	}

	if err := os.Chmod(src, fixedDirMode); err != nil {
		return err
	}

	return os.Rename(src, dest)
}

// openCompressed decompresses r according to the extension of name; closing
// the result closes r.
func openCompressed(r io.Reader, name string) (io.ReadCloser, error) {
	rc, err := deb.OpenIndex(r, name)
	if err != nil {
		return nil, fmt.Errorf("source: %s: %w", filepath.Base(name), err)
	}

	return rc, nil
}
