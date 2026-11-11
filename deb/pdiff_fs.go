package deb

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"sync"
)

// PDiffFS is the storage a PDiffIndexBuilder maintains a Packages.diff
// directory in. It is rooted at the directory that holds the index file
// (dists/<dist>/<component>/binary-<arch>) and addresses files by
// slash-separated names relative to it: "Packages.diff/Index",
// "Packages.diff/<patch>.gz", "Packages.xz".
//
// Implementations must make WriteFile atomic (readers see the old or the new
// content, never a partial file), create missing directories, and report a
// missing file as an error that wraps fs.ErrNotExist.
type PDiffFS interface {
	// ReadFile returns the content of the named file.
	ReadFile(name string) ([]byte, error)
	// WriteFile replaces the named file.
	WriteFile(name string, data []byte) error
	// Remove deletes the named file; a file that is already gone is not an error.
	Remove(name string) error
	// ReadDir lists the names (not paths) of the regular files directly inside
	// dir; a directory that does not exist has none.
	ReadDir(dir string) ([]string, error)
}

// PDiffMemFS is an in-memory PDiffFS.
type PDiffMemFS struct {
	mu    sync.Mutex
	files map[string][]byte
}

// NewPDiffMemFS returns an empty in-memory PDiffFS.
func NewPDiffMemFS() *PDiffMemFS { return &PDiffMemFS{files: map[string][]byte{}} }

// Names returns the names of all files, sorted.
func (m *PDiffMemFS) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	names := make([]string, 0, len(m.files))
	for n := range m.files {
		names = append(names, n)
	}

	sort.Strings(names)

	return names
}

// ReadFile implements PDiffFS.
func (m *PDiffMemFS) ReadFile(name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, ok := m.files[path.Clean(name)]
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrNotExist}
	}

	return append([]byte(nil), data...), nil
}

// WriteFile implements PDiffFS.
func (m *PDiffMemFS) WriteFile(name string, data []byte) error {
	if !fs.ValidPath(name) || name == "." {
		return &fs.PathError{Op: "write", Path: name, Err: fs.ErrInvalid}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.files[name] = append([]byte(nil), data...)

	return nil
}

// Remove implements PDiffFS.
func (m *PDiffMemFS) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.files, path.Clean(name))

	return nil
}

// ReadDir implements PDiffFS.
func (m *PDiffMemFS) ReadDir(dir string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []string

	for n := range m.files {
		if path.Dir(n) == path.Clean(dir) {
			out = append(out, path.Base(n))
		}
	}

	sort.Strings(out)

	return out, nil
}

// PDiffDirFS is a PDiffFS on a directory of the file system. All access goes
// through an os.Root, so no name can reach outside the directory, whatever it
// contains.
type PDiffDirFS struct {
	root *os.Root
}

// NewPDiffDirFS opens dir, creating it when it does not exist, as a PDiffFS.
// Close it when done.
func NewPDiffDirFS(dir string) (*PDiffDirFS, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // a published repository is world readable
		return nil, fmt.Errorf("deb: %w", err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("deb: %w", err)
	}

	return &PDiffDirFS{root: root}, nil
}

// Close releases the directory.
func (d *PDiffDirFS) Close() error { return d.root.Close() }

// ReadFile implements PDiffFS.
func (d *PDiffDirFS) ReadFile(name string) ([]byte, error) { return d.root.ReadFile(name) }

// WriteFile implements PDiffFS: the content goes to a temporary file in the
// same directory that is renamed over the target.
func (d *PDiffDirFS) WriteFile(name string, data []byte) error {
	if !fs.ValidPath(name) || name == "." {
		return &fs.PathError{Op: "write", Path: name, Err: fs.ErrInvalid}
	}

	if dir := path.Dir(name); dir != "." {
		if err := d.root.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("deb: %w", err)
		}
	}

	tmp := name + ".tmp"
	if err := d.root.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("deb: %w", err)
	}

	if err := d.root.Rename(tmp, name); err != nil {
		_ = d.root.Remove(tmp)

		return fmt.Errorf("deb: %w", err)
	}

	return nil
}

// Remove implements PDiffFS.
func (d *PDiffDirFS) Remove(name string) error {
	if err := d.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("deb: %w", err)
	}

	return nil
}

// ReadDir implements PDiffFS.
func (d *PDiffDirFS) ReadDir(dir string) ([]string, error) {
	f, err := d.root.Open(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}

		return nil, fmt.Errorf("deb: %w", err)
	}

	defer f.Close()

	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("deb: %w", err)
	}

	var out []string

	for _, e := range entries {
		if e.Type().IsRegular() {
			out = append(out, e.Name())
		}
	}

	sort.Strings(out)

	return out, nil
}
