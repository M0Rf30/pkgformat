package deb

import (
	"fmt"
	"io"
	"io/fs"
	"time"
)

// FSEntries lists the content of fsys as payload entries in lexical order:
// directories, regular files and symlinks. Other file types (devices, FIFOs,
// sockets) fail the call, as they cannot be part of a package built this way.
// The tree of a directory is os.DirFS(dir). Files are opened when Write reaches
// them, so the tree must stay unchanged until then.
//
// Entries get the modification time of their file, or modTime when it is not
// zero (use it for reproducible packages).
func FSEntries(fsys fs.FS, modTime time.Time) ([]Entry, error) {
	var entries []Entry

	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if p == "." {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		e := Entry{Path: p, Mode: info.Mode(), ModTime: modTime}
		if modTime.IsZero() {
			e.ModTime = info.ModTime()
		}

		switch {
		case info.IsDir():
		case info.Mode()&fs.ModeSymlink != 0:
			if e.Linkname, err = fs.ReadLink(fsys, p); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			e.Size = info.Size()
			e.Open = func() (io.ReadCloser, error) { return fsys.Open(p) }
		default:
			return fmt.Errorf("%w: %q has unsupported type %s", ErrInvalidSpec, p, info.Mode().Type())
		}

		entries = append(entries, e)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("deb: listing payload: %w", err)
	}

	return entries, nil
}
