package pacman

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"

	"github.com/M0Rf30/pkgformat/internal/pathseg"
)

// maxLocalMtreeBytes bounds the compressed mtree member of a package directory.
const maxLocalMtreeBytes = 256 << 20

// ErrNoLocalMtree reports a package directory without an mtree member. Old
// packages and some tools leave it out; pacman -Qk falls back to the file
// list then.
var ErrNoLocalMtree = errors.New("pacman: installed package has no mtree")

// Mtree reads and parses the mtree member of an installed package: the .MTREE
// of the package it came from, which pacman copies into the local database. It
// returns ErrNoLocalMtree when there is none.
func (db *LocalDB) Mtree(pkg *InstalledPackage) (*Mtree, error) {
	if pkg == nil || pkg.Dir == "" || !pathseg.Name(pkg.Dir) {
		return nil, fmt.Errorf("%w: no package directory", ErrInvalidLocalDB)
	}

	data, err := readLimited(db.fsys, pkg.Dir+"/mtree", maxLocalMtreeBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNoLocalMtree, pkg.Dir)
	}

	if err != nil {
		return nil, fmt.Errorf("pacman: reading the mtree of %s: %w", pkg.Dir, err)
	}

	mt, err := ParseMtree(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pkg.Dir, err)
	}

	return mt, nil
}

// VerifyInstalled checks the files of an installed package against its mtree,
// like pacman -Qkk: type, mode, owner, size, time, link target and digests.
// root is the root of the system the package is installed in; give it an
// fs.FS that implements fs.ReadLinkFS and stays inside the root, such as
// os.OpenRoot(dir).FS(). The backup files of the package (pkg.Backup) are
// exempt from the size, time and digest checks, because the user edits them.
// It returns nil when everything matches, ErrNoLocalMtree when the package has
// no mtree, and otherwise a *MtreeError.
func (db *LocalDB) VerifyInstalled(pkg *InstalledPackage, root fs.FS, opts VerifyOptions) error {
	mt, err := db.Mtree(pkg)
	if err != nil {
		return err
	}

	backup := make(map[string]bool, len(pkg.Backup))
	for _, b := range pkg.Backup {
		backup[b.Path] = true
	}

	prev := opts.SkipContent

	opts.SkipContent = func(p string) bool {
		return backup[p] || prev != nil && prev(p)
	}

	return VerifyInstalled(root, mt, opts)
}
