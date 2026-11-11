package pacman

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

// localMtreeDB builds a local database holding the package of the makepkg
// fixture, with its .MTREE as the mtree member, and an installed root.
func localMtreeDB(t *testing.T) (*LocalDB, *InstalledPackage, string) {
	t.Helper()

	root, _ := installed(t)

	var mtree []byte

	err := WalkPackage(bytes.NewReader(fixtureBytes(t)), func(e *Entry, body io.Reader) error {
		if e.Path == FileMtree {
			var err error

			mtree, err = io.ReadAll(body)

			return err
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	dir := "tree-shapes-1.0-1"
	fsys := fstest.MapFS{
		"ALPM_DB_VERSION": {Data: []byte("9\n")},
		dir + "/desc":     {Data: []byte("%NAME%\ntree-shapes\n\n%VERSION%\n1.0-1\n\n")},
		dir + "/files":    {Data: []byte("%FILES%\netc/\netc/shapes.conf\n\n%BACKUP%\netc/shapes.conf\tdeadbeef\n")},
		dir + "/mtree":    {Data: mtree},
	}

	db := NewLocalDB(fsys, LocalDBOptions{})

	pkgs, err := db.List(context.Background())
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("List: %v %v", pkgs, err)
	}

	return db, pkgs[0], root
}

func TestLocalDBMtreeAndVerify(t *testing.T) {
	t.Parallel()

	db, pkg, root := localMtreeDB(t)

	mt, err := db.Mtree(pkg)
	if err != nil {
		t.Fatal(err)
	}

	if len(mt.Entries) != 18 {
		t.Errorf("%d entries", len(mt.Entries))
	}

	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = r.Close() }()

	opts := VerifyOptions{IgnoreOwner: true}

	if err := db.VerifyInstalled(pkg, r.FS(), opts); err != nil {
		t.Fatalf("clean install: %v", err)
	}

	// A user's edit of a backup file is not an alteration; of anything else it is.
	write(t, root, "etc/shapes.conf", "edited by the user\n")
	touch(t, root, "etc/shapes.conf")

	if err := db.VerifyInstalled(pkg, r.FS(), opts); err != nil {
		t.Errorf("edited backup file: %v", err)
	}

	write(t, root, "usr/share/tagged", "tampered\n")

	var me *MtreeError
	if err := db.VerifyInstalled(pkg, r.FS(), opts); !errors.As(err, &me) || me.Diffs[0].Path != "usr/share/tagged" {
		t.Errorf("edited binary: %v", err)
	}

	// The caller's own exemption is kept next to the backup files.
	opts.SkipContent = func(p string) bool { return p == "usr/share/tagged" }
	if err := db.VerifyInstalled(pkg, r.FS(), opts); err != nil {
		t.Errorf("with SkipContent: %v", err)
	}
}

func TestLocalDBMtreeErrors(t *testing.T) {
	t.Parallel()

	fsys := fstest.MapFS{
		"ALPM_DB_VERSION": {Data: []byte("9\n")},
		"a-1/desc":        {Data: []byte("%NAME%\na\n\n%VERSION%\n1-1\n\n")},
		"b-1/desc":        {Data: []byte("%NAME%\nb\n\n%VERSION%\n1-1\n\n")},
		"b-1/mtree":       {Data: []byte("./x type=weird\n")},
	}

	db := NewLocalDB(fsys, LocalDBOptions{})

	pkgs, err := db.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]*InstalledPackage{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, err := db.Mtree(byName["a"]); !errors.Is(err, ErrNoLocalMtree) {
		t.Errorf("no mtree: %v", err)
	}

	if err := db.VerifyInstalled(byName["a"], fsys, VerifyOptions{}); !errors.Is(err, ErrNoLocalMtree) {
		t.Errorf("verify without mtree: %v", err)
	}

	if _, err := db.Mtree(byName["b"]); !errors.Is(err, ErrInvalidMtree) || !strings.Contains(err.Error(), "b-1") {
		t.Errorf("bad mtree: %v", err)
	}

	for _, p := range []*InstalledPackage{nil, {}, {Dir: "../x"}} {
		if _, err := db.Mtree(p); !errors.Is(err, ErrInvalidLocalDB) {
			t.Errorf("package %+v: %v", p, err)
		}
	}
}
