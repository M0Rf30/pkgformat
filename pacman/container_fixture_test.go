package pacman

import (
	"bytes"
	"context"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestContainerFixture reads what pacman wrote when it installed the package
// of testdata/container (see generate.sh): the local database entry agrees
// with the package this module wrote.
func TestContainerFixture(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("testdata/container/shapes-1.0-1-any.pkg.tar.zst")
	if err != nil {
		t.Fatal(err)
	}

	md, err := ReadMetadata(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	db := NewLocalDB(os.DirFS("testdata/container/local"), LocalDBOptions{})

	pkgs, err := db.List(context.Background())
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("List: %v %v", pkgs, err)
	}

	pkg := pkgs[0]
	if pkg.Name != "shapes" || pkg.Version != "1.0-1" || len(pkg.Backup) != 1 || pkg.Backup[0].Path != "etc/shapes.conf" {
		t.Errorf("package %+v", pkg)
	}

	mt, err := db.Mtree(pkg)
	if err != nil {
		t.Fatal(err)
	}

	// pacman keeps the .MTREE of the package as the mtree of the database.
	if len(mt.Entries) != len(md.Mtree.Entries) {
		t.Fatalf("%d entries, the package has %d", len(mt.Entries), len(md.Mtree.Entries))
	}

	for i := range mt.Entries {
		if mt.Entries[i].Path != md.Mtree.Entries[i].Path || mt.Entries[i].SHA256 != md.Mtree.Entries[i].SHA256 ||
			mt.Entries[i].MD5 != md.Mtree.Entries[i].MD5 {
			t.Errorf("entry %d: %+v, the package has %+v", i, mt.Entries[i], md.Mtree.Entries[i])
		}
	}

	if err := VerifyPackage(bytes.NewReader(raw), VerifyOptions{}); err != nil {
		t.Errorf("VerifyPackage: %v", err)
	}

	// Every path of the package is in the files list pacman wrote.
	files := strings.Split(readFile(t, "testdata/container/local/shapes-1.0-1/files"), "\n")
	for _, e := range mt.Entries {
		if strings.HasPrefix(e.Path, ".") {
			continue
		}

		want := e.Path
		if e.Type == MtreeDir {
			want += "/"
		}

		if !slices.Contains(files, want) {
			t.Errorf("%s is not in the files list", want)
		}
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()

	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}

	return string(raw)
}
