package repodata

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
)

// corpusTime is the modification time gen.sh gives every package of the
// corpus; createrepo_c records it as the file time.
const corpusTime = 1700000000

// loadCorpus reads the packages of testdata/createrepo the way a repository
// builder does: header from the file, digest and size of the whole file.
func loadCorpus(t testing.TB) []rpm.Package {
	t.Helper()

	files, err := filepath.Glob(filepath.Join("testdata", "createrepo", "Packages", "*.rpm"))
	if err != nil || len(files) == 0 {
		t.Fatalf("corpus not found: %v", err)
	}

	sort.Strings(files)

	pkgs := make([]rpm.Package, 0, len(files))

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}

		pkg, err := rpm.ReadPackage(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}

		sum := sha256.Sum256(data)
		pkg.SHA256 = hex.EncodeToString(sum[:])
		pkg.PackageSize = int64(len(data))
		pkg.FileTime = corpusTime
		pkgs = append(pkgs, *pkg)
		corpusFile[pkg.SHA256] = filepath.Base(f)
	}

	return pkgs
}

// corpusFile maps the digest of a corpus package to its file name.
var corpusFile = map[string]string{}

func goldenDoc(t testing.TB, name string) string {
	t.Helper()

	f, err := os.Open(filepath.Join("testdata", "createrepo", "golden", name+".xml.gz"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

// TestMatchesCreaterepoGolden compares the four documents written for a corpus
// of real Fedora and rpmbuild packages (rpm 4 and rpm 6 headers, weak and rich
// dependencies, file triggers, ghost files, epochs) with what createrepo_c
// 1.2 wrote for the same files (testdata/createrepo/gen.sh). The documents
// must be identical byte for byte.
func TestMatchesCreaterepoGolden(t *testing.T) {
	pkgs := loadCorpus(t)

	// createrepo_c lists the packages in directory order; the golden files are
	// in the order the directory was scanned, so index them by pkgid.
	for _, tc := range []struct {
		name string
		kind DocKind
	}{
		{"primary", DocPrimary},
		{"filelists", DocFilelists},
		{"other", DocOther},
		{"filelists-ext", DocFilelistsExt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := goldenDoc(t, tc.name)

			ordered := orderLike(t, pkgs, want)

			var got bytes.Buffer

			d := NewDocWriter(&got, tc.kind, len(ordered))

			for i := range ordered {
				d.PackageAt(&ordered[i], Location{Href: "Packages/" + corpusFile[ordered[i].SHA256]})
			}

			if err := d.Close(); err != nil {
				t.Fatal(err)
			}

			if got.String() != want {
				t.Fatalf("%s differs from createrepo_c at byte %d:\n%s", tc.name, firstStringDiff(got.String(), want), context(got.String(), want))
			}
		})
	}
}

// orderLike returns pkgs in the order the document lists them.
func orderLike(t testing.TB, pkgs []rpm.Package, doc string) []rpm.Package {
	t.Helper()

	var out []rpm.Package

	for _, id := range pkgIDs(doc) {
		for i := range pkgs {
			if pkgs[i].SHA256 == id {
				out = append(out, pkgs[i])

				break
			}
		}
	}

	if len(out) != len(pkgs) {
		t.Fatalf("document lists %d of %d corpus packages", len(out), len(pkgs))
	}

	return out
}

func pkgIDs(doc string) []string {
	var ids []string

	for _, line := range strings.Split(doc, "\n") {
		switch {
		case strings.HasPrefix(line, `<package pkgid="`):
			ids = append(ids, strings.SplitN(line[len(`<package pkgid="`):], `"`, 2)[0])
		case strings.HasPrefix(line, `  <checksum type="sha256" pkgid="YES">`):
			v := strings.TrimPrefix(line, `  <checksum type="sha256" pkgid="YES">`)
			ids = append(ids, strings.TrimSuffix(v, "</checksum>"))
		}
	}

	return ids
}

func firstStringDiff(a, b string) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}

	return n
}

func context(a, b string) string {
	i := max(firstStringDiff(a, b)-120, 0)

	return "written:      " + a[i:min(i+240, len(a))] + "\ncreaterepo_c: " + b[i:min(i+240, len(b))]
}
