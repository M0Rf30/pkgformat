package source_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/M0Rf30/pkgformat/deb/source"
)

// preparedTree unpacks a fixture and returns the tree, as a maintainer's
// working directory.
func preparedTree(t *testing.T, name string) (tree, parent string) {
	t.Helper()

	d, _ := fixtureDSC(t, name)
	parent = t.TempDir()

	up := d.Version
	if i := strings.LastIndexByte(up, '-'); i >= 0 {
		up = up[:i]
	}

	tree = filepath.Join(parent, d.Source+"-"+up)
	if err := source.Unpack(d, fixtureDir(name), tree, nil); err != nil {
		t.Fatal(err)
	}

	return tree, parent
}

func fileNames(files []source.FileRef) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Name
	}

	return out
}

func TestBuildRoundTrip(t *testing.T) {
	for _, name := range []string{"hello", "sl", "rust-getch", "node-boolbase", "node-is-node", "r-cran-bh", "icingaweb2-module-metapackages", "meta-exwm"} {
		t.Run(name, func(t *testing.T) {
			tree, _ := preparedTree(t, name)
			out := t.TempDir()

			res, err := source.Build(tree, &source.BuildOptions{OrigDir: fixtureDir(name), OutDir: out})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}

			orig, _ := fixtureDSC(t, name)
			if got, want := fileNames(res.DSC.Files), fileNames(orig.Files); !reflect.DeepEqual(got, want) {
				t.Fatalf("files %v, want %v", got, want)
			}

			// The result unpacks to the same tree dpkg-source -x makes of the
			// original package.
			parsed, err := source.ParseDSC(mustRead(t, res.DSCPath))
			if err != nil {
				t.Fatal(err)
			}

			dest := filepath.Join(t.TempDir(), "x")
			if err := source.Unpack(parsed, out, dest, nil); err != nil {
				t.Fatalf("Unpack of the built package: %v", err)
			}

			diffLines(t, readLines(t, filepath.Join("testdata", "expected", name+".manifest")), manifest(t, dest))
		})
	}
}

func mustRead(t testing.TB, p string) []byte {
	t.Helper()

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func TestBuildMatchesDpkgSource(t *testing.T) {
	if _, err := exec.LookPath("dpkg-source"); err != nil {
		t.Skip("dpkg-source not installed")
	}

	for _, name := range []string{"hello", "sl", "rust-getch", "node-boolbase", "node-is-node", "r-cran-bh", "icingaweb2-module-metapackages", "meta-exwm"} {
		t.Run(name, func(t *testing.T) {
			tree, parent := preparedTree(t, name)

			// dpkg-source -b finds the orig tarballs next to the tree.
			entries, _ := os.ReadDir(fixtureDir(name))
			for _, e := range entries {
				if strings.Contains(e.Name(), ".orig") {
					copyTo(t, filepath.Join(fixtureDir(name), e.Name()), filepath.Join(parent, e.Name()))
				}
			}

			cmd := exec.Command("dpkg-source", "-b", filepath.Base(tree))
			cmd.Dir = parent

			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("dpkg-source -b: %v\n%s", err, out)
			}

			refs, _ := filepath.Glob(filepath.Join(parent, "*.dsc"))
			if len(refs) != 1 {
				t.Fatalf("dpkg-source wrote %v", refs)
			}

			ref, err := source.ParseDSC(mustRead(t, refs[0]))
			if err != nil {
				t.Fatal(err)
			}

			out := t.TempDir()

			res, err := source.Build(tree, &source.BuildOptions{OrigDir: parent, OutDir: out})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}

			if got, want := fileNames(res.DSC.Files), fileNames(ref.Files); !reflect.DeepEqual(got, want) {
				t.Errorf("files %v, dpkg-source %v", got, want)
			}

			// Everything but the digests of the files is the same; the orig
			// tarballs are copied, so their digests are too.
			for i := range res.DSC.Files {
				if strings.Contains(res.DSC.Files[i].Name, ".orig") {
					if res.DSC.Files[i].SHA256 != ref.File(res.DSC.Files[i].Name).SHA256 {
						t.Errorf("%s: digest differs", res.DSC.Files[i].Name)
					}
				}
			}

			a, b := *res.DSC, *ref
			a.Files, b.Files = nil, nil

			if !reflect.DeepEqual(a, b) {
				t.Errorf("description differs\nours: %+v\ndpkg: %+v", a, b)
			}

			// dpkg-source accepts the package that was built.
			x := exec.Command("dpkg-source", "--no-check", "-x", filepath.Base(res.DSCPath), filepath.Join(t.TempDir(), "x"))
			x.Dir = out

			if o, err := x.CombinedOutput(); err != nil {
				t.Fatalf("dpkg-source -x on our package: %v\n%s", err, o)
			}
		})
	}
}

func copyTo(t *testing.T, src, dst string) {
	t.Helper()

	if err := os.WriteFile(dst, mustRead(t, src), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildLocalChanges(t *testing.T) {
	tree, _ := preparedTree(t, "sl")

	if err := os.WriteFile(filepath.Join(tree, "sl.c"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := source.Build(tree, &source.BuildOptions{OrigDir: fixtureDir("sl"), OutDir: t.TempDir()})
	if !errors.Is(err, source.ErrLocalChanges) {
		t.Fatalf("got %v, want ErrLocalChanges", err)
	}
}

func TestBuildOptions(t *testing.T) {
	tree, _ := preparedTree(t, "meta-exwm")

	for _, comp := range []string{"gzip", "zstd", "xz"} {
		out := t.TempDir()

		res, err := source.Build(tree, &source.BuildOptions{
			OutDir: out, Compression: comp, ModTime: time.Unix(1700000000, 0),
		})
		if err != nil {
			t.Fatalf("%s: %v", comp, err)
		}

		parsed, _ := source.ParseDSC(mustRead(t, res.DSCPath))

		dest := filepath.Join(t.TempDir(), "x")
		if err := source.Unpack(parsed, out, dest, nil); err != nil {
			t.Fatalf("%s: unpack: %v", comp, err)
		}
	}

	if _, err := source.Build(tree, &source.BuildOptions{Compression: "lzma"}); err == nil {
		t.Error("unknown compression accepted")
	}

	// Reproducible: the same inputs give the same bytes.
	a, b := t.TempDir(), t.TempDir()
	r1, _ := source.Build(tree, &source.BuildOptions{OutDir: a})
	r2, _ := source.Build(tree, &source.BuildOptions{OutDir: b})

	if r1 == nil || r2 == nil || string(mustRead(t, r1.DSCPath)) != string(mustRead(t, r2.DSCPath)) {
		t.Error("two builds differ")
	}
}
