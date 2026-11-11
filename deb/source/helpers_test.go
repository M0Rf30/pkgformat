package source_test

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/deb/source"
)

// fixtures lists the source packages of testdata/packages.
var fixtures = []struct {
	name   string
	format source.Format
}{
	{"hello", source.FormatQuilt},
	{"sl", source.FormatQuilt},
	{"rust-getch", source.FormatQuilt},
	{"node-boolbase", source.FormatQuilt}, // component tarball
	{"node-is-node", source.FormatQuilt},
	{"r-cran-bh", source.FormatQuilt},
	{"icingaweb2-module-metapackages", source.FormatQuilt},
	{"meta-exwm", source.FormatNative},
	{"cl-pipes", source.Format10},
	{"libtemplate-plugin-utf8decode-perl", source.Format10},
	{"vacation", source.Format10},
	{"valgrind-if-available", source.Format10},
}

func fixtureDir(name string) string { return filepath.Join("testdata", "packages", name) }

func fixtureDSC(t testing.TB, name string) (*source.DSC, string) {
	t.Helper()

	m, err := filepath.Glob(filepath.Join(fixtureDir(name), "*.dsc"))
	if err != nil || len(m) != 1 {
		t.Fatalf("fixture %s: dsc files %v, %v", name, m, err)
	}

	data, err := os.ReadFile(m[0])
	if err != nil {
		t.Fatal(err)
	}

	d, err := source.ParseDSC(data)
	if err != nil {
		t.Fatalf("parsing %s: %v", m[0], err)
	}

	return d, m[0]
}

// manifest renders a tree like testdata/generate.sh: "mode type path digest".
func manifest(t testing.TB, root string) []string {
	t.Helper()

	var out []string

	err := filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}

		st, err := os.Lstat(p)
		if err != nil {
			return err
		}

		mode := strconv.FormatUint(uint64(st.Mode().Perm()), 8)

		switch {
		case st.Mode()&fs.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			out = append(out, mode+" l ./"+filepath.ToSlash(rel)+" "+target)
		case st.IsDir():
			out = append(out, mode+" d ./"+filepath.ToSlash(rel)+" -")
		default:
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}

			sum := sha256.Sum256(data)
			out = append(out, mode+" f ./"+filepath.ToSlash(rel)+" "+hex.EncodeToString(sum[:]))
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	sort.Slice(out, func(i, j int) bool { return pathOf(out[i]) < pathOf(out[j]) })

	return out
}

func pathOf(line string) string { return strings.Fields(line)[2] }

func readLines(t testing.TB, file string) []string {
	t.Helper()

	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}

	defer f.Close()

	var lines []string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}

	return lines
}
