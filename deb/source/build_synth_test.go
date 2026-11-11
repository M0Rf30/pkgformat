package source_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/deb/source"
)

const synthChangelog = "foo (1.2-1) unstable; urgency=medium\n\n  * Release.\n\n -- A Maintainer <a@example.org>  Tue, 02 Jan 2024 03:04:05 +0000\n"

const synthControl = `Source: foo
Section: utils
Priority: optional
Maintainer: A Maintainer <a@example.org>
Uploaders: B <b@example.org>,
 C <c@example.org>
Standards-Version: 4.6.2
Build-Depends: debhelper-compat (= 13),
 libbar-dev <!nocheck>
Build-Depends-Arch: gcc
Build-Conflicts-Indep: baz
Homepage: https://example.org/foo
Vcs-Git: https://example.org/foo.git
XS-Testsuite: autopkgtest
XS-Custom-Field: kept
X-Not-Copied: dropped

Package: foo
Architecture: any
Description: the foo tool
 Longer text.

Package: foo-data
Architecture: all
Section: doc
Priority: extra
Build-Profiles: <!nodoc>
Description: data of foo

Package: foo-udeb
XC-Package-Type: udeb
Architecture: linux-any
Description: udeb of foo

Package: foo-core
Architecture: any
Essential: yes
Protected: yes
Description: core of foo
`

func synthTree(t *testing.T, format string, extra map[string]string) string {
	t.Helper()

	parent := t.TempDir()
	tree := filepath.Join(parent, "foo-1.2")
	files := map[string]string{
		"debian/changelog":     synthChangelog,
		"debian/control":       synthControl,
		"debian/rules":         "#!/usr/bin/make -f\n%:\n\tdh $@\n",
		"debian/source/format": format + "\n",
		"debian/tests/control": "Tests: smoke\n",
		"main.c":               "int main(void) { return 0; }\n",
		"skip.o":               "object",
		".git/config":          "ignored",
		"data/ignored.tmp":     "tmp",
	}

	for k, v := range extra {
		files[k] = v
	}

	for name, body := range files {
		p := filepath.Join(tree, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return tree
}

func TestBuildNativeFromScratch(t *testing.T) {
	signer, kr := newSigner(t)
	tree := synthTree(t, "3.0 (native)", nil)
	out := t.TempDir()

	res, err := source.Build(tree, &source.BuildOptions{
		OutDir: out, Compression: "gzip", Signer: signer, IgnorePatterns: []string{"*.tmp"},
	})
	if err != nil {
		t.Fatal(err)
	}

	d, _, err := source.ParseSignedDSC(mustRead(t, res.DSCPath), kr)
	if err != nil {
		t.Fatalf("signed .dsc: %v", err)
	}

	if d.Format != source.FormatNative || d.Source != "foo" || d.Version != "1.2-1" {
		t.Errorf("identity %+v", d)
	}

	if strings.Join(d.Binary, " ") != "foo foo-data foo-udeb foo-core" {
		t.Errorf("binary %v", d.Binary)
	}

	if d.Uploaders == "" || d.Homepage != "https://example.org/foo" || d.StandardsVersion != "4.6.2" ||
		d.Vcs["Vcs-Git"] == "" || d.Testsuite != "autopkgtest" {
		t.Errorf("metadata %+v", d)
	}

	custom := false

	for _, f := range d.Extra {
		if f.Name == "Custom-Field" && f.Value == "kept" {
			custom = true
		}

		if f.Name == "Not-Copied" || f.Name == "X-Not-Copied" {
			t.Errorf("copied %v", f)
		}
	}

	if !custom {
		t.Errorf("XS- field lost: %v", d.Extra)
	}

	var list []string
	for _, e := range d.PackageList {
		list = append(list, e.String())
	}

	joined := strings.Join(list, "\n")
	for _, want := range []string{
		"foo deb utils optional arch=any",
		"foo-data deb doc extra arch=all profile=!nodoc profile:v1=!nodoc",
		"foo-udeb udeb utils optional arch=linux-any",
		"foo-core deb utils optional arch=any protected=yes essential=yes",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("Package-List lacks %q:\n%s", want, joined)
		}
	}

	if d.Architecture[0] == "" || len(d.Files) != 1 || !strings.HasSuffix(d.Files[0].Name, ".tar.gz") {
		t.Errorf("architecture %v files %v", d.Architecture, d.Files)
	}

	// The ignored files stay out of the tarball.
	dest := filepath.Join(t.TempDir(), "x")
	if err := source.Unpack(d, out, dest, nil); err != nil {
		t.Fatal(err)
	}

	for _, gone := range []string{"skip.o", ".git", "data/ignored.tmp"} {
		if _, err := os.Lstat(filepath.Join(dest, gone)); err == nil {
			t.Errorf("%s was packed", gone)
		}
	}

	if _, err := os.Stat(filepath.Join(dest, "main.c")); err != nil {
		t.Error(err)
	}
}

func TestBuildErrors(t *testing.T) {
	build := func(tree string) error {
		_, err := source.Build(tree, &source.BuildOptions{OutDir: t.TempDir()})

		return err
	}

	if err := build(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("absent tree")
	}

	if err := build(synthTree(t, "1.0", nil)); !errors.Is(err, source.ErrUnsupportedFormat) {
		t.Errorf("format 1.0: %v", err)
	}

	if err := build(synthTree(t, "3.0 (git)", nil)); !errors.Is(err, source.ErrUnsupportedFormat) {
		t.Errorf("format git: %v", err)
	}

	if err := build(synthTree(t, "3.0 (quilt)", nil)); !errors.Is(err, source.ErrMissingFile) {
		t.Errorf("quilt without orig: %v", err)
	}

	for name, extra := range map[string]map[string]string{
		"bad changelog": {"debian/changelog": "garbage\n"},
		"bad version":   {"debian/changelog": strings.Replace(synthChangelog, "1.2-1", "1 2", 1)},
		"no source":     {"debian/control": "Package: foo\nArchitecture: any\n"},
		"bad source":    {"debian/control": "Source: Foo_\n\nPackage: foo\nArchitecture: any\nDescription: x\n"},
		"no packages":   {"debian/control": "Source: foo\nMaintainer: a\n"},
		"native dash":   {"debian/changelog": strings.Replace(synthChangelog, "1.2-1", "1.2", 1)},
	} {
		tree := synthTree(t, "3.0 (native)", extra)
		if err := build(tree); err == nil && name != "native dash" {
			t.Errorf("%s: accepted", name)
		}
	}

	noFormat := synthTree(t, "3.0 (native)", nil)
	_ = os.Remove(filepath.Join(noFormat, "debian", "source", "format"))

	if err := build(noFormat); err == nil {
		t.Error("tree without debian/source/format built")
	}

	if _, err := source.Build(synthTree(t, "3.0 (native)", nil), &source.BuildOptions{IgnorePatterns: []string{"[unclosed"}}); err == nil {
		t.Error("bad pattern accepted")
	}

	if _, err := source.Build(synthTree(t, "3.0 (native)", nil), &source.BuildOptions{Compression: "none"}); err == nil {
		t.Error("uncompressed tarball accepted")
	}
}

func TestBuildQuiltFromOrig(t *testing.T) {
	// A quilt tree is built against an orig tarball found in OrigDir; the
	// tarball is copied to the output.
	tree, parent := preparedTree(t, "sl")
	out := t.TempDir()

	res, err := source.Build(tree, &source.BuildOptions{OrigDir: fixtureDir("sl"), OutDir: out})
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range res.Files {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("listed file %s: %v", f, err)
		}
	}

	// Without OrigDir the parent of the tree is searched: not there.
	_ = parent

	if _, err := source.Build(tree, &source.BuildOptions{OutDir: t.TempDir(), OrigDir: t.TempDir()}); !errors.Is(err, source.ErrMissingFile) {
		t.Errorf("no orig: %v", err)
	}

	// A change to a file of the orig tarball is refused: it would need an auto-patch.
	if err := os.WriteFile(filepath.Join(tree, "newfile.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := source.Build(tree, &source.BuildOptions{OrigDir: fixtureDir("sl"), OutDir: t.TempDir()}); !errors.Is(err, source.ErrLocalChanges) {
		t.Errorf("local changes: %v", err)
	}
}
