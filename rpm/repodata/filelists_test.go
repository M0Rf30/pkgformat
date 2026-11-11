package repodata

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
)

// readGoldenFilelistsExt decodes the filelists-ext.xml createrepo_c wrote for
// the corpus of testdata/createrepo.
func readGoldenFilelistsExt(t testing.TB) []FilelistsExtPackage {
	t.Helper()

	var pkgs []FilelistsExtPackage

	err := ReadFilelistsExt(strings.NewReader(goldenDoc(t, "filelists-ext")), FilelistsLimits{}, func(p *FilelistsExtPackage) error {
		cp := *p
		cp.Files = append([]FilelistsFile(nil), p.Files...)
		pkgs = append(pkgs, cp)

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return pkgs
}

func TestReadFilelistsExtGolden(t *testing.T) {
	doc := goldenDoc(t, "filelists-ext")
	pkgs := readGoldenFilelistsExt(t)

	if len(pkgs) != strings.Count(doc, "<package ") || len(pkgs) != 33 {
		t.Fatalf("read %d packages, document has %d", len(pkgs), strings.Count(doc, "<package "))
	}

	first := pkgs[0]
	if first.PkgID != "e9f7e6d89b000a5436f266408ddf17ece31fcc2075b9e4759c116a39583fc318" ||
		first.Name != "NetworkManager-libnm" || first.Arch != "x86_64" ||
		first.Epoch != 1 || first.Version != "1.58.1" || first.Release != "3.fc45" || first.ChecksumType != "sha256" {
		t.Fatalf("first package = %+v", first)
	}

	want := []FilelistsFile{
		{Path: "/usr/lib/.build-id", Type: FileTypeDir},
		{Path: "/usr/lib/.build-id/66", Type: FileTypeDir},
		{Path: "/usr/lib/.build-id/66/065494db5bc1e8726c761522ad92e7057412eb"},
		{
			Path: "/usr/lib64/girepository-1.0/NM-1.0.typelib",
			Hash: "a8b28a7a3f19cff59ebbd7a1231d762b40f87fb788d6ecc60fda3d42fc2d7dc4",
		},
		{Path: "/usr/lib64/libnm.so.0"},
	}
	if !reflect.DeepEqual(first.Files[:len(want)], want) {
		t.Fatalf("files = %+v, want %+v", first.Files[:len(want)], want)
	}

	var dirs, ghosts, hashed, total int

	for i := range pkgs {
		for _, f := range pkgs[i].Files {
			total++

			switch {
			case f.Type == FileTypeDir:
				dirs++
			case f.Type == FileTypeGhost:
				ghosts++
			case f.Hash != "":
				hashed++
			}

			if f.Type != "" && f.Hash != "" {
				t.Fatalf("%s: %s has a type and a hash", pkgs[i].Name, f.Path)
			}
		}
	}

	if dirs != strings.Count(doc, `<file type="dir">`) ||
		ghosts != strings.Count(doc, `<file type="ghost">`) ||
		hashed != strings.Count(doc, `<file hash="`) ||
		total != strings.Count(doc, "<file>")+strings.Count(doc, "<file ") {
		t.Fatalf("dirs %d, ghosts %d, hashed %d of %d files disagree with the document", dirs, ghosts, hashed, total)
	}
}

// TestFilelistsExtMatchesPackages ties the document to the headers it was made
// from: every package lists the paths of its header, a digest exactly on the
// regular files that have one, and the type of the directories and ghosts.
func TestFilelistsExtMatchesPackages(t *testing.T) {
	corpus := loadCorpus(t)
	byID := map[string]*rpm.Package{}

	for i := range corpus {
		byID[corpus[i].SHA256] = &corpus[i]
	}

	for _, got := range readGoldenFilelistsExt(t) {
		p := byID[got.PkgID]
		if p == nil {
			t.Fatalf("%s: pkgid %s is not in the corpus", got.Name, got.PkgID)
		}

		if got.Name != p.Name || got.Arch != p.Arch || got.Epoch != p.Epoch || got.Version != p.Version || got.Release != p.Release {
			t.Fatalf("%s: identity %+v differs from the header", got.Name, got)
		}

		if len(got.Files) != len(p.Files) {
			t.Fatalf("%s: %d files, header has %d", got.Name, len(got.Files), len(p.Files))
		}

		for i, f := range got.Files {
			h := p.Files[i]

			switch {
			case f.Path != h.Path:
				t.Fatalf("%s: file %d is %q, header has %q", got.Name, i, f.Path, h.Path)
			case h.IsDir() && f.Type != FileTypeDir, h.IsGhost() && !h.IsDir() && f.Type != FileTypeGhost:
				t.Fatalf("%s: %s has type %q", got.Name, f.Path, f.Type)
			case f.Type == FileTypeRegular && f.Hash != h.Digest:
				t.Fatalf("%s: %s has hash %q, header has %q", got.Name, f.Path, f.Hash, h.Digest)
			}
		}
	}
}

// TestFilelistsExtRoundTrip reads the document createrepo_c wrote and writes
// the packages back: the bytes must be the same, as a document made by the
// package's own writer from the headers is (TestMatchesCreaterepoGolden).
func TestFilelistsExtRoundTrip(t *testing.T) {
	want := goldenDoc(t, "filelists-ext")

	var got bytes.Buffer
	if err := WriteFilelistsExt(&got, readGoldenFilelistsExt(t)); err != nil {
		t.Fatal(err)
	}

	if got.String() != want {
		t.Fatalf("round trip differs at byte %d:\n%s", firstStringDiff(got.String(), want), context(got.String(), want))
	}

	// The streaming writer gives the same document.
	var streamed bytes.Buffer

	pkgs := readGoldenFilelistsExt(t)
	d := NewDocWriter(&streamed, DocFilelistsExt, len(pkgs))

	for i := range pkgs {
		if err := d.FilelistsExt(&pkgs[i]); err != nil {
			t.Fatal(err)
		}
	}

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	if streamed.String() != want {
		t.Fatal("the DocWriter output differs from the golden document")
	}
}

// TestScanPackagesFilelistsExt checks that ScanPackages identifies the
// packages of a filelists-ext document: the <checksum type="sha256"/> element
// they carry must not wipe the pkgid.
func TestScanPackagesFilelistsExt(t *testing.T) {
	doc := goldenDoc(t, "filelists-ext")
	pkgs := readGoldenFilelistsExt(t)

	for _, withElement := range []bool{false, true} {
		i := 0

		err := ScanPackages(strings.NewReader(doc), withElement, func(info PackageInfo, element []byte) error {
			p := pkgs[i]
			i++

			if info.PkgID != p.PkgID || info.Name != p.Name || info.Arch != p.Arch ||
				info.Epoch != fmt.Sprint(p.Epoch) || info.Ver != p.Version || info.Rel != p.Release {
				t.Fatalf("scanned %+v, read %+v", info, p)
			}

			if withElement {
				// The element is a document of its own that reads back to
				// the same package.
				var again []FilelistsExtPackage

				err := ReadFilelistsExt(bytes.NewReader(element), FilelistsLimits{}, func(q *FilelistsExtPackage) error {
					again = append(again, *q)

					return nil
				})
				if err != nil || len(again) != 1 || again[0].PkgID != p.PkgID || len(again[0].Files) != len(p.Files) {
					t.Fatalf("element of %s reads as %+v (%v)", p.Name, again, err)
				}
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		if i != len(pkgs) {
			t.Fatalf("scanned %d of %d packages", i, len(pkgs))
		}
	}
}

func TestReadFilelistsExtPlainFilelists(t *testing.T) {
	const doc = `<?xml version="1.0"?>
<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="1">
<package pkgid="ab" name="n" arch="noarch">
  <version epoch="0" ver="1" rel="2"/>
  <file>/etc/n.conf</file>
  <file type="dir">/etc/n.d</file>
</package>
</filelists>`

	var got []FilelistsExtPackage

	err := ReadFilelistsExt(strings.NewReader(doc), FilelistsLimits{}, func(p *FilelistsExtPackage) error {
		got = append(got, *p)

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	want := FilelistsExtPackage{
		PkgID: "ab", Name: "n", Arch: "noarch", Version: "1", Release: "2",
		Files: []FilelistsFile{{Path: "/etc/n.conf"}, {Path: "/etc/n.d", Type: FileTypeDir}},
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestReadFilelistsExtSkipsAndErrors(t *testing.T) {
	read := func(doc string, lim FilelistsLimits, fn func(*FilelistsExtPackage) error) error {
		return ReadFilelistsExt(strings.NewReader(doc), lim, fn)
	}

	count := func(*FilelistsExtPackage) error { return nil }

	t.Run("invalid packages are skipped", func(t *testing.T) {
		const doc = `<filelists>
<package pkgid="1" arch="noarch"><version epoch="0" ver="1" rel="1"/></package>
<package pkgid="2" name="n"><version epoch="0" ver="1" rel="1"/></package>
<package pkgid="3" name="n" arch="a"><version epoch="x" ver="1" rel="1"/></package>
<package pkgid="4" name="n" arch="a"><version epoch="3" ver="1" rel="1"/><unknown><file>/skipped</file></unknown>
<file>   </file><file></file></package>
</filelists>`

		var got []FilelistsExtPackage

		err := read(doc, FilelistsLimits{}, func(p *FilelistsExtPackage) error {
			got = append(got, *p)

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		if len(got) != 1 || got[0].PkgID != "4" || got[0].Epoch != 3 || len(got[0].Files) != 1 || got[0].Files[0].Path != "   " {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("truncated", func(t *testing.T) {
		if err := read(`<filelists><package name="n" arch="a"><file>/x`, FilelistsLimits{}, count); err == nil {
			t.Fatal("a truncated document was accepted")
		}
	})

	t.Run("not xml", func(t *testing.T) {
		if err := read(`<a><b></a>`, FilelistsLimits{}, count); err == nil {
			t.Fatal("a malformed document was accepted")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if err := read("", FilelistsLimits{}, count); err != nil {
			t.Fatalf("empty input: %v", err)
		}
	})

	t.Run("callback error", func(t *testing.T) {
		boom := errors.New("boom")
		if err := read(goldenDoc(t, "filelists-ext"), FilelistsLimits{}, func(*FilelistsExtPackage) error { return boom }); !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestReadFilelistsExtLimits(t *testing.T) {
	pkg := func(files string) string {
		return `<filelists><package pkgid="1" name="n" arch="a"><version epoch="0" ver="1" rel="1"/>` + files + `</package></filelists>`
	}

	for _, tc := range []struct {
		name string
		doc  string
		lim  FilelistsLimits
	}{
		{"files", pkg("<file>/a</file><file>/b</file><file>/c</file>"), FilelistsLimits{MaxFiles: 2}},
		{"file bytes", pkg("<file>/aaaa</file><file>/bbbb</file>"), FilelistsLimits{MaxFileBytes: 8}},
		{"path", pkg("<file>/" + strings.Repeat("a", 100) + "</file>"), FilelistsLimits{MaxFieldBytes: 50}},
		{"hash", pkg(`<file hash="` + strings.Repeat("a", 100) + `">/a</file>`), FilelistsLimits{MaxFieldBytes: 50}},
		{"type", pkg(`<file type="` + strings.Repeat("a", 100) + `">/a</file>`), FilelistsLimits{MaxFieldBytes: 50}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ReadFilelistsExt(strings.NewReader(tc.doc), tc.lim, func(*FilelistsExtPackage) error { return nil })
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("err = %v, want ErrTooLarge", err)
			}
		})
	}
}

func TestFilelistsExtWriter(t *testing.T) {
	pkgs := []FilelistsExtPackage{{
		PkgID: "ab", Name: "a&b", Arch: "noarch", Epoch: 2, Version: "1<2", Release: `"r"`,
		Files: []FilelistsFile{
			{Path: "/d<&>", Type: FileTypeDir},
			{Path: "/g", Type: FileTypeGhost},
			{Path: "/f\t\"x\"", Hash: "00ff"},
		},
	}}

	var buf bytes.Buffer
	if err := WriteFilelistsExt(&buf, pkgs); err != nil {
		t.Fatal(err)
	}

	want := `<?xml version="1.0" encoding="UTF-8"?>
<filelists-ext xmlns="http://linux.duke.edu/metadata/filelists-ext" packages="1">
<package pkgid="ab" name="a&amp;b" arch="noarch">
  <version epoch="2" ver="1&lt;2" rel="&quot;r&quot;"/>
  <checksum type="sha256"/>
  <file type="dir">/d&lt;&amp;&gt;</file>
  <file type="ghost">/g</file>
  <file hash="00ff">/f	"x"</file>
</package>
</filelists-ext>`
	if buf.String() != want {
		t.Fatalf("document:\n%s\nwant:\n%s", buf.String(), want)
	}

	var back []FilelistsExtPackage

	err := ReadFilelistsExt(&buf, FilelistsLimits{}, func(p *FilelistsExtPackage) error {
		back = append(back, *p)

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	pkgs[0].ChecksumType = "sha256"
	if !reflect.DeepEqual(back, pkgs) {
		t.Fatalf("read back %+v, wrote %+v", back, pkgs)
	}
}

func TestFilelistsExtWrongDocKind(t *testing.T) {
	for _, kind := range []DocKind{DocPrimary, DocFilelists, DocOther} {
		d := NewDocWriter(&bytes.Buffer{}, kind, 0)
		if err := d.FilelistsExt(&FilelistsExtPackage{Name: "n", Arch: "a"}); !errors.Is(err, ErrDocKind) {
			t.Fatalf("kind %d: err = %v, want ErrDocKind", kind, err)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestFilelistsExtWriteError(t *testing.T) {
	err := WriteFilelistsExt(failingWriter{}, []FilelistsExtPackage{{Name: "n", Arch: "a"}})
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v", err)
	}
}

func FuzzReadFilelistsExt(f *testing.F) {
	golden := goldenDoc(f, "filelists-ext")
	// The first two packages of the golden document, and the corner cases.
	cut := 0
	for range 2 {
		cut += strings.Index(golden[cut:], "</package>") + len("</package>")
	}

	f.Add([]byte(golden[:cut] + "\n</filelists-ext>"))
	f.Add([]byte(`<filelists><package pkgid="a" name="n" arch="x"><version epoch="1" ver="2" rel="3"/><checksum type="md5"/>` +
		`<file type="dir">/d</file><file hash="ab">/f&amp;</file></package></filelists>`))
	f.Add([]byte("<package name=\"n\" arch=\"a\"><file>"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		lim := FilelistsLimits{MaxFiles: 64, MaxFileBytes: 1 << 12, MaxFieldBytes: 1 << 10}

		var first []FilelistsExtPackage

		err := ReadFilelistsExt(bytes.NewReader(data), lim, func(p *FilelistsExtPackage) error {
			cp := *p
			cp.Files = append([]FilelistsFile(nil), p.Files...)

			if cp.ChecksumType == "" {
				cp.ChecksumType = "sha256"
			}

			first = append(first, cp)

			return nil
		})
		if err != nil {
			return
		}

		// What was read is writable and reads back the same.
		var doc bytes.Buffer
		if err := WriteFilelistsExt(&doc, first); err != nil {
			t.Fatal(err)
		}

		var second []FilelistsExtPackage

		err = ReadFilelistsExt(&doc, lim, func(p *FilelistsExtPackage) error {
			cp := *p
			cp.Files = append([]FilelistsFile(nil), p.Files...)
			second = append(second, cp)

			return nil
		})
		if err != nil {
			t.Fatalf("rereading the written document: %v", err)
		}

		if len(first) != len(second) {
			t.Fatalf("%d packages written, %d read back", len(first), len(second))
		}

		for i := range first {
			if len(first[i].Files) == 0 && len(second[i].Files) == 0 {
				first[i].Files, second[i].Files = nil, nil
			}

			if !reflect.DeepEqual(first[i], second[i]) {
				t.Fatalf("package %d: wrote %+v, read back %+v", i, first[i], second[i])
			}
		}
	})
}
