package repodata

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// compsFixtures are real comps.xml documents (fedora43.xml, fedora15.xml,
// trimmed from the published ones) and features.xml, which uses the attributes
// no distribution publishes today. See testdata/comps/README.md.
var compsFixtures = []struct {
	name string
	// exact is true when the writer reproduces the file byte for byte; the
	// others differ in the order of the attributes of an element, which XML
	// does not define.
	exact bool
}{
	{"fedora43.xml", true},
	{"fedora15.xml", false},
	{"features.xml", true},
}

func readCompsFixture(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", "comps", name))
	if err != nil {
		t.Fatal(err)
	}

	return data
}

// canonicalXML renders a document in a form that is equal for documents that
// differ only in what XML leaves open: the order of attributes, empty-element
// syntax, the quoting of characters, whitespace between elements, comments and
// the document type declaration.
func canonicalXML(t *testing.T, data []byte) string {
	t.Helper()

	var sb strings.Builder

	dec := xml.NewDecoder(bytes.NewReader(data))

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return sb.String()
		}

		if err != nil {
			t.Fatal(err)
		}

		switch tk := tok.(type) {
		case xml.StartElement:
			attrs := slices.Clone(tk.Attr)
			slices.SortFunc(attrs, func(a, b xml.Attr) int { return strings.Compare(a.Name.Space+a.Name.Local, b.Name.Space+b.Name.Local) })

			sb.WriteString("<" + tk.Name.Local)

			for _, a := range attrs {
				sb.WriteString(" " + a.Name.Space + ":" + a.Name.Local + "=" + `"` + a.Value + `"`)
			}

			sb.WriteString(">")
		case xml.EndElement:
			sb.WriteString("</" + tk.Name.Local + ">")
		case xml.CharData:
			if strings.TrimSpace(string(tk)) != "" {
				sb.Write(tk)
			}
		}
	}
}

// TestCompsFixtures reads each document, writes it back and reads that: the
// model is equal, the file is canonical-XML equal to the original, and where
// the writer reproduces the layout the bytes are too.
func TestCompsFixtures(t *testing.T) {
	for _, fx := range compsFixtures {
		t.Run(fx.name, func(t *testing.T) {
			orig := readCompsFixture(t, fx.name)
			model := parseComps(t, orig)
			written := writeComps(t, model)

			if again := parseComps(t, written); !reflect.DeepEqual(again, model) {
				t.Errorf("parse(write(parse(x))) differs from parse(x)")
			}

			if got, want := canonicalXML(t, written), canonicalXML(t, orig); got != want {
				t.Errorf("written file is not canonical-XML equal to the original")
			}

			if fx.exact && !bytes.Equal(written, orig) {
				t.Errorf("written file differs from the original in bytes")
			}

			if err := ValidateCompsXML(written); err != nil {
				t.Error(err)
			}

			// The streaming reader and the model reader agree.
			var groups int

			err := ReadComps(bytes.NewReader(orig), CompsLimits{}, CompsVisitor{Group: func(*CompsGroup) error { groups++; return nil }})
			if err != nil || groups != len(model.Groups) {
				t.Errorf("ReadComps: %d groups, %v; want %d", groups, err, len(model.Groups))
			}
		})
	}
}

// TestCompsFixturesCanonicalWithXmllint compares libxml2's own canonical form
// (C14N) of the original and of the written file.
func TestCompsFixturesCanonicalWithXmllint(t *testing.T) {
	if _, err := exec.LookPath("xmllint"); err != nil {
		t.Skip("xmllint is not installed")
	}

	c14n := func(path string) string {
		out, err := exec.Command("xmllint", "--c14n", path).Output()
		if err != nil {
			t.Fatalf("xmllint %s: %v", path, err)
		}

		return string(out)
	}

	for _, fx := range compsFixtures {
		t.Run(fx.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "written.xml")

			if err := os.WriteFile(path, writeComps(t, parseComps(t, readCompsFixture(t, fx.name))), 0o600); err != nil {
				t.Fatal(err)
			}

			if c14n(path) != c14n(filepath.Join("testdata", "comps", fx.name)) {
				t.Error("the C14N form of the written file differs from the original's")
			}
		})
	}
}

// TestCompsFixtureContents pins what the real documents contain, so a reader
// that drops a feature fails here and not only in the equality tests.
func TestCompsFixtureContents(t *testing.T) {
	f43 := parseComps(t, readCompsFixture(t, "fedora43.xml"))

	if len(f43.Groups) != 9 || len(f43.Categories) != 2 || len(f43.Environments) != 2 || len(f43.Langpacks) != 3 {
		t.Fatalf("fedora43: %d groups, %d categories, %d environments, %d langpacks",
			len(f43.Groups), len(f43.Categories), len(f43.Environments), len(f43.Langpacks))
	}

	core := f43.Groups[0]
	if core.ID != "core" || core.Name != "Core" || core.NameLocalized["de"] == "" || core.NameLocalized["zh_CN"] == "" ||
		core.DescriptionLocalized["fr"] == "" || core.Default || core.UserVisible {
		t.Errorf("fedora43 core = %+v", core)
	}

	var conditional int

	for _, g := range f43.Groups {
		for _, p := range g.Packages {
			if p.Type == CompsConditional && p.Requires != "" {
				conditional++
			}
		}
	}

	if conditional == 0 {
		t.Error("fedora43: no conditional package with requires")
	}

	var env *CompsEnvironment

	for i := range f43.Environments {
		if f43.Environments[i].ID == "kde-mobile-environment" {
			env = &f43.Environments[i]
		}
	}

	if env == nil || env.DisplayOrder == 0 || len(env.Groups) == 0 || len(env.Options) == 0 || !env.Options[0].Default {
		t.Errorf("fedora43 environment = %+v", env)
	}

	f15 := parseComps(t, readCompsFixture(t, "fedora15.xml"))

	var baseArchOnly, langOnly, defaulted bool

	for _, g := range f15.Groups {
		langOnly = langOnly || g.LangOnly != ""
		defaulted = defaulted || g.Default

		for _, p := range g.Packages {
			baseArchOnly = baseArchOnly || p.BaseArchOnly
		}
	}

	if !baseArchOnly || !langOnly || !defaulted {
		t.Errorf("fedora15: basearchonly %v, langonly %v, default %v", baseArchOnly, langOnly, defaulted)
	}

	if len(f15.Blacklist) != 8 || f15.Blacklist[2] != (CompsBlacklisted{Name: "NetworkManager", Arch: "i386"}) {
		t.Errorf("fedora15 blacklist = %+v", f15.Blacklist)
	}

	if len(f15.Whiteout) != 8 || f15.Whiteout[0] != (CompsIgnoredDep{Requires: "Mesa", Package: "XFree86"}) {
		t.Errorf("fedora15 whiteout = %+v", f15.Whiteout)
	}

	feat := parseComps(t, readCompsFixture(t, "features.xml"))
	g := feat.Groups[0]

	if !g.BiarchOnly || g.DisplayOrder != 7 || g.LangOnly != "de" || !slices.Equal(g.Arch, []string{"x86_64", "aarch64"}) ||
		!g.Default || g.UserVisible || g.NameLocalized["fr"] != "Outils multi-architecture" {
		t.Errorf("features group = %+v", g)
	}

	p := g.Packages[0]
	if !p.BaseArchOnly || !slices.Equal(p.Arch, []string{"x86_64"}) || p.Type != CompsMandatory {
		t.Errorf("features package = %+v", p)
	}

	if feat.Categories[0].Groups[1].Arch == nil || !feat.Environments[0].Options[0].Default || feat.Environments[0].Arch == nil {
		t.Errorf("features lists = %+v %+v", feat.Categories[0], feat.Environments[0])
	}
}
