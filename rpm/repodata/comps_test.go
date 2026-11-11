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
	"strings"
	"testing"
)

// testComps is a model that uses every field.
func testComps() *Comps {
	return &Comps{
		Groups: []CompsGroup{
			{
				ID: "build-tools", Name: "Build & Tools", Description: "Compilers <and> friends",
				NameLocalized:        map[string]string{"de": "Bauwerkzeuge", "fr": "Outils d'assemblage"},
				DescriptionLocalized: map[string]string{"de": "Übersetzer"},
				Default:              true, UserVisible: true, BiarchOnly: true, DisplayOrder: 4, LangOnly: "de",
				Arch: []string{"x86_64", "aarch64"},
				Packages: []CompsPackage{
					{Name: "gcc", Type: CompsMandatory, BaseArchOnly: true, Arch: []string{"x86_64"}},
					{Name: "make"},
					{Name: "gdb", Type: CompsOptional},
					{Name: "gcc-plugin", Type: CompsConditional, Requires: "gcc"},
				},
			},
			{ID: "hidden", Name: "Hidden"},
		},
		Categories: []CompsCategory{{
			ID: "development", Name: "Development", Description: "Tools", DisplayOrder: 10, Arch: []string{"x86_64"},
			NameLocalized: map[string]string{"de": "Entwicklung"},
			Groups:        []CompsGroupRef{{ID: "build-tools"}, {ID: "hidden", Arch: []string{"aarch64", "x86_64"}}},
		}},
		Environments: []CompsEnvironment{{
			ID: "dev-env", Name: "Developer", Description: "A \"developer\" machine", DisplayOrder: 1, Arch: []string{"aarch64"},
			DescriptionLocalized: map[string]string{"de": "Ein Entwicklerrechner"},
			Groups:               []CompsGroupRef{{ID: "build-tools"}},
			Options:              []CompsGroupRef{{ID: "hidden", Default: true}},
		}},
		Langpacks: []CompsLangpack{{Name: "aspell", Install: "aspell-%s"}},
		Blacklist: []CompsBlacklisted{{Name: "dev"}, {Name: "dbus", Arch: "i386"}},
		Whiteout:  []CompsIgnoredDep{{Requires: "db1"}, {Requires: "bind-utils", Package: "bind"}},
	}
}

func writeComps(t *testing.T, c *Comps) []byte {
	t.Helper()

	var buf bytes.Buffer
	if err := WriteCompsXML(&buf, c); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func parseComps(t *testing.T, data []byte) *Comps {
	t.Helper()

	c, err := ParseComps(bytes.NewReader(data), CompsLimits{})
	if err != nil {
		t.Fatalf("%v\n%s", err, data)
	}

	return c
}

// normalizeComps is the model a write and a read gives back: an empty package
// type becomes the default one, empty lists are nil.
func normalizeComps(t *testing.T, c *Comps) *Comps {
	t.Helper()

	return parseComps(t, writeComps(t, c))
}

func TestWriteCompsXML(t *testing.T) {
	data := writeComps(t, testComps())

	if err := ValidateCompsXML(data); err != nil {
		t.Fatalf("written comps.xml is not well-formed: %v\n%s", err, data)
	}

	var doc struct {
		Groups []struct {
			ID    string `xml:"id"`
			Names []struct {
				Lang string `xml:"lang,attr"`
				Text string `xml:",chardata"`
			} `xml:"name"`
			Default  bool `xml:"default"`
			Packages []struct {
				Type     string `xml:"type,attr"`
				Requires string `xml:"requires,attr"`
				Name     string `xml:",chardata"`
			} `xml:"packagelist>packagereq"`
		} `xml:"group"`
		Categories []struct {
			ID      string   `xml:"id"`
			GroupID []string `xml:"grouplist>groupid"`
		} `xml:"category"`
	}

	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}

	g := doc.Groups[0]
	if g.ID != "build-tools" || len(g.Names) != 3 || g.Names[0].Text != "Build & Tools" || g.Names[0].Lang != "" || !g.Default || len(g.Packages) != 4 {
		t.Fatalf("group = %+v", g)
	}

	if g.Packages[1].Type != "default" || g.Packages[3].Requires != "gcc" || g.Packages[3].Name != "gcc-plugin" {
		t.Errorf("packages = %+v", g.Packages)
	}

	if len(doc.Categories) != 1 || doc.Categories[0].GroupID[0] != "build-tools" {
		t.Errorf("categories = %+v", doc.Categories)
	}
}

func TestWriteCompsXMLIsDeterministic(t *testing.T) {
	first := writeComps(t, testComps())

	for range 20 {
		if again := writeComps(t, testComps()); !bytes.Equal(first, again) {
			t.Fatalf("the output changes between runs:\n%s\n---\n%s", first, again)
		}
	}

	// The translations come out in the order of their language codes.
	out := string(first)
	if de, fr := strings.Index(out, `xml:lang="de"`), strings.Index(out, `xml:lang="fr"`); de < 0 || fr < de {
		t.Errorf("translations are not sorted:\n%s", out)
	}
}

func TestWriteCompsXMLLayout(t *testing.T) {
	c := &Comps{
		Groups: []CompsGroup{{
			ID: "g", Name: "G", UserVisible: true, DisplayOrder: 2, LangOnly: "fr",
			Packages: []CompsPackage{{Name: "p", Type: CompsConditional, Requires: "q", BaseArchOnly: true, Arch: []string{"a", "b"}}},
		}},
		Langpacks: []CompsLangpack{{Name: "n", Install: "i-%s"}},
	}

	want := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE comps PUBLIC "-//Red Hat, Inc.//DTD Comps info//EN" "comps.dtd">
<comps>
  <group>
    <id>g</id>
    <name>G</name>
    <default>false</default>
    <uservisible>true</uservisible>
    <display_order>2</display_order>
    <langonly>fr</langonly>
    <packagelist>
      <packagereq arch="a,b" basearchonly="true" requires="q" type="conditional">p</packagereq>
    </packagelist>
  </group>
  <langpacks>
    <match install="i-%s" name="n"/>
  </langpacks>
</comps>
`
	if got := string(writeComps(t, c)); got != want {
		t.Errorf("layout:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteCompsXMLNilAndEmpty(t *testing.T) {
	want := "<comps>\n</comps>\n"

	for _, c := range []*Comps{nil, {}} {
		if got := string(writeComps(t, c)); !strings.HasSuffix(got, want) {
			t.Errorf("empty comps = %q", got)
		}
	}
}

func TestCompsRoundTrip(t *testing.T) {
	want := normalizeComps(t, testComps())
	if len(want.Groups) != 2 || want.Groups[0].Packages[1].Type != CompsDefault {
		t.Fatalf("normalized model = %+v", want.Groups)
	}

	got := parseComps(t, writeComps(t, want))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip:\n got %+v\nwant %+v", got, want)
	}
}

// TestCompsTextRoundTrip: markup characters, line breaks and characters XML
// cannot carry survive (the last ones as U+FFFD).
func TestCompsTextRoundTrip(t *testing.T) {
	c := &Comps{Groups: []CompsGroup{{
		ID:                   "g",
		Name:                 " <b>\"q\" & 'a'</b>\r\n\ttab ",
		NameLocalized:        map[string]string{"x-\"quote\"&<>": "a\nb\tc"},
		Description:          "nul\x00 and \x01 and bad \xff utf-8",
		DescriptionLocalized: map[string]string{"en": "  padded  "},
		UserVisible:          true,
		Packages:             []CompsPackage{{Name: "p", Type: CompsDefault, Requires: "a\"b\n<c>"}},
	}}}

	got := parseComps(t, writeComps(t, c)).Groups[0]

	if got.Name != c.Groups[0].Name {
		t.Errorf("name = %q, want %q", got.Name, c.Groups[0].Name)
	}

	if got.NameLocalized["x-\"quote\"&<>"] != "a\nb\tc" {
		t.Errorf("localized name = %q", got.NameLocalized)
	}

	if want := "nul\uFFFD and \uFFFD and bad \uFFFD utf-8"; got.Description != want {
		t.Errorf("description = %q, want %q", got.Description, want)
	}

	if got.DescriptionLocalized["en"] != "  padded  " {
		t.Errorf("padding of a translation lost: %q", got.DescriptionLocalized["en"])
	}

	if got.Packages[0].Requires != "a\"b\n<c>" {
		t.Errorf("requires = %q", got.Packages[0].Requires)
	}
}

const readDoc = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE comps PUBLIC "-//Red Hat, Inc.//DTD Comps info//EN" "comps.dtd">
<!-- a comment -->
<comps xmlns="">
  <group arch="x86_64, aarch64 ppc64le">
    <id> core </id>
    <name> Core </name>
    <name xml:lang="de">Kern</name>
    <name xml:lang="de">Kern 2</name>
    <description>The core</description>
    <description xml:lang="fr">Le noyau</description>
    <default>TRUE</default>
    <uservisible>0</uservisible>
    <biarchonly>1</biarchonly>
    <display_order> 12 </display_order>
    <langonly>de</langonly>
    <lang_only>ignored</lang_only>
    <packagelist>
      <packagereq>bash</packagereq>
      <packagereq type="optional"> vim </packagereq>
      <packagereq basearchonly="true" requires="bash" type="conditional" arch="x86_64">less</packagereq>
      <unknown>ignored</unknown>
    </packagelist>
  </group>
  <group>
    <id>bare</id>
  </group>
  <category arch="s390x">
    <id>cat</id>
    <name>Cat</name>
    <display_order>3</display_order>
    <grouplist>
      <groupid>core</groupid>
      <groupreq>ignored</groupreq>
      <groupid arch="x86_64,ppc64le" default="false">bare</groupid>
    </grouplist>
  </category>
  <environment>
    <id>env</id>
    <name>Env</name>
    <grouplist><groupid>core</groupid></grouplist>
    <optionlist><groupid default="true">bare</groupid></optionlist>
  </environment>
  <future>
    <deep><deeper>ignored</deeper></deep>
  </future>
  <langpacks>
    <match name="aspell" install="aspell-%s"/>
    <other/>
  </langpacks>
  <langpacks>
    <match name="hunspell" install="hunspell-%s"></match>
  </langpacks>
  <blacklist>
    <package name="dev"/>
    <package name="dbus" arch="i386"/>
  </blacklist>
  <whiteout>
    <ignoredep requires="db1"/>
    <ignoredep requires="bind-utils" package="bind"/>
  </whiteout>
</comps>
`

func TestParseComps(t *testing.T) {
	got := parseComps(t, []byte(readDoc))

	want := &Comps{
		Groups: []CompsGroup{
			{
				ID: "core", Name: " Core ", Description: "The core",
				NameLocalized:        map[string]string{"de": "Kern 2"},
				DescriptionLocalized: map[string]string{"fr": "Le noyau"},
				Arch:                 []string{"x86_64", "aarch64", "ppc64le"},
				Default:              true, UserVisible: false, BiarchOnly: true, DisplayOrder: 12, LangOnly: "de",
				Packages: []CompsPackage{
					{Name: "bash", Type: CompsDefault},
					{Name: "vim", Type: CompsOptional},
					{Name: "less", Type: CompsConditional, Requires: "bash", BaseArchOnly: true, Arch: []string{"x86_64"}},
				},
			},
			{ID: "bare", UserVisible: true},
		},
		Categories: []CompsCategory{{
			ID: "cat", Name: "Cat", DisplayOrder: 3, Arch: []string{"s390x"},
			Groups: []CompsGroupRef{{ID: "core"}, {ID: "bare", Arch: []string{"x86_64", "ppc64le"}}},
		}},
		Environments: []CompsEnvironment{{
			ID: "env", Name: "Env",
			Groups:  []CompsGroupRef{{ID: "core"}},
			Options: []CompsGroupRef{{ID: "bare", Default: true}},
		}},
		Langpacks: []CompsLangpack{{Name: "aspell", Install: "aspell-%s"}, {Name: "hunspell", Install: "hunspell-%s"}},
		Blacklist: []CompsBlacklisted{{Name: "dev"}, {Name: "dbus", Arch: "i386"}},
		Whiteout:  []CompsIgnoredDep{{Requires: "db1"}, {Requires: "bind-utils", Package: "bind"}},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("model:\n got %+v\nwant %+v", got, want)
	}
}

func TestReadCompsInvalid(t *testing.T) {
	cases := map[string]string{
		"no root":                   "",
		"other root":                "<repomd></repomd>",
		"group without id":          "<comps><group><name>x</name></group></comps>",
		"category without id":       "<comps><category><id> </id></category></comps>",
		"environment without id":    "<comps><environment></environment></comps>",
		"unknown package type":      "<comps><group><id>g</id><packagelist><packagereq type=\"always\">p</packagereq></packagelist></group></comps>",
		"package without name":      "<comps><group><id>g</id><packagelist><packagereq type=\"default\"/></packagelist></group></comps>",
		"bad default":               "<comps><group><id>g</id><default>maybe</default></group></comps>",
		"bad uservisible":           "<comps><group><id>g</id><uservisible></uservisible></group></comps>",
		"bad biarchonly":            "<comps><group><id>g</id><biarchonly>yes</biarchonly></group></comps>",
		"bad basearchonly":          "<comps><group><id>g</id><packagelist><packagereq basearchonly=\"x\">p</packagereq></packagelist></group></comps>",
		"bad display_order":         "<comps><group><id>g</id><display_order>first</display_order></group></comps>",
		"empty groupid":             "<comps><category><id>c</id><grouplist><groupid/></grouplist></category></comps>",
		"bad groupid default":       "<comps><category><id>c</id><grouplist><groupid default=\"2\">g</groupid></grouplist></category></comps>",
		"langpack without name":     "<comps><langpacks><match install=\"x\"/></langpacks></comps>",
		"blacklist without name":    "<comps><blacklist><package/></blacklist></comps>",
		"ignoredep without require": "<comps><whiteout><ignoredep package=\"p\"/></whiteout></comps>",
	}

	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseComps(strings.NewReader(doc), CompsLimits{})
			if !errors.Is(err, ErrInvalidComps) {
				t.Errorf("err = %v, want ErrInvalidComps", err)
			}
		})
	}
}

func TestReadCompsMalformed(t *testing.T) {
	for _, doc := range []string{"<comps><group>", "<comps></group></comps>", "<comps></comps><", "<comps></comps></x>", "<comps>&bogus;</comps>"} {
		_, err := ParseComps(strings.NewReader(doc), CompsLimits{})
		if err == nil || errors.Is(err, ErrInvalidComps) || errors.Is(err, ErrTooLarge) {
			t.Errorf("%q: err = %v, want a syntax error", doc, err)
		}
	}
}

func TestReadCompsLimits(t *testing.T) {
	group := func(body string) string { return "<comps><group><id>g</id>" + body + "</group></comps>" }
	pkgs := strings.Repeat("<packagereq>p</packagereq>", 5)
	refs := strings.Repeat("<groupid>g</groupid>", 5)
	langs := `<name xml:lang="a">1</name><name xml:lang="b">2</name><name xml:lang="c">3</name>`

	cases := []struct {
		name string
		doc  string
		lim  CompsLimits
	}{
		{"bytes", group(""), CompsLimits{MaxBytes: 20}},
		{"entries", "<comps><group><id>a</id></group><group><id>b</id></group></comps>", CompsLimits{MaxEntries: 1}},
		{"rule entries", `<comps><blacklist><package name="a"/><package name="b"/></blacklist></comps>`, CompsLimits{MaxEntries: 1}},
		{"packages", group("<packagelist>" + pkgs + "</packagelist>"), CompsLimits{MaxListItems: 4}},
		{"group list", "<comps><category><id>c</id><grouplist>" + refs + "</grouplist></category></comps>", CompsLimits{MaxListItems: 4}},
		{"translations", group(langs), CompsLimits{MaxListItems: 2}},
		{"field", group("<name>" + strings.Repeat("x", 100) + "</name>"), CompsLimits{MaxFieldBytes: 99}},
		{"id", group("<id>" + strings.Repeat("x", 100) + "</id>"), CompsLimits{MaxFieldBytes: 99}},
		{"depth", "<comps>" + strings.Repeat("<a>", 100) + strings.Repeat("</a>", 100) + "</comps>", CompsLimits{}},
		{"depth in a group", group(strings.Repeat("<a>", 100) + strings.Repeat("</a>", 100)), CompsLimits{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseComps(strings.NewReader(tc.doc), tc.lim)
			if !errors.Is(err, ErrTooLarge) {
				t.Errorf("err = %v, want ErrTooLarge", err)
			}
		})
	}

	// A limit that is reached but not exceeded is fine.
	ok := group("<packagelist>" + pkgs + "</packagelist>" + langs)
	if _, err := ParseComps(strings.NewReader(ok), CompsLimits{MaxListItems: 5, MaxEntries: 1, MaxFieldBytes: 1}); err != nil {
		t.Errorf("limits at their value: %v", err)
	}

	if err := ValidateCompsXML([]byte("<a>" + strings.Repeat("<a>", 100))); !errors.Is(err, ErrTooLarge) {
		t.Errorf("ValidateCompsXML of a deep document: %v", err)
	}
}

func TestReadCompsVisitor(t *testing.T) {
	var order []string

	v := CompsVisitor{
		Group:       func(g *CompsGroup) error { order = append(order, "group "+g.ID); return nil },
		Category:    func(c *CompsCategory) error { order = append(order, "category "+c.ID); return nil },
		Environment: func(e *CompsEnvironment) error { order = append(order, "environment "+e.ID); return nil },
		Langpack:    func(l CompsLangpack) error { order = append(order, "langpack "+l.Name); return nil },
		Blacklisted: func(b CompsBlacklisted) error { order = append(order, "blacklist "+b.Name); return nil },
		IgnoredDep:  func(w CompsIgnoredDep) error { order = append(order, "whiteout "+w.Requires); return nil },
	}

	if err := ReadComps(strings.NewReader(readDoc), CompsLimits{}, v); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"group core", "group bare", "category cat", "environment env",
		"langpack aspell", "langpack hunspell", "blacklist dev", "blacklist dbus", "whiteout db1", "whiteout bind-utils",
	}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("order = %q, want %q", order, want)
	}

	// Skipping everything still validates the entries.
	if err := ReadComps(strings.NewReader(readDoc), CompsLimits{}, CompsVisitor{}); err != nil {
		t.Errorf("empty visitor: %v", err)
	}

	if err := ReadComps(strings.NewReader("<comps><group></group></comps>"), CompsLimits{}, CompsVisitor{}); !errors.Is(err, ErrInvalidComps) {
		t.Errorf("empty visitor on an invalid group: %v", err)
	}
}

func TestReadCompsVisitorErrorStopsTheRead(t *testing.T) {
	errStop := errors.New("stop")

	var seen int

	calls := map[string]CompsVisitor{
		"group":       {Group: func(*CompsGroup) error { seen++; return errStop }},
		"category":    {Category: func(*CompsCategory) error { seen++; return errStop }},
		"environment": {Environment: func(*CompsEnvironment) error { seen++; return errStop }},
		"langpack":    {Langpack: func(CompsLangpack) error { seen++; return errStop }},
		"blacklist":   {Blacklisted: func(CompsBlacklisted) error { seen++; return errStop }},
		"whiteout":    {IgnoredDep: func(CompsIgnoredDep) error { seen++; return errStop }},
	}

	for name, v := range calls {
		seen = 0

		if err := ReadComps(strings.NewReader(readDoc), CompsLimits{}, v); !errors.Is(err, errStop) {
			t.Errorf("%s: err = %v, want the callback error", name, err)
		}

		if seen != 1 {
			t.Errorf("%s: %d calls after the error", name, seen)
		}
	}
}

func TestReadCompsTrailingGarbage(t *testing.T) {
	var groups int

	err := ReadComps(strings.NewReader("<comps><group><id>g</id></group></comps><x"), CompsLimits{}, CompsVisitor{
		Group: func(*CompsGroup) error { groups++; return nil },
	})
	if err == nil {
		t.Error("trailing garbage is not reported")
	}

	if groups != 1 {
		t.Errorf("the group before the garbage was not delivered: %d", groups)
	}
}

func TestReadCompsNestedTextElement(t *testing.T) {
	c := parseComps(t, []byte(`<comps><group><id>g<b>skipped</b>1</id><name>a<i>b</i>c</name></group></comps>`))
	if g := c.Groups[0]; g.ID != "g1" || g.Name != "ac" {
		t.Errorf("group = %q %q", g.ID, g.Name)
	}
}

func TestWriteCompsXMLInvalid(t *testing.T) {
	cases := map[string]func(*Comps){
		"group id":            func(c *Comps) { c.Groups[0].ID = "" },
		"group id blank":      func(c *Comps) { c.Groups[0].ID = " " },
		"group id padded":     func(c *Comps) { c.Groups[0].ID = "g\n" },
		"group langonly":      func(c *Comps) { c.Groups[0].LangOnly = " de" },
		"package name padded": func(c *Comps) { c.Groups[0].Packages[0].Name = " gcc" },
		"groupid padded":      func(c *Comps) { c.Environments[0].Groups[0].ID = "g " },
		"group arch comma":    func(c *Comps) { c.Groups[0].Arch = []string{"a,b"} },
		"group arch empty":    func(c *Comps) { c.Groups[0].Arch = []string{""} },
		"group name lang":     func(c *Comps) { c.Groups[0].NameLocalized[""] = "x" },
		"group desc lang":     func(c *Comps) { c.Groups[0].DescriptionLocalized[""] = "x" },
		"package name":        func(c *Comps) { c.Groups[0].Packages[0].Name = "" },
		"package type":        func(c *Comps) { c.Groups[0].Packages[0].Type = "sometimes" },
		"package arch":        func(c *Comps) { c.Groups[0].Packages[0].Arch = []string{"a b"} },
		"category id":         func(c *Comps) { c.Categories[0].ID = "" },
		"category group":      func(c *Comps) { c.Categories[0].Groups[0].ID = "" },
		"category group arch": func(c *Comps) { c.Categories[0].Groups[0].Arch = []string{","} },
		"environment id":      func(c *Comps) { c.Environments[0].ID = "" },
		"environment group":   func(c *Comps) { c.Environments[0].Groups[0].ID = "" },
		"environment option":  func(c *Comps) { c.Environments[0].Options[0].ID = "" },
		"langpack":            func(c *Comps) { c.Langpacks[0].Name = "" },
		"blacklist":           func(c *Comps) { c.Blacklist[0].Name = "" },
		"whiteout":            func(c *Comps) { c.Whiteout[0].Requires = "" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := testComps()
			mutate(c)

			var buf bytes.Buffer

			err := WriteCompsXML(&buf, c)
			if !errors.Is(err, ErrInvalidComps) {
				t.Errorf("WriteCompsXML err = %v, want ErrInvalidComps", err)
			}

			if buf.Len() != 0 {
				t.Errorf("an invalid model wrote %d bytes", buf.Len())
			}

			if err := c.Validate(); !errors.Is(err, ErrInvalidComps) {
				t.Errorf("Validate err = %v", err)
			}
		})
	}

	if err := testComps().Validate(); err != nil {
		t.Errorf("valid model: %v", err)
	}
}

type compsFailWriter struct{ after int }

func (w *compsFailWriter) Write(p []byte) (int, error) {
	if w.after <= 0 {
		return 0, errDisk
	}

	w.after -= len(p)

	return len(p), nil
}

var errDisk = errors.New("disk full")

func TestWriteCompsXMLWriteError(t *testing.T) {
	// A group list big enough to flush in the middle of the document.
	c := &Comps{Groups: []CompsGroup{{ID: "g", Name: "g"}}}
	for range 40_000 {
		c.Groups[0].Packages = append(c.Groups[0].Packages, CompsPackage{Name: "package-with-a-long-name", Type: CompsDefault})
	}

	for _, after := range []int{0, 1 << 17} {
		if err := WriteCompsXML(&compsFailWriter{after: after}, c); !errors.Is(err, errDisk) {
			t.Errorf("after %d bytes: err = %v, want the write error", after, err)
		}
	}

	// A small document fails at Close.
	if err := WriteCompsXML(&compsFailWriter{}, testComps()); !errors.Is(err, errDisk) {
		t.Errorf("small document: err = %v", err)
	}
}

func TestCompsWriterStreaming(t *testing.T) {
	c := testComps()

	var buf bytes.Buffer

	// Merge two documents group by group without holding either.
	cw := NewCompsWriter(&buf)

	err := ReadComps(bytes.NewReader(writeComps(t, c)), CompsLimits{}, CompsVisitor{
		Group: cw.Group,
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := range c.Categories {
		if err := cw.Category(&c.Categories[i]); err != nil {
			t.Fatal(err)
		}
	}

	for i := range c.Environments {
		if err := cw.Environment(&c.Environments[i]); err != nil {
			t.Fatal(err)
		}
	}

	for _, err := range []error{cw.Langpacks(c.Langpacks), cw.Blacklist(c.Blacklist), cw.Whiteout(c.Whiteout), cw.Langpacks(nil), cw.Blacklist(nil), cw.Whiteout(nil)} {
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := cw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := cw.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if want := writeComps(t, normalizeComps(t, c)); !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("streamed:\n%s\nwant:\n%s", buf.Bytes(), want)
	}
}

func TestCompsWriterRejectsInvalidElements(t *testing.T) {
	cw := NewCompsWriter(io.Discard)

	if err := cw.Group(&CompsGroup{}); !errors.Is(err, ErrInvalidComps) {
		t.Errorf("Group: %v", err)
	}

	if err := cw.Category(&CompsCategory{}); !errors.Is(err, ErrInvalidComps) {
		t.Errorf("Category: %v", err)
	}

	if err := cw.Environment(&CompsEnvironment{}); !errors.Is(err, ErrInvalidComps) {
		t.Errorf("Environment: %v", err)
	}

	if err := cw.Langpacks([]CompsLangpack{{}}); !errors.Is(err, ErrInvalidComps) {
		t.Errorf("Langpacks: %v", err)
	}

	if err := cw.Blacklist([]CompsBlacklisted{{}}); !errors.Is(err, ErrInvalidComps) {
		t.Errorf("Blacklist: %v", err)
	}

	if err := cw.Whiteout([]CompsIgnoredDep{{}}); !errors.Is(err, ErrInvalidComps) {
		t.Errorf("Whiteout: %v", err)
	}
}

func TestValidateCompsXML(t *testing.T) {
	if err := ValidateCompsXML([]byte("<comps></comps>")); err != nil {
		t.Error(err)
	}

	if err := ValidateCompsXML([]byte("<comps><group>")); err == nil {
		t.Error("a truncated comps.xml must be invalid")
	}

	if err := ValidateCompsXML([]byte("<a></b>")); err == nil || errors.Is(err, ErrTooLarge) {
		t.Errorf("mismatched tags: %v", err)
	}

	if err := ValidateCompsXML(writeComps(t, testComps())); err != nil {
		t.Errorf("a written document: %v", err)
	}
}

// TestCompsAcceptedByCreaterepo has createrepo_c ingest the written comps.xml
// as the group file of a repository.
func TestCompsAcceptedByCreaterepo(t *testing.T) {
	if _, err := exec.LookPath("createrepo_c"); err != nil {
		t.Skip("createrepo_c is not installed")
	}

	dir := t.TempDir()

	data, err := os.ReadFile(filepath.Join("..", "testdata", "hello.rpm"))
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "hello.rpm"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	compsPath := filepath.Join(dir, "comps.xml")
	if err := os.WriteFile(compsPath, writeComps(t, testComps()), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("createrepo_c", "--no-database", "-g", compsPath, dir).CombinedOutput()
	if err != nil {
		t.Fatalf("createrepo_c: %v\n%s", err, out)
	}

	if strings.Contains(string(out), "arning") {
		t.Errorf("createrepo_c warns about comps.xml:\n%s", out)
	}

	repomd, err := os.Open(filepath.Join(dir, "repodata", "repomd.xml"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = repomd.Close() }()

	m, err := ParseRepomd(repomd)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := m.Find("group"); !ok {
		t.Error("repomd.xml has no group entry")
	}
}
