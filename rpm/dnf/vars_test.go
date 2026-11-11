package dnf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandVars(t *testing.T) {
	varsDir := t.TempDir()
	for name, val := range map[string]string{"infra": "stock\n", "contentdir": "  pub/rocky  "} {
		if err := os.WriteFile(filepath.Join(varsDir, name), []byte(val), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	c := New(Options{
		Releasever: "9.4",
		Arch:       "x86_64",
		VarsDirs:   []string{varsDir},
		Vars:       map[string]string{"infra": "override", "extra": "x"},
	})

	for in, want := range map[string]string{
		"https://h/$releasever/$basearch/os":     "https://h/9.4/x86_64/os",
		"https://h/${releasever}/${basearch}/os": "https://h/9.4/x86_64/os",
		"https://h/$infra/$contentdir/":          "https://h/override/pub/rocky/",
		"https://h/$extra":                       "https://h/x",
		"https://h/$unknown/${nope}/":            "https://h/$unknown/${nope}/",
		"https://h//a///b/":                      "https://h/a/b/",
		"https://h/$releasever$basearch":         "https://h/9.4x86_64",
		"https://h/$":                            "https://h/$",
		"https://h/${":                           "https://h/${",
		"https://h/${}":                          "https://h/${}",
		"https://h/$1abc":                        "https://h/$1abc",
		"https://h/$../x":                        "https://h/$../x",
	} {
		if got := c.expandVars(in); got != want {
			t.Errorf("expandVars(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpandVarsUnsetReleasever(t *testing.T) {
	c := New(Options{Arch: "aarch64"})
	if got := c.expandVars("https://h/$releasever/$basearch"); got != "https://h/$releasever/aarch64" {
		t.Errorf("got %q", got)
	}
}

func TestVarFileIsNotAPathEscape(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("leak"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := New(Options{VarsDirs: []string{filepath.Join(dir, "vars")}})
	// A name is [A-Za-z0-9_]+, so it cannot reach outside VarsDir; the
	// lookup of a name that is not a segment is refused outright.
	if _, ok := c.lookupVar("../secret"); ok {
		t.Error("looked up a variable outside the vars directory")
	}
}

func TestVarFileMemoizedAndLimited(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v")

	if err := os.WriteFile(path, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := New(Options{VarsDirs: []string{dir}})
	if got := c.expandVars("$v"); got != "one" {
		t.Fatal(got)
	}

	if err := os.WriteFile(path, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := c.expandVars("$v"); got != "one" {
		t.Errorf("a variable file is read once per client, got %q", got)
	}

	big := make([]byte, maxVarBytes+1)
	if err := os.WriteFile(filepath.Join(dir, "big"), big, 0o644); err != nil {
		t.Fatal(err)
	}

	if got := c.expandVars("$big"); got != "$big" {
		t.Errorf("oversized variable was used: %d bytes", len(got))
	}
}

func TestNormalizeURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://h//a//b":      "https://h/a/b",
		"https://h/a/b":        "https://h/a/b",
		"https://h/a?x=1//2":   "https://h/a?x=1//2",
		"http://[::1]:8080//x": "http://[::1]:8080/x",
		"%zz":                  "%zz",
	} {
		if got := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestArchMapping(t *testing.T) {
	for arch, want := range map[string]string{
		"x86_64": "x86_64", "i686": "i386", "i386": "i386", "armv7hl": "armhfp",
		"aarch64": "aarch64", "ppc64le": "ppc64le", "i68": "i68",
	} {
		if got := baseArch(arch); got != want {
			t.Errorf("baseArch(%q) = %q, want %q", arch, got, want)
		}
	}

	if goArchToRPM() == "" {
		t.Error("no architecture for the running program")
	}
}

func TestExpandVersionVariables(t *testing.T) {
	for rel, want := range map[string]string{
		"9.4":     "9.4|9|4",
		"40":      "40|40|",
		"9.4.1":   "9.4.1|9|4.1",
		"rawhide": "rawhide|rawhide|",
	} {
		c := New(Options{Releasever: rel, Arch: "x86_64"})
		if got := c.expandVars("$releasever|$releasever_major|$releasever_minor"); got != want {
			t.Errorf("%s: %q, want %q", rel, got, want)
		}
	}

	// without a releasever, none of them is known
	c := New(Options{Arch: "x86_64"})
	if got := c.expandVars("$releasever_major.$releasever_minor"); got != "$releasever_major.$releasever_minor" {
		t.Errorf("got %q", got)
	}

	if got := New(Options{Arch: "i686"}).expandVars("$arch/$basearch"); got != "i686/i386" {
		t.Errorf("got %q", got)
	}
}

func TestVarsDirsOfDnfConf(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()

	for dir, name := range map[string]string{first: "one", second: "two"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("v-"+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	c := New(Options{Config: &Config{VarsDirs: []string{first, second}}})
	if got := c.expandVars("$one/$two/$three"); got != "v-one/v-two/$three" {
		t.Errorf("got %q", got)
	}

	// Options.VarsDirs takes precedence
	c = New(Options{Config: &Config{VarsDirs: []string{first}}, VarsDirs: []string{second}})
	if got := c.expandVars("$one/$two"); got != "$one/v-two" {
		t.Errorf("got %q", got)
	}
}

func TestArchNames(t *testing.T) {
	for in, want := range map[string]string{
		"i686": "i386", "i586": "i386", "armv7hl": "armhfp", "armv6l": "armhfp", "x86_64": "x86_64", "ppc64le": "ppc64le",
	} {
		if got := baseArch(in); got != want {
			t.Errorf("baseArch(%q) = %q, want %q", in, got, want)
		}
	}

	if goArchToRPM() == "" {
		t.Error("no architecture for this host")
	}
}
