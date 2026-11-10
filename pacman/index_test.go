package pacman

import (
	"bytes"
	"errors"
	"slices"
	"strconv"
	"testing"
)

func TestParseDependency(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]Dependency{
		"glibc":          {Name: "glibc"},
		"sh>=5":          {Name: "sh", Op: ">=", Version: "5"},
		"sh<=5":          {Name: "sh", Op: "<=", Version: "5"},
		"sh=1:5-2":       {Name: "sh", Op: "=", Version: "1:5-2"},
		"lib++<2":        {Name: "lib++", Op: "<", Version: "2"},
		"libfoo.so>3":    {Name: "libfoo.so", Op: ">", Version: "3"},
		"libfoo.so=3-64": {Name: "libfoo.so", Op: "=", Version: "3-64"},
	} {
		got, err := ParseDependency(in)
		if err != nil || got != want {
			t.Errorf("ParseDependency(%q) = %+v, %v; want %+v", in, got, err, want)
		}

		if got.String() != in {
			t.Errorf("String() = %q, want %q", got.String(), in)
		}
	}

	for _, in := range []string{"", ">=1", "foo>=", "foo>>1", "foo=1=2", "foo bar", "a/b", "foo: desc", ".hidden", "-x", "foo=>1", "\x00", string(make([]byte, 2000))} {
		if _, err := ParseDependency(in); !errors.Is(err, ErrInvalidDependency) {
			t.Errorf("ParseDependency(%q) err = %v", in, err)
		}
	}
}

func TestDependencyAllows(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		dep, ver string
		want     bool
	}{
		{"x", "1", true}, {"x=1", "1-2", true}, {"x=1-1", "1-2", false}, {"x<2", "1.9", true}, {"x<2", "2", false},
		{"x<=2", "2", true}, {"x>2", "2.0.1", true}, {"x>2", "2", false}, {"x>=1:0", "9", false}, {"x>=1:0", "1:0", true},
	} {
		d, err := ParseDependency(c.dep)
		if err != nil {
			t.Fatal(err)
		}

		if got := d.Allows(c.ver); got != c.want {
			t.Errorf("%s allows %s = %v, want %v", c.dep, c.ver, got, c.want)
		}
	}
}

func testIndex(t *testing.T) *Index {
	t.Helper()

	x := &Index{}
	core := []DBEntry{
		{Name: "app", Version: "1-1", Depends: []string{"libfoo.so>=2", "sh", "util"}},
		{Name: "util", Version: "1.0-1", Depends: []string{"glibc"}},
		{Name: "util", Version: "1.10-1", Depends: []string{"glibc"}},
		{Name: "util", Version: "1.9-1", Depends: []string{"glibc"}},
		{Name: "glibc", Version: "2.40-1"},
		{Name: "bash", Version: "5.2-1", Provides: []string{"sh"}, Depends: []string{"glibc"}},
		{Name: "dash", Version: "0.5-1", Provides: []string{"sh", "dash=0.5"}},
		{Name: "libfoo", Version: "2.1-1", Provides: []string{"libfoo.so=2.1-64", "unversioned"}},
		{Name: "cyc-a", Version: "1-1", Depends: []string{"cyc-b"}},
		{Name: "cyc-b", Version: "1-1", Depends: []string{"cyc-a"}},
	}
	extra := []DBEntry{
		{Name: "util", Version: "9-1"},
		{Name: "sh", Version: "1-1"},
		{Name: "needs-missing", Version: "1-1", Depends: []string{"ghost>=1"}},
		{Name: "broken", Version: "1-1", Depends: []string{"bad dep"}},
	}

	if err := x.Add("core", core); err != nil {
		t.Fatal(err)
	}

	if err := x.Add("extra", extra); err != nil {
		t.Fatal(err)
	}

	return x
}

func names(pkgs []*IndexedPackage) []string {
	out := make([]string, len(pkgs))
	for i, p := range pkgs {
		out[i] = p.Name + "@" + p.Repo
	}

	return out
}

func TestIndexLookup(t *testing.T) {
	t.Parallel()

	x := testIndex(t)

	if x.Len() != 14 || len(x.Packages()) != 14 {
		t.Errorf("Len = %d", x.Len())
	}

	// First repository wins, then the newest version within it.
	if p, ok := x.Lookup("util"); !ok || p.Repo != "core" || p.Version != "1.10-1" {
		t.Errorf("Lookup(util) = %+v, %v", p, ok)
	}

	if _, ok := x.Lookup("ghost"); ok {
		t.Error("Lookup(ghost) found")
	}

	if _, ok := (&Index{}).Lookup("x"); ok {
		t.Error("empty index found a package")
	}
}

func TestIndexResolve(t *testing.T) {
	t.Parallel()

	x := testIndex(t)

	for dep, want := range map[string]string{
		"util":             "util@core",
		"util<1.5":         "util@core",
		"util>=5":          "util@extra",
		"sh":               "sh@extra", // an exact name beats a provider, whatever the repository
		"libfoo.so>=2":     "libfoo@core",
		"dash=0.5":         "dash@core",
		"unversioned":      "libfoo@core",
		"glibc>=2.40":      "glibc@core",
		"libfoo.so=2.1-64": "libfoo@core",
	} {
		d, err := ParseDependency(dep)
		if err != nil {
			t.Fatal(err)
		}

		p, err := x.Resolve(d)
		if err != nil {
			t.Errorf("Resolve(%s): %v", dep, err)

			continue
		}

		if got := p.Name + "@" + p.Repo; got != want {
			t.Errorf("Resolve(%s) = %s, want %s", dep, got, want)
		}
	}

	for _, dep := range []string{"ghost", "glibc>=3", "libfoo.so>=3", "unversioned>=1", "util>=10"} {
		d, _ := ParseDependency(dep)
		if _, err := x.Resolve(d); !errors.Is(err, ErrUnresolved) {
			t.Errorf("Resolve(%s) err = %v", dep, err)
		}
	}
}

func TestIndexProviders(t *testing.T) {
	t.Parallel()

	x := testIndex(t)

	got := names(x.Providers(Dependency{Name: "sh"}))
	if !slices.Equal(got, []string{"bash@core", "dash@core"}) {
		t.Errorf("providers of sh = %v", got)
	}

	if got := x.Providers(Dependency{Name: "sh", Op: ">=", Version: "1"}); len(got) != 0 {
		t.Errorf("versionless provisions satisfied a versioned dependency: %v", names(got))
	}
}

func TestResolveDeps(t *testing.T) {
	t.Parallel()

	x := testIndex(t)

	got, err := x.ResolveDeps([]string{"app"}, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// libfoo, then sh (the exact "sh" package of extra), then util with glibc first.
	want := []string{"libfoo@core", "sh@extra", "glibc@core", "util@core", "app@core"}
	if !slices.Equal(names(got), want) {
		t.Errorf("order = %v, want %v", names(got), want)
	}

	// Installed dependencies are not pulled in.
	got, err = x.ResolveDeps([]string{"app"}, ResolveOptions{Installed: func(d Dependency) bool {
		return d.Name == "glibc" || d.Name == "sh"
	}})
	if err != nil {
		t.Fatal(err)
	}

	if want := []string{"libfoo@core", "util@core", "app@core"}; !slices.Equal(names(got), want) {
		t.Errorf("with installed: %v, want %v", names(got), want)
	}

	// Several roots share dependencies and appear once.
	got, err = x.ResolveDeps([]string{"util", "bash", "util"}, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if want := []string{"glibc@core", "util@core", "bash@core"}; !slices.Equal(names(got), want) {
		t.Errorf("roots: %v, want %v", names(got), want)
	}
}

func TestResolveDepsCycle(t *testing.T) {
	t.Parallel()

	got, err := testIndex(t).ResolveDeps([]string{"cyc-a"}, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if want := []string{"cyc-b@core", "cyc-a@core"}; !slices.Equal(names(got), want) {
		t.Errorf("cycle order = %v, want %v", names(got), want)
	}
}

func TestResolveDepsErrors(t *testing.T) {
	t.Parallel()

	x := testIndex(t)

	_, err := x.ResolveDeps([]string{"needs-missing"}, ResolveOptions{})
	if !errors.Is(err, ErrUnresolved) || err.Error() != "pacman: unresolvable dependency: ghost>=1 (required by needs-missing)" {
		t.Errorf("err = %v", err)
	}

	if _, err := x.ResolveDeps([]string{"ghost"}, ResolveOptions{}); !errors.Is(err, ErrUnresolved) {
		t.Errorf("unknown root: %v", err)
	}

	if _, err := x.ResolveDeps([]string{"bad dep"}, ResolveOptions{}); !errors.Is(err, ErrInvalidDependency) {
		t.Errorf("bad root: %v", err)
	}

	if _, err := x.ResolveDeps([]string{"broken"}, ResolveOptions{}); !errors.Is(err, ErrInvalidDependency) {
		t.Errorf("bad depends entry: %v", err)
	}
}

func TestResolveDepsLongChain(t *testing.T) {
	t.Parallel()

	const n = 50000

	entries := make([]DBEntry, n)
	for i := range entries {
		entries[i] = DBEntry{Name: "p" + itoa(i), Version: "1-1"}
		if i+1 < n {
			entries[i].Depends = []string{"p" + itoa(i+1)}
		}
	}

	x := &Index{}
	if err := x.Add("r", entries); err != nil {
		t.Fatal(err)
	}

	got, err := x.ResolveDeps([]string{"p0"}, ResolveOptions{})
	if err != nil || len(got) != n || got[0].Name != "p"+itoa(n-1) {
		t.Fatalf("len = %d, err = %v", len(got), err)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestIndexAddDatabase(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := WriteDB(&buf, []DBEntry{{Filename: "a-1-1-any.pkg.tar.zst", Name: "a", Version: "1-1", Arch: "any", CSize: 1, SHA256: "00"}}, false); err != nil {
		t.Fatal(err)
	}

	x := &Index{}
	if err := x.AddDatabase("r", &buf); err != nil {
		t.Fatal(err)
	}

	if p, ok := x.Lookup("a"); !ok || p.Repo != "r" {
		t.Errorf("Lookup = %+v, %v", p, ok)
	}

	if err := x.AddDatabase("r", bytes.NewReader([]byte("junk"))); err == nil {
		t.Error("junk database accepted")
	}
}
