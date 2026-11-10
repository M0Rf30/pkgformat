package apk

import (
	"errors"
	"reflect"
	"testing"
)

func resolveIndex() *Index {
	idx := NewIndex()
	main := Repo{URL: "https://example.org/main"}
	edge := Repo{URL: "https://example.org/edge", Tag: "edge"}

	idx.Add(main, "x86_64", []Package{
		{Name: "app", Version: "1-r0", Depends: []string{"libfoo>=1.0", "so:libbar.so.1", "!conflict", "/bin/sh", "", "missing<2", "cycle-a"}},
		{Name: "libfoo", Version: "1-r0", Depends: []string{"libbar"}},
		{Name: "libbar", Version: "1-r0", Provides: []string{"so:libbar.so.1=1", "cmd:bar"}},
		{Name: "cycle-a", Version: "1-r0", Depends: []string{"cycle-b"}},
		{Name: "cycle-b", Version: "1-r0", Depends: []string{"cycle-a"}},
		{Name: "editor-a", Version: "1-r0", Provides: []string{"editor"}},
		{Name: "editor-b", Version: "1-r0", Provides: []string{"editor"}, ProviderPriority: 5},
		{Name: "editor-c", Version: "1-r0", Provides: []string{"editor"}, ProviderPriority: 5},
	})
	idx.Add(edge, "x86_64", []Package{
		{Name: "libfoo", Version: "2-r0"},
		{Name: "only-edge", Version: "1-r0"},
	})

	return idx
}

func names(pkgs []*RepoPackage) []string {
	var out []string
	for _, p := range pkgs {
		out = append(out, p.Name)
	}

	return out
}

func TestIndex_lookup(t *testing.T) {
	idx := resolveIndex()

	if p, ok := idx.Lookup("libfoo"); !ok || p.Version != "1-r0" || p.Repo.Tag != "" {
		t.Fatalf("first repository must win: %+v", p)
	}

	if p, ok := idx.Lookup("only-edge"); !ok || p.Repo.Tag != "edge" || p.URL() != "https://example.org/edge/x86_64/only-edge-1-r0.apk" {
		t.Fatalf("%+v", p)
	}

	if _, ok := idx.Lookup("so:libbar.so.1"); ok {
		t.Fatal("Lookup must not resolve capabilities")
	}

	if p, ok := idx.Find("so:libbar.so.1"); !ok || p.Name != "libbar" {
		t.Fatalf("%+v", p)
	}

	if p, ok := idx.ResolveVirtual("editor"); !ok || p.Name != "editor-b" {
		t.Fatalf("highest priority, then first: %+v", p)
	}

	if _, ok := idx.ResolveVirtual("nothing"); ok {
		t.Fatal("unknown capability resolved")
	}

	if _, ok := idx.Find("nothing"); ok {
		t.Fatal("unknown name found")
	}

	if n, c := idx.Stats(); n != 9 || c != 3 {
		t.Fatalf("stats %d %d", n, c)
	}
}

func TestIndex_resolveDeps(t *testing.T) {
	idx := resolveIndex()

	res, err := idx.ResolveDeps([]string{"app"})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := names(res.Packages), []string{"libbar", "libfoo", "cycle-b", "cycle-a", "app"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order %q, want %q", got, want)
	}

	if want := []string{"so:libbar.so.1"}; !reflect.DeepEqual(res.Virtual, want) {
		t.Fatalf("virtual %q", res.Virtual)
	}

	if want := []string{"missing"}; !reflect.DeepEqual(res.Unresolved, want) {
		t.Fatalf("unresolved %q", res.Unresolved)
	}

	// The same package by name and by capability appears once.
	res, err = idx.ResolveDeps([]string{"cmd:bar", "libbar", "libfoo"})
	if err != nil {
		t.Fatal(err)
	}

	if got := names(res.Packages); !reflect.DeepEqual(got, []string{"libbar", "libfoo"}) {
		t.Fatalf("got %q", got)
	}

	if _, err := idx.ResolveDeps([]string{"app", "absent>=1"}); !errors.Is(err, ErrPackageNotFound) {
		t.Fatalf("got %v", err)
	}

	if res, err := idx.ResolveDeps(nil); err != nil || len(res.Packages) != 0 {
		t.Fatalf("empty request: %v %v", res, err)
	}
}

func TestDependencyName(t *testing.T) {
	for in, want := range map[string]string{
		"musl-dev":          "musl-dev",
		"musl-dev>=1.2":     "musl-dev",
		"so:libc.so.6=1":    "so:libc.so.6",
		"a<2":               "a",
		"a~1.2":             "a",
		"a>1":               "a",
		" a = 1 ":           "a",
		"pc:openssl>=1.1.0": "pc:openssl",
		"":                  "",
	} {
		if got := DependencyName(in); got != want {
			t.Errorf("DependencyName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIndex_largeDependencyChain(t *testing.T) {
	idx := NewIndex()

	var pkgs []Package

	const depth = 5000

	for i := range depth {
		p := Package{Name: "p" + itoa(i), Version: "1"}
		if i+1 < depth {
			p.Depends = []string{"p" + itoa(i+1)}
		}

		pkgs = append(pkgs, p)
	}

	idx.Add(Repo{URL: "https://example.org"}, "x86_64", pkgs)

	res, err := idx.ResolveDeps([]string{"p0"})
	if err != nil || len(res.Packages) != depth {
		t.Fatalf("%d packages, %v", len(res.Packages), err)
	}
}

func itoa(i int) string {
	const digits = "0123456789"

	if i == 0 {
		return "0"
	}

	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{digits[i%10]}, b...)
	}

	return string(b)
}
