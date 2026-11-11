package apk

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func resolveIndex() *Index {
	idx := NewIndex()
	main := Repo{URL: "https://example.org/main"}
	edge := Repo{URL: "https://example.org/edge", Tag: "edge"}

	idx.Add(main, "x86_64", []Package{
		{Name: "app", Version: "1-r0", Depends: []string{"libfoo>=1", "so:libbar.so.1", "!conflict", "cycle-a"}},
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

	if n, c := idx.Stats(); n != 10 || c != 3 {
		t.Fatalf("stats %d %d", n, c)
	}
}

func TestIndex_solve(t *testing.T) {
	idx := resolveIndex()

	sol, err := idx.Solve(SolveRequest{World: []string{"app"}})
	if err != nil {
		t.Fatal(err)
	}

	got := names(sol.Packages)
	pos := map[string]int{}

	for i, n := range got {
		pos[n] = i
	}

	if len(got) != 5 || pos["libbar"] > pos["libfoo"] || pos["libfoo"] > pos["app"] {
		t.Fatalf("order %q", got)
	}

	if len(sol.Changes) != 5 || sol.Changes[0].Kind() != ChangeInstall {
		t.Fatalf("changes %+v", sol.Changes)
	}

	// The same package by name and by capability appears once.
	sol, err = idx.Solve(SolveRequest{World: []string{"cmd:bar", "libbar", "libfoo"}})
	if err != nil {
		t.Fatal(err)
	}

	if got := names(sol.Packages); !reflect.DeepEqual(got, []string{"libbar", "libfoo"}) {
		t.Fatalf("got %q", got)
	}

	_, err = idx.Solve(SolveRequest{World: []string{"app", "absent>=1"}})

	var se *SolveError
	if !errors.Is(err, ErrUnsatisfiable) || !errors.As(err, &se) || se.Problems[0].Name != "absent" ||
		!strings.Contains(err.Error(), "required by") {
		t.Fatalf("got %v", err)
	}

	if _, err := idx.Solve(SolveRequest{World: []string{"libfoo@nope"}}); !errors.Is(err, ErrUnsatisfiable) {
		t.Fatalf("unknown tag: %v", err)
	}

	if _, err := idx.Solve(SolveRequest{World: []string{"bad name"}}); !errors.Is(err, ErrUnsatisfiable) {
		t.Fatalf("invalid entry: %v", err)
	}

	if sol, err := idx.Solve(SolveRequest{}); err != nil || len(sol.Packages) != 0 {
		t.Fatalf("empty request: %v %v", sol, err)
	}
}

func TestSolve_stepLimit(t *testing.T) {
	// Every a<i> needs a b that conflicts with the next choice: exponential
	// backtracking that must stop at the budget.
	var pkgs []Package

	const n = 24

	for i := range n {
		is := itoa(i)
		pkgs = append(pkgs,
			Package{Name: "x" + is, Version: "1", Depends: []string{"y" + is + "=1"}},
			Package{Name: "y" + is, Version: "1", Depends: []string{"!z"}, Provides: []string{"y" + is + "=1"}},
			Package{Name: "y" + is, Version: "2", Provides: []string{"y" + is + "=2"}, Depends: []string{"!z"}},
		)
	}

	pkgs = append(pkgs, Package{Name: "z", Version: "1"})

	idx := NewIndex()
	idx.Add(Repo{URL: "https://example.org"}, "x86_64", pkgs)

	var world []string
	for i := range n {
		world = append(world, "x"+itoa(i))
	}

	world = append(world, "z")

	if _, err := idx.Solve(SolveRequest{World: world}); err == nil {
		t.Fatal("conflicting world must fail")
	}
}

func TestChangeKind(t *testing.T) {
	old := &Package{Name: "a", Version: "1"}

	for _, tc := range []struct {
		c    Change
		want ChangeKind
		str  string
	}{
		{Change{New: &RepoPackage{Package: Package{Version: "1"}}}, ChangeInstall, "install"},
		{Change{Old: old}, ChangeRemove, "remove"},
		{Change{Old: old, New: &RepoPackage{Package: Package{Version: "2"}}}, ChangeUpgrade, "upgrade"},
		{Change{Old: &Package{Version: "3"}, New: &RepoPackage{Package: Package{Version: "2"}}}, ChangeDowngrade, "downgrade"},
		{Change{Old: old, New: &RepoPackage{Package: Package{Version: "1"}}}, ChangeReinstall, "reinstall"},
	} {
		if k := tc.c.Kind(); k != tc.want || k.String() != tc.str {
			t.Errorf("%v: %v", tc.want, k)
		}
	}

	if ChangeKind(0).String() != "unknown" {
		t.Error("zero kind")
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

	sol, err := idx.Solve(SolveRequest{World: []string{"p0"}})
	if err != nil || len(sol.Packages) != depth {
		t.Fatalf("%v, %v", sol, err)
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
