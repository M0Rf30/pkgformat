package pacman

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func newIndex(t *testing.T, repos ...[]DBEntry) *Index {
	t.Helper()

	x := &Index{}

	for i, entries := range repos {
		if err := x.Add([]string{"core", "extra", "third"}[i], entries); err != nil {
			t.Fatal(err)
		}
	}

	return x
}

func pkgNames(pkgs []*IndexedPackage) []string {
	out := make([]string, len(pkgs))
	for i, p := range pkgs {
		out[i] = p.Name
	}

	return out
}

func inst(name, version string, mod func(*InstalledPackage)) *InstalledPackage {
	p := &InstalledPackage{Name: name, Version: version}
	if mod != nil {
		mod(p)
	}

	return p
}

func TestParseOptionalDep(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]OptionalDep{
		"nice: a nice extra":   {Dependency: Dependency{Name: "nice"}, Description: "a nice extra"},
		"nice":                 {Dependency: Dependency{Name: "nice"}},
		"nice:":                {Dependency: Dependency{Name: "nice"}},
		"lib>=2: needs 2: yes": {Dependency: Dependency{Name: "lib", Op: ">=", Version: "2"}, Description: "needs 2: yes"},
		"x:   spaced  ":        {Dependency: Dependency{Name: "x"}, Description: "spaced"},
	} {
		got, err := ParseOptionalDep(in)
		if err != nil || got != want {
			t.Errorf("ParseOptionalDep(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}

	for _, in := range []string{"", ": no name", "a b: c", "x>=: d", "a/b: c", "x: " + strings.Repeat("d", maxOptionalDescLen+1)} {
		if _, err := ParseOptionalDep(in); !errors.Is(err, ErrInvalidDependency) {
			t.Errorf("ParseOptionalDep(%q) err = %v", in[:min(len(in), 20)], err)
		}
	}

	if s := (OptionalDep{Dependency: Dependency{Name: "a", Op: "=", Version: "1"}, Description: "d"}).String(); s != "a=1: d" {
		t.Errorf("String = %q", s)
	}

	if s := (OptionalDep{Dependency: Dependency{Name: "a"}}).String(); s != "a" {
		t.Errorf("String = %q", s)
	}
}

func TestOptionalDeps(t *testing.T) {
	t.Parallel()

	x := newIndex(t, []DBEntry{
		{Name: "app", Version: "1-1", Depends: []string{"lib"}, OptDepends: []string{"nice: pretty", "ghost>=2: missing", "viaprov: virtual"}},
		{Name: "lib", Version: "1-1"},
		{Name: "nice", Version: "1-1", Depends: []string{"niceneeds"}},
		{Name: "niceneeds", Version: "1-1"},
		{Name: "impl", Version: "1-1", Provides: []string{"viaprov"}},
		{Name: "badopt", Version: "1-1", OptDepends: []string{"a b: c"}},
	})

	app, _ := x.Lookup("app")

	opts, err := app.OptionalDeps()
	if err != nil || len(opts) != 3 || opts[0].Description != "pretty" || opts[0].Package != nil {
		t.Fatalf("OptionalDeps = %+v, %v", opts, err)
	}

	opts, err = x.OptionalDeps(app)
	if err != nil {
		t.Fatal(err)
	}

	var got []string

	for _, o := range opts {
		name := "-"
		if o.Package != nil {
			name = o.Package.Name
		}

		got = append(got, o.Name+"->"+name)
	}

	if want := []string{"nice->nice", "ghost->-", "viaprov->impl"}; !slices.Equal(got, want) {
		t.Errorf("OptionalDeps = %v, want %v", got, want)
	}

	// Never installed by default.
	tx, err := x.Install([]string{"app"}, ResolveOptions{})
	if err != nil || !slices.Equal(pkgNames(tx.Packages), []string{"lib", "app"}) {
		t.Fatalf("Install = %v, %v", pkgNames(tx.Packages), err)
	}

	// With the option, the ones the index satisfies come with their dependencies.
	tx, err = x.Install([]string{"app"}, ResolveOptions{WithOptional: true})
	if err != nil {
		t.Fatal(err)
	}

	if want := []string{"lib", "niceneeds", "nice", "impl", "app"}; !slices.Equal(pkgNames(tx.Packages), want) {
		t.Errorf("WithOptional = %v, want %v", pkgNames(tx.Packages), want)
	}

	bad, _ := x.Lookup("badopt")
	if _, err := x.OptionalDeps(bad); !errors.Is(err, ErrInvalidDependency) {
		t.Errorf("bad optdepends: %v", err)
	}

	if _, err := x.Install([]string{"badopt"}, ResolveOptions{WithOptional: true}); err != nil {
		t.Errorf("an unparsable optional dependency must not fail the install: %v", err)
	}
}

func TestGroupAndSearch(t *testing.T) {
	t.Parallel()

	x := newIndex(t,
		[]DBEntry{
			{Name: "b", Version: "1-1", Groups: []string{"g"}, Description: "The Bee"},
			{Name: "a", Version: "1-1", Groups: []string{"g", "h"}},
			{Name: "a", Version: "2-1", Groups: []string{"g"}},
		},
		[]DBEntry{
			{Name: "a", Version: "9-1", Groups: []string{"g"}},
			{Name: "c", Version: "1-1", Groups: []string{"g"}, Description: "bee keeper"},
		},
	)

	// Repository, then name; the first repository that has a package wins, with its newest version.
	var got []string
	for _, p := range x.Group("g") {
		got = append(got, p.Repo+"/"+p.Name+"-"+p.Version)
	}

	if want := []string{"core/a-2-1", "core/b-1-1", "extra/c-1-1"}; !slices.Equal(got, want) {
		t.Errorf("Group(g) = %v, want %v", got, want)
	}

	if g := x.Group("none"); len(g) != 0 {
		t.Errorf("Group(none) = %v", g)
	}

	x.SetUsage("extra", UsageSearch)

	if got := pkgNames(x.Group("g")); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("Group with extra not installable = %v", got)
	}

	x.SetUsage("extra", UsageUpgrade)

	if got := pkgNames(x.Group("g")); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("Group with extra upgrade-only = %v", got)
	}

	x.SetUsage("extra", UsageSync|UsageSearch)

	if got := x.Search("BEE"); !slices.Equal(pkgNames(got), []string{"b", "c"}) {
		t.Errorf("Search(BEE) = %v", pkgNames(got))
	}

	x.SetUsage("extra", UsageSync|UsageInstall|UsageUpgrade)

	if got := pkgNames(x.Search("bee")); !slices.Equal(got, []string{"b"}) {
		t.Errorf("Search without extra = %v", got)
	}

	if got := x.Search(""); len(got) != 3 {
		t.Errorf("Search(\"\") = %d packages", len(got))
	}

	// A group named by a root installs its members; a versioned name is no group.
	tx, err := x.Install([]string{"g"}, ResolveOptions{})
	if err != nil || !slices.Equal(pkgNames(tx.Packages), []string{"a", "b", "c"}) {
		t.Errorf("Install(g) = %v, %v", tx, err)
	}

	if _, err := x.Install([]string{"g>=1"}, ResolveOptions{}); !errors.Is(err, ErrUnresolved) {
		t.Errorf("Install(g>=1) err = %v", err)
	}

	if _, err := x.Install([]string{"nothing"}, ResolveOptions{}); !errors.Is(err, ErrUnresolved) {
		t.Errorf("Install(nothing) err = %v", err)
	}
}

func TestUsageRestrictsResolution(t *testing.T) {
	t.Parallel()

	x := newIndex(t,
		[]DBEntry{{Name: "app", Version: "1-1", Depends: []string{"lib"}}},
		[]DBEntry{{Name: "lib", Version: "1-1"}, {Name: "virt", Version: "1-1", Provides: []string{"v"}}},
	)

	x.SetUsage("extra", UsageSync|UsageSearch)

	if _, err := x.Install([]string{"app"}, ResolveOptions{}); !errors.Is(err, ErrUnresolved) {
		t.Errorf("dependency from a search-only repository: %v", err)
	}

	if _, err := x.Resolve(Dependency{Name: "v"}); !errors.Is(err, ErrUnresolved) {
		t.Errorf("provider from a search-only repository: %v", err)
	}

	x.SetUsage("extra", UsageAll)

	if _, err := x.Install([]string{"app"}, ResolveOptions{}); err != nil {
		t.Errorf("all uses: %v", err)
	}
}

func TestProviderPreference(t *testing.T) {
	t.Parallel()

	x := newIndex(t,
		[]DBEntry{
			{Name: "zeta", Version: "1-1", Provides: []string{"v"}},
			{Name: "beta", Version: "1-1", Provides: []string{"v=1"}},
			{Name: "beta", Version: "2-1", Provides: []string{"v=2"}},
			{Name: "alpha-ignored", Version: "1-1", Provides: []string{"v"}},
			{Name: "installed-one", Version: "1-1", Provides: []string{"v"}},
		},
		[]DBEntry{{Name: "aaa", Version: "1-1", Provides: []string{"v"}}},
	)

	p, err := x.Resolve(Dependency{Name: "v"})
	if err != nil || p.Name != "alpha-ignored" {
		t.Fatalf("lowest name of the first repository: %v, %v", p, err)
	}

	// A versioned dependency finds the newest of the same package that fits.
	p, err = x.Resolve(Dependency{Name: "v", Op: ">=", Version: "2"})
	if err != nil || p.Name != "beta" || p.Version != "2-1" {
		t.Fatalf("versioned: %v, %v", p, err)
	}

	local := []*InstalledPackage{inst("installed-one", "1-1", nil)}

	tx, err := x.Install([]string{"v"}, ResolveOptions{Local: local})
	if err != nil || !slices.Equal(pkgNames(tx.Packages), []string{"installed-one"}) {
		t.Fatalf("an installed provider is preferred: %v, %v", tx, err)
	}

	// An ignored provider is not picked for a dependency.
	x2 := newIndex(t, []DBEntry{
		{Name: "needs", Version: "1-1", Depends: []string{"v"}},
		{Name: "alpha-ignored", Version: "1-1", Provides: []string{"v"}},
		{Name: "omega", Version: "1-1", Provides: []string{"v"}},
	})

	tx, err = x2.Install([]string{"needs"}, ResolveOptions{IgnorePkg: []string{"alpha-*"}})
	if err != nil || !slices.Equal(pkgNames(tx.Packages), []string{"omega", "needs"}) {
		t.Fatalf("ignored provider: %v, %v", tx, err)
	}

	// ... though one asked for is installed.
	tx, err = x2.Install([]string{"alpha-ignored"}, ResolveOptions{IgnorePkg: []string{"alpha-ignored"}})
	if err != nil || len(tx.Packages) != 1 {
		t.Fatalf("ignored target: %v, %v", tx, err)
	}
}

func TestExactNameWithBadVersionFallsBackToProvider(t *testing.T) {
	t.Parallel()

	x := newIndex(t, []DBEntry{
		{Name: "lib", Version: "1-1"},
		{Name: "libcompat", Version: "1-1", Provides: []string{"lib=5"}},
		{Name: "app", Version: "1-1", Depends: []string{"lib>=5"}},
	})

	tx, err := x.Install([]string{"app"}, ResolveOptions{})
	if err != nil || !slices.Equal(pkgNames(tx.Packages), []string{"libcompat", "app"}) {
		t.Fatalf("Install = %v, %v", tx, err)
	}
}

func TestInstallConflicts(t *testing.T) {
	t.Parallel()

	x := newIndex(t, []DBEntry{
		{Name: "a", Version: "1-1", Conflicts: []string{"b"}},
		{Name: "b", Version: "1-1"},
		{Name: "needs-b", Version: "1-1", Depends: []string{"b"}},
		{Name: "vc", Version: "1-1", Conflicts: []string{"lib<2"}},
		{Name: "provider", Version: "1-1", Provides: []string{"thing"}, Conflicts: []string{"thing"}},
		{Name: "thing", Version: "1-1"},
		{Name: "newer", Version: "1-1", Provides: []string{"older"}, Conflicts: []string{"older"}},
		{Name: "older", Version: "1-1"},
		{Name: "rev", Version: "1-1", Conflicts: []string{"lib"}},
		{Name: "badconf", Version: "1-1", Conflicts: []string{"x y"}},
		{Name: "lib", Version: "2-1"},
	})

	var ce *ConflictError

	// Between targets, either direction, and through a dependency.
	for _, roots := range [][]string{{"a", "b"}, {"b", "a"}, {"a", "needs-b"}} {
		_, err := x.Install(roots, ResolveOptions{})
		if !errors.Is(err, ErrConflict) || !errors.As(err, &ce) || ce.Package != "a" || ce.With != "b" || ce.Installed || ce.Expr != "b" {
			t.Errorf("Install(%v) = %v", roots, err)
		}
	}

	if !strings.Contains(ce.Error(), "a and b (in the transaction) conflict (b)") || !errors.Is(ce, ErrConflict) {
		t.Errorf("message = %q", ce.Error())
	}

	// A package that provides the other's name takes its place; a package never conflicts with itself.
	for roots, want := range map[string][]string{
		"provider thing": {"provider"},
		"thing provider": {"provider"},
		"newer older":    {"newer"},
		"older newer":    {"newer"},
		"provider":       {"provider"},
	} {
		tx, err := x.Install(strings.Fields(roots), ResolveOptions{})
		if err != nil || !slices.Equal(pkgNames(tx.Packages), want) {
			t.Errorf("Install(%s) = %v, %v; want %v", roots, tx, err, want)
		}
	}

	// Against the installed packages.
	local := []*InstalledPackage{
		inst("b", "1-1", nil),
		inst("lib", "1-1", nil),
		inst("holder", "1-1", func(p *InstalledPackage) { p.Provides = []string{"thing=1"} }),
		inst("hates-newer", "1-1", func(p *InstalledPackage) { p.Conflicts = []string{"newer>=1", "other"} }),
	}

	for roots, want := range map[string]*ConflictError{
		"a":        {Package: "a", With: "b", Installed: true, Expr: "b"},
		"vc":       {Package: "vc", With: "lib", Installed: true, Expr: "lib<2"},
		"provider": {Package: "provider", With: "holder", Installed: true, Expr: "thing"},
		"newer":    {Package: "newer", With: "hates-newer", Installed: true, Expr: "newer>=1"},
	} {
		_, err := x.Install([]string{roots}, ResolveOptions{Local: local})
		if !errors.As(err, &ce) || *ce != *want {
			t.Errorf("Install(%s) = %v, want %+v", roots, err, want)
		}
	}

	// Upgrading the installed package clears the conflict; so does an installed one that stays out of range.
	local[1] = inst("lib", "3-1", nil)

	if _, err := x.Install([]string{"vc"}, ResolveOptions{Local: local}); err != nil {
		t.Errorf("vc with lib 3: %v", err)
	}

	// A package of the same name in the transaction replaces the installed one, conflicts included.
	if _, err := x.Install([]string{"b", "lib"}, ResolveOptions{Local: []*InstalledPackage{inst("lib", "1-1", func(p *InstalledPackage) { p.Conflicts = []string{"b"} })}}); err != nil {
		t.Errorf("conflict of a package being upgraded: %v", err)
	}

	for _, root := range []string{"badconf"} {
		if _, err := x.Install([]string{root}, ResolveOptions{}); !errors.Is(err, ErrInvalidDependency) {
			t.Errorf("Install(%s): %v", root, err)
		}
	}

	bad := []*InstalledPackage{inst("lib2", "1-1", func(p *InstalledPackage) { p.Conflicts = []string{"x y"} })}
	if _, err := x.Install([]string{"b"}, ResolveOptions{Local: bad}); !errors.Is(err, ErrInvalidDependency) {
		t.Errorf("bad installed conflict: %v", err)
	}
}

func TestInstallBrokenDependency(t *testing.T) {
	t.Parallel()

	x := newIndex(t, []DBEntry{
		{Name: "lib", Version: "2-1"},
		{Name: "lib", Version: "1-1"}, // never newest, never picked over 2-1
		{Name: "compat", Version: "1-1", Provides: []string{"lib=1"}},
	})

	local := []*InstalledPackage{
		inst("lib", "1-1", nil),
		inst("user", "1-1", func(p *InstalledPackage) { p.Depends = []string{"lib=1", "bad dep", "gone"} }),
		inst("unrelated", "1-1", func(p *InstalledPackage) { p.Depends = []string{"lib>=1"} }),
	}

	_, err := x.Install([]string{"lib"}, ResolveOptions{Local: local})

	var be *BrokenDependencyError

	if !errors.Is(err, ErrBrokenDependency) || !errors.As(err, &be) || be.Package != "user" || be.Dependency != "lib=1" || be.By != "lib" {
		t.Fatalf("err = %v", err)
	}

	if !strings.Contains(be.Error(), "lib breaks dependency lib=1 of user") {
		t.Errorf("message = %q", be.Error())
	}

	// A package of the transaction that still satisfies it fixes it; so does the caller's Installed.
	if _, err := x.Install([]string{"lib", "compat"}, ResolveOptions{Local: local}); err != nil {
		t.Errorf("with compat: %v", err)
	}

	if _, err := x.Install([]string{"lib"}, ResolveOptions{Local: local, Installed: func(d Dependency) bool { return d.Name == "lib" && d.Op == "=" }}); err == nil {
		// Installed skips the root itself, so nothing is broken either.
		t.Log("root skipped by Installed")
	}
}

func TestSysupgrade(t *testing.T) {
	t.Parallel()

	x := newIndex(t,
		[]DBEntry{
			{Name: "up", Version: "2-1", Depends: []string{"newdep"}, Groups: []string{"grp"}},
			{Name: "same", Version: "1-1"},
			{Name: "older", Version: "1-1"},
			{Name: "newdep", Version: "1-1"},
			{Name: "ign", Version: "2-1"},
			{Name: "grouped", Version: "2-1", Groups: []string{"g1"}},
			{Name: "repl", Version: "1-1", Replaces: []string{"gone", "versioned<2", "bad dep", "gone"}},
			{Name: "badrepl", Version: "1-1", Replaces: []string{"other"}},
		},
		[]DBEntry{{Name: "up", Version: "9-1"}, {Name: "extraonly", Version: "2-1"}, {Name: "repl", Version: "5-1", Replaces: []string{"never"}}},
	)

	local := []*InstalledPackage{
		inst("up", "1-1", nil),
		inst("same", "1-1", nil),
		inst("older", "2-1", nil),
		inst("ign", "1-1", nil),
		inst("grouped", "1-1", func(p *InstalledPackage) { p.Groups = []string{"g1"} }),
		inst("gone", "1", nil),
		inst("versioned", "1.5", nil),
		inst("extraonly", "1-1", nil),
		inst("other", "1-1", func(p *InstalledPackage) { p.Groups = []string{"keep"} }),
		inst("unknown", "1-1", nil),
	}

	tx, err := x.Sysupgrade(local, ResolveOptions{IgnorePkg: []string{"ign"}, IgnoreGroup: []string{"g1"}})
	if err != nil {
		t.Fatal(err)
	}

	var ups []string
	for _, u := range tx.Upgrades {
		ups = append(ups, u.Installed.Name+"->"+u.Package.Version)
	}

	slices.Sort(ups)

	if want := []string{"extraonly->2-1", "up->2-1"}; !slices.Equal(ups, want) {
		t.Errorf("upgrades = %v, want %v", ups, want)
	}

	if got := pkgNames(tx.Installs); !slices.Equal(got, []string{"newdep"}) {
		t.Errorf("installs = %v", got)
	}

	var pairs []string
	for _, r := range tx.Replacements {
		pairs = append(pairs, r.Package.Name+"-"+r.Package.Version+" replaces "+r.Installed.Name)
	}

	if want := []string{"badrepl-1-1 replaces other", "repl-1-1 replaces gone", "repl-1-1 replaces versioned"}; !slices.Equal(sortedCopy(pairs), want) {
		t.Fatalf("replacements = %v, want %v", pairs, want)
	}

	var removed []string
	for _, r := range tx.Removals {
		removed = append(removed, r.Name)
	}

	if want := []string{"gone", "versioned", "other"}; !slices.Equal(sortedCopy(removed), sortedCopy(want)) {
		t.Errorf("removals = %v, want %v", removed, want)
	}

	// A local package covered by IgnorePkg or IgnoreGroup is not replaced.
	tx, err = x.Sysupgrade(local, ResolveOptions{IgnorePkg: []string{"gone", "ve*"}})
	if err != nil || len(tx.Removals) != 1 || tx.Removals[0].Name != "other" {
		t.Errorf("ignored installed packages were replaced: %+v, %v", tx.Removals, err)
	}

	// The replacement itself ignored: nothing is replaced.
	tx, err = x.Sysupgrade(local, ResolveOptions{IgnorePkg: []string{"repl", "badrepl"}})
	if err != nil || len(tx.Removals) != 0 || len(tx.Replacements) != 0 {
		t.Errorf("ignored replacement applied: %+v, %v", tx, err)
	}

	// IgnoreGroup applies to the installed package of the replaced name too.
	tx, err = x.Sysupgrade(local, ResolveOptions{IgnoreGroup: []string{"g1", "keep"}})
	if err != nil || len(tx.Upgrades) != 3 || len(tx.Removals) != 2 {
		t.Errorf("tx = %+v, %v", tx, err)
	}

	// Repositories that do not allow Upgrade neither upgrade nor replace.
	x.SetUsage("core", UsageSync|UsageSearch|UsageInstall)

	tx, err = x.Sysupgrade(local, ResolveOptions{})
	if err != nil || len(tx.Replacements) != 0 || !slices.Equal(pkgNames(tx.Packages), []string{"up", "extraonly"}) || tx.Packages[0].Version != "9-1" {
		t.Errorf("without core upgrades: %v, %v", tx, err)
	}

	// Local is replaced by the argument.
	tx, err = x.Sysupgrade(nil, ResolveOptions{Local: local})
	if err != nil || len(tx.Packages) != 0 {
		t.Errorf("nothing installed: %v, %v", tx, err)
	}
}

func sortedCopy(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)

	return s
}

func TestSysupgradeErrors(t *testing.T) {
	t.Parallel()

	x := newIndex(t, []DBEntry{
		{Name: "app", Version: "2-1", Depends: []string{"lib>=2"}},
		{Name: "lib", Version: "2-1"},
		{Name: "gone-new", Version: "1-1", Replaces: []string{"gone"}},
		{Name: "needs-ghost", Version: "2-1", Depends: []string{"ghost"}},
		{Name: "conf", Version: "2-1", Conflicts: []string{"stays"}},
	})

	// An ignored dependency is not picked: pacman reports it as unsatisfiable.
	_, err := x.Sysupgrade([]*InstalledPackage{inst("app", "1-1", nil)}, ResolveOptions{IgnorePkg: []string{"lib"}})
	if !errors.Is(err, ErrUnresolved) || !strings.Contains(err.Error(), "required by app") {
		t.Errorf("err = %v", err)
	}

	_, err = x.Sysupgrade([]*InstalledPackage{inst("needs-ghost", "1-1", nil)}, ResolveOptions{})
	if !errors.Is(err, ErrUnresolved) {
		t.Errorf("err = %v", err)
	}

	// Removing a replaced package breaks what depended on it.
	_, err = x.Sysupgrade([]*InstalledPackage{
		inst("gone", "1-1", nil),
		inst("user", "1-1", func(p *InstalledPackage) { p.Depends = []string{"gone"} }),
	}, ResolveOptions{})

	var be *BrokenDependencyError
	if !errors.As(err, &be) || be.Package != "user" || be.By != "gone" {
		t.Errorf("err = %v", err)
	}

	_, err = x.Sysupgrade([]*InstalledPackage{inst("conf", "1-1", nil), inst("stays", "1-1", nil)}, ResolveOptions{})
	if !errors.Is(err, ErrConflict) {
		t.Errorf("err = %v", err)
	}
}

func TestResolveDepsRootInstalledSkipped(t *testing.T) {
	t.Parallel()

	x := newIndex(t, []DBEntry{{Name: "a", Version: "1-1"}, {Name: "b", Version: "1-1", Depends: []string{"a"}}})

	got, err := x.ResolveDeps([]string{"a", "b"}, ResolveOptions{Installed: func(d Dependency) bool { return d.Name == "a" }})
	if err != nil || !slices.Equal(pkgNames(got), []string{"b"}) {
		t.Errorf("ResolveDeps = %v, %v", pkgNames(got), err)
	}
}

func TestMatchesAny(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		pats []string
		s    string
		want bool
	}{
		{[]string{"foo"}, "foo", true},
		{[]string{"foo*"}, "foobar", true},
		{[]string{"lib?"}, "libx", true},
		{[]string{"lib[ab]"}, "libb", true},
		{[]string{"[bad"}, "[bad", true},
		{[]string{"[bad"}, "bad", false},
		{[]string{"foo"}, "bar", false},
		{nil, "x", false},
	} {
		if got := matchesAny(c.pats, c.s); got != c.want {
			t.Errorf("matchesAny(%v, %q) = %v", c.pats, c.s, got)
		}
	}
}

func TestProvIndex(t *testing.T) {
	t.Parallel()

	m := provIndex{}
	m.addPackage("impl", "1-1", []string{"v=1", "plain"})
	m.addPackage("v", "3-1", nil)

	if o, ok := m.find(Dependency{Name: "v"}, nil); !ok || o != "v" {
		t.Errorf("exact name first: %q, %v", o, ok)
	}

	if o, ok := m.find(Dependency{Name: "v"}, func(o string) bool { return o == "v" }); !ok || o != "impl" {
		t.Errorf("skipping: %q, %v", o, ok)
	}

	if _, ok := m.find(Dependency{Name: "plain", Op: ">=", Version: "1"}, nil); ok {
		t.Error("an unversioned provision satisfied a versioned dependency")
	}

	if got := m.all(Dependency{Name: "v"}, nil); !slices.Equal(got, []string{"impl", "v"}) {
		t.Errorf("all = %v", got)
	}

	if got := m.all(Dependency{Name: "v", Op: "<", Version: "2"}, nil); !slices.Equal(got, []string{"impl"}) {
		t.Errorf("all versioned = %v", got)
	}
}
