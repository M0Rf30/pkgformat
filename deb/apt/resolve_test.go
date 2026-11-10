package apt

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stanza renders a Packages stanza of an amd64 package unless the fields name
// another architecture.
func stanza(name, version string, fields ...string) string {
	lines := []string{"Package: " + name, "Version: " + version}

	hasArch := false

	for _, f := range fields {
		hasArch = hasArch || strings.HasPrefix(f, "Architecture:")
	}

	if !hasArch {
		lines = append(lines, "Architecture: amd64")
	}

	return para(append(lines, fields...)...)
}

// installedStanza renders a dpkg status stanza of an installed amd64 package.
func installedStanza(name, version string, fields ...string) string {
	lines := []string{"Package: " + name, "Status: install ok installed", "Version: " + version}

	hasArch := false

	for _, f := range fields {
		hasArch = hasArch || strings.HasPrefix(f, "Architecture:")
	}

	if !hasArch {
		lines = append(lines, "Architecture: amd64")
	}

	return para(append(lines, fields...)...)
}

// cacheWithStatus loads an index and a dpkg status file.
func cacheWithStatus(tb testing.TB, index, status string) *Cache {
	tb.Helper()

	dir := tb.TempDir()
	writeFile(tb, filepath.Join(dir, indexName("x", "main", "amd64")), index)

	statusFile := filepath.Join(dir, "status")
	writeFile(tb, statusFile, status)

	c, err := Load(LoadOptions{ListsDir: dir, StatusFile: statusFile, HostArch: hostArch})
	require.NoError(tb, err)

	return c
}

// nameVersions lists name:arch=version of resolved packages in order.
func nameVersions(pkgs []*PackageInfo) []string {
	out := make([]string, len(pkgs))
	for i, p := range pkgs {
		out[i] = fmt.Sprintf("%s:%s=%s", p.Name, p.Architecture, p.Version)
	}

	return out
}

type resolveCase struct {
	name       string
	index      string
	status     string
	seeds      []string
	want       []string // name:arch=version
	unresolved []string
	wantErr    error
	errText    string
}

func (tt *resolveCase) run(t *testing.T) {
	t.Helper()

	c := cacheWithStatus(t, tt.index, tt.status)

	order, unresolved, err := c.ResolveDeps(tt.seeds)
	if tt.wantErr != nil {
		require.ErrorIs(t, err, tt.wantErr)

		if tt.errText != "" {
			assert.ErrorContains(t, err, tt.errText)
		}

		return
	}

	require.NoError(t, err)
	assert.Equal(t, tt.want, nameVersions(order))

	if len(tt.unresolved) == 0 {
		assert.Empty(t, unresolved)
	} else {
		assert.Equal(t, tt.unresolved, unresolved)
	}

	// the result does not depend on the run
	for range 3 {
		again, againUnresolved, err := c.ResolveDeps(tt.seeds)
		require.NoError(t, err)
		assert.Equal(t, nameVersions(order), nameVersions(again))
		assert.Equal(t, unresolved, againUnresolved)
	}
}

func runResolveCases(t *testing.T, cases []resolveCase) {
	t.Helper()

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.run(t)
		})
	}
}

func TestResolveVersionConstraints(t *testing.T) {
	t.Parallel()

	foos := stanza("foo", "1") + stanza("foo", "2") + stanza("foo", "3")

	runResolveCases(t, []resolveCase{
		{name: "no constraint takes the highest", index: foos, seeds: []string{"foo"}, want: []string{"foo:amd64=3"}},
		{name: "strictly earlier", index: foos, seeds: []string{"foo (<< 3)"}, want: []string{"foo:amd64=2"}},
		{name: "earlier or equal", index: foos, seeds: []string{"foo (<= 2)"}, want: []string{"foo:amd64=2"}},
		{name: "equal", index: foos, seeds: []string{"foo (= 1)"}, want: []string{"foo:amd64=1"}},
		{name: "later or equal", index: foos, seeds: []string{"foo (>= 2)"}, want: []string{"foo:amd64=3"}},
		{name: "strictly later", index: foos, seeds: []string{"foo (>> 1)"}, want: []string{"foo:amd64=3"}},
		{name: "deprecated < is <=", index: foos, seeds: []string{"foo (< 2)"}, want: []string{"foo:amd64=2"}},
		{name: "deprecated > is >=", index: foos, seeds: []string{"foo (> 3)"}, want: []string{"foo:amd64=3"}},
		{name: "no version in range", index: foos, seeds: []string{"foo (>> 3)"}, wantErr: ErrUnsatisfiable, errText: "foo (>> 3)"},
		{name: "epoch and revision order", index: stanza("foo", "1.0-1") + stanza("foo", "1:0.5") + stanza("foo", "1.0-1~bpo1"),
			seeds: []string{"foo (<< 1:0)"}, want: []string{"foo:amd64=1.0-1"}},
		{name: "dependency constraint", index: foos + stanza("app", "1", "Depends: foo (<< 3)"),
			seeds: []string{"app"}, want: []string{"foo:amd64=2", "app:amd64=1"}},
		{name: "two constraints on one package", index: foos + stanza("app", "1", "Depends: foo (>= 2), foo (<< 3)"),
			seeds: []string{"app"}, want: []string{"foo:amd64=2", "app:amd64=1"}},
		{name: "second constraint contradicts the version taken", index: foos + stanza("app", "1", "Depends: foo (>= 3), foo (<< 3)"),
			seeds: []string{"app"}, wantErr: ErrUnsatisfiable, errText: "app:amd64 1"},
	})
}

func TestResolveInstalledVersions(t *testing.T) {
	t.Parallel()

	runResolveCases(t, []resolveCase{
		{
			name:   "an installed version that meets the constraint stays",
			index:  stanza("foo", "2") + stanza("foo", "3") + stanza("app", "1", "Depends: foo (>= 2)"),
			status: installedStanza("foo", "2"),
			seeds:  []string{"app"}, want: []string{"app:amd64=1"},
		},
		{
			name:   "an installed version that does not is upgraded",
			index:  stanza("foo", "1") + stanza("foo", "3") + stanza("app", "1", "Depends: foo (>= 2)"),
			status: installedStanza("foo", "1"),
			seeds:  []string{"app"}, want: []string{"foo:amd64=3", "app:amd64=1"},
		},
		{
			name:   "no upgrade available is an error",
			index:  stanza("foo", "1") + stanza("app", "1", "Depends: foo (>= 2)"),
			status: installedStanza("foo", "1"),
			seeds:  []string{"app"}, wantErr: ErrUnsatisfiable, errText: "foo (>= 2)",
		},
		{
			name:   "the upgrade is the highest version that meets the constraint",
			index:  stanza("foo", "1") + stanza("foo", "2") + stanza("foo", "4") + stanza("app", "1", "Depends: foo (>= 2), foo (<< 4)"),
			status: installedStanza("foo", "1"),
			seeds:  []string{"app"}, want: []string{"foo:amd64=2", "app:amd64=1"},
		},
		{
			name:   "a seed upgrades an installed package",
			index:  stanza("foo", "1") + stanza("foo", "2"),
			status: installedStanza("foo", "1"),
			seeds:  []string{"foo"}, want: []string{"foo:amd64=2"},
		},
		{
			name:   "a seed at the newest installed version is skipped",
			index:  stanza("foo", "2"),
			status: installedStanza("foo", "2"),
			seeds:  []string{"foo"}, want: []string{},
		},
		{
			name:   "an installed version is never downgraded",
			index:  stanza("foo", "1") + stanza("foo", "3"),
			status: installedStanza("foo", "3"),
			seeds:  []string{"foo (<< 3)"}, wantErr: ErrUnsatisfiable,
		},
		{
			name:   "an upgrade that breaks an installed dependent is refused",
			index:  stanza("lib", "1") + stanza("lib", "2") + stanza("app", "1", "Depends: lib (= 1)"),
			status: installedStanza("lib", "1") + installedStanza("app", "1", "Depends: lib (= 1)"),
			seeds:  []string{"lib"}, wantErr: ErrUnsatisfiable, errText: "app:amd64 1",
		},
		{
			name:   "an upgrade that keeps an installed dependent working goes ahead",
			index:  stanza("lib", "1") + stanza("lib", "2"),
			status: installedStanza("lib", "1") + installedStanza("app", "1", "Depends: lib (>= 1)"),
			seeds:  []string{"lib"}, want: []string{"lib:amd64=2"},
		},
		{
			name:   "an installed package is taken to have its dependencies",
			index:  stanza("app", "2", "Depends: lib") + stanza("lib", "1"),
			status: installedStanza("app", "1", "Depends: lib"),
			seeds:  []string{"app"}, want: []string{"lib:amd64=1", "app:amd64=2"},
		},
	})
}

func TestResolveAlternatives(t *testing.T) {
	t.Parallel()

	ab := stanza("a", "1") + stanza("b", "1")

	runResolveCases(t, []resolveCase{
		{name: "the first alternative is taken", index: ab + stanza("app", "1", "Depends: a | b"),
			seeds: []string{"app"}, want: []string{"a:amd64=1", "app:amd64=1"}},
		{name: "an installed alternative is preferred", index: ab + stanza("app", "1", "Depends: a | b"),
			status: installedStanza("b", "1"), seeds: []string{"app"}, want: []string{"app:amd64=1"}},
		{name: "a selected alternative is preferred",
			index: ab + stanza("x", "1", "Depends: b") + stanza("app", "1", "Depends: x, a | b"),
			seeds: []string{"app"}, want: []string{"b:amd64=1", "x:amd64=1", "app:amd64=1"}},
		{name: "a broken first alternative falls through",
			index: stanza("a", "1", "Depends: zz (>= 9)") + stanza("zz", "1") + stanza("b", "1") + stanza("app", "1", "Depends: a | b"),
			seeds: []string{"app"}, want: []string{"b:amd64=1", "app:amd64=1"}},
		{name: "an alternative that is no package at all is skipped",
			index: stanza("b", "1") + stanza("app", "1", "Depends: ghost | b"),
			seeds: []string{"app"}, want: []string{"b:amd64=1", "app:amd64=1"}},
		{name: "an alternative that cannot meet its version is skipped",
			index: stanza("a", "1") + stanza("b", "2") + stanza("app", "1", "Depends: a (>= 2) | b (>= 2)"),
			seeds: []string{"app"}, want: []string{"b:amd64=2", "app:amd64=1"}},
		{name: "every alternative fails",
			index: stanza("a", "1", "Depends: zz (>= 9)") + stanza("b", "1", "Depends: zz (>= 9)") + stanza("zz", "1") +
				stanza("app", "1", "Depends: a | b"),
			seeds: []string{"app"}, wantErr: ErrUnsatisfiable, errText: "a | b"},
		{name: "a seed with alternatives", index: ab,
			seeds: []string{"a | b"}, want: []string{"a:amd64=1"}},
		{name: "a seed with alternatives prefers an installed one", index: ab,
			status: installedStanza("b", "1"), seeds: []string{"a | b"}, want: []string{}},
		{name: "a name nothing knows is unresolved", index: ab + stanza("app", "1", "Depends: ghost"),
			seeds: []string{"app"}, want: []string{"app:amd64=1"}, unresolved: []string{"ghost"}},
	})
}

func TestResolveProvides(t *testing.T) {
	t.Parallel()

	runResolveCases(t, []resolveCase{
		{name: "an unversioned provide meets an unversioned dependency",
			index: stanza("exim", "1", "Provides: mta") + stanza("app", "1", "Depends: mta"),
			seeds: []string{"app"}, want: []string{"exim:amd64=1", "app:amd64=1"}},
		{name: "a versioned provide meets a constraint it satisfies",
			index: stanza("prov", "9", "Provides: foo (= 1.5)") + stanza("app", "1", "Depends: foo (>= 1)"),
			seeds: []string{"app"}, want: []string{"prov:amd64=9", "app:amd64=1"}},
		{name: "a versioned provide does not meet a constraint it fails",
			index: stanza("prov", "9", "Provides: foo (= 1.5)") + stanza("app", "1", "Depends: foo (>= 2)"),
			seeds: []string{"app"}, wantErr: ErrUnsatisfiable, errText: "foo (>= 2)"},
		{name: "an unversioned provide never meets a versioned dependency",
			index: stanza("prov", "9", "Provides: foo") + stanza("app", "1", "Depends: foo (>= 1)"),
			seeds: []string{"app"}, wantErr: ErrUnsatisfiable},
		{name: "the version of the providing package is not the provided version",
			index: stanza("prov", "9", "Provides: foo") + stanza("app", "1", "Depends: foo (= 9)"),
			seeds: []string{"app"}, wantErr: ErrUnsatisfiable},
		{name: "a real package beats a provider",
			index: stanza("foo", "1") + stanza("prov", "1", "Provides: foo") + stanza("app", "1", "Depends: foo"),
			seeds: []string{"app"}, want: []string{"foo:amd64=1", "app:amd64=1"}},
		{name: "the real package with the wrong version is not replaced by a provider",
			index: stanza("foo", "1") + stanza("prov", "1", "Provides: foo") + stanza("app", "1", "Depends: foo (>= 2)"),
			seeds: []string{"app"}, wantErr: ErrUnsatisfiable},
		{name: "a higher priority provider wins",
			index: stanza("lo", "1", "Priority: optional", "Provides: mta") + stanza("hi", "1", "Priority: important", "Provides: mta") +
				stanza("app", "1", "Depends: mta"),
			seeds: []string{"app"}, want: []string{"hi:amd64=1", "app:amd64=1"}},
		{name: "of equal providers the one read last wins",
			index: stanza("first", "1", "Provides: mta") + stanza("second", "1", "Provides: mta") + stanza("app", "1", "Depends: mta"),
			seeds: []string{"app"}, want: []string{"second:amd64=1", "app:amd64=1"}},
		{name: "an installed provider is enough",
			index:  stanza("exim", "1", "Provides: mta") + stanza("postfix", "1", "Provides: mta") + stanza("app", "1", "Depends: mta"),
			status: installedStanza("exim", "1", "Provides: mta"), seeds: []string{"app"}, want: []string{"app:amd64=1"}},
		{name: "a selected provider is enough",
			index: stanza("exim", "1", "Provides: mta") + stanza("postfix", "1", "Provides: mta") +
				stanza("x", "1", "Depends: exim") + stanza("app", "1", "Depends: x, mta"),
			seeds: []string{"app"}, want: []string{"exim:amd64=1", "x:amd64=1", "app:amd64=1"}},
		{name: "a provider with an unmet dependency is skipped",
			index: stanza("bad", "1", "Provides: mta", "Depends: zz (>= 9)") + stanza("zz", "1") +
				stanza("good", "1", "Provides: mta") + stanza("app", "1", "Depends: mta"),
			// good is read before bad in the index below, so make bad the preferred one
			seeds: []string{"app"}, want: []string{"good:amd64=1", "app:amd64=1"}},
		{name: "a seed names a virtual package",
			index: stanza("exim", "1", "Provides: mta"), seeds: []string{"mta"}, want: []string{"exim:amd64=1"}},
	})
}

func TestResolvePreDepends(t *testing.T) {
	t.Parallel()

	runResolveCases(t, []resolveCase{
		{name: "a Pre-Depends is a dependency, ahead of Depends",
			index: stanza("base", "1") + stanza("lib", "1") + stanza("app", "1", "Depends: lib", "Pre-Depends: base"),
			seeds: []string{"app"}, want: []string{"base:amd64=1", "lib:amd64=1", "app:amd64=1"}},
		{name: "a Pre-Depends honours versions and alternatives",
			index: stanza("base", "1") + stanza("base", "2") + stanza("alt", "1") + stanza("app", "1", "Pre-Depends: nope (>= 1) | base (<< 2)"),
			seeds: []string{"app"}, want: []string{"base:amd64=1", "app:amd64=1"}},
		{name: "an unmet Pre-Depends fails",
			index: stanza("base", "1") + stanza("app", "1", "Pre-Depends: base (>= 2)"),
			seeds: []string{"app"}, wantErr: ErrUnsatisfiable},
	})
}

func TestResolveConflicts(t *testing.T) {
	t.Parallel()

	runResolveCases(t, []resolveCase{
		{name: "a candidate that conflicts with an installed package is refused",
			index: stanza("app", "1", "Conflicts: old"), status: installedStanza("old", "1"),
			seeds: []string{"app"}, wantErr: ErrConflict, errText: "old"},
		{name: "a conflict names the version range",
			index: stanza("app", "1", "Conflicts: old (<< 2)"), status: installedStanza("old", "1"),
			seeds: []string{"app"}, wantErr: ErrConflict},
		{name: "a conflict outside the version range is no conflict",
			index: stanza("app", "1", "Conflicts: old (<< 2)"), status: installedStanza("old", "2"),
			seeds: []string{"app"}, want: []string{"app:amd64=1"}},
		{name: "an installed package that conflicts with the candidate refuses it",
			index: stanza("app", "1"), status: installedStanza("old", "1", "Conflicts: app"),
			seeds: []string{"app"}, wantErr: ErrConflict, errText: "old"},
		{name: "the next alternative is tried after a conflict",
			index:  stanza("a", "1", "Conflicts: old") + stanza("b", "1") + stanza("app", "1", "Depends: a | b"),
			status: installedStanza("old", "1"), seeds: []string{"app"}, want: []string{"b:amd64=1", "app:amd64=1"}},
		{name: "two selected packages that conflict",
			index: stanza("x", "1") + stanza("y", "1", "Conflicts: x") + stanza("app", "1", "Depends: x, y"),
			seeds: []string{"app"}, wantErr: ErrConflict},
		{name: "two selected packages that conflict, the other way round",
			index: stanza("x", "1", "Conflicts: y") + stanza("y", "1") + stanza("app", "1", "Depends: x, y"),
			seeds: []string{"app"}, wantErr: ErrConflict},
		{name: "a conflict with a package the candidate provides itself is no conflict",
			index: stanza("app", "1", "Provides: other", "Conflicts: other"),
			seeds: []string{"app"}, want: []string{"app:amd64=1"}},
		{name: "a conflict hits a provider",
			index: stanza("app", "1", "Conflicts: mta"), status: installedStanza("exim", "1", "Provides: mta"),
			seeds: []string{"app"}, wantErr: ErrConflict},
		{name: "a versioned conflict does not hit an unversioned provide",
			index: stanza("app", "1", "Conflicts: mta (>= 1)"), status: installedStanza("exim", "1", "Provides: mta"),
			seeds: []string{"app"}, want: []string{"app:amd64=1"}},
		{name: "a versioned conflict hits a versioned provide",
			index: stanza("app", "1", "Conflicts: mta (>= 1)"), status: installedStanza("exim", "1", "Provides: mta (= 2)"),
			seeds: []string{"app"}, wantErr: ErrConflict},
		{name: "Breaks refuses a version in range",
			index: stanza("app", "1", "Breaks: lib (<< 2)"), status: installedStanza("lib", "1"),
			seeds: []string{"app"}, wantErr: ErrConflict, errText: "breaks"},
		{name: "Breaks leaves a version out of range",
			index: stanza("app", "1", "Breaks: lib (<< 2)"), status: installedStanza("lib", "2"),
			seeds: []string{"app"}, want: []string{"app:amd64=1"}},
		{name: "installed Breaks refuses the candidate",
			index: stanza("lib", "2"), status: installedStanza("app", "1", "Breaks: lib (>= 2)"),
			seeds: []string{"lib"}, wantErr: ErrConflict},
		{name: "an older version that avoids the conflict is chosen",
			index:  stanza("lib", "1") + stanza("lib", "2", "Conflicts: old") + stanza("app", "1", "Depends: lib"),
			status: installedStanza("old", "1"), seeds: []string{"app"}, want: []string{"lib:amd64=1", "app:amd64=1"}},
		{name: "an installed package never conflicts with its own upgrade",
			index:  stanza("lib", "2", "Conflicts: lib (<< 2)"),
			status: installedStanza("lib", "1"), seeds: []string{"lib"}, want: []string{"lib:amd64=2"}},
	})
}

func TestConflictErrorNamesBothPackages(t *testing.T) {
	t.Parallel()

	c := cacheWithStatus(t,
		stanza("app", "1.0", "Conflicts: old (<< 2)")+stanza("x", "1")+stanza("y", "1", "Breaks: x (>= 1)")+stanza("top", "1", "Depends: x, y"),
		installedStanza("old", "1.5"))

	_, _, err := c.ResolveDeps([]string{"app"})
	require.ErrorIs(t, err, ErrConflict)

	var conflict *ConflictError
	require.ErrorAs(t, err, &conflict)
	assert.Equal(t, "app:amd64 1.0", conflict.Package)
	assert.Equal(t, "old:amd64 1.5", conflict.With)
	assert.True(t, conflict.WithInstalled)
	assert.Equal(t, "Conflicts", conflict.Kind)
	assert.Equal(t, "old (<< 2)", conflict.Relation)
	assert.False(t, conflict.Reverse)
	assert.Contains(t, conflict.Error(), "app:amd64 1.0")
	assert.Contains(t, conflict.Error(), "old:amd64 1.5")
	assert.Contains(t, conflict.Error(), "installed")

	var unsat *UnsatisfiedError
	require.ErrorAs(t, err, &unsat, "a conflict that leaves no candidate is an unsatisfied dependency")
	assert.Equal(t, "app", unsat.Dependency)

	_, _, err = c.ResolveDeps([]string{"top"})
	require.ErrorAs(t, err, &conflict)
	assert.Equal(t, "y:amd64 1", conflict.Package)
	assert.Equal(t, "x:amd64 1", conflict.With)
	assert.False(t, conflict.WithInstalled, "x was selected in the same resolution")
	assert.Equal(t, "Breaks", conflict.Kind)
	assert.Contains(t, conflict.Error(), "selected")

	// the reverse direction names the declaring package as With
	c = cacheWithStatus(t, stanza("app", "1"), installedStanza("old", "1", "Breaks: app (>= 1)"))

	_, _, err = c.ResolveDeps([]string{"app"})
	require.ErrorAs(t, err, &conflict)
	assert.True(t, conflict.Reverse)
	assert.Equal(t, "old:amd64 1", conflict.With)
	assert.Contains(t, conflict.Error(), "old:amd64 1")
	assert.Contains(t, conflict.Error(), "breaks app (>= 1)")
}

func TestUnsatisfiedErrorShape(t *testing.T) {
	t.Parallel()

	// five alternatives that each fail show at most four causes
	var index strings.Builder

	index.WriteString(stanza("zz", "1"))

	alts := make([]string, 0, 5)

	for i := range 5 {
		name := fmt.Sprintf("c%d", i)
		index.WriteString(stanza(name, "1", "Depends: zz (>= 9)"))

		alts = append(alts, name)
	}

	index.WriteString(stanza("app", "1", "Depends: "+strings.Join(alts, " | ")))

	c := cacheWithStatus(t, index.String(), "")

	_, _, err := c.ResolveDeps([]string{"app"})
	require.ErrorIs(t, err, ErrUnsatisfiable)

	var unsat *UnsatisfiedError
	require.ErrorAs(t, err, &unsat)
	assert.Empty(t, unsat.Package, "the seed has no declaring package")
	assert.Equal(t, "app", unsat.Dependency)
	require.Len(t, unsat.Causes, 1)

	var inner *UnsatisfiedError
	require.ErrorAs(t, unsat.Causes[0], &inner)
	assert.Equal(t, "app:amd64 1", inner.Package)
	assert.Equal(t, "c0 | c1 | c2 | c3 | c4", inner.Dependency)
	assert.Len(t, inner.Causes, 5)
	assert.Contains(t, err.Error(), "and 1 more")

	// a malformed seed wraps the parse error
	_, _, err = c.ResolveDeps([]string{"foo (>= )"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `seed "foo (>= )"`)
	assert.NotErrorIs(t, err, ErrUnsatisfiable)
}

func TestResolveMultiArch(t *testing.T) {
	t.Parallel()

	tool := func(arch, multiArch string, fields ...string) string {
		f := []string{"Architecture: " + arch}
		if multiArch != "" {
			f = append(f, "Multi-Arch: "+multiArch)
		}

		return stanza("tool", "1", append(f, fields...)...)
	}
	app := func(dep string) string {
		return stanza("app", "1", "Architecture: arm64", "Depends: "+dep)
	}

	runResolveCases(t, []resolveCase{
		{name: "an unqualified dependency takes a foreign package of the host architecture",
			index: tool("amd64", "foreign") + app("tool"), seeds: []string{"app:arm64"},
			want: []string{"tool:amd64=1", "app:arm64=1"}},
		{name: "an unqualified dependency prefers the host architecture of a foreign package",
			index: tool("arm64", "foreign") + tool("amd64", "foreign") + app("tool"), seeds: []string{"app:arm64"},
			want: []string{"tool:amd64=1", "app:arm64=1"}},
		{name: "an unqualified dependency is met by an installed foreign package of the same architecture",
			index: tool("arm64", "foreign") + tool("amd64", "foreign") + app("tool"),
			status: installedStanza("tool", "1", "Architecture: arm64", "Multi-Arch: foreign"), seeds: []string{"app:arm64"},
			want: []string{"app:arm64=1"}},
		{name: "an unqualified dependency is not met by another architecture without foreign",
			index: tool("amd64", "") + app("tool"), seeds: []string{"app:arm64"}, wantErr: ErrUnsatisfiable},
		{name: "an unqualified dependency is not met by another architecture with allowed",
			index: tool("amd64", "allowed") + app("tool"), seeds: []string{"app:arm64"}, wantErr: ErrUnsatisfiable},
		{name: "an unqualified dependency is not met by another architecture with same",
			index: tool("amd64", "same") + app("tool"), seeds: []string{"app:arm64"}, wantErr: ErrUnsatisfiable},
		{name: "an unqualified dependency takes the same architecture without Multi-Arch",
			index: tool("amd64", "") + tool("arm64", "") + app("tool"), seeds: []string{"app:arm64"},
			want: []string{"tool:arm64=1", "app:arm64=1"}},
		{name: "any is met only by allowed",
			index: tool("amd64", "allowed") + app("tool:any"), seeds: []string{"app:arm64"},
			want: []string{"tool:amd64=1", "app:arm64=1"}},
		{name: "any is not met by foreign", index: tool("amd64", "foreign") + app("tool:any"),
			seeds: []string{"app:arm64"}, wantErr: ErrUnsatisfiable},
		{name: "any is not met by same", index: tool("amd64", "same") + app("tool:any"),
			seeds: []string{"app:arm64"}, wantErr: ErrUnsatisfiable},
		{name: "any is not met without Multi-Arch", index: tool("amd64", "") + app("tool:any"),
			seeds: []string{"app:arm64"}, wantErr: ErrUnsatisfiable},
		{name: "any prefers the host architecture",
			index: tool("arm64", "allowed") + tool("amd64", "allowed") + app("tool:any"), seeds: []string{"app:arm64"},
			want: []string{"tool:amd64=1", "app:arm64=1"}},
		{name: "native is the host architecture whatever Multi-Arch says",
			index: tool("amd64", "") + tool("arm64", "") + app("tool:native"), seeds: []string{"app:arm64"},
			want: []string{"tool:amd64=1", "app:arm64=1"}},
		{name: "native is not met by another architecture",
			index: tool("arm64", "foreign") + app("tool:native"), seeds: []string{"app:arm64"}, wantErr: ErrUnsatisfiable},
		{name: "an explicit architecture picks that one",
			index: tool("amd64", "") + tool("arm64", "") + app("tool:arm64"), seeds: []string{"app:arm64"},
			want: []string{"tool:arm64=1", "app:arm64=1"}},
		{name: "an explicit architecture is not met by another",
			index: tool("amd64", "foreign") + app("tool:arm64"), seeds: []string{"app:arm64"}, wantErr: ErrUnsatisfiable},
		{name: "an architecture all package meets anything",
			index: tool("all", "") + app("tool"), seeds: []string{"app:arm64"},
			want: []string{"tool:all=1", "app:arm64=1"}},
		{name: "any with an architecture all package",
			index: tool("all", "") + app("tool:any"), seeds: []string{"app:arm64"}, want: []string{"tool:all=1", "app:arm64=1"}},
		{name: "a provider obeys the rules too",
			index: stanza("prov", "1", "Architecture: amd64", "Multi-Arch: foreign", "Provides: virt") + app("virt"),
			seeds: []string{"app:arm64"}, want: []string{"prov:amd64=1", "app:arm64=1"}},
		{name: "a provider that is not foreign is no good",
			index: stanza("prov", "1", "Architecture: amd64", "Provides: virt") + app("virt"),
			seeds: []string{"app:arm64"}, wantErr: ErrUnsatisfiable},
		{name: "a provide qualified any is met only by allowed packages",
			index: stanza("prov", "1", "Architecture: amd64", "Multi-Arch: allowed", "Provides: virt") + app("virt:any"),
			seeds: []string{"app:arm64"}, want: []string{"prov:amd64=1", "app:arm64=1"}},
	})
}

func TestResolveSeedArchitectureFallback(t *testing.T) {
	t.Parallel()

	runResolveCases(t, []resolveCase{
		{name: "a qualified seed with no such architecture falls back to the host one",
			index: stanza("tool", "1"), seeds: []string{"tool:arm64"}, want: []string{"tool:amd64=1"}},
		{name: "a seed prefers the architecture it names",
			index: stanza("tool", "1") + stanza("tool", "1", "Architecture: arm64"), seeds: []string{"tool:arm64"},
			want: []string{"tool:arm64=1"}},
		{name: "native seed", index: stanza("tool", "1") + stanza("tool", "1", "Architecture: arm64"), seeds: []string{"tool:native"},
			want: []string{"tool:amd64=1"}},
		{name: "several seeds in one string", index: stanza("a", "1") + stanza("b", "1"),
			seeds: []string{"a, b"}, want: []string{"a:amd64=1", "b:amd64=1"}},
	})
}

func TestResolveDeterministicAcrossFileOrder(t *testing.T) {
	t.Parallel()

	index := stanza("app", "1", "Depends: a | b, mta, lib (>= 2)") + stanza("a", "1", "Provides: mta") + stanza("b", "1", "Provides: mta") +
		stanza("lib", "1") + stanza("lib", "2") + stanza("lib", "3", "Conflicts: zzz")

	var first []string

	for range 5 {
		c := cacheWithStatus(t, index, installedStanza("lib", "1"))

		order, unresolved, err := c.ResolveDeps([]string{"app", "mta"})
		require.NoError(t, err)
		assert.Empty(t, unresolved)

		got := nameVersions(order)
		if first == nil {
			first = got
		}

		assert.Equal(t, first, got)
	}

	assert.Equal(t, []string{"a:amd64=1", "lib:amd64=3", "app:amd64=1"}, first)
}

func TestResolveStepLimit(t *testing.T) {
	t.Parallel()

	// Thirty independent choices and a dependency that cannot be met: apt's
	// own solver would give up too, ours must end.
	var (
		index strings.Builder
		seeds []string
	)

	for i := range 30 {
		index.WriteString(stanza(fmt.Sprintf("x%da", i), "1"))
		index.WriteString(stanza(fmt.Sprintf("x%db", i), "1"))

		seeds = append(seeds, fmt.Sprintf("x%da | x%db", i, i))
	}

	index.WriteString(stanza("zz", "1"))
	index.WriteString(stanza("last", "1", "Depends: zz (>= 9)"))

	c := cacheWithStatus(t, index.String(), "")

	_, _, err := c.ResolveDeps(append(seeds, "last"))
	require.ErrorIs(t, err, ErrResolveLimit)
}

func TestVersionsAndLookupSpec(t *testing.T) {
	t.Parallel()

	c := cacheWithStatus(t,
		stanza("foo", "1")+stanza("foo", "3")+stanza("foo", "2")+stanza("foo", "2", "Architecture: arm64")+stanza("all-pkg", "1", "Architecture: all"),
		installedStanza("foo", "0.5"))

	versions := c.Versions("foo")
	require.Len(t, versions, 4)
	assert.Equal(t, "3", versions[0].Version)
	assert.Equal(t, "0.5", versions[3].Version)
	assert.True(t, versions[3].Installed)
	assert.False(t, versions[3].HasCandidate)

	assert.Equal(t, "2", c.Versions("foo:arm64")[0].Version)
	assert.Empty(t, c.Versions("nothing"))

	tests := []struct {
		spec    string
		name    string
		version string
		ok      bool
	}{
		{"foo", "foo", "3", true},
		{" foo ", "foo", "3", true},
		{"foo (= 2)", "foo", "2", true},
		{"foo (<< 3)", "foo", "2", true},
		{"foo:amd64 (>= 2)", "foo:amd64", "3", true},
		{"foo:arm64 (<= 5)", "foo:arm64", "2", true},
		{"foo (>> 3)", "foo", "", false},
		{"foo:arm64 (= 3)", "foo:arm64", "3", true}, // falls back to the host architecture, as Lookup does
		{"foo:arm64 (= 9)", "foo:arm64", "", false},
		{"nothing (>= 1)", "nothing", "", false},
		{"all-pkg:arm64 (= 1)", "all-pkg:arm64", "1", true},
		{"foo (>= )", "foo", "3", true}, // malformed: the name part alone
		{"a | b", "a | b", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			t.Parallel()

			name, info, ok := c.lookupSpec(tt.spec)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.name, name)
			assert.Equal(t, tt.version, info.Version)
		})
	}
}

func TestResolveErrorsAreNotSwallowedByStatusOnlyPackages(t *testing.T) {
	t.Parallel()

	// foo is installed but unknown to the index: a dependency on a newer one
	// cannot be met, and says so instead of reporting the name unresolved.
	c := cacheWithStatus(t, stanza("app", "1", "Depends: foo (>= 2)"), installedStanza("foo", "1"))

	_, _, err := c.ResolveDeps([]string{"app"})
	require.ErrorIs(t, err, ErrUnsatisfiable)

	var unsat *UnsatisfiedError
	require.True(t, errors.As(err, &unsat))
	assert.Contains(t, unsat.Error(), "foo")
}
