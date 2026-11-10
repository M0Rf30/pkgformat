package apt

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveRollbackAndDiagnostics(t *testing.T) {
	t.Parallel()

	runResolveCases(t, []resolveCase{
		{name: "an unresolved name of a refused candidate is forgotten",
			index: stanza("a", "1", "Depends: ghost, zz (>= 9)") + stanza("zz", "1") + stanza("b", "1") + stanza("app", "1", "Depends: a | b"),
			seeds: []string{"app"}, want: []string{"b:amd64=1", "app:amd64=1"}},
		{name: "the failure names an alternative the index does not know",
			index: stanza("a", "1") + stanza("app", "1", "Depends: ghost | a (>= 5)"),
			seeds: []string{"app"}, wantErr: ErrUnsatisfiable, errText: "ghost: no such package; a (>= 5): a:amd64 1"},
		{name: "the failure names the providers that were found",
			index: stanza("p", "1", "Provides: virt (= 1)") + stanza("app", "1", "Depends: virt (>= 2)"),
			seeds: []string{"app"}, wantErr: ErrUnsatisfiable, errText: "provided by p:amd64 1"},
	})
}

func TestResolveReplacedDependents(t *testing.T) {
	t.Parallel()

	runResolveCases(t, []resolveCase{
		{name: "a dependent that names something else is left alone",
			index:  stanza("lib", "1") + stanza("lib", "2") + stanza("other", "1"),
			status: installedStanza("lib", "1") + installedStanza("other", "1") + installedStanza("app", "1", "Depends: other, lib (>= 1)"),
			seeds:  []string{"lib"}, want: []string{"lib:amd64=2"}},
		{name: "a dependent that was unmet already is left alone",
			index:  stanza("lib", "1") + stanza("lib", "2"),
			status: installedStanza("lib", "1") + installedStanza("app", "1", "Depends: lib (>= 5)"),
			seeds:  []string{"lib"}, want: []string{"lib:amd64=2"}},
		{name: "a dependent met by another alternative is left alone",
			index:  stanza("lib", "1") + stanza("lib", "2"),
			status: installedStanza("lib", "1") + installedStanza("other", "1") + installedStanza("app", "1", "Depends: lib (= 1) | other"),
			seeds:  []string{"lib"}, want: []string{"lib:amd64=2"}},
		{name: "a package selected earlier is protected like an installed one",
			index:  stanza("lib", "1") + stanza("lib", "2") + stanza("app", "1", "Depends: lib (= 1)"),
			status: installedStanza("lib", "1"),
			seeds:  []string{"app", "lib (>= 2)"}, wantErr: ErrUnsatisfiable, errText: "would replace"},
		{name: "a provided name counts as replaced too",
			index:  stanza("exim", "2", "Provides: mta (= 2)"),
			status: installedStanza("exim", "1", "Provides: mta (= 1)") + installedStanza("app", "1", "Depends: mta (= 1)"),
			seeds:  []string{"exim"}, wantErr: ErrUnsatisfiable, errText: "app:amd64 1"},
	})
}

func TestResolveProvidesWithSeveralNames(t *testing.T) {
	t.Parallel()

	runResolveCases(t, []resolveCase{
		{name: "a provide of several names matches the second",
			index: stanza("p", "1", "Provides: a, b (= 2), c") + stanza("app", "1", "Depends: b (>= 1)"),
			seeds: []string{"app"}, want: []string{"p:amd64=1", "app:amd64=1"}},
	})
}

func TestResolveSeveralInstalledNegations(t *testing.T) {
	t.Parallel()

	runResolveCases(t, []resolveCase{
		{name: "installed packages with the same negation",
			index:  stanza("foo", "1"),
			status: installedStanza("a", "1", "Conflicts: zzz") + installedStanza("b", "1", "Breaks: zzz") + installedStanza("c", "1", "Conflicts: zzz"),
			seeds:  []string{"foo"}, want: []string{"foo:amd64=1"}},
		{name: "a relation of the owner on another name is skipped",
			index:  stanza("app", "2"),
			status: installedStanza("old", "1", "Conflicts: other, app (<< 1)"),
			seeds:  []string{"app"}, want: []string{"app:amd64=2"}},
	})
}

func TestResolveQualifiedNegations(t *testing.T) {
	t.Parallel()

	arm := installedStanza("foo", "1", "Architecture: arm64")

	runResolveCases(t, []resolveCase{
		{name: "a conflict with another architecture is no conflict", index: stanza("app", "1", "Conflicts: foo:amd64"),
			status: arm, seeds: []string{"app"}, want: []string{"app:amd64=1"}},
		{name: "a conflict with the host architecture is no conflict with arm64", index: stanza("app", "1", "Conflicts: foo:native"),
			status: arm, seeds: []string{"app"}, want: []string{"app:amd64=1"}},
		{name: "a conflict with native hits the host architecture", index: stanza("app", "1", "Conflicts: foo:native"),
			status: installedStanza("foo", "1"), seeds: []string{"app"}, wantErr: ErrConflict},
		{name: "a conflict with any hits every architecture", index: stanza("app", "1", "Conflicts: foo:any"),
			status: arm, seeds: []string{"app"}, wantErr: ErrConflict},
		{name: "a conflict with an architecture hits it", index: stanza("app", "1", "Conflicts: foo:arm64"),
			status: arm, seeds: []string{"app"}, wantErr: ErrConflict},
		{name: "an unqualified conflict hits every architecture", index: stanza("app", "1", "Conflicts: foo"),
			status: arm, seeds: []string{"app"}, wantErr: ErrConflict},
	})
}

func TestResolveArchitecturePreferences(t *testing.T) {
	t.Parallel()

	arch := func(a, multiArch string) string {
		f := []string{"Architecture: " + a}
		if multiArch != "" {
			f = append(f, "Multi-Arch: "+multiArch)
		}

		return stanza("tool", "1", f...)
	}
	app := func(dep string) string { return stanza("app", "1", "Architecture: arm64", "Depends: "+dep) }

	runResolveCases(t, []resolveCase{
		{name: "a seed prefers the host architecture over an all package",
			index: arch("all", "") + arch("amd64", ""), seeds: []string{"tool"}, want: []string{"tool:amd64=1"}},
		{name: "a seed takes the all package over a foreign architecture",
			index: arch("all", "") + arch("arm64", ""), seeds: []string{"tool"}, want: []string{"tool:all=1"}},
		{name: "a seed takes the host architecture before the others",
			index: arch("arm64", "") + arch("ppc64el", "") + arch("amd64", ""), seeds: []string{"tool"}, want: []string{"tool:amd64=1"}},
		{name: "a seed takes another architecture over none",
			index: arch("ppc64el", "") + arch("s390x", ""), seeds: []string{"tool"}, want: []string{"tool:ppc64el=1"}},
		{name: "an all package comes before the architecture of the dependent",
			index: arch("all", "") + arch("arm64", "") + app("tool"), seeds: []string{"app:arm64"},
			want: []string{"tool:all=1", "app:arm64=1"}},
		{name: "any takes the dependent's architecture over a distant one",
			index: arch("ppc64el", "allowed") + arch("arm64", "allowed") + app("tool:any"), seeds: []string{"app:arm64"},
			want: []string{"tool:arm64=1", "app:arm64=1"}},
		{name: "any takes the host architecture over a distant one",
			index: arch("ppc64el", "allowed") + arch("amd64", "allowed") + app("tool:any"), seeds: []string{"app:arm64"},
			want: []string{"tool:amd64=1", "app:arm64=1"}},
		{name: "any takes a distant architecture over none",
			index: arch("s390x", "allowed") + arch("ppc64el", "allowed") + app("tool:any"), seeds: []string{"app:arm64"},
			want: []string{"tool:ppc64el=1", "app:arm64=1"}},
		{name: "foreign takes the host architecture first",
			index: arch("ppc64el", "foreign") + arch("amd64", "foreign") + app("tool"), seeds: []string{"app:arm64"},
			want: []string{"tool:amd64=1", "app:arm64=1"}},
		{name: "foreign takes another architecture by name",
			index: arch("s390x", "foreign") + arch("ppc64el", "foreign") + app("tool"), seeds: []string{"app:arm64"},
			want: []string{"tool:ppc64el=1", "app:arm64=1"}},
		{name: "providers are ordered by architecture before they are by reading order",
			index: stanza("early", "1", "Architecture: amd64", "Multi-Arch: foreign", "Provides: virt") +
				stanza("late", "1", "Architecture: arm64", "Provides: virt") + app("virt"),
			seeds: []string{"app:arm64"}, want: []string{"early:amd64=1", "app:arm64=1"}},
	})
}

func TestResolveHandBuiltEntriesWithoutArchitecture(t *testing.T) {
	t.Parallel()

	c := NewCache("amd64")
	c.AddEntry(&PackageInfo{Name: "old", Version: "1", Installed: true})
	c.AddEntry(&PackageInfo{Name: "tool", Version: "1", HasCandidate: true})
	c.AddEntry(&PackageInfo{Name: "tool", Architecture: "amd64", Version: "1", HasCandidate: true})
	c.AddEntry(&PackageInfo{Name: "app", Architecture: "arm64", Version: "1", HasCandidate: true, Depends: deps(t, "tool")})
	c.AddEntry(&PackageInfo{Name: "bad", Architecture: "amd64", Version: "1", HasCandidate: true, Conflicts: rels(t, "old")})

	order, _, err := c.ResolveDeps([]string{"app:arm64"})
	require.NoError(t, err)
	assert.Equal(t, []string{"tool:", "app:arm64"}, names(order), "an entry without architecture is an all package")

	_, _, err = c.ResolveDeps([]string{"bad"})
	require.ErrorIs(t, err, ErrConflict)
	assert.ErrorContains(t, err, "old:all 1")
}

func TestPriorityRank(t *testing.T) {
	t.Parallel()

	order := []string{"required", "important", "standard", "optional", "extra", "", "unknown"}

	for i := range len(order) - 2 {
		assert.Greater(t, priorityRank(order[i]), priorityRank(order[i+1]), "%s above %s", order[i], order[i+1])
	}

	assert.Equal(t, priorityRank(""), priorityRank("unknown"))
	assert.Equal(t, priorityRank("required"), priorityRank("REQUIRED"))
}

func TestLoadSkipsBadRelationFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, indexName("x", "main", "amd64")),
		stanza("badpre", "1", "Pre-Depends: foo (>= )")+
			stanza("badconf", "1", "Conflicts: foo (>= )")+
			stanza("badbreaks", "1", "Breaks: foo (>= )")+
			stanza("badprov", "1", "Provides: foo (>= )")+
			stanza("fine", "1"))

	status := filepath.Join(dir, "status")
	writeFile(t, status, installedStanza("badstatus", "1", "Depends: foo (>= )")+
		para("Package: noversion", "Status: install ok installed", "Architecture: amd64")+
		installedStanza("goodstatus", "1"))

	var buf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	c, err := Load(LoadOptions{ListsDir: dir, StatusFile: status, HostArch: hostArch, Logger: logger})
	require.NoError(t, err)

	assert.Equal(t, 2, c.PackageCount())
	assert.Equal(t, map[string]bool{"goodstatus": true}, c.InstalledNames())
	assert.Contains(t, buf.String(), "badstatus")
	assert.Contains(t, buf.String(), "noversion")
}
