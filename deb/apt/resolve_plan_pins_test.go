package apt

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

// fakePolicy pins versions by "name=version": a figure in prio overrides the
// ordinary 500, a name in phased withholds its candidate.
type fakePolicy struct {
	prio   map[string]int
	phased map[string]bool
}

func (f fakePolicy) Priority(v *PackageInfo) int {
	if p, ok := f.prio[v.Name+"="+v.Version]; ok {
		return p
	}

	return 500
}

func (f fakePolicy) Candidate(versions []*PackageInfo, installed *PackageInfo) *PackageInfo {
	var (
		best *PackageInfo
		prio int
	)

	for _, v := range versions {
		p := f.Priority(v)
		if p <= 0 || p <= prio {
			continue
		}

		if installed != nil && p < 1000 && deb.CompareVersions(v.Version, installed.Version) < 0 {
			continue
		}

		best, prio = v, p
	}

	return best
}

func (f fakePolicy) Phased(v, _ *PackageInfo) bool { return f.phased[v.Name] }

func TestPlanPins(t *testing.T) {
	two := stanza("a", "1") + stanza("a", "2")

	runPlanCases(t, []planCase{
		{
			name: "never pinned version is skipped", index: two,
			req:  PlanRequest{Install: []string{"a"}},
			pol:  fakePolicy{prio: map[string]int{"a=2": -1}},
			want: []string{"install a=1"},
		},
		{
			name: "pinned above wins", index: two,
			req:  PlanRequest{Install: []string{"a"}},
			pol:  fakePolicy{prio: map[string]int{"a=1": 900}},
			want: []string{"install a=1"},
		},
		{
			name: "every version never pinned", index: two,
			req:   PlanRequest{Install: []string{"a"}},
			pol:   fakePolicy{prio: map[string]int{"a=1": -1, "a=2": -1}},
			want:  []string{},
			unres: []string{"a"},
		},
		{
			name: "explicit version overrides the pin", index: two,
			req:  PlanRequest{Install: []string{"a (= 2)"}},
			pol:  fakePolicy{prio: map[string]int{"a=2": -1}},
			want: []string{"install a=2"},
		},
		{
			name: "downgrade by a pin above 1000", index: two,
			status: installedStanza("a", "2"),
			req:    PlanRequest{Install: []string{"a"}},
			pol:    fakePolicy{prio: map[string]int{"a=1": 1001}},
			want:   []string{"downgrade a=1"},
		},
		{
			name: "older version is not a candidate below 1000", index: two,
			status: installedStanza("a", "2"),
			req:    PlanRequest{Install: []string{"a"}},
			pol:    fakePolicy{prio: map[string]int{"a=1": 999}},
			want:   []string{},
		},
		{
			name:  "dependency takes the pinned candidate",
			index: stanza("x", "1", "Depends: b") + stanza("b", "1") + stanza("b", "2"),
			req:   PlanRequest{Install: []string{"x"}},
			pol:   fakePolicy{prio: map[string]int{"b=2": -1}},
			want:  []string{"install b=1", "install x=1"},
		},
		{
			name:  "alternative skips the never pinned package",
			index: stanza("x", "1", "Depends: b | c") + stanza("b", "1") + stanza("c", "1"),
			req:   PlanRequest{Install: []string{"x"}},
			pol:   fakePolicy{prio: map[string]int{"b=1": -1}},
			want:  []string{"install c=1", "install x=1"},
		},
		{
			name:   "upgrade stays at the pinned candidate",
			index:  stanza("a", "2") + stanza("a", "3"),
			status: installedStanza("a", "1"),
			req:    PlanRequest{Upgrade: UpgradeSafe},
			pol:    fakePolicy{prio: map[string]int{"a=3": -1}},
			want:   []string{"upgrade a=2"},
		},
		{
			name: "phased update is kept back", index: stanza("a", "2"),
			status: installedStanza("a", "1"),
			req:    PlanRequest{Upgrade: UpgradeSafe},
			pol:    fakePolicy{phased: map[string]bool{"a": true}},
			want:   []string{},
			held:   []string{"a"},
		},
		{
			name: "phased update is kept back by dist-upgrade", index: stanza("a", "2"),
			status: installedStanza("a", "1"),
			req:    PlanRequest{Upgrade: UpgradeFull},
			pol:    fakePolicy{phased: map[string]bool{"a": true}},
			want:   []string{},
			held:   []string{"a"},
		},
	})
}

func TestPlanPinnedDependencyUnmet(t *testing.T) {
	c := cacheWithStatus(t, stanza("x", "1", "Depends: b (>= 2)")+stanza("b", "1")+stanza("b", "2"), "")

	_, err := c.plan(PlanRequest{Install: []string{"x"}}, PlanOptions{},
		fakePolicy{prio: map[string]int{"b=2": -1}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnresolvable)
	assert.ErrorIs(t, err, ErrUnsatisfiable)
}

func TestPlanHeld(t *testing.T) {
	index := stanza("a", "2") + stanza("u", "2", "Depends: a (>= 2)") + stanza("rm", "1", "Conflicts: a")
	status := installedStanza("a", "1") + installedStanza("u", "1", "Depends: a")

	runPlanCases(t, []planCase{
		{
			name: "upgrade skips a held package", index: index, status: status,
			req:  PlanRequest{Upgrade: UpgradeSafe},
			opts: PlanOptions{Held: []string{"a"}},
			want: []string{}, held: []string{"a", "u"},
		},
		{
			name: "held with its architecture", index: index, status: status,
			req:  PlanRequest{Upgrade: UpgradeSafe},
			opts: PlanOptions{Held: []string{"a:amd64"}},
			want: []string{}, held: []string{"a", "u"},
		},
	})

	c := cacheWithStatus(t, index, status)

	// A conflict cannot remove a held package: the plan fails, as apt's.
	_, err := c.Plan(PlanRequest{Install: []string{"rm"}}, PlanOptions{Held: []string{"a"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConflict)

	// Removing a held package is allowed when asked for by name, as in apt.
	got, err := c.Plan(PlanRequest{Remove: []string{"a"}}, PlanOptions{Held: []string{"a"}})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a=1", "u=1"}, sortedNames(got.Remove))
}

func sortedNames(list []*PackageInfo) []string {
	out := make([]string, 0, len(list))
	for _, p := range list {
		out = append(out, p.Name+"="+p.Version)
	}

	return out
}

func TestPlanVirtualRequest(t *testing.T) {
	index := stanza("m1", "1", "Provides: svc") + stanza("m2", "1", "Provides: svc") +
		stanza("one", "1", "Provides: solo")

	c := cacheWithStatus(t, index, "")

	_, err := c.Plan(PlanRequest{Install: []string{"svc"}}, PlanOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrVirtualPackage)

	var ve *VirtualPackageError

	require.True(t, errors.As(err, &ve))
	assert.Equal(t, "svc", ve.Name)
	assert.Len(t, ve.Providers, 2)
	assert.Contains(t, err.Error(), "svc")

	got, err := c.Plan(PlanRequest{Install: []string{"solo"}}, PlanOptions{})
	require.NoError(t, err)
	assert.Equal(t, []string{"install one=1"}, planNames(got))
}

func TestPlanMalformedRequest(t *testing.T) {
	c := cacheWithStatus(t, stanza("a", "1"), "")

	_, err := c.Plan(PlanRequest{Install: []string{"a (>= "}}, PlanOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, deb.ErrInvalidControlFormat)
}

func TestPlanBudget(t *testing.T) {
	c := cacheWithStatus(t, stanza("a", "1", "Depends: b")+stanza("b", "1", "Depends: c")+stanza("c", "1"), "")

	_, err := c.Plan(PlanRequest{Install: []string{"a"}}, PlanOptions{MaxSteps: 2})
	assert.ErrorIs(t, err, ErrResolveLimit)

	got, err := c.Plan(PlanRequest{Install: []string{"a"}}, PlanOptions{})
	require.NoError(t, err)
	assert.Len(t, got.Install, 3)
}

func TestPlanDeterministic(t *testing.T) {
	index := stanza("a", "1", "Depends: p | q") + stanza("p", "1", "Provides: v") +
		stanza("q", "1", "Provides: v") + stanza("b", "1", "Conflicts: z")
	status := installedStanza("z", "1")
	c := cacheWithStatus(t, index, status)

	first, err := c.Plan(PlanRequest{Install: []string{"a", "b"}}, PlanOptions{})
	require.NoError(t, err)

	for range 5 {
		again, err := c.Plan(PlanRequest{Install: []string{"b", "a"}}, PlanOptions{})
		require.NoError(t, err)
		assert.Equal(t, planNames(first), planNames(again))
	}
}

func TestPlanReasons(t *testing.T) {
	index := stanza("a", "2", "Depends: d", "Conflicts: c", "Breaks: b (<< 2)") +
		stanza("d", "1") + stanza("b", "2")
	status := installedStanza("c", "1") + installedStanza("b", "1")
	c := cacheWithStatus(t, index, status)

	got, err := c.Plan(PlanRequest{Install: []string{"a"}}, PlanOptions{})
	require.NoError(t, err)

	reasons := map[string]Reason{}
	kinds := map[string]ChangeKind{}

	for _, ch := range got.Changes {
		reasons[ch.Package.Name] = ch.Reason
		kinds[ch.Package.Name] = ch.Kind
	}

	assert.Equal(t, ReasonRequested, reasons["a"].Kind)
	assert.Equal(t, ReasonDependency, reasons["d"].Kind)
	assert.Equal(t, ReasonConflict, reasons["c"].Kind)
	assert.Contains(t, reasons["c"].Cause, "a")
	assert.Equal(t, ChangeUpgrade, kinds["b"])
	assert.Equal(t, ReasonUpgradeDependency, reasons["b"].Kind)

	for _, ch := range got.Changes {
		if ch.Kind == ChangeUpgrade {
			require.NotNil(t, ch.From)
			assert.Equal(t, "1", ch.From.Version)
		}
	}

	assert.False(t, got.Empty())
	assert.NotEmpty(t, reasons["c"].String())
}

func TestPlanStringers(t *testing.T) {
	assert.Equal(t, "dist-upgrade", UpgradeFull.String())
	assert.Equal(t, "upgrade", UpgradeSafe.String())
	assert.Equal(t, "upgrade-with-new-packages", UpgradeWithNew.String())
	assert.Equal(t, "none", UpgradeNone.String())
	assert.Equal(t, "UpgradeMode(9)", UpgradeMode(9).String())

	for _, k := range []ReasonKind{
		ReasonRequested, ReasonDependency, ReasonUpgradeDependency, ReasonSameSource,
		ReasonConflict, ReasonBreaks, ReasonBrokenDependency,
	} {
		assert.NotEmpty(t, k.String())
	}

	assert.Empty(t, ReasonKind(0).String())

	for _, k := range []ChangeKind{ChangeInstall, ChangeUpgrade, ChangeDowngrade, ChangeRemove} {
		assert.NotEmpty(t, k.String())
	}

	assert.Empty(t, ChangeKind(0).String())

	r := Reason{Kind: ReasonDependency, Cause: "a:amd64 1", Relation: "b (>= 1)"}
	assert.Equal(t, "dependency of a:amd64 1 (b (>= 1))", r.String())
	assert.True(t, (&Plan{}).Empty())
}

func TestPlanErrorBounded(t *testing.T) {
	pe := &PlanError{}
	for range 7 {
		pe.Broken = append(pe.Broken, ErrUnsatisfiable)
	}

	assert.Contains(t, pe.Error(), "and 3 more")
	assert.ErrorIs(t, pe, ErrUnresolvable)
	assert.ErrorIs(t, pe, ErrUnsatisfiable)
	assert.NotErrorIs(t, pe, ErrConflict)
}

func TestPlanSameSource(t *testing.T) {
	index := stanza("lib", "2", "Source: src") + stanza("bin", "2", "Source: src")
	status := installedStanza("lib", "1", "Source: src") + installedStanza("bin", "1", "Source: src")
	c := cacheWithStatus(t, index, status)

	// The loader leaves the source fields to the caller; set them as a
	// status reader that parses "Source:" would.
	for _, list := range c.slots {
		for _, v := range list {
			v.SourceName = "src"
			v.SourceVersion = v.Version
		}
	}

	got, err := c.Plan(PlanRequest{Install: []string{"lib"}}, PlanOptions{})
	require.NoError(t, err)
	assert.Equal(t, []string{"upgrade bin=2", "upgrade lib=2"}, planNames(got))

	for _, ch := range got.Changes {
		if ch.Package.Name == "bin" {
			assert.Equal(t, ReasonSameSource, ch.Reason.Kind)
		}
	}
}

func TestPlanMultiArch(t *testing.T) {
	c := cacheFromFiles(t, map[string]string{
		indexName("x", "main", "amd64"): stanza("a", "1", "Depends: b:any") +
			stanza("b", "1", "Multi-Arch: allowed"),
		indexName("x", "main", "i386"): stanza("b", "1", "Architecture: i386", "Multi-Arch: allowed"),
	})

	got, err := c.Plan(PlanRequest{Install: []string{"a", "b:i386"}}, PlanOptions{})
	require.NoError(t, err)
	// b:i386 meets b:any, so the amd64 b is not needed.
	assert.Equal(t, []string{"install b=1", "install a=1"}, planNames(got))
	assert.Equal(t, "i386", got.Install[0].Architecture)
}

func TestPlanRemoveHeldAndProtected(t *testing.T) {
	status := installedStanza("a", "1", "Essential: yes") + installedStanza("b", "1", "Depends: a")
	c := cacheWithStatus(t, "", status)

	got, err := c.Plan(PlanRequest{Remove: []string{"a"}}, PlanOptions{})
	require.NoError(t, err)
	assert.NotEmpty(t, got.Remove)
}
