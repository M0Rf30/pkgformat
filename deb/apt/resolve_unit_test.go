package apt

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unitEngine(tb testing.TB, c *Cache) *engine {
	tb.Helper()

	return newEngine(c, nil, engineConfig{recommends: true, maxSteps: 10000})
}

func TestDefaultPriority(t *testing.T) {
	t.Parallel()

	rel := func(notAuto, butAuto bool) *ReleaseInfo {
		return &ReleaseInfo{NotAutomatic: notAuto, ButAutomaticUpgrades: butAuto}
	}

	tests := []struct {
		name string
		info PackageInfo
		want int
	}{
		{"index without release", PackageInfo{HasCandidate: true}, prioDefault},
		{"plain release", PackageInfo{HasCandidate: true, Releases: []*ReleaseInfo{rel(false, false)}}, prioDefault},
		{"not automatic", PackageInfo{HasCandidate: true, Releases: []*ReleaseInfo{rel(true, false)}}, prioNotAutomatic},
		{"not automatic but upgrades", PackageInfo{HasCandidate: true, Releases: []*ReleaseInfo{rel(true, true)}}, prioButAutomatic},
		{
			"best of several releases",
			PackageInfo{HasCandidate: true, Releases: []*ReleaseInfo{rel(true, false), rel(false, false)}},
			prioDefault,
		},
		{"installed only", PackageInfo{Installed: true}, prioButAutomatic},
		{
			"installed and held back by its index",
			PackageInfo{Installed: true, HasCandidate: true, Releases: []*ReleaseInfo{rel(true, false)}},
			prioButAutomatic,
		},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, defaultPriority(&pkg{PackageInfo: tt.info}), tt.name)
	}
}

func TestDefaultCandidateSkipsDowngrades(t *testing.T) {
	t.Parallel()

	index := stanza("a", "1") + stanza("a", "3")
	c := cacheWithStatus(t, index, installedStanza("a", "2"))
	versions := c.slots[entryKey("a", hostArch)]

	// Version 3 is the candidate; version 1 is older than the installed
	// one and never chosen on its own.
	assert.Equal(t, "3", defaultCandidate(versions, c.installed[entryKey("a", hostArch)]).Version)
	assert.Equal(t, "1", defaultCandidate(versions[2:], nil).Version)
	assert.Nil(t, defaultCandidate(versions[2:], c.installed[entryKey("a", hostArch)]))
	assert.Nil(t, defaultCandidate(nil, nil))
}

func TestSourceOfAndSectionIn(t *testing.T) {
	t.Parallel()

	name, ver := sourceOf(&pkg{PackageInfo: PackageInfo{Name: "bin", Version: "1.2"}})
	assert.Equal(t, "bin", name)
	assert.Equal(t, "1.2", ver)

	name, ver = sourceOf(&pkg{PackageInfo: PackageInfo{Name: "bin", Version: "1.2", SourceName: "src", SourceVersion: "1.1"}})
	assert.Equal(t, "src", name)
	assert.Equal(t, "1.1", ver)

	assert.False(t, sectionIn("", moveAutobitSections))
	assert.True(t, sectionIn("oldlibs", moveAutobitSections))
	assert.True(t, sectionIn("main/oldlibs", moveAutobitSections))
	assert.False(t, sectionIn("main/libs", moveAutobitSections))
}

func TestReasonKindString(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}

	for k := ReasonRequested; k <= ReasonBrokenDependency; k++ {
		s := k.String()
		assert.NotEmpty(t, s, "kind %d", k)
		assert.False(t, seen[s], s)

		seen[s] = true
	}

	assert.Empty(t, ReasonKind(0).String())
}

func TestPlanOptionError(t *testing.T) {
	t.Parallel()

	c := cacheWithStatus(t, stanza("a", "1"), "")

	_, err := c.Plan(PlanRequest{Install: []string{"a"}}, PlanOptions{NeverAutoRemove: []string{"("}})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPlanOption)

	var oe *PlanOptionError

	require.ErrorAs(t, err, &oe)
	assert.Equal(t, "NeverAutoRemove", oe.Option)
	assert.Equal(t, "(", oe.Value)
	require.Error(t, oe.Unwrap())
	assert.Contains(t, oe.Error(), `NeverAutoRemove "("`)
	assert.False(t, errors.Is(oe, ErrUnresolvable))
}

func TestOrderErrorMatching(t *testing.T) {
	t.Parallel()

	tests := []struct {
		kind   OrderKind
		name   string
		target error
	}{
		{OrderLoop, "loop", ErrOrderLoop},
		{OrderUnconfigured, "unconfigured", ErrOrderLoop},
		{OrderEssentialRemoval, "essential removal", ErrOrderRemoval},
		{OrderEarlyRemove, "early remove", ErrOrderRemoval},
		{OrderSimulation, "simulation", ErrOrderSimulation},
	}

	for _, tt := range tests {
		err := &OrderError{Kind: tt.kind, Package: "a:amd64", Cycle: []string{"a", "b", "a"}, Detail: "cannot"}

		assert.Equal(t, tt.name, tt.kind.String())
		require.ErrorIs(t, err, tt.target)
		assert.Equal(t, "apt: cannot (a -> b -> a)", err.Error())

		for _, other := range []error{ErrOrderLoop, ErrOrderRemoval, ErrOrderSimulation} {
			if !errors.Is(other, tt.target) {
				assert.NotErrorIs(t, err, other, tt.name)
			}
		}
	}

	assert.Equal(t, "unknown", OrderKind(99).String())
	assert.NotErrorIs(t, &OrderError{}, ErrUnresolvable)
	assert.Equal(t, "apt: cannot", (&OrderError{Detail: "cannot"}).Error())
}

func TestIsImportantAndDeleteOK(t *testing.T) {
	t.Parallel()

	e := unitEngine(t, cacheWithStatus(t, "", ""))
	assert.True(t, e.isImportant(&depGroup{kind: kindDepends}))
	assert.True(t, e.isImportant(&depGroup{kind: kindRecommends}))
	assert.False(t, e.isImportant(&depGroup{kind: kindSuggests}))

	// A new package the resolver chose is not dropped again unless the
	// request names it or it was installed automatically.
	whim := &pstate{inst: &pkg{}, status: 2}
	assert.False(t, e.isDeleteOK(whim, false))
	assert.True(t, e.isDeleteOK(whim, true))

	whim.auto = true
	assert.True(t, e.isDeleteOK(whim, false))
}

func TestMultiArchSynced(t *testing.T) {
	t.Parallel()

	same := []string{"Multi-Arch: same"}
	amd := func(version string) string { return stanza("lib", version, same...) }
	i386 := func(version string) string {
		return stanza("lib", version, append([]string{"Architecture: i386"}, same...)...)
	}
	status := installedStanza("lib", "1", same...) + installedStanza("lib", "1", append([]string{"Architecture: i386"}, same...)...)

	tests := []struct {
		name      string
		amd, i386 string
		installed string
		synced    bool
	}{
		{"sibling offered at another version", amd("3"), i386("2"), status, false},
		{"sibling offered at the same version", amd("3"), i386("3"), status, true},
		{"sibling only installed", amd("3"), "", status, true},
	}

	for _, tt := range tests {
		files := map[string]string{indexName("x", "main", "amd64"): tt.amd}
		if tt.i386 != "" {
			files[indexName("x", "main", "i386")] = tt.i386
		}

		dir := t.TempDir()
		for name, content := range files {
			writeFile(t, dir+"/"+name, content)
		}

		writeFile(t, dir+"/status", tt.installed)

		c, err := Load(LoadOptions{ListsDir: dir, StatusFile: dir + "/status", HostArch: hostArch})
		require.NoError(t, err)

		e := unitEngine(t, c)
		s := e.state(entryKey("lib", hostArch))
		require.NotNil(t, s.cand, tt.name)
		assert.Equal(t, tt.synced, e.multiArchSynced(s, s.cand), tt.name)
	}
}

func TestCompareProviders(t *testing.T) {
	t.Parallel()

	index := stanza("t", "1") +
		stanza("req", "1", "Provides: t", "Priority: required") +
		stanza("opt", "1", "Provides: t", "Priority: optional") +
		stanza("extra", "1", "Provides: t", "Priority: extra") +
		stanza("tail", "1", "Provides: t", "Priority: extra") +
		stanza("foreign", "1", "Architecture: i386", "Provides: t", "Priority: extra", "Multi-Arch: same") +
		stanza("ess", "1", "Provides: t", "Priority: extra", "Essential: yes") +
		stanza("inst", "1", "Provides: t", "Priority: extra") +
		stanza("sib", "1", "Provides: t", "Multi-Arch: same") +
		stanza("sib", "1", "Architecture: i386", "Provides: t", "Multi-Arch: same")
	status := installedStanza("inst", "1", "Provides: t", "Priority: extra") +
		installedStanza("sib", "1", "Architecture: i386", "Provides: t", "Multi-Arch: same")
	c := cacheWithStatus(t, index, status)
	e := unitEngine(t, c)

	v := func(name string) *pkg { return c.slots[entryKey(name, hostArch)][0] }
	foreign := c.slots[entryKey("foreign", "i386")][0]
	sibAmd := c.slots[entryKey("sib", hostArch)][0]

	tests := []struct {
		name string
		a, b *pkg
		want int // sign
	}{
		{"the target itself first", v("t"), v("opt"), -1},
		{"the target itself first (b)", v("opt"), v("t"), 1},
		{"installed first", v("inst"), v("extra"), -1},
		{"essential first", v("ess"), v("extra"), -1},
		{"required first", v("req"), v("opt"), -1},
		{"optional before extra", v("opt"), v("extra"), -1},
		{"native architecture first", v("extra"), foreign, -1},
		{"native architecture first (b)", foreign, v("extra"), 1},
		{"read later first", v("tail"), v("extra"), -1},
		{"read earlier last", v("extra"), v("tail"), 1},
		{"Multi-Arch same with an installed sibling first", sibAmd, v("extra"), -1},
		{"Multi-Arch same with an installed sibling first (b)", v("extra"), sibAmd, 1},
		{"two Multi-Arch same packages", sibAmd, foreign, -1},
	}

	for _, tt := range tests {
		got := e.compareProviders("t", tt.a, tt.b)
		assert.Equal(t, tt.want, sign(got), tt.name)
	}

	// A protected package goes before any other.
	e.state(v("extra").slot).protect = true
	assert.Negative(t, e.compareProviders("t", v("extra"), v("t")))
	assert.Positive(t, e.compareProviders("t", v("t"), v("extra")))
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func TestSlotArchAndGroupPreferred(t *testing.T) {
	t.Parallel()

	e := unitEngine(t, cacheWithStatus(t, "", ""))
	assert.Equal(t, archAll, e.slotArch(&pkg{}))
	assert.Equal(t, "i386", e.slotArch(&pkg{PackageInfo: PackageInfo{Architecture: "i386"}}))

	assert.Equal(t, "a:amd64", e.groupPreferred([]string{"a:i386", "a:amd64"}))
	assert.Equal(t, "a", e.groupPreferred([]string{"a:i386", "a"}))
	assert.Equal(t, "a:i386", e.groupPreferred([]string{"a:i386", "a:arm64"}))
}

func TestMarkAutoArchitectures(t *testing.T) {
	t.Parallel()

	c := NewCache("amd64")
	for _, arch := range []string{"amd64", "i386", "all"} {
		c.AddEntry(&PackageInfo{Name: "a", Version: "1", Architecture: arch, Installed: true})
	}

	auto := func() []string {
		var out []string

		for key, p := range c.installed {
			if p.AutoInstalled {
				out = append(out, key)
			}
		}

		return out
	}

	c.markAuto(AutoMark{Package: "a", Architecture: "i386"})
	assert.ElementsMatch(t, []string{"a:i386"}, auto())

	c.markAuto(AutoMark{Package: "a", Architecture: "amd64"})
	assert.ElementsMatch(t, []string{"a:i386", "a:amd64", "a"}, auto())

	c = NewCache("amd64")
	c.AddEntry(&PackageInfo{Name: "a", Version: "1", Architecture: "amd64", Installed: true})
	c.AddEntry(&PackageInfo{Name: "a", Version: "1", Architecture: "i386", Installed: true})
	c.markAuto(AutoMark{Package: "a"})
	assert.ElementsMatch(t, []string{"a:i386", "a:amd64"}, auto())
}

func TestSweepGivesUpOnLongChains(t *testing.T) {
	t.Parallel()

	// A dependency chain longer than apt follows: the mark phase gives up and
	// nothing is called garbage, so autoremove leaves everything alone.
	const length = maxMarkChain + 50

	var status strings.Builder

	auto := []string{"loose"}

	for i := range length {
		fields := []string{}
		if i+1 < length {
			fields = append(fields, fmt.Sprintf("Depends: c%d", i+1))
		}

		status.WriteString(installedStanza(fmt.Sprintf("c%d", i), "1", fields...))

		if i > 0 {
			auto = append(auto, fmt.Sprintf("c%d", i))
		}
	}

	// c0 is manual and its chain is c1... ; a loose automatic package at the
	// end is garbage only if the mark phase finished.
	status.WriteString(installedStanza("loose", "1"))

	c := cacheWithAuto(t, "", status.String(), auto...)

	plan, err := c.Plan(PlanRequest{AutoRemove: true}, PlanOptions{})
	require.NoError(t, err)
	assert.Empty(t, plan.Changes)
}
