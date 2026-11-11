package apt

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// orderCache loads an amd64 index, an i386 index and a status file.
func orderCache(tb testing.TB, amd, i386, status string) *Cache {
	tb.Helper()

	dir := tb.TempDir()
	writeFile(tb, filepath.Join(dir, indexName("x", "main", "amd64")), amd)

	if i386 != "" {
		writeFile(tb, filepath.Join(dir, indexName("x", "main", "i386")), i386)
	}

	statusFile := filepath.Join(dir, "status")
	writeFile(tb, statusFile, status)

	c, err := Load(LoadOptions{ListsDir: dir, StatusFile: statusFile, HostArch: hostArch})
	require.NoError(tb, err)

	return c
}

func TestPlanOrderPreDependsFirst(t *testing.T) {
	t.Parallel()

	c := cacheWithStatus(t, stanza("app", "1", "Pre-Depends: lib")+stanza("lib", "1"), "")

	got, err := c.Plan(PlanRequest{Install: []string{"app"}}, PlanOptions{})
	require.NoError(t, err)
	assert.Equal(t, []string{"install lib=1", "install app=1"}, planNames(got))
}

func TestPlanOrderLoop(t *testing.T) {
	t.Parallel()

	c := cacheWithStatus(t, stanza("a", "1", "Pre-Depends: b")+stanza("b", "1", "Pre-Depends: a"), "")

	_, err := c.Plan(PlanRequest{Install: []string{"a"}}, PlanOptions{})
	require.ErrorIs(t, err, ErrOrderLoop)

	var oe *OrderError

	require.ErrorAs(t, err, &oe)
	assert.Equal(t, OrderLoop, oe.Kind)
	assert.Contains(t, oe.Cycle, "a:amd64")
	assert.Contains(t, oe.Cycle, "b:amd64")
	assert.Equal(t, oe.Cycle[0], oe.Cycle[len(oe.Cycle)-1])
}

// A Multi-Arch: same package is unpacked together with its other
// architectures; a failure in one of them is the failure of the group,
// whether the other architecture is installed or about to be.
func TestUnpackSameGroupFailure(t *testing.T) {
	t.Parallel()

	same := "Multi-Arch: same"
	amd := stanza("lib", "2", same)
	i386 := stanza("lib", "2", "Architecture: i386", same, "Pre-Depends: pq") +
		stanza("pq", "1", "Architecture: i386", "Pre-Depends: lib (>= 2)")

	libAmd, libI386 := entryKey("lib", hostArch), entryKey("lib", "i386")

	for name, status := range map[string]string{
		"installed mate":     installedStanza("lib", "1", same) + installedStanza("lib", "1", "Architecture: i386", same),
		"not installed mate": installedStanza("lib", "1", same),
	} {
		c := orderCache(t, amd, i386, status)
		e := newEngine(c, nil, engineConfig{recommends: true, maxSteps: 10000})
		e.markInstall(e.state(libAmd), false, 0, true)
		e.markInstall(e.state(libI386), false, 0, true)

		m := newPackageManager(e)
		m.createOrderList()

		err := m.unpackSameGroup(libAmd, e.state(libAmd), 0)
		require.ErrorIs(t, err, ErrOrderLoop, name)
	}
}

// Without trouble the architectures go in step: the installed one first.
func TestUnpackSameGroupOrder(t *testing.T) {
	t.Parallel()

	same := "Multi-Arch: same"
	amd := stanza("lib", "2", same)
	i386 := stanza("lib", "2", "Architecture: i386", same)
	status := installedStanza("lib", "1", "Architecture: i386", same)
	c := orderCache(t, amd, i386, status)

	libAmd, libI386 := entryKey("lib", hostArch), entryKey("lib", "i386")
	e := newEngine(c, nil, engineConfig{recommends: true, maxSteps: 10000})
	e.markInstall(e.state(libAmd), false, 0, true)
	e.markInstall(e.state(libI386), false, 0, true)

	m := newPackageManager(e)
	m.createOrderList()

	require.NoError(t, m.unpackSameGroup(libAmd, e.state(libAmd), 0))
	assert.Equal(t, []orderOp{{opInstall, libI386}, {opInstall, libAmd}}, m.ops)
}

// manager sets up the order lists of an engine whose packages were marked.
func orderManager(t *testing.T, index, status string, mark func(e *engine)) (*packageManager, *engine) {
	t.Helper()

	e := newEngine(cacheWithStatus(t, index, status), nil, engineConfig{recommends: true, maxSteps: 10000})
	mark(e)

	m := newPackageManager(e)
	m.createOrderList()

	return m, e
}

func TestConflictsOfRemovesWhatGoes(t *testing.T) {
	t.Parallel()

	za, zb := entryKey("za", hostArch), entryKey("zb", hostArch)
	m, e := orderManager(t, stanza("za", "1", "Conflicts: zb"), installedStanza("zb", "1"), func(e *engine) {
		e.markInstall(e.state(za), false, 0, true)
		e.markDelete(e.state(zb), 0, true)
	})

	g := &e.depsOf(e.state(za).inst)[0]
	changed := false

	bad, err := m.conflictsOf(za, g, 0, false, &changed)
	require.NoError(t, err)
	assert.False(t, bad)
	assert.Equal(t, []orderOp{{opRemove, zb}}, m.ops)
}

func TestEarlyRemove(t *testing.T) {
	t.Parallel()

	index := stanza("new", "1", "Conflicts: old") + stanza("also", "1")
	status := installedStanza("old", "1") + installedStanza("ess", "1", "Essential: yes") +
		installedStanza("dep", "1", "Depends: old") + installedStanza("boss", "1", "Essential: yes", "Pre-Depends: dep")
	m, e := orderManager(t, index, status, func(e *engine) {
		e.markInstall(e.state(entryKey("new", hostArch)), false, 0, true)
	})

	conflict := &depGroup{kind: kindConflicts}
	old, ess, dep := entryKey("old", hostArch), entryKey("ess", hostArch), entryKey("dep", hostArch)

	// An ordinary package is removed for the time being.
	m.l.set(old, ofInList)
	require.NoError(t, m.earlyRemove(old, conflict))
	assert.Equal(t, []orderOp{{opRemove, old}}, m.ops)

	// And only once.
	require.NoError(t, m.earlyRemove(old, conflict))
	assert.Len(t, m.ops, 1)

	// A package the list does not hold cannot be.
	err := m.earlyRemove(entryKey("also", hostArch), conflict)
	require.ErrorIs(t, err, ErrOrderRemoval)

	var oe *OrderError

	require.ErrorAs(t, err, &oe)
	assert.Equal(t, OrderEarlyRemove, oe.Kind)

	// An essential package, or one an essential package Pre-Depends on, never
	// is.
	m.l.set(ess, ofInList)
	err = m.earlyRemove(ess, conflict)
	require.ErrorAs(t, err, &oe)
	assert.Equal(t, OrderEssentialRemoval, oe.Kind)

	m.l.set(dep, ofInList)
	err = m.earlyRemove(dep, conflict)
	require.ErrorAs(t, err, &oe)
	assert.Equal(t, OrderEssentialRemoval, oe.Kind)

	// dpkg deconfigures a package a Breaks names by itself.
	m.l.set(ess, ofInList)
	require.NoError(t, m.earlyRemove(ess, &depGroup{kind: kindBreaks}))

	_ = e
}

func TestPlanFixBrokenLimit(t *testing.T) {
	t.Parallel()

	// a and e are installed without what they need; repairing them takes more
	// steps than a small budget allows, wherever the budget runs out.
	c := cacheWithStatus(t, stanza("b", "1")+stanza("c", "1", "Depends: d"),
		installedStanza("a", "1", "Depends: b | z")+installedStanza("e", "1", "Depends: nothere"))

	for steps := 1; steps <= 17; steps++ {
		_, err := c.Plan(PlanRequest{FixBroken: true}, PlanOptions{MaxSteps: steps})
		require.ErrorIs(t, err, ErrResolveLimit, "%d steps", steps)
	}

	got, err := c.Plan(PlanRequest{FixBroken: true}, PlanOptions{})
	require.NoError(t, err)
	assert.Contains(t, planNames(got), "install b=1")
	assert.Contains(t, planNames(got), "remove e=1")

	// A held package cannot be removed, and what it needs is not there.
	held := cacheWithStatus(t, "", para("Package: h", "Status: hold ok installed", "Version: 1",
		"Architecture: amd64", "Depends: nothere"))
	_, err = held.Plan(PlanRequest{FixBroken: true}, PlanOptions{})
	require.ErrorIs(t, err, ErrUnresolvable)
}
