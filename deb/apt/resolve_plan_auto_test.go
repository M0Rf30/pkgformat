package apt

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cacheWithAuto loads an index and a status file, marking the named packages
// as automatically installed through an extended_states file.
func cacheWithAuto(tb testing.TB, index, status string, auto ...string) *Cache {
	tb.Helper()

	dir := tb.TempDir()
	writeFile(tb, filepath.Join(dir, indexName("x", "main", "amd64")), index)

	statusFile := filepath.Join(dir, "status")
	writeFile(tb, statusFile, status)

	var states strings.Builder
	for _, name := range auto {
		states.WriteString(para("Package: "+name, "Architecture: amd64", "Auto-Installed: 1"))
	}

	statesFile := filepath.Join(dir, "extended_states")
	writeFile(tb, statesFile, states.String())

	c, err := Load(LoadOptions{
		ListsDir: dir, StatusFile: statusFile, ExtendedStatesFile: statesFile, HostArch: hostArch,
	})
	require.NoError(tb, err)

	return c
}

func autoNames(list []*PackageInfo) []string {
	out := make([]string, len(list))
	for i, p := range list {
		out[i] = p.Name
	}

	return out
}

func TestPlanAutoRemoveDropsOnlyUnneeded(t *testing.T) {
	t.Parallel()

	// a needs b; c is a leftover nothing needs.
	status := installedStanza("a", "1", "Depends: b") + installedStanza("b", "1") + installedStanza("c", "1")
	c := cacheWithAuto(t, "", status, "b", "c")

	got, err := c.Plan(PlanRequest{AutoRemove: true}, PlanOptions{})
	require.NoError(t, err)
	assert.Equal(t, []string{"remove c=1"}, planNames(got))

	// Without AutoRemove the leftover is only reported.
	got, err = c.Plan(PlanRequest{Install: []string{"a"}}, PlanOptions{})
	require.NoError(t, err)
	assert.Empty(t, got.Changes)
	assert.Equal(t, []string{"c"}, autoNames(got.AutoRemovable))
}

func TestPlanAutoRemoveRestoresNeededInstalls(t *testing.T) {
	t.Parallel()

	// Installing a upgrades the automatically installed y, which now needs a
	// new z. Nothing manual needs y or z, so both look like garbage, but y
	// stays installed and so z must too.
	index := stanza("a", "2", "Breaks: y (<< 2)") + stanza("y", "2", "Depends: z") + stanza("z", "1")
	status := installedStanza("y", "1")
	c := cacheWithAuto(t, index, status, "y")

	got, err := c.Plan(PlanRequest{Install: []string{"a"}}, PlanOptions{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"upgrade y=2", "install z=1", "install a=2"}, planNames(got))
}
