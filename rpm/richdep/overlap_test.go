package richdep_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/richdep"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// TestOverlapsMatchesLibrpm replays testdata/overlap_golden.tsv, the answers of
// librpm's rpmdsCompare (through the python bindings) for 6000 pairs of
// versioned capabilities: epochs given, absent or empty, tildes, carets,
// letters and releases.
func TestOverlapsMatchesLibrpm(t *testing.T) {
	lines := goldenLines(t, "overlap_golden.tsv")
	require.Greater(t, len(lines), 5000)

	for _, l := range lines {
		// goldenLines splits at the first two tabs only; the rest is
		// "evr1 TAB flags2 TAB evr2 TAB result".
		parts := strings.Split(l[0]+"\t"+l[1]+"\t"+l[2], "\t")
		require.Len(t, parts, 5)

		f1, err := strconv.Atoi(parts[0])
		require.NoError(t, err)

		f2, err := strconv.Atoi(parts[2])
		require.NoError(t, err)

		a := richdep.Atom{Name: "n", Cmp: richdep.Cmp(f1), Version: parts[1]}
		b := richdep.Atom{Name: "n", Cmp: richdep.Cmp(f2), Version: parts[3]}

		assert.Equalf(t, parts[4] == "1", a.Overlaps(b), "%s overlaps %s", a, b)
		assert.Equalf(t, parts[4] == "1", b.Overlaps(a), "%s overlaps %s", b, a)
	}
}

func TestOverlapsRules(t *testing.T) {
	t.Parallel()

	ge := func(v string) richdep.Atom {
		return richdep.Atom{Name: "n", Cmp: richdep.Greater | richdep.Equal, Version: v}
	}

	assert.False(t, richdep.Atom{Name: "n"}.Overlaps(richdep.Atom{Name: "m"}), "names differ")
	assert.True(t, richdep.Atom{Name: "n"}.Overlaps(ge("9")), "no constraint on one side")
	assert.True(t, ge("1").Overlaps(richdep.Atom{Name: "n", Cmp: richdep.Equal, Version: "2-5"}))
	assert.False(t, richdep.Atom{Name: "n", Cmp: richdep.Less, Version: "1"}.Overlaps(ge("1")))
}

func TestAtomOf(t *testing.T) {
	t.Parallel()

	assert.Equal(t, richdep.Atom{Name: "a"}, richdep.AtomOf(rpm.Dependency{Name: "a", Version: "9"}),
		"no comparison drops the version")
	assert.Equal(t, richdep.Atom{Name: "a", Cmp: richdep.Equal, Version: "1.0-2"},
		richdep.AtomOf(rpm.Dependency{Name: "a", Flags: tag.RPMSENSE_EQUAL, Version: "1.0-2"}))
	assert.Equal(t, richdep.Atom{Name: "a", Cmp: richdep.Greater | richdep.Equal, Version: "3:1.0"},
		richdep.AtomOf(rpm.Dependency{Name: "a", Flags: tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL | tag.RPMSENSE_PREREQ,
			Version: "1.0", Epoch: 3}), "an epoch is written, other flag bits are dropped")
}
