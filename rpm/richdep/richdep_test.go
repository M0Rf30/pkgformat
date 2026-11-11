package richdep_test

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/rpm/richdep"
)

func kindOf(tag string) richdep.Kind {
	switch tag {
	case "Conflicts", "Supplements", "Enhances":
		return richdep.KindConflict
	case "Provides", "Obsoletes":
		return richdep.KindProvide
	default:
		return richdep.KindRequire
	}
}

// goldenLines reads a tab separated file: tag, flag, dependency (which may
// have leading or trailing blanks, so only the newline is trimmed).
func goldenLines(t *testing.T, name string) [][3]string {
	t.Helper()

	f, err := os.Open("testdata/" + name)
	require.NoError(t, err)

	defer func() { _ = f.Close() }()

	var out [][3]string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 3)
		require.Len(t, parts, 3, sc.Text())

		out = append(out, [3]string{parts[0], parts[1], parts[2]})
	}

	require.NoError(t, sc.Err())

	return out
}

// TestParseMatchesLibrpm replays testdata/parse_golden.tsv, which
// testdata/generate.py recorded from rpmbuild 6.0.1 (librpm): every dependency
// rpmbuild accepts as the value of a tag must parse and the others must not.
func TestParseMatchesLibrpm(t *testing.T) {
	lines := goldenLines(t, "parse_golden.tsv")
	require.Greater(t, len(lines), 1000)

	for _, l := range lines {
		tag, want, dep := l[0], l[1] == "1", l[2]

		n, err := richdep.ParseFor(dep, kindOf(tag))
		if want {
			require.NoErrorf(t, err, "%s: %q is accepted by librpm", tag, dep)
			assertRoundTrip(t, n)
		} else {
			assert.Errorf(t, err, "%s: %q is refused by librpm", tag, dep)
		}
	}
}

// TestFedoraCorpus replays testdata/fedora_golden.tsv: boolean dependencies of
// the Fedora 43 packages, which testdata/fedora_corpus.py collected and had
// rpmbuild accept. Each must parse, print canonically and evaluate.
func TestFedoraCorpus(t *testing.T) {
	lines := goldenLines(t, "fedora_golden.tsv")
	require.Greater(t, len(lines), 1000)

	everything := richdep.OracleFunc(func(a richdep.Atom) []string { return []string{a.Name} })
	nothing := richdep.OracleFunc(func(richdep.Atom) []string { return nil })

	for _, l := range lines {
		tag, dep := l[0], l[2]

		n, err := richdep.ParseFor(dep, kindOf(tag))
		require.NoErrorf(t, err, "%s: %q is accepted by librpm", tag, dep)
		assertRoundTrip(t, n)
		assert.NotEmpty(t, richdep.Atoms(n), dep)

		// neither oracle may panic, and an empty one holds no conjunction
		_ = richdep.Eval(n, everything)
		_ = richdep.Set(n, everything)

		if e, ok := n.(*richdep.Expr); ok && e.Op == richdep.OpAnd {
			assert.False(t, richdep.Eval(n, nothing), dep)
		}
	}
}

// assertRoundTrip checks that the canonical text parses back to the same tree
// and is its own canonical text.
func assertRoundTrip(t *testing.T, n richdep.Node) {
	t.Helper()

	s := n.String()
	m, err := richdep.Parse(s)
	require.NoErrorf(t, err, "canonical form %q", s)
	assert.Equal(t, n, m, s)
	assert.Equal(t, s, m.String())
}

// fixtures is the installed set testdata/generate.py gave rpm: package name,
// then provides as (name, comparison, version); every package also provides
// itself at 1-1.
var fixtures = map[string][]richdep.Atom{
	"a":  {{Name: "a-virt", Cmp: richdep.Equal, Version: "2"}},
	"b":  nil,
	"c":  {{Name: "c-old", Cmp: richdep.Less, Version: "1"}},
	"x1": {{Name: "s1"}, {Name: "s2"}},
	"x2": {{Name: "s1", Cmp: richdep.Equal, Version: "1.5"}},
	"x3": {{Name: "s2", Cmp: richdep.Equal, Version: "3-4"}, {Name: "ep", Cmp: richdep.Equal, Version: "1:2.0"}},
}

// fixtureOracle is the installed set; rpmlib's own features count for a
// Requires only, since a Conflicts is checked against the installed packages.
func fixtureOracle(withRpmlib bool) richdep.Oracle {
	return richdep.OracleFunc(func(a richdep.Atom) []string {
		if a.Name == "rpmlib(CompressedFileNames)" {
			if !withRpmlib {
				return nil
			}

			// librpm provides its own features.
			if (richdep.Atom{Name: a.Name, Cmp: richdep.Less | richdep.Equal, Version: "3.0.4-1"}).Overlaps(a) {
				return []string{"rpmlib"}
			}

			return nil
		}

		var out []string

		for pkg, provides := range fixtures {
			all := append([]richdep.Atom{{Name: pkg, Cmp: richdep.Equal, Version: "1-1"}}, provides...)
			for _, p := range all {
				if p.Overlaps(a) {
					out = append(out, pkg)

					break
				}
			}
		}

		return out
	})
}

// TestEvalMatchesLibrpm replays testdata/eval_golden.tsv: for the fixtures
// above, "rpm -U --test" says whether each Requires is met and whether each
// Conflicts fires (it fires when the dependency is satisfied).
func TestEvalMatchesLibrpm(t *testing.T) {
	lines := goldenLines(t, "eval_golden.tsv")
	require.Greater(t, len(lines), 300)

	for _, l := range lines {
		tag, want, dep := l[0], l[1] == "1", l[2]

		n, err := richdep.ParseFor(dep, kindOf(tag))
		require.NoErrorf(t, err, "%s: %q", tag, dep)

		o := fixtureOracle(kindOf(tag) == richdep.KindRequire)

		assert.Equalf(t, want, richdep.Eval(n, o), "%s: %q", tag, dep)
	}
}
