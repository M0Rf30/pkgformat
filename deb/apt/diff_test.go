package apt

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The differential test resolves real packages from the package indexes and
// dpkg status of a debian container and compares the packages ResolveDeps
// would install with what `apt-get install -s --no-install-recommends` planned
// for them in that container. testdata/diff holds both, captured and trimmed
// by testdata/diff/generate.sh; MANIFEST says which image and apt.
//
// The targets of the fixture all match: the same packages, at the same
// versions. That is a property of this fixture and not a promise. ResolveDeps
// is documented to differ from apt in three ways, none of which these targets
// meet, and a target that does would have to be listed here with its reason
// instead of being left to fail:
//
//   - apt removes an installed package (Remv) that a candidate conflicts with,
//     or upgrades or removes one a candidate Breaks; ResolveDeps never removes
//     or upgrades to make room and reports a ConflictError (the test below
//     fails on a Remv line, so the fixture shows none).
//   - apt's solver scores the ways to meet a dependency when nothing installed
//     or selected decides; ResolveDeps takes the first alternative that can be
//     installed and, among providers, the one apt prefers (Priority, then the
//     one read last, candidate versions first). The first choice agrees with
//     apt's wherever it was probed, the trees below a choice may differ.
//   - apt weighs pin priorities, which are not modelled: the highest version
//     is the candidate, and apt looks only at the candidate where ResolveDeps
//     takes the highest version that meets a constraint.
//
// The comparison is on package names and, for the packages both plan, versions.
type aptPlan struct {
	install map[string]string // name -> version
	remove  []string
}

// loadPlans reads expected.tsv: target, Inst or Remv, package, version.
func loadPlans(t *testing.T, path string) (map[string]*aptPlan, []string) {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)

	defer func() { _ = f.Close() }()

	plans := map[string]*aptPlan{}

	var order []string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		require.Len(t, fields, 4, sc.Text())

		target, kind, name, version := fields[0], fields[1], fields[2], fields[3]

		plan := plans[target]
		if plan == nil {
			plan = &aptPlan{install: map[string]string{}}
			plans[target] = plan

			order = append(order, target)
		}

		switch kind {
		case "Inst":
			plan.install[name] = version
		case "Remv":
			plan.remove = append(plan.remove, name)
		default:
			t.Fatalf("unknown plan line %q", sc.Text())
		}
	}

	require.NoError(t, sc.Err())

	return plans, order
}

func TestDifferentialAgainstApt(t *testing.T) {
	t.Parallel()

	dir := filepath.Join("testdata", "diff")

	targetsText, err := os.ReadFile(filepath.Join(dir, "targets.txt"))
	require.NoError(t, err)

	plans, _ := loadPlans(t, filepath.Join(dir, "expected.tsv"))

	var targets []string

	for line := range strings.SplitSeq(string(targetsText), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	require.GreaterOrEqual(t, len(targets), 20)

	c, err := Load(LoadOptions{
		ListsDir:   filepath.Join(dir, "lists"),
		StatusFile: filepath.Join(dir, "status"),
		HostArch:   "amd64",
		Sources:    []Source{{URL: "http://deb.debian.org/debian/"}},
	})
	require.NoError(t, err)

	matches := 0

	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			plan := plans[target]
			require.NotNil(t, plan, "no apt plan for %s", target)

			order, unresolved, err := c.ResolveDeps([]string{target})

			require.NoError(t, err)
			assert.Empty(t, unresolved)

			got := map[string]string{}

			for _, p := range order {
				name := p.Name
				if p.Architecture != "amd64" && p.Architecture != "all" && p.Architecture != "" {
					name += ":" + p.Architecture
				}

				got[name] = p.Version
			}

			assert.Empty(t, plan.remove, "apt removes packages, which ResolveDeps never does")
			assert.Equal(t, sortedKeys(plan.install), sortedKeys(got), "packages installed for %s", target)

			for name, version := range got {
				if want, ok := plan.install[name]; ok {
					assert.Equal(t, want, version, "version of %s", name)
				}
			}

			if !t.Failed() {
				matches++
			}
		})
	}

	t.Logf("%d of %d targets match apt exactly", matches, len(targets))
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	slices.Sort(keys)

	return keys
}
