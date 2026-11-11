package apt

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

// randomWorld is a generated package universe: a Packages index per
// architecture, a dpkg status file and an extended_states file.
type randomWorld struct {
	amd64, i386, status, states string
	names                       []string
}

// genRandomWorld builds a universe of related packages with every kind of
// relation, virtual packages, Multi-Arch: same siblings, essential and
// required packages, metapackages, held and automatically installed ones.
func genRandomWorld(r *rand.Rand) *randomWorld {
	n := 8 + r.IntN(20)
	w := &randomWorld{}

	var amd, i386, status, states strings.Builder

	pick := func() string {
		if r.IntN(6) == 0 {
			return fmt.Sprintf("v%d", r.IntN(3))
		}

		return fmt.Sprintf("p%02d", r.IntN(n))
	}

	relation := func() string {
		out := pick()

		switch r.IntN(6) {
		case 0:
			out += fmt.Sprintf(" (>= %d)", 1+r.IntN(3))
		case 1:
			out += fmt.Sprintf(" (<< %d)", 2+r.IntN(2))
		case 2:
			out += fmt.Sprintf(" (= %d)", 1+r.IntN(3))
		}

		return out
	}

	group := func() string {
		alts := []string{relation()}
		if r.IntN(4) == 0 {
			alts = append(alts, relation())
		}

		return strings.Join(alts, " | ")
	}

	field := func(name string, chance, most int, rel func() string) string {
		if r.IntN(100) >= chance {
			return ""
		}

		parts := make([]string, 1+r.IntN(most))
		for i := range parts {
			parts[i] = rel()
		}

		return name + ": " + strings.Join(parts, ", ")
	}

	for i := range n {
		name := fmt.Sprintf("p%02d", i)
		w.names = append(w.names, name)

		versions := 1 + r.IntN(3)
		sameArch := r.IntN(6) == 0
		essential := r.IntN(25) == 0
		required := r.IntN(25) == 0
		section := []string{"", "", "", "metapackages", "oldlibs", "libs"}[r.IntN(6)]
		source := fmt.Sprintf("src%d", r.IntN(n/4+1))

		installed := 0
		if r.IntN(100) < 45 {
			installed = 1 + r.IntN(versions)
		}

		for v := 1; v <= versions; v++ {
			fields := []string{
				field("Pre-Depends", 14, 1, group),
				field("Depends", 45, 2, group),
				field("Recommends", 25, 2, group),
				field("Suggests", 15, 2, group),
				field("Conflicts", 12, 1, relation),
				field("Breaks", 10, 1, relation),
				field("Provides", 16, 1, func() string { return fmt.Sprintf("v%d", r.IntN(3)) }),
				"Source: " + source,
			}

			if section != "" {
				fields = append(fields, "Section: "+section)
			}

			if essential {
				fields = append(fields, "Essential: yes")
			}

			if required {
				fields = append(fields, "Priority: required")
			}

			if sameArch {
				fields = append(fields, "Multi-Arch: same")
			}

			fields = slicesDeleteEmpty(fields)
			amd.WriteString(stanza(name, fmt.Sprint(v), fields...))

			if sameArch {
				i386.WriteString(stanza(name, fmt.Sprint(v), append([]string{"Architecture: i386"}, fields...)...))
			}

			if v == installed {
				statusLine := "install ok installed"
				if r.IntN(12) == 0 {
					statusLine = "hold ok installed"
				}

				status.WriteString(para(append([]string{
					"Package: " + name, "Status: " + statusLine, "Version: " + fmt.Sprint(v), "Architecture: amd64",
				}, fields...)...))

				if r.IntN(2) == 0 {
					states.WriteString(para("Package: "+name, "Architecture: amd64", "Auto-Installed: 1"))
				}
			}
		}
	}

	w.amd64, w.i386, w.status, w.states = amd.String(), i386.String(), status.String(), states.String()

	return w
}

func slicesDeleteEmpty(in []string) []string {
	out := in[:0]

	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}

	return out
}

func (w *randomWorld) load(tb testing.TB) *Cache {
	tb.Helper()

	dir := tb.TempDir()
	writeFile(tb, filepath.Join(dir, indexName("x", "main", "amd64")), w.amd64)

	if w.i386 != "" {
		writeFile(tb, filepath.Join(dir, indexName("x", "main", "i386")), w.i386)
	}

	statusFile := filepath.Join(dir, "status")
	writeFile(tb, statusFile, w.status)

	statesFile := filepath.Join(dir, "extended_states")
	writeFile(tb, statesFile, w.states)

	c, err := Load(LoadOptions{ListsDir: dir, StatusFile: statusFile, ExtendedStatesFile: statesFile, HostArch: hostArch})
	require.NoError(tb, err)

	return c
}

// randomRequest draws a request and options.
func randomRequest(r *rand.Rand, w *randomWorld) (PlanRequest, PlanOptions) {
	name := func() string { return w.names[r.IntN(len(w.names))] }

	var req PlanRequest

	for range r.IntN(3) {
		req.Install = append(req.Install, name())
	}

	if r.IntN(3) == 0 {
		req.Remove = append(req.Remove, name())
	}

	req.Upgrade = UpgradeMode(r.IntN(4))
	req.FixBroken = r.IntN(4) == 0
	req.AutoRemove = r.IntN(3) == 0

	var opts PlanOptions

	opts.MaxSteps = 50000

	if r.IntN(2) == 0 {
		opts.InstallRecommends = new(r.IntN(2) == 0)
	}

	if r.IntN(4) == 0 {
		opts.InstallSuggests = new(true)
	}

	if r.IntN(4) == 0 {
		opts.AutoRemoveRecommendsImportant = new(false)
	}

	if r.IntN(4) == 0 {
		opts.AutoRemoveSuggestsImportant = new(true)
	}

	if r.IntN(6) == 0 {
		opts.Held = []string{name()}
	}

	return req, opts
}

// finalSet is the installed set after the plan.
func finalSet(c *Cache, plan *Plan) map[string]*PackageInfo {
	set := make(map[string]*PackageInfo, len(c.installed))
	for key, p := range c.installed {
		set[key] = &p.PackageInfo
	}

	for _, ch := range plan.Changes {
		key := entryKey(ch.Package.Name, ch.Package.Architecture)
		if ch.Kind == ChangeRemove {
			delete(set, key)

			continue
		}

		set[key] = ch.Package
	}

	return set
}

// meets reports whether a package of the set satisfies the relation, by name
// or as a provider.
func meets(set map[string]*PackageInfo, rel *deb.Relation) bool {
	for _, p := range set {
		if p.Name == rel.Name && rel.Satisfied(p.Version) {
			return true
		}

		for _, prov := range p.Provides {
			if prov.Name == rel.Name && (rel.Op == "" || prov.Version != "" && rel.Satisfied(prov.Version)) {
				return true
			}
		}
	}

	return false
}

// checkPlanConsistent verifies that every package the plan installs or
// upgrades has its hard dependencies met and no conflict in the final set.
func checkPlanConsistent(t *testing.T, c *Cache, plan *Plan) {
	t.Helper()

	set := finalSet(c, plan)
	changed := make(map[string]bool)

	for _, ch := range plan.Changes {
		key := entryKey(ch.Package.Name, ch.Package.Architecture)
		if changed[key] {
			t.Fatalf("%s changed twice: %v", key, planNames(plan))
		}

		changed[key] = true

		if ch.Kind == ChangeRemove {
			continue
		}

		checkDepends(t, set, ch.Package, plan)
	}
}

func checkDepends(t *testing.T, set map[string]*PackageInfo, p *PackageInfo, plan *Plan) {
	t.Helper()

	if bad := violation(set, p); bad != "" {
		t.Fatalf("%s=%s: %s after %v", p.Name, p.Version, bad, planNames(plan))
	}
}

// violation says how the set breaks a hard relation of p, or "" when it does
// not.
func violation(set map[string]*PackageInfo, p *PackageInfo) string {
	for _, field := range [][]deb.Alternatives{p.PreDepends, p.Depends} {
		for _, alts := range field {
			ok := false

			for i := range alts {
				ok = ok || meets(set, &alts[i])
			}

			if !ok {
				return "dependency " + alts.String() + " unmet"
			}
		}
	}

	for _, rel := range append(append([]deb.Relation(nil), p.Conflicts...), p.Breaks...) {
		for _, q := range set {
			if q.Name == rel.Name && q.Name != p.Name && rel.Satisfied(q.Version) {
				return "conflicts with " + q.Name + "=" + q.Version
			}
		}
	}

	return ""
}

// prune drops from the installed set the packages whose relations do not
// hold, until the system is consistent, as a real one is.
func (w *randomWorld) prune(tb testing.TB) {
	tb.Helper()

	set := finalSet(w.load(tb), &Plan{})

	for changed := true; changed; {
		changed = false

		for key, p := range set {
			if violation(set, p) != "" {
				delete(set, key)

				changed = true
			}
		}
	}

	var kept []string

	for _, stanza := range strings.Split(strings.TrimSpace(w.status), "\n\n") {
		name, _, _ := strings.Cut(strings.TrimPrefix(stanza, "Package: "), "\n")
		if set[entryKey(name, hostArch)] != nil {
			kept = append(kept, stanza)
		}
	}

	w.status = strings.Join(kept, "\n\n") + "\n\n"
}

// TestPlanRandomWorlds plans random requests over generated universes. A plan
// that succeeds must be self-consistent and repeatable; one that fails must
// fail with a typed error.
func TestPlanRandomWorlds(t *testing.T) {
	t.Parallel()

	var planned, failed int

	kinds := map[OrderKind]int{}

	for seed := range uint64(400) {
		r := rand.New(rand.NewPCG(seed, 7))
		w := genRandomWorld(r)
		w.prune(t)

		c := w.load(t)

		for range 6 {
			req, opts := randomRequest(r, w)

			plan, err := c.Plan(req, opts)
			if err != nil {
				failed++

				var oe *OrderError
				if errors.As(err, &oe) {
					kinds[oe.Kind]++
				}

				require.NotEmpty(t, err.Error())

				continue
			}

			planned++

			checkPlanConsistent(t, c, plan)

			again, err := c.Plan(req, opts)
			require.NoError(t, err)
			require.Equal(t, planNames(plan), planNames(again), "plan is not repeatable (seed %d)", seed)
		}
	}

	t.Logf("planned %d, failed %d, order errors %v", planned, failed, kinds)
	require.Positive(t, planned)
	require.Positive(t, failed)
}
