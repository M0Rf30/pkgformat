package apt

import (
	"testing"
)

// FuzzPlan plans requests over a small universe built from fuzzed relation
// fields: no input may panic or hang, and a plan that succeeds must change
// each package at most once.
func FuzzPlan(f *testing.F) {
	f.Add("Depends: b", "Conflicts: c", "a", uint8(0))
	f.Add("Depends: b | c", "Breaks: b (<< 2)", "a", uint8(1))
	f.Add("Pre-Depends: a", "Provides: v", "b", uint8(2))
	f.Add("Depends: v", "Replaces: a", "", uint8(3))

	f.Fuzz(func(t *testing.T, fieldA, fieldB, seed string, mode uint8) {
		if len(fieldA) > 256 || len(fieldB) > 256 || len(seed) > 64 {
			t.Skip()
		}

		index := stanza("a", "2", fieldA) + stanza("b", "2", fieldB) + stanza("c", "1")
		status := installedStanza("a", "1") + installedStanza("c", "1", "Depends: b")

		c := cacheWithStatus(t, index, status)

		req := PlanRequest{Upgrade: UpgradeMode(mode % 4), FixBroken: mode&4 != 0}
		if seed != "" {
			req.Install = []string{seed}
		}

		got, err := c.Plan(req, PlanOptions{MaxSteps: 5000})
		if err != nil {
			return
		}

		seen := map[string]bool{}

		for _, ch := range got.Changes {
			key := ch.Package.Name + ":" + ch.Package.Architecture
			if seen[key] {
				t.Fatalf("%s changed twice in %v", key, planNames(got))
			}

			seen[key] = true
		}
	})
}
