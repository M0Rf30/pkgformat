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

// FuzzParseExtendedStates reads arbitrary extended states files: no input may
// panic, and every mark returned must name a package.
func FuzzParseExtendedStates(f *testing.F) {
	f.Add([]byte("Package: a\nArchitecture: amd64\nAuto-Installed: 1\n\nPackage: b\nAuto-Installed: 0\n"))
	f.Add([]byte("Package: \nAuto-Installed: 1\n"))
	f.Add([]byte("Auto-Installed: 1\n\n\n\nPackage: x\nAuto-Installed: 1"))
	f.Add([]byte("Package: a\r\nAuto-Installed: 1\r\n"))
	f.Add([]byte{0, 0xff, '\n', '\n'})

	f.Fuzz(func(t *testing.T, data []byte) {
		marks, err := ParseExtendedStates(data)
		if err != nil {
			return
		}

		for _, m := range marks {
			if m.Package == "" {
				t.Fatalf("mark without a package in %q", data)
			}
		}
	})
}
