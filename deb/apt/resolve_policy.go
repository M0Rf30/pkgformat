package apt

import "github.com/M0Rf30/pkgformat/deb"

// candidatePolicy is what the resolver asks of a pin policy. A [*Policy]
// satisfies it; a nil policy selects the defaults of [defaultCandidate].
type candidatePolicy interface {
	// Candidate selects the version of one package to install, or nil.
	Candidate(versions []*PackageInfo, installed *PackageInfo) *PackageInfo
	// Priority is the pin priority of a version.
	Priority(v *PackageInfo) int
	// Phased reports whether a phased update of v is withheld from a system
	// that has installed.
	Phased(v, installed *PackageInfo) bool
}

// Default pin priorities of a package version that no preference changes.
const (
	prioDefault      = 500 // an ordinary index
	prioButAutomatic = 100 // NotAutomatic with ButAutomaticUpgrades; installed-only
	prioNotAutomatic = 1   // NotAutomatic
	prioUpgradeFloor = 1000
)

// defaultPriority is the pin priority apt gives a version when no preference
// applies: 500 for a version an index offers, 100 for a version only the
// installed system has, 1 for an index flagged NotAutomatic (100 with
// ButAutomaticUpgrades). The highest figure over all the places a version is
// found wins.
func defaultPriority(p *pkg) int {
	best := 0

	if p.available() {
		best = prioDefault

		if len(p.Releases) > 0 {
			best = 0

			for _, rel := range p.Releases {
				prio := prioDefault

				switch {
				case rel.NotAutomatic && rel.ButAutomaticUpgrades:
					prio = prioButAutomatic
				case rel.NotAutomatic:
					prio = prioNotAutomatic
				}

				best = max(best, prio)
			}
		}
	}

	if p.Installed {
		best = max(best, prioButAutomatic)
	}

	return best
}

// defaultCandidate is apt's choice of a candidate with no preferences: the
// highest priority wins, and among equals the highest version (versions are
// ordered highest first); a version of priority 0 is never chosen, and below
// priority 1000 a version older than the installed one is skipped.
func defaultCandidate(versions []*pkg, cur *pkg) *pkg {
	var (
		cand *pkg
		best = -1
	)

	for _, v := range versions {
		prio := defaultPriority(v)
		if prio == 0 || prio <= best {
			continue
		}

		if cur != nil && prio < prioUpgradeFloor && deb.CompareVersions(v.Version, cur.Version) < 0 {
			continue
		}

		cand, best = v, prio
	}

	return cand
}

// selectCandidate chooses the candidate of one package's versions, through
// the policy when there is one.
func selectCandidate(pol candidatePolicy, versions []*pkg, cur *pkg) *pkg {
	if pol == nil {
		return defaultCandidate(versions, cur)
	}

	infos := make([]*PackageInfo, len(versions))
	for i, v := range versions {
		infos[i] = &v.PackageInfo
	}

	var installed *PackageInfo
	if cur != nil {
		installed = &cur.PackageInfo
	}

	got := pol.Candidate(infos, installed)
	if got == nil {
		return nil
	}

	for _, v := range versions {
		if &v.PackageInfo == got {
			return v
		}
	}

	return nil
}
