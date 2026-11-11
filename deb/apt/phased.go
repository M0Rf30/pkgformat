package apt

import "strings"

// PhasedModel selects which generation of apt's phased-update logic a [Policy]
// reproduces. The three differ in details that decide whether one machine gets
// an update, so the one matching the apt being mimicked must be chosen; the
// zero value is the current one.
type PhasedModel int

const (
	// PhasedCurrent is apt 3.3.0 and later: the draw is uniform over 0..99 and
	// an update is held back when the draw is at least the percentage, so 0%
	// holds everyone back and 100% nobody. A version in a "-security" suite
	// between the installed and the candidate version, the candidate included,
	// lifts the hold.
	PhasedCurrent PhasedModel = iota
	// PhasedPre33 is apt 2.7.11 up to 3.2.x, Debian 13's apt among them: the
	// draw is uniform over 0..100 and an update is held back when the draw is
	// above the percentage, so a machine is in phase with probability
	// (percentage+1)/101, and 0% still lets one machine in a hundred and one
	// through. The security rule is as in [PhasedCurrent].
	PhasedPre33
	// PhasedPre2711 is apt before 2.7.11, Debian 12's apt among them. The draw
	// is that of [PhasedPre33]; the security rule only looks at the versions
	// between the installed one and the candidate, not at the candidate.
	PhasedPre2711
)

// draws returns the number of distinct values of the draw, 100 or 101.
func (m PhasedModel) draws() uint64 {
	if m == PhasedCurrent {
		return 100
	}

	return 101
}

// heldBack reports whether a draw keeps back a version phased at percentage.
func (m PhasedModel) heldBack(draw, percentage int) bool {
	if m == PhasedCurrent {
		return draw >= percentage
	}

	return draw > percentage
}

// securityIncludesCandidate reports whether the candidate's own suite counts
// for the security rule.
func (m PhasedModel) securityIncludesCandidate() bool { return m != PhasedPre2711 }

// Constants of the generators apt's draw is built from: std::seed_seq,
// std::minstd_rand (a=48271, c=0, m=2^31-1) and std::uniform_int_distribution
// as libstdc++ implements them.
const (
	minstdMultiplier = 48271
	minstdModulus    = 2147483647
	minstdRange      = minstdModulus - 2 // max() - min() of minstd_rand
	seedSeqWords     = 4                 // minstd_rand::seed(seed_seq) asks for k+3 words
)

// seedSeqGenerate is std::seed_seq::generate as libstdc++ implements it, for
// the 32-bit words v, filling n output words.
func seedSeqGenerate(v []uint32, n int) []uint32 {
	b := make([]uint32, n)
	for i := range b {
		b[i] = 0x8b8b8b8b
	}

	var t int

	switch {
	case n >= 623:
		t = 11
	case n >= 68:
		t = 7
	case n >= 39:
		t = 5
	case n >= 7:
		t = 3
	default:
		t = (n - 1) / 2
	}

	p := (n - t) / 2
	q := p + t
	s := len(v)
	m := max(s+1, n)

	mix := func(x uint32) uint32 { return x ^ x>>27 }

	for k := range m {
		r1 := 1664525 * mix(b[k%n]^b[(k+p)%n]^b[(k+n-1)%n])

		var r2 uint32

		switch {
		case k == 0:
			r2 = r1 + uint32(s)
		case k <= s:
			r2 = r1 + uint32(k%n) + v[k-1]
		default:
			r2 = r1 + uint32(k%n)
		}

		b[(k+p)%n] += r1
		b[(k+q)%n] += r2
		b[k%n] = r2
	}

	for k := m; k < m+n; k++ {
		r3 := 1566083941 * mix(b[k%n]+b[(k+p)%n]+b[(k+n-1)%n])
		r4 := r3 - uint32(k%n)

		b[(k+p)%n] ^= r3
		b[(k+q)%n] ^= r4
		b[k%n] = r4
	}

	return b
}

// PhasedDraw is the number apt draws for a machine and a source package
// version: it seeds std::minstd_rand through std::seed_seq with
// "<source>-<source version>-<machine id>" and takes one value of a
// std::uniform_int_distribution over 0..99 ([PhasedCurrent]) or 0..100 (the
// other models), computed the way libstdc++ does. A version phased at
// percentage p is held back when the draw is at least p ([PhasedCurrent]) or
// above p (the others).
//
// The bytes of the seed are widened as signed chars, as on x86; names and
// versions are ASCII.
func PhasedDraw(sourceName, sourceVersion, machineID string, model PhasedModel) int {
	seed := sourceName + "-" + sourceVersion + "-" + machineID
	words := make([]uint32, len(seed))

	for i := range len(seed) {
		words[i] = uint32(int32(int8(seed[i])))
	}

	x := uint64(seedSeqGenerate(words, seedSeqWords)[3]) % minstdModulus
	if x == 0 {
		x = 1
	}

	next := func() uint64 {
		x = x * minstdMultiplier % minstdModulus

		return x
	}

	// libstdc++ downscales with two divisions when the generator range is not
	// 2^32-1: reject draws past the largest multiple of the range.
	erange := model.draws()
	scaling := uint64(minstdRange) / erange
	past := erange * scaling

	for {
		ret := next() - 1
		if ret < past {
			return int(ret / scaling)
		}
	}
}

// phasedPercentage is the Phased-Update-Percentage of v; 100 for a version
// that has none or an invalid one, which apt ignores.
func phasedPercentage(v *PackageInfo) int {
	if v.PhasedUpdatePercentage == nil {
		return 100
	}

	if n := *v.PhasedUpdatePercentage; n >= 0 && n <= 100 {
		return n
	}

	return 100
}

// holdsBack is apt's phasing decision for a version phased below 100%,
// without the checks around it: the Always and Never options, the machine
// identifier, chroots, then the draw.
func (p *Policy) holdsBack(v *PackageInfo) bool {
	pct := phasedPercentage(v)
	if pct == 100 || p.opts.AlwaysIncludePhased {
		return false
	}

	if p.opts.NeverIncludePhased {
		return true
	}

	if p.machineID == "" || p.opts.InChroot {
		return false
	}

	draw := PhasedDraw(sourceNameOf(v), sourceVersionOf(v), p.machineID, p.opts.PhasedBehavior)

	return p.opts.PhasedBehavior.heldBack(draw, pct)
}

// Phased reports whether apt holds back an upgrade from installed to v because
// v is a phased update this machine is not yet part of (apt-get upgrade, full
// upgrade and the upgradable lists). It is false without an installed version
// (a new installation is never phased), when v is the installed version, when
// v has no Phased-Update-Percentage or it is 100, when [PolicyOptions]
// AlwaysIncludePhased is set, when the machine has no identifier or runs in a
// chroot, and when v comes from a security suite. It is true under
// NeverIncludePhased.
//
// With only v at hand the security rule looks at v's own suites; use
// [Policy.PhasedIn] to let it see the versions between the installed one and
// v too. With [PolicyOptions] PhasePolicy, phasing is part of the pin
// priorities instead and Phased answers for every version, installed or not.
func (p *Policy) Phased(v, installed *PackageInfo) bool {
	return p.PhasedIn(nil, v, installed)
}

// PhasedIn is [Policy.Phased] with the versions of the package, the highest
// first, for the security rule: a version in a "-security" suite lifts the
// hold when it is v or lies between the installed version and v.
func (p *Policy) PhasedIn(versions []*PackageInfo, v, installed *PackageInfo) bool {
	if v == nil {
		return false
	}

	if p.opts.PhasePolicy {
		return p.holdsBack(v)
	}

	if installed == nil || sameVersion(v, installed) || phasedPercentage(v) == 100 {
		return false
	}

	if p.securityUpdate(versions, v, installed) {
		return false
	}

	return p.holdsBack(v)
}

// sameVersion reports whether a and b are the same version of a package.
func sameVersion(a, b *PackageInfo) bool {
	return a == b || a != nil && b != nil && a.Version == b.Version
}

// inSecuritySuite reports whether any index of v belongs to a "-security"
// suite.
func inSecuritySuite(v *PackageInfo) bool {
	for _, r := range v.Releases {
		if r != nil && strings.HasSuffix(r.Suite, "-security") {
			return true
		}
	}

	return false
}

// securityUpdate is apt's IsSecurityUpdate: v, when the model counts it, or a
// version older than v and newer than the installed one is in a security
// suite.
func (p *Policy) securityUpdate(versions []*PackageInfo, v, installed *PackageInfo) bool {
	if p.opts.PhasedBehavior.securityIncludesCandidate() && inSecuritySuite(v) {
		return true
	}

	start := -1

	for i, o := range versions {
		if sameVersion(o, v) {
			start = i + 1

			break
		}
	}

	if start < 0 {
		return false
	}

	for _, o := range versions[start:] {
		if o == nil || sameVersion(o, installed) {
			break
		}

		if inSecuritySuite(o) {
			return true
		}
	}

	return false
}
