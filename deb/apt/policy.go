package apt

import (
	"math"
	"runtime"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
)

// Pin priorities apt assigns without a pin, see apt_preferences(5).
const (
	// PriorityDefault is the priority of a version from an ordinary archive.
	PriorityDefault = 500
	// PriorityTarget is the priority of the releases named by
	// [PolicyOptions].DefaultRelease (apt-get -t).
	PriorityTarget = 990
	// PriorityInstalled is the priority of the installed version, and of
	// those of a NotAutomatic archive that is also ButAutomaticUpgrades.
	PriorityInstalled = 100
	// PriorityNotAutomatic is the priority of a NotAutomatic archive.
	PriorityNotAutomatic = 1
	// PriorityDowngrade is the priority from which apt installs a version older
	// than the installed one.
	PriorityDowngrade = 1000
)

// PolicyOptions configures a Policy.
type PolicyOptions struct {
	// DefaultRelease is APT::Default-Release (apt-get -t): versions of that
	// release (matched as archive, then codename) get priority 990 unless a
	// pin says otherwise. Any release pin expression works ("a=stable",
	// "o=Debian,n=bookworm", "12*"). apt refuses a value no source has; a
	// Policy cannot, and then simply pins nothing.
	DefaultRelease string
	// MachineID is the identifier phased updates are seeded with (the content
	// of /etc/machine-id); empty disables phasing (every version is in phase).
	// Only the first line counts.
	MachineID string
	// AlwaysIncludePhased and NeverIncludePhased are
	// APT::Get::Always-Include-Phased-Updates and Never-Include-Phased-Updates.
	AlwaysIncludePhased, NeverIncludePhased bool
	// NativeArch is the native architecture: a "Package:" name without
	// architecture pins that one. Empty selects the one of the running
	// program.
	NativeArch string
	// PhasedBehavior selects the generation of apt's phasing logic; the zero
	// value is the current one.
	PhasedBehavior PhasedModel
	// PhasePolicy is APT::Get::Phase-Policy: phased versions that are not
	// yet in phase get a pin priority of at most 1 instead of being held back
	// at upgrade time.
	PhasePolicy bool
	// IgnoreSourceVersionPins reads the source-version pin type as apt before
	// 2.7 (Debian 12 and older) does: it does not know it, warns, and drops
	// the stanza.
	IgnoreSourceVersionPins bool
	// InChroot reports that the program runs in a chroot (ischroot -t), where
	// apt does not phase updates.
	InChroot bool
}

// defaultPin is a "Package: *" pin: it sets the priority of whole package
// files.
type defaultPin struct {
	spec     *pinSpec
	priority int
}

// versionPin is a pin for named packages: it sets the priority of the
// versions it matches.
type versionPin struct {
	names    []namePin
	spec     *pinSpec
	priority int
}

// Policy decides pin priorities and candidate versions, as apt's pkgPolicy.
// It is immutable and safe for concurrent use.
type Policy struct {
	opts      PolicyOptions
	native    string
	machineID string
	defaults  []defaultPin
	pins      []versionPin
}

// NewPolicy builds a Policy from preferences (nil for none) and options.
func NewPolicy(prefs *Preferences, opts PolicyOptions) *Policy {
	p := &Policy{opts: opts, native: opts.NativeArch}

	if p.native == "" {
		p.native = ArchFromGoarch(runtime.GOARCH)
	}

	id, _, _ := strings.Cut(opts.MachineID, "\n")
	p.machineID = strings.TrimSuffix(id, "\r")

	if opts.DefaultRelease != "" {
		p.defaults = append(p.defaults, defaultPin{newPinSpec(PinRelease, opts.DefaultRelease), PriorityTarget})
	}

	if prefs == nil {
		return p
	}

	for i := range prefs.Pins {
		pin := &prefs.Pins[i]

		if pin.Type == PinSourceVersion && opts.IgnoreSourceVersionPins {
			continue
		}

		if len(pin.Packages) == 0 {
			if pin.Type == PinRelease || pin.Type == PinOrigin {
				p.defaults = append(p.defaults, defaultPin{newPinSpec(pin.Type, pin.Data), pin.Priority})
			}

			continue
		}

		vp := versionPin{spec: newPinSpec(pin.Type, pin.Data), priority: pin.Priority}
		for _, token := range pin.Packages {
			vp.names = append(vp.names, newNamePin(token))
		}

		p.pins = append(p.pins, vp)
	}

	return p
}

// emptyRelease stands for the index of a version nothing is known about.
var emptyRelease = &ReleaseInfo{}

// filesOf lists the package files of a version: its indexes, the dpkg status
// database when it is installed, and a blank index for a hand-built version
// that says nothing about where it comes from.
func filesOf(v *PackageInfo, buf []pinFile) []pinFile {
	for _, r := range v.Releases {
		if r != nil {
			buf = append(buf, pinFile{rel: r})
		}
	}

	if v.Installed {
		buf = append(buf, pinFile{status: true})
	}

	if len(buf) == 0 && v.available() {
		buf = append(buf, pinFile{rel: emptyRelease})
	}

	return buf
}

// filePriority is the priority of a package file: its default from the
// Release flags, then the first "Package: *" pin that matches it, with a
// never pin overriding even that.
func (p *Policy) filePriority(f pinFile) int {
	prio := PriorityDefault

	switch {
	case f.status:
		prio = PriorityInstalled
	case f.rel.ButAutomaticUpgrades:
		prio = PriorityInstalled
	case f.rel.NotAutomatic:
		prio = PriorityNotAutomatic
	}

	fixed := false

	for i := range p.defaults {
		d := &p.defaults[i]

		if (!fixed || d.priority == PriorityNever) && prio != PriorityNever && d.spec.matchFile(f) {
			prio = d.priority
			fixed = true
		}
	}

	return prio
}

// pinFor returns the priority of the first pin for named packages that matches
// v.
func (p *Policy) pinFor(v *PackageInfo, files []pinFile) (int, bool) {
	for i := range p.pins {
		pin := &p.pins[i]

		for j := range pin.names {
			if pin.names[j].matches(v, p.native) && pin.spec.matchVersion(v, files) {
				return pin.priority, true
			}
		}
	}

	return 0, false
}

// Priority is the pin priority of a version, as apt's pkgPolicy::GetPriority:
// the priority of the first pin for its package that matches, unless every
// package file of the version is never-pinned; otherwise the highest priority
// of its package files (its indexes and, when installed, the status file),
// which a "Package: *" pin, [PolicyOptions].DefaultRelease or the flags of the
// Release file set. 0 means the version is no candidate and negative that it
// must not be installed; [PriorityNever] is the "never" pin.
//
// A version that has no Releases and is available (a hand-built entry) counts
// as one ordinary archive, priority 500 unless a "release *" pin says
// otherwise.
func (p *Policy) Priority(v *PackageInfo) int {
	if v == nil {
		return 0
	}

	var buf [8]pinFile

	files := filesOf(v, buf[:0])

	ceiling := math.MaxInt
	if p.opts.PhasePolicy && p.holdsBack(v) {
		ceiling = 1
	}

	if prio, ok := p.pinFor(v, files); ok {
		if prio == PriorityNever {
			return PriorityNever
		}

		for _, f := range files {
			if p.filePriority(f) != PriorityNever {
				return min(prio, ceiling)
			}
		}
	}

	best := math.MinInt
	for _, f := range files {
		best = max(best, p.filePriority(f))
	}

	if best == math.MinInt {
		best = 0
	}

	return min(best, ceiling)
}

// Candidate returns the version apt would install of a package, as apt's
// pkgPolicy::GetCandidateVer: versions are the available versions of one
// package, highest version first; installed is the installed one or nil (a
// version of versions flagged Installed stands in for a nil installed). It is
// the first version of the highest priority; a version older than the
// installed one only counts from priority 1000, and priority 0 never counts.
// It returns nil when no version qualifies.
func (p *Policy) Candidate(versions []*PackageInfo, installed *PackageInfo) *PackageInfo {
	cur := installed
	if cur == nil {
		for _, v := range versions {
			if v != nil && v.Installed {
				cur = v

				break
			}
		}
	}

	var cand *PackageInfo

	candPrio := -1

	for _, v := range versions {
		if v == nil {
			continue
		}

		prio := p.Priority(v)
		if prio == 0 || prio <= candPrio {
			continue
		}

		if cur != nil && prio < PriorityDowngrade && deb.CompareVersions(v.Version, cur.Version) < 0 {
			continue
		}

		candPrio, cand = prio, v
	}

	return cand
}
