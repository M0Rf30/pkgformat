package apt

// PolicyOptions configures a Policy.
type PolicyOptions struct {
	// DefaultRelease is APT::Default-Release (apt-get -t): versions of that
	// release (matched as archive, then codename) get priority 990 unless a
	// pin says otherwise.
	DefaultRelease string
	// MachineID is the identifier phased updates are seeded with (the content
	// of /etc/machine-id); empty disables phasing (every version is in phase).
	MachineID string
	// AlwaysIncludePhased and NeverIncludePhased are
	// APT::Get::Always-Include-Phased-Updates and Never-Include-Phased-Updates.
	AlwaysIncludePhased, NeverIncludePhased bool
}

// Policy decides pin priorities and candidate versions, as apt's pkgPolicy.
type Policy struct {
	prefs *Preferences
	opts  PolicyOptions
}

// NewPolicy builds a Policy from preferences (nil for none) and options.
func NewPolicy(prefs *Preferences, opts PolicyOptions) *Policy {
	return &Policy{prefs: prefs, opts: opts}
}

// Priority is the pin priority of a version.
func (p *Policy) Priority(v *PackageInfo) int { return 500 }

// Candidate returns the version apt would install of a package: versions are
// the available versions of one package, highest version first; installed is
// the installed one or nil. It returns nil when no version qualifies.
func (p *Policy) Candidate(versions []*PackageInfo, installed *PackageInfo) *PackageInfo {
	if len(versions) == 0 {
		return nil
	}

	return versions[0]
}

// Phased reports whether v is held back by a phased update with respect to
// the installed version.
func (p *Policy) Phased(v, installed *PackageInfo) bool { return false }
