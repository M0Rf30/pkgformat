package apk

// Replacement is the decision on a file that two packages both ship: whether
// the incoming package may take it over from the package that owns it.
type Replacement uint8

// The decisions of [ReplacesFile].
const (
	// ReplaceYes: the incoming package takes the file; apk overwrites it
	// without a warning.
	ReplaceYes Replacement = iota + 1
	// ReplaceNo: the owner keeps the file and the incoming package's copy is
	// skipped.
	ReplaceNo
	// ReplaceConflict: the metadata does not say who wins; apk refuses the
	// installation unless it is forced ("trying to overwrite ... owned by").
	ReplaceConflict
)

// String returns "yes", "no" or "conflict".
func (r Replacement) String() string {
	switch r {
	case ReplaceYes:
		return "yes"
	case ReplaceNo:
		return "no"
	case ReplaceConflict:
		return "conflict"
	default:
		return "unknown"
	}
}

// replacesPackage reports whether one of the replaces entries of p names
// other, by name and version; a package that is only provided under that name
// does not count.
func replacesPackage(p, other *Package) bool {
	for _, s := range p.Replaces {
		d, err := ParseDependency(s)
		if err != nil {
			continue
		}

		if d.Name != other.Name {
			if d.Conflict {
				return true
			}

			continue
		}

		var ok bool
		if d.Op == OpChecksum {
			ok = other.Checksum == d.Version
		} else {
			ok = d.MatchVersion(other.Version)
		}

		if ok != d.Conflict {
			return true
		}
	}

	return false
}

// ReplacesFile decides who gets a file that both owner (installed) and
// incoming (about to be installed) ship, with apk's rules: an overlay file (a
// nil owner) goes to the incoming package; two versions of the same package
// are no conflict; otherwise each side's "replaces" list and
// "replaces_priority" are compared, a package that lists the other in
// "replaces" wins over one that does not, the higher priority wins, and two
// packages of the same origin share files; anything else is a conflict.
func ReplacesFile(owner, incoming *Package) Replacement {
	if owner == nil {
		return ReplaceYes
	}

	if incoming == nil {
		return ReplaceNo
	}

	if owner.Name == incoming.Name {
		return ReplaceYes
	}

	ownerPrio, incomingPrio := -1, -1

	if replacesPackage(owner, incoming) {
		ownerPrio = owner.ReplacesPriority
	}

	if replacesPackage(incoming, owner) {
		incomingPrio = incoming.ReplacesPriority
	}

	switch {
	case ownerPrio > incomingPrio:
		return ReplaceNo
	case incomingPrio >= 0:
		return ReplaceYes
	case owner.Origin != "" && owner.Origin == incoming.Origin:
		return ReplaceYes
	default:
		return ReplaceConflict
	}
}
