package deb

import "strings"

// Wildcard and qualifier spellings of Debian architectures.
const (
	// ArchAny is the wildcard that matches every architecture, and the ":any"
	// qualifier of a relation.
	ArchAny = "any"
	// ArchNative is the ":native" qualifier of a relation: the architecture
	// of the system that runs the build.
	ArchNative = "native"
	// ArchAll is the Architecture value of a package that is the same on
	// every architecture.
	ArchAll = "all"
)

// archTuple is the Debian architecture tuple, "abi-libc-os-cpu", of an
// architecture or, with "any" parts, of a wildcard.
type archTuple [4]string

// debianCPUs are the CPU names of dpkg's cputable.
var debianCPUs = [...]string{
	"alpha", "amd64", "arc", "armeb", "arm", "arm64", "hppa", "loong64", "i386",
	"ia64", "m68k", "mips", "mipsel", "mipsr6", "mipsr6el", "mips64", "mips64el",
	"mips64r6", "mips64r6el", "nios2", "or1k", "powerpc", "powerpcel", "ppc64",
	"ppc64el", "riscv64", "s390", "s390x", "sh3", "sh3eb", "sh4", "sh4eb",
	"sparc", "sparc64",
}

func isDebianCPU(s string) bool {
	for _, c := range debianCPUs {
		if c == s {
			return true
		}
	}

	return false
}

// debarchTuple maps a Debian architecture name to its tuple, following dpkg's
// tupletable. A "linux-" prefix is dropped first ("linux-amd64" is "amd64"), as
// dpkg does. ok is false for a name that is not a known architecture.
func debarchTuple(arch string) (archTuple, bool) {
	if rest, ok := strings.CutPrefix(arch, "linux-"); ok {
		arch, _, _ = strings.Cut(rest, "-")
	}

	// The architectures whose names do not follow a pattern.
	switch arch {
	case "armhf":
		return archTuple{"eabihf", "gnu", "linux", "arm"}, true
	case "armel":
		return archTuple{"eabi", "gnu", "linux", "arm"}, true
	case "mipsn32r6el":
		return archTuple{"abin32", "gnu", "linux", "mips64r6el"}, true
	case "mipsn32r6":
		return archTuple{"abin32", "gnu", "linux", "mips64r6"}, true
	case "mipsn32el":
		return archTuple{"abin32", "gnu", "linux", "mips64el"}, true
	case "mipsn32":
		return archTuple{"abin32", "gnu", "linux", "mips64"}, true
	case "mips64r6el", "mips64r6", "mips64el", "mips64":
		return archTuple{"abi64", "gnu", "linux", arch}, true
	case "x32":
		return archTuple{"x32", "gnu", "linux", "amd64"}, true
	case "hurd-amd64", "hurd-i386":
		return archTuple{"base", "gnu", "hurd", strings.TrimPrefix(arch, "hurd-")}, true
	case "uclibc-linux-armel":
		return archTuple{"eabi", "uclibc", "linux", "arm"}, true
	case "musl-linux-armhf":
		return archTuple{"eabihf", "musl", "linux", "arm"}, true
	case "dragonflybsd-amd64":
		return archTuple{"base", "bsd", "dragonflybsd", "amd64"}, true
	case "freebsd-amd64", "freebsd-arm", "freebsd-arm64", "freebsd-i386",
		"freebsd-powerpc", "freebsd-ppc64", "freebsd-riscv",
		"darwin-amd64", "darwin-arm", "darwin-arm64", "darwin-i386",
		"darwin-powerpc", "darwin-ppc64":
		osName, cpu, _ := strings.Cut(arch, "-")

		return archTuple{"base", "bsd", osName, cpu}, true
	case "aix-powerpc", "aix-ppc64", "solaris-amd64", "solaris-i386", "solaris-sparc", "solaris-sparc64":
		osName, cpu, _ := strings.Cut(arch, "-")

		return archTuple{"base", "sysv", osName, cpu}, true
	case "mint-m68k":
		return archTuple{"base", "tos", "mint", "m68k"}, true
	}

	if isDebianCPU(arch) {
		return archTuple{"base", "gnu", "linux", arch}, true
	}

	for _, p := range [...]struct{ prefix, libc, osName string }{
		{"uclibc-linux-", "uclibc", "linux"},
		{"musl-linux-", "musl", "linux"},
		{"openbsd-", "bsd", "openbsd"},
		{"netbsd-", "bsd", "netbsd"},
	} {
		if cpu, ok := strings.CutPrefix(arch, p.prefix); ok && isDebianCPU(cpu) {
			return archTuple{"base", p.libc, p.osName, cpu}, true
		}
	}

	return archTuple{}, false
}

// wildcardTuple maps an architecture or architecture wildcard to its tuple,
// padding a short wildcard with "any" on the left as dpkg does: "linux-any"
// is "any-any-linux-any" and "any-arm64" is "any-any-any-arm64".
func wildcardTuple(pattern string) (archTuple, bool) {
	parts := strings.SplitN(pattern, "-", 4)

	hasAny := false

	for _, p := range parts {
		if p == ArchAny {
			hasAny = true

			break
		}
	}

	if !hasAny {
		return debarchTuple(pattern)
	}

	t := archTuple{ArchAny, ArchAny, ArchAny, ArchAny}
	copy(t[len(t)-len(parts):], parts)

	return t, true
}

// ArchMatches reports whether the Debian architecture arch ("amd64", "armhf")
// is the architecture pattern names, or belongs to the wildcard it is: "any",
// "linux-any", "any-amd64", "gnu-linux-any" and so on, with the semantics of
// dpkg-architecture -i. An architecture matches itself even when it is not one
// dpkg knows.
func ArchMatches(arch, pattern string) bool {
	if arch == pattern || pattern == ArchAny {
		return true
	}

	have, ok := debarchTuple(arch)
	if !ok {
		return false
	}

	want, ok := wildcardTuple(pattern)
	if !ok {
		return false
	}

	for i := range have {
		if want[i] != have[i] && want[i] != ArchAny {
			return false
		}
	}

	return true
}

// ArchRestrictionApplies reports whether the architecture list of a relation
// ("[amd64 !i386]") selects hostArch. No restriction selects every
// architecture. The terms are read as dpkg reads them: the first positive term
// that matches selects the architecture, a negative term that matches rejects
// it, and a list of only negative terms selects what none of them matches.
// Names are compared without regard to case.
func ArchRestrictionApplies(hostArch string, terms []Restriction) bool {
	if len(terms) == 0 {
		return true
	}

	hostArch = strings.ToLower(hostArch)
	seen := false

	for _, t := range terms {
		name := strings.ToLower(t.Name)

		if t.Negated {
			if ArchMatches(hostArch, name) {
				return false
			}

			seen = true
		} else if ArchMatches(hostArch, name) {
			return true
		}
	}

	return seen
}

// ProfileRestrictionApplies reports whether the build-profile groups of a
// relation ("<!nocheck> <stage1 cross>") hold for the active profiles. The
// groups are alternatives and the terms of a group are all required; a term
// holds when its profile is active, or, negated, when it is not. No group
// holds always.
func ProfileRestrictionApplies(profiles []string, groups [][]Restriction) bool {
	if len(groups) == 0 {
		return true
	}

	for _, group := range groups {
		holds := true

		for _, t := range group {
			active := false

			for _, p := range profiles {
				if p == t.Name {
					active = true

					break
				}
			}

			if active == t.Negated {
				holds = false

				break
			}
		}

		if holds {
			return true
		}
	}

	return false
}

// AppliesTo reports whether the relation is in force for a build on hostArch
// with the given active build profiles: both its architecture restriction and
// its profile restrictions must select it. A relation without restrictions
// always applies. This is the evaluation dpkg-checkbuilddeps does.
func (r Relation) AppliesTo(hostArch string, profiles []string) bool {
	return ArchRestrictionApplies(hostArch, r.ArchRestrictions) &&
		ProfileRestrictionApplies(profiles, r.ProfileGroups)
}

// Active returns the alternatives that apply (see [Relation.AppliesTo]), in
// order, without the restrictions on them. It returns nil when none applies,
// which means the whole dependency does not.
func (a Alternatives) Active(hostArch string, profiles []string) Alternatives {
	var out Alternatives

	for _, r := range a {
		if !r.AppliesTo(hostArch, profiles) {
			continue
		}

		r.ArchRestrictions, r.ProfileGroups = nil, nil
		out = append(out, r)
	}

	return out
}

// ActiveRelations evaluates the restrictions of a parsed dependency field for
// a build on hostArch with the given build profiles: the relations that do not
// apply are dropped, and so is a dependency left without any alternative. What
// remains has no restrictions, so it is what a resolver has to satisfy.
func ActiveRelations(rels []Alternatives, hostArch string, profiles []string) []Alternatives {
	var out []Alternatives

	for _, a := range rels {
		if active := a.Active(hostArch, profiles); len(active) > 0 {
			out = append(out, active)
		}
	}

	return out
}

// TargetArch resolves the architecture qualifier of a relation. dependerArch
// is the architecture of the package that holds the relation and nativeArch
// the architecture of the system. It returns the architecture the relation
// names, and any=true for ":any", which names every architecture. A relation
// without qualifier names the architecture of its package, ":native" the one of
// the system, and an architecture qualifier itself. An architecture "all"
// depender counts as the system's.
func (r Relation) TargetArch(dependerArch, nativeArch string) (arch string, anyArch bool) {
	switch r.Arch {
	case "":
		if dependerArch == "" || dependerArch == ArchAll {
			return nativeArch, false
		}

		return dependerArch, false
	case ArchAny:
		return "", true
	case ArchNative:
		return nativeArch, false
	default:
		return r.Arch, false
	}
}
