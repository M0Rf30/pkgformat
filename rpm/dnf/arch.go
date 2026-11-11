package dnf

import "strings"

const archNoarch = "noarch"

// archCompat lists, best first, the architectures a host of the given one can
// run, noarch last. It is the table libsolv applies for the architectures rpm
// distributions ship; an architecture that is not in it only runs itself.
//
// The 32-bit libraries of a 64-bit host (i686 on x86_64) are compatible, which
// is what lets a 32-bit package that a 64-bit one needs be installed next to
// it; the best architecture is still the host's own, which is how a capability
// that both provide is resolved to the 64-bit package.
func archCompat(arch string) []string {
	var list []string

	switch arch {
	case "x86_64", "amd64":
		list = []string{"x86_64", "athlon", "i686", "i586", "i486", "i386"}
	case "i686":
		list = []string{"i686", "i586", "i486", "i386"}
	case "i586":
		list = []string{"i586", "i486", "i386"}
	case "i486":
		list = []string{"i486", "i386"}
	case "i386":
		list = []string{"i386"}
	case "athlon":
		list = []string{"athlon", "i686", "i586", "i486", "i386"}
	case "aarch64":
		list = []string{"aarch64"}
	case "armv8hl":
		list = []string{"armv8hl", "armv7hnl", "armv7hl", "armv6hl", "armv5tel"}
	case "armv7hnl":
		list = []string{"armv7hnl", "armv7hl", "armv6hl", "armv5tel"}
	case "armv7hl":
		list = []string{"armv7hl", "armv6hl", "armv5tel"}
	case "armv7l":
		list = []string{"armv7l", "armv6l", "armv5tel", "armv5l"}
	case "armv6hl":
		list = []string{"armv6hl", "armv5tel"}
	case "armv6l":
		list = []string{"armv6l", "armv5tel", "armv5l"}
	case "armv5tel":
		list = []string{"armv5tel"}
	case "ppc64le":
		list = []string{"ppc64le"}
	case "ppc64p7":
		list = []string{"ppc64p7", "ppc64", "ppc"}
	case "ppc64":
		list = []string{"ppc64", "ppc"}
	case "ppc":
		list = []string{"ppc"}
	case "s390x":
		list = []string{"s390x", "s390"}
	case "s390":
		list = []string{"s390"}
	case "sparc64v":
		list = []string{"sparc64v", "sparc64", "sparcv9v", "sparcv9", "sparcv8", "sparc"}
	case "sparc64":
		list = []string{"sparc64", "sparcv9v", "sparcv9", "sparcv8", "sparc"}
	case "ia64":
		list = []string{"ia64"}
	case "alpha":
		list = []string{"alpha"}
	case "riscv64", "loongarch64", "mips64el", "mipsel", "mips64r6el", "mipsr6el":
		list = []string{arch}
	default:
		list = []string{arch}
	}

	return append(list, archNoarch)
}

// archRanks maps each architecture a host can run to its rank, 0 being the
// best.
func archRanks(arch string) map[string]int {
	compat := archCompat(arch)
	ranks := make(map[string]int, len(compat))

	for i, a := range compat {
		if _, dup := ranks[a]; !dup {
			ranks[a] = i
		}
	}

	return ranks
}

// is32of64 reports whether a is a 32-bit architecture that coexists with the
// 64-bit host architecture host (multilib).
func isMultilibArch(host, a string) bool {
	return a != host && a != archNoarch && strings.HasPrefix(host, "x86_64") && strings.HasPrefix(a, "i")
}
