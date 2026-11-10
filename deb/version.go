package deb

import "strings"

// CompareVersions compares two Debian version strings the way dpkg does (see
// deb-version(7)) and returns -1, 0 or +1. The versions are split into
// [epoch:]upstream[-revision], then upstream and revision are compared by
// alternating non-digit and digit chunks. In a non-digit chunk '~' sorts before
// everything, even the end of the chunk, then letters, then other characters.
// An empty version sorts lowest.
func CompareVersions(a, b string) int {
	if a == b {
		return 0
	}

	if a == "" {
		return -1
	}

	if b == "" {
		return 1
	}

	epochA, upstreamA, revA := splitVersion(a)
	epochB, upstreamB, revB := splitVersion(b)

	if c := compareDigits(epochA, epochB); c != 0 {
		return c
	}

	if c := comparePart(upstreamA, upstreamB); c != 0 {
		return c
	}

	return comparePart(revA, revB)
}

// splitVersion breaks "[epoch:]upstream[-revision]" into its parts. A missing
// epoch is "0" and a missing revision is "". An epoch that is not all digits
// is not an epoch: the colon stays in the upstream version.
func splitVersion(v string) (epoch, upstream, revision string) {
	epoch = "0"

	if i := strings.IndexByte(v, ':'); i >= 0 && isDigits(v[:i]) {
		epoch = v[:i]
		v = v[i+1:]
	}

	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}

	return epoch, v, ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}

	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}

// comparePart compares an upstream version or a revision.
func comparePart(a, b string) int {
	for a != "" || b != "" {
		na, ra := splitNonDigit(a)
		nb, rb := splitNonDigit(b)

		if c := compareNonDigit(na, nb); c != 0 {
			return c
		}

		da, ra2 := splitDigit(ra)
		db, rb2 := splitDigit(rb)

		if c := compareDigits(da, db); c != 0 {
			return c
		}

		a, b = ra2, rb2
	}

	return 0
}

// splitNonDigit returns the leading run of non-digits of s and the rest.
func splitNonDigit(s string) (prefix, rest string) {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return s[:i], s[i:]
		}
	}

	return s, ""
}

// splitDigit returns the leading run of digits of s and the rest.
func splitDigit(s string) (prefix, rest string) {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return s[:i], s[i:]
		}
	}

	return s, ""
}

// compareNonDigit compares two non-digit chunks character by character.
func compareNonDigit(a, b string) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var ca, cb byte

		if i < len(a) {
			ca = a[i]
		}

		if i < len(b) {
			cb = b[i]
		}

		if oa, ob := charOrder(ca), charOrder(cb); oa != ob {
			return cmpInt(oa, ob)
		}
	}

	return 0
}

// charOrder is the sort key of a byte in a non-digit chunk: '~' < end of
// chunk < letters < everything else (by byte value within each class).
func charOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c == 0:
		return 0
	case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
		return int(c)
	default:
		return int(c) + 256
	}
}

// compareDigits compares two digit strings numerically, whatever their length.
func compareDigits(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")

	if len(a) != len(b) {
		return cmpInt(len(a), len(b))
	}

	return strings.Compare(a, b)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// ValidVersion reports whether v is a version dpkg accepts: an optional
// numeric epoch followed by a colon, then letters, digits and . + - ~ :. It
// does not require the upstream version to start with a digit, which dpkg only
// warns about.
func ValidVersion(v string) bool {
	if v == "" || len(v) > 256 {
		return false
	}

	rest := v

	if epoch, after, found := strings.Cut(v, ":"); found {
		if !isDigits(epoch) {
			return false
		}

		rest = after
	}

	if rest == "" {
		return false
	}

	for i := 0; i < len(rest); i++ {
		c := rest[i]

		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c == '.', c == '+', c == '-', c == '~', c == ':':
		default:
			return false
		}
	}

	return true
}

// StripEpoch returns v without its numeric epoch ("1:2.0-1" is "2.0-1"), the
// form a package file name carries.
func StripEpoch(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 && isDigits(v[:i]) {
		return v[i+1:]
	}

	return v
}
