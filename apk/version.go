package apk

import (
	"math/bits"
	"strings"
)

// An Alpine version is a number, any number of ".number" components, an
// optional lowercase letter, any number of "_suffix[number]" groups, an
// optional "~hexdigits" commit hash and an optional "-rN" release:
//
//	1.2.3b_rc2_p4~9fceb02-r5
//
// CompareVersions orders such versions as apk does, and [ValidVersion] tells
// whether a string is one. A version is read as a sequence of tokens, each of
// a kind that may only follow some other kinds; the ordering of the kinds
// themselves decides how versions of different shapes compare ("1.0" is
// older than "1.0.1" and than "1.0a" but newer than "1.0_rc1").

// tokenKind is the kind of a version token. The order is significant: it is
// the order in which the kinds may appear in a version and the order in which
// a longer version compares to a shorter one.
type tokenKind uint8

const (
	kindLead     tokenKind = iota // the first number
	kindNumber                    // ".number" after another number
	kindLetter                    // one lowercase letter
	kindSuffix                    // "_alpha", "_rc", "_p", ...
	kindSuffixNo                  // the number that follows a suffix
	kindHash                      // "~" and hexadecimal digits
	kindRelease                   // "-r" and a number
	kindEnd                       // the end of a valid version
	kindInvalid                   // where a version stops being valid
)

// suffixRank orders the version suffixes; "none" (rank noSuffix) is what a
// version without a suffix is compared as, so the ranks below it are the
// pre-release suffixes.
const (
	suffixAlpha = iota + 1
	suffixBeta
	suffixPre
	suffixRC
	noSuffix
	suffixCVS
	suffixSVN
	suffixGit
	suffixHg
	suffixP
)

// suffixRanks maps the suffix names to their rank.
var suffixRanks = map[string]int{
	"alpha": suffixAlpha, "beta": suffixBeta, "pre": suffixPre, "rc": suffixRC,
	"cvs": suffixCVS, "svn": suffixSVN, "git": suffixGit, "hg": suffixHg, "p": suffixP,
}

// versionToken is one token of a version. text is the digits of a number
// token, the hexadecimal digits of a hash or the letter; num is the value of a
// number token and rank the rank of a suffix.
type versionToken struct {
	kind tokenKind
	text string
	num  uint64
	rank int
}

// tokenize splits v into tokens. The last token has the kind kindEnd for a
// valid version, and kindInvalid at the first place where v stops being one.
func tokenize(v string) []versionToken {
	toks := make([]versionToken, 0, 8)

	var (
		pos  int
		prev = kindLead
	)

	// The first token is a number without a dot.
	tok, n, ok := lexNumber(v, kindLead)
	if !ok {
		return append(toks, versionToken{kind: kindInvalid})
	}

	toks, pos = append(toks, tok), n

	for pos < len(v) {
		tok, n, ok = lexToken(v[pos:], prev)
		if !ok {
			return append(toks, versionToken{kind: kindInvalid})
		}

		toks, pos, prev = append(toks, tok), pos+n, tok.kind
	}

	return append(toks, versionToken{kind: kindEnd})
}

// lexNumber reads the decimal digits at the start of s as a token of kind.
// It fails when there are none or when the number does not fit 64 bits.
func lexNumber(s string, kind tokenKind) (versionToken, int, bool) {
	n := 0
	for n < len(s) && isDigit(s[n]) {
		n++
	}

	if n == 0 {
		return versionToken{}, 0, false
	}

	var num uint64

	for i := range n {
		hi, lo := bits.Mul64(num, 10)
		sum, carry := bits.Add64(lo, uint64(s[i]-'0'), 0)

		if hi != 0 || carry != 0 {
			return versionToken{}, 0, false
		}

		num = sum
	}

	return versionToken{kind: kind, text: s[:n], num: num}, n, true
}

// lexToken reads the token at the start of s, which follows a token of kind
// prev, and returns it with the number of bytes it takes.
func lexToken(s string, prev tokenKind) (versionToken, int, bool) {
	switch c := s[0]; {
	case c >= 'a' && c <= 'z':
		if prev > kindNumber {
			return versionToken{}, 0, false
		}

		return versionToken{kind: kindLetter, text: s[:1]}, 1, true
	case c == '.':
		if prev > kindNumber {
			return versionToken{}, 0, false
		}

		tok, n, ok := lexNumber(s[1:], kindNumber)

		return tok, n + 1, ok
	case isDigit(c):
		// A number directly after a suffix belongs to it; after a number it
		// would have needed a dot, so the digits are part of that number and
		// cannot start a token.
		if prev != kindSuffix {
			return versionToken{}, 0, false
		}

		return lexNumber(s, kindSuffixNo)
	case c == '_':
		return lexSuffix(s, prev)
	case c == '~':
		if prev >= kindHash {
			return versionToken{}, 0, false
		}

		n := 1
		for n < len(s) && isHex(s[n]) {
			n++
		}

		if n == 1 {
			return versionToken{}, 0, false
		}

		return versionToken{kind: kindHash, text: s[1:n]}, n, true
	case c == '-':
		if prev >= kindRelease || !strings.HasPrefix(s, "-r") {
			return versionToken{}, 0, false
		}

		tok, n, ok := lexNumber(s[2:], kindRelease)

		return tok, n + 2, ok
	}

	return versionToken{}, 0, false
}

// lexSuffix reads "_name" at the start of s: the name is the run of lowercase
// letters, and must be one of the known suffixes.
func lexSuffix(s string, prev tokenKind) (versionToken, int, bool) {
	if prev > kindSuffixNo {
		return versionToken{}, 0, false
	}

	n := 1
	for n < len(s) && s[n] >= 'a' && s[n] <= 'z' {
		n++
	}

	rank, ok := suffixRanks[s[1:n]]
	if !ok {
		return versionToken{}, 0, false
	}

	return versionToken{kind: kindSuffix, text: s[1:n], rank: rank}, n, true
}

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// ValidVersion reports whether v is a version in the syntax apk accepts:
// digits, ".digits", a letter, "_suffix[digits]" groups, "~hash" and "-rN", in
// that order. "1.2.3-r0", "2.0_rc1" and "20240101_git~1a2b3c-r2" are valid;
// "", "1.", "1.0-1" and "1.0_foo" are not.
func ValidVersion(v string) bool {
	toks := tokenize(v)

	return toks[len(toks)-1].kind == kindEnd
}

// compareToken orders two tokens of the same kind.
func compareToken(a, b *versionToken) int {
	switch a.kind {
	case kindNumber:
		// A leading zero makes both components compare as text, so that
		// "1.01" is older than "1.1" the way a version with a date-like
		// component expects.
		if a.text[0] == '0' || b.text[0] == '0' {
			return strings.Compare(a.text, b.text)
		}

		return cmpUint(a.num, b.num)
	case kindLead, kindSuffixNo, kindRelease:
		return cmpUint(a.num, b.num)
	case kindSuffix:
		return cmpUint(uint64(a.rank), uint64(b.rank))
	default: // letters and hashes compare as text
		return strings.Compare(a.text, b.text)
	}
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}

	return 0
}

// CompareVersions compares two versions as apk does and returns -1, 0 or +1.
// Both versions are expected to be valid; for a string that is not (see
// [ValidVersion]) the result is defined but not meaningful.
//
// The release ("-r1") counts: "1.0-r1" is older than "1.0-r2", and "1.0" is
// older than "1.0-r1". Pre-release suffixes (_alpha, _beta, _pre, _rc) are
// older than the version without them and post-release ones (_cvs, _svn, _git,
// _hg, _p) are newer.
func CompareVersions(a, b string) int {
	return compareVersions(a, b, false)
}

// compareVersions is CompareVersions; with fuzzy, a version that has more
// components than b but starts with all of them is equal to b.
func compareVersions(a, b string, fuzzy bool) int {
	ta, tb := tokenize(a), tokenize(b)

	i := 0

	for ; i < len(ta) && i < len(tb); i++ {
		x, y := &ta[i], &tb[i]
		if x.kind != y.kind {
			break
		}

		if x.kind >= kindEnd {
			// Both versions end, or become invalid, in the same place.
			return 0
		}

		if r := compareToken(x, y); r != 0 {
			return r
		}
	}

	// The versions agree up to here. Whichever has more left is newer,
	// unless what is left is a pre-release suffix.
	x, y := &ta[i], &tb[i]

	switch {
	case y.kind == kindEnd && fuzzy:
		return 0
	case x.kind == kindSuffix && x.rank < noSuffix:
		return -1
	case y.kind == kindSuffix && y.rank < noSuffix:
		return 1
	case x.kind > y.kind:
		return -1
	case y.kind > x.kind:
		return 1
	}

	return 0
}
