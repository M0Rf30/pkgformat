package adb

import (
	"fmt"
	"strings"
)

// Match is the set of comparison bits of a dependency. A dependency on
// "name>=1.2" has Match [MatchGreater] | [MatchEqual].
type Match uint32

// Comparison bits.
const (
	MatchEqual    Match = 1
	MatchLess     Match = 2
	MatchGreater  Match = 4
	MatchFuzzy    Match = 8
	MatchConflict Match = 16

	// matchAny is the match of a dependency that accepts any version.
	matchAny = MatchEqual | MatchLess | MatchGreater
	// matchChecksum names a package by the checksum its version holds.
	matchChecksum = MatchLess | MatchGreater
)

// Dependency is one entry of a dependency list in its structured form.
type Dependency struct {
	Name    string
	Version string
	// Match holds the comparison as stored in the file. Zero means [MatchEqual].
	Match Match
}

// String formats the dependency as apk does: "name", "!name", "name>=1.2".
func (d Dependency) String() string {
	op := d.Match
	if op == 0 {
		op = MatchEqual
	}

	var sb strings.Builder

	if op&MatchConflict != 0 {
		sb.WriteByte('!')
	}

	sb.WriteString(d.Name)

	if d.Version != "" {
		sb.WriteString(matchString(op))
		sb.WriteString(d.Version)
	}

	return sb.String()
}

func matchString(op Match) string {
	switch op &^ MatchConflict {
	case MatchLess:
		return "<"
	case MatchLess | MatchEqual:
		return "<="
	case MatchLess | MatchEqual | MatchFuzzy:
		return "<~"
	case MatchEqual | MatchFuzzy, MatchFuzzy:
		return "~"
	case MatchEqual:
		return "="
	case MatchGreater | MatchEqual:
		return ">="
	case MatchGreater | MatchEqual | MatchFuzzy:
		return ">~"
	case MatchGreater:
		return ">"
	case matchChecksum:
		return "><"
	case matchAny:
		return ""
	default:
		return "?"
	}
}

// ParseDependency parses "[!]name[op version]" where op is any run of the
// characters "<", ">", "=" and "~". It rejects names and versions apk would.
func ParseDependency(s string) (Dependency, error) {
	var op Match

	spec := s
	if strings.HasPrefix(spec, "!") {
		op |= MatchConflict
		spec = spec[1:]
	}

	i := strings.IndexAny(spec, "<>=~")
	if i < 0 {
		if err := checkDepName(spec); err != nil {
			return Dependency{}, fmt.Errorf("%w: dependency %q", err, s)
		}

		if op == 0 {
			return Dependency{Name: spec}, nil
		}

		return Dependency{Name: spec, Match: op | matchAny}, nil
	}

	name, rest := spec[:i], spec[i:]

	j := 0
	for j < len(rest) && strings.IndexByte("<>=~", rest[j]) >= 0 {
		j++
	}

	if j == len(rest) {
		return Dependency{}, specErr("dependency %q has an operator but no version", s)
	}

	for _, c := range rest[:j] {
		switch c {
		case '<':
			op |= MatchLess
		case '>':
			op |= MatchGreater
		case '=':
			op |= MatchEqual
		case '~':
			op |= MatchFuzzy | MatchEqual
		}
	}

	ver := rest[j:]
	if op&^MatchConflict != matchChecksum && !ValidVersion(ver) {
		return Dependency{}, specErr("dependency %q has an invalid version", s)
	}

	if err := checkDepName(name); err != nil {
		return Dependency{}, fmt.Errorf("%w: dependency %q", err, s)
	}

	d := Dependency{Name: name, Version: ver}
	if op != MatchEqual {
		d.Match = op
	}

	return d, nil
}

func checkDepName(name string) error {
	if name == "" {
		return specErr("empty name")
	}

	for i := range len(name) {
		if !isDepNameByte(name[i]) {
			return specErr("invalid character %q in name", name[i])
		}
	}

	return nil
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// isDepNameByte reports whether c may be in a dependency name.
func isDepNameByte(c byte) bool {
	return isAlnum(c) || strings.IndexByte("+-._,:/[]", c) >= 0
}

// isTagByte reports whether c may be in a tag.
func isTagByte(c byte) bool {
	return isAlnum(c) || strings.IndexByte("+-._,:=/[]", c) >= 0
}

// checkPkgName validates a package name as apk does.
func checkPkgName(name string) error {
	if name == "" {
		return specErr("empty package name")
	}

	if !isAlnum(name[0]) {
		return specErr("package name %q must start with a letter or a digit", name)
	}

	for i := range len(name) {
		if c := name[i]; !isAlnum(c) && !strings.ContainsRune("+-._", rune(c)) {
			return specErr("invalid character %q in package name %q", c, name)
		}
	}

	return nil
}

// Version comparison, ported token for token from the Alpine version syntax:
//
//	digit{.digit}...{letter}{_suffix{number}}...{~hash}{-rN}
type verToken uint8

const (
	tokInitialDigit verToken = iota
	tokDigit
	tokLetter
	tokSuffix
	tokSuffixNo
	tokCommitHash
	tokRevisionNo
	tokEnd
	tokInvalid
)

// Suffix ranks. Those below sufNone mark a pre-release.
const (
	sufInvalid = iota
	sufAlpha
	sufBeta
	sufPre
	sufRC
	sufNone
	sufCVS
	sufSVN
	sufGit
	sufHg
	sufP
)

type verState struct {
	tok    verToken
	suffix int
	number uint64
	value  string
}

func suffixRank(s string) int {
	switch s {
	case "alpha":
		return sufAlpha
	case "beta":
		return sufBeta
	case "pre":
		return sufPre
	case "rc":
		return sufRC
	case "cvs":
		return sufCVS
	case "svn":
		return sufSVN
	case "git":
		return sufGit
	case "hg":
		return sufHg
	case "p":
		return sufP
	default:
		return sufInvalid
	}
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// parseDigits reads a run of digits; the number wraps like apk's does.
func (t *verState) parseDigits(s *string) {
	i := 0

	var n uint64

	for i < len(*s) && (*s)[i] >= '0' && (*s)[i] <= '9' {
		n = n*10 + uint64((*s)[i]-'0')
		i++
	}

	if i == 0 {
		t.tok, t.value = tokInvalid, ""

		return
	}

	t.number, t.value = n, (*s)[:i]
	*s = (*s)[i:]
}

func (t *verState) first(s *string) {
	t.tok = tokInitialDigit
	t.parseDigits(s)
}

func (t *verState) next(s *string) {
	if len(*s) == 0 {
		t.tok = tokEnd

		return
	}

	c := (*s)[0]

	switch {
	case c >= 'a' && c <= 'z':
		if t.tok > tokDigit {
			t.tok = tokInvalid

			return
		}

		t.value, t.tok = (*s)[:1], tokLetter
		*s = (*s)[1:]
	case c == '.' || c >= '0' && c <= '9':
		if c == '.' {
			if t.tok > tokDigit {
				t.tok = tokInvalid

				return
			}

			*s = (*s)[1:]
		}

		switch t.tok {
		case tokInitialDigit, tokDigit:
			t.tok = tokDigit
		case tokSuffix:
			t.tok = tokSuffixNo
		default:
			t.tok = tokInvalid

			return
		}

		t.parseDigits(s)
	case c == '_':
		if t.tok > tokSuffixNo {
			t.tok = tokInvalid

			return
		}

		rest := (*s)[1:]
		i := 0

		for i < len(rest) && rest[i] >= 'a' && rest[i] <= 'z' {
			i++
		}

		t.value, *s = rest[:i], rest[i:]

		t.suffix = suffixRank(t.value)
		if t.suffix == sufInvalid {
			t.tok = tokInvalid

			return
		}

		t.tok = tokSuffix
	case c == '~':
		if t.tok >= tokCommitHash {
			t.tok = tokInvalid

			return
		}

		rest := (*s)[1:]
		i := 0

		for i < len(rest) && isHex(rest[i]) {
			i++
		}

		if i == 0 {
			t.tok = tokInvalid

			return
		}

		t.value, *s, t.tok = rest[:i], rest[i:], tokCommitHash
	case c == '-':
		if t.tok >= tokRevisionNo || !strings.HasPrefix(*s, "-r") {
			t.tok = tokInvalid

			return
		}

		*s = (*s)[2:]
		t.tok = tokRevisionNo
		t.parseDigits(s)
	default:
		t.tok = tokInvalid
	}
}

// ValidVersion reports whether v is a well-formed package version.
func ValidVersion(v string) bool {
	var t verState

	for t.first(&v); t.tok < tokEnd; t.next(&v) {
	}

	return t.tok == tokEnd
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func (t *verState) cmp(o *verState) int {
	switch t.tok {
	case tokDigit:
		if t.value[0] != '0' && o.value[0] != '0' {
			return cmpUint(t.number, o.number)
		}
	case tokInitialDigit, tokSuffixNo, tokRevisionNo:
		return cmpUint(t.number, o.number)
	case tokLetter:
		return cmpUint(uint64(t.value[0]), uint64(o.value[0]))
	case tokSuffix:
		return cmpUint(uint64(t.suffix), uint64(o.suffix))
	}

	return strings.Compare(t.value, o.value)
}

// CompareVersions compares two package versions with the ordering of apk:
// it returns -1, 0 or +1. Versions that do not parse compare by the part that
// does; use [ValidVersion] first when that matters.
func CompareVersions(a, b string) int {
	return compareVersions(a, b, false)
}

func compareVersions(a, b string, fuzzy bool) int {
	var ta, tb verState

	ta.first(&a)
	tb.first(&b)

	for ; ta.tok == tb.tok && ta.tok < tokEnd; ta.next(&a) {
		if r := ta.cmp(&tb); r != 0 {
			return r
		}

		tb.next(&b)
	}

	switch {
	case ta.tok == tb.tok:
		return 0
	case tb.tok == tokEnd && fuzzy:
		return 0
	case ta.tok == tokSuffix && ta.suffix < sufNone:
		return -1
	case tb.tok == tokSuffix && tb.suffix < sufNone:
		return 1
	case ta.tok > tb.tok:
		return -1
	default:
		return 1
	}
}

// compareOptVersion orders versions for sorting: an absent version equals
// every other, as it does in apk.
func compareOptVersion(a, b string) int {
	if a == "" || b == "" {
		return 0
	}

	return CompareVersions(a, b)
}

// compareDeps orders dependencies by name, version and match.
func compareDeps(a, b Dependency) int {
	if r := strings.Compare(a.Name, b.Name); r != 0 {
		return r
	}

	if r := compareOptVersion(a.Version, b.Version); r != 0 {
		return r
	}

	return cmpUint(uint64(a.Match), uint64(b.Match))
}
