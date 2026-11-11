package adb

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/apkver"
)

// Match is the set of comparison bits of a dependency. A dependency on
// "name>=1.2" has Match [MatchGreater] | [MatchEqual].
type Match = apkver.Op

// Comparison bits.
const (
	MatchEqual    = apkver.Equal
	MatchLess     = apkver.Less
	MatchGreater  = apkver.Greater
	MatchFuzzy    = apkver.Fuzzy
	MatchConflict = apkver.Conflict

	// matchAny is the match of a dependency that accepts any version.
	matchAny = MatchEqual | MatchLess | MatchGreater
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
		sb.WriteString(op.String())
		sb.WriteString(d.Version)
	}

	return sb.String()
}

// ParseDependency parses "[!]name[op version]" where op is any run of the
// characters "<", ">", "=" and "~". It rejects names and versions apk would.
func ParseDependency(s string) (Dependency, error) {
	parts, err := apkver.Split(s)
	if err != nil {
		return Dependency{}, specErr("dependency %q: %v", s, err)
	}

	if err := checkDepName(parts.Name); err != nil {
		return Dependency{}, fmt.Errorf("%w: dependency %q", err, s)
	}

	d := Dependency{Name: parts.Name, Version: parts.Version}

	switch {
	case parts.Conflict && parts.Op == apkver.Any:
		d.Match = MatchConflict | matchAny
	case parts.Conflict:
		d.Match = MatchConflict | parts.Op
	case parts.Op != MatchEqual && parts.Op != apkver.Any:
		d.Match = parts.Op
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

// ValidVersion reports whether v is a well-formed package version.
func ValidVersion(v string) bool {
	return apkver.Valid(v)
}

// CompareVersions compares two package versions with the ordering of apk:
// it returns -1, 0 or +1. Versions that do not parse compare by the part that
// does; use [ValidVersion] first when that matters.
func CompareVersions(a, b string) int {
	return apkver.Compare(a, b)
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

	return cmp.Compare(a.Match, b.Match)
}
