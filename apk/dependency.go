package apk

import (
	"errors"
	"fmt"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/apkver"
)

// ErrInvalidDependency is wrapped by the errors of [ParseDependency].
var ErrInvalidDependency = errors.New("apk: invalid dependency")

// Op is the comparison of a versioned dependency, a set of the results a
// version comparison may have. The zero value, [OpAny], is a dependency
// without a version.
type Op = apkver.Op

// The comparison bits of an Op. The textual operators are what a depend,
// provides or world entry uses: "=" is [OpEqual], "<" [OpLess], "<=" the two
// together, ">" [OpGreater], ">=", and "~" the fuzzy equality.
const (
	// OpAny matches every version.
	OpAny = apkver.Any
	// OpEqual accepts a version equal to the dependency's.
	OpEqual = apkver.Equal
	// OpLess accepts an older version.
	OpLess = apkver.Less
	// OpGreater accepts a newer version.
	OpGreater = apkver.Greater
	// OpFuzzy, always together with [OpEqual] ("~"), accepts a version that
	// starts with all the components of the dependency's: "foo~1.2" is met by
	// 1.2, 1.2.9 and 1.2.9-r3 but not by 1.3.
	OpFuzzy = apkver.Fuzzy
	// OpChecksum is "><": the version is not a version but the checksum of one
	// package, as "apk add foo><Q1..." pins it.
	OpChecksum = apkver.Checksum
)

// Dependency is one entry of a depend, provides, replaces, install_if or world
// list: [!]name[@tag][op version].
type Dependency struct {
	// Name is a package name or a capability such as "so:libc.musl-x86_64.so.1"
	// or "cmd:sh".
	Name string
	// Conflict is the "!" prefix: no package providing Name (at a version
	// matching Op and Version) may be installed.
	Conflict bool
	// Tag is the repository tag of "name@tag": the dependency may be met from
	// the repositories of that tag. Empty means untagged repositories only.
	Tag string
	// Op and Version are the version constraint. Version is empty for
	// [OpAny]; for [OpChecksum] it is the Q1 checksum of the package.
	Op      Op
	Version string
}

// ParseDependency parses one dependency of the forms apk accepts:
//
//	name   !name   name@tag   name=1.2   name>=1.2-r1   name<2   name~1.2   name><Q1...
//
// The name runs up to the first of '<', '>', '=' and '~'. A version must be
// valid (see [ValidVersion]), except for a checksum. The text must be a single
// entry, without white space.
func ParseDependency(spec string) (Dependency, error) {
	var d Dependency

	if spec == "" || strings.ContainsAny(spec, " \t\n\r") {
		return d, fmt.Errorf("%w: %q", ErrInvalidDependency, short(spec))
	}

	parts, err := apkver.Split(spec)
	if err != nil {
		return Dependency{}, fmt.Errorf("%w: %q: %w", ErrInvalidDependency, short(spec), err)
	}

	d.Conflict, d.Op, d.Version = parts.Conflict, parts.Op, parts.Version

	name := parts.Name
	if base, tag, ok := strings.Cut(name, "@"); ok {
		if tag == "" || base == "" || strings.Contains(tag, "@") {
			return Dependency{}, fmt.Errorf("%w: %q has a malformed tag", ErrInvalidDependency, short(spec))
		}

		name, d.Tag = base, tag
	}

	if name == "" || !cleanText(name) {
		return Dependency{}, fmt.Errorf("%w: %q has no name", ErrInvalidDependency, short(spec))
	}

	d.Name = name

	return d, nil
}

// String returns the dependency as it is written: "!name@tag>=1.2".
func (d Dependency) String() string {
	var b strings.Builder

	if d.Conflict {
		b.WriteByte('!')
	}

	b.WriteString(d.Name)

	if d.Tag != "" {
		b.WriteString("@" + d.Tag)
	}

	if d.Op != OpAny {
		b.WriteString(d.Op.String() + d.Version)
	}

	return b.String()
}

// MatchVersion reports whether a provider of the version have meets the
// version constraint of d. The Conflict flag is not applied: "!foo<2" and
// "foo<2" give the same answer here. An empty have stands for a provider
// that declares no version ("provides: foo"), which meets any constraint, as
// it does in apk.
func (d Dependency) MatchVersion(have string) bool {
	return d.Op.Satisfied(have, d.Version)
}

// MatchesPackage reports whether p, a package of an index or the installed
// database, meets d the way apk says a dependency on its own name does: its
// name is d.Name and its version meets the constraint, or one of its provides
// entries names d.Name with a matching version. A conflict is met by the
// packages that do not match.
func (d Dependency) MatchesPackage(p *Package) bool {
	m := d.providedBy(p)

	return m != d.Conflict
}

// providedBy reports whether p provides d, before the Conflict flag.
func (d Dependency) providedBy(p *Package) bool {
	if d.Op == OpChecksum && p.Name == d.Name {
		return p.Checksum == d.Version
	}

	if p.Name == d.Name {
		return d.MatchVersion(p.Version)
	}

	for _, s := range p.Provides {
		pd, err := ParseDependency(s)
		if err != nil || pd.Name != d.Name {
			continue
		}

		return d.MatchVersion(providedVersion(pd))
	}

	return false
}

// providedVersion returns the version a provides entry declares: its
// version for "name=1.2" and "" otherwise.
func providedVersion(pd Dependency) string {
	if pd.Op == OpEqual {
		return pd.Version
	}

	return ""
}
