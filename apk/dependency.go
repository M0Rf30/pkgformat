package apk

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidDependency is wrapped by the errors of [ParseDependency].
var ErrInvalidDependency = errors.New("apk: invalid dependency")

// Op is the comparison of a versioned dependency, a set of the results a
// version comparison may have. The zero value, [OpAny], is a dependency
// without a version.
type Op uint8

// The comparison bits of an Op. The textual operators are what a depend,
// provides or world entry uses: "=" is [OpEqual], "<" [OpLess], "<=" the two
// together, ">" [OpGreater], ">=", and "~" the fuzzy equality.
const (
	// OpAny matches every version.
	OpAny Op = 0
	// OpEqual accepts a version equal to the dependency's.
	OpEqual Op = 1
	// OpLess accepts an older version.
	OpLess Op = 2
	// OpGreater accepts a newer version.
	OpGreater Op = 4
	// OpFuzzy, always together with [OpEqual] ("~"), accepts a version that
	// starts with all the components of the dependency's: "foo~1.2" is met by
	// 1.2, 1.2.9 and 1.2.9-r3 but not by 1.3.
	OpFuzzy Op = 8
	// OpChecksum is "><": the version is not a version but the checksum of one
	// package, as "apk add foo><Q1..." pins it.
	OpChecksum = OpLess | OpGreater
)

// opSets are the spellings of the operators, indexed by their bits.
var opStrings = map[Op]string{
	OpAny:                          "",
	OpEqual:                        "=",
	OpLess:                         "<",
	OpLess | OpEqual:               "<=",
	OpGreater:                      ">",
	OpGreater | OpEqual:            ">=",
	OpEqual | OpFuzzy:              "~",
	OpFuzzy:                        "~",
	OpLess | OpEqual | OpFuzzy:     "<~",
	OpGreater | OpEqual | OpFuzzy:  ">~",
	OpChecksum:                     "><",
	OpLess | OpGreater | OpEqual:   "",
	OpChecksum | OpEqual | OpFuzzy: "",
}

// String returns the operator as written in a dependency: "", "=", "<", "<=",
// ">", ">=", "~", "<~", ">~" or "><".
func (o Op) String() string {
	if s, ok := opStrings[o]; ok {
		return s
	}

	return "?"
}

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

	rest, conflict := strings.CutPrefix(spec, "!")
	d.Conflict = conflict

	name, rest := rest, ""
	if i := strings.IndexAny(name, "<>=~"); i >= 0 {
		name, rest = name[:i], name[i:]
	}

	if rest != "" {
		n := 0
		for n < len(rest) && strings.IndexByte("<>=~", rest[n]) >= 0 {
			n++
		}

		op, ver := opFromChars(rest[:n]), rest[n:]
		if op == 0 || ver == "" {
			return Dependency{}, fmt.Errorf("%w: %q has no version", ErrInvalidDependency, short(spec))
		}

		if op&(OpLess|OpEqual|OpGreater) == OpLess|OpEqual|OpGreater {
			// Every result is accepted: the dependency has no constraint.
			op, ver = OpAny, ""
		}

		d.Op, d.Version = op, ver
	}

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

	if d.Op != OpAny && d.Op != OpChecksum && !ValidVersion(d.Version) {
		return Dependency{}, fmt.Errorf("%w: %q has an invalid version", ErrInvalidDependency, short(spec))
	}

	return d, nil
}

// opFromChars converts the operator characters to bits: every '<', '>' and
// '=' sets its bit and '~' sets the fuzzy and equal bits.
func opFromChars(chars string) Op {
	var o Op

	for i := range len(chars) {
		switch chars[i] {
		case '<':
			o |= OpLess
		case '>':
			o |= OpGreater
		case '=':
			o |= OpEqual
		case '~':
			o |= OpFuzzy | OpEqual
		}
	}

	return o
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
	if d.Op == OpAny || have == "" {
		return true
	}

	if d.Op == OpChecksum {
		return have == d.Version
	}

	r := compareVersions(have, d.Version, d.Op&OpFuzzy != 0)

	var bit Op

	switch {
	case r < 0:
		bit = OpLess
	case r > 0:
		bit = OpGreater
	default:
		bit = OpEqual
	}

	return d.Op&bit != 0
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
