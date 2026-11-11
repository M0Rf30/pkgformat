package apkver

import (
	"errors"
	"strings"
)

// Op is the comparison of a versioned dependency, a set of the results a
// version comparison may have. The zero value, [Any], is a dependency without
// a version.
type Op uint32

// The bits of an Op.
const (
	// Any matches every version.
	Any Op = 0
	// Equal accepts a version equal to the dependency's.
	Equal Op = 1
	// Less accepts an older version.
	Less Op = 2
	// Greater accepts a newer version.
	Greater Op = 4
	// Fuzzy, together with [Equal] ("~"), accepts a version that starts with
	// all the components of the dependency's: "foo~1.2" is met by 1.2, 1.2.9
	// and 1.2.9-r3 but not by 1.3.
	Fuzzy Op = 8
	// Conflict is the "!" prefix. It is a bit of the Op only where a format
	// stores the two together; [Op.String] and [Op.Satisfied] ignore it.
	Conflict Op = 16
	// Checksum is "><": the version is not a version but the checksum of one
	// package, as "apk add foo><Q1..." pins it.
	Checksum = Less | Greater

	// everything is what the three result bits make together: no constraint.
	everything = Equal | Less | Greater
)

// opStrings are the spellings of the operators, indexed by their bits.
var opStrings = map[Op]string{
	Any:                      "",
	Equal:                    "=",
	Less:                     "<",
	Less | Equal:             "<=",
	Greater:                  ">",
	Greater | Equal:          ">=",
	Equal | Fuzzy:            "~",
	Fuzzy:                    "~",
	Less | Equal | Fuzzy:     "<~",
	Greater | Equal | Fuzzy:  ">~",
	Checksum:                 "><",
	everything:               "",
	Checksum | Equal | Fuzzy: "",
}

// String returns the operator as written in a dependency: "", "=", "<", "<=",
// ">", ">=", "~", "<~", ">~" or "><"; "?" for a combination that has no
// spelling.
func (o Op) String() string {
	if s, ok := opStrings[o&^Conflict]; ok {
		return s
	}

	return "?"
}

// ParseOp converts operator characters to bits: every '<', '>' and '=' sets
// its bit and '~' sets the fuzzy and equal bits. Other characters are ignored.
func ParseOp(chars string) Op {
	var o Op

	for i := range len(chars) {
		switch chars[i] {
		case '<':
			o |= Less
		case '>':
			o |= Greater
		case '=':
			o |= Equal
		case '~':
			o |= Fuzzy | Equal
		}
	}

	return o
}

// Satisfied reports whether a provider of the version have meets the
// constraint of o against want. The [Conflict] bit is not applied. An empty
// have stands for a provider that declares no version ("provides: foo"),
// which meets any constraint, as it does in apk.
func (o Op) Satisfied(have, want string) bool {
	o &^= Conflict

	if o == Any || have == "" {
		return true
	}

	if o == Checksum {
		return have == want
	}

	r := compare(have, want, o&Fuzzy != 0)

	var bit Op

	switch {
	case r < 0:
		bit = Less
	case r > 0:
		bit = Greater
	default:
		bit = Equal
	}

	return o&bit != 0
}

// Errors of [Split].
var (
	// ErrNoVersion is returned for an operator without a version.
	ErrNoVersion = errors.New("operator without a version")
	// ErrBadVersion is returned for a version that is not valid.
	ErrBadVersion = errors.New("invalid version")
)

// Spec is a dependency cut into its parts, before the name is checked.
type Spec struct {
	// Name is the text before the operator, without the "!". It may be empty
	// or hold characters a format does not allow, and a tag ("name@tag").
	Name string
	// Conflict is the "!" prefix.
	Conflict bool
	// Op and Version are the constraint: [Any] and "" when there is none, or
	// when the operator accepts every result.
	Op      Op
	Version string
}

// Split cuts "[!]name[op version]" into its parts. The name ends at the first
// of '<', '>', '=' and '~', and the operator is the run of those characters. A
// version must be valid, except after "><", where it is a checksum.
func Split(spec string) (Spec, error) {
	var s Spec

	rest, conflict := strings.CutPrefix(spec, "!")
	s.Conflict = conflict
	s.Name = rest

	i := strings.IndexAny(rest, "<>=~")
	if i < 0 {
		return s, nil
	}

	s.Name, rest = rest[:i], rest[i:]

	n := 0
	for n < len(rest) && strings.IndexByte("<>=~", rest[n]) >= 0 {
		n++
	}

	op, ver := ParseOp(rest[:n]), rest[n:]
	if ver == "" {
		return Spec{}, ErrNoVersion
	}

	if op&everything == everything {
		// Every result is accepted: the dependency has no constraint.
		return s, nil
	}

	if op != Checksum && !Valid(ver) {
		return Spec{}, ErrBadVersion
	}

	s.Op, s.Version = op, ver

	return s, nil
}
