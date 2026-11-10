package deb

import (
	"fmt"
	"strings"
	"unicode"
)

// maxRelations bounds the number of comma-separated entries of one dependency
// field, so a hostile Depends line cannot make the parser allocate without
// limit.
const maxRelations = 1 << 16

// Relation is one package reference of a dependency field: name, optional
// architecture qualifier and optional version constraint.
type Relation struct {
	// Name is the package name.
	Name string
	// Arch is the ":arch" qualifier ("any", "native" or an architecture), or "".
	Arch string
	// Op is the version operator: "<<", "<=", "=", ">=", ">>" or the obsolete
	// "<" and ">". It is "" when the relation has no version constraint.
	Op string
	// Version is the version the operator compares with.
	Version string
}

// String renders the relation the way a control file spells it.
func (r Relation) String() string {
	name := r.Name
	if r.Arch != "" {
		name += ":" + r.Arch
	}

	if r.Op == "" {
		return name
	}

	return fmt.Sprintf("%s (%s %s)", name, r.Op, r.Version)
}

// Satisfied reports whether version meets the constraint of the relation. A
// relation without an operator is met by any version.
func (r Relation) Satisfied(version string) bool {
	if r.Op == "" {
		return true
	}

	c := CompareVersions(version, r.Version)

	switch r.Op {
	case "<<", "<":
		return c < 0
	case "<=":
		return c <= 0
	case "=":
		return c == 0
	case ">=":
		return c >= 0
	case ">>", ">":
		return c > 0
	}

	return false
}

// Alternatives is a group of relations separated by "|": any one of them
// satisfies the dependency.
type Alternatives []Relation

// ParseRelations parses a dependency field (Depends, Pre-Depends, Conflicts,
// Provides, ...) into its comma-separated entries, each a list of
// alternatives. Architecture restrictions ("[amd64]") and build profiles
// ("<!nocheck>") are accepted and dropped. A malformed entry fails with
// ErrInvalidControlFormat.
func ParseRelations(field string) ([]Alternatives, error) {
	var out []Alternatives

	for entry := range strings.SplitSeq(field, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if len(out) >= maxRelations {
			return nil, fmt.Errorf("%w: more than %d relations", ErrTooLarge, maxRelations)
		}

		var alts Alternatives

		for alt := range strings.SplitSeq(entry, "|") {
			rel, err := parseRelation(strings.TrimSpace(alt))
			if err != nil {
				return nil, err
			}

			alts = append(alts, rel)
		}

		out = append(out, alts)
	}

	return out, nil
}

// parseRelation parses "name[:arch] [(op version)] [[archs]] [<profiles>]".
func parseRelation(s string) (Relation, error) {
	var rel Relation

	name := s

	if i := strings.IndexFunc(s, func(r rune) bool { return r == '(' || r == '[' || unicode.IsSpace(r) }); i >= 0 {
		name = s[:i]
	}

	rest := strings.TrimSpace(s[len(name):])

	rel.Name, rel.Arch, _ = strings.Cut(name, ":")
	if rel.Name == "" || strings.ContainsAny(rel.Name, ",|()[]<>=") {
		return Relation{}, fmt.Errorf("%w: relation %q", ErrInvalidControlFormat, s)
	}

	if strings.HasPrefix(rest, "(") {
		inner, after, ok := strings.Cut(rest[1:], ")")
		if !ok {
			return Relation{}, fmt.Errorf("%w: unterminated version in %q", ErrInvalidControlFormat, s)
		}

		op, ver := splitConstraint(strings.TrimSpace(inner))
		if op == "" || ver == "" {
			return Relation{}, fmt.Errorf("%w: version constraint in %q", ErrInvalidControlFormat, s)
		}

		rel.Op, rel.Version = op, ver
		rest = strings.TrimSpace(after)
	}

	// What is left may only be architecture restrictions and build profiles.
	for rest != "" {
		var closer byte

		switch rest[0] {
		case '[':
			closer = ']'
		case '<':
			closer = '>'
		default:
			return Relation{}, fmt.Errorf("%w: trailing text in %q", ErrInvalidControlFormat, s)
		}

		end := strings.IndexByte(rest, closer)
		if end < 0 {
			return Relation{}, fmt.Errorf("%w: unterminated restriction in %q", ErrInvalidControlFormat, s)
		}

		rest = strings.TrimSpace(rest[end+1:])
	}

	return rel, nil
}

// splitConstraint splits "<op> <version>" or "<op><version>".
func splitConstraint(s string) (op, version string) {
	i := 0
	for i < len(s) && strings.IndexByte("<>=", s[i]) >= 0 {
		i++
	}

	op = s[:i]

	switch op {
	case "<<", "<=", "=", ">=", ">>", "<", ">":
	default:
		return "", ""
	}

	return op, strings.TrimSpace(s[i:])
}

// DependencyNames returns the package names of a dependency field the way a
// resolver that ignores versions needs them: the first alternative of every
// entry, without version constraint or architecture qualifier.
func DependencyNames(field string) []string {
	if field == "" {
		return nil
	}

	out := make([]string, 0, 4)

	for entry := range strings.SplitSeq(field, ",") {
		entry, _, _ = strings.Cut(entry, "|")
		entry, _, _ = strings.Cut(entry, "(")
		entry, _, _ = strings.Cut(entry, ":")
		entry, _, _ = strings.Cut(strings.TrimSpace(entry), " ")

		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, entry)
		}
	}

	return out
}

// NormalizeDependency rewrites a dependency written the way a PKGBUILD does
// ("gcc>=11", "libfoo>2.0") into control-file syntax ("gcc (>= 11)",
// "libfoo (>> 2.0)"). The obsolete bare ">" and "<" are spelled ">>" and "<<",
// as dpkg means "<=" and ">=" by them. A dependency that already has the
// "name (op version)" form, or has no operator, is returned unchanged.
func NormalizeDependency(dep string) string {
	if strings.HasPrefix(dep, "(") || strings.Contains(dep, " (") {
		return dep
	}

	i := strings.IndexAny(dep, "<>=")
	if i < 0 {
		return dep
	}

	j := i
	for j < len(dep) && strings.IndexByte("<>=", dep[j]) >= 0 {
		j++
	}

	name, op, version := dep[:i], dep[i:j], dep[j:]

	switch op {
	case ">":
		op = ">>"
	case "<":
		op = "<<"
	case "<=", ">=", "=":
	default:
		return dep
	}

	if strings.ContainsAny(version, "<>=") {
		return dep
	}

	return fmt.Sprintf("%s (%s %s)", name, op, version)
}
