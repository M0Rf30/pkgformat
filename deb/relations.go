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

// Restriction is one term of an architecture restriction ("[amd64 !i386]") or
// of a build-profile restriction ("<!nocheck>"): a name, optionally negated.
type Restriction struct {
	// Name is the architecture, architecture wildcard ("linux-any",
	// "any-arm64") or build profile, as written without the "!".
	Name string
	// Negated is true when the term was written with a "!".
	Negated bool
}

// String renders the term as written.
func (t Restriction) String() string {
	if t.Negated {
		return "!" + t.Name
	}

	return t.Name
}

// Relation is one package reference of a dependency field: name, optional
// architecture qualifier, optional version constraint, and the architecture
// and build-profile restrictions of a source package's Build-Depends.
type Relation struct {
	// Name is the package name.
	Name string
	// Arch is the ":arch" qualifier ("any", "native" or an architecture), or "".
	Arch string
	// Op is the version operator: "<<", "<=", "=", ">=", ">>" or the obsolete
	// "<" and ">" (which dpkg reads as "<=" and ">="). It is "" when the
	// relation has no version constraint.
	Op string
	// Version is the version the operator compares with.
	Version string
	// ArchRestrictions is the "[amd64 !i386 linux-any]" list: the relation is
	// in force only for the host architectures it selects (see
	// [Relation.AppliesTo]). Nil when there is none.
	ArchRestrictions []Restriction
	// ProfileGroups are the "<!nocheck> <stage1 cross>" groups: the relation
	// is in force when every term of at least one group holds for the active
	// build profiles. Nil when there is none.
	ProfileGroups [][]Restriction
}

// String renders the relation in canonical control-file syntax:
// "name[:arch] (op version) [architectures] <profiles> <profiles>".
func (r Relation) String() string {
	var sb strings.Builder

	sb.WriteString(r.Name)

	if r.Arch != "" {
		sb.WriteByte(':')
		sb.WriteString(r.Arch)
	}

	if r.Op != "" {
		sb.WriteString(" (")
		sb.WriteString(r.Op)
		sb.WriteByte(' ')
		sb.WriteString(r.Version)
		sb.WriteByte(')')
	}

	if len(r.ArchRestrictions) > 0 {
		sb.WriteString(" [")
		writeRestrictions(&sb, r.ArchRestrictions)
		sb.WriteByte(']')
	}

	for _, group := range r.ProfileGroups {
		sb.WriteString(" <")
		writeRestrictions(&sb, group)
		sb.WriteByte('>')
	}

	return sb.String()
}

func writeRestrictions(sb *strings.Builder, terms []Restriction) {
	for i, t := range terms {
		if i > 0 {
			sb.WriteByte(' ')
		}

		sb.WriteString(t.String())
	}
}

// Satisfied reports whether version meets the constraint of the relation. A
// relation without an operator is met by any version. The obsolete operators
// "<" and ">" mean "<=" and ">=", as they do for dpkg. An unknown operator is
// met by no version.
func (r Relation) Satisfied(version string) bool {
	if r.Op == "" {
		return true
	}

	c := CompareVersions(version, r.Version)

	switch r.Op {
	case "<<":
		return c < 0
	case "<=", "<":
		return c <= 0
	case "=":
		return c == 0
	case ">=", ">":
		return c >= 0
	case ">>":
		return c > 0
	}

	return false
}

// Alternatives is a group of relations separated by "|": any one of them
// satisfies the dependency.
type Alternatives []Relation

// String renders the group with " | " between the relations.
func (a Alternatives) String() string {
	parts := make([]string, len(a))
	for i, r := range a {
		parts[i] = r.String()
	}

	return strings.Join(parts, " | ")
}

// FormatRelations renders a dependency field the way [ParseRelations] reads
// it: entries separated by ", ", alternatives by " | ".
func FormatRelations(rels []Alternatives) string {
	parts := make([]string, len(rels))
	for i, a := range rels {
		parts[i] = a.String()
	}

	return strings.Join(parts, ", ")
}

// ParseRelations parses a dependency field (Depends, Pre-Depends, Conflicts,
// Provides, Build-Depends, ...) into its comma-separated entries, each a list
// of alternatives. Architecture restrictions ("[amd64 !i386]") and build
// profile restrictions ("<!nocheck> <stage1 cross>") are kept on the relation;
// [Relation.AppliesTo] and [ActiveRelations] evaluate them. A malformed entry
// fails with ErrInvalidControlFormat.
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

// parseRelation parses "name[:arch] [(op version)] [[archs]] [<profiles>...]".
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

	// What is left may only be the architecture restriction, then the build
	// profile restrictions.
	if strings.HasPrefix(rest, "[") {
		inner, after, ok := strings.Cut(rest[1:], "]")
		if !ok {
			return Relation{}, fmt.Errorf("%w: unterminated architecture restriction in %q", ErrInvalidControlFormat, s)
		}

		terms, ok := parseRestrictions(inner)
		if !ok {
			return Relation{}, fmt.Errorf("%w: architecture restriction in %q", ErrInvalidControlFormat, s)
		}

		rel.ArchRestrictions = terms
		rest = strings.TrimSpace(after)
	}

	for strings.HasPrefix(rest, "<") {
		inner, after, ok := strings.Cut(rest[1:], ">")
		if !ok {
			return Relation{}, fmt.Errorf("%w: unterminated build profile restriction in %q", ErrInvalidControlFormat, s)
		}

		terms, ok := parseRestrictions(inner)
		if !ok {
			return Relation{}, fmt.Errorf("%w: build profile restriction in %q", ErrInvalidControlFormat, s)
		}

		rel.ProfileGroups = append(rel.ProfileGroups, terms)
		rest = strings.TrimSpace(after)
	}

	if rest != "" {
		return Relation{}, fmt.Errorf("%w: trailing text in %q", ErrInvalidControlFormat, s)
	}

	return rel, nil
}

// parseRestrictions splits the inside of "[...]" or "<...>" into terms. It
// fails for an empty list and for a term that is empty or has characters no
// architecture or profile name has.
func parseRestrictions(inner string) ([]Restriction, bool) {
	words := strings.Fields(inner)
	if len(words) == 0 {
		return nil, false
	}

	terms := make([]Restriction, len(words))

	for i, w := range words {
		neg := strings.HasPrefix(w, "!")
		w = strings.TrimPrefix(w, "!")

		if w == "" || strings.ContainsAny(w, "!<>[](),|:=") {
			return nil, false
		}

		terms[i] = Restriction{Name: w, Negated: neg}
	}

	return terms, true
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
