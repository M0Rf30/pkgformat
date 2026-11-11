package pack

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// Sense is the flags word of a dependency: the version comparison and the
// scope the dependency applies to.
type Sense uint32

// The comparison bits: SenseAny (0) specifies no version compare, SenseLess (2)
// less than the version, SenseGreater (4) greater than it and SenseEqual (8)
// equal to it. Combine them for "<=" and ">=".
const (
	SenseAny     Sense = tag.RPMSENSE_ANY
	SenseLess    Sense = tag.RPMSENSE_LESS
	SenseGreater Sense = tag.RPMSENSE_GREATER
	SenseEqual   Sense = tag.RPMSENSE_EQUAL
)

// The scope bits restrict a requirement to a stage of the transaction: Requires(pre)
// is SenseScriptPre, Requires(post) SenseScriptPost and so on. A requirement without
// scope bits is needed at all times.
const (
	// SensePosttrans is Requires(posttrans).
	SensePosttrans Sense = tag.RPMSENSE_POSTTRANS
	// SensePrereq is the legacy PreReq.
	SensePrereq Sense = tag.RPMSENSE_PREREQ
	// SensePretrans is Requires(pretrans).
	SensePretrans Sense = tag.RPMSENSE_PRETRANS
	// SenseInterp marks the interpreter of a scriptlet; rpm sets it on the
	// requirements that name an interpreter.
	SenseInterp Sense = tag.RPMSENSE_INTERP
	// SenseScriptPre is Requires(pre).
	SenseScriptPre Sense = tag.RPMSENSE_SCRIPT_PRE
	// SenseScriptPost is Requires(post).
	SenseScriptPost Sense = tag.RPMSENSE_SCRIPT_POST
	// SenseScriptPreun is Requires(preun).
	SenseScriptPreun Sense = tag.RPMSENSE_SCRIPT_PREUN
	// SenseScriptPostun is Requires(postun).
	SenseScriptPostun Sense = tag.RPMSENSE_SCRIPT_POSTUN
	// SenseScriptVerify is Requires(verify).
	SenseScriptVerify Sense = tag.RPMSENSE_SCRIPT_VERIFY
	// SenseMissingOK is set on dependencies that need not be satisfiable
	// (Requires(hint) / "missingok").
	SenseMissingOK Sense = tag.RPMSENSE_MISSINGOK
	// SensePreuntrans is Requires(preuntrans).
	SensePreuntrans Sense = tag.RPMSENSE_PREUNTRANS
	// SensePostuntrans is Requires(postuntrans).
	SensePostuntrans Sense = tag.RPMSENSE_POSTUNTRANS
	// SenseRPMLIB marks rpmlib(...) feature requirements.
	SenseRPMLIB Sense = tag.RPMSENSE_RPMLIB
	// SenseKeyring marks a requirement on a package that provides a keyring.
	SenseKeyring Sense = tag.RPMSENSE_KEYRING
	// SenseConfig marks the config(name) dependencies of packages with config files.
	SenseConfig Sense = tag.RPMSENSE_CONFIG
	// SenseMeta is Requires(meta): a requirement that does not order the transaction.
	SenseMeta Sense = tag.RPMSENSE_RICH
)

// senseCompare selects the version comparison bits of a Sense.
const senseCompare = SenseLess | SenseGreater | SenseEqual

// Compare returns the version comparison bits of s.
func (s Sense) Compare() Sense { return s & senseCompare }

// ErrInvalidRelation is returned for dependencies that cannot be parsed or that are
// malformed boolean ("rich") dependencies.
var ErrInvalidRelation = errors.New("invalid rpm dependency")

// Relation is the structure of rpm sense relationships.
type Relation struct {
	Name    string
	Version string
	Sense   Sense
}

// String return the string representation of the Relation: the name, the
// comparison and the version. Scope bits are not shown.
func (r *Relation) String() string {
	return fmt.Sprintf("%s%v%s", r.Name, r.Sense, r.Version)
}

// Equal compare the equality of two relations
func (r *Relation) Equal(o *Relation) bool {
	return r.Name == o.Name && r.Version == o.Version && r.Sense == o.Sense
}

// Relations is a slice of Relation pointers
type Relations []*Relation

// String return the string representation of the Relations
func (r *Relations) String() string {
	var val []string
	for _, rel := range *r {
		val = append(val, rel.String())
	}
	return strings.Join(val, ",")
}

// Set parse a string into a Relation and append it to the Relations slice if it is missing
// this is used by the flag package
func (r *Relations) Set(value string) error {
	relation, err := NewRelation(value)
	if err != nil {
		return err
	}
	r.addIfMissing(relation)

	return nil
}

func (r *Relations) addIfMissing(value *Relation) {
	for _, relation := range *r {
		if relation.Equal(value) {
			return
		}
	}

	*r = append(*r, value)
}

// sorted returns a copy sorted as rpmbuild does: by name, version and flags.
func (r Relations) sorted() Relations {
	out := slices.Clone(r)
	slices.SortStableFunc(out, func(a, b *Relation) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		if c := strings.Compare(a.Version, b.Version); c != 0 {
			return c
		}
		switch {
		case a.Sense < b.Sense:
			return -1
		case a.Sense > b.Sense:
			return 1
		}
		return 0
	})
	return out
}

// index returns the position of rel in r, which must hold it.
func (r Relations) index(rel *Relation) int {
	for i, o := range r {
		if o == rel || o.Equal(rel) {
			return i
		}
	}
	return -1
}

// AddToIndex add the relations to the specified category on the index
func (r *Relations) AddToIndex(h *rpmhdr.Index, nameTag, versionTag, flagsTag int) error {
	var (
		num      = len(*r)
		names    = make([]string, num)
		versions = make([]string, num)
		flags    = make([]uint32, num)
	)

	if num == 0 {
		return nil
	}

	for idx, relation := range r.sorted() {
		names[idx] = relation.Name
		versions[idx] = relation.Version
		flags[idx] = uint32(relation.Sense)
	}

	h.Add(nameTag, EntryStringSlice(names))
	h.Add(versionTag, EntryStringSlice(versions))
	h.Add(flagsTag, EntryUint32(flags))

	return nil
}

// isRich reports whether name is a boolean dependency.
func isRich(name string) bool { return strings.HasPrefix(name, "(") }

// NewRelation parses a dependency of the form "name", "name = 1.0", "name >= 1.0"
// or a boolean dependency such as "(a or (b if c))". Boolean dependencies are
// validated with the grammar of rpm: see ValidateRich.
func NewRelation(related string) (*Relation, error) {
	if isRich(related) {
		if err := ValidateRich(related); err != nil {
			return nil, err
		}
		return &Relation{Name: related}, nil
	}
	name, rest := splitName(strings.TrimSpace(related))
	op, version := splitOp(rest)
	sense, ok := stringToSense[op]
	if !ok {
		return nil, fmt.Errorf("%w: unknown sense value %q in %q", ErrInvalidRelation, op, related)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: empty name in %q", ErrInvalidRelation, related)
	}
	if (op == "") != (version == "") || strings.ContainsAny(version, " \t<>=") || (op == "" && rest != "") {
		return nil, fmt.Errorf("%w: %q is not a name with an optional comparison and version", ErrInvalidRelation, related)
	}
	return &Relation{Name: name, Version: version, Sense: sense}, nil
}

// splitName splits the leading name, which ends at white space or a comparison operator.
func splitName(s string) (name, rest string) {
	i := strings.IndexFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '=' || r == '<' || r == '>'
	})
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimSpace(s[i:])
}

// splitOp splits the operator characters at the start of s from the version.
func splitOp(s string) (op, version string) {
	i := strings.IndexFunc(s, func(r rune) bool { return r != '=' && r != '<' && r != '>' })
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimSpace(s[i:])
}

var stringToSense = map[string]Sense{
	"":   SenseAny,
	"<":  SenseLess,
	">":  SenseGreater,
	"=":  SenseEqual,
	"<=": SenseLess | SenseEqual,
	">=": SenseGreater | SenseEqual,
}

// String return the comparison operator of the sense ("" for any version, "<",
// ">", "=", "<=" or ">="), whatever its scope bits.
func (s Sense) String() string {
	for op, val := range stringToSense {
		if s.Compare() == val {
			return op
		}
	}
	return "unknown"
}

// ValidateRich checks that s is a well formed boolean dependency in the syntax
// rpm accepts: a parenthesized expression of operands joined by a chain of
// "and", "or", "with" or "without" (chains do not mix without parentheses), or
// "if"/"unless" with an optional "else". An operand is a name with an optional
// comparison and version, or a nested expression. Names may contain balanced
// parentheses, as in "perl(Foo)". It checks the syntax only: rpm further limits
// where "if" and "unless" may appear depending on the kind of dependency, which
// Write enforces for each list.
func ValidateRich(s string) error {
	return validateRich(s, richAny)
}

// richContext is the polarity an expression is evaluated in.
type richContext int

const (
	richAny richContext = iota // no context rules
	richAnd                    // all operands must hold: "if" is legal, "unless" is not
	richOr                     // one operand suffices: "unless" is legal, "if" is not
)

// validateRich parses s; ctx is the context of the top level expression:
// richAnd for requires like dependencies, richOr for conflicts.
func validateRich(s string, ctx richContext) error {
	p := &richParser{s: s}
	p.skipSpace()
	n, err := p.group()
	if err == nil {
		p.skipSpace()
		if p.i != len(p.s) {
			err = fmt.Errorf("trailing characters at %d", p.i)
		}
	}
	if err == nil && ctx != richAny {
		err = n.check(ctx)
	}
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrInvalidRelation, s, err)
	}
	return nil
}

type richParser struct {
	s string
	i int
}

func (p *richParser) skipSpace() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

// group parses "(" expression ")" and returns its operator.
func (p *richParser) group() (*richNode, error) {
	if p.i >= len(p.s) || p.s[p.i] != '(' {
		return nil, errors.New("expected '('")
	}
	p.i++
	n, err := p.expression()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.i >= len(p.s) || p.s[p.i] != ')' {
		return nil, fmt.Errorf("expected ')' at %d", p.i)
	}
	p.i++
	return n, nil
}

// word returns the next white space delimited word without consuming it.
func (p *richParser) word() string {
	j := p.i
	for j < len(p.s) && p.s[j] != ' ' && p.s[j] != '\t' && p.s[j] != ')' && p.s[j] != '(' {
		j++
	}
	return p.s[p.i:j]
}

// richNode is a parsed group: its operator ("" for a single operand) and the
// groups among its operands.
type richNode struct {
	op   string
	kids []*richNode
}

// check applies the context rules of rpm to n, which is evaluated in ctx.
func (n *richNode) check(ctx richContext) error {
	switch {
	case n.op == "if" && ctx != richAnd:
		return errors.New("'if' is not allowed here, use 'and'")
	case n.op == "unless" && ctx != richOr:
		return errors.New("'unless' is not allowed here, use 'or'")
	}
	cc := ctx
	switch n.op {
	case "and", "if", "else":
		cc = richAnd
	case "or", "unless":
		cc = richOr
	}
	for _, k := range n.kids {
		if (n.op == "with" || n.op == "without") && (k.op == "if" || k.op == "unless") {
			return fmt.Errorf("'%s' is not allowed inside %q", k.op, n.op)
		}
		if err := k.check(cc); err != nil {
			return err
		}
	}
	return nil
}

// operandNode parses an operand; a name is a node without operator.
func (p *richParser) operandNode() (*richNode, error) {
	p.skipSpace()
	if p.i < len(p.s) && p.s[p.i] == '(' {
		return p.group()
	}
	return &richNode{}, p.operand()
}

func (p *richParser) expression() (*richNode, error) {
	n := &richNode{}
	first, err := p.operandNode()
	if err != nil {
		return nil, err
	}
	n.kids = append(n.kids, first)
	p.skipSpace()
	op := p.word()
	switch op {
	case "":
		return first, nil
	case "and", "or", "with", "without":
		n.op = op
		for {
			p.i += len(op)
			if err := p.requireSpace(); err != nil {
				return nil, err
			}
			k, err := p.operandNode()
			if err != nil {
				return nil, err
			}
			n.kids = append(n.kids, k)
			p.skipSpace()
			next := p.word()
			if next == "" {
				return n, nil
			}
			if next != op {
				return nil, fmt.Errorf("unexpected %q after %q chain at %d", next, op, p.i)
			}
		}
	case "if", "unless", "else":
		n.op = op
		for _, w := range []string{op, "else"} {
			if w == "else" && op == "else" {
				break
			}
			if p.word() != w {
				break
			}
			p.i += len(w)
			if err := p.requireSpace(); err != nil {
				return nil, err
			}
			k, err := p.operandNode()
			if err != nil {
				return nil, err
			}
			n.kids = append(n.kids, k)
			p.skipSpace()
		}
		if p.word() != "" {
			return nil, fmt.Errorf("unexpected %q at %d", p.word(), p.i)
		}
		return n, nil
	}
	return nil, fmt.Errorf("unknown operator %q at %d", op, p.i)
}

func (p *richParser) requireSpace() error {
	if p.i >= len(p.s) || (p.s[p.i] != ' ' && p.s[p.i] != '\t') {
		return fmt.Errorf("expected white space at %d", p.i)
	}
	p.skipSpace()
	return nil
}

// operand parses "name [op version]".
func (p *richParser) operand() error {
	p.skipSpace()
	start := p.i
	depth := 0
	for p.i < len(p.s) {
		c := p.s[p.i]
		if c == ' ' || c == '\t' || (c == ')' && depth == 0) {
			break
		}
		switch c {
		case '(':
			depth++
		case ')':
			depth--
		}
		p.i++
	}
	if depth != 0 {
		return fmt.Errorf("unbalanced parentheses in name at %d", start)
	}
	name := p.s[start:p.i]
	if name == "" || strings.ContainsAny(name, "<>=") {
		return fmt.Errorf("expected a name at %d", start)
	}
	switch name {
	case "and", "or", "if", "unless", "else", "with", "without":
		return fmt.Errorf("operator %q used as a name at %d", name, start)
	}
	// optional comparison and version
	save := p.i
	p.skipSpace()
	opStart := p.i
	for p.i < len(p.s) && (p.s[p.i] == '<' || p.s[p.i] == '>' || p.s[p.i] == '=') {
		p.i++
	}
	if p.i == opStart {
		p.i = save
		return nil
	}
	if _, ok := stringToSense[p.s[opStart:p.i]]; !ok {
		return fmt.Errorf("unknown comparison %q at %d", p.s[opStart:p.i], opStart)
	}
	if err := p.requireSpace(); err != nil {
		return err
	}
	vs := p.i
	for p.i < len(p.s) && p.s[p.i] != ' ' && p.s[p.i] != '\t' && p.s[p.i] != ')' {
		p.i++
	}
	if p.i == vs {
		return fmt.Errorf("missing version at %d", vs)
	}
	return nil
}
