// Package richdep parses and evaluates the rich (boolean) dependencies of
// RPM: "(foo and bar)", "(foo if bar)", "(foo unless bar else baz)",
// "((a or b) with c)" and the like, as rpm 4.12 and later read them.
//
// [Parse] turns the text of a dependency into a tree of [Atom] (a capability
// with an optional version comparison) and [Expr] (an operator and its
// operands). [Node.String] writes the canonical form, which parses back to an
// equal tree. [Eval] decides whether a dependency is met, against an
// [Oracle] that says which packages provide a capability.
//
// The grammar, the context rules and the evaluation follow librpm
// (rpmrichParse, rpmdsParseRichDep and unsatisfiedDepend), so the same strings
// are accepted and the same answers come out; the tests compare them with
// librpm on a corpus when its python bindings are installed.
//
// # Grammar
//
// A rich dependency is a parenthesised list of operands, which are atoms
// ("name", or "name <op> version" with <op> one of < <= = == >= > =< =>) or
// further rich dependencies. Operands are separated by and, or, if, unless,
// else, with or without; whitespace and commas separate words alike. A chain
// may repeat one of and, or, with: "(a and b and c)". if and unless take one
// condition and, optionally, an else branch: "(a if b else c)". Anything else
// needs parentheses: "((a and b) or c)".
//
// # Semantics
//
// Eval returns whether the dependency is "satisfied" in the sense librpm gives
// it for a Requires. For a Conflicts, the conflict is raised when the
// dependency is satisfied. The operators are:
//
//   - a and b, a or b: both, either.
//   - a if b: a when b is satisfied, else satisfied. a unless b: not satisfied
//     when b is, else a. With "else c" the branch not taken is c: "a if b else
//     c" is a when b is satisfied and c when not; "a unless b else c" is c when
//     b is satisfied and a when not.
//   - a with b: one package that satisfies both a and b. a without b: a
//     package that satisfies a and not b. Their operands are evaluated as sets
//     of packages: an atom is the packages the oracle names, "or" is the union
//     of two sets, with and without nest; any other operator inside one makes
//     the set empty.
package richdep

import (
	"strings"
)

// Cmp is the comparison of a versioned capability, as the bits of rpm's
// RPMSENSE_LESS, RPMSENSE_GREATER and RPMSENSE_EQUAL. The zero value means no
// version constraint.
type Cmp uint32

// The bits of a Cmp; they are the values of tag.RPMSENSE_LESS, GREATER and
// EQUAL, so the comparison bits of rpm.Dependency.Flags convert directly.
const (
	Less    Cmp = 0x02
	Greater Cmp = 0x04
	Equal   Cmp = 0x08

	// cmpMask selects the comparison bits.
	cmpMask = Less | Greater | Equal
)

// FromFlags returns the comparison bits of the sense flags of a dependency.
func FromFlags[T ~uint32](flags T) Cmp { return Cmp(flags) & cmpMask }

// String renders the comparison operator: "<", "<=", "=", ">=", ">", or ""
// when there is none.
func (c Cmp) String() string {
	switch c & cmpMask {
	case Less:
		return "<"
	case Less | Equal:
		return "<="
	case Equal:
		return "="
	case Greater | Equal:
		return ">="
	case Greater:
		return ">"
	default:
		return ""
	}
}

// Op is an operator of a rich dependency.
type Op int

// The operators.
const (
	OpAnd Op = iota + 1
	OpOr
	OpIf
	OpUnless
	OpElse
	OpWith
	OpWithout
)

// String returns the keyword of the operator.
func (o Op) String() string {
	switch o {
	case OpAnd:
		return "and"
	case OpOr:
		return "or"
	case OpIf:
		return "if"
	case OpUnless:
		return "unless"
	case OpElse:
		return "else"
	case OpWith:
		return "with"
	case OpWithout:
		return "without"
	default:
		return ""
	}
}

// Node is an Atom or an Expr.
type Node interface {
	// String writes the canonical text: single spaces, the operators in
	// lower case, "=" for "==", and the parentheses exactly where they were.
	// The text parses back to an equal tree, except for a capability name
	// with a "(" that nothing closes, which librpm reads the same way.
	String() string
	isNode()
}

// Atom is a capability, with a version comparison when Cmp is not zero.
// Version is "[epoch:]version[-release]".
type Atom struct {
	Name    string
	Cmp     Cmp
	Version string
}

func (Atom) isNode() {}

// String writes "name" or "name <op> version".
func (a Atom) String() string {
	if a.Cmp&cmpMask == 0 || a.Version == "" {
		return a.Name
	}

	return a.Name + " " + a.Cmp.String() + " " + a.Version
}

// Expr is an operator applied to operands, always parenthesised in text.
//
// And, Or and With take two or more operands (a chain); Without takes two.
// If and Unless take the subject, the condition and, when there is an else
// branch, a third operand: Args is {a, b} or {a, b, c} for "(a if b)" and
// "(a if b else c)". Else without a preceding if or unless, "(a else b)", is
// accepted as librpm accepts it: Args is {a, b}, and it is
// evaluated like its subject alone, as librpm does, and is not a useful form.
type Expr struct {
	Op   Op
	Args []Node
}

func (*Expr) isNode() {}

// String writes the parenthesised expression.
func (e *Expr) String() string {
	var b strings.Builder

	b.WriteByte('(')

	switch e.Op {
	case OpIf, OpUnless:
		b.WriteString(e.Args[0].String())
		b.WriteByte(' ')
		b.WriteString(e.Op.String())
		b.WriteByte(' ')
		b.WriteString(e.Args[1].String())

		if len(e.Args) > 2 {
			b.WriteString(" else ")
			b.WriteString(e.Args[2].String())
		}
	default:
		for i, a := range e.Args {
			if i > 0 {
				b.WriteByte(' ')
				b.WriteString(e.Op.String())
				b.WriteByte(' ')
			}

			b.WriteString(a.String())
		}
	}

	b.WriteByte(')')

	return b.String()
}

// Atoms returns every atom of the tree, in text order.
func Atoms(n Node) []Atom {
	var out []Atom

	walk(n, func(a Atom) { out = append(out, a) })

	return out
}

func walk(n Node, fn func(Atom)) {
	switch n := n.(type) {
	case Atom:
		fn(n)
	case *Expr:
		for _, a := range n.Args {
			walk(a, fn)
		}
	}
}

// Oracle answers what the packages provide.
type Oracle interface {
	// Satisfiers returns the identities of the packages that provide a
	// capability meeting a: the same name, and a version range that overlaps
	// the one of a (see [Atom.Overlaps]). The identities only need to be
	// comparable with each other: they are the elements of the sets of "with"
	// and "without". A nil or empty result means nothing provides it.
	Satisfiers(a Atom) []string
}

// OracleFunc adapts a function to an [Oracle].
type OracleFunc func(a Atom) []string

// Satisfiers calls f.
func (f OracleFunc) Satisfiers(a Atom) []string { return f(a) }

// Eval reports whether the dependency n is satisfied, as librpm decides it
// for the Requires of a package. See the package comment for the operators.
func Eval(n Node, o Oracle) bool {
	switch n := n.(type) {
	case Atom:
		return len(o.Satisfiers(n)) > 0
	case *Expr:
		return evalExpr(n, o)
	default:
		return false
	}
}

func evalExpr(e *Expr, o Oracle) bool {
	switch e.Op {
	case OpAnd:
		for _, a := range e.Args {
			if !Eval(a, o) {
				return false
			}
		}

		return true
	case OpOr:
		for _, a := range e.Args {
			if Eval(a, o) {
				return true
			}
		}

		return false
	case OpIf, OpUnless:
		cond := Eval(e.Args[1], o)
		// "a if b" is a when b holds; "a unless b" is a when b does not. The
		// branch not taken is the else operand, or for the bare forms
		// satisfied (if) and unsatisfied (unless).
		takeA := cond == (e.Op == OpIf)
		if takeA {
			return Eval(e.Args[0], o)
		}

		if len(e.Args) > 2 {
			return Eval(e.Args[2], o)
		}

		return e.Op == OpIf
	case OpWith, OpWithout:
		return len(Set(e, o)) > 0
	case OpElse:
		// librpm gives a stray else no meaning of its own: only the first
		// operand counts.
		return Eval(e.Args[0], o)
	default:
		return false
	}
}

// Set returns the packages that satisfy n in the sense of "with" and
// "without": the oracle's packages for an atom, the union for "or", the
// intersection for "with", and for "without" those of the first operand that
// are not among the others. Any other operator yields none.
func Set(n Node, o Oracle) []string {
	switch n := n.(type) {
	case Atom:
		return o.Satisfiers(n)
	case *Expr:
		switch n.Op {
		case OpOr:
			var out []string

			seen := make(map[string]struct{})

			for _, a := range n.Args {
				for _, id := range Set(a, o) {
					if _, dup := seen[id]; !dup {
						seen[id] = struct{}{}
						out = append(out, id)
					}
				}
			}

			return out
		case OpWith:
			cur := Set(n.Args[0], o)
			for _, a := range n.Args[1:] {
				if len(cur) == 0 {
					return nil
				}

				cur = intersect(cur, Set(a, o))
			}

			return cur
		case OpWithout:
			cur := Set(n.Args[0], o)
			if len(cur) == 0 {
				return nil
			}

			return subtract(cur, Set(n.Args[1], o))
		}
	}

	return nil
}

func intersect(a, b []string) []string {
	in := make(map[string]struct{}, len(b))
	for _, id := range b {
		in[id] = struct{}{}
	}

	var out []string

	for _, id := range a {
		if _, ok := in[id]; ok {
			out = append(out, id)
		}
	}

	return out
}

func subtract(a, b []string) []string {
	drop := make(map[string]struct{}, len(b))
	for _, id := range b {
		drop[id] = struct{}{}
	}

	var out []string

	for _, id := range a {
		if _, ok := drop[id]; !ok {
			out = append(out, id)
		}
	}

	return out
}
