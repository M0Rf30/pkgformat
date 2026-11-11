package richdep

import (
	"errors"
	"fmt"
	"strings"
)

// ErrSyntax is wrapped by every error of [Parse].
var ErrSyntax = errors.New("richdep: invalid rich dependency")

// maxDepth bounds the nesting of parentheses, so that hostile metadata cannot
// exhaust the stack. librpm recurses without a bound; no real dependency
// nests more than a handful of levels.
const maxDepth = 128

// Kind says which tag a dependency belongs to, as librpm checks the contexts
// of the operators per tag.
type Kind int

const (
	// KindRequire is for Requires, Provides, Recommends and Suggests, where
	// "unless" is only valid below an "and"-free context: "(a unless b)" is
	// refused and "or" must be used.
	KindRequire Kind = iota
	// KindConflict is for Conflicts, Supplements and Enhances, where "if" is
	// refused at the top and "and" is the one to use.
	KindConflict
	// KindProvide is for Provides and Obsoletes, which take no rich
	// dependency at all.
	KindProvide
)

// check flags, rpmrichParse's RICHPARSE_*.
const (
	chkCheck  = 1 << 0
	chkNoWith = 1 << 1
	chkNoAnd  = 1 << 2
	chkNoOr   = 1 << 3
)

// Parse reads a dependency: a plain atom ("name", "name >= 1.2") or a rich
// dependency in parentheses. It applies the context rules librpm applies to
// every dependency (no "and"/"or"/"if"/... below a "with" or "without").
// Use [ParseFor] to apply those of one tag as well.
func Parse(s string) (Node, error) {
	return parse(s, false, KindRequire)
}

// ParseFor is [Parse] with the rules of the tag the dependency is in: the
// "unless" of a Requires and the "if" of a Conflicts are refused, and so is
// any rich dependency in a Provides, as rpmbuild refuses them.
func ParseFor(s string, kind Kind) (Node, error) {
	return parse(s, true, kind)
}

func parse(s string, forTag bool, kind Kind) (Node, error) {
	// The spec parser of rpmbuild trims the line a dependency is on, so
	// surrounding ASCII whitespace is not part of it.
	p := &parser{s: strings.Trim(s, " \t\n\r\v\f")}
	s = p.s

	if forTag && kind == KindProvide && strings.HasPrefix(s, "(") {
		return nil, p.errorf("no rich dependency allowed for this tag")
	}

	p.skipWhite()

	if p.pos >= len(p.s) || p.s[p.pos] != '(' {
		a, err := p.simple()
		if err != nil {
			return nil, err
		}

		p.skipWhite()

		if p.pos < len(p.s) {
			return nil, p.errorf("junk after dependency")
		}

		return a, nil
	}

	check := 0
	if forTag {
		check = chkCheck
	}

	n, err := p.rich(&check, 1)
	if err != nil {
		return nil, err
	}

	if p.pos < len(p.s) {
		return nil, p.errorf("junk after rich dependency")
	}

	if forTag {
		op := OpAnd
		if kind == KindConflict {
			op = OpOr
		}

		if err := checkContext(op, check); err != nil {
			return nil, p.errorf("%s", err)
		}
	}

	return n, nil
}

type parser struct {
	s   string
	pos int
}

func (p *parser) errorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s: %q", ErrSyntax, fmt.Sprintf(format, args...), p.s)
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

// skipWhite skips whitespace and commas, which librpm treats alike.
func (p *parser) skipWhite() {
	for p.pos < len(p.s) && (isSpace(p.s[p.pos]) || p.s[p.pos] == ',') {
		p.pos++
	}
}

// word consumes a token: up to whitespace, a comma, or a ")" that no "(" of
// the token opened.
func (p *parser) word() string {
	start, balance := p.pos, 0

	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if isSpace(c) || c == ',' {
			break
		}

		if c == ')' {
			if balance <= 0 {
				break
			}

			balance--
		}

		if c == '(' {
			balance++
		}

		p.pos++
	}

	return p.s[start:p.pos]
}

// parseCmp maps a comparison token to its bits, 0 for anything else.
func parseCmp(tok string) Cmp {
	switch tok {
	case "<":
		return Less
	case "<=", "=<":
		return Less | Equal
	case "=", "==":
		return Equal
	case ">=", "=>":
		return Greater | Equal
	case ">":
		return Greater
	default:
		return 0
	}
}

// simple reads "name" or "name <op> version".
func (p *parser) simple() (Atom, error) {
	p.skipWhite()

	name := p.word()
	if name == "" {
		return Atom{}, p.errorf("name required")
	}

	a := Atom{Name: name}

	p.skipWhite()

	if p.pos < len(p.s) {
		save := p.pos

		if cmp := parseCmp(p.word()); cmp != 0 {
			p.skipWhite()

			ver := p.word()
			if ver == "" {
				return Atom{}, p.errorf("version required")
			}

			a.Cmp, a.Version = cmp, ver
		} else {
			p.pos = save
		}
	}

	return a, nil
}

func (p *parser) op() (Op, error) {
	start := p.pos

	for p.pos < len(p.s) && !isSpace(p.s[p.pos]) && p.s[p.pos] != ')' {
		p.pos++
	}

	switch tok := p.s[start:p.pos]; tok {
	case "and":
		return OpAnd, nil
	case "or":
		return OpOr, nil
	case "if":
		return OpIf, nil
	case "unless":
		return OpUnless, nil
	case "else":
		return OpElse, nil
	case "with":
		return OpWith, nil
	case "without":
		return OpWithout, nil
	default:
		return 0, p.errorf("unknown rich dependency op %q", tok)
	}
}

func checkContext(op Op, check int) error {
	if (op == OpWith || op == OpWithout) && check&chkNoWith != 0 {
		return errors.New("illegal ops in with/without")
	}

	if check&chkCheck == 0 {
		return nil
	}

	if (op == OpAnd || op == OpIf) && check&chkNoAnd != 0 {
		return errors.New("illegal context for 'unless', please use 'or' instead")
	}

	if (op == OpOr || op == OpUnless) && check&chkNoOr != 0 {
		return errors.New("illegal context for 'if', please use 'and' instead")
	}

	return nil
}

// rich reads one parenthesised group; it is rpmrichParseInternal.
func (p *parser) rich(checkp *int, depth int) (Node, error) {
	if depth > maxDepth {
		return nil, p.errorf("nesting too deep")
	}

	if p.pos >= len(p.s) || p.s[p.pos] != '(' {
		return nil, p.errorf("rich dependency does not start with '('")
	}

	start := p.pos
	p.pos++

	var (
		operands             []Node
		ops                  []Op
		op, firstop, chainop = Op(0), Op(0), Op(0)
		check                = *checkp
	)

	for {
		p.skipWhite()

		if p.pos < len(p.s) && p.s[p.pos] == ')' {
			if chainop != 0 {
				return nil, p.errorf("missing argument to rich dependency op")
			}

			return nil, p.errorf("empty rich dependency")
		}

		if p.pos < len(p.s) && p.s[p.pos] == '(' {
			sub := check & chkCheck

			n, err := p.rich(&sub, depth+1)
			if err != nil {
				return nil, err
			}

			if op == OpIf || op == OpUnless {
				sub &^= chkNoAnd | chkNoOr
			}

			check |= sub

			operands = append(operands, n)
		} else {
			a, err := p.simple()
			if err != nil {
				return nil, err
			}

			operands = append(operands, a)
		}

		p.skipWhite()

		if p.pos >= len(p.s) {
			return nil, p.errorf("unterminated rich dependency: %s", p.s[start:])
		}

		if p.s[p.pos] == ')' {
			break
		}

		var err error
		if op, err = p.op(); err != nil {
			return nil, err
		}

		if firstop == 0 {
			firstop = op
		}

		if op == OpElse && (chainop == OpIf || chainop == OpUnless) {
			chainop = 0
		}

		if chainop != 0 && op != chainop {
			return nil, p.errorf("cannot chain different ops")
		}

		if chainop != 0 && op != OpAnd && op != OpOr && op != OpWith {
			return nil, p.errorf("can only chain and/or/with ops")
		}

		ops = append(ops, op)
		chainop = op
	}

	if err := checkContext(firstop, check); err != nil {
		return nil, p.errorf("%s", err)
	}

	switch firstop {
	case OpIf:
		check |= chkNoOr
	case OpUnless:
		check |= chkNoAnd
	}

	if op == OpAnd || op == OpOr {
		check &^= chkNoAnd | chkNoOr
	}

	if op != 0 && op != OpWith && op != OpWithout && op != OpOr {
		check |= chkNoWith
	}

	p.pos++ // the closing parenthesis
	*checkp |= check

	return build(operands, ops), nil
}

// build assembles the operands and operators of one group. The parser has
// already ruled out every sequence but: no operator (a parenthesised operand,
// which is the operand itself), one operator, a chain of and/or/with, and
// "if|unless ... else".
func build(operands []Node, ops []Op) Node {
	switch {
	case len(ops) == 0:
		return operands[0]
	default:
		return &Expr{Op: ops[0], Args: operands}
	}
}
