package repodata

import (
	"bytes"
	"fmt"
	"unicode/utf8"
)

// This file lays a tree of YAML nodes out the way libyaml's emitter does with
// its default settings and unicode output: two-space indentation, block
// sequences that are not indented inside a mapping, flow sequences and
// mappings only where requested (or empty), and lines folded at column 80.
// libmodulemd, which writes the modules.yaml of every distribution, emits
// through libyaml, so following its layout keeps a document written here
// textually equal to the one libmodulemd writes for the same content.

type yamlKind uint8

const (
	yamlKindScalar yamlKind = iota
	yamlKindSequence
	yamlKindMapping
)

type yamlStyle uint8

const (
	yamlPlain yamlStyle = iota
	yamlSingleQuoted
	yamlDoubleQuoted
	yamlFolded
)

const (
	yamlBestIndent = 2
	yamlBestWidth  = 80
	// yamlMaxSimpleKey is the longest scalar libyaml writes as an implicit
	// key; a longer one is written with an explicit "?" indicator.
	yamlMaxSimpleKey = 128
)

// yamlNode is a scalar, a sequence or a mapping. The items of a mapping
// alternate between keys and values.
type yamlNode struct {
	kind  yamlKind
	value string
	style yamlStyle
	// flow requests the flow style ([a, b]) for a sequence; empty sequences
	// and mappings are always written in flow style.
	flow  bool
	items []*yamlNode
}

func yamlScalarNode(value string, style yamlStyle) *yamlNode {
	return &yamlNode{kind: yamlKindScalar, value: value, style: style}
}

func yamlSeqNode(flow bool) *yamlNode {
	return &yamlNode{kind: yamlKindSequence, flow: flow}
}

func yamlMapNode() *yamlNode {
	return &yamlNode{kind: yamlKindMapping}
}

func (n *yamlNode) append(item *yamlNode) { n.items = append(n.items, item) }

// set appends a key and its value to a mapping.
func (n *yamlNode) set(key, value *yamlNode) { n.items = append(n.items, key, value) }

type yamlScalarData struct {
	length         int
	multiline      bool
	flowPlainOK    bool
	blockPlainOK   bool
	singleQuotedOK bool
	blockScalarOK  bool
	runes          []rune
}

// yamlEmitter holds the state of libyaml's emitter that decides where
// whitespace and breaks go.
type yamlEmitter struct {
	out       *bytes.Buffer
	column    int
	indent    int
	indents   []int
	flowLevel int

	whitespace bool
	indention  bool

	mapCtx, simpleKeyCtx bool
}

// emitYAMLDocument appends the node as one explicit document ("---" to "...")
// to out.
func emitYAMLDocument(out *bytes.Buffer, root *yamlNode) {
	e := &yamlEmitter{out: out, indent: -1, whitespace: true, indention: true}

	e.writeIndent()
	e.writeIndicator("---", true, false, false)
	e.emitNode(root, false, false)
	e.writeIndent()
	e.writeIndicator("...", true, false, false)
	e.writeIndent()
}

func (e *yamlEmitter) put(r rune) {
	e.out.WriteRune(r)
	e.column++
}

func (e *yamlEmitter) putBreak() {
	e.out.WriteByte('\n')
	e.column = 0
}

// writeBreak copies a line-break character of a scalar: a line feed becomes
// the emitter's break, the others are kept as they are.
func (e *yamlEmitter) writeBreak(r rune) {
	if r == '\n' {
		e.putBreak()

		return
	}

	e.out.WriteRune(r)
	e.column = 0
}

func (e *yamlEmitter) increaseIndent(flow, indentless bool) {
	e.indents = append(e.indents, e.indent)

	switch {
	case e.indent < 0:
		if flow {
			e.indent = yamlBestIndent
		} else {
			e.indent = 0
		}
	case !indentless:
		e.indent += yamlBestIndent
	}
}

func (e *yamlEmitter) popIndent() {
	e.indent = e.indents[len(e.indents)-1]
	e.indents = e.indents[:len(e.indents)-1]
}

func (e *yamlEmitter) writeIndent() {
	indent := max(e.indent, 0)

	if !e.indention || e.column > indent || (e.column == indent && !e.whitespace) {
		e.putBreak()
	}

	for e.column < indent {
		e.put(' ')
	}

	e.whitespace = true
	e.indention = true
}

func (e *yamlEmitter) writeIndicator(indicator string, needWhitespace, isWhitespace, isIndention bool) {
	if needWhitespace && !e.whitespace {
		e.put(' ')
	}

	for _, r := range indicator {
		e.put(r)
	}

	e.whitespace = isWhitespace
	e.indention = e.indention && isIndention
}

// emitNode writes a node; mapping and simpleKey say whether it is the key or
// value of a mapping and whether it is written as an implicit key.
func (e *yamlEmitter) emitNode(n *yamlNode, mapping, simpleKey bool) {
	e.mapCtx, e.simpleKeyCtx = mapping, simpleKey

	switch n.kind {
	case yamlKindScalar:
		e.emitScalar(n)
	case yamlKindSequence:
		e.emitSequence(n)
	case yamlKindMapping:
		e.emitMapping(n)
	}
}

func (e *yamlEmitter) emitSequence(n *yamlNode) {
	if e.flowLevel > 0 || n.flow || len(n.items) == 0 {
		e.writeIndicator("[", true, true, false)
		e.increaseIndent(true, false)
		e.flowLevel++

		for i, item := range n.items {
			if i > 0 {
				e.writeIndicator(",", false, false, false)
			}

			if e.column > yamlBestWidth {
				e.writeIndent()
			}

			e.emitNode(item, false, false)
		}

		e.flowLevel--
		e.popIndent()
		e.writeIndicator("]", false, false, false)

		return
	}

	e.increaseIndent(false, e.mapCtx && !e.indention)

	for _, item := range n.items {
		e.writeIndent()
		e.writeIndicator("-", true, false, true)
		e.emitNode(item, false, false)
	}

	e.popIndent()
}

func (e *yamlEmitter) emitMapping(n *yamlNode) {
	if len(n.items) == 0 {
		e.emitEmptyMapping()

		return
	}

	e.increaseIndent(false, false)

	for i := 0; i < len(n.items); i += 2 {
		key, value := n.items[i], n.items[i+1]

		e.writeIndent()

		simple := yamlSimpleKey(key)
		if simple {
			e.emitNode(key, true, true)
			e.writeIndicator(":", false, false, false)
		} else {
			e.writeIndicator("?", true, false, true)
			e.emitNode(key, true, false)
			e.writeIndent()
			e.writeIndicator(":", true, false, true)
		}

		e.emitNode(value, true, false)
	}

	e.popIndent()
}

// emitEmptyMapping writes "{}". Mappings are never written in flow style
// otherwise: libmodulemd asks for block style everywhere.
func (e *yamlEmitter) emitEmptyMapping() {
	e.writeIndicator("{", true, true, false)
	e.writeIndicator("}", false, false, false)
}

// yamlSimpleKey reports whether the node can be written as an implicit key:
// a single-line scalar of at most 128 bytes, or an empty collection.
func yamlSimpleKey(n *yamlNode) bool {
	switch n.kind {
	case yamlKindScalar:
		d := analyzeYAMLScalar(n.value)

		return !d.multiline && len(n.value) <= yamlMaxSimpleKey
	default:
		return len(n.items) == 0
	}
}

func (e *yamlEmitter) emitScalar(n *yamlNode) {
	d := analyzeYAMLScalar(n.value)
	style := n.style

	if e.simpleKeyCtx && d.multiline {
		style = yamlDoubleQuoted
	}

	if style == yamlPlain {
		if (e.flowLevel > 0 && !d.flowPlainOK) || (e.flowLevel == 0 && !d.blockPlainOK) {
			style = yamlSingleQuoted
		}

		if d.length == 0 && (e.flowLevel > 0 || e.simpleKeyCtx) {
			style = yamlSingleQuoted
		}
	}

	if style == yamlSingleQuoted && !d.singleQuotedOK {
		style = yamlDoubleQuoted
	}

	if style == yamlFolded && (!d.blockScalarOK || e.flowLevel > 0 || e.simpleKeyCtx) {
		style = yamlDoubleQuoted
	}

	e.increaseIndent(true, false)

	allowBreaks := !e.simpleKeyCtx

	switch style {
	case yamlPlain:
		e.writePlainScalar(d.runes, allowBreaks)
	case yamlSingleQuoted:
		e.writeSingleQuotedScalar(d.runes, allowBreaks)
	case yamlDoubleQuoted:
		e.writeDoubleQuotedScalar(d.runes, allowBreaks)
	case yamlFolded:
		e.writeFoldedScalar(d.runes)
	}

	e.popIndent()
}

func yamlIsBreak(r rune) bool {
	return r == '\r' || r == '\n' || r == 0x85 || r == 0x2028 || r == 0x2029
}

func yamlIsBlank(r rune) bool { return r == ' ' || r == '\t' }

// yamlIsPrintable mirrors libyaml: the characters of the YAML printable set
// except tab, carriage return and the C1 controls.
func yamlIsPrintable(r rune) bool {
	return r == 0x0A || (r >= 0x20 && r <= 0x7E) || (r >= 0xA0 && r <= 0xD7FF) ||
		(r >= 0xE000 && r <= 0xFFFD && r != 0xFEFF)
}

// runeAt returns the rune at i, or NUL past the end the way libyaml's
// terminated buffer does.
func runeAt(rs []rune, i int) rune {
	if i < 0 || i >= len(rs) {
		return 0
	}

	return rs[i]
}

func yamlIsBlankZAt(rs []rune, i int) bool {
	if i >= len(rs) {
		return true
	}

	return yamlIsBlank(rs[i]) || yamlIsBreak(rs[i])
}

// analyzeYAMLScalar decides which styles can carry the scalar.
func analyzeYAMLScalar(value string) yamlScalarData {
	rs := []rune(value)
	d := yamlScalarData{length: len(value), runes: rs}

	if len(rs) == 0 {
		d.blockPlainOK = true
		d.singleQuotedOK = true

		return d
	}

	var (
		blockIndicators, flowIndicators, lineBreaks, specialChars                bool
		leadingSpace, leadingBreak, trailingSpace, trailingBreak                 bool
		breakSpace, spaceBreak                                                   bool
		precededByWhitespace, followedByWhitespace, previousSpace, previousBreak bool
	)

	if len(rs) >= 3 && ((rs[0] == '-' && rs[1] == '-' && rs[2] == '-') || (rs[0] == '.' && rs[1] == '.' && rs[2] == '.')) {
		blockIndicators, flowIndicators = true, true
	}

	precededByWhitespace = true
	followedByWhitespace = yamlIsBlankZAt(rs, 1)

	for i, r := range rs {
		if i == 0 {
			switch r {
			case '#', ',', '[', ']', '{', '}', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`':
				flowIndicators, blockIndicators = true, true
			}

			if r == '?' || r == ':' {
				flowIndicators = true

				if followedByWhitespace {
					blockIndicators = true
				}
			}

			if r == '-' && followedByWhitespace {
				flowIndicators, blockIndicators = true, true
			}
		} else {
			switch r {
			case ',', '?', '[', ']', '{', '}':
				flowIndicators = true
			case ':':
				flowIndicators = true

				if followedByWhitespace {
					blockIndicators = true
				}
			case '#':
				if precededByWhitespace {
					flowIndicators, blockIndicators = true, true
				}
			}
		}

		if !yamlIsPrintable(r) {
			specialChars = true
		}

		if yamlIsBreak(r) {
			lineBreaks = true
		}

		switch {
		case r == ' ':
			if i == 0 {
				leadingSpace = true
			}

			if i == len(rs)-1 {
				trailingSpace = true
			}

			if previousBreak {
				breakSpace = true
			}

			previousSpace, previousBreak = true, false
		case yamlIsBreak(r):
			if i == 0 {
				leadingBreak = true
			}

			if i == len(rs)-1 {
				trailingBreak = true
			}

			if previousSpace {
				spaceBreak = true
			}

			previousSpace, previousBreak = false, true
		default:
			previousSpace, previousBreak = false, false
		}

		precededByWhitespace = yamlIsBlankZAt(rs, i)
		if i+1 < len(rs) {
			followedByWhitespace = yamlIsBlankZAt(rs, i+2)
		}
	}

	d.multiline = lineBreaks
	d.flowPlainOK, d.blockPlainOK, d.singleQuotedOK, d.blockScalarOK = true, true, true, true

	if leadingSpace || leadingBreak || trailingSpace || trailingBreak {
		d.flowPlainOK, d.blockPlainOK = false, false
	}

	if trailingSpace {
		d.blockScalarOK = false
	}

	if breakSpace {
		d.flowPlainOK, d.blockPlainOK, d.singleQuotedOK = false, false, false
	}

	if spaceBreak || specialChars {
		d.flowPlainOK, d.blockPlainOK, d.singleQuotedOK, d.blockScalarOK = false, false, false, false
	}

	if lineBreaks {
		d.flowPlainOK, d.blockPlainOK = false, false
	}

	if flowIndicators {
		d.flowPlainOK = false
	}

	if blockIndicators {
		d.blockPlainOK = false
	}

	return d
}

func (e *yamlEmitter) writePlainScalar(rs []rune, allowBreaks bool) {
	spaces, breaks := false, false

	if !e.whitespace && (len(rs) > 0 || e.flowLevel > 0) {
		e.put(' ')
	}

	for i, r := range rs {

		switch {
		case r == ' ':
			if allowBreaks && !spaces && e.column > yamlBestWidth && runeAt(rs, i+1) != ' ' {
				e.writeIndent()
			} else {
				e.put(r)
			}

			spaces = true
		case yamlIsBreak(r):
			if !breaks && r == '\n' {
				e.putBreak()
			}

			e.writeBreak(r)
			e.indention = true
			breaks = true
		default:
			if breaks {
				e.writeIndent()
			}

			e.put(r)
			e.indention = false
			spaces, breaks = false, false
		}
	}

	e.whitespace = false
	e.indention = false
}

func (e *yamlEmitter) writeSingleQuotedScalar(rs []rune, allowBreaks bool) {
	spaces, breaks := false, false

	e.writeIndicator("'", true, false, false)

	for i, r := range rs {

		switch {
		case r == ' ':
			if allowBreaks && !spaces && e.column > yamlBestWidth && i != 0 && i != len(rs)-1 && runeAt(rs, i+1) != ' ' {
				e.writeIndent()
			} else {
				e.put(r)
			}

			spaces = true
		case yamlIsBreak(r):
			if !breaks && r == '\n' {
				e.putBreak()
			}

			e.writeBreak(r)
			e.indention = true
			breaks = true
		default:
			if breaks {
				e.writeIndent()
			}

			if r == '\'' {
				e.put('\'')
			}

			e.put(r)
			e.indention = false
			spaces, breaks = false, false
		}
	}

	if breaks {
		e.writeIndent()
	}

	e.writeIndicator("'", false, false, false)
	e.whitespace = false
	e.indention = false
}

func (e *yamlEmitter) writeDoubleQuotedScalar(rs []rune, allowBreaks bool) {
	spaces := false

	e.writeIndicator("\"", true, false, false)

	for i, r := range rs {

		switch {
		case !yamlIsPrintable(r) || yamlIsBreak(r) || r == '"' || r == '\\':
			e.put('\\')
			e.writeEscape(r)

			spaces = false
		case r == ' ':
			if allowBreaks && !spaces && e.column > yamlBestWidth && i != 0 && i != len(rs)-1 {
				e.writeIndent()

				if runeAt(rs, i+1) == ' ' {
					e.put('\\')
				}
			} else {
				e.put(r)
			}

			spaces = true
		default:
			e.put(r)

			spaces = false
		}
	}

	e.writeIndicator("\"", false, false, false)
	e.whitespace = false
	e.indention = false
}

// writeEscape writes what follows the backslash of a double-quoted escape.
func (e *yamlEmitter) writeEscape(r rune) {
	switch r {
	case 0x00:
		e.put('0')
	case 0x07:
		e.put('a')
	case 0x08:
		e.put('b')
	case 0x09:
		e.put('t')
	case 0x0A:
		e.put('n')
	case 0x0B:
		e.put('v')
	case 0x0C:
		e.put('f')
	case 0x0D:
		e.put('r')
	case 0x1B:
		e.put('e')
	case 0x22:
		e.put('"')
	case 0x5C:
		e.put('\\')
	case 0x85:
		e.put('N')
	case 0xA0:
		e.put('_')
	case 0x2028:
		e.put('L')
	case 0x2029:
		e.put('P')
	default:
		width := 8

		switch {
		case r <= 0xFF:
			e.put('x')

			width = 2
		case r <= 0xFFFF:
			e.put('u')

			width = 4
		default:
			e.put('U')
		}

		const digits = "0123456789ABCDEF"

		for k := (width - 1) * 4; k >= 0; k -= 4 {
			e.put(rune(digits[(r>>k)&0x0F]))
		}
	}
}

// writeBlockScalarHints writes the indentation and chomping indicators of a
// block scalar header.
func (e *yamlEmitter) writeBlockScalarHints(rs []rune) {
	if len(rs) > 0 && (rs[0] == ' ' || yamlIsBreak(rs[0])) {
		e.writeIndicator(string(rune('0'+yamlBestIndent)), false, false, false)
	}

	chomp := ""

	switch n := len(rs); {
	case n == 0 || !yamlIsBreak(rs[n-1]):
		chomp = "-"
	case n == 1 || yamlIsBreak(rs[n-2]):
		chomp = "+"
	}

	if chomp != "" {
		e.writeIndicator(chomp, false, false, false)
	}
}

func (e *yamlEmitter) writeFoldedScalar(rs []rune) {
	breaks, leadingSpaces := true, true

	e.writeIndicator(">", true, false, false)
	e.writeBlockScalarHints(rs)
	e.putBreak()

	e.indention = true
	e.whitespace = true

	for i, r := range rs {

		if yamlIsBreak(r) {
			if !breaks && !leadingSpaces && r == '\n' {
				k := 0
				for i+k < len(rs) && yamlIsBreak(rs[i+k]) {
					k++
				}

				if !yamlIsBlankZAt(rs, i+k) {
					e.putBreak()
				}
			}

			e.writeBreak(r)
			e.indention = true
			breaks = true

			continue
		}

		if breaks {
			e.writeIndent()

			leadingSpaces = yamlIsBlank(r)
		}

		// libyaml also folds a line that starts with a blank, which makes a
		// reader keep the break; such a line is left long instead.
		if !breaks && !leadingSpaces && r == ' ' && runeAt(rs, i+1) != ' ' && e.column > yamlBestWidth {
			e.writeIndent()
		} else {
			e.put(r)
		}

		e.indention = false
		breaks = false
	}
}

// checkYAMLText fails on a scalar that is not valid UTF-8, which the YAML
// output could not carry.
func checkYAMLText(n *yamlNode) error {
	if n.kind == yamlKindScalar {
		if !utf8.ValidString(n.value) {
			return fmt.Errorf("%q is not valid UTF-8", n.value)
		}

		return nil
	}

	for _, item := range n.items {
		if err := checkYAMLText(item); err != nil {
			return err
		}
	}

	return nil
}
