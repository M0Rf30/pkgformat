package deb

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
)

// pdiffOp is one step of a patch seen as a walk over the file it applies to:
// keep n lines, drop n lines, or insert lines. A keep of math.MaxInt is "the
// rest of the file".
type pdiffOp struct {
	kind  byte // '=', '-' or '+'
	n     int
	lines [][]byte // for '+': the inserted lines, each with its newline
}

// pdiffOps turns the edits of a patch (in file order) into ops that end in a
// keep of the rest of the file.
func pdiffOps(edits []pdiffEdit) []pdiffOp {
	var (
		ops []pdiffOp
		pos int
	)

	for _, e := range edits {
		if e.at > pos {
			ops = append(ops, pdiffOp{kind: '=', n: e.at - pos})
		}

		if e.del > 0 {
			ops = append(ops, pdiffOp{kind: '-', n: e.del})
		}

		if e.lines > 0 {
			ops = append(ops, pdiffOp{kind: '+', n: e.lines, lines: splitPDiffLines(e.text)})
		}

		pos = e.at + e.del
	}

	return append(ops, pdiffOp{kind: '=', n: math.MaxInt})
}

// pdiffCursor walks over the output lines of an op list; deletions it passes
// on the way are handed to the caller, as they are changes to the original
// file that the walk does not consume.
type pdiffCursor struct {
	ops  []pdiffOp
	i    int
	used int // lines already consumed from ops[i]
}

// take consumes up to n output lines (all of them when n is math.MaxInt) and
// emits what they were made of: kept lines as keeps, inserted lines as inserts,
// and the deletions met on the way as deletions. When drop is set the lines
// are dropped instead of kept: kept lines become deletions of the original
// file and inserted lines vanish.
func (c *pdiffCursor) take(n int, drop bool, emit func(pdiffOp)) {
	for n > 0 && c.i < len(c.ops) {
		op := c.ops[c.i]

		if op.kind == '-' {
			emit(op)

			c.i++
			c.used = 0

			continue
		}

		avail := op.n - c.used
		if op.n == math.MaxInt {
			avail = math.MaxInt
		}

		k := min(n, avail)

		switch {
		case op.kind == '=' && drop:
			emit(pdiffOp{kind: '-', n: k})
		case op.kind == '=':
			emit(pdiffOp{kind: '=', n: k})
		case !drop:
			emit(pdiffOp{kind: '+', n: k, lines: op.lines[c.used : c.used+k]})
		}

		if n != math.MaxInt {
			n -= k
		}

		if op.n == math.MaxInt {
			if n == math.MaxInt {
				return
			}

			continue
		}

		c.used += k
		if c.used == op.n {
			c.i++
			c.used = 0
		}
	}
}

// drain emits the rest of the walk unchanged.
func (c *pdiffCursor) drain(emit func(pdiffOp)) { c.take(math.MaxInt, false, emit) }

// composePDiffOps returns the ops of applying second after first.
func composePDiffOps(first, second []pdiffOp) []pdiffOp {
	var out []pdiffOp

	emit := func(op pdiffOp) { out = append(out, op) }
	c := &pdiffCursor{ops: first}

	for _, op := range second {
		switch op.kind {
		case '=':
			c.take(op.n, false, emit)
		case '-':
			c.take(op.n, true, emit)
		default:
			emit(op)
		}
	}

	c.drain(emit)

	return out
}

// pdiffScriptOf writes the ed script of ops, last command first. Between two
// kept stretches the deletions and insertions are combined into one command,
// as rred does.
func pdiffScriptOf(ops []pdiffOp) []byte {
	type hunk struct {
		at, del int
		add     [][]byte
	}

	var (
		hunks []hunk
		pos   int
		cur   *hunk
	)

	flush := func() {
		if cur != nil && (cur.del > 0 || len(cur.add) > 0) {
			hunks = append(hunks, *cur)
		}

		cur = nil
	}

	for _, op := range ops {
		switch op.kind {
		case '=':
			flush()

			if op.n != math.MaxInt {
				pos += op.n
			}
		case '-':
			if cur == nil {
				cur = &hunk{at: pos}
			}

			cur.del += op.n
			pos += op.n
		default:
			if cur == nil {
				cur = &hunk{at: pos}
			}

			cur.add = append(cur.add, op.lines...)
		}
	}

	flush()

	var out bytes.Buffer

	for k := len(hunks) - 1; k >= 0; k-- {
		h := hunks[k]

		if h.del == 0 {
			out.WriteString(strconv.Itoa(h.at) + "a\n")
		} else {
			writePDiffRange(&out, h.at+1, h.at+h.del)

			if len(h.add) == 0 {
				out.WriteString("d\n")

				continue
			}

			out.WriteString("c\n")
		}

		for _, l := range h.add {
			out.Write(l)
		}

		out.WriteString(".\n")
	}

	return pdiffBytes(&out)
}

// MergePDiffs combines patches into one that does the work of all of them:
// applying the result to a file gives what applying the patches in turn would.
// The first patch is the one applied first. This is what apt's rred does to
// merge the patches of a series, and what a server does to publish merged
// patches (X-Patch-Precedence: merged). It is MergePDiffsWith with the
// default limits.
func MergePDiffs(patches ...[]byte) ([]byte, error) {
	return MergePDiffsWith(PDiffApplyOptions{}, patches...)
}

// MergePDiffsWith is MergePDiffs with explicit limits; only MaxPatchSize and
// MaxCommands apply. The patches need not fit any particular file, but must
// fit each other: a patch that deletes or keeps lines the earlier ones did not
// leave there is not noticed here, only when the merged patch is applied.
func MergePDiffsWith(opts PDiffApplyOptions, patches ...[]byte) ([]byte, error) {
	opts = opts.withDefaults()

	if len(patches) == 0 {
		return []byte{}, nil
	}

	var merged []pdiffOp

	for i, p := range patches {
		if int64(len(p)) > opts.MaxPatchSize {
			return nil, pdiffLimitErr("patch %d exceeds %d bytes", i+1, opts.MaxPatchSize)
		}

		edits, err := parsePDiffScript(p, opts)
		if err != nil {
			return nil, fmt.Errorf("deb: merging pdiff %d: %w", i+1, err)
		}

		ops := pdiffOps(edits)
		if i == 0 {
			merged = ops

			continue
		}

		merged = composePDiffOps(merged, ops)
	}

	return pdiffScriptOf(merged), nil
}
