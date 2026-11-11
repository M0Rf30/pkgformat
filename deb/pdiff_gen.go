package deb

import (
	"bytes"
	"fmt"
	"strconv"
)

// Default limits of PDiffGenerateOptions.
const (
	// DefaultMaxPDiffLines is the default bound on the lines of either file.
	DefaultMaxPDiffLines = 1 << 24
	// DefaultMaxPDiffEditDistance is the default bound on the edit distance
	// GeneratePDiff searches for.
	DefaultMaxPDiffEditDistance = 1 << 16
)

// PDiffGenerateOptions bounds GeneratePDiff. The zero value selects the
// defaults.
type PDiffGenerateOptions struct {
	// MaxLines bounds the number of lines of either file;
	// DefaultMaxPDiffLines when zero. Larger files fail with ErrPDiffLimit.
	MaxLines int
	// MaxEditDistance bounds the number of inserted plus deleted lines the
	// search looks for: its cost grows with the square of it. Where two
	// stretches of the files differ by more, the stretch is replaced as a
	// whole instead of being compared line by line, which stays correct but is
	// larger. DefaultMaxPDiffEditDistance when zero.
	MaxEditDistance int
}

// GeneratePDiff returns the ed script that turns old into new, in the dialect
// apt's rred reads: "Na", "Nc", "N,Mc", "Nd" and "N,Md" commands from the end
// of the file to its start, as diff --ed writes them. The script is built
// from a shortest edit script over lines (Myers' O(ND) algorithm), so it is as
// small as the line-based edit distance allows unless the files differ by more
// than DefaultMaxPDiffEditDistance, where the stretches that differ are
// replaced whole. Identical files give an empty script.
//
// New text a script cannot carry fails with ErrPDiffUnrepresentable: a line
// that is just ".", which would end the text of a command, and a final line
// without a newline.
func GeneratePDiff(old, newData []byte) ([]byte, error) {
	return GeneratePDiffWith(old, newData, PDiffGenerateOptions{})
}

// GeneratePDiffWith is GeneratePDiff with explicit limits.
func GeneratePDiffWith(old, newData []byte, opts PDiffGenerateOptions) ([]byte, error) {
	if opts.MaxLines <= 0 {
		opts.MaxLines = DefaultMaxPDiffLines
	}

	if opts.MaxEditDistance <= 0 {
		opts.MaxEditDistance = DefaultMaxPDiffEditDistance
	}

	oldLines, newLines := splitPDiffLines(old), splitPDiffLines(newData)
	if len(oldLines) > opts.MaxLines || len(newLines) > opts.MaxLines {
		return nil, fmt.Errorf("%w: more than %d lines", ErrPDiffLimit, opts.MaxLines)
	}

	d := newPDiffDiffer(oldLines, newLines, opts.MaxEditDistance)
	d.compare(0, len(d.a), 0, len(d.b))

	return d.script(oldLines, newLines)
}

// splitPDiffLines splits data into lines that keep their newline; a last line
// without one is a line too.
func splitPDiffLines(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}

	lines := make([][]byte, 0, bytes.Count(data, []byte{'\n'})+1)

	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			lines = append(lines, data)

			break
		}

		lines = append(lines, data[:i+1])
		data = data[i+1:]
	}

	return lines
}

// pdiffDiffer finds the lines of two files that differ. The lines are interned
// as integers so that comparing two of them is cheap.
type pdiffDiffer struct {
	a, b []int32
	// delA and insB mark the lines of a that are deleted and of b that are inserted.
	delA, insB []bool
	// vf and vb are the furthest-reaching tables of the forward and backward
	// search, shared by all recursion levels.
	vf, vb []int
	// maxHalf is the bound on the number of edits one search direction takes.
	maxHalf int
}

func newPDiffDiffer(oldLines, newLines [][]byte, maxEditDistance int) *pdiffDiffer {
	ids := make(map[string]int32, len(oldLines)+len(newLines))
	intern := func(lines [][]byte) []int32 {
		out := make([]int32, len(lines))

		for i, l := range lines {
			id, ok := ids[string(l)]
			if !ok {
				id = int32(len(ids))
				ids[string(l)] = id
			}

			out[i] = id
		}

		return out
	}

	d := &pdiffDiffer{maxHalf: (maxEditDistance + 1) / 2}
	d.a, d.b = intern(oldLines), intern(newLines)
	d.delA = make([]bool, len(d.a))
	d.insB = make([]bool, len(d.b))

	return d
}

// compare marks the differences between a[aLo:aHi] and b[bLo:bHi].
func (d *pdiffDiffer) compare(aLo, aHi, bLo, bHi int) {
	for aLo < aHi && bLo < bHi && d.a[aLo] == d.b[bLo] {
		aLo++
		bLo++
	}

	for aLo < aHi && bLo < bHi && d.a[aHi-1] == d.b[bHi-1] {
		aHi--
		bHi--
	}

	switch {
	case aLo == aHi:
		d.markInserted(bLo, bHi)

		return
	case bLo == bHi:
		d.markDeleted(aLo, aHi)

		return
	}

	x, y, ok := d.bisect(aLo, aHi, bLo, bHi)
	if !ok || (x == 0 && y == 0) || (x == aHi-aLo && y == bHi-bLo) {
		d.markDeleted(aLo, aHi)
		d.markInserted(bLo, bHi)

		return
	}

	d.compare(aLo, aLo+x, bLo, bLo+y)
	d.compare(aLo+x, aHi, bLo+y, bHi)
}

func (d *pdiffDiffer) markDeleted(lo, hi int) {
	for i := lo; i < hi; i++ {
		d.delA[i] = true
	}
}

func (d *pdiffDiffer) markInserted(lo, hi int) {
	for i := lo; i < hi; i++ {
		d.insB[i] = true
	}
}

// bisect finds a point (x, y), relative to the start of the ranges, that lies
// on a shortest edit path between them: the middle snake of Myers' linear
// space refinement, found by searching from both ends at once. ok is false
// when the search gave up at the edit distance bound.
func (d *pdiffDiffer) bisect(aLo, aHi, bLo, bHi int) (x, y int, ok bool) {
	n, m := aHi-aLo, bHi-bLo
	delta := n - m
	odd := delta&1 != 0
	maxD := min((n+m+1)/2, d.maxHalf)
	off := maxD + 1
	size := 2*off + 2

	if cap(d.vf) < size {
		d.vf, d.vb = make([]int, size), make([]int, size)
	}

	vf, vb := d.vf[:size], d.vb[:size]
	for i := range vf {
		vf[i], vb[i] = -1, -1
	}

	vf[off+1], vb[off+1] = 0, 0

	// The ranges of diagonals still inside the edit grid.
	k1Start, k1End, k2Start, k2End := 0, 0, 0, 0

	for dd := range maxD {
		for k1 := -dd + k1Start; k1 <= dd-k1End; k1 += 2 {
			ko := off + k1

			var x1 int
			if k1 == -dd || (k1 != dd && vf[ko-1] < vf[ko+1]) {
				x1 = vf[ko+1]
			} else {
				x1 = vf[ko-1] + 1
			}

			y1 := x1 - k1

			for x1 < n && y1 < m && d.a[aLo+x1] == d.b[bLo+y1] {
				x1++
				y1++
			}

			vf[ko] = x1

			switch {
			case x1 > n:
				k1End += 2
			case y1 > m:
				k1Start += 2
			case odd:
				k2o := off + delta - k1
				if k2o >= 0 && k2o < size && vb[k2o] != -1 && x1 >= n-vb[k2o] {
					return x1, y1, true
				}
			}
		}

		for k2 := -dd + k2Start; k2 <= dd-k2End; k2 += 2 {
			ko := off + k2

			var x2 int
			if k2 == -dd || (k2 != dd && vb[ko-1] < vb[ko+1]) {
				x2 = vb[ko+1]
			} else {
				x2 = vb[ko-1] + 1
			}

			y2 := x2 - k2

			for x2 < n && y2 < m && d.a[aHi-x2-1] == d.b[bHi-y2-1] {
				x2++
				y2++
			}

			vb[ko] = x2

			switch {
			case x2 > n:
				k2End += 2
			case y2 > m:
				k2Start += 2
			case !odd:
				k1o := off + delta - k2
				if k1o >= 0 && k1o < size && vf[k1o] != -1 {
					x1 := vf[k1o]
					y1 := x1 - (k1o - off)

					if x1 >= n-x2 {
						return x1, y1, true
					}
				}
			}
		}
	}

	return 0, 0, false
}

// script writes the ed script of the marked differences, last hunk first.
func (d *pdiffDiffer) script(oldLines, newLines [][]byte) ([]byte, error) {
	type hunk struct{ at, del, addLo, addHi int }

	var hunks []hunk

	for i, j := 0, 0; i < len(d.a) || j < len(d.b); {
		if i < len(d.a) && j < len(d.b) && !d.delA[i] && !d.insB[j] {
			i++
			j++

			continue
		}

		h := hunk{at: i, addLo: j}

		for i < len(d.a) && d.delA[i] {
			i++
		}

		for j < len(d.b) && d.insB[j] {
			j++
		}

		h.del, h.addHi = i-h.at, j
		hunks = append(hunks, h)
	}

	var out bytes.Buffer

	for k := len(hunks) - 1; k >= 0; k-- {
		h := hunks[k]
		add := newLines[h.addLo:h.addHi]

		switch {
		case h.del == 0:
			out.WriteString(strconv.Itoa(h.at) + "a\n")
		case len(add) == 0:
			writePDiffRange(&out, h.at+1, h.at+h.del)
			out.WriteString("d\n")

			continue
		default:
			writePDiffRange(&out, h.at+1, h.at+h.del)
			out.WriteString("c\n")
		}

		for _, l := range add {
			if string(l) == ".\n" || l[len(l)-1] != '\n' {
				return nil, fmt.Errorf("%w: line %q of the new file", ErrPDiffUnrepresentable, bytes.TrimRight(l, "\n"))
			}

			out.Write(l)
		}

		out.WriteString(".\n")
	}

	return pdiffBytes(&out), nil
}

// pdiffBytes returns the content of b, an empty slice rather than nil when b is empty.
func pdiffBytes(b *bytes.Buffer) []byte {
	if b.Len() == 0 {
		return []byte{}
	}

	return b.Bytes()
}

// writePDiffRange writes the address "N" or "N,M" of lines first..last.
func writePDiffRange(out *bytes.Buffer, first, last int) {
	out.WriteString(strconv.Itoa(first))

	if last != first {
		out.WriteString("," + strconv.Itoa(last))
	}
}
