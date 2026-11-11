package deb_test

import (
	"fmt"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

// pdiffCommands matches the command lines of a script (its text lines start with "line").
var pdiffCommands = regexp.MustCompile(`(?m)^\d+(,\d+)?[acd]$`)

// pdiffRandomFile returns a file of n lines drawn from an alphabet of the given size.
func pdiffRandomFile(r *rand.Rand, n, alphabet int) string {
	var sb strings.Builder

	for range n {
		sb.WriteString("line " + strconv.Itoa(r.IntN(alphabet)) + "\n")
	}

	return sb.String()
}

// pdiffMutate edits a file at random: deletes, inserts and replaces runs of lines.
func pdiffMutate(r *rand.Rand, in string, edits, alphabet int) string {
	lines := strings.SplitAfter(in, "\n")
	lines = lines[:len(lines)-1]

	for range edits {
		if len(lines) == 0 {
			lines = append(lines, "line x\n")

			continue
		}

		at := r.IntN(len(lines))
		n := 1 + r.IntN(4)

		switch r.IntN(3) {
		case 0:
			lines = append(lines[:at], lines[min(at+n, len(lines)):]...)
		case 1:
			ins := make([]string, n)
			for i := range ins {
				ins[i] = "line " + strconv.Itoa(r.IntN(alphabet)) + "\n"
			}

			lines = append(lines[:at], append(ins, lines[at:]...)...)
		default:
			for i := at; i < min(at+n, len(lines)); i++ {
				lines[i] = "line " + strconv.Itoa(r.IntN(alphabet)) + "\n"
			}
		}
	}

	return strings.Join(lines, "")
}

// pdiffLCS is the textbook dynamic program: the reference for the minimal
// number of changed lines.
func pdiffLCS(a, b []string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)

	for i := range a {
		for j := range b {
			switch {
			case a[i] == b[j]:
				cur[j+1] = prev[j] + 1
			case cur[j] >= prev[j+1]:
				cur[j+1] = cur[j]
			default:
				cur[j+1] = prev[j+1]
			}
		}

		prev, cur = cur, prev
	}

	return prev[len(b)]
}

// pdiffScriptCost counts the lines a script deletes and inserts.
func pdiffScriptCost(tb testing.TB, script string) int {
	tb.Helper()

	cost := 0
	inText := false

	for _, l := range strings.SplitAfter(script, "\n") {
		l = strings.TrimSuffix(l, "\n")

		switch {
		case l == "":
		case inText && l == ".":
			inText = false
		case inText:
			cost++
		default:
			op := l[len(l)-1]
			addr := l[:len(l)-1]
			first, last, ranged := strings.Cut(addr, ",")
			f, err := strconv.Atoi(first)
			require.NoError(tb, err)

			if op != 'a' {
				cost++

				if ranged {
					la, err := strconv.Atoi(last)
					require.NoError(tb, err)

					cost += la - f
				}
			}

			inText = op != 'd'
		}
	}

	return cost
}

func TestPDiffGenerateRoundTripAndMinimal(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))

	for i := range 600 {
		alphabet := 2 + r.IntN(12)
		a := pdiffRandomFile(r, r.IntN(40), alphabet)
		b := pdiffMutate(r, a, r.IntN(6), alphabet)

		if i%5 == 0 {
			b = pdiffRandomFile(r, r.IntN(40), alphabet)
		}

		patch, err := deb.GeneratePDiff([]byte(a), []byte(b))
		require.NoError(t, err)

		got, err := deb.ApplyPDiff([]byte(a), patch)
		require.NoError(t, err, "a=%q b=%q patch=%q", a, b, patch)
		require.Equal(t, b, string(got), "a=%q patch=%q", a, patch)

		al := strings.SplitAfter(a, "\n")
		bl := strings.SplitAfter(b, "\n")
		al, bl = al[:len(al)-1], bl[:len(bl)-1]

		want := len(al) + len(bl) - 2*pdiffLCS(al, bl)
		require.Equal(t, want, pdiffScriptCost(t, string(patch)), "not minimal: a=%q b=%q patch=%q", a, b, patch)
	}
}

func TestPDiffGenerateShapes(t *testing.T) {
	cases := []struct {
		name, a, b, patch string
	}{
		{"identical", "a\nb\n", "a\nb\n", ""},
		{"both empty", "", "", ""},
		{"from empty", "", "a\nb\n", "0a\na\nb\n.\n"},
		{"to empty", "a\nb\n", "", "1,2d\n"},
		{"replace all", "a\nb\n", "x\ny\nz\n", "1,2c\nx\ny\nz\n.\n"},
		{"append", "a\nb\n", "a\nb\nc\n", "2a\nc\n.\n"},
		{"prepend", "b\n", "a\nb\n", "0a\na\n.\n"},
		{"delete middle", "a\nb\nc\n", "a\nc\n", "2d\n"},
		{"change middle", "a\nb\nc\n", "a\nX\nc\n", "2c\nX\n.\n"},
		{"two hunks last first", "a\nb\nc\nd\ne\n", "A\nb\nc\nd\nE\n", "5c\nE\n.\n1c\nA\n.\n"},
		{"unterminated last line kept", "a\nb", "A\nb", "1c\nA\n.\n"},
		{"unterminated last line deleted", "a\nb", "a\n", "2d\n"},
		{"unterminated old, added after", "a\n", "a\nb\n", "1a\nb\n.\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			patch, err := deb.GeneratePDiff([]byte(tc.a), []byte(tc.b))
			require.NoError(t, err)
			require.Equal(t, tc.patch, string(patch))
			require.NotNil(t, patch)

			got, err := deb.ApplyPDiff([]byte(tc.a), patch)
			require.NoError(t, err)
			require.Equal(t, tc.b, string(got))
		})
	}
}

func TestPDiffGenerateUnrepresentable(t *testing.T) {
	for name, tc := range map[string][2]string{
		"dot line added":          {"a\n", "a\n.\nb\n"},
		"dot line replaces":       {"a\nb\n", "a\n.\n"},
		"no newline at the end":   {"a\n", "a\nb"},
		"no newline, last edited": {"a\nb", "a\nc"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := deb.GeneratePDiff([]byte(tc[0]), []byte(tc[1]))
			require.ErrorIs(t, err, deb.ErrPDiffUnrepresentable)
		})
	}

	// A dot line that stays is no problem, nor is an unterminated one that stays.
	patch, err := deb.GeneratePDiff([]byte("a\n.\nb\n"), []byte("A\n.\nb\n"))
	require.NoError(t, err)
	require.Equal(t, "1c\nA\n.\n", string(patch))

	// Deleting a dot line is fine too.
	patch, err = deb.GeneratePDiff([]byte("a\n.\nb\n"), []byte("a\nb\n"))
	require.NoError(t, err)
	require.Equal(t, "2d\n", string(patch))
}

func TestPDiffGenerateLimits(t *testing.T) {
	_, err := deb.GeneratePDiffWith([]byte("a\nb\nc\n"), []byte("a\n"), deb.PDiffGenerateOptions{MaxLines: 2})
	require.ErrorIs(t, err, deb.ErrPDiffLimit)

	_, err = deb.GeneratePDiffWith([]byte("a\n"), []byte("a\nb\nc\n"), deb.PDiffGenerateOptions{MaxLines: 2})
	require.ErrorIs(t, err, deb.ErrPDiffLimit)
}

func TestPDiffGenerateEditDistanceFallback(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	a := pdiffRandomFile(r, 400, 50)
	b := pdiffMutate(r, a, 60, 50)

	full, err := deb.GeneratePDiff([]byte(a), []byte(b))
	require.NoError(t, err)

	for _, limit := range []int{1, 2, 5, 40} {
		patch, err := deb.GeneratePDiffWith([]byte(a), []byte(b), deb.PDiffGenerateOptions{MaxEditDistance: limit})
		require.NoError(t, err)

		got, err := deb.ApplyPDiff([]byte(a), patch)
		require.NoError(t, err)
		require.Equal(t, b, string(got), "limit %d", limit)
		require.GreaterOrEqual(t, len(patch), len(full), "a bounded search cannot beat the exact one")
	}

	// With a bound of 1 nothing is matched but the common ends: one big hunk.
	one, err := deb.GeneratePDiffWith([]byte(a), []byte(b), deb.PDiffGenerateOptions{MaxEditDistance: 1})
	require.NoError(t, err)
	require.LessOrEqual(t, len(pdiffCommands.FindAllString(string(one), -1)), 1, "a bound of 1 replaces the stretch between the common ends whole")
}

func TestPDiffGenerateLargeFile(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))

	var sb strings.Builder

	for i := range 60000 {
		fmt.Fprintf(&sb, "Package: p%d\nVersion: 1.%d\n\n", i, r.IntN(1000))
	}

	a := sb.String()
	b := pdiffMutate(r, a, 300, 1000)

	patch, err := deb.GeneratePDiff([]byte(a), []byte(b))
	require.NoError(t, err)
	require.Less(t, len(patch), len(a)/20)

	got, err := deb.ApplyPDiff([]byte(a), patch)
	require.NoError(t, err)
	require.Equal(t, b, string(got))
}

func TestPDiffMerge(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 8))

	for range 400 {
		alphabet := 2 + r.IntN(10)
		v := []string{pdiffRandomFile(r, r.IntN(30), alphabet)}

		for range 1 + r.IntN(4) {
			v = append(v, pdiffMutate(r, v[len(v)-1], r.IntN(5), alphabet))
		}

		var patches [][]byte

		for i := 1; i < len(v); i++ {
			p, err := deb.GeneratePDiff([]byte(v[i-1]), []byte(v[i]))
			require.NoError(t, err)

			patches = append(patches, p)
		}

		merged, err := deb.MergePDiffs(patches...)
		require.NoError(t, err)

		got, err := deb.ApplyPDiff([]byte(v[0]), merged)
		require.NoError(t, err, "versions=%q merged=%q", v, merged)
		require.Equal(t, v[len(v)-1], string(got), "versions=%q merged=%q", v, merged)
	}
}

func TestPDiffMergeEdges(t *testing.T) {
	m, err := deb.MergePDiffs()
	require.NoError(t, err)
	require.Empty(t, m)

	m, err = deb.MergePDiffs([]byte("2d\n"))
	require.NoError(t, err)
	require.Equal(t, "2d\n", string(m))

	// A later patch that undoes an earlier one leaves nothing.
	m, err = deb.MergePDiffs([]byte("1a\nx\n.\n"), []byte("2d\n"))
	require.NoError(t, err)
	require.Empty(t, m)

	// Changes that touch each other fuse into one command.
	m, err = deb.MergePDiffs([]byte("2c\nB\n.\n"), []byte("2,3c\nBC\n.\n"))
	require.NoError(t, err)
	require.Equal(t, "2,3c\nBC\n.\n", string(m))

	// An append is rewritten when the second patch deletes part of the text.
	m, err = deb.MergePDiffs([]byte("1a\nx\ny\nz\n.\n"), []byte("3d\n"))
	require.NoError(t, err)
	require.Equal(t, "1a\nx\nz\n.\n", string(m))

	_, err = deb.MergePDiffs([]byte("1d\n"), []byte("garbage\n"))
	require.ErrorIs(t, err, deb.ErrPDiffScript)

	_, err = deb.MergePDiffsWith(deb.PDiffApplyOptions{MaxPatchSize: 3}, []byte("1d\n"), []byte("1d\n2d\n"))
	require.ErrorIs(t, err, deb.ErrPDiffLimit)
}
