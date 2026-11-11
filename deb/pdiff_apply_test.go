package deb_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

func TestPDiffApplySemantics(t *testing.T) {
	// The table is shared with the interop tests, where rred and ed confirm it.
	for _, tc := range pdiffSemanticCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deb.ApplyPDiff([]byte(pdiffSemanticBase), []byte(tc.patch))
			require.NoError(t, err)
			require.Equal(t, tc.want, string(got))
		})
	}
}

func TestPDiffApplyUnterminatedLastLine(t *testing.T) {
	// A file whose last line has no newline keeps it that way when the patch
	// does not touch that line.
	got, err := deb.ApplyPDiff([]byte("a\nb\nc"), []byte("1c\nA\n.\n"))
	require.NoError(t, err)
	require.Equal(t, "A\nb\nc", string(got))

	// Replacing it works as well.
	got, err = deb.ApplyPDiff([]byte("a\nb\nc"), []byte("3c\nC\n.\n"))
	require.NoError(t, err)
	require.Equal(t, "a\nb\nC\n", string(got))

	// Deleting it.
	got, err = deb.ApplyPDiff([]byte("a\nb\nc"), []byte("3d\n"))
	require.NoError(t, err)
	require.Equal(t, "a\nb\n", string(got))

	// Bytes that are kept are copied as they are, as rred does (ed would add
	// the missing newline): text appended after such a line follows it directly.
	// Measured with rred of apt 2.6.2.
	got, err = deb.ApplyPDiff([]byte("a\nb"), []byte("2a\nx\n.\n"))
	require.NoError(t, err)
	require.Equal(t, "a\nbx\n", string(got))

	got, err = deb.ApplyPDiff([]byte("a\nb"), []byte("1d\n"))
	require.NoError(t, err)
	require.Equal(t, "b", string(got))
}

func TestPDiffApplyMalformed(t *testing.T) {
	base := []byte("1\n2\n3\n")

	cases := map[string]struct {
		patch string
		line  int
	}{
		"unknown command":        {"1x\n", 1},
		"substitute":             {"1a\nx\n.\ns/x/y/\n", 4},
		"write command":          {"w\n", 1},
		"no address":             {"a\nx\n.\n", 1},
		"letter only":            {"d\n", 1},
		"negative":               {"-1d\n", 1},
		"plus":                   {"+1d\n", 1},
		"huge":                   {"99999999999999999999d\n", 1},
		"bad range":              {"3,1d\n", 1},
		"empty range end":        {"1,d\n", 1},
		"range append":           {"1,2a\nx\n.\n", 1},
		"change line zero":       {"0c\nx\n.\n", 1},
		"delete line zero":       {"0d\n", 1},
		"ascending":              {"1d\n3d\n", 2},
		"overlap":                {"2,3d\n1,2d\n", 2},
		"unterminated text":      {"1a\nx\n", 1},
		"missing final newline":  {"1d", 1},
		"text without newline":   {"1a\nx\n.", 3},
		"change then append":     {"3c\nC\n.\n3a\nA\n.\n", 4},
		"trailing garbage":       {"1d x\n", 1},
		"carriage return":        {"1d\r\n", 1},
		"space":                  {" 1d\n", 1},
		"blank":                  {"\n", 1},
		"unterminated then cmds": {"2a\nx\n1d\n", 1},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := deb.ApplyPDiff(base, []byte(tc.patch))
			require.ErrorIs(t, err, deb.ErrPDiffScript)

			var pe *deb.PDiffError

			require.ErrorAs(t, err, &pe)
			require.Equal(t, tc.line, pe.Line, pe.Error())
			require.NotEmpty(t, pe.Reason)
			require.NotErrorIs(t, err, deb.ErrPDiffLimit)
		})
	}
}

func TestPDiffApplyBeyondTheFile(t *testing.T) {
	base := []byte("1\n2\n3\n")

	for _, patch := range []string{"4a\nx\n.\n", "4d\n", "2,4d\n", "5c\nx\n.\n", "9,10d\n", "1,4c\nx\n.\n"} {
		_, err := deb.ApplyPDiff(base, []byte(patch))
		require.ErrorIs(t, err, deb.ErrPDiffScript, patch)

		var pe *deb.PDiffError

		require.ErrorAs(t, err, &pe)
		require.Zero(t, pe.Line, "the error is about the file, not a script line")
	}

	// Exactly the last line is fine.
	_, err := deb.ApplyPDiff(base, []byte("3a\nx\n.\n"))
	require.NoError(t, err)

	// An empty file takes an append at line 0 only.
	got, err := deb.ApplyPDiff(nil, []byte("0a\nx\n.\n"))
	require.NoError(t, err)
	require.Equal(t, "x\n", string(got))

	_, err = deb.ApplyPDiff(nil, []byte("1d\n"))
	require.ErrorIs(t, err, deb.ErrPDiffScript)
}

func TestPDiffApplyLimits(t *testing.T) {
	base := []byte("1\n2\n3\n")

	_, err := deb.ApplyPDiffWith(base, []byte("1d\n2d\n"), deb.PDiffApplyOptions{MaxPatchSize: 4})
	require.ErrorIs(t, err, deb.ErrPDiffLimit)

	_, err = deb.ApplyPDiffWith(base, []byte("3d\n2d\n1d\n"), deb.PDiffApplyOptions{MaxCommands: 2})
	require.ErrorIs(t, err, deb.ErrPDiffLimit)

	got, err := deb.ApplyPDiffWith(base, []byte("3d\n2d\n"), deb.PDiffApplyOptions{MaxCommands: 2})
	require.NoError(t, err)
	require.Equal(t, "1\n", string(got))

	_, err = deb.ApplyPDiffWith(base, []byte("0a\n"+strings.Repeat("xxxxxxxx\n", 10)+".\n"), deb.PDiffApplyOptions{MaxResultSize: 50})
	require.ErrorIs(t, err, deb.ErrPDiffLimit)

	var pe *deb.PDiffError

	require.ErrorAs(t, err, &pe)
	require.NotErrorIs(t, err, deb.ErrPDiffScript)

	// A result at the limit passes.
	_, err = deb.ApplyPDiffWith(base, nil, deb.PDiffApplyOptions{MaxResultSize: int64(len(base))})
	require.NoError(t, err)
}

func TestPDiffApplyToStreams(t *testing.T) {
	// A base with a line longer than the read buffer, streamed in pieces.
	long := strings.Repeat("x", 200<<10)
	base := "first\n" + long + "\nthird\nlast-without-newline"

	var out bytes.Buffer

	n, err := deb.ApplyPDiffTo(&out, iotest.OneByteReader(strings.NewReader(base)), strings.NewReader("3c\nTHIRD\n.\n1d\n"), deb.PDiffApplyOptions{})
	require.NoError(t, err)
	require.Equal(t, int64(out.Len()), n)
	require.Equal(t, long+"\nTHIRD\nlast-without-newline", out.String())

	// Reading the patch can fail, and so can the base and the sink.
	boom := errors.New("boom")

	_, err = deb.ApplyPDiffTo(io.Discard, strings.NewReader(base), iotest.ErrReader(boom), deb.PDiffApplyOptions{})
	require.ErrorIs(t, err, boom)

	_, err = deb.ApplyPDiffTo(io.Discard, iotest.ErrReader(boom), strings.NewReader("1d\n"), deb.PDiffApplyOptions{})
	require.ErrorIs(t, err, boom)

	_, err = deb.ApplyPDiffTo(io.Discard, iotest.ErrReader(boom), strings.NewReader(""), deb.PDiffApplyOptions{})
	require.ErrorIs(t, err, boom)

	_, err = deb.ApplyPDiffTo(errWriter{boom}, strings.NewReader(base), strings.NewReader(""), deb.PDiffApplyOptions{})
	require.ErrorIs(t, err, boom)

	_, err = deb.ApplyPDiffTo(errWriter{boom}, strings.NewReader(base), strings.NewReader("1d\n"), deb.PDiffApplyOptions{})
	require.ErrorIs(t, err, boom)

	// A patch over its limit is refused without being applied.
	_, err = deb.ApplyPDiffTo(io.Discard, strings.NewReader(base), strings.NewReader(strings.Repeat("1d\n", 100)), deb.PDiffApplyOptions{MaxPatchSize: 10})
	require.ErrorIs(t, err, deb.ErrPDiffLimit)
}

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

func TestPDiffHashErrorFormat(t *testing.T) {
	e := &deb.PDiffHashError{Patch: "p", What: "result", Want: "a", Got: "b"}
	require.Contains(t, e.Error(), "result of p")
	require.ErrorIs(t, e, deb.ErrPDiffHash)

	e = &deb.PDiffHashError{What: "base", Want: "a", Got: "b"}
	require.Contains(t, e.Error(), "base:")
}

func TestPDiffErrorFormat(t *testing.T) {
	e := &deb.PDiffError{Line: 3, Reason: "bad", Err: deb.ErrPDiffScript}
	require.Contains(t, e.Error(), "line 3")

	e = &deb.PDiffError{Reason: "bad", Err: deb.ErrPDiffLimit}
	require.NotContains(t, e.Error(), "line")
}

func TestPDiffPatchHelpers(t *testing.T) {
	require.True(t, deb.PDiffHash{}.IsZero())
	require.False(t, deb.PDiffHash{Size: 1}.IsZero())
}
