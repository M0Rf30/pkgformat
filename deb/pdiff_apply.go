package deb

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// Default limits of PDiffApplyOptions.
const (
	// DefaultMaxPDiffPatchBytes is the default bound on a decompressed patch.
	DefaultMaxPDiffPatchBytes int64 = 256 << 20
	// DefaultMaxPDiffCommands is the default bound on the commands of a patch.
	DefaultMaxPDiffCommands = 1 << 21
)

// PDiffApplyOptions bounds the application of a patch. The zero value selects
// the defaults.
type PDiffApplyOptions struct {
	// MaxPatchSize bounds the (decompressed) ed script; DefaultMaxPDiffPatchBytes
	// when zero.
	MaxPatchSize int64
	// MaxResultSize bounds the patched file; MaxIndexBytes when zero.
	MaxResultSize int64
	// MaxCommands bounds the a, c and d commands of the script;
	// DefaultMaxPDiffCommands when zero.
	MaxCommands int
}

func (o PDiffApplyOptions) withDefaults() PDiffApplyOptions {
	if o.MaxPatchSize <= 0 {
		o.MaxPatchSize = DefaultMaxPDiffPatchBytes
	}

	if o.MaxResultSize <= 0 {
		o.MaxResultSize = MaxIndexBytes
	}

	if o.MaxCommands <= 0 {
		o.MaxCommands = DefaultMaxPDiffCommands
	}

	return o
}

// PDiffError reports a malformed or misfitting edit script. It wraps
// ErrPDiffScript, or ErrPDiffLimit for a script or result over a limit, so
// errors.Is tells the two apart and errors.As recovers the position.
type PDiffError struct {
	// Line is the 1-based line of the script the error is about; 0 when it is
	// not tied to a line (a limit, a command that does not fit the file).
	Line int
	// Reason says what is wrong.
	Reason string
	// Err is ErrPDiffScript or ErrPDiffLimit.
	Err error
}

func (e *PDiffError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%v: line %d: %s", e.Err, e.Line, e.Reason)
	}

	return fmt.Sprintf("%v: %s", e.Err, e.Reason)
}

// Unwrap returns the sentinel the error belongs to.
func (e *PDiffError) Unwrap() error { return e.Err }

func pdiffScriptErr(line int, format string, args ...any) *PDiffError {
	return &PDiffError{Line: line, Reason: fmt.Sprintf(format, args...), Err: ErrPDiffScript}
}

func pdiffLimitErr(format string, args ...any) *PDiffError {
	return &PDiffError{Reason: fmt.Sprintf(format, args...), Err: ErrPDiffLimit}
}

// PDiffHashError reports a digest or size that does not match the Index. It
// wraps ErrPDiffHash.
type PDiffHashError struct {
	// Patch is the patch being processed ("" for the base file).
	Patch string
	// What is the object checked: "base", "download", "patch" or "result".
	What string
	// Want and Got are the expected and the computed SHA-256 digests, or sizes
	// formatted as "<n> bytes" when the size disagreed.
	Want, Got string
}

func (e *PDiffHashError) Error() string {
	if e.Patch == "" {
		return fmt.Sprintf("%v: %s: want %s, got %s", ErrPDiffHash, e.What, e.Want, e.Got)
	}

	return fmt.Sprintf("%v: %s of %s: want %s, got %s", ErrPDiffHash, e.What, e.Patch, e.Want, e.Got)
}

// Unwrap returns ErrPDiffHash.
func (e *PDiffHashError) Unwrap() error { return ErrPDiffHash }

// pdiffEdit is one command of an ed script, in terms of the file it applies to:
// skip into the file at lines, drop del lines, insert the lines of text.
type pdiffEdit struct {
	at    int
	del   int
	text  []byte // the inserted lines, each with its newline; aliases the script
	lines int
}

// parsePDiffScript reads the ed script of a patch: the commands "Na", "Nc",
// "N,Mc", "Nd" and "N,Md", the text of a and c ending at a line with just ".".
// The commands must go from the end of the file to its start, as diff --ed and
// apt's rred write them, and must not overlap; the edits are returned in the
// order of the file (the reverse of the script), so that several inserts at
// one position come out in the order ed would leave them.
func parsePDiffScript(patch []byte, opts PDiffApplyOptions) ([]pdiffEdit, error) {
	var (
		edits   []pdiffEdit
		lineNo  int
		rest    = patch
		prev    = math.MaxInt
		hasPrev bool
	)

	next := func() ([]byte, bool, error) {
		if len(rest) == 0 {
			return nil, false, nil
		}

		lineNo++

		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			return nil, false, pdiffScriptErr(lineNo, "line without a newline at the end of the script")
		}

		l := rest[:i]
		rest = rest[i+1:]

		return l, true, nil
	}

	for {
		cmd, ok, err := next()
		if err != nil {
			return nil, err
		}

		if !ok {
			break
		}

		if len(edits) >= opts.MaxCommands {
			return nil, pdiffLimitErr("more than %d commands", opts.MaxCommands)
		}

		first, last, op, err := parsePDiffCommand(cmd, lineNo)
		if err != nil {
			return nil, err
		}

		e := pdiffEdit{at: first - 1, del: last - first + 1}
		if op == 'a' {
			e.at, e.del = first, 0
		}

		if hasPrev && e.at+e.del > prev {
			return nil, pdiffScriptErr(lineNo, "command is not before the previous one (commands must go from the end of the file to its start)")
		}

		prev, hasPrev = e.at, true

		if op != 'd' {
			start := len(patch) - len(rest)
			cmdLine := lineNo

			for {
				text, ok, err := next()
				if err != nil {
					return nil, err
				}

				if !ok {
					return nil, pdiffScriptErr(cmdLine, "text of the command is not terminated by a line with a single dot")
				}

				if len(text) == 1 && text[0] == '.' {
					e.text = patch[start : len(patch)-len(rest)-2]

					break
				}

				e.lines++
			}
		}

		edits = append(edits, e)
	}

	slices.Reverse(edits)

	return edits, nil
}

// parsePDiffCommand reads "N", "N,M" and the command letter of a script line.
// It returns the 1-based first and last line (equal for a single line) and the
// command; for a the line is the one the text goes after (0 for the start of
// the file).
func parsePDiffCommand(cmd []byte, lineNo int) (first, last int, op byte, err error) {
	if len(cmd) < 2 {
		return 0, 0, 0, pdiffScriptErr(lineNo, "not a command: %q", cmd)
	}

	op = cmd[len(cmd)-1]
	if op != 'a' && op != 'c' && op != 'd' {
		return 0, 0, 0, pdiffScriptErr(lineNo, "unsupported command %q (only a, c and d)", string(op))
	}

	addr := string(cmd[:len(cmd)-1])
	lo, hi, ranged := cutPDiff(addr, ',')

	first, err = parsePDiffNumber(lo, lineNo)
	if err != nil {
		return 0, 0, 0, err
	}

	last = first

	if ranged {
		last, err = parsePDiffNumber(hi, lineNo)
		if err != nil {
			return 0, 0, 0, err
		}

		if last < first {
			return 0, 0, 0, pdiffScriptErr(lineNo, "range end %d is before its start %d", last, first)
		}
	}

	switch {
	case op == 'a' && ranged:
		return 0, 0, 0, pdiffScriptErr(lineNo, "a takes a single line")
	case op != 'a' && first == 0:
		return 0, 0, 0, pdiffScriptErr(lineNo, "%c cannot address line 0", op)
	}

	return first, last, op, nil
}

func cutPDiff(s string, sep byte) (before, after string, found bool) {
	for i := range len(s) {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}

	return s, "", false
}

// parsePDiffNumber reads a line number: decimal digits only, in the range of
// an int.
func parsePDiffNumber(s string, lineNo int) (int, error) {
	if s == "" || s[0] == '+' || s[0] == '-' {
		return 0, pdiffScriptErr(lineNo, "bad line number %q", s)
	}

	n, err := strconv.ParseUint(s, 10, 63)
	if err != nil || n > math.MaxInt32 {
		return 0, pdiffScriptErr(lineNo, "bad line number %q", s)
	}

	return int(n), nil
}

// pdiffLineReader reads its input a line at a time without holding more than a
// buffer of it.
type pdiffLineReader struct {
	r *bufio.Reader
}

// pass moves up to n lines to w (a nil w drops them) and reports how many it
// moved; fewer than n means the input ended.
func (l *pdiffLineReader) pass(n int, w io.Writer) (int, error) {
	done := 0

	for done < n {
		chunk, err := l.r.ReadSlice('\n')

		if len(chunk) > 0 && w != nil {
			if _, werr := w.Write(chunk); werr != nil {
				return done, werr
			}
		}

		switch {
		case err == nil:
			done++
		case errors.Is(err, bufio.ErrBufferFull):
		case errors.Is(err, io.EOF):
			if len(chunk) > 0 {
				done++ // the last line has no newline
			}

			return done, nil
		default:
			return done, err
		}
	}

	return done, nil
}

// pdiffCapWriter fails with a limit error once more than left bytes went through.
type pdiffCapWriter struct {
	w    io.Writer
	left int64
	n    int64
}

func (c *pdiffCapWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.left {
		return 0, pdiffLimitErr("patched file exceeds %d bytes", c.n+c.left)
	}

	n, err := c.w.Write(p)
	c.left -= int64(n)
	c.n += int64(n)

	return n, err
}

// ApplyPDiffTo applies the ed script read from patch to base and writes the
// result to dst, returning the bytes written. The script is read whole, up to
// MaxPatchSize; the base is streamed line by line, so memory stays bounded by
// the script plus a buffer however large the file is. dst may hold a partial
// result when an error is returned.
//
// Malformed scripts, scripts whose commands address lines beyond the end of
// base, and scripts or results over a limit fail with a *PDiffError.
func ApplyPDiffTo(dst io.Writer, base, patch io.Reader, opts PDiffApplyOptions) (int64, error) {
	opts = opts.withDefaults()

	script, err := limitio.ReadAll(patch, opts.MaxPatchSize, ErrPDiffLimit)
	if err != nil {
		if errors.Is(err, ErrPDiffLimit) {
			return 0, &PDiffError{Reason: err.Error(), Err: ErrPDiffLimit}
		}

		return 0, fmt.Errorf("deb: reading pdiff script: %w", err)
	}

	edits, err := parsePDiffScript(script, opts)
	if err != nil {
		return 0, err
	}

	return applyPDiffEdits(dst, base, edits, opts)
}

func applyPDiffEdits(dst io.Writer, base io.Reader, edits []pdiffEdit, opts PDiffApplyOptions) (int64, error) {
	capw := &pdiffCapWriter{w: dst, left: opts.MaxResultSize}
	out := bufio.NewWriterSize(capw, 64<<10)
	in := &pdiffLineReader{r: bufio.NewReaderSize(base, 64<<10)}
	pos := 0

	for _, e := range edits {
		if n, err := in.pass(e.at-pos, out); err != nil {
			return capw.n, err
		} else if n < e.at-pos {
			return capw.n, pdiffScriptErr(0, "command addresses line %d, but the file has %d lines", e.at+e.del, pos+n)
		}

		if n, err := in.pass(e.del, nil); err != nil {
			return capw.n, err
		} else if n < e.del {
			return capw.n, pdiffScriptErr(0, "command addresses line %d, but the file has %d lines", e.at+e.del, e.at+n)
		}

		pos = e.at + e.del

		if _, err := out.Write(e.text); err != nil {
			return capw.n, err
		}
	}

	if _, err := io.Copy(out, in.r); err != nil {
		return capw.n, err
	}

	if err := out.Flush(); err != nil {
		return capw.n, err
	}

	return capw.n, nil
}

// ApplyPDiff applies the ed script patch to base, as apt's rred does for a
// Packages.diff patch, and returns the patched file. It is ApplyPDiffWith
// with the default limits.
func ApplyPDiff(base, patch []byte) ([]byte, error) {
	return ApplyPDiffWith(base, patch, PDiffApplyOptions{})
}

// ApplyPDiffWith is ApplyPDiff with explicit limits.
func ApplyPDiffWith(base, patch []byte, opts PDiffApplyOptions) ([]byte, error) {
	opts = opts.withDefaults()

	if int64(len(patch)) > opts.MaxPatchSize {
		return nil, pdiffLimitErr("patch exceeds %d bytes", opts.MaxPatchSize)
	}

	edits, err := parsePDiffScript(patch, opts)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer

	out.Grow(len(base))

	if _, err := applyPDiffEdits(&out, bytes.NewReader(base), edits, opts); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// PDiffFetcher returns the bytes of the gzip file Packages.diff/<p.Name>.gz
// for a patch; ApplyPDiffChain calls it once per patch, in order.
type PDiffFetcher func(p PDiffPatch) ([]byte, error)

// ApplyPDiffChain turns base into the file at the end of chain, the result of
// PDiffIndex.Chain. For each patch it fetches the gzip download, checks its
// size and SHA-256 against the Index, decompresses it within the patch size
// limit, checks the script's size and SHA-256, applies it, and checks the
// patched file against the patch's To digest, so every intermediate file is
// verified and a poisoned patch is never carried forward. A mismatch is a
// *PDiffHashError (errors.Is ErrPDiffHash). An empty chain returns base.
func ApplyPDiffChain(base []byte, chain []PDiffPatch, fetch PDiffFetcher, opts PDiffApplyOptions) ([]byte, error) {
	opts = opts.withDefaults()
	cur := base

	for i, p := range chain {
		if i == 0 {
			if err := checkPDiffHash(p.Name, "base", cur, p.From); err != nil {
				return nil, err
			}
		}

		gz, err := fetch(p)
		if err != nil {
			return nil, fmt.Errorf("deb: fetching pdiff %s: %w", p.Name, err)
		}

		if err := checkPDiffHash(p.Name, "download", gz, p.Download); err != nil {
			return nil, err
		}

		script, err := gunzipPDiff(gz, opts.MaxPatchSize)
		if err != nil {
			return nil, fmt.Errorf("deb: pdiff %s: %w", p.Name, err)
		}

		if err := checkPDiffHash(p.Name, "patch", script, p.Patch); err != nil {
			return nil, err
		}

		cur, err = ApplyPDiffWith(cur, script, opts)
		if err != nil {
			return nil, fmt.Errorf("deb: applying pdiff %s: %w", p.Name, err)
		}

		if err := checkPDiffHash(p.Name, "result", cur, p.To); err != nil {
			return nil, err
		}
	}

	return cur, nil
}

// gunzipPDiff decompresses a gzip patch, failing with a limit error beyond max
// bytes.
func gunzipPDiff(gz []byte, limit int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}

	defer zr.Close()

	data, err := limitio.ReadAll(zr, limit, ErrPDiffLimit)
	if err != nil {
		if errors.Is(err, ErrPDiffLimit) {
			return nil, &PDiffError{Reason: "decompressed patch exceeds " + strconv.FormatInt(limit, 10) + " bytes", Err: ErrPDiffLimit}
		}

		return nil, fmt.Errorf("gzip: %w", err)
	}

	return data, nil
}

// checkPDiffHash verifies data against want (a size and a SHA-256); a want
// without a size is only checked for its digest.
func checkPDiffHash(patch, what string, data []byte, want PDiffHash) error {
	if want.Size > 0 && int64(len(data)) != want.Size {
		return &PDiffHashError{Patch: patch, What: what, Want: strconv.FormatInt(want.Size, 10) + " bytes", Got: strconv.Itoa(len(data)) + " bytes"}
	}

	if want.SHA256 == "" {
		return nil
	}

	sum := sha256.Sum256(data)

	if got := hex.EncodeToString(sum[:]); got != want.SHA256 {
		return &PDiffHashError{Patch: patch, What: what, Want: want.SHA256, Got: got}
	}

	return nil
}

// PDiffSHA256 returns the lowercase hex SHA-256 of a file, the digest
// PDiffIndex.Chain is keyed by.
func PDiffSHA256(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}
