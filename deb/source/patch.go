package source

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/safepath"
)

// MaxPatchBytes bounds one patch file.
const MaxPatchBytes = 256 << 20

// PatchOptions tunes [ApplyPatch].
type PatchOptions struct {
	// Strip is the number of leading path components removed from the file
	// names of the patch (patch -pN); dpkg-source always uses 1.
	Strip int
	// BackupDir, when set, receives a copy of every file before the patch
	// changes it, below the same relative path, and an empty file for every
	// file the patch creates: the layout of a quilt .pc/<patch> directory. It
	// must be an absolute path.
	BackupDir string
}

type hunkLine struct {
	op   byte // ' ', '-' or '+'
	text string
}

type hunk struct {
	oldStart, oldLines int
	newLines           int
	lines              []hunkLine
}

type filePatch struct {
	oldName, newName string
	hunks            []hunk
}

var (
	hunkHeaderRE = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)
	stampRE      = regexp.MustCompile(`\s+\d{4}-\d\d-\d\d[ T]\d\d:\d\d`)
)

// ApplyPatch applies the unified diff in patch to the tree at root with the
// strictness dpkg-source asks of patch(1): fuzz 0, so every context line must
// match, though a hunk may sit at a different line than it claims. A file that
// ends up empty is removed, and so is a directory that the removal empties.
// Files are only read and written inside root, and never through a symlink. It
// returns the root-relative names of the files it changed. A patch that does
// not apply fails with [ErrPatch], and the tree is then partly patched.
func ApplyPatch(root string, patch io.Reader, opts PatchOptions) ([]string, error) {
	data, err := io.ReadAll(io.LimitReader(patch, MaxPatchBytes+1))
	if err != nil {
		return nil, err
	}

	if len(data) > MaxPatchBytes {
		return nil, fmt.Errorf("%w: patch of %d bytes", ErrTooLarge, len(data))
	}

	files, err := parsePatch(data)
	if err != nil {
		return nil, err
	}

	var changed []string

	backedUp := map[string]bool{}

	for i := range files {
		name, err := files[i].target(root, opts.Strip)
		if err != nil {
			return changed, err
		}

		if err := applyFilePatch(root, name, &files[i], opts, backedUp); err != nil {
			return changed, fmt.Errorf("source: patching %s: %w", name, err)
		}

		changed = append(changed, name)
	}

	return changed, nil
}

func splitLines(data []byte) []string {
	var lines []string

	sc := bufio.NewReader(bytes.NewReader(data))
	for {
		line, err := sc.ReadString('\n')
		if line != "" {
			lines = append(lines, line)
		}

		if err != nil {
			return lines
		}
	}
}

// diffName extracts the file name of a "--- " or "+++ " line.
func diffName(rest string) string {
	if i := strings.IndexByte(rest, '\t'); i >= 0 {
		return rest[:i]
	}

	if loc := stampRE.FindStringIndex(rest); loc != nil {
		return rest[:loc[0]]
	}

	return strings.TrimRight(rest, " \r")
}

func parsePatch(data []byte) ([]filePatch, error) {
	lines := splitLines(data)

	var files []filePatch

	for i := 0; i < len(lines); {
		if !strings.HasPrefix(lines[i], "--- ") || i+1 >= len(lines) || !strings.HasPrefix(lines[i+1], "+++ ") {
			i++

			continue
		}

		fp := filePatch{
			oldName: diffName(strings.TrimRight(lines[i][4:], "\r\n")),
			newName: diffName(strings.TrimRight(lines[i+1][4:], "\r\n")),
		}

		i += 2

		for i < len(lines) {
			m := hunkHeaderRE.FindStringSubmatch(lines[i])
			if m == nil {
				break
			}

			h := hunk{oldStart: atoi(m[1]), oldLines: 1, newLines: 1}
			if m[2] != "" {
				h.oldLines = atoi(m[2])
			}

			if m[4] != "" {
				h.newLines = atoi(m[4])
			}

			i++

			var err error

			if i, err = readHunk(lines, i, &h); err != nil {
				return nil, err
			}

			fp.hunks = append(fp.hunks, h)
		}

		if len(fp.hunks) == 0 {
			return nil, fmt.Errorf("%w: no hunks for %s", ErrPatch, fp.newName)
		}

		files = append(files, fp)
	}

	return files, nil
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 1<<30 {
		return 1 << 30
	}

	return n
}

// readHunk reads the body of a hunk starting at lines[i] and returns the index
// of the first line after it.
func readHunk(lines []string, i int, h *hunk) (int, error) {
	oldLeft, newLeft := h.oldLines, h.newLines

	for oldLeft > 0 || newLeft > 0 {
		if i >= len(lines) {
			return i, fmt.Errorf("%w: truncated hunk", ErrPatch)
		}

		line := lines[i]
		text := strings.TrimSuffix(line, "\n")

		var op byte = ' '
		if text != "" {
			op = text[0]
		}

		switch op {
		case '\\':
			// "\ No newline at end of file" applies to the previous line.
			if n := len(h.lines); n > 0 {
				h.lines[n-1].text = strings.TrimSuffix(h.lines[n-1].text, "\n")
			}

			i++

			continue
		case ' ', '-', '+':
		default:
			return i, fmt.Errorf("%w: unexpected line %q in a hunk", ErrPatch, truncate(text))
		}

		body := ""
		if text != "" {
			body = line[1:]
		} else {
			body = line
		}

		switch op {
		case ' ':
			oldLeft--
			newLeft--
		case '-':
			oldLeft--
		case '+':
			newLeft--
		}

		if oldLeft < 0 || newLeft < 0 {
			return i, fmt.Errorf("%w: hunk is longer than its header", ErrPatch)
		}

		h.lines = append(h.lines, hunkLine{op: op, text: body})
		i++
	}

	// A trailing "\ No newline" marker belongs to the hunk.
	for i < len(lines) && strings.HasPrefix(lines[i], `\`) {
		if n := len(h.lines); n > 0 {
			h.lines[n-1].text = strings.TrimSuffix(h.lines[n-1].text, "\n")
		}

		i++
	}

	return i, nil
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}

	return s
}

// strip removes n leading components of name.
func stripName(name string, n int) (string, bool) {
	name = strings.TrimLeft(name, "/")
	for ; n > 0; n-- {
		_, rest, ok := strings.Cut(name, "/")
		if !ok {
			return "", false
		}

		name = rest
	}

	return path.Clean(name), name != ""
}

// target names the file the patch changes, relative to root, and checks it.
func (fp *filePatch) target(root string, strip int) (string, error) {
	oldDev, newDev := fp.oldName == "/dev/null", fp.newName == "/dev/null"

	var name string

	switch {
	case oldDev && newDev:
		return "", fmt.Errorf("%w: patch from /dev/null to /dev/null", ErrPatch)
	case oldDev:
		name, _ = stripName(fp.newName, strip)
	case newDev:
		name, _ = stripName(fp.oldName, strip)
	default:
		o, ok1 := stripName(fp.oldName, strip)
		n, ok2 := stripName(fp.newName, strip)

		switch {
		case ok1 && exists(root, o):
			name = o
		case ok2 && exists(root, n):
			name = n
		case ok2:
			name = n
		default:
			name = o
		}
	}

	if name == "" || name == "." {
		return "", fmt.Errorf("%w: patch names no file after stripping %d components", ErrPatch, strip)
	}

	if _, err := safepath.JoinStrict(root, name); err != nil {
		return "", fmt.Errorf("%w: %w", ErrUnsafe, err)
	}

	return name, nil
}

func exists(root, name string) bool {
	_, err := os.Lstat(filepath.Join(root, filepath.FromSlash(name)))

	return err == nil
}

func applyFilePatch(root, name string, fp *filePatch, opts PatchOptions, backedUp map[string]bool) error {
	full := filepath.Join(root, filepath.FromSlash(name))

	if dir := path.Dir(name); dir != "." {
		if err := checkNoSymlinks(root, dir); err != nil {
			return err
		}
	}

	var (
		orig []string
		mode = fixedFileMode
	)

	st, err := os.Lstat(full)

	switch {
	case err == nil && !st.Mode().IsRegular():
		return fmt.Errorf("%w: %q is not a regular file", ErrUnsafe, name)
	case err == nil:
		data, err := os.ReadFile(full)
		if err != nil {
			return err
		}

		orig = splitLines(data)
		mode = st.Mode().Perm()
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}

	if fp.oldName == "/dev/null" && len(orig) > 0 {
		return fmt.Errorf("%w: %q exists, the patch creates it", ErrPatch, name)
	}

	res, err := applyHunks(orig, fp.hunks)
	if err != nil {
		return err
	}

	if opts.BackupDir != "" && !backedUp[name] {
		backedUp[name] = true

		if err := backup(opts.BackupDir, name, full, st); err != nil {
			return err
		}
	}

	if len(res) == 0 {
		if err := os.Remove(full); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}

		return removeEmptyParents(root, path.Dir(name))
	}

	if err := walkDirs(root, path.Dir(name)); err != nil {
		return err
	}

	return os.WriteFile(full, []byte(strings.Join(res, "")), mode)
}

// checkNoSymlinks verifies that no component of rel below root is a symlink.
func checkNoSymlinks(root, rel string) error {
	cur := root

	for _, part := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, part)

		st, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}

		if err != nil {
			return err
		}

		if st.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: %q is a symlink", ErrUnsafe, rel)
		}
	}

	return nil
}

func removeEmptyParents(root, dir string) error {
	for dir != "." && dir != "/" && dir != "" {
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(dir))); err != nil {
			return nil //nolint:nilerr // not empty: stop
		}

		dir = path.Dir(dir)
	}

	return nil
}

func backup(backupDir, name, full string, st os.FileInfo) error {
	dst := filepath.Join(backupDir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(dst), fixedDirMode); err != nil {
		return err
	}

	if st == nil {
		return os.WriteFile(dst, nil, fixedFileMode)
	}

	data, err := os.ReadFile(full)
	if err != nil {
		return err
	}

	if err := os.WriteFile(dst, data, st.Mode().Perm()); err != nil { //nolint:gosec // backup tree
		return err
	}

	return os.Chtimes(dst, st.ModTime(), st.ModTime())
}

// applyHunks applies the hunks to the lines of a file with fuzz 0.
func applyHunks(orig []string, hunks []hunk) ([]string, error) {
	out := make([]string, 0, len(orig))
	cursor := 0 // index into orig of the first line not yet copied
	delta := 0  // offset found for the previous hunk

	for hi := range hunks {
		h := &hunks[hi]

		var oldSide, newSide []string

		pre, suf := 0, 0
		seenChange := false

		for _, l := range h.lines {
			switch l.op {
			case ' ':
				oldSide = append(oldSide, l.text)
				newSide = append(newSide, l.text)

				if seenChange {
					suf++
				} else {
					pre++
				}
			case '-':
				oldSide = append(oldSide, l.text)
				seenChange, suf = true, 0
			case '+':
				newSide = append(newSide, l.text)
				seenChange, suf = true, 0
			}
		}

		want := h.oldStart - 1
		if len(oldSide) == 0 {
			// Nothing to match: insert after line oldStart.
			want = h.oldStart
		}

		want += delta

		pos, ok := locate(orig, oldSide, want, cursor, pre, suf)
		if !ok {
			return nil, fmt.Errorf("%w: hunk %d (@@ -%d) does not match", ErrPatch, hi+1, h.oldStart)
		}

		out = append(out, orig[cursor:pos]...)
		out = append(out, newSide...)
		cursor = pos + len(oldSide)
		delta = pos - (h.oldStart - 1)

		if len(oldSide) == 0 {
			delta = pos - h.oldStart
		}
	}

	out = append(out, orig[cursor:]...)

	return out, nil
}

// locate finds where the old side of a hunk matches, nearest to want first.
func locate(orig, old []string, want, from, pre, suf int) (int, bool) {
	matchAt := func(p int) bool {
		if p < from || p+len(old) > len(orig) {
			return false
		}

		for i, l := range old {
			if orig[p+i] != l {
				return false
			}
		}

		return true
	}

	if len(old) == 0 {
		if want < from {
			want = from
		}

		if want > len(orig) {
			want = len(orig)
		}

		return want, true
	}

	ok := func(p int) bool {
		if !matchAt(p) {
			return false
		}

		// A hunk with less context before than after sits at the start of the
		// file; with less after than before, at its end.
		if pre < suf && p != 0 {
			return false
		}

		if suf < pre && p+len(old) != len(orig) {
			return false
		}

		return true
	}

	limit := len(orig) + 1
	for d := 0; d <= limit; d++ {
		if ok(want + d) {
			return want + d, true
		}

		if d > 0 && ok(want-d) {
			return want - d, true
		}
	}

	return 0, false
}
