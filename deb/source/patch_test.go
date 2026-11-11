package source_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/deb/source"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()

	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return root
}

func readFile(t *testing.T, root, name string) string {
	t.Helper()

	b, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

const numbered = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n"

func TestApplyPatchBasics(t *testing.T) {
	const patch = "--- a/f.txt\n+++ b/f.txt\n@@ -3,3 +3,3 @@\n 3\n-4\n+four\n 5\n"

	root := writeTree(t, map[string]string{"f.txt": numbered})

	changed, err := source.ApplyPatch(root, strings.NewReader(patch), source.PatchOptions{Strip: 1})
	if err != nil || len(changed) != 1 || changed[0] != "f.txt" {
		t.Fatalf("apply: %v %v", changed, err)
	}

	if got := readFile(t, root, "f.txt"); got != strings.Replace(numbered, "4\n", "four\n", 1) {
		t.Errorf("content %q", got)
	}

	// The same patch no longer applies: the context has moved on.
	if _, err := source.ApplyPatch(root, strings.NewReader(patch), source.PatchOptions{Strip: 1}); !errors.Is(err, source.ErrPatch) {
		t.Errorf("reapply: %v", err)
	}
}

func TestApplyPatchOffsetAndFuzz(t *testing.T) {
	// The hunk is declared at line 1 but the text sits at line 5: patch
	// finds it by offset, as long as the context matches exactly.
	const moved = "--- a/f\n+++ b/f\n@@ -1,3 +1,3 @@\n 5\n-6\n+six\n 7\n"

	root := writeTree(t, map[string]string{"f": numbered})
	if _, err := source.ApplyPatch(root, strings.NewReader(moved), source.PatchOptions{Strip: 1}); err != nil {
		t.Fatalf("offset: %v", err)
	}

	if !strings.Contains(readFile(t, root, "f"), "six") {
		t.Error("offset hunk not applied")
	}

	// A hunk whose leading context differs needs fuzz, which is zero.
	const fuzzy = "--- a/f\n+++ b/f\n@@ -3,3 +3,3 @@\n X\n-4\n+four\n 5\n"

	root = writeTree(t, map[string]string{"f": numbered})
	if _, err := source.ApplyPatch(root, strings.NewReader(fuzzy), source.PatchOptions{Strip: 1}); !errors.Is(err, source.ErrPatch) {
		t.Errorf("fuzz: %v", err)
	}

	if readFile(t, root, "f") != numbered {
		t.Error("a failed patch changed the tree")
	}
}

func TestApplyPatchCreateDeleteMultiHunk(t *testing.T) {
	root := writeTree(t, map[string]string{"old.txt": "gone\n", "m.txt": numbered, "d/keep": "k\n"})

	patch := "--- a/old.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n" +
		"--- /dev/null\n+++ b/new/dir/x.txt\n@@ -0,0 +1,2 @@\n+hello\n+world\n" +
		"--- a/m.txt\n+++ b/m.txt\n@@ -1,2 +1,2 @@\n-1\n+one\n 2\n@@ -9,2 +9,3 @@\n 9\n 10\n+eleven\n"

	changed, err := source.ApplyPatch(root, strings.NewReader(patch), source.PatchOptions{Strip: 1})
	if err != nil {
		t.Fatal(err)
	}

	if len(changed) != 3 {
		t.Errorf("changed %v", changed)
	}

	if _, err := os.Stat(filepath.Join(root, "old.txt")); !os.IsNotExist(err) {
		t.Error("old.txt not deleted")
	}

	if readFile(t, root, "new/dir/x.txt") != "hello\nworld\n" {
		t.Error("new file")
	}

	if got := readFile(t, root, "m.txt"); !strings.HasPrefix(got, "one\n2\n") || !strings.HasSuffix(got, "10\neleven\n") {
		t.Errorf("m.txt %q", got)
	}
}

func TestApplyPatchNoNewlineAtEnd(t *testing.T) {
	root := writeTree(t, map[string]string{"f": "a\nb"})
	patch := "--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n"

	if _, err := source.ApplyPatch(root, strings.NewReader(patch), source.PatchOptions{Strip: 1}); err != nil {
		t.Fatal(err)
	}

	if got := readFile(t, root, "f"); got != "a\nc" {
		t.Errorf("got %q", got)
	}
}

func TestApplyPatchBackupDir(t *testing.T) {
	root := writeTree(t, map[string]string{"f": numbered})
	backup := filepath.Join(t.TempDir(), "pc")

	patch := "--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n-1\n+one\n--- /dev/null\n+++ b/n\n@@ -0,0 +1 @@\n+new\n"
	if _, err := source.ApplyPatch(root, strings.NewReader(patch), source.PatchOptions{Strip: 1, BackupDir: backup}); err != nil {
		t.Fatal(err)
	}

	if readFile(t, backup, "f") != numbered || readFile(t, backup, "n") != "" {
		t.Error("backup contents")
	}

	if _, err := source.ApplyPatch(root, strings.NewReader(patch), source.PatchOptions{Strip: 1, BackupDir: "relative"}); err == nil {
		t.Error("relative backup dir accepted")
	}
}

func TestApplyPatchMatchesPatchTool(t *testing.T) {
	bin, err := exec.LookPath("patch")
	if err != nil {
		t.Skip("patch not installed")
	}

	diff, err := exec.LookPath("diff")
	if err != nil {
		t.Skip("diff not installed")
	}

	a := writeTree(t, map[string]string{"x": numbered, "y": "a\nb\nc\n"})
	b := writeTree(t, map[string]string{"x": "1\n2\nTWO-AND-A-HALF\n3\n4\n5\n6\n7\n8\n10\n", "y": "a\nb\nc\nd"})

	out, _ := exec.Command(diff, "-ruN", "--label", "a", a, b).CombinedOutput()
	patch := strings.NewReplacer(a, "a", b, "b").Replace(string(out))

	ours := writeTree(t, map[string]string{"x": numbered, "y": "a\nb\nc\n"})
	theirs := writeTree(t, map[string]string{"x": numbered, "y": "a\nb\nc\n"})

	if _, err := source.ApplyPatch(ours, strings.NewReader(patch), source.PatchOptions{Strip: 1}); err != nil {
		t.Fatalf("%v\n%s", err, patch)
	}

	cmd := exec.Command(bin, "-p1", "-F0", "--no-backup-if-mismatch", "-s")
	cmd.Dir, cmd.Stdin = theirs, strings.NewReader(patch)

	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("patch: %v\n%s", err, o)
	}

	for _, f := range []string{"x", "y"} {
		if readFile(t, ours, f) != readFile(t, theirs, f) {
			t.Errorf("%s: %q vs %q", f, readFile(t, ours, f), readFile(t, theirs, f))
		}
	}
}

func TestApplyPatchRejects(t *testing.T) {
	for name, patch := range map[string]string{
		"parent path":     "--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-1\n+2\n",
		"absolute path":   "--- /etc/passwd\n+++ /etc/passwd\n@@ -1 +1 @@\n-1\n+2\n",
		"missing file":    "--- a/absent\n+++ b/absent\n@@ -1 +1 @@\n-1\n+2\n",
		"truncated hunk":  "--- a/f\n+++ b/f\n@@ -1,5 +1,5 @@\n 1\n",
		"bad header":      "--- a/f\n+++ b/f\n@@ nonsense @@\n 1\n",
		"through link":    "--- a/link/f\n+++ b/link/f\n@@ -1 +1 @@\n-1\n+2\n",
		"create exists":   "--- /dev/null\n+++ b/f\n@@ -0,0 +1 @@\n+x\n",
		"delete mismatch": "--- a/f\n+++ /dev/null\n@@ -1 +0,0 @@\n-different\n",
	} {
		root := writeTree(t, map[string]string{"f": numbered})
		outside := t.TempDir()

		_ = os.WriteFile(filepath.Join(outside, "f"), []byte("1\n"), 0o644)
		_ = os.Symlink(outside, filepath.Join(root, "link"))

		_, err := source.ApplyPatch(root, strings.NewReader(patch), source.PatchOptions{Strip: 1})
		if err == nil {
			t.Errorf("%s: accepted", name)

			continue
		}

		if b, _ := os.ReadFile(filepath.Join(outside, "f")); string(b) != "1\n" {
			t.Errorf("%s: wrote outside the tree", name)
		}
	}

	big := io_Repeat("x", source.MaxPatchBytes+1)
	if _, err := source.ApplyPatch(t.TempDir(), big, source.PatchOptions{}); !errors.Is(err, source.ErrTooLarge) {
		t.Errorf("oversized patch: %v", err)
	}
}

// -- hostile archives --

type tarEntry struct {
	name, link string
	typ        byte
	body       string
	mode       int64
}

func nativeFixture(t *testing.T, entries []tarEntry) (*source.DSC, string) {
	t.Helper()

	var tb bytes.Buffer

	gz := gzip.NewWriter(&tb)
	tw := tar.NewWriter(gz)

	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}

		h := &tar.Header{Name: e.name, Linkname: e.link, Typeflag: e.typ, Mode: mode, Size: int64(len(e.body))}
		if e.typ == 0 {
			h.Typeflag = tar.TypeReg
		}

		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}

		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}

		if h.Size > 0 {
			_, _ = tw.Write([]byte(e.body))
		}
	}

	_ = tw.Close()
	_ = gz.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evil_1.0.tar.gz"), tb.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(tb.Bytes())
	d := &source.DSC{
		Format: source.FormatNative, Source: "evil", Version: "1.0",
		Files: []source.FileRef{{Name: "evil_1.0.tar.gz", Size: int64(tb.Len()), SHA256: hex.EncodeToString(sum[:])}},
	}

	return d, dir
}

func TestUnpackHostileArchives(t *testing.T) {
	cases := map[string][]tarEntry{
		"parent traversal":   {{name: "../escape", body: "x"}},
		"nested traversal":   {{name: "a/../../escape", body: "x"}},
		"symlink escape":     {{name: "evil/link", typ: tar.TypeSymlink, link: "../../.."}},
		"write through link": {{name: "evil/link", typ: tar.TypeSymlink, link: "."}, {name: "evil/link/f", body: "x"}},
		"hardlink outside":   {{name: "evil/h", typ: tar.TypeLink, link: "../../etc/passwd"}},
		"hardlink absolute":  {{name: "evil/h", typ: tar.TypeLink, link: "/etc/passwd"}},
		"device node":        {{name: "evil/dev", typ: tar.TypeChar}},
		"fifo":               {{name: "evil/fifo", typ: tar.TypeFifo}},
	}

	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			d, dir := nativeFixture(t, entries)
			parent := t.TempDir()
			dest := filepath.Join(parent, "out")

			err := source.Unpack(d, dir, dest, nil)
			if err == nil {
				t.Fatal("accepted")
			}

			if !errors.Is(err, source.ErrUnsafe) {
				t.Errorf("error is not ErrUnsafe: %v", err)
			}

			if _, err := os.Lstat(filepath.Join(parent, "escape")); err == nil {
				t.Error("file written outside the target")
			}
		})
	}
}

func TestUnpackAbsoluteNamesStayInside(t *testing.T) {
	d, dir := nativeFixture(t, []tarEntry{{name: "/tmp/pkgformat-escape-test", body: "x"}})
	dest := filepath.Join(t.TempDir(), "o")

	_ = source.Unpack(d, dir, dest, nil)

	if _, err := os.Lstat("/tmp/pkgformat-escape-test"); err == nil {
		t.Error("absolute name written to the host path")
	}
}

func TestUnpackLimits(t *testing.T) {
	d, dir := nativeFixture(t, []tarEntry{{name: "evil-1.0/a", body: "aaaa"}, {name: "evil-1.0/b", body: "bbbb"}})

	if err := source.Unpack(d, dir, filepath.Join(t.TempDir(), "o"), &source.UnpackOptions{MaxEntries: 1}); !errors.Is(err, source.ErrTooLarge) {
		t.Errorf("entries: %v", err)
	}

	if err := source.Unpack(d, dir, filepath.Join(t.TempDir(), "o"), &source.UnpackOptions{MaxBytes: 5}); !errors.Is(err, source.ErrTooLarge) {
		t.Errorf("bytes: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "o")
	if err := source.Unpack(d, dir, dest, nil); err != nil {
		t.Fatal(err)
	}

	if readFile(t, dest, "a") != "aaaa" {
		t.Error("content")
	}

	// An existing, non-empty target is refused unless Replace is set.
	if err := source.Unpack(d, dir, dest, nil); !errors.Is(err, source.ErrDestExists) {
		t.Errorf("existing: %v", err)
	}

	if err := source.Unpack(d, dir, dest, &source.UnpackOptions{Replace: true}); err != nil {
		t.Errorf("replace: %v", err)
	}
}

func TestUnpackLinksAndModes(t *testing.T) {
	d, dir := nativeFixture(t, []tarEntry{
		{name: "evil-1.0/", typ: tar.TypeDir, mode: 0o700},
		{name: "evil-1.0/bin/run", body: "#!/bin/sh\n", mode: 0o700},
		{name: "evil-1.0/plain", body: "x", mode: 0o640},
		{name: "evil-1.0/sym", typ: tar.TypeSymlink, link: "plain"},
		{name: "evil-1.0/hard", typ: tar.TypeLink, link: "evil-1.0/plain"},
	})

	dest := filepath.Join(t.TempDir(), "o")
	if err := source.Unpack(d, dir, dest, nil); err != nil {
		t.Fatal(err)
	}

	for name, want := range map[string]os.FileMode{"bin/run": 0o755, "plain": 0o644, "bin": 0o755, ".": 0o755} {
		fi, err := os.Lstat(filepath.Join(dest, name))
		if err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v %v", name, fi, err)
		}
	}

	if l, err := os.Readlink(filepath.Join(dest, "sym")); err != nil || l != "plain" {
		t.Errorf("symlink: %q %v", l, err)
	}

	if readFile(t, dest, "hard") != "x" {
		t.Error("hard link content")
	}
}

func io_Repeat(s string, n int) *strings.Reader { return strings.NewReader(strings.Repeat(s, n)) }

var _ = fmt.Sprint
