package adb

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// symlinkEntry and friends build entries of a raw package.
func rawFileEntry(name string, target []byte) FileEntry {
	return FileEntry{Name: name, ACL: ACL{Mode: 0o777, User: "root", Group: "root"}, Target: target}
}

func rawSymlink(name, target string) FileEntry {
	return rawFileEntry(name, append([]byte{0x00, 0xa0}, target...))
}

func rawDir(name string, files ...FileEntry) Dir {
	return Dir{Name: name, ACL: ACL{Mode: 0o755, User: "root", Group: "root"}, Files: files}
}

func rawPkg(dirs ...Dir) *Package {
	return &Package{Info: Info{Name: "raw", Version: "1", Arch: "noarch", Hashes: make([]byte, 20)}, Paths: dirs}
}

func extractTo(t *testing.T, file []byte, dir string, opts ExtractOptions) error {
	t.Helper()

	opts.AllowUntrusted = true
	_, err := Extract(bytes.NewReader(file), dir, opts)

	return err
}

func TestExtractSkipsDevicesAndDropsSpecialBits(t *testing.T) {
	var out bytes.Buffer
	if _, err := WritePackage(&out, kindsSpec(), WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := extractTo(t, out.Bytes(), dir, ExtractOptions{}); err != nil {
		t.Fatal(err)
	}

	for _, gone := range []string{"dev/null", "dev/sda", "run/pipe"} {
		if _, err := os.Lstat(filepath.Join(dir, gone)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s was created: %v", gone, err)
		}
	}

	fi, err := os.Stat(filepath.Join(dir, "bin", "tool"))
	if err != nil {
		t.Fatal(err)
	}

	if fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 || fi.Mode().Perm() != 0o755 {
		t.Errorf("bin/tool has mode %v", fi.Mode())
	}

	a, _ := os.Stat(filepath.Join(dir, "lib", "libx.so.1"))
	b, _ := os.Stat(filepath.Join(dir, "lib", "libx.so.1.hard"))

	if a == nil || b == nil || !os.SameFile(a, b) {
		t.Error("the hard link is not one")
	}

	// A second extraction over the first replaces what is there.
	if err := extractTo(t, out.Bytes(), dir, ExtractOptions{}); err != nil {
		t.Errorf("extracting twice: %v", err)
	}
}

func TestExtractLimits(t *testing.T) {
	var out bytes.Buffer
	if _, err := WritePackage(&out, kindsSpec(), WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := extractTo(t, out.Bytes(), t.TempDir(), ExtractOptions{MaxBytes: 3}); !errors.Is(err, ErrDataTooLarge) {
		t.Errorf("MaxBytes: %v", err)
	}

	if err := extractTo(t, out.Bytes(), t.TempDir(), ExtractOptions{MaxEntries: 4}); !errors.Is(err, ErrDataTooLarge) {
		t.Errorf("MaxEntries: %v", err)
	}

	if err := extractTo(t, out.Bytes(), filepath.Join(t.TempDir(), "missing"), ExtractOptions{}); err == nil {
		t.Error("extracted into a directory that does not exist")
	}
}

func TestExtractRefusesEscapes(t *testing.T) {
	sum := sha256.Sum256(nil)
	file := func(name string) FileEntry {
		return FileEntry{Name: name, ACL: okACL, Hash: sum[:]}
	}

	for name, pkg := range map[string]*Package{
		"symlink out": rawPkg(rawDir("usr", rawSymlink("x", "../../etc"))),
		"symlink up":  rawPkg(rawDir("", rawSymlink("x", ".."))),
		"deep symlink up": rawPkg(
			rawDir("a/b", rawSymlink("x", "../../.."))),
		"link source out": rawPkg(rawDir("", rawFileEntry("l", append([]byte{0x00, 0x80}, "nothing"...)))),
		"file through a link out": rawPkg(
			rawDir("", rawSymlink("up", "x/y/..")),
			rawDir("up", file("f"))),
	} {
		t.Run(name, func(t *testing.T) {
			outside := t.TempDir()
			root := filepath.Join(t.TempDir(), "root")

			if err := os.Mkdir(root, 0o755); err != nil {
				t.Fatal(err)
			}

			err := extractTo(t, rawPackage(t, pkg), root, ExtractOptions{})
			if err == nil && name != "file through a link out" {
				t.Error("accepted")
			}

			if name != "link source out" && err != nil && !errors.Is(err, ErrUnsafeEntry) {
				t.Errorf("%v is not ErrUnsafeEntry", err)
			}

			if entries, _ := os.ReadDir(outside); len(entries) != 0 {
				t.Errorf("something was written outside: %v", entries)
			}

			if parent, _ := os.ReadDir(filepath.Dir(root)); len(parent) != 1 {
				t.Errorf("something was written beside the root: %v", parent)
			}
		})
	}
}

func TestExtractDoesNotFollowExistingLinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "x")); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "d")); err != nil {
		t.Fatal(err)
	}

	spec := &Spec{
		Info: Info{Name: "k", Version: "1", Arch: "noarch"},
		Files: []File{
			MemFile("x", 0o644, []byte("overwritten")),
			MemFile("d/victim", 0o644, []byte("overwritten")),
		},
	}

	var out bytes.Buffer
	if _, err := WritePackage(&out, spec, WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	// Whether it fails or lands inside the root, it must not touch the file
	// the links point to.
	_ = extractTo(t, out.Bytes(), root, ExtractOptions{})

	if got, _ := os.ReadFile(outside); string(got) != "keep" {
		t.Errorf("the file outside holds %q", got)
	}
}

func TestExtractReplacesLinks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "old"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink("old", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, "hard"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	hard := MemFile("hard", 0o644, []byte("new"))
	hard.HardLink = "base"

	spec := &Spec{
		Info: Info{Name: "k", Version: "1", Arch: "noarch"},
		Files: []File{
			MemFile("base", 0o644, []byte("new")),
			{Name: "link", Mode: fs.ModeSymlink | 0o777, LinkTarget: "base"},
			hard,
		},
	}

	var out bytes.Buffer
	if _, err := WritePackage(&out, spec, WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := extractTo(t, out.Bytes(), root, ExtractOptions{}); err != nil {
		t.Fatal(err)
	}

	if got, _ := os.Readlink(filepath.Join(root, "link")); got != "base" {
		t.Errorf("link -> %q", got)
	}

	if got, _ := os.ReadFile(filepath.Join(root, "hard")); string(got) != "new" {
		t.Errorf("hard holds %q", got)
	}
}

func TestExtractHardLinkToMissing(t *testing.T) {
	pkg := rawPkg(rawDir("", rawFileEntry("l", append([]byte{0x00, 0x80}, "nothing"...))))
	if err := extractTo(t, rawPackage(t, pkg), t.TempDir(), ExtractOptions{}); err == nil {
		t.Error("linked to a file that does not exist")
	}
}

func TestExtractCorruptContentFails(t *testing.T) {
	base := signedBase(t)
	schema, blocks := splitFile(t, base)

	blocks[2].payload = append([]byte(nil), blocks[2].payload...)
	blocks[2].payload[9] ^= 1

	err := extractTo(t, joinFile(schema, blocks...), t.TempDir(), ExtractOptions{})
	if !errors.Is(err, ErrDigest) {
		t.Errorf("%v", err)
	}
}

func TestExtractTrustAndBadSignature(t *testing.T) {
	k := keysOf(t)[0]
	base := signedBase(t)

	if _, err := Extract(bytes.NewReader(base), t.TempDir(), ExtractOptions{Keyring: keyringOf(t, k)}); err != nil {
		t.Fatal(err)
	}

	// A signature by a trusted key that does not verify is never accepted.
	schema, blocks := splitFile(t, base)
	blocks[0].payload = append([]byte(nil), blocks[0].payload...)
	blocks[0].payload[len(blocks[0].payload)-1] ^= 1
	forged := joinFile(schema, blocks...)

	for _, allow := range []bool{false, true} {
		_, err := Extract(bytes.NewReader(forged), t.TempDir(), ExtractOptions{Keyring: keyringOf(t, k), AllowUntrusted: allow})
		if !errors.Is(err, ErrBadSignature) {
			t.Errorf("AllowUntrusted=%v: %v", allow, err)
		}
	}
}
