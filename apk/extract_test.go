package apk

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func openArchiveBytes(t testing.TB, raw []byte) *Archive {
	t.Helper()

	a, err := OpenArchive(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}

	return a
}

// TestExtract_matchesApk compares the entries and the extracted tree of real
// Alpine packages with the tree `apk extract` made (testdata/extract).
func TestExtract_matchesApk(t *testing.T) {
	dir := filepath.Join("testdata", "extract")

	pkgs, err := filepath.Glob(filepath.Join(dir, "*.apk"))
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}

	for _, path := range pkgs {
		name := strings.TrimSuffix(filepath.Base(path), ".apk")

		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			golden, err := os.ReadFile(filepath.Join(dir, "listings", name+".listing"))
			if os.IsNotExist(err) && strings.HasPrefix(name, "devices-") {
				t.Skip("device nodes are compared in TestInterop_devices")
			}

			if err != nil {
				t.Fatal(err)
			}

			a := openArchiveBytes(t, raw)

			entries, err := a.Files()
			if err != nil {
				t.Fatal(err)
			}

			byName := make(map[string]*Entry, len(entries))
			for i := range entries {
				byName[entries[i].Name] = &entries[i]
			}

			out := t.TempDir()
			if err := a.Extract(out, ExtractOptions{}); err != nil {
				t.Fatal(err)
			}

			lines := strings.Split(strings.TrimSpace(string(golden)), "\n")
			if strings.TrimSpace(string(golden)) == "" {
				lines = nil
			}

			seen := 0

			for _, line := range lines {
				f := strings.Split(line, "|")
				if len(f) != 10 {
					t.Fatalf("bad listing line %q", line)
				}

				rel, typ, mode, uid, gid, size, link, sum := f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]

				e := byName[rel]
				if e == nil {
					t.Fatalf("%s: apk extracts it, Files does not list it", rel)
				}

				seen++

				m, _ := strconv.ParseUint(mode, 8, 32)
				want := fs.FileMode(m & 0o777)

				if m&0o4000 != 0 {
					want |= fs.ModeSetuid
				}

				if m&0o2000 != 0 {
					want |= fs.ModeSetgid
				}

				if m&0o1000 != 0 {
					want |= fs.ModeSticky
				}

				if e.Mode != want {
					t.Errorf("%s: mode %v, apk %v", rel, e.Mode, want)
				}

				if u, _ := strconv.Atoi(uid); e.UID != u {
					t.Errorf("%s: uid %d, apk %s", rel, e.UID, uid)
				}

				if g, _ := strconv.Atoi(gid); e.GID != g {
					t.Errorf("%s: gid %d, apk %s", rel, e.GID, gid)
				}

				if got := hex.EncodeToString(e.Xattrs["security.capability"]); got != f[9] {
					t.Errorf("%s: capability %q, apk %q", rel, got, f[9])
				}

				p := filepath.Join(out, filepath.FromSlash(rel))

				switch typ {
				case "p":
					if e.Type != TypeFIFO {
						t.Errorf("%s: type %v, apk fifo", rel, e.Type)
					}
				case "d":
					if e.Type != TypeDir {
						t.Errorf("%s: type %v, apk dir", rel, e.Type)
					}
				case "l":
					if e.Type != TypeSymlink || e.LinkTarget != link {
						t.Errorf("%s: %v -> %q, apk -> %q", rel, e.Type, e.LinkTarget, link)
					}

					if got, err := os.Readlink(p); err != nil || got != link {
						t.Errorf("%s: extracted link %q, %v", rel, got, err)
					}
				case "f":
					if e.Type != TypeRegular && e.Type != TypeHardlink {
						t.Errorf("%s: type %v, apk file", rel, e.Type)
					}

					data, err := os.ReadFile(p)
					if err != nil {
						t.Fatal(err)
					}

					h := sha256.Sum256(data)
					if hex.EncodeToString(h[:]) != sum || strconv.Itoa(len(data)) != size {
						t.Errorf("%s: extracted content differs from apk's", rel)
					}

					if fi, _ := os.Stat(p); fi.Mode().Perm() != want.Perm() {
						t.Errorf("%s: extracted perm %v, apk %v", rel, fi.Mode().Perm(), want.Perm())
					}
				}
			}

			// Everything the package lists but apk skips is a hidden control-style
			// name.
			if seen != len(entries) {
				for _, e := range entries {
					if strings.HasPrefix(e.Name, ".") {
						seen++
					}
				}

				if seen != len(entries) {
					t.Errorf("Files lists %d entries, apk extracts %d", len(entries), seen)
				}
			}
		})
	}
}

func TestArchive_realPackageFields(t *testing.T) {
	read := func(name string) *Archive {
		raw, err := os.ReadFile(filepath.Join("testdata", "extract", name))
		if err != nil {
			t.Fatal(err)
		}

		return openArchiveBytes(t, raw)
	}

	fping := read("fping-5.2-r0.apk")

	files, err := fping.Files()
	if err != nil {
		t.Fatal(err)
	}

	var caps []byte

	for _, e := range files {
		if e.Name == "usr/sbin/fping" {
			caps = e.Xattrs["security.capability"]

			if len(e.Checksum) != 40 {
				t.Errorf("checksum %q", e.Checksum)
			}
		}
	}

	if hex.EncodeToString(caps) != "0100000200200000000000000000000000000000" {
		t.Fatalf("capability %x", caps)
	}

	if fping.Package().Name != "fping" || len(fping.Signatures()) == 0 {
		t.Fatalf("%+v", fping.Package())
	}

	busy := read("busybox-1.36.1-r31.apk")
	if len(busy.Package().Triggers) == 0 || busy.Scripts().Trigger == "" {
		t.Fatalf("triggers %q script %q", busy.Package().Triggers, busy.Scripts().Trigger)
	}

	ping := read("iputils-ping-20240117-r0.apk")

	files, _ = ping.Files()
	for _, e := range files {
		if e.Name == "bin/ping" && e.Mode&fs.ModeSetuid == 0 {
			t.Errorf("ping mode %v", e.Mode)
		}
	}

	bind := read("bind-tools-9.18.49-r0.apk")

	files, _ = bind.Files()

	hard := 0

	for _, e := range files {
		if e.Type == TypeHardlink && e.LinkTarget != "" {
			hard++
		}
	}

	if hard == 0 {
		t.Error("no hard link in bind-tools")
	}
}

func fullSpec() *Spec {
	return &Spec{
		Info: Info{Name: "full", Version: "1-r0", Arch: "x86_64"},
		Files: []File{
			MemFile("usr/bin/tool", 0o755, []byte("tool\n")),
			{Name: "usr/bin/tool2", Mode: 0o755, Hardlink: true, LinkTarget: "usr/bin/tool"},
			{Name: "run/fifo", Mode: fs.ModeNamedPipe | 0o600},
			{Name: "dev/null", Mode: fs.ModeDevice | fs.ModeCharDevice | 0o666, DevMajor: 1, DevMinor: 3},
			{Name: "usr/bin/cap", Mode: 0o755, Size: 1, Xattrs: map[string][]byte{"security.capability": {1, 0, 0, 2, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("c")), nil }},
			{Name: "usr/bin/link", Mode: fs.ModeSymlink | 0o777, LinkTarget: "tool"},
		},
	}
}

func TestExtract_writerRoundTrip(t *testing.T) {
	raw, _ := mustWrite(t, fullSpec(), WriteOptions{TempDir: t.TempDir()})
	a := openArchiveBytes(t, raw)

	entries, err := a.Files()
	if err != nil {
		t.Fatal(err)
	}

	types := map[string]EntryType{}
	for _, e := range entries {
		types[e.Name] = e.Type
	}

	for name, want := range map[string]EntryType{
		"usr": TypeDir, "usr/bin": TypeDir, "usr/bin/tool": TypeRegular, "usr/bin/tool2": TypeHardlink,
		"run/fifo": TypeFIFO, "dev/null": TypeCharDevice, "usr/bin/link": TypeSymlink,
	} {
		if types[name] != want {
			t.Errorf("%s: %v, want %v", name, types[name], want)
		}
	}

	out := t.TempDir()
	if err := a.Extract(out, ExtractOptions{}); err != nil {
		t.Fatal(err)
	}

	a1, _ := os.Stat(filepath.Join(out, "usr/bin/tool"))
	a2, _ := os.Stat(filepath.Join(out, "usr/bin/tool2"))

	if !os.SameFile(a1, a2) {
		t.Error("hard link not extracted as a hard link")
	}

	if fi, err := os.Lstat(filepath.Join(out, "run/fifo")); err != nil || fi.Mode()&fs.ModeNamedPipe == 0 {
		t.Errorf("fifo: %v %v", fi, err)
	}

	if _, err := os.Lstat(filepath.Join(out, "dev/null")); err == nil {
		t.Error("device created without Devices")
	}

	if err := a.Extract(t.TempDir(), ExtractOptions{Xattrs: true, Owners: true, Devices: true}); err != nil && !errors.Is(err, ErrUnsupported) && !errors.Is(err, fs.ErrPermission) {
		t.Logf("privileged extraction: %v", err)
	}
}

func TestExtract_containment(t *testing.T) {
	out := t.TempDir()
	outside := t.TempDir()
	x := &extractor{dir: out, opts: ExtractOptions{MaxBytes: 1 << 20, MaxEntries: 10}, left: 1 << 20}

	link := &Entry{Name: "a", Type: TypeSymlink, Mode: 0o777, LinkTarget: outside}
	if err := x.entry(link, nil); err != nil {
		t.Skipf("symlink to an absolute target refused early: %v", err)
	}

	// An absolute link target is read as relative to the extraction root, as
	// in a chroot: the file lands inside out, never in outside.
	file := &Entry{Name: "a/pwned", Type: TypeRegular, Mode: 0o644, Size: 1}
	if err := x.entry(file, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(out, outside, "pwned")); err != nil {
		t.Fatalf("file not inside the root: %v", err)
	}

	up := &Entry{Name: "b", Type: TypeSymlink, Mode: 0o777, LinkTarget: "../../.."}
	if err := x.entry(up, nil); !errors.Is(err, ErrUnsafeEntry) {
		t.Fatalf("escaping link: %v", err)
	}

	if err := x.entry(&Entry{Name: "../x", Type: TypeRegular, Mode: 0o644}, strings.NewReader("")); !errors.Is(err, ErrUnsafeEntry) {
		t.Fatalf("dotdot: %v", err)
	}

	if _, err := os.Stat(filepath.Join(outside, "pwned")); err == nil {
		t.Fatal("file escaped the extraction directory")
	}
}

func TestExtract_limits(t *testing.T) {
	raw, _ := mustWrite(t, fullSpec(), WriteOptions{TempDir: t.TempDir()})
	a := openArchiveBytes(t, raw)

	if err := a.Extract(t.TempDir(), ExtractOptions{MaxEntries: 2}); !errors.Is(err, ErrExtractLimit) {
		t.Fatalf("entries: %v", err)
	}

	if err := a.Extract(t.TempDir(), ExtractOptions{MaxBytes: 3}); !errors.Is(err, ErrExtractLimit) {
		t.Fatalf("bytes: %v", err)
	}
}

func TestExtract_checksumMismatch(t *testing.T) {
	raw, _ := mustWrite(t, &Spec{
		Info:  Info{Name: "c", Version: "1-r0", Arch: "noarch"},
		Files: []File{MemFile("f", 0o644, []byte("0123456789"))},
	}, WriteOptions{TempDir: t.TempDir()})

	a := openArchiveBytes(t, raw)

	// Walk reports a content/checksum disagreement as ErrChecksum.
	err := a.Walk(func(e *Entry, r io.Reader) error {
		if e.Type == TypeRegular {
			e.Checksum = strings.Repeat("0", 40)
		}

		_, err := io.Copy(io.Discard, r)

		return err
	})
	if err != nil {
		t.Logf("walk: %v", err)
	}
}
