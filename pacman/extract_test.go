package pacman

import (
	"archive/tar"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const makepkgFixture = "testdata/makepkg/tree-shapes-1.0-1-any.pkg.tar.zst"

func fixtureBytes(t *testing.T) []byte {
	t.Helper()

	raw, err := os.ReadFile(makepkgFixture)
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

func TestExtractMakepkgPackage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	pkg, err := Extract(bytes.NewReader(fixtureBytes(t)), dir, ExtractOptions{
		Verify: true, VerifyOptions: VerifyOptions{IgnoreOwner: true}, SpecialFiles: true, Metadata: true,
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if pkg.Info.Name != "tree-shapes" || !slices.Contains(pkg.Files, "usr/bin/shape-hard") || !slices.Contains(pkg.Files, "usr/bin/") {
		t.Errorf("package %+v", pkg)
	}

	stat := func(p string) fs.FileInfo {
		t.Helper()

		fi, err := os.Lstat(filepath.Join(dir, p))
		if err != nil {
			t.Fatal(err)
		}

		return fi
	}

	if fi := stat("usr/bin/shape-suid"); fi.Mode()&fs.ModeSetuid == 0 || fi.Mode().Perm() != 0o755 {
		t.Errorf("suid mode %v", fi.Mode())
	}

	if fi := stat("usr/bin/shape-fifo"); fi.Mode()&fs.ModeNamedPipe == 0 || fi.Mode().Perm() != 0o640 {
		t.Errorf("fifo mode %v", fi.Mode())
	}

	if fi := stat("usr/bin/shape-sym"); fi.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("symlink mode %v", fi.Mode())
	}

	if target, _ := os.Readlink(filepath.Join(dir, "usr/bin/shape-sym")); target != "shape" {
		t.Errorf("symlink target %q", target)
	}

	if !os.SameFile(stat("usr/bin/shape"), stat("usr/bin/shape-hard")) {
		t.Error("hard link is a copy")
	}

	if fi := stat("usr/share/a b/c=d"); fi.ModTime().Unix() != 1700000000 {
		t.Errorf("mtime %v", fi.ModTime())
	}

	if fi := stat("usr/bin"); fi.ModTime().Unix() != 1700000000 || fi.Mode().Perm() != 0o755 {
		t.Errorf("dir %v %v", fi.ModTime(), fi.Mode())
	}

	for _, m := range []string{".PKGINFO", ".BUILDINFO", ".MTREE", ".INSTALL", ".CHANGELOG"} {
		if _, err := os.Stat(filepath.Join(dir, m)); err != nil {
			t.Errorf("metadata %s: %v", m, err)
		}
	}

	if v, err := getXattr(filepath.Join(dir, "usr/share/tagged"), "user.shape"); err == nil && v != "" {
		t.Errorf("xattr applied without the option: %q", v)
	}
}

func TestExtractWithoutOptionsSkipsSpecial(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if _, err := Extract(bytes.NewReader(fixtureBytes(t)), dir, ExtractOptions{}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(filepath.Join(dir, "usr/bin/shape-fifo")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("fifo created without SpecialFiles: %v", err)
	}

	if _, err := os.Lstat(filepath.Join(dir, ".PKGINFO")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("metadata written without the option: %v", err)
	}
}

func TestExtractXattrs(t *testing.T) {
	t.Parallel()

	probe := filepath.Join(t.TempDir(), "p")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := setXattr(probe, "user.probe", []byte("1")); err != nil {
		t.Skipf("no user xattrs here: %v", err)
	}

	dir := t.TempDir()

	if _, err := Extract(bytes.NewReader(fixtureBytes(t)), dir, ExtractOptions{Xattrs: true}); err != nil {
		t.Fatal(err)
	}

	if v, err := getXattr(filepath.Join(dir, "usr/share/tagged"), "user.shape"); err != nil || v != "tagged" {
		t.Errorf("xattr = %q, %v", v, err)
	}
}

func TestExtractUmaskDropsSpecialBits(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if _, err := Extract(bytes.NewReader(fixtureBytes(t)), dir, ExtractOptions{Umask: 0o7022}); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Lstat(filepath.Join(dir, "usr/bin/shape-suid"))
	if err != nil {
		t.Fatal(err)
	}

	if fi.Mode()&fs.ModeSetuid != 0 || fi.Mode().Perm() != 0o755&^0o022 {
		t.Errorf("mode %v", fi.Mode())
	}
}

func TestExtractChown(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	opts := ExtractOptions{Chown: true}

	_, err := Extract(bytes.NewReader(fixtureBytes(t)), dir, opts)

	if os.Geteuid() == 0 {
		if err != nil {
			t.Fatalf("Extract as root: %v", err)
		}

		fi, _ := os.Lstat(filepath.Join(dir, "usr/share/owned"))
		if st, _ := sysStat(fi); st.uid != 1234 || st.gid != 5678 {
			t.Errorf("owner %d:%d", st.uid, st.gid)
		}

		return
	}

	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("err = %v, want a permission error", err)
	}
}

type tm struct {
	hdr  tar.Header
	body string
}

func rawPackage(t *testing.T, members ...tm) []byte {
	t.Helper()

	var buf bytes.Buffer

	tw := tar.NewWriter(&buf)

	pkginfo := tm{hdr: tar.Header{Name: ".PKGINFO", Mode: 0o644}, body: samplePkgInfo}

	for _, m := range append([]tm{pkginfo}, members...) {
		h := m.hdr
		h.Size = int64(len(m.body))

		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}

		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}

		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}

		if h.Size > 0 {
			if _, err := tw.Write([]byte(m.body)); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	return compress(t, CompressionZstd, buf.Bytes())
}

func TestExtractContainment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		members []tm
		want    error
	}{
		{"parent traversal", []tm{{hdr: tar.Header{Name: "../evil", Mode: 0o644}, body: "x"}}, ErrUnsafeEntry},
		{"deep traversal", []tm{{hdr: tar.Header{Name: "a/../../evil", Mode: 0o644}, body: "x"}}, ErrUnsafeEntry},
		{"absolute", []tm{{hdr: tar.Header{Name: "/etc/evil", Mode: 0o644}, body: "x"}}, ErrUnsafeEntry},
		{"symlink out", []tm{{hdr: tar.Header{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "../../outside", Mode: 0o777}}}, ErrUnsafeEntry},
		{"hardlink out", []tm{{hdr: tar.Header{Name: "h", Typeflag: tar.TypeLink, Linkname: "../outside", Mode: 0o644}}}, ErrUnsafeEntry},
		{"hardlink to the root", []tm{{hdr: tar.Header{Name: "h", Typeflag: tar.TypeLink, Linkname: ".", Mode: 0o644}}}, ErrUnsafeEntry},
		{"control character", []tm{{hdr: tar.Header{Name: "a\nb", Mode: 0o644}, body: "x"}}, ErrUnsafeEntry},
		{"unsupported member", []tm{{hdr: tar.Header{Name: "c", Typeflag: tar.TypeCont, Mode: 0o644}}}, ErrUnsupportedFile},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base := t.TempDir()
			dir := filepath.Join(base, "root")

			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}

			_, err := Extract(bytes.NewReader(rawPackage(t, tc.members...)), dir, ExtractOptions{})
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}

			entries, _ := os.ReadDir(base)
			if len(entries) != 1 {
				t.Errorf("something was written beside the root: %v", entries)
			}
		})
	}
}

// A symbolic link inside the package, even an absolute one, does not carry a
// later entry out of the root: it is read as a chroot would read it.
func TestExtractSymlinkRedirectStaysInRoot(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	dir := filepath.Join(base, "root")

	if err := os.MkdirAll(filepath.Join(dir, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}

	raw := rawPackage(t,
		tm{hdr: tar.Header{Name: "lib", Typeflag: tar.TypeSymlink, Linkname: "/usr/lib", Mode: 0o777}},
		tm{hdr: tar.Header{Name: "lib/libx.so", Mode: 0o644}, body: "elf"},
		tm{hdr: tar.Header{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: "/", Mode: 0o777}},
		tm{hdr: tar.Header{Name: "evil/pwned", Mode: 0o644}, body: "x"},
	)

	if _, err := Extract(bytes.NewReader(raw), dir, ExtractOptions{}); err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if got, err := os.ReadFile(filepath.Join(dir, "usr/lib/libx.so")); err != nil || string(got) != "elf" {
		t.Errorf("lib/libx.so: %q %v", got, err)
	}

	if got, err := os.ReadFile(filepath.Join(dir, "pwned")); err != nil || string(got) != "x" {
		t.Errorf("evil/pwned landed outside the root: %q %v", got, err)
	}

	if entries, _ := os.ReadDir(base); len(entries) != 1 {
		t.Errorf("something was written beside the root: %v", entries)
	}
}

func TestExtractReplacesExisting(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "outside")

	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A file already there, and a symlink in the way of a file entry, are
	// replaced, not written through.
	if err := os.Symlink(target, filepath.Join(dir, "f")); err != nil {
		t.Fatal(err)
	}

	raw := rawPackage(t, tm{hdr: tar.Header{Name: "f", Mode: 0o644}, body: "new"})

	if _, err := Extract(bytes.NewReader(raw), dir, ExtractOptions{}); err != nil {
		t.Fatal(err)
	}

	if got, _ := os.ReadFile(target); string(got) != "keep" {
		t.Errorf("wrote through a symlink: %q", got)
	}

	if got, _ := os.ReadFile(filepath.Join(dir, "f")); string(got) != "new" {
		t.Errorf("f = %q", got)
	}
}

func TestExtractLimits(t *testing.T) {
	t.Parallel()

	raw := rawPackage(t,
		tm{hdr: tar.Header{Name: "a", Mode: 0o644}, body: strings.Repeat("x", 100)},
		tm{hdr: tar.Header{Name: "b", Mode: 0o644}, body: "y"},
	)

	if _, err := Extract(bytes.NewReader(raw), t.TempDir(), ExtractOptions{MaxBytes: 50}); !errors.Is(err, ErrExtractTooLarge) {
		t.Errorf("bytes: %v", err)
	}

	if _, err := Extract(bytes.NewReader(raw), t.TempDir(), ExtractOptions{MaxEntries: 2}); !errors.Is(err, ErrExtractTooLarge) {
		t.Errorf("entries: %v", err)
	}
}

func TestExtractErrors(t *testing.T) {
	t.Parallel()

	if _, err := Extract(strings.NewReader("not a package"), t.TempDir(), ExtractOptions{}); !errors.Is(err, ErrNotPackage) {
		t.Errorf("garbage: %v", err)
	}

	noInfo := compress(t, CompressionZstd, buildTar(t, []member{{name: "a", body: "x"}}))
	if _, err := Extract(bytes.NewReader(noInfo), t.TempDir(), ExtractOptions{}); !errors.Is(err, ErrNoPkgInfo) {
		t.Errorf("no .PKGINFO: %v", err)
	}

	dup := rawPackage(t, tm{hdr: tar.Header{Name: ".PKGINFO", Mode: 0o644}, body: samplePkgInfo})
	if _, err := Extract(bytes.NewReader(dup), t.TempDir(), ExtractOptions{}); !errors.Is(err, ErrInvalidField) {
		t.Errorf("duplicate .PKGINFO: %v", err)
	}

	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Extract(bytes.NewReader(fixtureBytes(t)), file, ExtractOptions{}); err == nil {
		t.Error("extracting into a file succeeded")
	}
}

func TestExtractVerifyDetectsTampering(t *testing.T) {
	t.Parallel()

	mtree := "#mtree\n/set type=file uid=0 gid=0 mode=644\n./a time=1700000000.0 size=1 sha256digest=" +
		strings.Repeat("0", 64) + "\n./gone time=1700000000.0 size=1 sha256digest=" + strings.Repeat("0", 64) + "\n"

	raw := rawPackage(t,
		tm{hdr: tar.Header{Name: ".MTREE", Mode: 0o644}, body: mtree},
		tm{hdr: tar.Header{Name: "a", Mode: 0o644, ModTime: time.Unix(1700000000, 0)}, body: "x"},
		tm{hdr: tar.Header{Name: "extra", Mode: 0o644}, body: "e"},
	)

	dir := t.TempDir()

	_, err := Extract(bytes.NewReader(raw), dir, ExtractOptions{Verify: true, VerifyOptions: VerifyOptions{IgnoreOwner: true}})

	var me *MtreeError
	if !errors.As(err, &me) || !errors.Is(err, ErrMtreeMismatch) {
		t.Fatalf("err = %v", err)
	}

	kinds := map[string]bool{}
	for _, d := range me.Diffs {
		kinds[d.Path+"/"+d.Kind.String()+"/"+d.Keyword] = true
	}

	for _, k := range []string{"a/mismatch/sha256digest", "gone/missing/", "extra/extra/"} {
		if !kinds[k] {
			t.Errorf("missing difference %s in %v", k, kinds)
		}
	}

	if _, err := os.Stat(filepath.Join(dir, "a")); err != nil {
		t.Errorf("files are not kept after a verification failure: %v", err)
	}

	// No .MTREE at all.
	_, err = Extract(bytes.NewReader(rawPackage(t)), t.TempDir(), ExtractOptions{Verify: true})
	if !errors.Is(err, ErrNoMtree) {
		t.Errorf("no mtree: %v", err)
	}
}
