package pacman

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // reference digest of the test
)

func TestDigester(t *testing.T) {
	t.Parallel()

	data := []byte("123456789")
	d := newDigester(digestKeys)

	if _, err := d.w.Write(data); err != nil {
		t.Fatal(err)
	}

	got := d.sums()

	md5sum := md5.Sum(data)
	sha1sum := sha1.Sum(data)
	s256 := sha256.Sum256(data)
	s384 := sha512.Sum384(data)
	s512 := sha512.Sum512(data)

	rmd := ripemd160.New()
	_, _ = rmd.Write(data)

	for key, want := range map[MtreeKeys]string{
		KeyMD5: hex.EncodeToString(md5sum[:]), KeySHA1: hex.EncodeToString(sha1sum[:]), KeySHA256: hex.EncodeToString(s256[:]),
		KeySHA384: hex.EncodeToString(s384[:]), KeySHA512: hex.EncodeToString(s512[:]),
		KeyRMD160: hex.EncodeToString(rmd.Sum(nil)),
		// cksum(1) of "123456789": the POSIX test vector.
		KeyCksum: "930766865",
	} {
		if v := got.value(key); v != want {
			t.Errorf("key %b: %s, want %s", key, v, want)
		}
	}

	// Only what was asked is computed.
	if only := newDigester(KeySHA256); len(only.hashes) != 1 || only.cksum != nil {
		t.Errorf("digester computes more than asked: %+v", only)
	}

	// The empty content has the cksum of an empty file.
	if e := newDigester(KeyCksum); e.sums().cksum != "4294967295" {
		t.Errorf("empty cksum = %s", e.sums().cksum)
	}
}

func TestVerifyPackageMakepkg(t *testing.T) {
	t.Parallel()

	if err := VerifyPackage(bytes.NewReader(fixtureBytes(t)), VerifyOptions{}); err != nil {
		t.Errorf("makepkg package: %v", err)
	}
}

func TestVerifyPackageWithGivenMtree(t *testing.T) {
	t.Parallel()

	raw := fixtureBytes(t)

	md, err := ReadMetadata(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyPackageWith(bytes.NewReader(raw), md.Mtree, VerifyOptions{}); err != nil {
		t.Errorf("VerifyPackageWith: %v", err)
	}

	// A different mtree fails.
	other := parseMtreeText(t, "./usr type=dir\n./x type=file size=1\n")
	if err := VerifyPackageWith(bytes.NewReader(raw), other, VerifyOptions{}); !errors.Is(err, ErrMtreeMismatch) {
		t.Errorf("other mtree: %v", err)
	}

	if err := VerifyPackageWith(strings.NewReader("junk"), md.Mtree, VerifyOptions{}); !errors.Is(err, ErrNotPackage) {
		t.Errorf("junk: %v", err)
	}
}

// mtreePackage builds a package with the given .MTREE text and one file.
func mtreePackage(t *testing.T, mtree string, members ...tm) []byte {
	t.Helper()

	all := []tm{{hdr: tar.Header{Name: ".MTREE", Mode: 0o644}, body: mtree}}

	return rawPackage(t, append(all, members...)...)
}

func TestVerifyPackageKeywords(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256([]byte("body"))
	good := hex.EncodeToString(sum[:])
	mtime := time.Unix(1700000000, 0)

	base := func(extra string) string {
		return "#mtree\n./.PKGINFO type=file mode=644 uid=0 gid=0\n./f type=file mode=644 uid=0 gid=0 uname=root gname=root size=4 time=1700000000.0 " + extra + "\n"
	}

	file := tm{hdr: tar.Header{Name: "f", Mode: 0o644, Uname: "root", Gname: "root", ModTime: mtime}, body: "body"}

	tests := []struct {
		name    string
		mtree   string
		member  tm
		opts    VerifyOptions
		keyword string
	}{
		{name: "clean", mtree: base("sha256digest=" + good), member: file},
		{name: "size", mtree: strings.Replace(base("sha256digest="+good), "size=4", "size=5", 1), member: file, keyword: "size"},
		{name: "mode", mtree: strings.Replace(base("sha256digest="+good), "mode=644 uid=0 gid=0 uname", "mode=600 uid=0 gid=0 uname", 1), member: file, keyword: "mode"},
		{name: "mode ignored", mtree: strings.Replace(base("sha256digest="+good), "mode=644 uid=0 gid=0 uname", "mode=600 uid=0 gid=0 uname", 1), member: file, opts: VerifyOptions{IgnoreMode: true}},
		{name: "uid", mtree: strings.Replace(base("sha256digest="+good), " uid=0 gid=0 uname", " uid=5 gid=0 uname", 1), member: file, keyword: "uid"},
		{name: "gid", mtree: strings.Replace(base("sha256digest="+good), " gid=0 uname", " gid=5 uname", 1), member: file, keyword: "gid"},
		{name: "uname", mtree: strings.Replace(base("sha256digest="+good), "uname=root", "uname=bob", 1), member: file, keyword: "uname"},
		{name: "gname", mtree: strings.Replace(base("sha256digest="+good), "gname=root", "gname=bob", 1), member: file, keyword: "gname"},
		{name: "owner ignored", mtree: strings.Replace(base("sha256digest="+good), " uid=0 gid=0 uname", " uid=5 gid=0 uname", 1), member: file, opts: VerifyOptions{IgnoreOwner: true}},
		{name: "time", mtree: strings.Replace(base("sha256digest="+good), "time=1700000000.0", "time=1700000001.0", 1), member: file, keyword: "time"},
		{name: "time ignored", mtree: strings.Replace(base("sha256digest="+good), "time=1700000000.0", "time=1.0", 1), member: file, opts: VerifyOptions{IgnoreTime: true}},
		{name: "sha256", mtree: base("sha256digest=" + strings.Repeat("1", 64)), member: file, keyword: "sha256digest"},
		{name: "md5", mtree: base("md5digest=" + strings.Repeat("1", 32)), member: file, keyword: "md5digest"},
		{name: "sha1", mtree: base("sha1digest=" + strings.Repeat("1", 40)), member: file, keyword: "sha1digest"},
		{name: "sha512", mtree: base("sha512digest=" + strings.Repeat("1", 128)), member: file, keyword: "sha512digest"},
		{name: "cksum", mtree: base("cksum=1"), member: file, keyword: "cksum"},
		{name: "skipped content", mtree: base("sha256digest=" + strings.Repeat("1", 64)), member: file, opts: VerifyOptions{SkipContent: func(p string) bool { return p == "f" }}},
		{name: "type", mtree: "#mtree\n./f type=dir\n", member: file, keyword: "type"},
		{
			name: "link", mtree: "#mtree\n./f type=link link=a mode=777\n",
			member: tm{hdr: tar.Header{Name: "f", Typeflag: tar.TypeSymlink, Linkname: "b", Mode: 0o777}}, keyword: "link",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := VerifyPackage(bytes.NewReader(mtreePackage(t, tc.mtree, tc.member)), tc.opts)

			if tc.keyword == "" {
				// The .PKGINFO of the fixture is listed without digest or size.
				var me *MtreeError
				if errors.As(err, &me) {
					for _, d := range me.Diffs {
						t.Errorf("unexpected: %s", d)
					}
				} else if err != nil {
					t.Fatal(err)
				}

				return
			}

			var me *MtreeError
			if !errors.As(err, &me) {
				t.Fatalf("err = %v", err)
			}

			if !slices.ContainsFunc(me.Diffs, func(d MtreeDiff) bool { return d.Keyword == tc.keyword && d.Path == "f" }) {
				t.Errorf("no %s difference: %v", tc.keyword, me.Diffs)
			}
		})
	}
}

func TestVerifyPackageHardLinkAndDigestKeys(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256([]byte("body"))
	h := hex.EncodeToString(sum[:])

	mtree := "#mtree\n/set type=file uid=0 gid=0 mode=644\n./.PKGINFO\n./a size=4 sha256digest=" + h + "\n./b size=4 sha256digest=" + h + "\n"
	raw := mtreePackage(t, mtree,
		tm{hdr: tar.Header{Name: "a", Mode: 0o644}, body: "body"},
		tm{hdr: tar.Header{Name: "b", Mode: 0o644, Typeflag: tar.TypeLink, Linkname: "a"}},
	)

	if err := VerifyPackage(bytes.NewReader(raw), VerifyOptions{IgnoreTime: true}); err != nil {
		t.Errorf("hard link: %v", err)
	}
}

func TestVerifyPackageOptionalAndNoMtree(t *testing.T) {
	t.Parallel()

	raw := mtreePackage(t, "#mtree\n./.PKGINFO type=file\n./maybe type=file optional\n./needed type=file\n")

	var me *MtreeError
	if err := VerifyPackage(bytes.NewReader(raw), VerifyOptions{}); !errors.As(err, &me) {
		t.Fatalf("err = %v", err)
	}

	if len(me.Diffs) != 1 || me.Diffs[0].Path != "needed" || me.Diffs[0].Kind != DiffMissing {
		t.Errorf("diffs = %v", me.Diffs)
	}

	if !strings.Contains(me.Error(), "needed: missing") || !strings.Contains(me.String(), "needed: missing") {
		t.Errorf("messages: %q %q", me.Error(), me.String())
	}

	if err := VerifyPackage(bytes.NewReader(rawPackage(t)), VerifyOptions{}); !errors.Is(err, ErrNoMtree) {
		t.Errorf("no mtree: %v", err)
	}
}

func TestMtreeErrorFormatting(t *testing.T) {
	t.Parallel()

	e := &MtreeError{Diffs: []MtreeDiff{
		{Path: "a", Kind: DiffMismatch, Keyword: "size", Want: "1", Got: "2"},
		{Path: "b", Kind: DiffExtra},
	}}

	if got := e.Error(); !strings.Contains(got, "a: size is 2, the .MTREE has 1") || !strings.Contains(got, "2 differences") {
		t.Errorf("Error() = %q", got)
	}

	e.Truncated = true

	if !strings.Contains(e.Error(), "or more") || !errors.Is(e, ErrMtreeMismatch) {
		t.Errorf("truncated: %q", e.Error())
	}

	if (&MtreeError{Diffs: []MtreeDiff{{Path: "x", Kind: DiffMissing}}}).Error() == "" || DiffKind(9).String() != "mismatch" {
		t.Error("formatting")
	}
}

func TestDiffSinkTruncates(t *testing.T) {
	t.Parallel()

	var s diffSink

	for range MaxMtreeDiffs + 5 {
		s.add(MtreeDiff{Path: "x"})
	}

	err := s.err()

	var me *MtreeError
	if !errors.As(err, &me) || len(me.Diffs) != MaxMtreeDiffs || !me.Truncated {
		t.Errorf("err = %v", err)
	}

	if (&diffSink{}).err() != nil {
		t.Error("empty sink has an error")
	}
}

// installed extracts the makepkg fixture into a root and returns the root and
// the .MTREE of the package.
func installed(t *testing.T) (string, *Mtree) {
	t.Helper()

	root := t.TempDir()

	if _, err := Extract(bytes.NewReader(fixtureBytes(t)), root, ExtractOptions{SpecialFiles: true}); err != nil {
		t.Fatal(err)
	}

	md, err := ReadMetadata(bytes.NewReader(fixtureBytes(t)))
	if err != nil {
		t.Fatal(err)
	}

	return root, md.Mtree
}

func verifyRoot(t *testing.T, root string, mt *Mtree, opts VerifyOptions) error {
	t.Helper()

	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = r.Close() }()

	return VerifyInstalled(r.FS(), mt, opts)
}

func TestVerifyInstalled(t *testing.T) {
	t.Parallel()

	// The owner of the fixture's "owned" file is not ours, so owners are not
	// compared here; every other keyword is.
	opts := VerifyOptions{IgnoreOwner: true}

	t.Run("clean", func(t *testing.T) {
		t.Parallel()

		root, mt := installed(t)

		// .PKGINFO and friends are listed but not installed.
		if err := verifyRoot(t, root, mt, opts); err != nil {
			t.Fatalf("err = %v", err)
		}
	})

	mutations := []struct {
		name    string
		mutate  func(t *testing.T, root string)
		path    string
		kind    DiffKind
		keyword string
	}{
		{"content", func(t *testing.T, r string) { write(t, r, "usr/bin/shape", "#!/bin/zsh\n") }, "usr/bin/shape", DiffMismatch, "sha256digest"},
		{"size", func(t *testing.T, r string) { write(t, r, "etc/shapes.conf", "x=12345\n") }, "etc/shapes.conf", DiffMismatch, "size"},
		{"mode", func(t *testing.T, r string) { chmod(t, r, "etc/shapes.conf", 0o600) }, "etc/shapes.conf", DiffMismatch, "mode"},
		{"time", func(t *testing.T, r string) { touch(t, r, "etc/shapes.conf") }, "etc/shapes.conf", DiffMismatch, "time"},
		{"missing", func(t *testing.T, r string) { remove(t, r, "usr/bin/shape-hard") }, "usr/bin/shape-hard", DiffMissing, ""},
		{"link target", func(t *testing.T, r string) {
			remove(t, r, "usr/bin/shape-sym")

			if err := os.Symlink("elsewhere", filepath.Join(r, "usr/bin/shape-sym")); err != nil {
				t.Fatal(err)
			}
		}, "usr/bin/shape-sym", DiffMismatch, "link"},
		{"type", func(t *testing.T, r string) {
			remove(t, r, "etc/shapes.conf")

			if err := os.Mkdir(filepath.Join(r, "etc/shapes.conf"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "etc/shapes.conf", DiffMismatch, "type"},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()

			root, mt := installed(t)
			m.mutate(t, root)

			var me *MtreeError
			if err := verifyRoot(t, root, mt, opts); !errors.As(err, &me) {
				t.Fatalf("err = %v", err)
			}

			if !slices.ContainsFunc(me.Diffs, func(d MtreeDiff) bool {
				return d.Path == m.path && d.Kind == m.kind && d.Keyword == m.keyword
			}) {
				t.Errorf("no %s difference at %s: %v", m.keyword, m.path, me.Diffs)
			}
		})
	}

	t.Run("skip content", func(t *testing.T) {
		t.Parallel()

		root, mt := installed(t)
		write(t, root, "etc/shapes.conf", "edited by the user\n")

		skip := opts
		skip.SkipContent = func(p string) bool { return p == "etc/shapes.conf" }

		if err := verifyRoot(t, root, mt, skip); err != nil {
			t.Errorf("a skipped file differs: %v", err)
		}
	})

	t.Run("owner", func(t *testing.T) {
		t.Parallel()

		root, mt := installed(t)

		err := verifyRoot(t, root, mt, VerifyOptions{})

		// Everything the extracting user owns differs from root:root.
		var me *MtreeError
		if os.Geteuid() != 0 && (!errors.As(err, &me) || !slices.ContainsFunc(me.Diffs, func(d MtreeDiff) bool { return d.Keyword == "uid" })) {
			t.Errorf("no uid difference: %v", err)
		}
	})

	t.Run("optional", func(t *testing.T) {
		t.Parallel()

		mt := parseMtreeText(t, "./gone type=file optional\n./. type=dir\n")
		if err := verifyRoot(t, t.TempDir(), mt, VerifyOptions{}); err != nil {
			t.Errorf("optional: %v", err)
		}
	})
}

func write(t *testing.T, root, name, data string) {
	t.Helper()

	p := filepath.Join(root, name)

	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}

	mode := st.Mode().Perm()

	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}

	if err := os.Chtimes(p, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
}

func chmod(t *testing.T, root, name string, m fs.FileMode) {
	t.Helper()

	if err := os.Chmod(filepath.Join(root, name), m); err != nil {
		t.Fatal(err)
	}
}

func touch(t *testing.T, root, name string) {
	t.Helper()

	now := time.Now()
	if err := os.Chtimes(filepath.Join(root, name), now, now); err != nil {
		t.Fatal(err)
	}
}

func remove(t *testing.T, root, name string) {
	t.Helper()

	if err := os.Remove(filepath.Join(root, name)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyInstalledUnreadableFile(t *testing.T) {
	t.Parallel()

	mt := parseMtreeText(t, "./f type=file sha256digest="+strings.Repeat("0", 64)+"\n")
	fsys := fstest.MapFS{"f": {Data: []byte("x"), Mode: 0o644}}

	// A MapFS has no Lstat of its own: fs.Lstat falls back to Stat.
	var me *MtreeError
	if err := VerifyInstalled(fsys, mt, VerifyOptions{}); !errors.As(err, &me) {
		t.Fatalf("err = %v", err)
	}

	if me.Diffs[0].Keyword != "sha256digest" {
		t.Errorf("diffs = %v", me.Diffs)
	}

	broken := fstest.MapFS{}
	if err := VerifyInstalled(broken, mt, VerifyOptions{}); !errors.As(err, &me) || me.Diffs[0].Kind != DiffMissing {
		t.Errorf("missing: %v", err)
	}

	if err := VerifyInstalled(failFS{}, mt, VerifyOptions{}); err == nil || errors.As(err, &me) && len(me.Diffs) > 0 && me.Diffs[0].Kind == DiffMissing {
		t.Errorf("a hard error was reported as missing: %v", err)
	}
}

// failFS fails every Stat with an error that is not "not exist".
type failFS struct{}

func (failFS) Open(string) (fs.File, error) { return nil, fs.ErrPermission }

func TestVerifyMtreeDiffString(t *testing.T) {
	t.Parallel()

	for d, want := range map[MtreeDiff]string{
		{Path: "p", Kind: DiffMissing}:                                        "p: missing",
		{Path: "p", Kind: DiffExtra}:                                          "p: extra",
		{Path: "p", Keyword: "mode", Want: "644", Got: "600"}:                 "p: mode is 600, the .MTREE has 644",
		{Path: "q", Kind: DiffMismatch, Keyword: "size", Want: "1", Got: "2"}: "q: size is 2, the .MTREE has 1",
	} {
		if got := d.String(); got != want {
			t.Errorf("%q, want %q", got, want)
		}
	}
}

func TestReadEntryAndWalk(t *testing.T) {
	t.Parallel()

	var seen []string

	err := WalkPackage(bytes.NewReader(fixtureBytes(t)), func(e *Entry, body io.Reader) error {
		seen = append(seen, e.Path)

		switch e.Path {
		case "usr/bin/shape-hard":
			if e.Hardlink != "usr/bin/shape" || e.IsRegular() || e.Size != 0 {
				t.Errorf("hard link %+v", e)
			}
		case "usr/bin/shape-fifo":
			if e.Mode&fs.ModeNamedPipe == 0 || e.Mode.Perm() != 0o640 {
				t.Errorf("fifo %+v", e)
			}
		case "usr/share/owned":
			if e.UID != 1234 || e.GID != 5678 {
				t.Errorf("owner %+v", e)
			}
		case "usr/share/tagged":
			if string(e.Xattrs["user.shape"]) != "tagged" {
				t.Errorf("xattrs %v", e.Xattrs)
			}
		case "usr/bin":
			if !e.IsDir() {
				t.Errorf("dir %+v", e)
			}
		case ".PKGINFO":
			if !e.IsMetadata() || !e.IsRegular() {
				t.Errorf(".PKGINFO %+v", e)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(seen) != 19 || seen[0] != ".BUILDINFO" {
		t.Errorf("walked %v", seen)
	}

	stop := errors.New("stop")
	if err := WalkPackage(bytes.NewReader(fixtureBytes(t)), func(*Entry, io.Reader) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("stop: %v", err)
	}
}

func TestWalkPackageRejectsHeaders(t *testing.T) {
	t.Parallel()

	bigValue := strings.Repeat("v", MaxXattrValueBytes+1)

	tests := map[string]tar.Header{
		"huge xattr":      {Name: "a", Mode: 0o644, PAXRecords: map[string]string{paxSchilyXattr + "user.x": bigValue}},
		"bad base64":      {Name: "a", Mode: 0o644, PAXRecords: map[string]string{paxLibarchiveAttr + "user.x": "!!"}},
		"bad escape":      {Name: "a", Mode: 0o644, PAXRecords: map[string]string{paxLibarchiveAttr + "%zz": "AA=="}},
		"empty name":      {Name: "a", Mode: 0o644, PAXRecords: map[string]string{paxLibarchiveAttr: "AA=="}},
		"huge libarchive": {Name: "a", Mode: 0o644, PAXRecords: map[string]string{paxLibarchiveAttr + "user.x": base64.StdEncoding.EncodeToString(make([]byte, MaxXattrValueBytes+1))}},
	}

	for name, h := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h.Format = tar.FormatPAX

			raw := rawPackage(t, tm{hdr: h, body: "x"})
			if err := WalkPackage(bytes.NewReader(raw), func(*Entry, io.Reader) error { return nil }); !errors.Is(err, ErrUnsafeEntry) {
				t.Errorf("err = %v", err)
			}
		})
	}

	t.Run("too many xattrs", func(t *testing.T) {
		t.Parallel()

		recs := map[string]string{}
		for i := range MaxEntryXattrs + 1 {
			recs[paxSchilyXattr+"user."+strings.Repeat("n", i+1)] = "v"
		}

		raw := rawPackage(t, tm{hdr: tar.Header{Name: "a", Mode: 0o644, PAXRecords: recs, Format: tar.FormatPAX}, body: "x"})
		if err := WalkPackage(bytes.NewReader(raw), func(*Entry, io.Reader) error { return nil }); !errors.Is(err, ErrUnsafeEntry) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("both records agree", func(t *testing.T) {
		t.Parallel()

		h := tar.Header{
			Name: "a", Mode: 0o644, Format: tar.FormatPAX,
			PAXRecords: map[string]string{paxSchilyXattr + "user.x": "raw", paxLibarchiveAttr + "user.x": "AA=="},
		}

		var got map[string][]byte

		raw := rawPackage(t, tm{hdr: h, body: "x"})
		_ = WalkPackage(bytes.NewReader(raw), func(e *Entry, _ io.Reader) error {
			if e.Path == "a" {
				got = e.Xattrs
			}

			return nil
		})

		if string(got["user.x"]) != "raw" {
			t.Errorf("xattrs = %q", got)
		}
	})
}
