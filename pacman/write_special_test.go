package pacman

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func mtreeText(t *testing.T, gz []byte) string {
	t.Helper()

	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}

	text, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}

	return string(text)
}

func specialSpec() *Spec {
	s := sampleSpec()
	s.Files = []File{
		{Path: "usr/bin/tool", Mode: 0o755, Data: []byte("#!/bin/sh\n")},
		{Path: "usr/bin/tool-link", Hardlink: "usr/bin/tool"},
		{Path: "usr/bin/aaa-link", Hardlink: "usr/bin/tool"},
		{Path: "run/queue", Mode: fs.ModeNamedPipe | 0o640},
		{Path: "dev/null", Mode: fs.ModeDevice | fs.ModeCharDevice | 0o666, DevMajor: 1, DevMinor: 3},
		{Path: "dev/loop0", Mode: fs.ModeDevice | 0o660, DevMajor: 7, DevMinor: 0, GID: 6, Gname: "disk"},
		{
			Path: "usr/bin/ping", Mode: fs.ModeSetuid | 0o755, Data: []byte("p"),
			Xattrs: map[string][]byte{"security.capability": {1, 0, 0, 2, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		},
		{Path: "var/lib/app/state", Mode: 0o600, Data: []byte("s"), UID: 1234, GID: 5678, Uname: "app", Gname: "apps"},
	}

	return s
}

func TestWriteSpecialFiles(t *testing.T) {
	t.Parallel()

	raw := writeSpec(t, specialSpec(), WriteOptions{ClampMTime: true})
	hdrs, bodies := members(t, raw)

	byName := map[string]*tar.Header{}
	for _, h := range hdrs {
		byName[strings.TrimSuffix(h.Name, "/")] = h
	}

	// The member that sorts first carries the data; the others link to it.
	carrier := byName["usr/bin/aaa-link"]
	if carrier.Typeflag != tar.TypeReg || string(bodies["usr/bin/aaa-link"]) != "#!/bin/sh\n" {
		t.Errorf("carrier: %+v", carrier)
	}

	for _, n := range []string{"usr/bin/tool", "usr/bin/tool-link"} {
		if h := byName[n]; h.Typeflag != tar.TypeLink || h.Linkname != "usr/bin/aaa-link" || h.Size != 0 || h.Mode != 0o755 {
			t.Errorf("%s: %+v", n, h)
		}
	}

	if h := byName["run/queue"]; h.Typeflag != tar.TypeFifo || h.Mode != 0o640 {
		t.Errorf("fifo: %+v", h)
	}

	if h := byName["dev/null"]; h.Typeflag != tar.TypeChar || h.Devmajor != 1 || h.Devminor != 3 {
		t.Errorf("char device: %+v", h)
	}

	if h := byName["dev/loop0"]; h.Typeflag != tar.TypeBlock || h.Devmajor != 7 || h.Gid != 6 || h.Gname != "disk" || h.Uname != "root" {
		t.Errorf("block device: %+v", h)
	}

	if h := byName["var/lib/app/state"]; h.Uid != 1234 || h.Gid != 5678 || h.Uname != "app" || h.Gname != "apps" {
		t.Errorf("owner: %+v", h)
	}

	ping := byName["usr/bin/ping"]
	capVal := "\x01\x00\x00\x02\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

	if ping.PAXRecords["SCHILY.xattr.security.capability"] != capVal ||
		ping.PAXRecords["LIBARCHIVE.xattr.security.capability"] != base64.StdEncoding.EncodeToString([]byte(capVal)) {
		t.Errorf("xattr records: %q", ping.PAXRecords)
	}

	// The .MTREE lists a hard link as the file it is, devices and pipes by type.
	mt := mtreeLines(t, bodies[".MTREE"])
	for path, want := range map[string]string{
		"./usr/bin/tool-link": "size=10 sha256digest=",
		"./run/queue":         "mode=640 type=fifo",
		"./dev/null":          "mode=666 type=char",
		"./dev/loop0":         "mode=660 gid=6 type=block",
	} {
		if !strings.Contains(mt[path], want) {
			t.Errorf("%s: %s", path, mt[path])
		}
	}

	if !strings.Contains(mt["./var/lib/app/state"], "mode=600 gid=5678 uid=1234 size=1") {
		t.Errorf("owner line: %s", mt["./var/lib/app/state"])
	}

	if err := VerifyPackage(bytes.NewReader(raw), VerifyOptions{}); err != nil {
		t.Errorf("VerifyPackage: %v", err)
	}
}

func TestWriteMtreeMD5(t *testing.T) {
	t.Parallel()

	s := &Spec{Info: sampleSpec().Info, Files: []File{{Path: "hello", Mode: 0o644, ModTime: time.Unix(buildTime, 0), Data: []byte("hello\n")}}}
	raw := writeSpec(t, s, WriteOptions{MtreeMD5: true})
	_, bodies := members(t, raw)

	want, err := os.ReadFile("testdata/makepkg/md5.expected")
	if err != nil {
		t.Fatal(err)
	}

	exp, err := ParseMtree(bytes.NewReader(want))
	if err != nil {
		t.Fatal(err)
	}

	wantEntry, _ := exp.Lookup("hello")
	got, err := ParseMtree(bytes.NewReader(bodies[".MTREE"]))
	if err != nil {
		t.Fatal(err)
	}

	gotEntry, _ := got.Lookup("hello")
	if gotEntry == nil || wantEntry == nil || gotEntry.MD5 != wantEntry.MD5 || gotEntry.SHA256 != wantEntry.SHA256 ||
		gotEntry.Size != wantEntry.Size || !gotEntry.Has(KeyMD5) {
		t.Errorf("md5 entry\n got %+v\nwant %+v", gotEntry, wantEntry)
	}

	// The digests come in bsdtar's order: md5 before sha256.
	line := mtreeLines(t, bodies[".MTREE"])["./hello"]
	if i, j := strings.Index(line, "md5digest="), strings.Index(line, "sha256digest="); i < 0 || j < i {
		t.Errorf("digest order: %s", line)
	}

	if err := VerifyPackage(bytes.NewReader(raw), VerifyOptions{}); err != nil {
		t.Errorf("VerifyPackage: %v", err)
	}

	// Without the option no md5 is written.
	if plain := mtreeText(t, bodies[".MTREE"]); !strings.Contains(plain, "md5digest=") {
		t.Errorf("no md5 with the option: %s", plain)
	}

	_, bodies = members(t, writeSpec(t, s, WriteOptions{}))
	if strings.Contains(mtreeText(t, bodies[".MTREE"]), "md5digest") {
		t.Error("md5 written by default")
	}
}

// TestMtreeMatchesMakepkg builds the package of testdata/makepkg with the
// writer and compares its .MTREE with the one makepkg wrote for it, entry by
// entry but for the metadata files whose digests depend on the generator.
func TestMtreeMatchesMakepkg(t *testing.T) {
	t.Parallel()

	data := func(s string) []byte { return []byte(s) }

	s := &Spec{
		Info: PkgInfo{Name: "tree-shapes", Version: "1.0-1", Description: "Every file type and owner a package can hold", Arch: "any", BuildDate: buildTime},
		Files: []File{
			{Path: "etc/shapes.conf", Mode: 0o644, Data: data("x=1\n")},
			{Path: "usr/bin/shape", Mode: 0o755, Data: data("#!/bin/sh\n")},
			{Path: "usr/bin/shape-hard", Hardlink: "usr/bin/shape"},
			{Path: "usr/bin/shape-sym", Mode: fs.ModeSymlink | 0o777, Linkname: "shape"},
			{Path: "usr/bin/shape-fifo", Mode: fs.ModeNamedPipe | 0o640},
			{Path: "usr/bin/shape-suid", Mode: fs.ModeSetuid | 0o755, Data: data("s\n")},
			{Path: "usr/share/a b/c=d", Mode: 0o644, Data: data("hi\n")},
			{Path: "usr/share/owned", Mode: 0o644, UID: 1234, GID: 5678, Data: data("owned\n")},
			{Path: "usr/share/tagged", Mode: 0o644, UID: 1000, GID: 1000, Data: data("tagged\n"), Xattrs: map[string][]byte{"user.shape": []byte("tagged")}},
		},
	}

	_, bodies := members(t, writeSpec(t, s, WriteOptions{ClampMTime: true}))

	want, err := os.ReadFile("testdata/makepkg/mtree.expected")
	if err != nil {
		t.Fatal(err)
	}

	exp, err := ParseMtree(strings.NewReader(string(want)))
	if err != nil {
		t.Fatal(err)
	}

	got, err := ParseMtree(bytes.NewReader(bodies[".MTREE"]))
	if err != nil {
		t.Fatal(err)
	}

	// bsdtar's use-set heuristic chooses where to repeat "/set", and it lists
	// the files of a directory before its subdirectories; the entries are
	// compared after the defaults are applied, by path.
	strip := func(m *Mtree) []MtreeEntry {
		var out []MtreeEntry

		for _, e := range m.Entries {
			if !strings.HasPrefix(e.Path, ".") || e.Path == "." {
				out = append(out, e)
			}
		}

		return out
	}

	byPath := func(a, b MtreeEntry) int { return strings.Compare(a.Path, b.Path) }
	g, w := strip(got), strip(exp)

	slices.SortFunc(g, byPath)
	slices.SortFunc(w, byPath)

	if len(g) != len(w) {
		t.Fatalf("%d entries, makepkg has %d", len(g), len(w))
	}

	for i := range w {
		if g[i].Path != w[i].Path || g[i].Type != w[i].Type || g[i].Mode != w[i].Mode || g[i].UID != w[i].UID ||
			g[i].GID != w[i].GID || g[i].Size != w[i].Size || !g[i].Time.Equal(w[i].Time) || g[i].Link != w[i].Link ||
			g[i].SHA256 != w[i].SHA256 || g[i].Keys != w[i].Keys {
			t.Errorf("entry %d\n got %+v\nwant %+v", i, g[i], w[i])
		}
	}
}

func TestWriteRejectsSpecialFiles(t *testing.T) {
	t.Parallel()

	reg := File{Path: "a", Mode: 0o644, Data: []byte("x")}

	tests := []struct {
		name  string
		files []File
		opts  WriteOptions
		want  error
	}{
		{name: "hard link to nothing", files: []File{{Path: "b", Hardlink: "a"}}, want: ErrInvalidFile},
		{name: "hard link to itself", files: []File{{Path: "a", Hardlink: "a"}}, want: ErrInvalidFile},
		{name: "hard link to a directory", files: []File{{Path: "d", Mode: fs.ModeDir | 0o755}, {Path: "b", Hardlink: "d"}}, want: ErrInvalidFile},
		{name: "hard link to a hard link", files: []File{reg, {Path: "b", Hardlink: "a"}, {Path: "c", Hardlink: "b"}}, want: ErrInvalidFile},
		{name: "hard link with a bad target", files: []File{reg, {Path: "b", Hardlink: "../a"}}, want: ErrInvalidFile},
		{name: "negative owner", files: []File{{Path: "a", Mode: 0o644, UID: -1}}, want: ErrInvalidFile},
		{name: "owner name with a newline", files: []File{{Path: "a", Mode: 0o644, Uname: "a\nb"}}, want: ErrInvalidFile},
		{name: "owner name too long", files: []File{{Path: "a", Mode: 0o644, Gname: strings.Repeat("g", 300)}}, want: ErrInvalidFile},
		{name: "negative device number", files: []File{{Path: "d", Mode: fs.ModeDevice | 0o600, DevMajor: -1}}, want: ErrInvalidFile},
		{name: "xattr without PAX", files: []File{{Path: "a", Mode: 0o644, Xattrs: map[string][]byte{"user.a": nil}}}, opts: WriteOptions{TarFormat: tar.FormatGNU}, want: ErrInvalidFile},
		{name: "xattr name", files: []File{{Path: "a", Mode: 0o644, Xattrs: map[string][]byte{"a=b": nil}}}, want: ErrInvalidFile},
		{name: "empty xattr name", files: []File{{Path: "a", Mode: 0o644, Xattrs: map[string][]byte{"": nil}}}, want: ErrInvalidFile},
		{name: "socket", files: []File{{Path: "s", Mode: fs.ModeSocket | 0o600}}, want: ErrUnsupportedFile},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := sampleSpec()
			s.Files = tc.files

			err := s.Write(io.Discard, tc.opts)
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("too many xattrs", func(t *testing.T) {
		t.Parallel()

		x := map[string][]byte{}
		for i := range maxXattrs + 1 {
			x["user."+strings.Repeat("a", i+1)] = nil
		}

		s := sampleSpec()
		s.Files = []File{{Path: "a", Mode: 0o644, Xattrs: x}}

		if err := s.Write(io.Discard, WriteOptions{}); !errors.Is(err, ErrInvalidFile) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestScanDirWithOwnersAndXattrs(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	if err := os.WriteFile(filepath.Join(root, "a"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.Link(filepath.Join(root, "a"), filepath.Join(root, "b")); err != nil {
		t.Skip(err)
	}

	if err := os.WriteFile(filepath.Join(root, "c"), []byte("c"), 0o600); err != nil {
		t.Fatal(err)
	}

	xattrSet := setXattr(filepath.Join(root, "c"), "user.pkgformat", []byte("v")) == nil

	files, err := ScanDirWith(root, ScanOptions{Owners: true, Xattrs: true})
	if err != nil {
		t.Fatal(err)
	}

	byPath := map[string]File{}
	for _, f := range files {
		byPath[f.Path] = f
	}

	if byPath["a"].Hardlink != "" || byPath["b"].Hardlink != "a" {
		t.Errorf("hard links: a=%q b=%q", byPath["a"].Hardlink, byPath["b"].Hardlink)
	}

	if byPath["a"].Uname == "" || byPath["a"].UID != os.Getuid() {
		t.Errorf("owner: %+v", byPath["a"])
	}

	if xattrSet && string(byPath["c"].Xattrs["user.pkgformat"]) != "v" {
		t.Errorf("xattrs: %v", byPath["c"].Xattrs)
	}

	// ScanDir keeps root:root and no attributes.
	plain, err := ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range plain {
		if f.UID != 0 || f.Uname != "" || f.Xattrs != nil {
			t.Errorf("ScanDir kept metadata: %+v", f)
		}
	}

	// The scanned tree writes and verifies.
	s := sampleSpec()
	s.Files = files

	if err := VerifyPackage(bytes.NewReader(writeSpec(t, s, WriteOptions{})), VerifyOptions{}); err != nil {
		t.Errorf("VerifyPackage: %v", err)
	}
}

func TestScanDirSpecialFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := mknod(filepath.Join(root, "fifo"), fs.ModeNamedPipe|0o600, 0, 0); err != nil {
		t.Skip(err)
	}

	files, err := ScanDir(root)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) != 1 || files[0].Mode&fs.ModeNamedPipe == 0 {
		t.Errorf("files = %+v", files)
	}

	s := sampleSpec()
	s.Files = files

	if err := VerifyPackage(bytes.NewReader(writeSpec(t, s, WriteOptions{})), VerifyOptions{}); err != nil {
		t.Errorf("VerifyPackage: %v", err)
	}
}

// TestSpecialFilesReadByBsdtar has bsdtar list the package that holds device
// nodes, pipes and hard links (a device cannot be installed without privilege,
// so what libarchive reads from the archive and from the .MTREE stands in).
func TestSpecialFilesReadByBsdtar(t *testing.T) {
	t.Parallel()

	bsdtar := pacmanTool(t, "bsdtar")

	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "special.pkg.tar.zst")

	if err := specialSpec().WriteFile(pkgPath, WriteOptions{ClampMTime: true}); err != nil {
		t.Fatal(err)
	}

	list := func(args ...string) string {
		t.Helper()

		out, err := exec.Command(bsdtar, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("bsdtar %v: %v\n%s", args, err, out)
		}

		return string(out)
	}

	archive := list("-tvf", pkgPath)

	for _, want := range []string{
		"crw-rw-rw-  0 root   root      1,3 ", " dev/null", "brw-rw----  0 root   disk      7,0 ", " dev/loop0",
		"prw-r-----  0 root   root        0 ", " run/queue", "usr/bin/tool link to usr/bin/aaa-link",
		"-rw-------  0 app    apps        1 ", " var/lib/app/state",
	} {
		if !strings.Contains(archive, want) {
			t.Errorf("bsdtar -tvf lacks %q:\n%s", want, archive)
		}
	}

	out, err := exec.Command(bsdtar, "-xOf", pkgPath, ".MTREE").Output()
	if err != nil {
		t.Fatal(err)
	}

	mtree := filepath.Join(dir, "mtree")
	if err := os.WriteFile(mtree, out, 0o600); err != nil {
		t.Fatal(err)
	}

	described := list("-tvf", mtree)

	for _, want := range []string{" ./dev/null", " ./dev/loop0", " ./run/queue", " ./usr/bin/tool-link"} {
		if !strings.Contains(described, want) {
			t.Errorf("bsdtar reads no %q in the .MTREE:\n%s", want, described)
		}
	}

	// makepkg has bsdtar describe the tree it packs; describing the package
	// the same way gives the entries of the .MTREE the writer wrote (but for a
	// hard link, which bsdtar reads from the tree as the file it is and from an
	// archive as an empty member).
	regenerated := list("-cf", "-", "--format=mtree", "--options=!all,use-set,type,uid,gid,mode,time,size,sha256,link", "@"+pkgPath)

	exp, err := ParseMtree(strings.NewReader(regenerated))
	if err != nil {
		t.Fatalf("%v\n%s", err, regenerated)
	}

	got, err := ParseMtree(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{"dev/null", "dev/loop0", "run/queue", "usr/bin/ping", "var/lib/app/state"} {
		g, _ := got.Lookup(p)
		w, _ := exp.Lookup(p)

		if g == nil || w == nil || g.Type != w.Type || g.Mode != w.Mode || g.UID != w.UID || g.GID != w.GID ||
			g.Size != w.Size || g.SHA256 != w.SHA256 || !g.Time.Equal(w.Time) {
			t.Errorf("%s\n got %+v\nwant %+v", p, g, w)
		}
	}
}
