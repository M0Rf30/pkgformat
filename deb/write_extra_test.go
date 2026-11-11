package deb_test

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

func writeBytes(t *testing.T, spec *deb.Spec, payload []deb.Entry) []byte {
	t.Helper()

	var buf bytes.Buffer

	require.NoError(t, deb.Write(&buf, spec, payload, deb.WriteOptions{TempDir: t.TempDir()}))

	return buf.Bytes()
}

func parseWritten(t *testing.T, spec *deb.Spec, payload []deb.Entry) *deb.DebFile {
	t.Helper()

	f, err := parseDeb(writeBytes(t, spec, payload))
	require.NoError(t, err)

	return f
}

func minimalSpec() *deb.Spec {
	return &deb.Spec{Name: "mini", Version: "1.0", Architecture: "amd64", Compression: "none"}
}

// arMemberNames lists the member names of an ar archive.
func arMemberNames(t *testing.T, raw []byte) []string {
	t.Helper()

	require.True(t, bytes.HasPrefix(raw, []byte("!<arch>\n")))

	var names []string

	for off := 8; off+60 <= len(raw); {
		names = append(names, strings.TrimSpace(string(raw[off:off+16])))

		size, err := strconv.Atoi(strings.TrimSpace(string(raw[off+48 : off+58])))
		require.NoError(t, err)

		off += 60 + size + size%2
	}

	return names
}

func dataTarEntries(t *testing.T, f *deb.DebFile) map[string]*tar.Header {
	t.Helper()

	rc, err := f.OpenData()
	require.NoError(t, err)

	defer rc.Close()

	out := map[string]*tar.Header{}
	tr := tar.NewReader(rc)

	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}

		require.NoError(t, err)

		out[h.Name] = h
	}
}

func TestWriteMemberNames(t *testing.T) {
	for comp, ext := range map[string]string{"none": "", "gzip": ".gz", "xz": ".xz", "zstd": ".zst", "": ".zst"} {
		t.Run("comp="+comp, func(t *testing.T) {
			spec := minimalSpec()
			spec.Compression = comp

			assert.Equal(t, []string{"debian-binary", "control.tar" + ext, "data.tar" + ext}, arMemberNames(t, writeBytes(t, spec, nil)))
		})
	}
}

func TestWriteEmptyPayload(t *testing.T) {
	f := parseWritten(t, minimalSpec(), nil)

	assert.Equal(t, "mini", f.Package.Package)
	assert.Equal(t, int64(0), f.Package.InstalledSize)
	assert.Equal(t, "0", f.ControlFile.Get("Installed-Size"))
	assert.NotContains(t, f.Control, "md5sums")
	assert.NotContains(t, f.Control, "conffiles")
	assert.NotContains(t, f.Control, "copyright")

	assert.Contains(t, dataTarEntries(t, f), "./")
	assert.Len(t, dataTarEntries(t, f), 1)

	require.NoError(t, f.Extract(t.TempDir(), deb.ExtractOptions{}))
}

func TestWriteScripts(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		f := parseWritten(t, minimalSpec(), nil)

		for _, name := range []string{"preinst", "postinst", "prerm", "postrm", "config", "templates"} {
			assert.NotContains(t, f.Control, name)
		}
	})

	t.Run("only postinst", func(t *testing.T) {
		spec := minimalSpec()
		spec.Scripts.Postinst = "#!/bin/sh\ntrue\n"

		f := parseWritten(t, spec, nil)
		assert.Equal(t, "#!/bin/sh\ntrue\n", string(f.Control["postinst"]))
		assert.NotContains(t, f.Control, "prerm")
		assert.NotContains(t, f.Control, "postrm")
	})

	t.Run("only prerm gets the header", func(t *testing.T) {
		spec := minimalSpec()
		spec.Scripts.Prerm = "echo bye\n"

		f := parseWritten(t, spec, nil)
		assert.Equal(t, deb.RemoveScriptHeader+"echo bye\n", string(f.Control["prerm"]))
		assert.NotContains(t, f.Control, "postrm")
	})

	t.Run("modes", func(t *testing.T) {
		spec := minimalSpec()
		spec.Scripts = deb.Scripts{Preinst: "a", Postinst: "b", Prerm: "c", Postrm: "d", Config: "e", Templates: "f"}

		raw := writeBytes(t, spec, nil)
		f, err := parseDeb(raw)
		require.NoError(t, err)

		tr := tar.NewReader(bytes.NewReader(f.ControlTarGz))
		modes := map[string]int64{}

		for {
			h, err := tr.Next()
			if err != nil {
				break
			}

			modes[h.Name] = h.Mode
		}

		for _, n := range []string{"preinst", "postinst", "prerm", "postrm", "config"} {
			assert.Equal(t, int64(0o755), modes["./"+n], n)
		}

		assert.Equal(t, int64(0o644), modes["./templates"])
		assert.Equal(t, int64(0o644), modes["./control"])
	})
}

func TestWriteDescription(t *testing.T) {
	tests := map[string]struct {
		in   string
		want string // the Description field as the parser sees it; "-" means absent
	}{
		"empty":             {"", "-"},
		"whitespace only":   {" \n\t ", "-"},
		"synopsis":          {"Just a synopsis", "Just a synopsis"},
		"trailing newline":  {"Synopsis\nbody\n\n", "Synopsis\nbody"},
		"blank line":        {"S\n\nsecond", "S\n\nsecond"},
		"blank with spaces": {"S\n   \nsecond", "S\n\nsecond"},
		"indented":          {"S\n  indented\n\ttab", "S\n  indented\n\ttab"},
		"leading space":     {"  S\nbody", "S\nbody"},
		"hash line":         {"S\n# not a comment", "S\n# not a comment"},
		"colon line":        {"S\nPackage: not a field", "S\nPackage: not a field"},
		"dot line":          {"S\nmore. text", "S\nmore. text"},
		"long line":         {"S\n" + strings.Repeat("x", 10000), "S\n" + strings.Repeat("x", 10000)},
		"unicode":           {"Zażółć gęślą jaźń\n日本語", "Zażółć gęślą jaźń\n日本語"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			spec := minimalSpec()
			spec.Description = tc.in

			f := parseWritten(t, spec, nil)

			got, ok := f.ControlFile.Lookup("Description")
			if tc.want == "-" {
				assert.False(t, ok)

				return
			}

			require.True(t, ok)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, "mini", f.Package.Package, "the description cannot inject fields")
			assert.Equal(t, []string{"Package", "Version", "Architecture", "Installed-Size", "Description"}, f.ControlFile.Order)
		})
	}
}

func TestWriteConffilesNormalised(t *testing.T) {
	spec := minimalSpec()
	spec.Conffiles = []string{"etc/a.conf", "/etc/b.conf", "", "usr/share/c"}

	f := parseWritten(t, spec, nil)
	assert.Equal(t, []string{"/etc/a.conf", "/etc/b.conf", "/usr/share/c"}, f.Conffiles())

	spec.Conffiles = []string{"", ""}
	f = parseWritten(t, spec, nil)
	assert.NotContains(t, f.Control, "conffiles", "an empty list writes no file")
}

func TestWriteInstalledSize(t *testing.T) {
	payload := []deb.Entry{
		{Path: "a", Mode: 0o644, Data: bytes.Repeat([]byte("a"), 3000)},
		{Path: "b", Mode: 0o644, Data: bytes.Repeat([]byte("b"), 1500)},
		{Path: "l", Mode: fs.ModeSymlink | 0o777, Linkname: strings.Repeat("t", 600)},
		{Path: "d", Mode: fs.ModeDir | 0o755},
	}

	t.Run("computed", func(t *testing.T) {
		f := parseWritten(t, minimalSpec(), payload)
		assert.Equal(t, int64((3000+1500+600)/1024), f.Package.InstalledSize)
	})

	t.Run("override", func(t *testing.T) {
		spec := minimalSpec()
		spec.InstalledSize = 99

		f := parseWritten(t, spec, payload)
		assert.Equal(t, int64(99), f.Package.InstalledSize)
	})

	t.Run("small payload rounds down", func(t *testing.T) {
		f := parseWritten(t, minimalSpec(), []deb.Entry{{Path: "a", Mode: 0o644, Data: []byte("tiny")}})
		assert.Equal(t, "0", f.ControlFile.Get("Installed-Size"))
	})
}

func TestWriteRelationLists(t *testing.T) {
	spec := minimalSpec()
	spec.Depends = rels(" libc6 (>= 2.31) ", "bash | dash")
	spec.Provides = []deb.Alternatives{}

	f := parseWritten(t, spec, nil)
	assert.Equal(t, "libc6 (>= 2.31), bash | dash", f.Package.Depends)
	_, ok := f.ControlFile.Lookup("Provides")
	assert.False(t, ok, "an empty list writes no field")
}

func TestWriteMultiArch(t *testing.T) {
	for name, tc := range map[string]struct{ arch, multi, want string }{
		"all defaults to foreign": {"all", "", "foreign"},
		"all explicit":            {"all", "no", "no"},
		"arch default absent":     {"amd64", "", ""},
		"arch same":               {"amd64", "same", "same"},
	} {
		t.Run(name, func(t *testing.T) {
			spec := minimalSpec()
			spec.Architecture, spec.MultiArch = tc.arch, tc.multi

			assert.Equal(t, tc.want, parseWritten(t, spec, nil).Package.MultiArch)
		})
	}
}

func TestWriteCopyright(t *testing.T) {
	spec := minimalSpec()
	spec.Licenses = []string{"MIT", "Apache-2.0"}

	f := parseWritten(t, spec, nil)
	cp := string(f.Control["copyright"])
	assert.Contains(t, cp, "License: MIT and Apache-2.0\n")
	assert.Contains(t, cp, "Upstream-Name: mini\n")
	assert.NotContains(t, cp, "Copyright:")
	assert.NotContains(t, cp, "Upstream-Contact")
}

func TestWriteMD5SumsSorted(t *testing.T) {
	f := parseWritten(t, minimalSpec(), []deb.Entry{
		{Path: "z", Mode: 0o644, Data: []byte("z")},
		{Path: "a/b", Mode: 0o644, Data: []byte("b")},
		{Path: "m", Mode: 0o644, Data: []byte("m")},
		{Path: "l", Mode: fs.ModeSymlink | 0o777, Linkname: "z"},
	})

	var paths []string

	for line := range strings.SplitSeq(strings.TrimSpace(string(f.Control["md5sums"])), "\n") {
		sum, path, ok := strings.Cut(line, "  ")
		require.True(t, ok)
		assert.Len(t, sum, 32)

		paths = append(paths, path)
	}

	assert.Equal(t, []string{"a/b", "m", "z"}, paths)

	want := md5.Sum([]byte("m"))
	assert.Contains(t, string(f.Control["md5sums"]), hex.EncodeToString(want[:])+"  m\n")
}

func TestWriteEntryPaths(t *testing.T) {
	t.Run("parent added once even when named later", func(t *testing.T) {
		f := parseWritten(t, minimalSpec(), []deb.Entry{
			{Path: "usr/bin/x", Mode: 0o755, Data: []byte("x")},
			{Path: "usr", Mode: fs.ModeDir | 0o700},
			{Path: "/usr/lib/", Mode: fs.ModeDir | 0o755},
		})

		rc, err := f.OpenData()
		require.NoError(t, err)

		defer rc.Close()

		var names []string

		tr := tar.NewReader(rc)

		for {
			h, err := tr.Next()
			if err != nil {
				break
			}

			names = append(names, h.Name)
		}

		assert.Equal(t, []string{"./", "./usr/bin/", "./usr/bin/x", "./usr/", "./usr/lib/"}, names)
	})

	t.Run("root directory entry is accepted and ignored", func(t *testing.T) {
		for _, p := range []string{"", ".", "./", "/"} {
			f := parseWritten(t, minimalSpec(), []deb.Entry{{Path: p, Mode: fs.ModeDir | 0o755}})
			assert.Len(t, dataTarEntries(t, f), 1, "%q", p)
		}
	})

	for name, e := range map[string]deb.Entry{
		"root file":            {Path: "./", Mode: 0o644},
		"dotdot":               {Path: "a/../../b", Mode: 0o644},
		"dotdot only":          {Path: "..", Mode: fs.ModeDir | 0o755},
		"newline":              {Path: "a\nb", Mode: 0o644},
		"nul":                  {Path: "a\x00b", Mode: 0o644},
		"socket":               {Path: "s", Mode: fs.ModeSocket | 0o644},
		"symlink without dest": {Path: "l", Mode: fs.ModeSymlink | 0o777},
	} {
		t.Run(name, func(t *testing.T) {
			err := deb.Write(io.Discard, minimalSpec(), []deb.Entry{e}, deb.WriteOptions{})
			require.ErrorIs(t, err, deb.ErrInvalidSpec)
		})
	}

	t.Run("duplicate directory", func(t *testing.T) {
		err := deb.Write(io.Discard, minimalSpec(), []deb.Entry{
			{Path: "d", Mode: fs.ModeDir | 0o755}, {Path: "d/", Mode: fs.ModeDir | 0o755},
		}, deb.WriteOptions{})
		require.ErrorIs(t, err, deb.ErrInvalidSpec)
	})

	t.Run("file where a parent was added", func(t *testing.T) {
		err := deb.Write(io.Discard, minimalSpec(), []deb.Entry{
			{Path: "a/b", Mode: 0o644}, {Path: "a", Mode: 0o644},
		}, deb.WriteOptions{})
		require.ErrorIs(t, err, deb.ErrInvalidSpec)
	})
}

func TestWriteModesInArchive(t *testing.T) {
	f := parseWritten(t, minimalSpec(), []deb.Entry{
		{Path: "suid", Mode: fs.ModeSetuid | 0o755, Data: []byte("x")},
		{Path: "sgid", Mode: fs.ModeSetgid | 0o755, Data: []byte("x")},
		{Path: "tmp", Mode: fs.ModeDir | fs.ModeSticky | 0o777},
		{Path: "ro", Mode: 0o400, Data: []byte("x")},
		{Path: "l", Mode: fs.ModeSymlink | 0o600, Linkname: "ro"},
	})

	h := dataTarEntries(t, f)
	assert.Equal(t, int64(0o4755), h["./suid"].Mode)
	assert.Equal(t, int64(0o2755), h["./sgid"].Mode)
	assert.Equal(t, int64(0o1777), h["./tmp/"].Mode)
	assert.Equal(t, int64(0o400), h["./ro"].Mode)
	assert.Equal(t, int64(0o777), h["./l"].Mode, "symlinks are always 0777")
	assert.Equal(t, "ro", h["./l"].Linkname)

	for name, hdr := range h {
		assert.Equal(t, 0, hdr.Uid, name)
		assert.Equal(t, 0, hdr.Gid, name)
		assert.Equal(t, "root", hdr.Gname, name)
	}
}

func TestWriteModTimes(t *testing.T) {
	spec := minimalSpec()
	spec.ModTime = time.Unix(1_600_000_000, 0)

	entryTime := time.Unix(1_500_000_000, 0)

	f := parseWritten(t, spec, []deb.Entry{
		{Path: "default", Mode: 0o644, Data: []byte("x")},
		{Path: "own", Mode: 0o644, Data: []byte("x"), ModTime: entryTime},
	})

	h := dataTarEntries(t, f)
	assert.Equal(t, spec.ModTime.Unix(), h["./default"].ModTime.Unix())
	assert.Equal(t, entryTime.Unix(), h["./own"].ModTime.Unix())
	assert.Equal(t, spec.ModTime.Unix(), h["./"].ModTime.Unix())
}

func TestWriteChangelog(t *testing.T) {
	spec := minimalSpec()
	spec.Changelog = []byte("mini (1.0) unstable; urgency=low\n")
	spec.ModTime = time.Unix(1_600_000_000, 0)

	f := parseWritten(t, spec, nil)
	require.Contains(t, dataTarEntries(t, f), "./usr/share/doc/mini/changelog.Debian.gz")

	dir := t.TempDir()
	require.NoError(t, f.Extract(dir, deb.ExtractOptions{}))

	file, err := os.Open(filepath.Join(dir, "usr/share/doc/mini/changelog.Debian.gz"))
	require.NoError(t, err)

	defer file.Close()

	gz, err := gzip.NewReader(file)
	require.NoError(t, err)

	body, err := io.ReadAll(gz)
	require.NoError(t, err)
	assert.Equal(t, string(spec.Changelog), string(body))
	assert.Equal(t, spec.ModTime.Unix(), gz.ModTime.Unix())

	// A changelog colliding with an explicit entry of the same path is an error.
	err = deb.Write(io.Discard, spec, []deb.Entry{{Path: "usr/share/doc/mini/changelog.Debian.gz", Mode: 0o644}}, deb.WriteOptions{})
	require.ErrorIs(t, err, deb.ErrInvalidSpec)
}

func TestWriteDoesNotMutateInputs(t *testing.T) {
	spec := minimalSpec()
	spec.Changelog = []byte("x")

	payload := []deb.Entry{{Path: "a", Mode: 0o644, Data: []byte("a")}}
	before := len(payload)

	_ = writeBytes(t, spec, payload)
	assert.Len(t, payload, before)
	assert.Equal(t, "mini", spec.Name)
}

func TestWriteReproducible(t *testing.T) {
	tree := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tree, "usr/bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "usr/bin/tool"), []byte("tool"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "usr/readme"), []byte("readme"), 0o644))
	require.NoError(t, os.Symlink("bin/tool", filepath.Join(tree, "usr/link")))

	build := func() []byte {
		entries, err := deb.FSEntries(os.DirFS(tree), time.Unix(1_700_000_000, 0))
		require.NoError(t, err)

		spec := testSpec()
		spec.ModTime = time.Unix(1_700_000_000, 0)

		return writeBytes(t, spec, entries)
	}

	first := build()

	// Touching the files on disk does not change the package.
	later := time.Now().Add(48 * time.Hour)
	require.NoError(t, os.Chtimes(filepath.Join(tree, "usr/bin/tool"), later, later))
	require.NoError(t, os.Chtimes(filepath.Join(tree, "usr"), later, later))

	assert.Equal(t, first, build())

	// Without the override the file times are used.
	entries, err := deb.FSEntries(os.DirFS(tree), time.Time{})
	require.NoError(t, err)

	for _, e := range entries {
		assert.False(t, e.ModTime.IsZero(), e.Path)
	}
}

func TestFSEntries(t *testing.T) {
	tree := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tree, "usr/bin"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(tree, "etc/empty"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "usr/bin/tool"), []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "etc/a.conf"), []byte("a=1\n"), 0o640))
	require.NoError(t, os.Symlink("tool", filepath.Join(tree, "usr/bin/alias")))
	require.NoError(t, os.Symlink("/etc/a.conf", filepath.Join(tree, "usr/abs")))

	mod := time.Unix(1_700_000_000, 0)

	entries, err := deb.FSEntries(os.DirFS(tree), mod)
	require.NoError(t, err)

	var paths []string

	byPath := map[string]deb.Entry{}

	for _, e := range entries {
		paths = append(paths, e.Path)
		byPath[e.Path] = e

		assert.True(t, e.ModTime.Equal(mod), e.Path)
	}

	assert.Equal(t, []string{
		"etc", "etc/a.conf", "etc/empty", "usr", "usr/abs", "usr/bin", "usr/bin/alias", "usr/bin/tool",
	}, paths)

	assert.True(t, byPath["etc"].Mode.IsDir())
	assert.Equal(t, fs.FileMode(0o750), byPath["etc/empty"].Mode.Perm())
	assert.Equal(t, "tool", byPath["usr/bin/alias"].Linkname)
	assert.NotZero(t, byPath["usr/bin/alias"].Mode&fs.ModeSymlink)
	assert.Equal(t, "/etc/a.conf", byPath["usr/abs"].Linkname)

	tool := byPath["usr/bin/tool"]
	assert.Equal(t, fs.FileMode(0o755), tool.Mode)
	assert.Equal(t, int64(10), tool.Size)
	require.NotNil(t, tool.Open)

	rc, err := tool.Open()
	require.NoError(t, err)

	body, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, "#!/bin/sh\n", string(body))

	// The listing makes a package that extracts to the same tree.
	f := parseWritten(t, minimalSpec(), entries)
	dir := t.TempDir()
	require.NoError(t, f.Extract(dir, deb.ExtractOptions{}))

	got, err := os.ReadFile(filepath.Join(dir, "etc/a.conf"))
	require.NoError(t, err)
	assert.Equal(t, "a=1\n", string(got))

	st, err := os.Stat(filepath.Join(dir, "etc/empty"))
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o750), st.Mode().Perm())

	link, err := os.Readlink(filepath.Join(dir, "usr/abs"))
	require.NoError(t, err)
	assert.Equal(t, "/etc/a.conf", link)
}

func TestFSEntriesUsesFileTimesByDefault(t *testing.T) {
	fsys := fstest.MapFS{"a": {Data: []byte("x"), Mode: 0o644, ModTime: time.Unix(12345, 0)}}

	entries, err := deb.FSEntries(fsys, time.Time{})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, int64(12345), entries[0].ModTime.Unix())
}

func TestFSEntriesEmpty(t *testing.T) {
	entries, err := deb.FSEntries(fstest.MapFS{}, time.Time{})
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestFSEntriesUnsupportedType(t *testing.T) {
	for name, mode := range map[string]fs.FileMode{
		"device": fs.ModeDevice | 0o644,
		"fifo":   fs.ModeNamedPipe | 0o644,
		"socket": fs.ModeSocket | 0o644,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := deb.FSEntries(fstest.MapFS{"ok": {Data: []byte("x")}, "odd": {Mode: mode}}, time.Time{})
			require.ErrorIs(t, err, deb.ErrInvalidSpec)
		})
	}
}

type brokenFS struct{ fstest.MapFS }

var errBrokenFS = errors.New("fs broke")

func (b brokenFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "bad" {
		return nil, errBrokenFS
	}

	return b.MapFS.ReadDir(name)
}

func TestFSEntriesWalkError(t *testing.T) {
	_, err := deb.FSEntries(brokenFS{fstest.MapFS{"bad/x": {Data: []byte("x")}}}, time.Time{})
	require.ErrorIs(t, err, errBrokenFS)
}

func TestFSEntriesFileOpenedLazily(t *testing.T) {
	tree := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tree, "f"), []byte("old"), 0o644))

	entries, err := deb.FSEntries(os.DirFS(tree), time.Unix(1, 0))
	require.NoError(t, err)

	// Removing the file before Write reaches it is reported, not ignored.
	require.NoError(t, os.Remove(filepath.Join(tree, "f")))
	require.Error(t, deb.Write(io.Discard, minimalSpec(), entries, deb.WriteOptions{}))
}

type countingCloser struct {
	io.Reader

	closed *int
}

func (c countingCloser) Close() error { *c.closed++; return nil }

func TestWriteLargeFileStreams(t *testing.T) {
	const size = 20 << 20

	closed := 0
	entry := deb.Entry{
		Path: "usr/share/big.bin", Mode: 0o644, Size: size,
		Open: func() (io.ReadCloser, error) {
			return countingCloser{Reader: io.LimitReader(zeros{}, size), closed: &closed}, nil
		},
	}

	spec := minimalSpec()
	path := filepath.Join(t.TempDir(), "big.deb")
	require.NoError(t, deb.WriteFile(path, spec, []deb.Entry{entry}, deb.WriteOptions{TempDir: t.TempDir()}))
	assert.Equal(t, 1, closed)

	st, err := os.Stat(path)
	require.NoError(t, err)
	assert.Greater(t, st.Size(), int64(size))

	file, err := os.Open(path)
	require.NoError(t, err)

	defer file.Close()

	f, err := deb.ParseDebFileAt(file, st.Size())
	require.NoError(t, err)
	assert.Equal(t, int64(size/1024), f.Package.InstalledSize)

	sum := md5.Sum(make([]byte, size))
	assert.Contains(t, string(f.Control["md5sums"]), hex.EncodeToString(sum[:])+"  usr/share/big.bin\n")

	dir := t.TempDir()
	require.NoError(t, f.Extract(dir, deb.ExtractOptions{}))

	info, err := os.Stat(filepath.Join(dir, "usr/share/big.bin"))
	require.NoError(t, err)
	assert.Equal(t, int64(size), info.Size())

	// The size limit of Extract applies to such a package.
	require.ErrorIs(t, f.Extract(t.TempDir(), deb.ExtractOptions{MaxBytes: size - 1}), deb.ErrDataTooLarge)
}

func TestWriteEntryOpenFailures(t *testing.T) {
	errOpen := errors.New("cannot open")

	err := deb.Write(io.Discard, minimalSpec(), []deb.Entry{
		{Path: "f", Mode: 0o644, Size: 1, Open: func() (io.ReadCloser, error) { return nil, errOpen }},
	}, deb.WriteOptions{})
	require.ErrorIs(t, err, errOpen)

	// An Open source longer than the declared size is cut at Size.
	f := parseWritten(t, minimalSpec(), []deb.Entry{
		{Path: "f", Mode: 0o644, Size: 2, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("abcdef")), nil }},
	})

	dir := t.TempDir()
	require.NoError(t, f.Extract(dir, deb.ExtractOptions{}))

	got, err := os.ReadFile(filepath.Join(dir, "f"))
	require.NoError(t, err)
	assert.Equal(t, "ab", string(got))

	// Data wins over Open; no content at all is an empty file.
	f = parseWritten(t, minimalSpec(), []deb.Entry{
		{Path: "d", Mode: 0o644, Data: []byte("data"), Open: func() (io.ReadCloser, error) { return nil, errOpen }},
		{Path: "e", Mode: 0o644},
	})
	require.NoError(t, f.Extract(dir, deb.ExtractOptions{}))

	got, err = os.ReadFile(filepath.Join(dir, "d"))
	require.NoError(t, err)
	assert.Equal(t, "data", string(got))

	st, err := os.Stat(filepath.Join(dir, "e"))
	require.NoError(t, err)
	assert.Zero(t, st.Size())
}

func TestWriteTempDir(t *testing.T) {
	stage := t.TempDir()

	require.NoError(t, deb.Write(io.Discard, minimalSpec(), []deb.Entry{{Path: "a", Mode: 0o644, Data: []byte("a")}}, deb.WriteOptions{TempDir: stage}))

	left, err := os.ReadDir(stage)
	require.NoError(t, err)
	assert.Empty(t, left, "the staging file is removed")

	// And after a failure.
	require.Error(t, deb.Write(io.Discard, minimalSpec(), []deb.Entry{{Path: "../a", Mode: 0o644}}, deb.WriteOptions{TempDir: stage}))

	left, err = os.ReadDir(stage)
	require.NoError(t, err)
	assert.Empty(t, left)

	require.Error(t, deb.Write(io.Discard, minimalSpec(), nil, deb.WriteOptions{TempDir: filepath.Join(stage, "missing")}))
}

type failingWriter struct{ left int }

var errSink = errors.New("sink full")

func (f *failingWriter) Write(p []byte) (int, error) {
	if len(p) > f.left {
		return 0, errSink
	}

	f.left -= len(p)

	return len(p), nil
}

func TestWriteSinkErrors(t *testing.T) {
	var full bytes.Buffer

	require.NoError(t, deb.Write(&full, testSpec(), testPayload(), deb.WriteOptions{}))

	// A sink that fails at several points of the stream makes Write fail.
	for _, limit := range []int{0, 8, 70, 200, full.Len() - 10} {
		err := deb.Write(&failingWriter{left: limit}, testSpec(), testPayload(), deb.WriteOptions{})
		require.ErrorIs(t, err, errSink, "limit %d", limit)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	t.Run("invalid spec leaves nothing", func(t *testing.T) {
		dir := t.TempDir()
		spec := minimalSpec()
		spec.Name = "X"

		require.ErrorIs(t, deb.WriteFile(filepath.Join(dir, "x.deb"), spec, nil, deb.WriteOptions{}), deb.ErrInvalidSpec)

		left, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, left)
	})

	t.Run("failure while writing the payload leaves nothing", func(t *testing.T) {
		dir := t.TempDir()

		err := deb.WriteFile(filepath.Join(dir, "x.deb"), minimalSpec(), []deb.Entry{
			{Path: "a", Mode: 0o644, Size: 100, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("short")), nil }},
		}, deb.WriteOptions{TempDir: t.TempDir()})
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)

		left, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, left)
	})

	t.Run("failure keeps an existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "x.deb")
		require.NoError(t, os.WriteFile(path, []byte("previous"), 0o600))

		require.Error(t, deb.WriteFile(path, minimalSpec(), []deb.Entry{{Path: "../x", Mode: 0o644}}, deb.WriteOptions{}))

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "previous", string(got))

		left, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Len(t, left, 1)
	})

	t.Run("success replaces the file and sets 0644", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "x.deb")
		require.NoError(t, os.WriteFile(path, []byte("previous"), 0o600))

		require.NoError(t, deb.WriteFile(path, minimalSpec(), nil, deb.WriteOptions{}))

		st, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, fs.FileMode(0o644), st.Mode().Perm())

		raw, err := os.ReadFile(path)
		require.NoError(t, err)

		_, err = parseDeb(raw)
		require.NoError(t, err)

		left, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Len(t, left, 1, "no temporary file stays behind")
	})

	t.Run("missing directory", func(t *testing.T) {
		require.Error(t, deb.WriteFile(filepath.Join(t.TempDir(), "nope", "x.deb"), minimalSpec(), nil, deb.WriteOptions{}))
	})
}

func TestSpecFileNameAndVersion(t *testing.T) {
	spec := &deb.Spec{Name: "tool", Epoch: "2", Version: "1.5", Release: "3", Architecture: "arm64"}
	assert.Equal(t, "2:1.5-3", spec.FullVersion())
	assert.Equal(t, "tool_1.5-3_arm64.deb", spec.FileName())

	spec = &deb.Spec{Name: "tool", Version: "1.5", Architecture: "all"}
	assert.Equal(t, "1.5", spec.FullVersion())
	assert.Equal(t, "tool_1.5_all.deb", spec.FileName())
}

func TestSpecValidate(t *testing.T) {
	valid := []func(*deb.Spec){
		func(*deb.Spec) {},
		func(s *deb.Spec) { s.Name = "ab" },
		func(s *deb.Spec) { s.Name = "lib++-dev" },
		func(s *deb.Spec) { s.Name = "a.b-c+d9" },
		func(s *deb.Spec) { s.Version = "1.0~rc1+dfsg" },
		func(s *deb.Spec) { s.Epoch = "10" },
		func(s *deb.Spec) { s.Release = "1ubuntu2~bpo1" },
		func(s *deb.Spec) { s.Architecture = "linux-amd64" },
		func(s *deb.Spec) { s.Architecture = "all" },
		func(s *deb.Spec) { s.Compression = "xz" },
		func(s *deb.Spec) { s.Description = "multi\nline" },
	}

	for i, mutate := range valid {
		spec := minimalSpec()
		mutate(spec)
		assert.NoError(t, spec.Validate(), "valid case %d", i)
	}

	invalid := map[string]func(*deb.Spec){
		"empty name":           func(s *deb.Spec) { s.Name = "" },
		"one char name":        func(s *deb.Spec) { s.Name = "a" },
		"uppercase name":       func(s *deb.Spec) { s.Name = "Tool" },
		"underscore name":      func(s *deb.Spec) { s.Name = "my_tool" },
		"name starts with dot": func(s *deb.Spec) { s.Name = ".tool" },
		"name starts with -":   func(s *deb.Spec) { s.Name = "-tool" },
		"name with space":      func(s *deb.Spec) { s.Name = "my tool" },
		"name with newline":    func(s *deb.Spec) { s.Name = "tool\n" },
		"empty version":        func(s *deb.Spec) { s.Version = "" },
		"version with space":   func(s *deb.Spec) { s.Version = "1 0" },
		"version with colon":   func(s *deb.Spec) { s.Version = "1:0" },
		"version with newline": func(s *deb.Spec) { s.Version = "1\nX: y" },
		"epoch not number":     func(s *deb.Spec) { s.Epoch = "e" },
		"epoch negative":       func(s *deb.Spec) { s.Epoch = "-1" },
		"release with space":   func(s *deb.Spec) { s.Release = "1 2" },
		"arch empty":           func(s *deb.Spec) { s.Architecture = "" },
		"arch uppercase":       func(s *deb.Spec) { s.Architecture = "AMD64" },
		"arch with space":      func(s *deb.Spec) { s.Architecture = "amd64 i386" },
		"unknown compression":  func(s *deb.Spec) { s.Compression = "bzip2" },
		"maintainer newline":   func(s *deb.Spec) { s.Maintainer = "a\nb" },
		"section CR":           func(s *deb.Spec) { s.Section = "a\rb" },
		"url newline":          func(s *deb.Spec) { s.URL = "http://x\nEvil: 1" },
		"bugs newline":         func(s *deb.Spec) { s.Bugs = "x\ny" },
		"source newline":       func(s *deb.Spec) { s.SourcePkg = "x\ny" },
		"priority newline":     func(s *deb.Spec) { s.Priority = "x\ny" },
		"multiarch newline":    func(s *deb.Spec) { s.MultiArch = "x\ny" },
		"depends newline":      func(s *deb.Spec) { s.Depends = []deb.Alternatives{{{Name: "b\nEvil: 1"}}} },
		"conffile newline":     func(s *deb.Spec) { s.Conffiles = []string{"/etc/a\n/etc/b"} },
		"license newline":      func(s *deb.Spec) { s.Licenses = []string{"MIT\nX: y"} },
		"provides CR":          func(s *deb.Spec) { s.Provides = []deb.Alternatives{{{Name: "ab", Version: "1\r", Op: "="}}} },
		"built-using newline":  func(s *deb.Spec) { s.BuiltUsing = []deb.Alternatives{{{Name: "ab", Version: "1\n2", Op: "="}}} },
	}

	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			spec := minimalSpec()
			mutate(spec)

			err := spec.Validate()
			require.Error(t, err)
			assert.True(t, errors.Is(err, deb.ErrInvalidSpec) || errors.Is(err, deb.ErrUnsupportedCompression), err)
		})
	}
}

func TestWriteMinimalPackageField(t *testing.T) {
	f := parseWritten(t, minimalSpec(), nil)
	assert.Equal(t, "Package: mini\nVersion: 1.0\nArchitecture: amd64\nInstalled-Size: 0\n", f.ControlFile.String())
}

func TestDpkgInfoAcceptsWrittenPackage(t *testing.T) {
	dpkg, err := exec.LookPath("dpkg")
	if err != nil {
		t.Skip("dpkg not installed")
	}

	for _, comp := range []string{"gzip", "xz", "zstd", "none"} {
		t.Run(comp, func(t *testing.T) {
			spec := testSpec()
			spec.Compression = comp

			path := filepath.Join(t.TempDir(), spec.FileName())
			require.NoError(t, deb.WriteFile(path, spec, testPayload(), deb.WriteOptions{}))

			out, err := exec.Command(dpkg, "--info", path).CombinedOutput()
			require.NoError(t, err, string(out))
			assert.Contains(t, string(out), "Package: hello-tool")
			assert.Contains(t, string(out), "Version: 1:2.0-3")
			assert.Contains(t, string(out), "Architecture: amd64")
			assert.NotContains(t, strings.ToLower(string(out)), "warning")
			assert.NotContains(t, strings.ToLower(string(out)), "error")

			out, err = exec.Command(dpkg, "--field", path, "Depends", "Installed-Size", "Pre-Depends").CombinedOutput()
			require.NoError(t, err, string(out))
			assert.Contains(t, string(out), "Depends: libc6 (>= 2.31), bash")
			assert.Contains(t, string(out), "Pre-Depends: dpkg")

			out, err = exec.Command(dpkg, "--contents", path).CombinedOutput()
			require.NoError(t, err, string(out))
			assert.Contains(t, string(out), "./usr/bin/hello")
			assert.Contains(t, string(out), "drwxr-x---")
			assert.Contains(t, string(out), "root/root")
		})
	}
}

func TestDpkgDebAcceptsFSEntriesPackage(t *testing.T) {
	dpkgDeb, err := exec.LookPath("dpkg-deb")
	if err != nil {
		t.Skip("dpkg-deb not installed")
	}

	tree := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tree, "usr/bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "usr/bin/t"), []byte("x"), 0o755))
	require.NoError(t, os.Symlink("t", filepath.Join(tree, "usr/bin/u")))

	entries, err := deb.FSEntries(os.DirFS(tree), time.Unix(1_700_000_000, 0))
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "x.deb")
	require.NoError(t, deb.WriteFile(path, minimalSpec(), entries, deb.WriteOptions{}))

	out, err := exec.Command(dpkgDeb, "--contents", path).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Contains(t, string(out), "./usr/bin/u -> t")

	// dpkg-deb --fsys-tarfile streams the data archive; our extractor sees the same.
	out, err = exec.Command(dpkgDeb, "--fsys-tarfile", path).Output()
	require.NoError(t, err)

	tr := tar.NewReader(bytes.NewReader(out))
	n := 0

	for {
		_, err := tr.Next()
		if err != nil {
			break
		}

		n++
	}

	assert.Equal(t, 5, n, "./, usr/, usr/bin/, usr/bin/t and usr/bin/u")
}

// FuzzValidateSpec builds specs from arbitrary strings: a spec either fails
// validation (and Write refuses it), or yields a package that reads back with
// the same identity.
func FuzzValidateSpec(f *testing.F) {
	f.Add("hello", "", "1.0", "1", "amd64", "Jane <j@x>", "Short\nlong", "libc6 (>= 2)")
	f.Add("Bad_Name", "x", "1 0", "", "", "a\nb", "", "a\nb")
	f.Add("a", "1", "1:2", "-", "all", "", "\n\n", ",")
	f.Add("lib+x.y-z", "0", "~", "~", "linux-any", "#", ".", "|")

	f.Fuzz(func(t *testing.T, name, epoch, version, release, arch, maintainer, desc, dep string) {
		depends, _ := deb.ParseRelations(dep)

		spec := &deb.Spec{
			Name: name, Epoch: epoch, Version: version, Release: release, Architecture: arch,
			Maintainer: maintainer, Description: desc, Depends: depends, Compression: "none",
		}

		var buf bytes.Buffer

		err := deb.Write(&buf, spec, []deb.Entry{{Path: "usr/share/x", Mode: 0o644, Data: []byte("x")}}, deb.WriteOptions{TempDir: t.TempDir()})
		if verr := spec.Validate(); verr != nil {
			require.Error(t, err)
			require.ErrorIs(t, verr, deb.ErrInvalidSpec)

			return
		}

		require.NoError(t, err)

		d, err := deb.ParseDebFileAt(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		require.NoError(t, err)
		assert.Equal(t, name, d.Package.Package)
		assert.Equal(t, spec.FullVersion(), d.Package.Version)
		assert.Equal(t, arch, d.Package.Architecture)
		assert.True(t, deb.ValidVersion(d.Package.Version))
	})
}
