package deb_test

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

// poolDebs opens the packages of testdata/repo-contents/pool, in file name order.
func poolDebs(t testing.TB) []*deb.DebFile {
	t.Helper()

	names, err := filepath.Glob(filepath.Join("testdata", "repo-contents", "pool", "*.deb"))
	require.NoError(t, err)
	require.Len(t, names, 3)

	out := make([]*deb.DebFile, 0, len(names))

	for _, n := range names {
		raw, err := os.ReadFile(n)
		require.NoError(t, err)

		d, err := deb.ParseDebFileAt(bytes.NewReader(raw), int64(len(raw)))
		require.NoError(t, err)

		out = append(out, d)
	}

	return out
}

func scanContentsAll(t testing.TB, data string) []deb.ContentsEntry {
	t.Helper()

	var out []deb.ContentsEntry

	for e, err := range deb.ScanContents(strings.NewReader(data)) {
		require.NoError(t, err)

		out = append(out, e)
	}

	return out
}

func TestContentsFileNameAndLocation(t *testing.T) {
	assert.Equal(t, "Contents-amd64", deb.ContentsFileName("amd64", false, ""))
	assert.Equal(t, "Contents-amd64.gz", deb.ContentsFileName("amd64", false, ".gz"))
	assert.Equal(t, "Contents-udeb-arm64.xz", deb.ContentsFileName("arm64", true, ".xz"))

	cf, err := deb.ParseControlFile(strings.NewReader("Package: p\nSection: utils\n"))
	require.NoError(t, err)
	assert.Equal(t, "utils/p", deb.ContentsLocation(cf))

	cf, err = deb.ParseControlFile(strings.NewReader("Package: p\n"))
	require.NoError(t, err)
	assert.Equal(t, "p", deb.ContentsLocation(cf))
}

func TestContentsBuilder(t *testing.T) {
	var b deb.ContentsBuilder

	require.NoError(t, b.Add("utils/b", "./usr/bin/x", "/usr/bin/y", "usr/share/dir/", "", "with space/file name", "bad\nname", "usr/bin/x"))
	require.NoError(t, b.Add("utils/a", "usr/bin/x"))
	require.NoError(t, b.Add("utils/a", "usr/bin/x"), "adding twice is the same as once")

	assert.Equal(t, 3, b.Len())
	assert.Equal(t, []string{"utils/a", "utils/b"}, b.Locations("usr/bin/x"))
	assert.Equal(t, []string{"utils/a", "utils/b"}, b.Locations("./usr/bin/x"))
	assert.Equal(t, []string{"utils/b"}, b.Locations("usr/bin/y"))
	assert.Empty(t, b.Locations("nope"))

	want := "usr/bin/x" + strings.Repeat("\t", 6) + "    utils/a,utils/b\n" +
		"usr/bin/y" + strings.Repeat("\t", 6) + "    utils/b\n" +
		"with space/file name" + strings.Repeat("\t", 5) + "    utils/b\n"
	assert.Equal(t, want, string(b.Bytes()), "sorted by path, tab padded to the package column")

	var seen []string
	for e := range b.Entries() {
		seen = append(seen, e.Path)
	}

	assert.Equal(t, []string{"usr/bin/x", "usr/bin/y", "with space/file name"}, seen)

	for e := range b.Entries() {
		assert.NotEmpty(t, e.Locations)

		break
	}

	// Long paths still get a separator.
	var long deb.ContentsBuilder

	p := strings.Repeat("d/", 40) + "file"
	require.NoError(t, long.Add("a", p))
	assert.Equal(t, p+" a\n", string(long.Bytes()), "a path beyond the column gets one blank")

	// Around the column, as apt-ftparchive contents writes it.
	for n, pad := range map[int]string{54: "\t    ", 55: "\t    ", 56: "    ", 57: "   ", 58: "  ", 59: " ", 60: " ", 61: " "} {
		var edge deb.ContentsBuilder

		name := "f" + strings.Repeat("0", n-1)
		require.NoError(t, edge.Add("lp", name))
		assert.Equal(t, name+pad+"lp\n", string(edge.Bytes()), "path of %d bytes", n)
	}

	assert.Empty(t, (&deb.ContentsBuilder{}).Bytes())

	for _, bad := range []string{"", "a b", "a,b", "a\tb", "a\nb"} {
		require.ErrorIs(t, b.Add(bad, "x"), deb.ErrInvalidContents, "%q", bad)
	}

	require.ErrorIs(t, b.AddEntry(deb.ContentsEntry{Path: "x", Locations: []string{"ok", "not ok"}}), deb.ErrInvalidContents)
}

func TestContentsBuilderCompressed(t *testing.T) {
	var b deb.ContentsBuilder
	for i := range 200 {
		require.NoError(t, b.Add("sect/pkg"+string(rune('a'+i%7)), "usr/share/f/"+strings.Repeat("x", i%13)+string(rune('a'+i%26))))
	}

	plain := b.Bytes()
	require.NotEmpty(t, plain)

	for c, ext := range map[deb.Compression]string{deb.CompressionNone: "", deb.CompressionGzip: ".gz", deb.CompressionXZ: ".xz", deb.CompressionZstd: ".zst"} {
		packed, err := b.Compressed(c)
		require.NoError(t, err)

		rc, err := deb.OpenIndex(bytes.NewReader(packed), "Contents-amd64"+ext)
		require.NoError(t, err)

		got, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
		assert.Equal(t, string(plain), string(got), "compression %d", c)

		var streamed bytes.Buffer

		n, err := b.WriteTo(&streamed, c)
		require.NoError(t, err)
		assert.Equal(t, int64(streamed.Len()), n)

		rc, err = deb.OpenIndex(&streamed, "Contents-amd64"+ext)
		require.NoError(t, err)

		got, err = io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
		assert.Equal(t, string(plain), string(got), "streamed, compression %d", c)
	}

	_, err := b.Compressed(deb.Compression(99))
	require.Error(t, err)

	_, err = b.WriteTo(io.Discard, deb.Compression(99))
	require.Error(t, err)

	_, err = b.WriteTo(ctsFailWriter{}, deb.CompressionGzip)
	require.Error(t, err)
}

type ctsFailWriter struct{}

func (ctsFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestDebContentsFiles(t *testing.T) {
	debs := poolDebs(t)

	files := map[string][]string{}

	for _, d := range debs {
		got, err := deb.DebContentsFiles(d)
		require.NoError(t, err)

		files[d.ControlFile.Get("Package")] = got
	}

	assert.ElementsMatch(t, []string{"usr/bin/alpha", "usr/bin/alpha-link", "usr/share/with space/file one.txt", "usr/share/doc/alpha/copyright"}, files["alpha"], "symlinks count, directories do not")
	assert.ElementsMatch(t, []string{"usr/bin/beta", "usr/bin/alpha", "etc/beta.conf"}, files["beta"])
	assert.ElementsMatch(t, []string{"usr/lib/gamma/libgamma.so.1", "usr/lib/gamma/libgamma.so.1.0"}, files["gamma"], "a hard link is a file")

	var b deb.ContentsBuilder
	require.NoError(t, b.AddDeb(debs[0]))
	assert.Equal(t, []string{"utils/alpha"}, b.Locations("usr/bin/alpha"))

	require.Error(t, (&deb.ContentsBuilder{}).AddDeb(&deb.DebFile{}))
}

// apt-ftparchive contents names packages by their bare name.
func TestContentsBuilderMatchesAptFTPArchiveContents(t *testing.T) {
	var b deb.ContentsBuilder
	for _, d := range poolDebs(t) {
		require.NoError(t, b.AddDebAs(d, d.ControlFile.Get("Package")))
	}

	expected := readFixture(t, "repo-contents", "contents.expected")
	assert.Equal(t, string(expected), string(b.Bytes()))

	t.Run("live", func(t *testing.T) {
		ftp, err := exec.LookPath("apt-ftparchive")
		if err != nil {
			t.Skip("apt-ftparchive not installed")
		}

		cmd := exec.Command(ftp, "contents", "pool")
		cmd.Dir = filepath.Join("testdata", "repo-contents")

		out, err := cmd.Output()
		require.NoError(t, err)
		assert.Equal(t, string(out), string(b.Bytes()))
	})
}

// apt-ftparchive generate names packages Section/name, with a slash in the
// section kept, and a package without a Section by its bare name.
func TestContentsBuilderMatchesAptFTPArchiveGenerate(t *testing.T) {
	var b deb.ContentsBuilder
	for _, d := range poolDebs(t) {
		require.NoError(t, b.AddDeb(d))
	}

	assert.Equal(t, string(readFixture(t, "repo-contents", "generate.expected")), string(b.Bytes()))

	t.Run("live", func(t *testing.T) {
		ftp, err := exec.LookPath("apt-ftparchive")
		if err != nil {
			t.Skip("apt-ftparchive not installed")
		}

		tree := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(tree, "pool", "main"), 0o755))
		require.NoError(t, os.MkdirAll(filepath.Join(tree, "dists", "x", "main", "binary-amd64"), 0o755))
		require.NoError(t, os.MkdirAll(filepath.Join(tree, "cache"), 0o755))

		for _, d := range []string{"alpha_1.0-1_amd64.deb", "beta_2.0_amd64.deb", "gamma_3.1_all.deb"} {
			raw, err := os.ReadFile(filepath.Join("testdata", "repo-contents", "pool", d))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(tree, "pool", "main", d), raw, 0o644))
		}

		conf := "Dir { ArchiveDir \"" + tree + "\"; CacheDir \"" + tree + "/cache\"; };\n" +
			"Default { Packages::Compress \".\"; Contents::Compress \".\"; };\n" +
			"TreeDefault { Directory \"pool/$(SECTION)\"; Contents \"$(DIST)/Contents-$(ARCH)\"; };\n" +
			"Tree \"dists/x\" { Sections \"main\"; Architectures \"amd64\"; };\n"
		confPath := filepath.Join(tree, "ftp.conf")
		require.NoError(t, os.WriteFile(confPath, []byte(conf), 0o644))

		cmd := exec.Command(ftp, "generate", confPath)
		cmd.Dir = tree

		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))

		got, err := os.ReadFile(filepath.Join(tree, "dists", "x", "Contents-amd64"))
		require.NoError(t, err)
		assert.Equal(t, string(got), string(b.Bytes()))
	})
}

func TestScanContentsRealIndexes(t *testing.T) {
	t.Run("debian", func(t *testing.T) {
		entries := scanContentsAll(t, string(readFixture(t, "repo-contents", "debian-contents-amd64.head")))
		require.Len(t, entries, 120)
		assert.Equal(t, deb.ContentsEntry{Path: "bin", Locations: []string{"admin/base-files"}}, entries[0])

		multi := 0

		for _, e := range entries {
			assert.NotEmpty(t, e.Path)
			assert.NotEmpty(t, e.Locations)

			if len(e.Locations) > 1 {
				multi++
			}
		}

		assert.Positive(t, multi, "files provided by several packages")
		assert.Equal(t, "boot/System.map-6.12.107+deb13-amd64", entries[1].Path)

		// Rendering what was read and reading it back gives the same entries
		// (the padding differs from dak's: that is a matter of bytes only).
		var b deb.ContentsBuilder
		for _, e := range entries {
			require.NoError(t, b.AddEntry(e))
		}

		again := scanContentsAll(t, string(b.Bytes()))
		assert.Equal(t, entries, again)

		idx, err := deb.ParseContents(strings.NewReader(string(b.Bytes())))
		require.NoError(t, err)
		assert.Equal(t, len(entries), idx.Len())
	})

	t.Run("ubuntu", func(t *testing.T) {
		entries := scanContentsAll(t, string(readFixture(t, "repo-contents", "ubuntu-contents-amd64.head")))
		require.Len(t, entries, 80)
		assert.Equal(t, deb.ContentsEntry{Path: "bin/archdetect", Locations: []string{"admin/ubiquity"}}, entries[0])
		assert.Equal(t, []string{"universe/shells/ash"}, entries[1].Locations)
	})

	t.Run("debian udeb gzip", func(t *testing.T) {
		f, err := os.Open(filepath.Join("testdata", "repo-contents", "debian-contents-udeb-amd64.head.gz"))
		require.NoError(t, err)

		defer func() { _ = f.Close() }()

		rc, err := deb.OpenIndex(f, "Contents-udeb-amd64.gz")
		require.NoError(t, err)

		defer func() { _ = rc.Close() }()

		idx, err := deb.ParseContents(rc)
		require.NoError(t, err)
		assert.Equal(t, 150, idx.Len())
		assert.Equal(t, []string{"debian-installer/cdebconf-text-udeb"}, idx.Locations(".inputrc"))
		assert.Equal(t, []string{"debian-installer/anna"}, idx.Locations("bin/anna"))
		assert.Equal(t, []string{"debian-installer/anna"}, idx.Locations("/bin/anna"), "a leading slash is ignored")
		assert.Empty(t, idx.Locations("not/there"))

		found := idx.Find(func(p string) bool { return strings.HasPrefix(p, "bin/") })
		assert.NotEmpty(t, found)
		assert.Contains(t, found, "bin/anna")

		var n int
		var last string

		for e := range idx.Entries() {
			assert.Less(t, last, e.Path)

			last = e.Path
			n++
		}

		assert.Equal(t, 150, n)
	})
}

func TestScanContentsLineShapes(t *testing.T) {
	tests := map[string]struct {
		in   string
		want []deb.ContentsEntry
	}{
		"header":              {"FILE                                                    LOCATION\nusr/bin/a\t\t\tutils/a\n", []deb.ContentsEntry{{Path: "usr/bin/a", Locations: []string{"utils/a"}}}},
		"blanks in the path":  {"usr/share/with space/file one.txt\t\t\t    utils/alpha\n", []deb.ContentsEntry{{Path: "usr/share/with space/file one.txt", Locations: []string{"utils/alpha"}}}},
		"several packages":    {"x  a/b,c/d,e\n", []deb.ContentsEntry{{Path: "x", Locations: []string{"a/b", "c/d", "e"}}}},
		"crlf":                {"x\ta\r\ny\tb\r\n", []deb.ContentsEntry{{Path: "x", Locations: []string{"a"}}, {Path: "y", Locations: []string{"b"}}}},
		"no trailing newline": {"x a", []deb.ContentsEntry{{Path: "x", Locations: []string{"a"}}}},
		"blank and one-word":  {"\n\nlonely\n  \nx a\n", []deb.ContentsEntry{{Path: "x", Locations: []string{"a"}}}},
		"empty list items":    {"x ,a,,b,\ny ,\n", []deb.ContentsEntry{{Path: "x", Locations: []string{"a", "b"}}}},
		"empty":               {"", nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, scanContentsAll(t, tc.in))
		})
	}
}

func TestScanContentsBounds(t *testing.T) {
	t.Run("line too long", func(t *testing.T) {
		var errSeen error

		for _, err := range deb.ScanContents(strings.NewReader(strings.Repeat("a", deb.MaxLineBytes+10) + " p\n")) {
			errSeen = err
		}

		require.Error(t, errSeen)
	})

	t.Run("too many locations", func(t *testing.T) {
		line := "f " + strings.Repeat("p,", deb.MaxContentsLocations) + "p\n"

		var errSeen error

		for _, err := range deb.ScanContents(strings.NewReader(line)) {
			errSeen = err
		}

		require.ErrorIs(t, errSeen, deb.ErrTooLarge)

		_, err := deb.ParseContents(strings.NewReader(line))
		require.ErrorIs(t, err, deb.ErrTooLarge)

		require.ErrorIs(t, (&deb.ContentsBuilder{}).AddReader(strings.NewReader(line)), deb.ErrTooLarge)
	})

	t.Run("stopping early stops reading", func(t *testing.T) {
		r := &ctsCountReader{r: strings.NewReader(strings.Repeat("some/file/path p\n", 100000))}

		for range deb.ScanContents(r) {
			break
		}

		assert.Less(t, r.n, 1<<20, "the scan reads a buffer, not the whole input")
	})

	t.Run("read error", func(t *testing.T) {
		var errSeen error

		for _, err := range deb.ScanContents(io.MultiReader(strings.NewReader("a b\n"), ctsErrReader{})) {
			errSeen = err
		}

		require.ErrorIs(t, errSeen, io.ErrUnexpectedEOF)
	})

	t.Run("invalid location from a file", func(t *testing.T) {
		var b deb.ContentsBuilder
		require.NoError(t, b.AddReader(strings.NewReader("a/b\tx,y\n")))
		assert.Equal(t, 1, b.Len())
	})
}

type ctsCountReader struct {
	r io.Reader
	n int
}

func (c *ctsCountReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n

	return n, err
}

type ctsErrReader struct{}

func (ctsErrReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestContentsBuilderMergesAnIndex(t *testing.T) {
	data := readFixture(t, "repo-contents", "ubuntu-contents-amd64.head")

	var b deb.ContentsBuilder
	require.NoError(t, b.AddReader(bytes.NewReader(data)))
	require.NoError(t, b.AddReader(strings.NewReader("bin/archdetect extra/other\n")))

	assert.Equal(t, []string{"admin/ubiquity", "extra/other"}, b.Locations("bin/archdetect"))
	assert.Equal(t, 80, b.Len())

	entries := slices.Collect(b.Entries())
	require.Len(t, entries, 80)
	assert.True(t, slices.IsSortedFunc(entries, func(a, b deb.ContentsEntry) int { return strings.Compare(a.Path, b.Path) }))
}

func FuzzScanContents(f *testing.F) {
	f.Add("FILE LOCATION\nusr/bin/a\t\t\tutils/a,b/c\n")
	f.Add("with space/x y   sect/p\n\n\nlonely\n")
	f.Add("x\ta\r\n,\n")
	f.Add(string(readFixtureBytes("repo-contents", "ubuntu-contents-amd64.head"))[:600])

	f.Fuzz(func(t *testing.T, in string) {
		var b deb.ContentsBuilder

		var entries []deb.ContentsEntry

		for e, err := range deb.ScanContents(strings.NewReader(in)) {
			if err != nil {
				return
			}

			assert.NotEmpty(t, e.Path)
			assert.NotEmpty(t, e.Locations)

			entries = append(entries, e)

			// Entries the builder accepts survive a render and a re-read.
			_ = b.AddEntry(e)
		}

		for e := range deb.ScanContents(bytes.NewReader(b.Bytes())) {
			assert.NotEmpty(t, e.Path)
		}

		idx, err := deb.ParseContents(strings.NewReader(in))
		if err == nil {
			assert.LessOrEqual(t, idx.Len(), len(entries))
		}
	})
}

func readFixtureBytes(elem ...string) []byte {
	b, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, elem...)...))
	if err != nil {
		panic(err)
	}

	return b
}
