package deb_test

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

const packagesFixture = "Package: foo\nVersion: 1.0-1\nArchitecture: amd64\nFilename: pool/main/f/foo/foo_1.0-1_amd64.deb\nSize: 10\nSHA256: aa\nDescription: first\n" +
	" continued line\n\n" +
	"package: Bar\r\nversion: 2:2.0\r\narchitecture: all\r\nfilename: pool/main/b/bar/bar_2.0_all.deb\r\nsha256: bb\r\n\r\n\r\n" +
	"Version: 9\nArchitecture: amd64\n\n" + // no Package field: skipped
	"Package: baz\nVersion: 3\nArchitecture: amd64\nFilename: pool/main/b/baz/baz_3_amd64.deb\nSHA256: cc"

func scanAll(t *testing.T, doc string) []deb.Stanza {
	t.Helper()

	var got []deb.Stanza

	require.NoError(t, deb.ScanPackages(strings.NewReader(doc), func(s deb.Stanza) error {
		got = append(got, s)

		return nil
	}))

	return got
}

func TestScanPackages(t *testing.T) {
	got := scanAll(t, packagesFixture)
	require.Len(t, got, 3, "the stanza without a Package field is skipped")

	foo := got[0]
	assert.Equal(t, "foo", foo.Package)
	assert.Equal(t, "1.0-1", foo.Version)
	assert.Equal(t, "amd64", foo.Architecture)
	assert.Equal(t, "pool/main/f/foo/foo_1.0-1_amd64.deb", foo.Filename)
	assert.Equal(t, "aa", foo.SHA256)
	assert.Contains(t, foo.Text, " continued line\n")
	assert.True(t, strings.HasSuffix(foo.Text, "\n\n"))

	bar := got[1]
	assert.Equal(t, "Bar", bar.Package, "field names match case-insensitively")
	assert.Equal(t, "2:2.0", bar.Version)
	assert.Equal(t, "all", bar.Architecture)
	assert.Equal(t, "bb", bar.SHA256)
	assert.NotContains(t, bar.Text, "\r", "CRLF is normalised")

	assert.Equal(t, "baz", got[2].Package)
	assert.True(t, strings.HasSuffix(got[2].Text, "SHA256: cc\n\n"), "a last stanza without a blank line is terminated: %q", got[2].Text)
}

func TestScanPackagesIgnoresCommentsAndContinuationFields(t *testing.T) {
	got := scanAll(t, "# comment\nPackage: a\nDescription: x\n Version: 99\n Package: evil\nVersion: 1\n")
	require.Len(t, got, 1)
	assert.Equal(t, "a", got[0].Package)
	assert.Equal(t, "1", got[0].Version, "a continuation line is not a field")
	assert.NotContains(t, got[0].Text, "#")
}

func TestScanPackagesEmpty(t *testing.T) {
	assert.Empty(t, scanAll(t, ""))
	assert.Empty(t, scanAll(t, "\n\n\n"))
}

func TestScanPackagesStopsOnCallbackError(t *testing.T) {
	stop := io.ErrClosedPipe
	n := 0

	err := deb.ScanPackages(strings.NewReader(packagesFixture), func(deb.Stanza) error {
		n++

		return stop
	})
	require.ErrorIs(t, err, stop)
	assert.Equal(t, 1, n)
}

func TestScanPackagesRejectsHugeLine(t *testing.T) {
	doc := "Package: foo\nDescription: " + strings.Repeat("x", deb.MaxLineBytes) + "\n\n"

	err := deb.ScanPackages(strings.NewReader(doc), func(deb.Stanza) error { return nil })
	require.ErrorIs(t, err, deb.ErrTooLarge)
}

func TestScanPackagesReadError(t *testing.T) {
	err := deb.ScanPackages(failingReader{}, func(deb.Stanza) error { return nil })
	require.ErrorIs(t, err, errBroken)
}

func TestFormatPackagesEntry(t *testing.T) {
	got := deb.FormatPackagesEntry(deb.IndexEntry{
		Name: "libfoo", Version: "1.0", Arch: "amd64",
		Filename: deb.PoolPath("main", "libfoo", "libfoo_1.0_amd64.deb"),
		SHA256:   "abc", Size: 2048, InstalledSize: 9,
		Control: map[string]string{"Depends": "libc6", "Maintainer": "A <a@b>", "Description": "short\nlong"},
	})

	assert.Equal(t, "Package: libfoo\n"+
		"Version: 1.0\n"+
		"Architecture: amd64\n"+
		"Maintainer: A <a@b>\n"+
		"Installed-Size: 9\n"+
		"Depends: libc6\n"+
		"Filename: pool/main/libf/libfoo/libfoo_1.0_amd64.deb\n"+
		"Size: 2048\n"+
		"SHA256: abc\n"+
		"Description: short\n long\n"+
		"\n", got)
}

func TestFormatPackagesEntryFieldOrder(t *testing.T) {
	control := map[string]string{
		"Priority": "optional", "Section": "utils", "Homepage": "https://x", "Multi-Arch": "same", "Essential": "yes",
		"Built-Using": "g (= 1)", "Replaces": "r", "Provides": "p", "Conflicts": "c", "Breaks": "b", "Enhances": "e",
		"Suggests": "s", "Recommends": "rec", "Depends": "d", "Pre-Depends": "pd", "Maintainer": "m", "Source": "src",
		"X-Zed": "z", "Bugs": "bug", "X-Alpha": "a", "Description": "desc",
	}

	cf, err := deb.ParseControlFile(strings.NewReader(deb.FormatPackagesEntry(deb.IndexEntry{
		Name: "p", Version: "1", Arch: "all", InstalledSize: 3, Filename: "f", Size: 5,
		MD5sum: "m5", SHA1: "s1", SHA256: "s256", SHA512: "s512", Control: control,
	})))
	require.NoError(t, err)

	assert.Equal(t, []string{
		"Package", "Source", "Version", "Architecture", "Maintainer", "Installed-Size", "Pre-Depends", "Depends",
		"Recommends", "Suggests", "Enhances", "Breaks", "Conflicts", "Provides", "Replaces", "Built-Using",
		"Essential", "Multi-Arch", "Section", "Priority", "Homepage",
		"Bugs", "X-Alpha", "X-Zed", // unknown fields, sorted
		"Filename", "Size", "MD5sum", "SHA1", "SHA256", "SHA512", "Description",
	}, cf.Order)
}

func TestFormatPackagesEntryOmitsEmpty(t *testing.T) {
	got := deb.FormatPackagesEntry(deb.IndexEntry{Name: "p", Version: "1", Arch: "all"})
	assert.Equal(t, "Package: p\nVersion: 1\nArchitecture: all\nSize: 0\n\n", got)

	assert.Equal(t, "Size: 0\n\n", deb.FormatPackagesEntry(deb.IndexEntry{}))
}

func TestFormatPackagesEntryMultilineDescription(t *testing.T) {
	got := deb.FormatPackagesEntry(deb.IndexEntry{
		Name: "p", Version: "1", Arch: "all",
		Control: map[string]string{"Description": "S\nlong\n\nafter blank"},
	})
	assert.Contains(t, got, "Description: S\n long\n .\n after blank\n\n")

	stanzas := scanAll(t, got)
	require.Len(t, stanzas, 1)

	cf, err := deb.ParseControlFile(strings.NewReader(stanzas[0].Text))
	require.NoError(t, err)
	assert.Equal(t, "S\nlong\n\nafter blank", cf.Get("Description"))
}

// apt matches field names case-insensitively: a lowercase "filename:" or
// "sha256:" in an uploaded control stanza must not reach the Packages entry.
func TestControlFieldsCaseInsensitiveOwnedFields(t *testing.T) {
	in := map[string]string{
		"filename": "pool/main/e/evil/evil.deb", "SHA256": "dead", "sha256": "beef", "size": "1",
		"md5SUM": "x", "Section": "admin", "x-custom": "ok",
	}

	stored := deb.ControlFieldsToStore(in)

	for _, k := range []string{"filename", "Filename", "sha256", "SHA256", "size", "Size", "md5SUM", "MD5sum"} {
		assert.NotContains(t, stored, k, "owned field %q was stored", k)
	}

	assert.Equal(t, "admin", stored["Section"])
	assert.Equal(t, "ok", stored["x-custom"])

	// A row stored before the filter existed (lowercase owned fields kept) still
	// renders once.
	entry := deb.FormatPackagesEntry(deb.IndexEntry{
		Name: "pkg", Version: "1", Arch: "amd64", Filename: "pkg_1_amd64.deb", Size: 10, SHA256: "abc", Control: in,
	})

	for _, k := range []string{"\nfilename:", "\nsha256:", "\nsize:", "\nmd5SUM:", "\nmd5sum:"} {
		assert.NotContains(t, entry, k)
	}

	assert.Equal(t, 1, strings.Count(entry, "Filename:"), entry)
	assert.Equal(t, 1, strings.Count(entry, "SHA256: abc"), entry)
	assert.Equal(t, 1, strings.Count(entry, "Size:"), entry)
}

func TestControlFieldsToStore(t *testing.T) {
	stored := deb.ControlFieldsToStore(map[string]string{
		"Package": "p", "package": "q", "Version": "1", "Architecture": "a", "Installed-Size": "1", "installed-size": "2",
		"Filename": "f", "Size": "1", "MD5sum": "m", "SHA1": "s", "SHA256": "s", "SHA512": "s",
		"Description": "d", "Depends": "x", "depends": "y", "DEPENDS": "z", "maintainer": "m", "Bugs": "b", "bugs": "c",
	})

	assert.Equal(t, map[string]string{
		"Description": "d",
		"Depends":     "x", // the canonical spelling wins
		"Maintainer":  "m",
		"Bugs":        "b", // not a field the index knows: spellings stay apart
		"bugs":        "c",
	}, stored)

	// Spelling variants without the canonical one collapse onto the lexically smallest.
	assert.Equal(t, map[string]string{"Depends": "Z"}, deb.ControlFieldsToStore(map[string]string{"depends": "z", "DEPENDS": "Z"}))
	assert.Empty(t, deb.ControlFieldsToStore(nil))
}

func TestFormatPackagesEntryCollapsesVariants(t *testing.T) {
	entry := deb.FormatPackagesEntry(deb.IndexEntry{
		Name: "p", Version: "1", Arch: "all",
		Control: map[string]string{"depends": "lower", "DEPENDS": "upper", "section": "s"},
	})

	assert.Equal(t, 1, strings.Count(strings.ToLower(entry), "depends:"), entry)
	assert.Contains(t, entry, "Depends: upper\n")
	assert.Contains(t, entry, "Section: s\n")
}

func TestEntryFromControl(t *testing.T) {
	cf := parseControl(t, "Package: hello\nVersion: 1:2.0-1\nArchitecture: amd64\nInstalled-Size: 42\nDepends: libc6\nFilename: evil\nSize: 1\nSHA256: dead\nDescription: hi\n long\nX-Custom: yes\n")

	file := deb.HashBytes("pool/main/h/hello/hello_2.0-1_amd64.deb", []byte("content"))

	e, err := deb.EntryFromControl(cf, file)
	require.NoError(t, err)

	assert.Equal(t, "hello", e.Name)
	assert.Equal(t, "1:2.0-1", e.Version)
	assert.Equal(t, "amd64", e.Arch)
	assert.Equal(t, int64(42), e.InstalledSize)
	assert.Equal(t, file.Path, e.Filename)
	assert.Equal(t, int64(7), e.Size)
	assert.Equal(t, file.MD5sum, e.MD5sum)
	assert.Equal(t, file.SHA1, e.SHA1)
	assert.Equal(t, file.SHA256, e.SHA256)
	assert.Equal(t, file.SHA512, e.SHA512)
	assert.Equal(t, map[string]string{"Depends": "libc6", "Description": "hi\nlong", "X-Custom": "yes"}, e.Control)

	// The rendered stanza carries the file facts, not the control file's claims.
	stanza := scanAll(t, deb.FormatPackagesEntry(e))
	require.Len(t, stanza, 1)
	assert.Equal(t, file.Path, stanza[0].Filename)
	assert.Equal(t, file.SHA256, stanza[0].SHA256)
	assert.NotContains(t, stanza[0].Text, "evil")
	assert.NotContains(t, stanza[0].Text, "dead")

	_, err = deb.EntryFromControl(parseControl(t, "Package: x\n"), file)
	require.ErrorIs(t, err, deb.ErrMissingRequiredField)
}

func TestIndexAddAndBytes(t *testing.T) {
	var ix deb.Index

	assert.Zero(t, ix.Len())
	assert.Empty(t, ix.Bytes())

	ix.Add(deb.IndexEntry{Name: "a", Version: "1", Arch: "all"})
	ix.AddText("Package: b\nVersion: 2")
	ix.AddText("Package: c\n\n")
	ix.AddText("")

	assert.Equal(t, 3, ix.Len())
	assert.Equal(t, "Package: a\nVersion: 1\nArchitecture: all\nSize: 0\n\nPackage: b\nVersion: 2\n\nPackage: c\n\n", string(ix.Bytes()))

	got := scanAll(t, string(ix.Bytes()))
	require.Len(t, got, 3)
	assert.Equal(t, []string{"a", "b", "c"}, []string{got[0].Package, got[1].Package, got[2].Package})
}

func TestIndexBytesCacheInvalidated(t *testing.T) {
	var ix deb.Index

	ix.AddText("Package: a\n")

	first := ix.Bytes()
	assert.Equal(t, "Package: a\n\n", string(first))

	// The render is shared between calls...
	assert.Same(t, &first[0], &ix.Bytes()[0])

	// ...and refreshed by an addition.
	ix.AddText("Package: b\n")
	assert.Equal(t, "Package: a\n\nPackage: b\n\n", string(ix.Bytes()))
}

func TestIndexCompressedRoundTrip(t *testing.T) {
	var ix deb.Index

	for i := range 50 {
		ix.Add(deb.IndexEntry{
			Name: "pkg" + strings.Repeat("x", i%5), Version: "1." + strings.Repeat("1", i), Arch: "amd64",
			Filename: "f", Size: int64(i), Control: map[string]string{"Description": "d " + strings.Repeat("y", i)},
		})
	}

	for _, tc := range []struct {
		c    deb.Compression
		name string
	}{
		{deb.CompressionNone, "Packages"},
		{deb.CompressionGzip, "Packages.gz"},
		{deb.CompressionXZ, "Packages.xz"},
		{deb.CompressionZstd, "Packages.zst"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := ix.Compressed(tc.c)
			require.NoError(t, err)

			if tc.c != deb.CompressionNone {
				assert.Less(t, len(raw), len(ix.Bytes()))
			}

			rc, err := deb.OpenIndex(bytes.NewReader(raw), tc.name)
			require.NoError(t, err)

			back, err := io.ReadAll(rc)
			require.NoError(t, err)
			require.NoError(t, rc.Close())
			assert.Equal(t, ix.Bytes(), back)

			var buf bytes.Buffer

			n, err := ix.WriteTo(&buf, tc.c)
			require.NoError(t, err)
			assert.Equal(t, int64(buf.Len()), n)
			assert.Equal(t, raw, buf.Bytes())
		})
	}
}

func TestIndexWriteToErrors(t *testing.T) {
	var ix deb.Index

	ix.AddText("Package: a\n")

	_, err := ix.Compressed(deb.Compression(42))
	require.ErrorIs(t, err, deb.ErrUnsupportedCompression)

	for _, c := range []deb.Compression{deb.CompressionNone, deb.CompressionGzip, deb.CompressionXZ, deb.CompressionZstd} {
		_, err = ix.WriteTo(&failingWriter{left: 0}, c)
		require.ErrorIs(t, err, errSink, "compression %d", c)
	}
}

func TestIndexRoundTripThroughScanPackages(t *testing.T) {
	entries := []deb.IndexEntry{
		{Name: "libfoo", Version: "1:1.0-1", Arch: "amd64", Filename: deb.PoolPath("main", "libfoo", "libfoo_1.0-1_amd64.deb"), SHA256: "aa", Size: 1,
			Control: map[string]string{"Depends": "libc6", "Description": "foo\n bar"}},
		{Name: "tool", Version: "2", Arch: "all", Filename: deb.PoolPath("main", "tool", "tool_2_all.deb"), SHA256: "bb", Size: 2},
	}

	var ix deb.Index
	for _, e := range entries {
		ix.Add(e)
	}

	got := scanAll(t, string(ix.Bytes()))
	require.Len(t, got, len(entries))

	for i, e := range entries {
		assert.Equal(t, e.Name, got[i].Package)
		assert.Equal(t, e.Version, got[i].Version)
		assert.Equal(t, e.Arch, got[i].Architecture)
		assert.Equal(t, e.Filename, got[i].Filename)
		assert.Equal(t, e.SHA256, got[i].SHA256)
	}
}

// writeRepoPackage writes a package into dir/pool and returns its path.
func writeRepoPackage(t *testing.T, dir string, spec *deb.Spec, payload []deb.Entry) string {
	t.Helper()

	path := filepath.Join(dir, "pool", spec.FileName())
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, deb.WriteFile(path, spec, payload, deb.WriteOptions{}))

	return path
}

func indexEntryOf(t *testing.T, path, repoPath string) deb.IndexEntry {
	t.Helper()

	file, err := os.Open(path)
	require.NoError(t, err)

	defer file.Close()

	info, err := deb.HashReader(repoPath, file)
	require.NoError(t, err)

	st, err := file.Stat()
	require.NoError(t, err)

	d, err := deb.ParseDebFileAt(file, st.Size())
	require.NoError(t, err)

	e, err := deb.EntryFromControl(d.ControlFile, info)
	require.NoError(t, err)

	return e
}

// stanzaFields parses one stanza into its canonical-case field map.
func stanzaFields(t *testing.T, text string) map[string]string {
	t.Helper()

	cf := parseControl(t, text)
	out := map[string]string{}

	for _, k := range cf.Order {
		out[strings.ToLower(k)] = cf.Fields[k]
	}

	return out
}

func TestIndexMatchesRealTools(t *testing.T) {
	scan, scanErr := exec.LookPath("dpkg-scanpackages")
	ftp, ftpErr := exec.LookPath("apt-ftparchive")

	if scanErr != nil && ftpErr != nil {
		t.Skip("neither dpkg-scanpackages nor apt-ftparchive installed")
	}

	repo := t.TempDir()

	spec := testSpec()
	spec.Compression = "xz"
	path := writeRepoPackage(t, repo, spec, append(testPayload(), deb.Entry{Path: "usr/share/big", Mode: 0o644, Data: bytes.Repeat([]byte("z"), 8192)}))

	other := &deb.Spec{Name: "other", Version: "0.1", Architecture: "all", Description: "second package", Compression: "gzip", Section: "misc", Priority: "extra"}
	writeRepoPackage(t, repo, other, []deb.Entry{{Path: "usr/share/other", Mode: 0o644, Data: []byte("o")}})

	e := indexEntryOf(t, path, "pool/"+spec.FileName())
	ours := stanzaFields(t, deb.FormatPackagesEntry(e))

	run := func(tool string, args ...string) string {
		cmd := exec.Command(tool, args...)
		cmd.Dir = repo

		out, err := cmd.Output()
		require.NoError(t, err)

		return string(out)
	}

	check := func(t *testing.T, toolOut string, ignore ...string) {
		t.Helper()

		var theirs map[string]string

		for _, st := range scanAll(t, toolOut) {
			if st.Package == spec.Name {
				theirs = stanzaFields(t, st.Text)
			}
		}

		require.NotNil(t, theirs, "the tool did not list the package:\n%s", toolOut)

		for k, v := range theirs {
			if !assert.Contains(t, ours, k, "field %q written by the tool is missing from our stanza", k) {
				continue
			}

			if !assert.ObjectsAreEqual(v, ours[k]) && !contains(ignore, k) {
				t.Errorf("field %q: tool %q, ours %q", k, v, ours[k])
			}
		}

		for k := range ours {
			if k == "sha512" {
				continue // not every tool computes it
			}

			assert.Contains(t, theirs, k, "field %q of our stanza is not in the tool's", k)
		}
	}

	if scanErr == nil {
		t.Run("dpkg-scanpackages", func(t *testing.T) {
			check(t, run(scan, "--multiversion", "pool"))
		})
	}

	if ftpErr == nil {
		t.Run("apt-ftparchive", func(t *testing.T) {
			check(t, run(ftp, "packages", "pool"))
		})
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}

	return false
}

func TestIndexReadByRealTool(t *testing.T) {
	ftp, err := exec.LookPath("apt-ftparchive")
	if err != nil {
		t.Skip("apt-ftparchive not installed")
	}

	// apt-ftparchive contents reads packages, not an index; use "release" on a
	// tree holding our Packages files and compare its digests with ours.
	repo := t.TempDir()
	dist := filepath.Join(repo, "dists", "stable")
	dir := filepath.Join(dist, "main", "binary-amd64")
	require.NoError(t, os.MkdirAll(dir, 0o755))

	var ix deb.Index

	ix.Add(deb.IndexEntry{Name: "a", Version: "1", Arch: "amd64", Filename: "pool/a.deb", Size: 1, SHA256: "aa"})

	rel := &deb.Release{Suite: "stable", Codename: "stable", Architectures: []string{"amd64"}, Components: []string{"main"}}

	for _, c := range []deb.Compression{deb.CompressionNone, deb.CompressionGzip, deb.CompressionXZ} {
		raw, err := ix.Compressed(c)
		require.NoError(t, err)

		name := "Packages" + c.Extension()
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), raw, 0o644))
		rel.AddFile(deb.HashBytes("main/binary-amd64/"+name, raw))
	}

	cmd := exec.Command(ftp, "release", ".")
	cmd.Dir = dist

	out, err := cmd.Output()
	require.NoError(t, err)

	theirs, err := deb.ParseRelease(out)
	require.NoError(t, err)

	require.NotEmpty(t, theirs.Files)

	for path, want := range rel.Files {
		got, ok := theirs.Files[path]
		require.True(t, ok, "apt-ftparchive did not list %s", path)
		assert.Equal(t, want, got, path)
	}

}

func FuzzScanPackages(f *testing.F) {
	f.Add(packagesFixture)
	f.Add("Package: a\nVersion: 1\n\n\n\nPackage: b\n")
	f.Add("Package: a\r\nDescription: x\r\n y\r\n\r\n")
	f.Add("# c\n Package: no\nPackage:\n\n")
	f.Add(deb.FormatPackagesEntry(deb.IndexEntry{Name: "p", Version: "1", Arch: "all", Control: map[string]string{"Description": "a\n\nb"}}))

	f.Fuzz(func(t *testing.T, doc string) {
		var stanzas []deb.Stanza

		err := deb.ScanPackages(strings.NewReader(doc), func(s deb.Stanza) error {
			stanzas = append(stanzas, s)

			return nil
		})
		if err != nil {
			return
		}

		for _, s := range stanzas {
			assert.NotEmpty(t, s.Package)
			assert.True(t, strings.HasSuffix(s.Text, "\n\n"), "%q", s.Text)

			// A stanza reads back as itself.
			again := scanAll(t, s.Text)
			require.Len(t, again, 1)
			assert.Equal(t, s, again[0])
		}
	})
}
