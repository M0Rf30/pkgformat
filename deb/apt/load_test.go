package apt

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

func gzipBytes(tb testing.TB, data []byte) []byte {
	tb.Helper()

	var buf bytes.Buffer

	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(data)
	require.NoError(tb, err)
	require.NoError(tb, zw.Close())

	return buf.Bytes()
}

func TestLoadParsesStanzaFields(t *testing.T) {
	t.Parallel()

	c := cacheFromText(t, para(
		"Package: gcc-12",
		"Version: 12.2.0-14",
		"Architecture: amd64",
		"Essential: yes",
		"Multi-Arch: same",
		"Depends: libc6 (>= 2.34), libgcc-12-dev (= 12.2.0-14) | other",
		"Pre-Depends: dpkg (>= 1.0)",
		"Filename: pool/main/g/gcc-12/gcc-12_12.2.0-14_amd64.deb",
		"Size: 1234",
		"SHA256: "+sha256Hex([]byte("x")),
	))

	got, ok := c.Lookup("gcc-12")
	require.True(t, ok)
	assert.Equal(t, PackageInfo{
		Name: "gcc-12", Version: "12.2.0-14", Architecture: "amd64", Essential: true, MultiArch: "same",
		HasCandidate: true, Filename: "pool/main/g/gcc-12/gcc-12_12.2.0-14_amd64.deb", Size: 1234,
		SHA256:  sha256Hex([]byte("x")),
		Depends: deps(t, "libc6 (>= 2.34), libgcc-12-dev (= 12.2.0-14) | other"), PreDepends: deps(t, "dpkg (>= 1.0)"),
	}, got)
}

func TestLoadContinuationLines(t *testing.T) {
	t.Parallel()

	c := cacheFromText(t, "Package: multi\n"+
		"Version: 1\n"+
		"Architecture: amd64\n"+
		"Depends: first,\n second,\n third\n"+
		"Description: short\n long description\n .\n more\n"+
		"Filename: pool/multi.deb\n\n"+
		"Package: first\nVersion: 1\nArchitecture: amd64\n\n"+
		"Package: second\nVersion: 1\nArchitecture: amd64\n\n"+
		"Package: third\nVersion: 1\nArchitecture: amd64\nDescription: x\n .\n\n")

	got, ok := c.Lookup("multi")
	require.True(t, ok)
	assert.Equal(t, "first, second, third", deb.FormatRelations(got.Depends))
	assert.Equal(t, "pool/multi.deb", got.Filename, "a field after continuation lines is still read")
	assert.Equal(t, 4, c.PackageCount())
}

func TestLoadSkipsUnusableStanzas(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, indexName("x", "main", "amd64")),
		para("Package: virt", "Architecture: amd64", "Depends: x")+
			para("Package: badrel", "Version: 1", "Architecture: amd64", "Depends: foo (>= )")+
			para("Version: 1", "Architecture: amd64")+
			para("Package: fine", "Version: 1", "Architecture: amd64", "Conflicts: a, b (<< 2)", "Breaks: c", "Provides: d (= 1)"))

	var buf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	c, err := Load(LoadOptions{ListsDir: dir, HostArch: hostArch, Logger: logger})
	require.NoError(t, err)

	for _, name := range []string{"virt", "badrel"} {
		_, ok := c.Lookup(name)
		assert.False(t, ok, "%s is not kept", name)
	}

	assert.Contains(t, buf.String(), "stanza skipped")
	assert.Equal(t, 1, c.PackageCount())

	fine, ok := c.Lookup("fine")
	require.True(t, ok)
	assert.Equal(t, "a, b (<< 2)", deb.FormatRelations(altsOf(fine.Conflicts)))
	assert.Equal(t, "c", deb.FormatRelations(altsOf(fine.Breaks)))
	assert.Equal(t, "d (= 1)", deb.FormatRelations(altsOf(fine.Provides)))
}

func TestLoadStatusOverlay(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "lists", indexName("x", "main", "amd64")),
		para("Package: ok", "Version: 1", "Architecture: amd64", "Filename: ok.deb")+
			para("Package: removed", "Version: 1", "Architecture: amd64", "Filename: removed.deb")+
			para("Package: half", "Version: 1", "Architecture: amd64", "Filename: half.deb")+
			para("Package: wanthold", "Version: 1", "Architecture: amd64", "Filename: wh.deb")+
			para("Package: notindexed", "Version: 1", "Architecture: amd64"))
	writeFile(t, filepath.Join(dir, "status"),
		para("Package: ok", "Status: install ok installed", "Architecture: amd64", "Version: 1", "Filename: IGNORED.deb", "SHA256: ignored", "Size: 99")+
			para("Package: removed", "Status: deinstall ok config-files", "Architecture: amd64", "Version: 1")+
			para("Package: half", "Status: install ok half-installed", "Architecture: amd64", "Version: 1")+
			para("Package: wanthold", "Status: hold ok installed", "Architecture: amd64", "Version: 1")+
			para("Package: only-status", "Status: install ok installed", "Architecture: arm64", "Version: 3"))

	c, err := Load(LoadOptions{ListsDir: filepath.Join(dir, "lists"), StatusFile: filepath.Join(dir, "status"), HostArch: hostArch})
	require.NoError(t, err)

	ok, _ := c.Lookup("ok")
	assert.True(t, ok.Installed)
	assert.Equal(t, "ok.deb", ok.Filename, "the status database does not change artifact fields of the index")
	assert.Zero(t, ok.Size)

	for _, n := range []string{"removed", "half", "notindexed"} {
		info, found := c.Lookup(n)
		require.True(t, found, n)
		assert.False(t, info.Installed, n)
	}

	held, found := c.Lookup("wanthold")
	require.True(t, found)
	assert.True(t, held.Installed, "a package on hold is installed")

	only, found := c.Lookup("only-status")
	require.True(t, found)
	assert.True(t, only.Installed)
	assert.Empty(t, only.BaseURL, "a status-only package cannot be downloaded")

	assert.Equal(t, map[string]bool{"ok": true, "only-status": true, "wanthold": true}, c.InstalledNames())
}

func TestLoadMergeRules(t *testing.T) {
	t.Parallel()

	one := Source{URL: "http://one.example/debian/", Suite: "x", Components: []string{"main"}}
	two := Source{URL: "http://two.example/ubuntu-ports/", Suite: "x", Components: []string{"main"}}

	nameOne := "one.example_debian_dists_x_main_binary-amd64_Packages"
	nameTwo := "two.example_ubuntu-ports_dists_x_main_binary-amd64_Packages"

	t.Run("every version is kept and the highest is the candidate, whatever the file order", func(t *testing.T) {
		t.Parallel()

		// file order is the lexical order of names: nameOne is read first
		c := cacheFromFiles(t, map[string]string{
			nameOne: para("Package: p", "Version: 1.0", "Architecture: amd64", "Filename: old.deb", "Depends: oldlib"),
			nameTwo: para("Package: p", "Version: 2.0", "Architecture: amd64", "Filename: new.deb", "Depends: newlib"),
		}, one, two)

		got, _ := c.Lookup("p")
		assert.Equal(t, "2.0", got.Version)
		assert.Equal(t, "new.deb", got.Filename)
		assert.Equal(t, two.URL, got.BaseURL)
		assert.Equal(t, "newlib", deb.FormatRelations(got.Depends))

		versions := c.Versions("p")
		require.Len(t, versions, 2)
		assert.Equal(t, "1.0", versions[1].Version)
		assert.Equal(t, "old.deb", versions[1].Filename)
		assert.Equal(t, one.URL, versions[1].BaseURL)
		assert.Equal(t, "oldlib", deb.FormatRelations(versions[1].Depends))
		assert.Equal(t, 1, c.PackageCount(), "one name and architecture")

		c = cacheFromFiles(t, map[string]string{
			nameOne: para("Package: p", "Version: 3.0", "Architecture: amd64", "Filename: new.deb"),
			nameTwo: para("Package: p", "Version: 2.0", "Architecture: amd64", "Filename: old.deb"),
		}, one, two)

		got, _ = c.Lookup("p")
		assert.Equal(t, "3.0", got.Version)
		assert.Equal(t, one.URL, got.BaseURL)
		assert.Equal(t, []string{"3.0", "2.0"}, []string{c.Versions("p")[0].Version, c.Versions("p")[1].Version})
	})

	t.Run("a tie favours the later file", func(t *testing.T) {
		t.Parallel()

		c := cacheFromFiles(t, map[string]string{
			nameOne: para("Package: p", "Version: 1.0", "Architecture: amd64", "Filename: a.deb", "SHA256: "+sha256Hex([]byte("a")), "Size: 1"),
			nameTwo: para("Package: p", "Version: 1.0", "Architecture: amd64", "Filename: b.deb", "SHA256: "+sha256Hex([]byte("b")), "Size: 2"),
		}, one, two)

		got, _ := c.Lookup("p")
		assert.Equal(t, "b.deb", got.Filename)
		assert.Equal(t, sha256Hex([]byte("b")), got.SHA256)
		assert.EqualValues(t, 2, got.Size)
		assert.Equal(t, two.URL, got.BaseURL)
	})

	t.Run("the base URL is not taken for an all package", func(t *testing.T) {
		t.Parallel()

		c := cacheFromFiles(t, map[string]string{
			nameOne: para("Package: docs", "Version: 1.0", "Architecture: all", "Filename: docs1.deb"),
			nameTwo: para("Package: docs", "Version: 2.0", "Architecture: all", "Filename: docs2.deb"),
		}, one, two)

		got, _ := c.Lookup("docs")
		assert.Equal(t, "docs2.deb", got.Filename, "the candidate is the higher version")
		assert.Equal(t, two.URL, got.BaseURL)

		// the same all version in both repositories stays with the first one
		c = cacheFromFiles(t, map[string]string{
			nameOne: para("Package: docs", "Version: 1.0", "Architecture: all", "Filename: a.deb"),
			nameTwo: para("Package: docs", "Version: 1.0", "Architecture: all", "Filename: b.deb"),
		}, one, two)

		got, _ = c.Lookup("docs")
		assert.Equal(t, "b.deb", got.Filename, "artifacts follow the later file")
		assert.Equal(t, one.URL, got.BaseURL, "but the repository of an all package stays the first one")
	})

	t.Run("flags accumulate", func(t *testing.T) {
		t.Parallel()

		c := cacheFromFiles(t, map[string]string{
			nameOne: para("Package: p", "Version: 1", "Architecture: amd64", "Essential: yes", "Multi-Arch: foreign", "Provides: v"),
			nameTwo: para("Package: p", "Version: 1", "Architecture: amd64", "Provides: w"),
		}, one, two)

		got, _ := c.Lookup("p")
		assert.True(t, got.Essential)
		assert.Equal(t, "foreign", got.MultiArch)
		assert.True(t, got.HasCandidate)
		assert.Equal(t, "p", c.ResolveVirtual("v"))
		assert.Equal(t, "p", c.ResolveVirtual("w"))
	})

	t.Run("one file with the same package twice keeps both and prefers the higher version", func(t *testing.T) {
		t.Parallel()

		c := cacheFromText(t, para("Package: p", "Version: 1.0", "Architecture: amd64", "Filename: old.deb")+
			para("Package: p", "Version: 2.0", "Architecture: amd64", "Filename: new.deb"))

		got, _ := c.Lookup("p")
		assert.Equal(t, "new.deb", got.Filename)
		assert.Len(t, c.Versions("p"), 2)
	})
}

func TestMergeVersion(t *testing.T) {
	t.Parallel()

	t.Run("an index version takes the place of a status-only one", func(t *testing.T) {
		t.Parallel()

		existing := PackageInfo{Name: "p", Architecture: "amd64", Version: "1", Installed: true, Priority: "optional"}
		mergeVersion(&existing, &PackageInfo{
			Name: "p", Architecture: "amd64", Version: "1", MultiArch: "same", Essential: true, HasCandidate: true,
			Filename: "f.deb", BaseURL: "http://m/", SHA256: "aa", Size: 5, Priority: "required",
			Depends: deps(t, "d"), PreDepends: deps(t, "pd"), Conflicts: rels(t, "x"), Breaks: rels(t, "y"), Provides: rels(t, "v"),
		})

		assert.Equal(t, PackageInfo{
			Name: "p", Architecture: "amd64", Version: "1", MultiArch: "same", Essential: true, HasCandidate: true, Installed: true,
			Filename: "f.deb", BaseURL: "http://m/", SHA256: "aa", Size: 5, Priority: "required",
			Depends: deps(t, "d"), PreDepends: deps(t, "pd"), Conflicts: rels(t, "x"), Breaks: rels(t, "y"), Provides: rels(t, "v"),
		}, existing)
	})

	t.Run("a status stanza keeps what the index says", func(t *testing.T) {
		t.Parallel()

		existing := PackageInfo{
			Name: "p", Version: "1", HasCandidate: true, Filename: "f.deb", Depends: deps(t, "d"), Provides: rels(t, "v"),
		}
		mergeVersion(&existing, &PackageInfo{Name: "p", Version: "1", Installed: true, Depends: deps(t, "other"), Provides: rels(t, "v, w")})

		assert.True(t, existing.Installed)
		assert.Equal(t, "f.deb", existing.Filename)
		assert.Equal(t, "d", deb.FormatRelations(existing.Depends))
		assert.Equal(t, "v, w", deb.FormatRelations(altsOf(existing.Provides)))
	})

	t.Run("a status-only version takes the relations of a later status stanza", func(t *testing.T) {
		t.Parallel()

		existing := PackageInfo{Name: "p", Version: "1", Installed: true}
		mergeVersion(&existing, &PackageInfo{Name: "p", Version: "1", Installed: true, Depends: deps(t, "d"), Priority: "extra"})

		assert.Equal(t, "d", deb.FormatRelations(existing.Depends))
		assert.Equal(t, "extra", existing.Priority)
	})
}

func TestLoadIndexCompressions(t *testing.T) {
	t.Parallel()

	text := para("Package: p", "Version: 1", "Architecture: amd64", "Filename: p.deb")

	var ix deb.Index

	ix.AddText(text)

	xzData, err := ix.Compressed(deb.CompressionXZ)
	require.NoError(t, err)

	bz2Data, err := base64.StdEncoding.DecodeString("QlpoOTFBWSZTWR2JodMAAAZfgAAQQAAgECAAQQA67Z4QIAAxQAYjTTRoUaPUTDQ1MyaiTB4Q3B9UDuHMtroIvCSSr1jOX2G8LuSKcKEgOxNDpg==")
	require.NoError(t, err)

	tests := map[string]struct {
		file string
		data []byte
		pkg  string
	}{
		"plain": {"example.org_dists_x_main_binary-amd64_Packages", []byte(text), "p"},
		"gz":    {"example.org_dists_x_main_binary-amd64_Packages.gz", gzipBytes(t, []byte(text)), "p"},
		"xz":    {"example.org_dists_x_main_binary-amd64_Packages.xz", xzData, "p"},
		"bz2":   {"example.org_dists_x_main_binary-amd64_Packages.bz2", bz2Data, "bz"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, tt.file), tt.data, 0o644))

			c, err := Load(LoadOptions{ListsDir: dir, HostArch: hostArch})
			require.NoError(t, err)

			_, ok := c.Lookup(tt.pkg)
			assert.True(t, ok)
		})
	}
}

func TestLoadToleratesBrokenInput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "example.org_dists_x_main_binary-amd64_Packages"),
		para("Package: good", "Version: 1", "Architecture: amd64"))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "example.org_dists_x_contrib_binary-amd64_Packages.gz"), []byte("not gzip"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "example.org_dists_x_extra_binary-amd64_Packages.xz"), []byte("not xz"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "example.org_dists_x_misc_binary-amd64_Packages.lz4"), []byte("not lz4"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "example.org_dists_x_dir_binary-amd64_Packages"), 0o755))
	writeFile(t, filepath.Join(dir, "example.org_dists_x_main_i18n_Translation-en"), "Package: ignored\nVersion: 1\n\n")
	writeFile(t, filepath.Join(dir, "lock"), "")

	c, err := Load(LoadOptions{ListsDir: dir, HostArch: hostArch, StatusFile: filepath.Join(dir, "missing-status")})
	require.Error(t, err)
	require.NotNil(t, c)

	_, ok := c.Lookup("good")
	assert.True(t, ok, "what loads is kept")
	assert.Equal(t, 1, c.PackageCount())
	assert.ErrorContains(t, err, "contrib_binary-amd64_Packages.gz")
	assert.ErrorContains(t, err, "missing-status")
}

func TestLoadMissingDirectory(t *testing.T) {
	t.Parallel()

	c, err := Load(LoadOptions{ListsDir: filepath.Join(t.TempDir(), "absent")})
	require.Error(t, err)
	require.NotNil(t, c)
	assert.Zero(t, c.PackageCount())
	assert.Equal(t, runtimeArch(), c.HostArch())

	c, err = Load(LoadOptions{})
	require.NoError(t, err)
	assert.Zero(t, c.PackageCount())

	empty := t.TempDir()
	c, err = Load(LoadOptions{ListsDir: empty})
	require.NoError(t, err)
	assert.Zero(t, c.PackageCount())
}

func TestLoadStatusOnly(t *testing.T) {
	t.Parallel()

	status := filepath.Join(t.TempDir(), "status")
	writeFile(t, status, para("Package: bash", "Status: install ok installed", "Architecture: amd64", "Version: 5"))

	c, err := Load(LoadOptions{StatusFile: status, HostArch: hostArch})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"bash": true}, c.InstalledNames())
}

func TestLoadLogger(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, indexName("x", "main", "amd64")), para("Package: p", "Version: 1", "Architecture: amd64"))

	var buf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := Load(LoadOptions{ListsDir: dir, Logger: logger})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "index loaded")
}

func TestLoadManyIndexesDeterministic(t *testing.T) {
	t.Parallel()

	files := map[string]string{}

	for _, comp := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"} {
		files[indexName("x", comp, "amd64")] = para("Package: shared", "Version: 1", "Architecture: amd64", "Filename: "+comp+".deb")
	}

	for range 5 {
		c := cacheFromFiles(t, files)
		got, _ := c.Lookup("shared")
		assert.Equal(t, "l.deb", got.Filename, "a tie favours the last file by name")
	}
}

func TestListFileNameAndBaseURLRoundTrip(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "archive.ubuntu.com_ubuntu_dists_jammy_main_binary-amd64_Packages.xz",
		ListFileName("https://archive.ubuntu.com/ubuntu/", "jammy", "main/binary-amd64/Packages.xz"))
	assert.Equal(t, "ports.ubuntu.com_ubuntu-ports_dists_jammy-updates_universe_binary-arm64_Packages",
		ListFileName("https://ports.ubuntu.com/ubuntu-ports", "jammy-updates", "universe/binary-arm64/Packages"))
	assert.Equal(t, "deb.example.org_dists_stable_main_binary-amd64_Packages",
		ListFileName("http://deb.example.org", "stable", "main/binary-amd64/Packages"))
	assert.Equal(t, "127.0.0.1:8080_a_b_dists_s_c_binary-i386_Packages.gz",
		ListFileName("http://127.0.0.1:8080/a/b/", "s", "c/binary-i386/Packages.gz"))
	assert.Empty(t, ListFileName("http://[::1", "s", "x"))
	assert.Empty(t, ListFileName("%zz", "s", "x"))

	sources := []Source{
		{URL: "https://archive.ubuntu.com/ubuntu/", Suite: "jammy"},
		{URL: "https://ports.ubuntu.com/ubuntu-ports/", Suite: "jammy"},
		{URL: "http://deb.example.org/", Suite: "stable"},
		{URL: "http://127.0.0.1:8080/a/b/", Suite: "s"},
	}

	files := map[string]string{}

	for i, s := range sources {
		name := ListFileName(s.URL, s.Suite, "main/binary-amd64/Packages")
		files[name] = para(fmt.Sprintf("Package: from-%d", i), "Version: 1", "Architecture: amd64", "Filename: x.deb")
	}

	c := cacheFromFiles(t, files, sources...)

	for i, s := range sources {
		info, ok := c.Lookup(fmt.Sprintf("from-%d", i))
		require.True(t, ok, s.URL)
		assert.Equal(t, s.URL, info.BaseURL)
	}
}

func TestBaseURLs(t *testing.T) {
	t.Parallel()

	got := BaseURLs([]Source{
		{URL: "http://a.example/x/", Suite: "one"},
		{URL: "http://a.example/x/", Suite: "two"},
		{URL: "http://b.example/", Suite: "s"},
		{URL: "http://[::1"},
	})

	assert.Equal(t, map[string]string{"a.example_x": "http://a.example/x/", "b.example": "http://b.example/"}, got)
}

func TestDeriveBaseURL(t *testing.T) {
	t.Parallel()

	bases := map[string]string{"a.example_x": "http://a.example/x/"}

	assert.Equal(t, "http://a.example/x/", deriveBaseURL("a.example_x_dists_s_main_binary-amd64_Packages", bases))
	assert.Empty(t, deriveBaseURL("a.example_x_Packages", bases))
	assert.Empty(t, deriveBaseURL("other_dists_s_main_binary-amd64_Packages", bases))
	assert.Empty(t, deriveBaseURL("a.example_x_dists_s_main_binary-amd64_Packages", nil))
}
