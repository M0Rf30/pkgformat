package apt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSourcesList(t *testing.T) {
	t.Parallel()

	content := strings.Join([]string{
		"# the main archive",
		"",
		"deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/k.gpg] https://a.example/ubuntu jammy main universe",
		"deb-src http://a.example/ubuntu jammy main",
		"deb file:///srv/repo jammy main",
		"deb cdrom:[Debian 12] bookworm main",
		"deb ftp://a.example/debian bookworm main",
		"deb http://b.example/debian bookworm",
		"deb [arch=amd64 http://c.example/ stable main",
		"deb [trusted=yes] http://d.example/ stable main contrib",
		"   deb   http://e.example/debian/    stable   main   ",
		"deb [ arch=i386 ] http://f.example/ stable main",
		"debian http://g.example/ stable main",
		"deb http://h.example/\tstable main",
		"deb\thttp://i.example/ stable main",
		"deb http://j.example/ stable main\r",
	}, "\n")

	assert.Equal(t, []Source{
		{
			URL: "https://a.example/ubuntu/", Suite: "jammy", Components: []string{"main", "universe"},
			Architectures: []string{"amd64", "arm64"}, SignedBy: "/usr/share/keyrings/k.gpg",
		},
		{URL: "http://d.example/", Suite: "stable", Components: []string{"main", "contrib"}},
		{URL: "http://e.example/debian/", Suite: "stable", Components: []string{"main"}},
		{URL: "http://f.example/", Suite: "stable", Components: []string{"main"}, Architectures: []string{"i386"}},
		{URL: "http://h.example/", Suite: "stable", Components: []string{"main"}},
		{URL: "http://j.example/", Suite: "stable", Components: []string{"main"}},
	}, ParseSourcesList(content))

	assert.Empty(t, ParseSourcesList(""))
}

func TestParseLegacyOptions(t *testing.T) {
	t.Parallel()

	archs, signedBy, rest := parseLegacyOptions("[arch=amd64 signed-by=/k] http://x/ s m")
	assert.Equal(t, []string{"amd64"}, archs)
	assert.Equal(t, "/k", signedBy)
	assert.Equal(t, "http://x/ s m", rest)

	archs, signedBy, rest = parseLegacyOptions("http://x/ s m")
	assert.Nil(t, archs)
	assert.Empty(t, signedBy)
	assert.Equal(t, "http://x/ s m", rest)

	_, _, rest = parseLegacyOptions("[arch=amd64 http://x/ s m")
	assert.Equal(t, "[arch=amd64 http://x/ s m", rest, "an unterminated block is left alone")
}

func TestParseSources822(t *testing.T) {
	t.Parallel()

	content := `Types: deb deb-src
URIs: https://a.example/debian https://b.example/debian/
Suites: bookworm bookworm-updates
Components: main contrib
Architectures: amd64 arm64
Signed-By: /usr/share/keyrings/debian.gpg

Types: deb-src
URIs: https://src.example/
Suites: stable
Components: main

Types: deb
URIs: https://off.example/
Suites: stable
Components: main
Enabled: no

Types: deb
URIs: https://off2.example/
Suites: stable
Components: main
Enabled: False

Types: deb
URIs: https://on.example/
Suites: stable
Components: main
Enabled: yes

Types: deb
URIs: file:///srv/repo ftp://f.example/ http://ok.example
Suites: stable
Components: main

Types: deb
URIs: https://nocomp.example/
Suites: stable

Types: deb
Suites: stable
Components: main

Types: deb
URIs: https://nosuite.example/
Components: main

URIs: https://notypes.example/
Suites: stable
Components: main
`

	got := ParseSources822(content)

	archs := []string{"amd64", "arm64"}
	comps := []string{"main", "contrib"}
	key := "/usr/share/keyrings/debian.gpg"

	assert.Equal(t, []Source{
		{URL: "https://a.example/debian/", Suite: "bookworm", Components: comps, Architectures: archs, SignedBy: key},
		{URL: "https://a.example/debian/", Suite: "bookworm-updates", Components: comps, Architectures: archs, SignedBy: key},
		{URL: "https://b.example/debian/", Suite: "bookworm", Components: comps, Architectures: archs, SignedBy: key},
		{URL: "https://b.example/debian/", Suite: "bookworm-updates", Components: comps, Architectures: archs, SignedBy: key},
		{URL: "https://on.example/", Suite: "stable", Components: []string{"main"}, Architectures: []string{}},
		{URL: "http://ok.example/", Suite: "stable", Components: []string{"main"}, Architectures: []string{}},
	}, got)

	assert.Empty(t, ParseSources822(""))
}

func TestLoadSources(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	listFile := filepath.Join(dir, "sources.list")
	listDir := filepath.Join(dir, "sources.list.d")

	writeFile(t, listFile, "deb http://main.example/ stable main\n")
	writeFile(t, filepath.Join(listDir, "b.sources"), "Types: deb\nURIs: http://b.example/\nSuites: s\nComponents: c\n")
	writeFile(t, filepath.Join(listDir, "a.list"), "deb http://a.example/ s c\n")
	writeFile(t, filepath.Join(listDir, "z.txt"), "deb http://ignored.example/ s c\n")
	require.NoError(t, os.Mkdir(filepath.Join(listDir, "dir.list"), 0o755))

	got, err := LoadSources(listFile, listDir)
	require.NoError(t, err)

	urls := make([]string, len(got))
	for i, s := range got {
		urls[i] = s.URL
	}

	assert.Equal(t, []string{"http://main.example/", "http://a.example/", "http://b.example/"}, urls,
		"the file first, then the directory in name order")
}

func TestLoadSourcesTolerance(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	got, err := LoadSources("", "")
	require.NoError(t, err)
	assert.Empty(t, got)

	got, err = LoadSources(filepath.Join(dir, "absent.list"), filepath.Join(dir, "absent.d"))
	require.NoError(t, err, "missing files and directories are fine")
	assert.Empty(t, got)

	// a file where the directory should be
	notDir := filepath.Join(dir, "file")
	writeFile(t, notDir, "x")

	_, err = LoadSources("", notDir)
	require.Error(t, err)
}

func TestLoadSourcesOversizedAndUnreadable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	listDir := filepath.Join(dir, "d")

	writeFile(t, filepath.Join(listDir, "a.list"), "deb http://a.example/ s c\n")
	writeFile(t, filepath.Join(listDir, "big.list"), "# "+strings.Repeat("x", MaxSourcesFileBytes)+"\ndeb http://big.example/ s c\n")

	got, err := LoadSources("", listDir)
	require.ErrorIs(t, err, ErrTooLarge)
	assert.ErrorContains(t, err, "big.list")
	require.Len(t, got, 1)
	assert.Equal(t, "http://a.example/", got[0].URL, "the readable sources still load")

	// A file exactly at the limit is accepted.
	exact := filepath.Join(dir, "exact.list")
	line := "deb http://exact.example/ s c\n"
	writeFile(t, exact, line+strings.Repeat("#", MaxSourcesFileBytes-len(line)))

	got, err = LoadSources(exact, "")
	require.NoError(t, err)
	require.Len(t, got, 1)

	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked.list")
		writeFile(t, locked, "deb http://locked.example/ s c\n")
		require.NoError(t, os.Chmod(locked, 0o000))

		t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })

		got, err = LoadSources(locked, "")
		require.Error(t, err)
		assert.Empty(t, got)
	}
}

func FuzzParseSourcesList(f *testing.F) {
	for _, seed := range []string{
		"",
		"deb http://a.example/ stable main\n",
		"deb [arch=amd64,arm64 signed-by=/k.gpg] https://a.example/ubuntu jammy main universe\ndeb-src http://x/ y z\n",
		"deb [arch=amd64 http://broken/ s m\n",
		"deb [] http://x/ s m",
		"deb [arch= signed-by=] http://x/ s m",
		"# comment\n\n   deb\thttp://x/ s m\r\n",
		"deb http://\x00/ s m",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		for _, s := range ParseSourcesList(content) {
			if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
				t.Fatalf("non-http URL %q accepted", s.URL)
			}

			if !strings.HasSuffix(s.URL, "/") {
				t.Fatalf("URL %q has no trailing slash", s.URL)
			}

			if s.Suite == "" || len(s.Components) == 0 {
				t.Fatalf("source without suite or components: %+v", s)
			}
		}
	})
}

func FuzzParseSources822(f *testing.F) {
	for _, seed := range []string{
		"",
		"Types: deb\nURIs: https://a.example/debian\nSuites: bookworm\nComponents: main\n",
		"Types: deb deb-src\nURIs: http://a/ http://b/\nSuites: s t\nComponents: c d\nArchitectures: amd64\nSigned-By: /k\n\nTypes: deb\nURIs: http://c/\nSuites: s\nComponents: c\nEnabled: no\n",
		"Types: deb\nURIs: http://a/\n  http://b/\nSuites: s\nComponents: c\n",
		"Types:deb\nURIs:\nSuites:\n\n\n\nComponents: c",
		"# comment\nTypes: deb\n",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		for _, s := range ParseSources822(content) {
			if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
				t.Fatalf("non-http URL %q accepted", s.URL)
			}

			if s.Suite == "" || len(s.Components) == 0 {
				t.Fatalf("source without suite or components: %+v", s)
			}
		}
	})
}

func FuzzListFileName(f *testing.F) {
	for _, seed := range [][3]string{
		{"https://archive.ubuntu.com/ubuntu/", "jammy", "main/binary-amd64/Packages.xz"},
		{"http://127.0.0.1:8080/a/b/", "s", "c/binary-i386/Packages"},
		{"http://[::1", "s", "x"},
		{"%zz", "", ""},
		{"", "", ""},
		{"http://h/%2F%2e%2e/", "../s", "a//b"},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}

	f.Fuzz(func(t *testing.T, baseURL, suite, rel string) {
		name := ListFileName(baseURL, suite, rel)
		if name == "" {
			return
		}

		if !strings.Contains(name, "_dists_") {
			t.Fatalf("%q lacks the dists separator", name)
		}

		if !strings.Contains(suite, "/") && strings.Contains(name, "/") {
			t.Fatalf("%q still holds a path separator", name)
		}

		// The result must not depend on how many times it is derived.
		if again := ListFileName(baseURL, suite, rel); again != name {
			t.Fatalf("unstable result %q vs %q", again, name)
		}

		_ = BaseURLs([]Source{{URL: baseURL}})
	})
}
