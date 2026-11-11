package apt

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
)

// e2eRepo publishes generations of a signed repository with everything a
// client fetches: Packages in three compressions, English translations with
// their i18n/Index, Contents, a Packages.diff, by-hash copies and a signed
// Release, to a directory.
type e2eRepo struct {
	t       *testing.T
	dir     string
	signer  *gpg.LocalSigner
	keyPath string
	pdiffs  *deb.PDiffMemFS
	builder *deb.PDiffIndexBuilder
	prev    []byte
	step    int

	// Bytes of the indexes of the last publication, uncompressed.
	packages, translation, contents []byte
}

func newE2ERepo(t *testing.T) *e2eRepo {
	t.Helper()

	signer := newSigner(t)
	fsys := deb.NewPDiffMemFS()

	builder, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{})
	require.NoError(t, err)

	return &e2eRepo{
		t: t, dir: t.TempDir(), signer: signer, keyPath: writeKeyring(t, t.TempDir(), signer),
		pdiffs: fsys, builder: builder,
	}
}

func (r *e2eRepo) distDir() string { return filepath.Join(r.dir, "dists", "e2e") }

// write stores a file below the distribution directory and, when listed,
// records it in the Release.
func (r *e2eRepo) write(rel *deb.Release, name string, data []byte, listed bool) {
	r.t.Helper()

	dest := filepath.Join(r.distDir(), filepath.FromSlash(name))
	require.NoError(r.t, os.MkdirAll(filepath.Dir(dest), 0o755))
	require.NoError(r.t, os.WriteFile(dest, data, 0o644))

	if listed {
		rel.AddFile(deb.HashBytes(name, data))
	}
}

// publish writes the next generation: 60 packages plus one per step.
func (r *e2eRepo) publish() {
	t := r.t
	t.Helper()

	r.step++

	var (
		text  strings.Builder
		trans = deb.NewTranslationBuilder("en")
		cont  deb.ContentsBuilder
	)

	for i := range 59 + r.step {
		name := fmt.Sprintf("pkg%03d", i)
		desc := fmt.Sprintf("tool number %d\n a longer description of %s\n .\n with a second paragraph", i, name)
		sum := sha256Hex([]byte(name))

		text.WriteString(para(
			"Package: "+name, "Version: 1.0-1", "Architecture: amd64", "Maintainer: Test <t@example.org>",
			"Filename: pool/main/"+name+"_1.0-1_amd64.deb", "Size: 1234", "SHA256: "+sum,
			"Description-md5: "+deb.DescriptionMD5(desc),
		))

		require.NoError(t, trans.Add(deb.TranslationEntry{Package: name, DescriptionMD5: deb.DescriptionMD5(desc), Description: desc}))
		require.NoError(t, cont.Add("misc/"+name, "usr/bin/"+name, "usr/share/doc/"+name+"/copyright"))
	}

	var ix deb.Index

	ix.AddText(text.String())

	r.packages = ix.Bytes()
	r.translation = trans.Bytes()
	r.contents = cont.Bytes()

	rel := &deb.Release{
		Origin: "e2e", Label: "e2e", Suite: "e2e", Codename: "e2e",
		Date:          time.Now().UTC().Add(-time.Minute).Truncate(time.Second),
		Architectures: []string{"amd64"}, Components: []string{"main"},
		AcquireByHash: true,
	}

	for _, c := range []deb.Compression{deb.CompressionNone, deb.CompressionGzip, deb.CompressionXZ} {
		data, err := ix.Compressed(c)
		if c == deb.CompressionNone {
			data, err = ix.Bytes(), nil
		}

		require.NoError(t, err)
		r.write(rel, "main/binary-amd64/Packages"+c.Extension(), data, true)
	}

	i18n := &deb.I18nIndex{}

	for _, c := range []deb.Compression{deb.CompressionNone, deb.CompressionGzip, deb.CompressionXZ} {
		data, err := trans.Compressed(c)
		if c == deb.CompressionNone {
			data, err = trans.Bytes(), nil
		}

		require.NoError(t, err)

		name := "main/i18n/" + deb.TranslationFileName("en", c.Extension())
		r.write(rel, name, data, true)
		i18n.AddFile(deb.HashBytes(strings.TrimPrefix(name, "main/i18n/"), data))
	}

	r.write(rel, deb.I18nIndexName("main"), i18n.Marshal(), true)

	gz, err := cont.Compressed(deb.CompressionGzip)
	require.NoError(t, err)

	r.write(rel, "main/"+deb.ContentsFileName("amd64", false, ".gz"), gz, true)
	r.write(rel, "main/"+deb.ContentsFileName("amd64", false, ""), cont.Bytes(), true)

	if r.prev != nil {
		upd, err := r.builder.UpdateFrom(r.prev, r.packages, time.Date(2026, 6, 1, r.step, 0, 0, 0, time.UTC))
		require.NoError(t, err)

		for _, name := range upd.Written {
			data, err := r.pdiffs.ReadFile(name)
			require.NoError(t, err)

			r.write(rel, "main/binary-amd64/"+name, data, name == "Packages.diff/Index")
		}

		for _, name := range upd.Removed {
			_ = os.Remove(filepath.Join(r.distDir(), "main", "binary-amd64", filepath.FromSlash(name)))
		}
	}

	r.prev = r.packages

	_, err = deb.WriteByHash(r.distDir(), rel, deb.ByHashOptions{})
	require.NoError(t, err)

	signed, err := deb.SignRelease(r.signer, rel.Marshal())
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(r.distDir(), "Release"), signed.Release, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(r.distDir(), "Release.gpg"), signed.ReleaseGPG, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(r.distDir(), "InRelease"), signed.InRelease, 0o644))
}

// accessLog serves a directory and records the request paths.
type accessLog struct {
	*httptest.Server

	mu    sync.Mutex
	paths []string
}

func serveLogged(t *testing.T, dir string) *accessLog {
	t.Helper()

	l := &accessLog{}
	files := http.FileServer(http.Dir(dir))
	l.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		l.mu.Lock()
		l.paths = append(l.paths, req.URL.Path)
		l.mu.Unlock()
		files.ServeHTTP(w, req)
	}))
	t.Cleanup(l.Close)

	return l
}

// reset returns the paths asked for since the last call.
func (l *accessLog) reset() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := l.paths
	l.paths = nil

	return out
}

func anyContains(paths []string, sub string) bool {
	return slices.ContainsFunc(paths, func(p string) bool { return strings.Contains(p, sub) })
}

func countContains(paths []string, sub string) int {
	n := 0

	for _, p := range paths {
		if strings.Contains(p, sub) {
			n++
		}
	}

	return n
}

// TestUpdateEndToEnd updates from a served, signed repository in two
// generations: the first fetches everything by hash, the second patches the
// Packages index and fetches the changed translations and Contents by hash.
func TestUpdateEndToEnd(t *testing.T) {
	t.Parallel()

	repo := newE2ERepo(t)
	repo.publish()

	srv := serveLogged(t, repo.dir)
	lists := t.TempDir()

	src := Source{
		URL: srv.URL + "/", Suite: "e2e", Components: []string{"main"}, SignedBy: repo.keyPath,
		Languages: []string{"en"}, Targets: []string{"Packages", "Translations", "Contents"},
	}
	opts := UpdateOptions{ListsDir: lists, DefaultArch: "amd64", Client: testClient(1)}

	list := func(rel string) string { return filepath.Join(lists, ListFileName(src.URL, "e2e", rel)) }

	n, err := Update(context.Background(), []Source{src}, opts)
	require.NoError(t, err)
	assert.Equal(t, 3, n, "packages, translation and contents")

	first := srv.reset()
	assert.Equal(t, 3, countContains(first, "/by-hash/"), "each index is fetched by hash: %v", first)
	assert.False(t, anyContains(first, "/Packages.diff/"))

	repo.publish()

	n, err = Update(context.Background(), []Source{src}, opts)
	require.NoError(t, err)
	assert.Equal(t, 3, n)

	second := srv.reset()
	assert.True(t, anyContains(second, "/Packages.diff/by-hash/"), "the patch index is read by hash: %v", second)
	assert.Equal(t, 1, countContains(second, "/Packages.diff/2026"), "one patch is fetched: %v", second)
	assert.False(t, anyContains(second, "/binary-amd64/Packages.xz"), "the index is not fetched whole: %v", second)
	assert.False(t, anyContains(second, "by-hash/SHA512/"+deb.HashBytes("", repo.packages).SHA512))

	assert.Equal(t, string(repo.packages), readFileString(t, list("main/binary-amd64/Packages")))

	c, err := Load(LoadOptions{ListsDir: lists, HostArch: "amd64", Sources: []Source{src}})
	require.NoError(t, err)
	assert.Equal(t, 61, c.PackageCount())

	info, ok := c.Lookup("pkg060")
	require.True(t, ok, "a package added by the patch")
	assert.Equal(t, "e2e", info.Releases[0].Origin)
}

var e2eListLine = regexp.MustCompile(`(?m)^LIST-SHA256 (\w+) ([0-9a-f]{64})$`)

// TestUpdateAptE2E runs the same repository against the real apt-get in a
// Debian container: apt has to accept the signed InRelease, use by-hash, apply
// the pdiff and end up with the files published. It needs PKGFORMAT_E2E=1,
// podman and a local Debian image with apt (PKGFORMAT_E2E_IMAGE, default
// localhost/debtools:bookworm); the repository is served on the loopback only.
func TestUpdateAptE2E(t *testing.T) {
	if os.Getenv("PKGFORMAT_E2E") != "1" {
		t.Skip("set PKGFORMAT_E2E=1 to run the container test")
	}

	podman, err := exec.LookPath("podman")
	if err != nil {
		t.Skip("podman not found")
	}

	image := os.Getenv("PKGFORMAT_E2E_IMAGE")
	if image == "" {
		image = "localhost/debtools:bookworm"
	}

	script, err := filepath.Abs(filepath.Join("testdata", "e2e-update", "apt-update.sh"))
	require.NoError(t, err)

	repo := newE2ERepo(t)
	repo.publish()

	srv := serveLogged(t, repo.dir)
	lists := t.TempDir()
	work := t.TempDir()

	key, err := os.ReadFile(repo.keyPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(work, "key.asc"), key, 0o644))

	scriptData, err := os.ReadFile(script)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(work, "apt-update.sh"), scriptData, 0o755))

	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]

	aptUpdate := func() map[string]string {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		out, err := exec.CommandContext(ctx, podman, "run", "--rm", "--network=host",
			"-v", lists+":/var/lib/apt/lists:Z", "-v", work+":/w:Z,ro", image, "sh", "/w/apt-update.sh", port).CombinedOutput()
		require.NoError(t, err, string(out))

		got := map[string]string{}
		for _, m := range e2eListLine.FindAllStringSubmatch(string(out), -1) {
			got[m[1]] = m[2]
		}

		return got
	}

	check := func(got map[string]string) {
		assert.Equal(t, deb.HashBytes("", repo.packages).SHA256, got["packages"], "Packages")
		assert.Equal(t, deb.HashBytes("", repo.translation).SHA256, got["translation"], "Translation-en")
		assert.Equal(t, deb.HashBytes("", repo.contents).SHA256, got["contents"], "Contents")
	}

	check(aptUpdate())

	first := srv.reset()
	assert.True(t, anyContains(first, "/by-hash/"), "apt fetched by hash: %v", first)
	assert.False(t, anyContains(first, "/Packages.diff/"))

	repo.publish()
	check(aptUpdate())

	second := srv.reset()
	assert.True(t, anyContains(second, "/Packages.diff/by-hash/"), "apt read the patch index by hash: %v", second)
	assert.Equal(t, 1, countContains(second, "/Packages.diff/2026"), "apt fetched one patch: %v", second)
	assert.False(t, anyContains(second, "/binary-amd64/Packages.xz"), "apt did not fetch the index whole: %v", second)

	// Our client, over the same served repository, ends up with the same files.
	src := Source{
		URL: srv.URL + "/", Suite: "e2e", Components: []string{"main"}, SignedBy: repo.keyPath,
		Languages: []string{"en"}, Targets: []string{"Packages", "Translations", "Contents"},
	}
	ours := t.TempDir()

	_, err = Update(context.Background(), []Source{src}, UpdateOptions{ListsDir: ours, DefaultArch: "amd64", Client: testClient(1)})
	require.NoError(t, err)

	read := func(rel string) []byte {
		for _, ext := range []string{"", ".xz", ".gz"} {
			data, err := os.ReadFile(filepath.Join(ours, ListFileName(src.URL, "e2e", rel+ext)))
			if err == nil {
				return decompressForTest(t, data, ext)
			}

			require.ErrorIs(t, err, fs.ErrNotExist)
		}

		t.Fatalf("no list file for %s", rel)

		return nil
	}

	assert.Equal(t, repo.packages, read("main/binary-amd64/Packages"))
	assert.Equal(t, repo.translation, read("main/i18n/Translation-en"))
	assert.Equal(t, repo.contents, read("main/Contents-amd64"))
}

func decompressForTest(t *testing.T, data []byte, ext string) []byte {
	t.Helper()

	if ext == "" {
		return data
	}

	r, err := deb.OpenIndex(bytes.NewReader(data), "x"+ext)
	require.NoError(t, err)

	defer func() { _ = r.Close() }()

	out, err := io.ReadAll(r)
	require.NoError(t, err)

	return out
}
