package apt

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/httpclient"
)

// publishDeb serves content at filename and indexes it in c.
func publishDeb(c *Cache, repo *testRepo, name, arch, filename string, content []byte, depends ...string) {
	repo.put("/"+filename, content)
	c.AddEntry(&PackageInfo{
		Name: name, Architecture: arch, Version: "1", Filename: filename, HasCandidate: true,
		SHA256: sha256Hex(content), Size: int64(len(content)), BaseURL: repo.baseURL(), Depends: depends,
	})
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	return data
}

func TestDownload(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	c := NewCache("amd64")
	publishDeb(c, repo, "alpha", "amd64", "pool/main/a/alpha/alpha_1_amd64.deb", []byte("alpha payload"))
	publishDeb(c, repo, "beta", "amd64", "pool/main/b/beta/beta_1_amd64.deb", []byte("beta payload"))
	publishDeb(c, repo, "gamma", "arm64", "pool/main/g/gamma/gamma_1_arm64.deb", []byte("gamma payload"))

	dest := filepath.Join(t.TempDir(), "out", "debs")

	var (
		mu       sync.Mutex
		progress = map[string][2]int64{}
	)

	err := c.Download(context.Background(), dest, []string{"alpha", "beta", "gamma:arm64", "alpha (>= 1)"}, DownloadOptions{
		Client:      testClient(2),
		Concurrency: 2,
		Progress: func(name string, done, total int64) {
			mu.Lock()
			defer mu.Unlock()

			progress[name] = [2]int64{done, total}
		},
	})
	require.NoError(t, err)

	assert.Equal(t, []byte("alpha payload"), readFile(t, filepath.Join(dest, "alpha_1_amd64.deb")))
	assert.Equal(t, []byte("beta payload"), readFile(t, filepath.Join(dest, "beta_1_amd64.deb")))
	assert.Equal(t, []byte("gamma payload"), readFile(t, filepath.Join(dest, "gamma_1_arm64.deb")))
	assert.Equal(t, 1, repo.count("/pool/main/a/alpha/alpha_1_amd64.deb"), "the repeated name is downloaded once")

	entries, err := os.ReadDir(dest)
	require.NoError(t, err)
	assert.Len(t, entries, 3, "no temporary file is left")

	assert.Equal(t, [2]int64{int64(len("alpha payload")), int64(len("alpha payload"))}, progress["alpha_1_amd64.deb"])
	assert.Len(t, progress, 3)
}

func TestDownloadNothing(t *testing.T) {
	t.Parallel()

	dest := filepath.Join(t.TempDir(), "never")

	require.NoError(t, NewCache("amd64").Download(context.Background(), dest, nil, DownloadOptions{}))

	_, err := os.Stat(dest)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestDownloadDefaultClientAndConcurrency(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	c := NewCache("amd64")
	publishDeb(c, repo, "alpha", "amd64", "pool/alpha_1_amd64.deb", []byte("payload"))

	dest := t.TempDir()
	require.NoError(t, c.Download(context.Background(), dest, []string{"alpha"}, DownloadOptions{}))
	assert.Equal(t, []byte("payload"), readFile(t, filepath.Join(dest, "alpha_1_amd64.deb")))
}

func TestDownloadIntegrityFailures(t *testing.T) {
	t.Parallel()

	good := []byte("the genuine payload")

	tests := map[string][]byte{
		"same size, other content": []byte("the GENUINE payload"),
		"shorter":                  good[:5],
		"longer":                   append(append([]byte{}, good...), "!"...),
		"empty":                    {},
	}

	for name, served := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			repo := newTestRepo(t)
			c := NewCache("amd64")
			publishDeb(c, repo, "alpha", "amd64", "pool/alpha_1_amd64.deb", good)
			repo.put("/pool/alpha_1_amd64.deb", served)

			dest := t.TempDir()

			err := c.Download(context.Background(), dest, []string{"alpha"}, DownloadOptions{Client: testClient(1)})
			require.ErrorIs(t, err, ErrIntegrity)

			entries, readErr := os.ReadDir(dest)
			require.NoError(t, readErr)
			assert.Empty(t, entries, "neither the file nor a partial one is left")
		})
	}
}

func TestDownloadRejectsUnsafeEntriesBeforeAnyRequest(t *testing.T) {
	t.Parallel()

	content := []byte("payload")
	goodSum := sha256Hex(content)

	tests := []struct {
		name string
		info PackageInfo
		want error
	}{
		{"parent traversal", PackageInfo{Filename: "../x.deb", SHA256: goodSum, Size: 7}, ErrInvalidIndexEntry},
		{"embedded traversal", PackageInfo{Filename: "pool/../../x.deb", SHA256: goodSum, Size: 7}, ErrInvalidIndexEntry},
		{"query", PackageInfo{Filename: "a?b.deb", SHA256: goodSum, Size: 7}, ErrInvalidIndexEntry},
		{"fragment", PackageInfo{Filename: "a#b.deb", SHA256: goodSum, Size: 7}, ErrInvalidIndexEntry},
		{"absolute", PackageInfo{Filename: "/etc/x.deb", SHA256: goodSum, Size: 7}, ErrInvalidIndexEntry},
		{"whitespace", PackageInfo{Filename: "a b.deb", SHA256: goodSum, Size: 7}, ErrInvalidIndexEntry},
		{"control character", PackageInfo{Filename: "a\x01b.deb", SHA256: goodSum, Size: 7}, ErrInvalidIndexEntry},
		{"newline", PackageInfo{Filename: "a\nb.deb", SHA256: goodSum, Size: 7}, ErrInvalidIndexEntry},
		{"delete character", PackageInfo{Filename: "a\x7fb.deb", SHA256: goodSum, Size: 7}, ErrInvalidIndexEntry},
		{"no SHA256", PackageInfo{Filename: "x.deb", Size: 7}, ErrInvalidIndexEntry},
		{"odd length SHA256", PackageInfo{Filename: "x.deb", SHA256: goodSum[:63], Size: 7}, ErrInvalidIndexEntry},
		{"short SHA256", PackageInfo{Filename: "x.deb", SHA256: goodSum[:32], Size: 7}, ErrInvalidIndexEntry},
		{"non-hex SHA256", PackageInfo{Filename: "x.deb", SHA256: "zz" + goodSum[2:], Size: 7}, ErrInvalidIndexEntry},
		{"zero size", PackageInfo{Filename: "x.deb", SHA256: goodSum}, ErrInvalidIndexEntry},
		{"negative size", PackageInfo{Filename: "x.deb", SHA256: goodSum, Size: -1}, ErrInvalidIndexEntry},
		{"size over the cap", PackageInfo{Filename: "x.deb", SHA256: goodSum, Size: MaxDebBytes + 1}, ErrInvalidIndexEntry},
		{"no Filename", PackageInfo{SHA256: goodSum, Size: 7}, ErrPackageNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			repo := newTestRepo(t)
			repo.put("/x.deb", content)

			info := tt.info
			info.Name, info.Architecture, info.BaseURL = "victim", "amd64", repo.baseURL()

			c := NewCache("amd64")
			c.AddEntry(&info)
			publishDeb(c, repo, "fine", "amd64", "pool/fine_1_amd64.deb", content)

			dest := filepath.Join(t.TempDir(), "dest")

			err := c.Download(context.Background(), dest, []string{"fine", "victim"}, DownloadOptions{Client: testClient(1)})
			require.ErrorIs(t, err, tt.want)
			assert.Zero(t, repo.total(), "nothing was requested, not even the valid package")

			_, statErr := os.Stat(dest)
			assert.ErrorIs(t, statErr, os.ErrNotExist, "the destination is not created")
		})
	}
}

func TestDownloadSizeAtTheCapIsAccepted(t *testing.T) {
	t.Parallel()

	j := &debJob{name: "p", info: PackageInfo{SHA256: sha256Hex([]byte("x")), Size: MaxDebBytes}}
	_, err := validateDebIntegrity(j)
	require.NoError(t, err)

	j.info.Size = 1
	_, err = validateDebIntegrity(j)
	require.NoError(t, err)
}

func TestDownloadUnknownAndUnreachable(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	c := NewCache("amd64")
	publishDeb(c, repo, "alpha", "amd64", "pool/alpha_1_amd64.deb", []byte("x"))
	c.AddEntry(&PackageInfo{
		Name: "nobase", Architecture: "amd64", Filename: "pool/nobase.deb", SHA256: sha256Hex([]byte("x")), Size: 1,
	})
	c.AddEntry(&PackageInfo{Name: "virtual", Architecture: "amd64", BaseURL: repo.baseURL()})

	err := c.Download(context.Background(), t.TempDir(), []string{"alpha", "ghost"}, DownloadOptions{})
	require.ErrorIs(t, err, ErrPackageNotFound)
	assert.ErrorContains(t, err, "ghost")

	err = c.Download(context.Background(), t.TempDir(), []string{"virtual"}, DownloadOptions{})
	require.ErrorIs(t, err, ErrPackageNotFound, "an entry without a file is not downloadable")

	err = c.Download(context.Background(), t.TempDir(), []string{"alpha", "nobase"}, DownloadOptions{})
	require.ErrorIs(t, err, ErrNoBaseURL)
	assert.ErrorContains(t, err, "nobase")
	assert.Zero(t, repo.total())
}

func TestDownloadHTTPErrors(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	c := NewCache("amd64")
	publishDeb(c, repo, "alpha", "amd64", "pool/alpha_1_amd64.deb", []byte("x"))
	repo.remove("/pool/alpha_1_amd64.deb")

	err := c.Download(context.Background(), t.TempDir(), []string{"alpha"}, DownloadOptions{Client: testClient(2)})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrIntegrity)
	assert.ErrorContains(t, err, "alpha_1_amd64.deb")

	var statusErr *httpclient.HTTPStatusError

	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, 404, statusErr.Code)
	assert.Equal(t, 1, repo.count("/pool/alpha_1_amd64.deb"), "a 404 is not retried")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	repo.put("/pool/alpha_1_amd64.deb", []byte("x"))

	err = c.Download(ctx, t.TempDir(), []string{"alpha"}, DownloadOptions{Client: testClient(1)})
	require.Error(t, err)

	blocker := filepath.Join(t.TempDir(), "file")
	writeFile(t, blocker, "x")

	err = c.Download(context.Background(), filepath.Join(blocker, "sub"), []string{"alpha"}, DownloadOptions{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "create download directory")
}

func TestDownloadDeduplicatesByBaseName(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	c := NewCache("amd64")
	// Two entries that would write one destination file.
	publishDeb(c, repo, "one", "amd64", "pool/main/shared_1_amd64.deb", []byte("same bytes"))
	publishDeb(c, repo, "two", "amd64", "pool/main/shared_1_amd64.deb", []byte("same bytes"))

	dest := t.TempDir()
	require.NoError(t, c.Download(context.Background(), dest, []string{"one", "two", "one:amd64"}, DownloadOptions{}))
	assert.Equal(t, 1, repo.count("/pool/main/shared_1_amd64.deb"))
	assert.Equal(t, []byte("same bytes"), readFile(t, filepath.Join(dest, "shared_1_amd64.deb")))
}

func TestDownloadBaseURLWithoutTrailingSlash(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	c := NewCache("amd64")
	publishDeb(c, repo, "alpha", "amd64", "pool/alpha_1_amd64.deb", []byte("x"))

	info, _ := c.Lookup("alpha")
	info.BaseURL = repo.URL
	c.AddEntry(&info)

	require.NoError(t, c.Download(context.Background(), t.TempDir(), []string{"alpha"}, DownloadOptions{}))
}

func TestDownloadClosure(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	c := NewCache("amd64")
	publishDeb(c, repo, "app", "amd64", "pool/app_1_amd64.deb", []byte("app"), "lib", "virt", "missing")
	publishDeb(c, repo, "lib", "amd64", "pool/lib_1_amd64.deb", []byte("lib"), "deep")
	publishDeb(c, repo, "deep", "amd64", "pool/deep_1_amd64.deb", []byte("deep"))
	publishDeb(c, repo, "provider", "amd64", "pool/provider_1_amd64.deb", []byte("provider"))
	c.providers["virt"] = []string{"provider"}

	dest := t.TempDir()

	resolved, unresolved, err := c.DownloadClosure(context.Background(), dest, []string{"app"}, DownloadOptions{Client: testClient(1)})
	require.NoError(t, err)
	assert.Equal(t, []string{"deep:amd64", "lib:amd64", "provider:amd64", "app:amd64"}, names(resolved))
	assert.Equal(t, []string{"missing"}, unresolved)

	for _, f := range []string{"app", "lib", "deep", "provider"} {
		assert.Equal(t, []byte(f), readFile(t, filepath.Join(dest, f+"_1_amd64.deb")), f)
	}
}

func TestDownloadClosureEdgeCases(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	c := NewCache("amd64")
	publishDeb(c, repo, "app", "amd64", "pool/app_1_amd64.deb", []byte("app"))

	info, _ := c.Lookup("app")
	info.Installed = true
	c.AddEntry(&info)

	dest := filepath.Join(t.TempDir(), "never")

	resolved, unresolved, err := c.DownloadClosure(context.Background(), dest, []string{"app", "ghost"}, DownloadOptions{})
	require.NoError(t, err)
	assert.Empty(t, resolved, "everything installed: nothing to fetch")
	assert.Equal(t, []string{"ghost"}, unresolved)

	_, statErr := os.Stat(dest)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	assert.Zero(t, repo.total())

	// A resolution failure.
	deep := cacheFromText(t, chain(maxResolveDepth+2))

	resolved, unresolved, err = deep.DownloadClosure(context.Background(), dest, []string{"p0"}, DownloadOptions{})
	require.ErrorIs(t, err, ErrDependencyDepth)
	assert.Nil(t, resolved)
	assert.Nil(t, unresolved)

	// A download failure still reports what was resolved.
	repo.remove("/pool/app_1_amd64.deb")
	info.Installed = false
	c.AddEntry(&info)

	resolved, unresolved, err = c.DownloadClosure(context.Background(), t.TempDir(), []string{"app"}, DownloadOptions{Client: testClient(1)})
	require.Error(t, err)
	assert.Len(t, resolved, 1)
	assert.Empty(t, unresolved)
}

func TestDownloadHTTPSFallback(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	target, err := url.Parse(repo.URL)
	require.NoError(t, err)

	rt := &httpFailingTransport{target: target}

	c := NewCache("amd64")
	publishDeb(c, repo, "alpha", "amd64", "pool/alpha_1_amd64.deb", []byte("alpha"))
	publishDeb(c, repo, "beta", "amd64", "pool/beta_1_amd64.deb", []byte("beta"))

	// Both are served by a mirror whose plain-http port is dead.
	for _, name := range []string{"alpha", "beta"} {
		info, _ := c.Lookup(name)
		info.BaseURL = "http://mirror.example/"
		c.AddEntry(&info)
	}

	dest := t.TempDir()
	client := httpclient.New(httpclient.Options{Transport: rt, Retry: httpclient.RetryPolicy{Attempts: 2, BaseDelay: -1}})

	require.NoError(t, c.Download(context.Background(), dest, []string{"alpha", "beta"}, DownloadOptions{Client: client}))
	assert.Equal(t, []byte("alpha"), readFile(t, filepath.Join(dest, "alpha_1_amd64.deb")))
	assert.Equal(t, []byte("beta"), readFile(t, filepath.Join(dest, "beta_1_amd64.deb")))
	assert.Positive(t, rt.httpHits.Load())

	// With the fallback failing too, the error is reported.
	bad := &httpFailingTransport{target: &url.URL{Host: "127.0.0.1:1"}}
	client = httpclient.New(httpclient.Options{Transport: bad, Retry: httpclient.RetryPolicy{Attempts: 1, BaseDelay: -1}})

	err = c.Download(context.Background(), t.TempDir(), []string{"alpha"}, DownloadOptions{Client: client})
	require.Error(t, err)

	// A https mirror is not retried over https again; an integrity failure over
	// the fallback is still an integrity failure.
	repo.put("/pool/alpha_1_amd64.deb", []byte("ALPHA"))

	err = c.Download(context.Background(), t.TempDir(), []string{"alpha"}, DownloadOptions{Client: httpclient.New(httpclient.Options{
		Transport: rt, Retry: httpclient.RetryPolicy{Attempts: 1, BaseDelay: -1},
	})})
	require.ErrorIs(t, err, ErrIntegrity)
}

func TestSafeFilename(t *testing.T) {
	t.Parallel()

	for _, ok := range []string{"pool/main/a/a_1_amd64.deb", "x.deb", "pool/main/libf/libfoo/libfoo_1%7e2_amd64.deb", "a+b_1.deb"} {
		assert.True(t, safeFilename(ok), ok)
	}

	for _, bad := range []string{"", "..", "../x", "a/../b", "/x", "a?b", "a#b", "a b", "a\tb", "a\x00b", "a\\..\\b"} {
		assert.False(t, safeFilename(bad), "%q", bad)
	}
}
