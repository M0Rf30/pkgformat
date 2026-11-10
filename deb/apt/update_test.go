package apt

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/M0Rf30/pkgformat/httpclient"
)

// standardFixture is a repository with a main component holding two packages.
func standardFixture(t *testing.T) *fixture {
	t.Helper()

	f := newFixture(t)
	f.addPackage("main", "alpha", "1.0", "Depends: beta")
	f.addPackage("main", "beta", "2.0")
	f.publish()

	return f
}

func TestUpdateOptionsValidation(t *testing.T) {
	t.Parallel()

	_, err := Update(context.Background(), []Source{{URL: "http://x/"}}, UpdateOptions{})
	require.ErrorIs(t, err, ErrNoListsDir)

	_, err = Update(context.Background(), nil, UpdateOptions{ListsDir: t.TempDir()})
	require.ErrorIs(t, err, ErrNoSources)

	blocker := filepath.Join(t.TempDir(), "file")
	writeFile(t, blocker, "x")

	_, err = Update(context.Background(), []Source{{URL: "http://x/"}}, UpdateOptions{ListsDir: filepath.Join(blocker, "lists")})
	require.Error(t, err)
	assert.ErrorContains(t, err, "create lists directory")
}

func TestUpdateIndexVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		formats []deb.Compression
		ext     string
	}{
		{"xz", []deb.Compression{deb.CompressionXZ}, ".xz"},
		{"gzip", []deb.Compression{deb.CompressionGzip}, ".gz"},
		{"plain", []deb.Compression{deb.CompressionNone}, ""},
		{"all, the best one is used", []deb.Compression{deb.CompressionNone, deb.CompressionGzip, deb.CompressionXZ}, ".xz"},
		{"gzip and plain, gzip is used", []deb.Compression{deb.CompressionNone, deb.CompressionGzip}, ".gz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			f.addPackage("main", "alpha", "1.0", "Depends: beta")
			f.addPackage("main", "beta", "2.0")
			f.formats = tt.formats
			f.publish()

			n, err := Update(context.Background(), []Source{f.source()}, f.opts())
			require.NoError(t, err)
			assert.Equal(t, 1, n)

			entries, err := os.ReadDir(f.lists)
			require.NoError(t, err)
			require.Len(t, entries, 1, "only the chosen variant is stored")
			assert.Equal(t, filepath.Base(f.listPath("main", tt.ext)), entries[0].Name())

			c, err := f.load()
			require.NoError(t, err)

			alpha, ok := c.Lookup("alpha")
			require.True(t, ok)
			assert.Equal(t, f.repo.baseURL(), alpha.BaseURL)
			assert.Equal(t, "beta", deb.FormatRelations(alpha.Depends))

			order, unresolved, err := c.ResolveDeps([]string{"alpha"})
			require.NoError(t, err)
			assert.Empty(t, unresolved)
			assert.Equal(t, []string{"beta:amd64", "alpha:amd64"}, names(order))
		})
	}
}

func TestUpdateWarmCache(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)

	n, err := Update(context.Background(), []Source{f.source()}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 1, f.repo.count(f.distPath(f.indexRel("main", ".xz"))))

	n, err = Update(context.Background(), []Source{f.source()}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "an index already in place counts")
	assert.Equal(t, 1, f.repo.count(f.distPath(f.indexRel("main", ".xz"))), "and is not downloaded again")
	assert.Equal(t, 2, f.repo.count(f.distPath("InRelease")), "the Release is always refreshed")

	// A changed index is fetched again.
	f.addPackage("main", "gamma", "3.0")
	f.publish()

	n, err = Update(context.Background(), []Source{f.source()}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 2, f.repo.count(f.distPath(f.indexRel("main", ".xz"))))

	c, err := f.load()
	require.NoError(t, err)

	_, ok := c.Lookup("gamma")
	assert.True(t, ok)
}

func TestUpdateSurvivesCorruptLocalIndex(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)
	writeFile(t, f.listPath("main", ".xz"), "stale or truncated")

	n, err := Update(context.Background(), []Source{f.source()}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	c, err := f.load()
	require.NoError(t, err)
	assert.Equal(t, 2, c.PackageCount())
}

func TestUpdateDigestMismatch(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)
	path := f.distPath(f.indexRel("main", ".xz"))

	f.repo.mu.Lock()
	good := f.repo.files[path]
	f.repo.mu.Unlock()

	tests := map[string][]byte{
		"same size, other content": append([]byte{^good[0]}, good[1:]...),
		"truncated":                good[:len(good)-1],
		"longer":                   append(append([]byte{}, good...), "tail"...),
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			f.repo.put(path, body)

			n, err := Update(context.Background(), []Source{f.source()}, f.opts())
			require.ErrorIs(t, err, ErrIntegrity)
			assert.Zero(t, n)

			_, statErr := os.Stat(f.listPath("main", ".xz"))
			assert.ErrorIs(t, statErr, os.ErrNotExist, "no unverified index is left")

			_, statErr = os.Stat(f.listPath("main", ".xz") + ".part")
			assert.ErrorIs(t, statErr, os.ErrNotExist)
		})
	}

	// A mismatch is definitive: the other variants are not tried.
	assert.Zero(t, f.repo.count(f.distPath(f.indexRel("main", ".gz"))))
}

func TestUpdateReleaseSizeLies(t *testing.T) {
	t.Parallel()

	for name, delta := range map[string]int64{"larger than the file": 10, "smaller than the file": -1} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			f.addPackage("main", "alpha", "1.0")
			f.formats = []deb.Compression{deb.CompressionNone}
			f.mutate = func(r *deb.Release) {
				fi := r.Files[f.indexRel("main", "")]
				fi.Size += delta
				r.Files[fi.Path] = fi
			}
			f.publish()

			n, err := Update(context.Background(), []Source{f.source()}, f.opts())
			require.ErrorIs(t, err, ErrIntegrity)
			assert.Zero(t, n)

			_, statErr := os.Stat(f.listPath("main", ""))
			assert.ErrorIs(t, statErr, os.ErrNotExist)
		})
	}
}

func TestUpdateTransportFailureFallsThroughVariants(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)
	f.repo.remove(f.distPath(f.indexRel("main", ".xz")))

	n, err := Update(context.Background(), []Source{f.source()}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	_, statErr := os.Stat(f.listPath("main", ".gz"))
	require.NoError(t, statErr, "the gzip variant took over")

	// With every variant gone the transport error surfaces.
	require.NoError(t, os.RemoveAll(f.lists))
	f.repo.remove(f.distPath(f.indexRel("main", ".gz")))
	f.repo.remove(f.distPath(f.indexRel("main", "")))

	n, err = Update(context.Background(), []Source{f.source()}, f.opts())
	require.Error(t, err)
	assert.Zero(t, n)

	var statusErr *httpclient.HTTPStatusError

	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, http.StatusNotFound, statusErr.Code)
	assert.False(t, IsVerificationError(err))
}

func TestUpdateUnlistedComponentIsSkipped(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)

	src := f.source()
	src.Components = []string{"main", "contrib", "non-free"}

	n, err := Update(context.Background(), []Source{src}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "only the listed component counts")

	only := f.source()
	only.Components = []string{"contrib"}

	n, err = Update(context.Background(), []Source{only}, f.opts())
	require.NoError(t, err)
	assert.Zero(t, n)

	// An architecture the Release does not list is skipped the same way.
	arm := f.source()
	arm.Architectures = []string{"arm64"}

	n, err = Update(context.Background(), []Source{arm}, f.opts())
	require.NoError(t, err)
	assert.Zero(t, n)
}

func TestUpdateWeakDigestOnlyIsNotUsable(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.addPackage("main", "alpha", "1.0")
	f.mutate = func(r *deb.Release) {
		for p, fi := range r.Files {
			fi.SHA256, fi.SHA512 = "", ""
			r.Files[p] = fi
		}
	}
	f.publish()

	n, err := Update(context.Background(), []Source{f.source()}, f.opts())
	require.NoError(t, err, "an index that cannot be verified counts as not listed")
	assert.Zero(t, n)
	assert.Zero(t, f.repo.count(f.distPath(f.indexRel("main", ".xz"))))
}

func TestUpdateInvalidReleaseEntries(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate func(fi *deb.FileInfo)
		want   error
	}{
		// the Release parser already refuses malformed digests
		"malformed digest": {func(fi *deb.FileInfo) { fi.SHA256 = "not-hex" }, deb.ErrInvalidRelease},
		"short digest":     {func(fi *deb.FileInfo) { fi.SHA256 = "abcd" }, deb.ErrInvalidRelease},
		"oversized":        {func(fi *deb.FileInfo) { fi.Size = httpclient.DefaultMaxBytes + 1 }, ErrInvalidIndexEntry},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			f.addPackage("main", "alpha", "1.0")
			f.formats = []deb.Compression{deb.CompressionNone}
			f.mutate = func(r *deb.Release) {
				fi := r.Files[f.indexRel("main", "")]
				tt.mutate(&fi)
				r.Files[fi.Path] = fi
			}
			f.publish()

			n, err := Update(context.Background(), []Source{f.source()}, f.opts())
			require.ErrorIs(t, err, tt.want)
			assert.Zero(t, n)
			assert.Zero(t, f.repo.count(f.distPath(f.indexRel("main", ""))), "refused before any download")
		})
	}
}

func TestUpdateDuplicateSourcesShareOneRelease(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.addPackage("main", "alpha", "1.0")
	f.addPackage("universe", "beta", "1.0")
	f.publish()

	main := f.source()
	main.Components = []string{"main"}

	universe := f.source()
	universe.Components = []string{"universe"}

	n, err := Update(context.Background(), []Source{main, universe, main, universe}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, 1, f.repo.count(f.distPath("InRelease")), "one Release fetch for the (url, suite) pair")
	assert.Equal(t, 1, f.repo.count(f.distPath(f.indexRel("main", ".xz"))), "and one download per index")
	assert.Equal(t, 1, f.repo.count(f.distPath(f.indexRel("universe", ".xz"))))
}

func TestUpdateDuplicateSourcesWritingOnePath(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)

	src := f.source()
	sources := make([]Source, 16)

	for i := range sources {
		sources[i] = src
	}

	opts := f.opts()
	opts.Concurrency = 16

	n, err := Update(context.Background(), sources, opts)
	require.NoError(t, err)
	assert.Equal(t, 16, n)
	assert.Equal(t, 1, f.repo.count(f.distPath(f.indexRel("main", ".xz"))))

	c, err := f.load()
	require.NoError(t, err)
	assert.Equal(t, 2, c.PackageCount())
}

func TestUpdateMultiArchitectureShareOneRelease(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.addPackage("main", "alpha", "1.0")

	// A second architecture of the same component.
	var ix deb.Index

	ix.AddText(para("Package: alpha", "Version: 1.0", "Architecture: arm64"))

	armRel := "main/binary-arm64/Packages"
	f.mutate = func(r *deb.Release) {
		r.Architectures = []string{"amd64", "arm64"}
		r.AddFile(deb.HashBytes(armRel, ix.Bytes()))
	}
	f.publish()
	f.repo.put(f.distPath(armRel), ix.Bytes())

	src := f.source()
	src.Architectures = []string{"amd64", "arm64"}

	n, err := Update(context.Background(), []Source{src}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, 1, f.repo.count(f.distPath("InRelease")))

	c, err := Load(LoadOptions{ListsDir: f.lists, HostArch: "amd64"})
	require.NoError(t, err)

	_, ok := c.Lookup("alpha:arm64")
	assert.True(t, ok)
}

func TestUpdateLegacyDetachedRelease(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)
	f.sign = signDetached
	f.publish()

	n, err := Update(context.Background(), []Source{f.source()}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 1, f.repo.count(f.distPath("InRelease")), "InRelease was tried first")
	assert.Equal(t, 1, f.repo.count(f.distPath("Release.gpg")))
}

func TestUpdateUnsignedRelease(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)
	f.sign = signNone
	f.publish()

	n, err := Update(context.Background(), []Source{f.source()}, f.opts())
	require.Error(t, err)
	assert.Zero(t, n)
	assert.Positive(t, f.repo.count(f.distPath("Release.gpg")), "the signature was looked for")

	opts := f.opts()
	opts.AllowUnverified = true

	n, err = Update(context.Background(), []Source{f.source()}, opts)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestUpdateBadSignatureIsAlwaysFatal(t *testing.T) {
	t.Parallel()

	t.Run("InRelease", func(t *testing.T) {
		t.Parallel()

		f := standardFixture(t)

		path := f.distPath("InRelease")

		f.repo.mu.Lock()
		doc := string(f.repo.files[path])
		f.repo.mu.Unlock()

		tampered := strings.Replace(doc, "Suite: stable", "Suite: evil", 1)
		require.NotEqual(t, doc, tampered)
		f.repo.put(path, []byte(tampered))

		for _, allow := range []bool{false, true} {
			opts := f.opts()
			opts.AllowUnverified = allow

			n, err := Update(context.Background(), []Source{f.source()}, opts)
			require.ErrorIs(t, err, gpg.ErrBadSignature, "allow=%v", allow)
			assert.Zero(t, n)
			assert.False(t, IsVerificationError(err), "a bad signature is not downgradable")
		}
	})

	t.Run("Release.gpg", func(t *testing.T) {
		t.Parallel()

		f := standardFixture(t)
		f.sign = signDetached
		f.publish()

		path := f.distPath("Release")

		f.repo.mu.Lock()
		doc := string(f.repo.files[path])
		f.repo.mu.Unlock()

		f.repo.put(path, []byte(strings.Replace(doc, "Suite: stable", "Suite: evil", 1)))

		opts := f.opts()
		opts.AllowUnverified = true

		_, err := Update(context.Background(), []Source{f.source()}, opts)
		require.ErrorIs(t, err, gpg.ErrBadSignature)
	})
}

func TestUpdateUnknownSigner(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{signInRelease, signDetached} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			f := standardFixture(t)
			f.sign = mode
			f.publish()

			other := f.source()
			other.SignedBy = writeKeyring(t, t.TempDir(), newSigner(t))

			n, err := Update(context.Background(), []Source{other}, f.opts())
			require.ErrorIs(t, err, deb.ErrUnknownSigner)
			assert.True(t, IsVerificationError(err))
			assert.Zero(t, n)

			opts := f.opts()
			opts.AllowUnverified = true

			n, err = Update(context.Background(), []Source{other}, opts)
			require.NoError(t, err)
			assert.Equal(t, 1, n)
		})
	}
}

func TestUpdateWithoutTrustAnchor(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)

	src := f.source()
	src.SignedBy = ""

	n, err := Update(context.Background(), []Source{src}, f.opts())
	require.ErrorIs(t, err, deb.ErrNoTrustAnchor)
	assert.True(t, IsVerificationError(err))
	assert.Zero(t, n)

	missing := f.source()
	missing.SignedBy = filepath.Join(t.TempDir(), "absent.gpg")

	_, err = Update(context.Background(), []Source{missing}, f.opts())
	require.ErrorIs(t, err, deb.ErrNoTrustAnchor)

	opts := f.opts()
	opts.AllowUnverified = true

	n, err = Update(context.Background(), []Source{src}, opts)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestUpdateDefaultKeyrings(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)

	keyDir := t.TempDir()
	writeKeyring(t, keyDir, newSigner(t))
	writeKeyring(t, keyDir, f.signer)

	src := f.source()
	src.SignedBy = ""

	opts := f.opts()
	opts.DefaultKeyrings = []string{filepath.Join(keyDir, "absent"), keyDir}

	n, err := Update(context.Background(), []Source{src}, opts)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestUpdateVerificationErrorNextToSuccess(t *testing.T) {
	t.Parallel()

	good := standardFixture(t)

	bad := standardFixture(t)
	badSrc := bad.source()
	badSrc.SignedBy = writeKeyring(t, t.TempDir(), newSigner(t))

	opts := good.opts()

	n, err := Update(context.Background(), []Source{good.source(), badSrc}, opts)
	require.Error(t, err)
	assert.Equal(t, 1, n, "the verified source still counts")
	assert.True(t, IsVerificationError(err), "only trust failures: it may be downgraded to a warning")

	dead := good.source()
	dead.Suite = "nonexistent"

	n, err = Update(context.Background(), []Source{good.source(), badSrc, dead}, opts)
	require.Error(t, err)
	assert.Equal(t, 1, n)
	assert.False(t, IsVerificationError(err), "a network error next to a trust one is not downgraded")
}

func TestUpdateReleaseExpiry(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.addPackage("main", "alpha", "1.0")

	validUntil := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	f.mutate = func(r *deb.Release) { r.ValidUntil = validUntil }
	f.publish()

	opts := f.opts()
	opts.Now = func() time.Time { return validUntil.Add(-time.Hour) }

	n, err := Update(context.Background(), []Source{f.source()}, opts)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	require.NoError(t, os.RemoveAll(f.lists))

	opts.Now = func() time.Time { return validUntil.Add(time.Hour) }

	n, err = Update(context.Background(), []Source{f.source()}, opts)
	require.ErrorIs(t, err, deb.ErrReleaseExpired)
	assert.Zero(t, n)
	assert.False(t, IsVerificationError(err))
}

func TestUpdateReleaseFetchFailures(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)

	gone := f.source()
	gone.Suite = "gone"

	n, err := Update(context.Background(), []Source{gone}, f.opts())
	require.Error(t, err)
	assert.Zero(t, n)

	// InRelease absent, Release present but Release.gpg absent.
	f.sign = signNone
	f.publish()

	_, err = Update(context.Background(), []Source{f.source()}, f.opts())
	require.Error(t, err)

	// A document that is no Release.
	f.repo.put(f.distPath("Release"), []byte("Suite: stable\nSHA256:\n zz 10 main/binary-amd64/Packages\n"))

	opts := f.opts()
	opts.AllowUnverified = true

	_, err = Update(context.Background(), []Source{f.source()}, opts)
	require.ErrorIs(t, err, deb.ErrInvalidRelease)
}

func TestUpdateDefaultsAndLogger(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.arch = runtimeArch()
	f.addPackage("main", "alpha", "1.0")
	f.publish()

	opts := UpdateOptions{ListsDir: f.lists, Logger: discardLogger()} // default arch, client, concurrency, clock

	n, err := Update(context.Background(), []Source{f.source()}, opts)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	// The failure path logs warnings.
	bad := f.source()
	bad.Suite = "none"

	_, err = Update(context.Background(), []Source{bad}, opts)
	require.Error(t, err)
}

func TestUpdateContextCancelled(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	n, err := Update(ctx, []Source{f.source()}, f.opts())
	require.Error(t, err)
	assert.Zero(t, n)
	assert.ErrorIs(t, err, context.Canceled)
}

// httpFailingTransport fails every plain-http request with a transient
// transport error and serves https requests from a plain test server.
type httpFailingTransport struct {
	target   *url.URL
	httpHits atomic.Int64
}

func (rt *httpFailingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" {
		rt.httpHits.Add(1)

		return nil, errors.New("connection reset by peer")
	}

	out := req.Clone(req.Context())
	out.URL.Scheme = "http"
	out.URL.Host = rt.target.Host
	out.Host = rt.target.Host

	return http.DefaultTransport.RoundTrip(out)
}

func TestUpdateHTTPSFallback(t *testing.T) {
	t.Parallel()

	f := standardFixture(t)

	target, err := url.Parse(f.repo.URL)
	require.NoError(t, err)

	rt := &httpFailingTransport{target: target}

	src := f.source()
	src.URL = "http://mirror.example/debian/"

	opts := f.opts()
	opts.Client = httpclient.New(httpclient.Options{
		Transport: rt,
		Retry:     httpclient.RetryPolicy{Attempts: 2, BaseDelay: -1},
	})

	// The repository paths live under /dists/..., the mirror prefix is /debian.
	for _, p := range []string{"InRelease"} {
		f.repo.mu.Lock()
		data := f.repo.files[f.distPath(p)]
		f.repo.mu.Unlock()

		f.repo.put("/debian"+f.distPath(p), data)
	}

	for _, ext := range []string{".xz", ".gz", ""} {
		f.repo.mu.Lock()
		data := f.repo.files[f.distPath(f.indexRel("main", ext))]
		f.repo.mu.Unlock()

		f.repo.put("/debian"+f.distPath(f.indexRel("main", ext)), data)
	}

	opts.Logger = discardLogger()

	n, err := Update(context.Background(), []Source{src}, opts)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Positive(t, rt.httpHits.Load(), "plain http was tried first")

	_, statErr := os.Stat(filepath.Join(f.lists, ListFileName(src.URL, src.Suite, f.indexRel("main", ".xz"))))
	require.NoError(t, statErr)

	// When https fails too, the first error is reported with the fallback's.
	dead := &httpFailingTransport{target: &url.URL{Host: "127.0.0.1:1"}}
	opts.Client = httpclient.New(httpclient.Options{
		Transport: dead,
		Retry:     httpclient.RetryPolicy{Attempts: 1, BaseDelay: -1},
	})

	require.NoError(t, os.RemoveAll(f.lists))

	_, err = Update(context.Background(), []Source{src}, opts)
	require.Error(t, err)
	assert.ErrorContains(t, err, "https fallback also failed")

	// A https source has nothing to fall back to.
	httpsSrc := src
	httpsSrc.URL = "https://mirror.example/debian/"

	_, err = Update(context.Background(), []Source{httpsSrc}, opts)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "https fallback")
}

func TestFileMatches(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	data := []byte("content")
	writeFile(t, path, string(data))

	assert.True(t, fileMatches(path, int64(len(data)), sha256Hex(data)))
	assert.True(t, fileMatches(path, int64(len(data)), strings.ToUpper(sha256Hex(data))))
	assert.False(t, fileMatches(path, int64(len(data))+1, sha256Hex(data)))
	assert.False(t, fileMatches(path, int64(len(data)), sha256Hex([]byte("other!!"))))
	assert.False(t, fileMatches(filepath.Join(dir, "absent"), 1, "aa"))
	assert.False(t, fileMatches(dir, 0, "aa"), "a directory is no index")

	if os.Geteuid() != 0 {
		require.NoError(t, os.Chmod(path, 0o000))

		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

		assert.False(t, fileMatches(path, int64(len(data)), sha256Hex(data)))
	}
}

func TestDistURL(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "http://h/debian/dists/stable/InRelease", distURL(&Source{URL: "http://h/debian/", Suite: "stable"}, "InRelease"))
	assert.Equal(t, "http://h/dists/s/main/binary-amd64/Packages.xz",
		distURL(&Source{URL: "http://h", Suite: "s"}, "main/binary-amd64/Packages.xz"))
}
