package apt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/download"
	"github.com/M0Rf30/pkgformat/httpclient"
)

// UpdateOptions configures Update. Only ListsDir is required.
type UpdateOptions struct {
	// ListsDir is the directory the Packages indexes are written to, under the
	// names apt gives them. Update creates it. A Cache reads it back through
	// LoadOptions.ListsDir.
	ListsDir string
	// DefaultArch is the architecture of sources that name none. Empty selects
	// the one of the running program.
	DefaultArch string
	// DefaultKeyrings are the keyring files and directories that trust sources
	// without a Signed-By option (/etc/apt/trusted.gpg.d, /usr/share/keyrings,
	// /etc/apt/keyrings, /etc/apt/trusted.gpg on a Debian host). See LoadKeyring.
	DefaultKeyrings []string
	// AllowUnverified accepts a repository for which no trust anchor exists, a
	// Release signed by an unknown key, or one without a signature. A signature
	// that is present and does not verify is rejected regardless.
	AllowUnverified bool
	// Client performs the transfers. Nil builds one with the default policy.
	Client *httpclient.Client
	// Concurrency caps the (source, architecture) pairs updated at once. Zero
	// selects min(2*GOMAXPROCS, 8).
	Concurrency int
	// Now is the clock the Valid-Until check of a Release uses. Nil is
	// time.Now.
	Now func() time.Time
	// Logger receives progress and warnings. Nil is silent.
	Logger *slog.Logger
}

// maxIndexBytes caps one Packages index download, compressed.
const maxIndexBytes = httpclient.DefaultMaxBytes

// Update fetches the binary Packages index of every component and
// architecture of every source, verifies the Release signature and every
// index's size and SHA-256 against it, and writes the indexes to
// opts.ListsDir.
//
// Sources whose Release does not list an index for a component and
// architecture are skipped silently, as apt does. It returns how many
// (source, component, architecture) indexes are now in place, whether fetched
// or already current, and an *UpdateError holding everything that failed: a
// partial failure still reports the successes. Use IsVerificationError to tell
// trust failures from network ones.
func Update(ctx context.Context, sources []Source, opts UpdateOptions) (int, error) {
	if opts.ListsDir == "" {
		return 0, ErrNoListsDir
	}

	if len(sources) == 0 {
		return 0, ErrNoSources
	}

	if err := os.MkdirAll(opts.ListsDir, 0o755); err != nil { //nolint:gosec // apt lists are world readable
		return 0, fmt.Errorf("apt: create lists directory: %w", err)
	}

	u := newUpdater(opts)

	type job struct {
		src  *Source
		arch string
	}

	// Every (source, arch) pair is independent, so they all run concurrently;
	// the shared transport caps per-host parallelism.
	var jobs []job

	for i := range sources {
		src := &sources[i]

		archs := src.Architectures
		if len(archs) == 0 {
			archs = []string{u.defaultArch}
		}

		for _, arch := range archs {
			jobs = append(jobs, job{src: src, arch: arch})
		}
	}

	type result struct {
		n   int
		err error
	}

	// Results are stored by job index so the joined error is deterministic.
	results := make([]result, len(jobs))
	jobCh := make(chan int, len(jobs))

	for i := range jobs {
		jobCh <- i
	}

	close(jobCh)

	var wg sync.WaitGroup

	for range min(u.concurrency, len(jobs)) {
		wg.Go(func() {
			for idx := range jobCh {
				n, err := u.updateSource(ctx, jobs[idx].src, jobs[idx].arch)
				results[idx] = result{n: n, err: err}
			}
		})
	}

	wg.Wait()

	var (
		total int
		errs  []error
	)

	for i, res := range results {
		total += res.n

		if res.err != nil {
			u.warn("apt: source update failed", "url", jobs[i].src.URL, "suite", jobs[i].src.Suite,
				"arch", jobs[i].arch, "error", res.err)

			errs = append(errs, res.err)
		}
	}

	return total, newUpdateError(errs)
}

// updater is the state of one Update call.
type updater struct {
	opts        UpdateOptions
	client      *httpclient.Client
	defaultArch string
	concurrency int
	now         func() time.Time
	releases    releaseCache
	locks       sync.Map // destination path -> *sync.Mutex
}

func newUpdater(opts UpdateOptions) *updater {
	u := &updater{
		opts:        opts,
		client:      opts.Client,
		defaultArch: opts.DefaultArch,
		concurrency: opts.Concurrency,
		now:         opts.Now,
	}

	if u.client == nil {
		u.client = httpclient.New(httpclient.Options{Logger: opts.Logger})
	}

	if u.defaultArch == "" {
		u.defaultArch = ArchFromGoarch(runtime.GOARCH)
	}

	if u.concurrency <= 0 {
		u.concurrency = min(runtime.GOMAXPROCS(0)*2, 8)
	}

	if u.now == nil {
		u.now = time.Now
	}

	return u
}

func (u *updater) warn(msg string, args ...any) {
	if u.opts.Logger != nil {
		u.opts.Logger.Warn(msg, args...)
	}
}

// lockPath serialises work per destination file: duplicate deb lines for one
// (url, suite, component, arch) would otherwise fetch and write one list file
// concurrently.
func (u *updater) lockPath(dest string) (unlock func()) {
	m, _ := u.locks.LoadOrStore(dest, &sync.Mutex{})

	mu := m.(*sync.Mutex) //nolint:forcetypeassert // only *sync.Mutex is ever stored

	mu.Lock()

	return mu.Unlock
}

// updateSource fetches the Release of a source and the indexes of its
// components for one architecture.
//
// The Release is verified against the trust anchor declared by Signed-By, or
// the default keyrings when unset; a signature that exists and fails to verify
// is fatal whatever AllowUnverified says.
func (u *updater) updateSource(ctx context.Context, src *Source, arch string) (int, error) {
	rel, err := u.releases.fetch(src, u.opts.AllowUnverified, func() (*deb.Release, error) {
		return u.fetchRelease(ctx, src)
	})
	if err != nil {
		return 0, err
	}

	// Components fan out too: they hit one mirror, whose connection limit is
	// what bounds parallelism. Results are stored by component index.
	compErrs := make([]error, len(src.Components))

	var wg sync.WaitGroup

	for i, comp := range src.Components {
		wg.Go(func() {
			compErrs[i] = u.fetchComponentIndex(ctx, src, comp, arch, rel)
		})
	}

	wg.Wait()

	n := 0

	var failures []error

	for i, err := range compErrs {
		if err == nil {
			n++

			continue
		}

		// A component the Release does not list is nothing to fetch; every
		// other failure (network, size or digest mismatch, disk) surfaces.
		if !errors.Is(err, ErrNoPackagesIndex) {
			u.warn("apt: component update failed", "url", src.URL, "component", src.Components[i],
				"arch", arch, "error", err)

			failures = append(failures, err)
		}
	}

	return n, newUpdateError(failures)
}

// distURL is the URL of a file under the dists/<suite> directory of a source.
func distURL(src *Source, rel string) string {
	return strings.TrimRight(src.URL, "/") + "/dists/" + src.Suite + "/" + rel
}

// fetchBytes downloads a small document, retrying once over https when a plain
// http fetch fails transiently. Some networks (egress proxies, sandboxed CI)
// reset port 80 and leave 443 alone, and mirrors serve the same content on both.
func (u *updater) fetchBytes(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	var data []byte

	err := u.withHTTPSFallback(rawURL, func(target string) error {
		var err error

		data, err = u.client.FetchBytes(ctx, target, maxBytes)

		return err
	})

	return data, err
}

// withHTTPSFallback runs fn on rawURL and, if that fails with a transient error
// and the URL is plain http, once more on its https equivalent.
func (u *updater) withHTTPSFallback(rawURL string, fn func(target string) error) error {
	err := fn(rawURL)
	if err == nil || !httpclient.IsRetryable(err) {
		return err
	}

	httpsURL, ok := httpclient.UpgradeToHTTPS(rawURL)
	if !ok {
		return err
	}

	u.warn("apt: retrying over https", "url", rawURL, "error", err)

	if httpsErr := fn(httpsURL); httpsErr != nil {
		return fmt.Errorf("%w (https fallback also failed: %v)", err, httpsErr) //nolint:errorlint // one wrapped cause
	}

	return nil
}

// fetchRelease fetches and verifies the Release of a source: InRelease first,
// then Release with Release.gpg, which many third-party repositories still use.
func (u *updater) fetchRelease(ctx context.Context, src *Source) (*deb.Release, error) {
	kr, krErr := LoadKeyring(src.SignedBy, u.opts.DefaultKeyrings)
	trust := deb.Trust{
		Keyring:         kr,
		KeyringErr:      krErr,
		AllowUnverified: u.opts.AllowUnverified,
		Logger:          u.opts.Logger,
		Source:          src.URL,
	}

	var body []byte

	if data, err := u.fetchBytes(ctx, distURL(src, "InRelease"), deb.MaxReleaseBytes); err == nil {
		body, err = trust.VerifyInRelease(data)
		if err != nil {
			return nil, err
		}
	} else {
		plain, err := u.fetchBytes(ctx, distURL(src, "Release"), deb.MaxReleaseBytes)
		if err != nil {
			return nil, err
		}

		sig, sigErr := u.fetchBytes(ctx, distURL(src, "Release.gpg"), deb.MaxReleaseBytes)

		body, err = trust.VerifyReleaseGPG(plain, sig, sigErr)
		if err != nil {
			return nil, err
		}
	}

	rel, err := deb.ParseRelease(body)
	if err != nil {
		return nil, err
	}

	if err := rel.CheckValidity(u.now()); err != nil {
		return nil, fmt.Errorf("apt: %s %s: %w", src.URL, src.Suite, err)
	}

	return rel, nil
}

// releaseCache deduplicates Release fetches within one Update. Stock
// sources.list files split one (url, suite) over several deb lines (Ubuntu
// ships main+restricted, universe and multiverse separately), and multi
// architecture sources fan out one job per architecture; without this every
// job would download and verify the same InRelease again. Failures are cached
// too, so a dead mirror fails each duplicate without a retry storm.
type releaseCache struct {
	mu sync.Mutex
	m  map[string]*releaseCacheEntry
}

type releaseCacheEntry struct {
	once sync.Once
	rel  *deb.Release
	err  error
}

// fetch returns the Release for the source, running load at most once per key
// even under concurrent callers.
func (c *releaseCache) fetch(src *Source, allowUnverified bool, load func() (*deb.Release, error)) (*deb.Release, error) {
	key := src.URL + "\x00" + src.Suite + "\x00" + src.SignedBy
	if allowUnverified {
		key += "\x00u"
	}

	c.mu.Lock()

	if c.m == nil {
		c.m = make(map[string]*releaseCacheEntry)
	}

	e, ok := c.m[key]
	if !ok {
		e = &releaseCacheEntry{}
		c.m[key] = e
	}

	c.mu.Unlock()

	e.once.Do(func() { e.rel, e.err = load() })

	return e.rel, e.err
}

// fetchComponentIndex downloads the Packages index of a component and
// architecture into the lists directory. It tries the variants the Release
// lists, best compression first. A transport failure falls through to the next
// variant; if none succeeds the last transport error is returned, so the caller
// sees the real cause.
func (u *updater) fetchComponentIndex(ctx context.Context, src *Source, comp, arch string, rel *deb.Release) error {
	var lastErr error

	tried := false

	for _, relPath := range rel.PackagesVariants(comp, arch) {
		entry := rel.Files[relPath]
		if entry.SHA256 == "" {
			continue // only a weaker digest is listed; cannot verify
		}

		tried = true

		stop, err := u.fetchIndexVariant(ctx, src, relPath, entry)
		if err == nil {
			return nil
		}

		if stop {
			return err
		}

		lastErr = err
	}

	if lastErr != nil {
		return lastErr
	}

	if tried {
		return fmt.Errorf("apt: component %s arch %s: no usable Packages index", comp, arch)
	}

	return fmt.Errorf("%w: component %s arch %s", ErrNoPackagesIndex, comp, arch)
}

// fetchIndexVariant fetches, verifies and atomically stores one Packages
// variant. stop reports a definitive error (integrity or I/O): no other
// compression variant is tried. A plain transport error leaves it false.
func (u *updater) fetchIndexVariant(
	ctx context.Context, src *Source, relPath string, entry deb.FileInfo,
) (stop bool, err error) {
	dest := filepath.Join(u.opts.ListsDir, ListFileName(src.URL, src.Suite, relPath))

	unlock := u.lockPath(dest)
	defer unlock()

	// Warm cache: a list file that already has the size and SHA-256 of the
	// freshly verified Release entry needs no download. It also makes duplicate
	// sources queued behind the path lock a no-op.
	if fileMatches(dest, entry.Size, entry.SHA256) {
		return true, nil
	}

	sum, err := download.ParseChecksum("sha256", entry.SHA256)
	if err != nil || entry.Size < 0 || entry.Size > maxIndexBytes {
		return true, fmt.Errorf("%w: %s lists size %d, sha256 %q", ErrInvalidIndexEntry, relPath, entry.Size, entry.SHA256)
	}

	target := distURL(src, relPath)

	err = u.withHTTPSFallback(target, func(raw string) error {
		return download.Download(ctx, download.Request{
			URL:      raw,
			Dest:     dest,
			Checksum: sum,
			MaxBytes: max(entry.Size, 1), // zero would mean uncapped
		}, download.Options{Client: u.client})
	})
	if err != nil {
		if errors.Is(err, download.ErrChecksumMismatch) || errors.Is(err, download.ErrTooLarge) {
			return true, fmt.Errorf("%w: %s: %w", ErrIntegrity, target, err)
		}

		return false, fmt.Errorf("apt: fetch %s: %w", target, err)
	}

	// The digest matched; a shorter file than declared still means a lying
	// Release entry, and is refused like a mismatch.
	if fi, statErr := os.Stat(dest); statErr != nil || fi.Size() != entry.Size {
		_ = os.Remove(dest)

		return true, fmt.Errorf("%w: %s: size differs from the %d bytes the Release lists", ErrIntegrity, target, entry.Size)
	}

	return true, nil
}

// fileMatches reports whether dest exists with the given size and SHA-256. It
// is the warm cache check; the file is hashed as a stream, so a large index is
// never held in memory. Any failure is a miss.
func fileMatches(dest string, size int64, sha256Hex string) bool {
	fi, err := os.Stat(dest)
	if err != nil || fi.Size() != size {
		return false
	}

	f, err := os.Open(dest)
	if err != nil {
		return false
	}

	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}

	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), sha256Hex)
}
