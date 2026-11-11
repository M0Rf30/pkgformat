package apt

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/M0Rf30/pkgformat/download"
	"github.com/M0Rf30/pkgformat/httpclient"
)

// UpdateOptions configures Update. Only ListsDir is required.
type UpdateOptions struct {
	// ListsDir is the directory the indexes and Release files are written to,
	// under the names apt gives them. Update creates it. A Cache reads it back
	// through LoadOptions.ListsDir.
	ListsDir string
	// DefaultArch is the architecture of sources that name none. Empty selects
	// the one of the running program.
	DefaultArch string
	// DefaultLanguages are the Translation languages of sources without a
	// Languages option (Acquire::Languages). Empty fetches no translations.
	DefaultLanguages []string
	// DefaultKeyrings are the keyring files and directories that trust sources
	// without a Signed-By option (/etc/apt/trusted.gpg.d, /usr/share/keyrings,
	// /etc/apt/keyrings, /etc/apt/trusted.gpg on a Debian host). See LoadKeyring.
	DefaultKeyrings []string
	// AllowUnverified accepts a repository for which no trust anchor exists, a
	// Release signed by an unknown key, or one without a signature. A signature
	// that is present and does not verify is rejected regardless. The
	// allow-insecure source option does the same for one source, and
	// trusted=no refuses it for one source.
	AllowUnverified bool
	// DisableByHash stops Update from fetching indexes by their digest, which
	// it otherwise does for a Release that says Acquire-By-Hash: yes (the
	// source option By-Hash overrides it per source).
	DisableByHash bool
	// DisablePDiffs stops Update from patching an index it already has with
	// the Packages.diff of the repository instead of fetching it whole
	// (Acquire::PDiffs); the source option PDiffs overrides it per source.
	DisablePDiffs bool
	// Client performs the transfers. Nil builds one with the default policy.
	Client *httpclient.Client
	// Concurrency caps the sources updated at once. Zero selects
	// min(2*GOMAXPROCS, 8).
	Concurrency int
	// Now is the clock the Date and Valid-Until checks of a Release use. Nil is
	// time.Now.
	Now func() time.Time
	// Logger receives progress and warnings. Nil is silent.
	Logger *slog.Logger
}

// maxIndexBytes caps one index download, compressed.
const maxIndexBytes = httpclient.DefaultMaxBytes

// Update fetches the indexes every source asks for, verifies the Release
// signature and every index's size and SHA-256 against it, and writes the
// Release files and indexes to opts.ListsDir.
//
// For a deb source the indexes are the Packages of every component and
// architecture (Architectures, Architectures-Add and -Remove), the
// Translation files of the languages (Languages) and, if Targets names it, the
// Contents files; for a deb-src source they are the Sources of every
// component. The Targets, Languages and Architectures options select among
// them (see Source.EffectiveTargets). Sources reached over http, https, file:
// and copy:, and through mirror+ lists, are supported; cdrom: and every other
// scheme fail with ErrUnsupportedScheme.
//
// An index is fetched by its digest (by-hash) when the Release says
// Acquire-By-Hash: yes or the source says By-Hash: force, and falls back to the
// plain path unless forced. An index the previous update left, in any
// compression, is brought up to date with the repository's Packages.diff
// patches when it lists any and they are smaller than the whole file, and
// fetched whole otherwise.
//
// Indexes the Release does not list are skipped silently, as apt does. It
// returns how many (source, index) pairs are now in place, whether fetched or
// already current, and an *UpdateError holding everything that failed: a
// partial failure still reports the successes. Use IsVerificationError to
// tell trust failures from network ones.
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

	type result struct {
		n   int
		err error
	}

	// Every source is independent, so they all run concurrently; the shared
	// transport caps per-host parallelism. Results are stored by index so the
	// joined error is deterministic.
	results := make([]result, len(sources))
	jobCh := make(chan int, len(sources))

	for i := range sources {
		jobCh <- i
	}

	close(jobCh)

	var wg sync.WaitGroup

	for range min(u.concurrency, len(sources)) {
		wg.Go(func() {
			for idx := range jobCh {
				src := sources[idx].ExpandArch(u.defaultArch)
				n, err := u.updateSource(ctx, &src)
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
			u.warn("apt: source update failed", "url", sources[i].URL, "suite", sources[i].Suite, "error", res.err)

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

func (u *updater) debug(msg string, args ...any) {
	if u.opts.Logger != nil {
		u.opts.Logger.Debug(msg, args...)
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

// distURL is the URL of a file under the dists/<suite> directory of a source
// (under the suite directory of a flat one).
func distURL(src *Source, rel string) string {
	return distURLBase(src.URL, src, rel)
}

// distURLBase is distURL for a base URL other than src.URL: one mirror of a
// mirror list.
func distURLBase(base string, src *Source, rel string) string {
	root := strings.TrimRight(base, "/")

	switch {
	case src.Suite == "/":
		return root + "/" + rel
	case src.Flat():
		return root + "/" + src.Suite + rel
	default:
		return root + "/dists/" + src.Suite + "/" + rel
	}
}

// fetchBytes downloads a small document from an http(s) URL, retrying once
// over https when a plain http fetch fails transiently (some networks, such as
// egress proxies and sandboxed CI, reset port 80 and leave 443 alone, and
// mirrors serve the same content on both), or reads it from a file: or copy:
// URL.
func (u *updater) fetchBytes(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	if p, ok := localPath(rawURL); ok {
		return readLocal(p, maxBytes)
	}

	if !isHTTPURL(rawURL) {
		return nil, schemeError(rawURL)
	}

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

// fileMatches reports whether dest exists with the given size and SHA-256. It
// is the warm cache check; the file is hashed as a stream, so a large index is
// never held in memory. Any failure is a miss.
func fileMatches(dest string, size int64, sha256Hex string) bool {
	return fileMatchesWith(dest, size, indexDigest{alg: "sha256", hex: sha256Hex})
}

// fileMatchesWith is fileMatches for any digest of indexDigest.
func fileMatchesWith(dest string, size int64, d indexDigest) bool {
	sum, err := download.ParseChecksum(d.alg, d.hex)
	if err != nil {
		return false
	}

	fi, err := os.Stat(dest)
	if err != nil || fi.Size() != size {
		return false
	}

	f, err := os.Open(dest)
	if err != nil {
		return false
	}

	defer func() { _ = f.Close() }()

	h := sum.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}

	return bytes.Equal(h.Sum(nil), sum.Sum)
}

// listPath is the path of the list file of relPath under the dists directory
// of src.
func (u *updater) listPath(src *Source, relPath string) (string, error) {
	name := ListFileNameFor(src, relPath)
	if name == "" {
		return "", fmt.Errorf("%w: %q is not a usable base URL", ErrUnsupportedScheme, src.URL)
	}

	return u.opts.ListsDir + string(os.PathSeparator) + name, nil
}
