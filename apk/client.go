package apk

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // names the cache file of an index URL, not a security use
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/M0Rf30/pkgformat/download"
	"github.com/M0Rf30/pkgformat/httpclient"
	"github.com/M0Rf30/pkgformat/internal/pathseg"
)

// Limits of the client.
const (
	// maxIndexDownload caps an APKINDEX.tar.gz download. Real indexes are a few
	// MB; this is slack that still stops an unbounded stream.
	maxIndexDownload = 100 << 20
	// maxPackageDownload caps a package whose index entry has no size.
	maxPackageDownload = 1 << 30

	indexFetchConcurrency = 4
)

var (
	// ErrInvalidOptions is wrapped by the errors of [NewClient] for options it
	// refuses.
	ErrInvalidOptions = errors.New("apk: invalid client options")
	// ErrNoIndex is returned by [Client.Update] when no repository index could
	// be loaded. It wraps the failure of each repository.
	ErrNoIndex = errors.New("apk: no repository index could be loaded")
	// ErrPackageMismatch means a downloaded package is not the one its index
	// entry describes: another size, checksum, name or version.
	ErrPackageMismatch = errors.New("apk: downloaded package does not match the index")
)

// ClientOptions configures a [Client]. Repos, Arch, and a trust decision (KeysDir
// with Algorithms, or InsecureSkipVerify) are required; nothing is read from a
// host path unless the caller names it.
type ClientOptions struct {
	// Repos are the repositories, in order of preference.
	Repos []Repo
	// Arch is the architecture directory of every repository, for example
	// x86_64.
	Arch string

	// KeysDir is the directory of trusted public keys (the keys directory of
	// /etc/apk) the index signatures are checked against. An index without a
	// valid signature by one of them is refused.
	KeysDir string
	// Algorithms are the signature types accepted when KeysDir is set. There
	// is no default: a caller that accepts SHA-1 signatures says so.
	Algorithms []SigAlgorithm
	// InsecureSkipVerify accepts indexes without checking their signature. It
	// excludes KeysDir. The downloaded packages are still checked against the
	// index entries.
	InsecureSkipVerify bool

	// HTTP fetches the indexes and the packages. Nil builds a client with the
	// default retry policy.
	HTTP *httpclient.Client
	// CacheDir, when set, receives a copy of each verified index tarball, named
	// APKINDEX.<sha1 of the URL>.tar.gz. The directory is created.
	CacheDir string
	// Concurrency bounds the parallel package downloads; zero selects the
	// download package's default.
	Concurrency int
	// Logger receives one line per repository and package. Nil is silent.
	Logger *slog.Logger
}

// Client fetches and verifies repository indexes and downloads packages. It is
// safe for concurrent use.
type Client struct {
	opts    ClientOptions
	http    *httpclient.Client
	keyring *Keyring
	verify  VerifyOptions
	logger  *slog.Logger
}

// NewClient validates opts and loads the trusted keys.
func NewClient(opts ClientOptions) (*Client, error) {
	if len(opts.Repos) == 0 {
		return nil, fmt.Errorf("%w: no repositories", ErrInvalidOptions)
	}

	if !validArch(opts.Arch) {
		return nil, fmt.Errorf("%w: arch %q is not a valid architecture", ErrInvalidOptions, short(opts.Arch))
	}

	for _, r := range opts.Repos {
		if err := checkRepoURL(r.URL); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
		}
	}

	c := &Client{opts: opts, http: opts.HTTP, logger: opts.Logger}

	if c.http == nil {
		c.http = httpclient.New(httpclient.Options{})
	}

	switch {
	case opts.KeysDir != "" && opts.InsecureSkipVerify:
		return nil, fmt.Errorf("%w: KeysDir and InsecureSkipVerify exclude each other", ErrInvalidOptions)
	case opts.KeysDir != "":
		ring, err := LoadKeyring(opts.KeysDir)
		if err != nil {
			return nil, err
		}

		c.keyring = ring
		c.verify = VerifyOptions{Keys: ring, Algorithms: opts.Algorithms}

		if err := c.verify.check(); err != nil {
			return nil, err
		}

		if ring.Len() == 0 {
			return nil, fmt.Errorf("%w: no .rsa.pub keys in %s", ErrNoKeyring, opts.KeysDir)
		}
	case !opts.InsecureSkipVerify:
		return nil, fmt.Errorf("%w: set KeysDir or InsecureSkipVerify", ErrNoKeyring)
	}

	return c, nil
}

func (c *Client) log(level slog.Level, msg string, args ...any) {
	if c.logger != nil {
		c.logger.Log(context.Background(), level, msg, args...)
	}
}

// RepoError is the failure to load one repository's index.
type RepoError struct {
	Repo Repo
	Err  error
}

func (e *RepoError) Error() string { return "apk: repository " + e.Repo.URL + ": " + e.Err.Error() }
func (e *RepoError) Unwrap() error { return e.Err }

// IndexURL returns the URL of repo's index for the client's architecture.
func (c *Client) IndexURL(repo Repo) string {
	return repo.URL + "/" + c.opts.Arch + "/APKINDEX.tar.gz"
}

// FetchIndex downloads, verifies (when the client has keys) and parses the
// index of one repository.
func (c *Client) FetchIndex(ctx context.Context, repo Repo) ([]Package, error) {
	url := c.IndexURL(repo)

	data, err := c.http.FetchBytes(ctx, url, maxIndexDownload)
	if err != nil {
		return nil, err
	}

	var pkgs []Package

	if c.keyring != nil {
		pkgs, err = VerifyIndex(data, c.verify)
	} else {
		pkgs, err = ParseIndex(bytes.NewReader(data))
	}

	if err != nil {
		return nil, err
	}

	c.cacheIndex(url, data)

	return pkgs, nil
}

// cacheIndex stores the verified tarball; a failure only costs the cache.
func (c *Client) cacheIndex(url string, data []byte) {
	if c.opts.CacheDir == "" {
		return
	}

	sum := sha1.Sum([]byte(url)) //nolint:gosec // see the import
	dest := filepath.Join(c.opts.CacheDir, "APKINDEX."+hex.EncodeToString(sum[:])+".tar.gz")

	err := os.MkdirAll(c.opts.CacheDir, 0o755) //nolint:gosec // a cache directory is shared readable
	if err == nil {
		err = httpclient.AtomicWrite(dest, func(w io.Writer) error {
			_, err := w.Write(data)

			return err
		})
	}

	if err != nil {
		c.log(slog.LevelWarn, "apk: caching the index failed", "url", url, "error", err)
	}
}

// Update fetches the index of every repository (a few in parallel) and returns
// them as one [Index] in the order of the repositories. A repository that
// cannot be fetched, verified or parsed is left out and reported by
// [Client.Failures] of the result; Update fails with [ErrNoIndex] only when no
// repository loads.
func (c *Client) Update(ctx context.Context) (*UpdatedIndex, error) {
	repos := c.opts.Repos
	results := make([]struct {
		pkgs []Package
		err  error
	}, len(repos))

	sem := make(chan struct{}, indexFetchConcurrency)

	var wg sync.WaitGroup

	for i, repo := range repos {
		wg.Add(1)

		sem <- struct{}{}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			c.log(slog.LevelDebug, "apk: fetching the index", "url", repo.URL, "arch", c.opts.Arch)

			results[i].pkgs, results[i].err = c.FetchIndex(ctx, repo)
		}()
	}

	wg.Wait()

	out := &UpdatedIndex{Index: NewIndex()}

	var errs []error

	for i, repo := range repos {
		if err := results[i].err; err != nil {
			re := &RepoError{Repo: repo, Err: err}
			out.Failures = append(out.Failures, re)
			errs = append(errs, re)

			c.log(slog.LevelWarn, "apk: repository skipped", "url", repo.URL, "error", err)

			continue
		}

		out.Add(repo, c.opts.Arch, results[i].pkgs)
		c.log(slog.LevelInfo, "apk: repository loaded", "url", repo.URL, "packages", len(results[i].pkgs))
	}

	if len(errs) == len(repos) {
		return nil, fmt.Errorf("%w: %w", ErrNoIndex, errors.Join(errs...))
	}

	return out, nil
}

// UpdatedIndex is the result of [Client.Update].
type UpdatedIndex struct {
	*Index
	// Failures are the repositories that were left out.
	Failures []*RepoError
}

// Download fetches the package files of pkgs into destDir, which must exist,
// and returns their paths in the order given. Transfers resume after a partial
// download and are retried by the client's policy. Each file is checked against
// its index entry before it is kept: it must be a valid package of the size,
// checksum, name and version the index lists, otherwise it is deleted and the
// error wraps [ErrPackageMismatch] or [ErrInvalidPackage]. The index checksum is
// the trust anchor, as in apk itself: when the index was verified, so is every
// package it lists.
func (c *Client) Download(ctx context.Context, destDir string, pkgs ...*RepoPackage) ([]string, error) {
	reqs := make([]download.Request, len(pkgs))
	paths := make([]string, len(pkgs))

	for i, p := range pkgs {
		if err := checkDownloadable(p); err != nil {
			return nil, err
		}

		limit := int64(maxPackageDownload)
		if p.Size > 0 && p.Size < limit {
			limit = p.Size
		}

		paths[i] = filepath.Join(destDir, p.FileName())
		reqs[i] = download.Request{URL: p.URL(), Dest: paths[i], MaxBytes: limit}
	}

	results := download.DownloadAll(ctx, reqs, download.Options{Client: c.http, Concurrency: c.opts.Concurrency})

	var errs []error

	for i, p := range pkgs {
		err := results[i].Err
		if err == nil {
			err = checkPackageFile(paths[i], p)
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("apk: %s: %w", p.FileName(), err))

			continue
		}

		c.log(slog.LevelDebug, "apk: package downloaded", "file", paths[i])
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return paths, nil
}

// checkDownloadable refuses an entry whose name could escape the destination
// directory or the repository path.
func checkDownloadable(p *RepoPackage) error {
	if p == nil {
		return fmt.Errorf("%w: nil package", ErrPackageNotFound)
	}

	if !validName(p.Name) || !validVersion(p.Version) || !pathseg.Name(p.IndexArch) || p.Repo.URL == "" {
		return fmt.Errorf("%w: package %q has an unsafe name, version or architecture", ErrInvalidPackage, short(p.Name))
	}

	return nil
}

// checkPackageFile parses the downloaded file and compares it with its index
// entry; a file that fails is removed.
func checkPackageFile(path string, want *RepoPackage) (err error) {
	defer func() {
		if err != nil {
			_ = os.Remove(path)
		}
	}()

	f, err := os.Open(path)
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	got, err := ParsePackage(f, info.Size())
	if err != nil {
		return err
	}

	switch {
	case want.Size > 0 && got.Size != want.Size:
		return fmt.Errorf("%w: size %d, the index says %d", ErrPackageMismatch, got.Size, want.Size)
	case got.Checksum != want.Checksum:
		return fmt.Errorf("%w: checksum %s, the index says %s", ErrPackageMismatch, got.Checksum, want.Checksum)
	case got.Name != want.Name || got.Version != want.Version:
		return fmt.Errorf("%w: %s-%s, the index says %s-%s",
			ErrPackageMismatch, got.Name, got.Version, want.Name, want.Version)
	}

	return nil
}
