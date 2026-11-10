package apt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/M0Rf30/pkgformat/download"
	"github.com/M0Rf30/pkgformat/httpclient"
	"github.com/M0Rf30/pkgformat/internal/pathseg"
)

// MaxDebBytes caps one .deb download. Real packages top out around 500 MB;
// 2 GiB leaves room while still stopping an unbounded mirror stream.
const MaxDebBytes int64 = 2 << 30

// defaultDownloadConcurrency is the number of parallel .deb transfers. A mirror
// tolerates a handful of connections; six saturate a typical link without
// being rude.
const defaultDownloadConcurrency = 6

// DownloadOptions configures Download and DownloadClosure. The zero value is
// valid.
type DownloadOptions struct {
	// Client performs the transfers. Nil builds one without an overall timeout,
	// which would abort a large package on a slow link.
	Client *httpclient.Client
	// Concurrency caps the parallel transfers. Zero selects 6.
	Concurrency int
	// Progress, when set, is called after each chunk of a package with its
	// file name, the bytes on disk and the expected size. It must be safe for
	// concurrent use.
	Progress func(name string, done, total int64)
}

// DownloadClosure resolves the transitive closure of the seed names with
// ResolveDeps, downloads every resulting .deb into destDir, and returns the
// resolved packages in dependency order (dependencies first) and the names
// that could not be resolved.
//
// Installed packages are skipped, and so are their dependencies: as with apt,
// an installed package is taken to have its own met. A dependency an
// installed package would meet only for another architecture (a cross build
// reading the dependencies of a foreign library) is still resolved, since the
// installed one does not satisfy it.
func (c *Cache) DownloadClosure(
	ctx context.Context, destDir string, seeds []string, opts DownloadOptions,
) (resolved []*PackageInfo, unresolved []string, err error) {
	resolved, unresolved, err = c.ResolveDeps(seeds)
	if err != nil {
		return nil, nil, err
	}

	if len(resolved) == 0 {
		return resolved, unresolved, nil
	}

	names := make([]string, len(resolved))
	for i, p := range resolved {
		names[i] = entryKey(p.Name, p.Architecture)
		if p.Version != "" {
			names[i] += " (= " + p.Version + ")"
		}
	}

	if err := c.Download(ctx, destDir, names, opts); err != nil {
		return resolved, unresolved, err
	}

	return resolved, unresolved, nil
}

// debJob pairs a package name with its index entry and the file it is stored
// in.
type debJob struct {
	name string
	info PackageInfo
	url  string
	dest string
}

// Download fetches the named packages into destDir, each as the base name of
// its index Filename. A name may carry an architecture qualifier and a version
// constraint ("gcc-11:arm64 (= 11.3.0-1)"); the highest version that meets it
// is fetched, the highest of all without one. The size and
// SHA-256 of the index are enforced while the file is written, and a file that
// fails the check is not left behind.
//
// Every package is resolved and validated before any transfer starts, so an
// unknown package, a package without a repository URL, or a malformed index
// entry (missing or invalid SHA256, Size out of range, unsafe Filename) fails
// the call at once. Transfers then run to completion; the error of the first
// failing package, in argument order, is returned.
//
// A plain-http transfer that fails with a transient error is retried once over
// https.
func (c *Cache) Download(ctx context.Context, destDir string, pkgs []string, opts DownloadOptions) error {
	if len(pkgs) == 0 {
		return nil
	}

	jobs, err := c.resolveDownloadJobs(destDir, pkgs)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil { //nolint:gosec // downloaded packages are not secret
		return fmt.Errorf("apt: create download directory: %w", err)
	}

	dopts := download.Options{Client: opts.Client, Concurrency: opts.Concurrency}
	if dopts.Concurrency <= 0 {
		dopts.Concurrency = defaultDownloadConcurrency
	}

	reqs, err := downloadRequests(jobs, opts, func(j *debJob) string { return j.url })
	if err != nil {
		return err
	}

	results := download.DownloadAll(ctx, reqs, dopts)

	// One retry over https, for the plain-http transfers that failed
	// transiently. A truncated partial is discarded by the downloader, so the
	// retry starts clean.
	var (
		retryIdx  []int
		retryJobs []*debJob
		httpsURLs = make(map[*debJob]string)
	)

	for i, res := range results {
		if res.Err == nil || !httpclient.IsRetryable(res.Err) {
			continue
		}

		httpsURL, ok := httpclient.UpgradeToHTTPS(jobs[i].url)
		if !ok {
			continue
		}

		httpsURLs[jobs[i]] = httpsURL

		retryIdx = append(retryIdx, i)
		retryJobs = append(retryJobs, jobs[i])
	}

	if len(retryJobs) > 0 {
		retryReqs, err := downloadRequests(retryJobs, opts, func(j *debJob) string { return httpsURLs[j] })
		if err != nil {
			return err
		}

		for i, res := range download.DownloadAll(ctx, retryReqs, dopts) {
			results[retryIdx[i]] = res
		}
	}

	for i, res := range results {
		if res.Err == nil {
			continue
		}

		if errors.Is(res.Err, download.ErrChecksumMismatch) || errors.Is(res.Err, download.ErrTooLarge) {
			return fmt.Errorf("%w: %s: %w", ErrIntegrity, filepath.Base(jobs[i].dest), res.Err)
		}

		return fmt.Errorf("apt: download %s: %w", filepath.Base(jobs[i].dest), res.Err)
	}

	return nil
}

// downloadRequests builds one verified request per job against the URL
// chosen by urlOf.
func downloadRequests(jobs []*debJob, opts DownloadOptions, urlOf func(*debJob) string) ([]download.Request, error) {
	reqs := make([]download.Request, len(jobs))

	for i, j := range jobs {
		sum, err := validateDebIntegrity(j)
		if err != nil {
			return nil, err
		}

		req := download.Request{URL: urlOf(j), Dest: j.dest, Checksum: sum, MaxBytes: j.info.Size}

		if opts.Progress != nil {
			name := filepath.Base(j.dest)
			req.Progress = func(done, total int64) { opts.Progress(name, done, total) }
		}

		reqs[i] = req
	}

	return reqs, nil
}

// resolveDownloadJobs resolves every package name to its index entry up front,
// so that a missing package or a missing BaseURL surfaces before any HTTP.
func (c *Cache) resolveDownloadJobs(destDir string, pkgs []string) ([]*debJob, error) {
	jobs := make([]*debJob, 0, len(pkgs))
	// Two jobs with one destination base name would write one file
	// concurrently and fail the checksum.
	seenDest := make(map[string]bool, len(pkgs))

	for _, spec := range pkgs {
		name, info, ok := c.lookupSpec(spec)
		if !ok || info.Filename == "" {
			return nil, fmt.Errorf("%w: %s", ErrPackageNotFound, name)
		}

		if info.BaseURL == "" {
			return nil, fmt.Errorf("%w: %s", ErrNoBaseURL, name)
		}

		if !safeFilename(info.Filename) {
			return nil, fmt.Errorf("%w: %s: unsafe Filename %q", ErrInvalidIndexEntry, name, info.Filename)
		}

		base := path.Base(info.Filename)

		job := &debJob{
			name: name,
			info: info,
			url:  strings.TrimSuffix(info.BaseURL, "/") + "/" + info.Filename,
			dest: filepath.Join(destDir, base),
		}

		if _, err := validateDebIntegrity(job); err != nil {
			return nil, err
		}

		if seenDest[base] {
			continue
		}

		seenDest[base] = true

		jobs = append(jobs, job)
	}

	return jobs, nil
}

// safeFilename reports whether a Filename from an index can be joined to a base
// URL and stored by its base name: a plain relative path that cannot start a
// query or a fragment, or smuggle whitespace or control characters.
func safeFilename(name string) bool {
	if !pathseg.Path(name) {
		return false
	}

	return !strings.ContainsFunc(name, func(r rune) bool {
		return r <= ' ' || r == 0x7f || r == '?' || r == '#'
	})
}

// validateDebIntegrity requires that a download is verifiable before a byte is
// fetched: the index must supply a well-formed SHA-256 and a positive Size not
// above MaxDebBytes. An odd-length digest from a truncated index would
// otherwise yield an unverified .deb that is later extracted as root.
func validateDebIntegrity(j *debJob) (*download.Checksum, error) {
	if sum, err := hex.DecodeString(j.info.SHA256); err != nil || len(sum) != sha256.Size {
		return nil, fmt.Errorf("%w: %s: missing or invalid SHA256 %q", ErrInvalidIndexEntry, j.name, j.info.SHA256)
	}

	if j.info.Size <= 0 || j.info.Size > MaxDebBytes {
		return nil, fmt.Errorf("%w: %s: missing or out-of-range Size %d (cap %d)",
			ErrInvalidIndexEntry, j.name, j.info.Size, MaxDebBytes)
	}

	sum, err := download.ParseChecksum("sha256", j.info.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidIndexEntry, j.name, err)
	}

	return sum, nil
}
