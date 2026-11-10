package dnf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/M0Rf30/pkgformat/download"
	"github.com/M0Rf30/pkgformat/httpclient"
	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

// Update refreshes the metadata of every enabled repository into
// Options.CacheDir. Repositories are fetched concurrently. For each one the
// mirrors are tried in order until one serves a complete, verified set of
// metadata: repomd.xml and the files it names always come from the same mirror.
// Only then are repomd.xml and the winning mirror written to the cache, so a
// failed update leaves the previous metadata intact.
//
// A repository that answers with an HTTP 4xx (not found, forbidden) on every
// mirror is logged and skipped; any other failure is returned, joined with the
// others, after all repositories were tried.
func (c *Client) Update(ctx context.Context) error {
	if c.opts.CacheDir == "" {
		return ErrNoCacheDir
	}

	repos, err := c.enabledRepos()
	if err != nil {
		return err
	}

	errs := make([]error, len(repos))

	var group errgroup.Group

	group.SetLimit(min(c.opts.Concurrency, max(len(repos), 1)))

	for i := range repos {
		group.Go(func() error {
			errs[i] = c.fetchRepo(ctx, &repos[i])

			return nil
		})
	}

	_ = group.Wait()

	var fatal []error

	for i, err := range errs {
		switch {
		case err == nil:
		case isNonFatal(err):
			c.opts.Logger.Warn("repository unavailable", "repo", repos[i].ID, "error", err)
		default:
			fatal = append(fatal, err)
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return errors.Join(fatal...)
}

// isNonFatal reports whether err is an HTTP 4xx answer: a repository that is
// gone or private must not fail the refresh of the others.
func isNonFatal(err error) bool {
	if se, ok := errors.AsType[*httpclient.HTTPStatusError](err); ok {
		return se.IsClientError()
	}

	return false
}

// fetchRepo tries the candidate mirrors of one repository in order. The last
// failure is returned when none works.
func (c *Client) fetchRepo(ctx context.Context, repo *Repo) error {
	bases, err := c.candidates(ctx, repo)
	if err != nil {
		return err
	}

	var lastErr error

	for _, base := range bases {
		if err := ctx.Err(); err != nil {
			return err
		}

		lastErr = c.fetchRepoFrom(ctx, repo, base)
		if lastErr == nil {
			return nil
		}

		c.opts.Logger.Warn("mirror failed, trying the next", "repo", repo.ID, "mirror", base, "error", lastErr)
	}

	return fmt.Errorf("dnf: repository %s: %w", repo.ID, lastErr)
}

// fetchRepoFrom takes the metadata of repo from one mirror.
func (c *Client) fetchRepoFrom(ctx context.Context, repo *Repo, base string) error {
	cacheDir := c.repoCacheDir(repo.ID)
	dataDir := filepath.Join(cacheDir, repodataDir)

	if err := os.MkdirAll(dataDir, 0o755); err != nil { //nolint:gosec // a cache directory others may read
		return fmt.Errorf("dnf: creating cache directory: %w", err)
	}

	repomdXML, err := c.fetchRepomd(ctx, base, filepath.Join(dataDir, repomdName))
	if err != nil {
		return err
	}

	md, err := repodata.ParseRepomd(bytes.NewReader(repomdXML))
	if err != nil {
		return fmt.Errorf("dnf: %s: %w", base, err)
	}

	primary, ok := md.Find("primary")
	if !ok || primary.Location == "" {
		return fmt.Errorf("%s: %w", base, ErrNoPrimary)
	}

	if err := c.fetchMetadataFile(ctx, base, dataDir, &primary); err != nil {
		return err
	}

	// Module metadata only narrows what the index offers; losing it must not
	// lose the repository.
	if modules, ok := md.Find("modules"); ok && modules.Location != "" {
		if err := c.fetchMetadataFile(ctx, base, dataDir, &modules); err != nil {
			c.opts.Logger.Warn("module metadata not fetched", "repo", repo.ID, "error", err)
		}
	}

	// Commit last: repomd.xml is what Load reads, and the mirror recorded here
	// is the one that served every file it names.
	if err := httpclient.AtomicWrite(filepath.Join(dataDir, repomdName), func(w io.Writer) error {
		_, err := w.Write(repomdXML)

		return err
	}); err != nil {
		return fmt.Errorf("dnf: caching repomd.xml: %w", err)
	}

	if err := httpclient.AtomicWrite(filepath.Join(cacheDir, baseURLName), func(w io.Writer) error {
		_, err := io.WriteString(w, base)

		return err
	}); err != nil {
		return fmt.Errorf("dnf: caching the mirror: %w", err)
	}

	return nil
}

// fetchRepomd downloads repomd.xml, sending If-Modified-Since when a copy is
// cached; on 304 the cached copy is used. The copy is not rewritten here.
func (c *Client) fetchRepomd(ctx context.Context, base, cached string) ([]byte, error) {
	var since time.Time

	if fi, err := os.Stat(cached); err == nil {
		since = fi.ModTime()
	}

	data, notModified, err := c.opts.HTTP.FetchBytesConditional(
		ctx, base+"/"+repodataDir+"/"+repomdName, maxRepomdBytes, since)
	if err != nil {
		return nil, fmt.Errorf("dnf: fetching repomd.xml: %w", err)
	}

	if !notModified {
		return data, nil
	}

	data, err = readCapped(cached, maxRepomdBytes)
	if err != nil {
		return nil, fmt.Errorf("dnf: reading cached repomd.xml: %w", err)
	}

	return data, nil
}

// fetchMetadataFile downloads the file a repomd entry describes into dataDir,
// verified against the entry's checksum, unless it is there already.
func (c *Client) fetchMetadataFile(ctx context.Context, base, dataDir string, e *repodata.RepomdData) error {
	loc, ok := repodata.SafeLocation(e.Location)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnsafeLocation, e.Location)
	}

	sum, err := checksumFor(e.ChecksumType, e.Checksum)
	if err != nil {
		return fmt.Errorf("%s: %w", loc, err)
	}

	dest := filepath.Join(dataDir, path.Base(loc))
	if fileMatches(dest, sum) {
		return nil
	}

	return download.Download(ctx, download.Request{
		URL:      joinURL(base, loc),
		Dest:     dest,
		Checksum: sum,
		MaxBytes: c.opts.MaxMetadataBytes,
	}, download.Options{Client: c.opts.HTTP})
}

// checksumFor builds the verifier for a checksum of repository metadata. Only
// SHA-256 and SHA-512 are accepted: nothing weaker proves a download genuine.
func checksumFor(kind, sum string) (*download.Checksum, error) {
	switch strings.ToLower(kind) {
	case "sha256", "sha512":
	default:
		return nil, fmt.Errorf("%w (%q)", ErrUnverifiable, kind)
	}

	ck, err := download.ParseChecksum(kind, sum)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnverifiable, err)
	}

	return ck, nil
}

// fileMatches reports whether the file at p exists and has the checksum.
func fileMatches(p string, sum *download.Checksum) bool {
	f, err := os.Open(p)
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

// joinURL appends a repository-relative path, escaped, to a base URL.
func joinURL(base, loc string) string {
	return base + "/" + (&url.URL{Path: loc}).EscapedPath()
}

func readCapped(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}

	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %s", repodata.ErrTooLarge, p)
	}

	return data, nil
}
