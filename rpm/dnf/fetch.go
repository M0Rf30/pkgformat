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
// failed update leaves the previous metadata intact. A repository with
// repo_gpgcheck=1 is only accepted when repomd.xml.asc is a valid signature of
// repomd.xml by one of its gpgkey keys ([ErrRepoSignature]); the metadata types
// of its enabled_metadata are fetched along with primary and modules.
//
// A repository that answers with an HTTP 4xx (not found, forbidden) on every
// mirror is logged and skipped, and so is any repository that fails when it
// sets skip_if_unavailable=1; any other failure is returned, joined with the
// others, after all repositories were tried.
func (c *Client) Update(ctx context.Context) error {
	return c.update(ctx, false)
}

// UpdateExpired is [Client.Update] for the repositories whose cached metadata
// is expired ([Client.Expired]) or missing; the others are left alone without a
// request.
func (c *Client) UpdateExpired(ctx context.Context) error {
	return c.update(ctx, true)
}

// Expired reports whether the cached metadata of repo is older than its
// metadata_expire, or absent. Metadata of a repository with
// metadata_expire=never does not expire once it is cached.
func (c *Client) Expired(repo *Repo) bool {
	fi, err := os.Stat(filepath.Join(c.repoCacheDir(repo.ID), repodataDir, repomdName))
	if err != nil {
		return true
	}

	if repo.MetadataExpire < 0 {
		return false
	}

	return c.now().Sub(fi.ModTime()) > repo.MetadataExpire
}

func (c *Client) update(ctx context.Context, onlyExpired bool) error {
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
			if onlyExpired && !c.Expired(&repos[i]) {
				return nil
			}

			errs[i] = c.fetchRepo(ctx, &repos[i])

			return nil
		})
	}

	_ = group.Wait()

	var fatal []error

	for i, err := range errs {
		switch {
		case err == nil:
		case repos[i].SkipIfUnavailable || isNonFatal(err):
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
	if errors.Is(err, ErrRepoSignature) {
		return false
	}

	if se, ok := errors.AsType[*httpclient.HTTPStatusError](err); ok {
		return se.IsClientError()
	}

	return false
}

// fetchRepo tries the candidate mirrors of one repository in order. The last
// failure is returned when none works.
func (c *Client) fetchRepo(ctx context.Context, repo *Repo) error {
	hc, err := c.httpFor(repo)
	if err != nil {
		return err
	}

	bases, meta, err := c.candidates(ctx, hc, repo)
	if err != nil {
		return err
	}

	var lastErr error

	for _, base := range bases {
		if err := ctx.Err(); err != nil {
			return err
		}

		lastErr = c.fetchRepoFrom(ctx, hc, repo, base, meta)
		if lastErr == nil {
			return nil
		}

		c.opts.Logger.Warn("mirror failed, trying the next", "repo", repo.ID, "mirror", base, "error", lastErr)
	}

	return fmt.Errorf("dnf: repository %s: %w", repo.ID, lastErr)
}

// fetchRepoFrom takes the metadata of repo from one mirror. A non-nil meta is
// what the repository's metalink says about repomd.xml, which must match.
func (c *Client) fetchRepoFrom(
	ctx context.Context, hc *httpclient.Client, repo *Repo, base string, meta *metalinkInfo,
) error {
	cacheDir := c.repoCacheDir(repo.ID)
	dataDir := filepath.Join(cacheDir, repodataDir)

	if err := os.MkdirAll(dataDir, 0o755); err != nil { //nolint:gosec // a cache directory others may read
		return fmt.Errorf("dnf: creating cache directory: %w", err)
	}

	cachedRepomd := filepath.Join(dataDir, repomdName)

	repomdXML, fromCache, err := c.fetchRepomd(ctx, hc, base, cachedRepomd)
	if err != nil {
		return err
	}

	if err := meta.verify(repomdXML); err != nil {
		if !fromCache {
			return fmt.Errorf("dnf: %s: %w", base, err)
		}

		// The mirror said "not modified" about a copy that is not the one the
		// metalink names: ask for the current file.
		if repomdXML, _, err = c.fetchRepomd(ctx, hc, base, ""); err != nil {
			return err
		}

		if err := meta.verify(repomdXML); err != nil {
			return fmt.Errorf("dnf: %s: %w", base, err)
		}
	}

	if repo.RepoGPGCheck {
		if err := c.checkRepomdSignature(ctx, hc, repo, base, repomdXML); err != nil {
			return err
		}
	}

	md, err := repodata.ParseRepomd(bytes.NewReader(repomdXML))
	if err != nil {
		return fmt.Errorf("dnf: %s: %w", base, err)
	}

	primary, ok := md.Find("primary")
	if !ok || primary.Location == "" {
		return fmt.Errorf("%s: %w", base, ErrNoPrimary)
	}

	if err := c.fetchMetadataFile(ctx, hc, base, dataDir, &primary); err != nil {
		return err
	}

	// Module metadata only narrows what the index offers; losing it must not
	// lose the repository.
	if modules, ok := md.Find("modules"); ok && modules.Location != "" {
		if err := c.fetchMetadataFile(ctx, hc, base, dataDir, &modules); err != nil {
			c.opts.Logger.Warn("module metadata not fetched", "repo", repo.ID, "error", err)
		}
	}

	// Further metadata only enlarges what a resolution can do; losing it must
	// not lose the repository.
	for _, kind := range repo.EnabledMetadata {
		kind = strings.ToLower(kind)
		if kind == "primary" || kind == "modules" {
			continue
		}

		entry, ok := md.Find(kind)
		if !ok || entry.Location == "" {
			continue
		}

		if err := c.fetchMetadataFile(ctx, hc, base, dataDir, &entry); err != nil {
			c.opts.Logger.Warn("metadata not fetched", "repo", repo.ID, "type", kind, "error", err)
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
// cached; on 304 the cached copy is used and fromCache is true. An empty cached
// path makes the request unconditional. The copy is not rewritten here.
func (c *Client) fetchRepomd(
	ctx context.Context, hc *httpclient.Client, base, cached string,
) (data []byte, fromCache bool, err error) {
	var since time.Time

	if fi, err := os.Stat(cached); err == nil {
		since = fi.ModTime()
	}

	data, notModified, err := hc.FetchBytesConditional(
		ctx, base+"/"+repodataDir+"/"+repomdName, maxRepomdBytes, since)
	if err != nil {
		return nil, false, fmt.Errorf("dnf: fetching repomd.xml: %w", err)
	}

	if !notModified {
		return data, false, nil
	}

	data, err = readCapped(cached, maxRepomdBytes)
	if err != nil {
		return nil, false, fmt.Errorf("dnf: reading cached repomd.xml: %w", err)
	}

	return data, true, nil
}

// fetchMetadataFile downloads the file a repomd entry describes into dataDir,
// verified against the entry's checksum, unless it is there already.
func (c *Client) fetchMetadataFile(
	ctx context.Context, hc *httpclient.Client, base, dataDir string, e *repodata.RepomdData,
) error {
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
	}, download.Options{Client: hc})
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
