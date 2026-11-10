package dnf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/M0Rf30/pkgformat/download"
	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

// Download fetches the .rpm of p into destDir, under the base name of its
// location, and returns the path. The file is checked against the checksum of
// the metadata (SHA-256 or SHA-512) before it appears at its final name, and a
// file already there with that checksum is kept without a transfer. A package
// without a verifiable checksum is refused with [ErrUnverifiable].
//
// The mirror the metadata came from is tried first, then the mirrors of the
// repository's mirror list. A mirror that serves wrong bytes or fails is
// skipped for the next; the last error is returned when none works.
func (c *Client) Download(ctx context.Context, p *Package, destDir string) (string, error) {
	loc, ok := repoLocation(p.Location)
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnsafeLocation, p.Location)
	}

	sum, err := checksumFor(p.ChecksumType, p.Checksum)
	if err != nil {
		return "", fmt.Errorf("dnf: %s: %w", p.Name, err)
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil { //nolint:gosec // a download directory others may read
		return "", fmt.Errorf("dnf: creating destination: %w", err)
	}

	dest := filepath.Join(destDir, path.Base(loc))
	if fileMatches(dest, sum) {
		return dest, nil
	}

	req := download.Request{
		Dest:     dest,
		Checksum: sum,
		MaxBytes: c.opts.MaxPackageBytes,
	}

	var lastErr error

	try := func(base string) bool {
		req.URL = joinURL(base, loc)

		lastErr = download.Download(ctx, req, download.Options{Client: c.opts.HTTP})
		if lastErr != nil {
			c.opts.Logger.Warn("package download failed", "package", p.Name, "mirror", base, "error", lastErr)
		}

		return lastErr == nil
	}

	base := strings.TrimSuffix(p.BaseURL, "/")
	if base != "" && try(base) {
		return dest, nil
	}

	if p.MirrorList != "" && ctx.Err() == nil {
		mirrors, err := c.resolveMirrors(ctx, p.MirrorList)
		if err != nil {
			lastErr = errors.Join(lastErr, err)
		}

		for _, m := range mirrors {
			if err := ctx.Err(); err != nil {
				return "", err
			}

			if m = strings.TrimSuffix(m, "/"); m != base && try(m) {
				return dest, nil
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	if lastErr == nil {
		lastErr = ErrNoMirror
	}

	return "", fmt.Errorf("dnf: downloading %s: %w", p.Name, lastErr)
}

// DownloadAll downloads the packages into destDir with at most
// Options.Concurrency transfers at a time and returns their paths in the order
// given. The first failure cancels the transfers still running and is
// returned.
func (c *Client) DownloadAll(ctx context.Context, pkgs []*Package, destDir string) ([]string, error) {
	paths := make([]string, len(pkgs))

	group, gctx := errgroup.WithContext(ctx)
	group.SetLimit(min(c.opts.Concurrency, max(len(pkgs), 1)))

	for i, p := range pkgs {
		group.Go(func() error {
			var err error

			paths[i], err = c.Download(gctx, p, destDir)

			return err
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	return paths, nil
}

// repoLocation validates a package location and returns it as the decoded,
// cleaned repository-relative path. A leading slash is tolerated.
func repoLocation(href string) (string, bool) {
	return repodata.SafeLocation(strings.TrimLeft(href, "/"))
}
