package dnf

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// maxFilelistsEntries bounds the file entries read from a filelists.xml: a
// hostile one cannot keep a resolution scanning forever.
const maxFilelistsEntries = 1 << 28

// ErrFilelists means the file lists of a repository could not be read to
// look a file requirement up.
var ErrFilelists = errors.New("dnf: filelists.xml unavailable")

// FileOwners returns the packages of the repositories that own the file path:
// those whose primary.xml lists it and those whose filelists.xml does. The
// file lists of the repositories are fetched, if they are not in the cache, and
// read the first time a path they hold is not in primary.xml; one pass looks
// up every path a package of the index requires. A repository whose file
// lists cannot be had is reported by [ErrFilelists] (joined, one per
// repository) together with the owners that the others gave.
func (ix *Index) FileOwners(ctx context.Context, p string) ([]*Package, error) {
	owners := slices.Clone(ix.files[p])

	ix.lazyMu.Lock()
	defer ix.lazyMu.Unlock()

	var err error

	if _, done := ix.scanned[p]; !done {
		err = ix.scanFilelists(ctx, p)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
	}

	for _, o := range ix.owners[p] {
		if !slices.Contains(owners, o) {
			owners = append(owners, o)
		}
	}

	slices.SortStableFunc(owners, ix.compare)

	return owners, err
}

// scanFilelists reads the file lists of every repository for the paths not
// scanned yet: the one asked for and every path of wantFiles. The caller holds
// lazyMu.
func (ix *Index) scanFilelists(ctx context.Context, p string) error {
	wanted := map[string]struct{}{p: {}}

	for w := range ix.wantFiles {
		if _, done := ix.scanned[w]; !done {
			wanted[w] = struct{}{}
		}
	}

	var errs []error

	for _, src := range ix.sources {
		if src.filelists == "" {
			continue
		}

		if err := ix.client.scanSource(ctx, ix, src, wanted); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			errs = append(errs, fmt.Errorf("%w: %s: %w", ErrFilelists, src.repo.ID, err))
		}
	}

	for w := range wanted {
		ix.scanned[w] = struct{}{}
	}

	if len(errs) > 0 {
		ix.logger.Warn("file lists of a repository not read", "error", errors.Join(errs...))
	}

	return errors.Join(errs...)
}

// scanSource reads the filelists.xml of one repository, fetching it when it is
// not in the cache, and records the owners of the wanted paths.
func (c *Client) scanSource(ctx context.Context, ix *Index, src *repoSource, wanted map[string]struct{}) error {
	if _, err := os.Stat(src.filelists); err != nil {
		if err := c.fetchFilelists(ctx, src); err != nil {
			return err
		}
	}

	rc, err := c.openMetadata(src.filelists)
	if err != nil {
		return err
	}

	defer func() { _ = rc.Close() }()

	return readFilelists(rc, wanted, func(sum, file string) {
		if pkg, ok := src.bySum[sum]; ok {
			if !slices.Contains(ix.owners[file], pkg) {
				ix.owners[file] = append(ix.owners[file], pkg)
			}
		}
	})
}

// fetchFilelists downloads the filelists.xml the cached repomd.xml names into
// the cache, from the mirror the metadata came from, else the mirrors of the
// repository.
func (c *Client) fetchFilelists(ctx context.Context, src *repoSource) error {
	hc, err := c.httpFor(src.repo)
	if err != nil {
		return err
	}

	var lastErr error

	try := func(base string) bool {
		lastErr = c.fetchMetadataFile(ctx, hc, base, src.dataDir, &src.filelistsEntry)

		return lastErr == nil
	}

	tried := map[string]bool{}

	attempt := func(base string) bool {
		base = strings.TrimSuffix(base, "/")
		if base == "" || tried[base] || !isHTTP(base) {
			return false
		}

		tried[base] = true

		return try(base)
	}

	if attempt(src.baseURL) {
		return nil
	}

	for _, raw := range src.repo.BaseURLs {
		if ctx.Err() == nil && attempt(c.expandVars(raw)) {
			return nil
		}
	}

	if src.mirrorList != "" && ctx.Err() == nil {
		mirrors, _, err := c.resolveMirrors(ctx, hc, src.mirrorList)
		if err != nil {
			lastErr = errors.Join(lastErr, err)
		}

		for _, m := range mirrors {
			if err := ctx.Err(); err != nil {
				return err
			}

			if attempt(m) {
				return nil
			}
		}
	}

	if lastErr == nil {
		lastErr = ErrNoMirror
	}

	return lastErr
}

// readFilelists streams a filelists.xml and calls found with the package id and
// the path of every file entry whose path is in wanted. The entries of the other
// files are skipped without being kept.
func readFilelists(r io.Reader, wanted map[string]struct{}, found func(pkgid, file string)) error {
	dec := xml.NewDecoder(r)

	var (
		pkgid   string
		inFile  bool
		entries int
	)

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("dnf: reading filelists.xml: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "package":
				pkgid = ""

				for _, a := range t.Attr {
					if a.Name.Local == "pkgid" {
						pkgid = a.Value
					}
				}
			case "file":
				inFile = true
			}
		case xml.EndElement:
			if t.Name.Local == "file" {
				inFile = false
			}
		case xml.CharData:
			if !inFile || pkgid == "" {
				continue
			}

			if entries++; entries > maxFilelistsEntries {
				return fmt.Errorf("dnf: filelists.xml has more than %d entries", maxFilelistsEntries)
			}

			if _, ok := wanted[string(t)]; ok {
				found(pkgid, string(t))
			}
		}
	}
}
