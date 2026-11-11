package apt

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/httpclient"
)

// maxPDiffPatchDownload caps one compressed patch download.
const maxPDiffPatchDownload = 64 << 20

// pdiffSizeLimit is apt's Acquire::PDiffs::SizeLimit: patches are used only if
// together they are smaller than this fraction of the whole index, in percent.
const pdiffSizeLimit = 50

// pdiffEnabled reports whether the source may be updated by patches.
func (u *updater) pdiffEnabled(src *Source) bool {
	return src.PDiffs.Enabled(!u.opts.DisablePDiffs)
}

// tryPDiff brings the local copy of an index up to date with the Packages.diff
// of the repository. It reports whether it did: any reason not to (patches
// disabled, none listed, no local copy, a local copy the history does not
// know, patches not smaller than the file, a failed transfer or digest) sends
// the caller to fetch the whole index, which then needs no special handling.
//
// The Release must list the uncompressed index (the digest the patched file is
// checked against) and Packages.diff/Index. The patched file is stored
// uncompressed under its own list name and the other compressions of the index
// are removed.
func (u *updater) tryPDiff(
	ctx context.Context, src *Source, fr *fetchedRelease, base string, variants []deb.IndexVariant,
) bool {
	if !u.pdiffEnabled(src) {
		return false
	}

	var target deb.FileInfo

	for _, v := range variants {
		if v.Extension == "" && v.Info.SHA256 != "" {
			target = v.Info
		}
	}

	indexPath := base + ".diff/Index"

	indexEntry, listed := fr.rel.Files[indexPath]
	if target.SHA256 == "" || !listed || indexEntry.SHA256 == "" || target.Size <= 0 || target.Size > maxIndexBytes {
		return false
	}

	dest, err := u.listPath(src, base)
	if err != nil {
		return false
	}

	unlock := u.lockPath(dest)
	defer unlock()

	local, found := u.readLocalIndex(src, base)
	if !found {
		return false
	}

	localSum := deb.PDiffSHA256(local)
	if localSum == target.SHA256 {
		// Same content as the Release lists, only stored in another form.
		return u.storeUncompressed(src, base, dest, local) == nil
	}

	data, err := u.fetchFromBases(ctx, src, fr, indexPath, indexEntry.Size+1)
	if err != nil || !matchesEntry(data, indexEntry) {
		u.debug("apt: pdiff index unusable", "path", indexPath, "error", err)

		return false
	}

	idx, err := deb.ParsePDiffIndex(data)
	if err != nil || idx.Current.SHA256 != target.SHA256 {
		u.debug("apt: pdiff index does not describe the listed index", "path", indexPath, "error", err)

		return false
	}

	chain, err := idx.Chain(localSum)
	if err != nil {
		u.debug("apt: no pdiff path", "path", indexPath, "error", err)

		return false
	}

	var download int64
	for _, p := range chain {
		download += p.Download.Size
	}

	if download*100 >= target.Size*pdiffSizeLimit {
		return false
	}

	patched, err := deb.ApplyPDiffChain(local, chain, func(p deb.PDiffPatch) ([]byte, error) {
		return u.fetchFromBases(ctx, src, fr, base+".diff/"+p.DownloadName(), min(max(p.Download.Size, 1), maxPDiffPatchDownload))
	}, deb.PDiffApplyOptions{})
	if err != nil || !matchesEntry(patched, target) {
		u.debug("apt: pdiff failed, fetching the whole index", "path", indexPath, "error", err)

		return false
	}

	if err := u.storeUncompressed(src, base, dest, patched); err != nil {
		u.warn("apt: storing patched index failed", "path", dest, "error", err)

		return false
	}

	u.debug("apt: index patched", "path", dest, "patches", len(chain))

	return true
}

// matchesEntry reports whether data has the size and SHA-256 of a Release
// entry.
func matchesEntry(data []byte, e deb.FileInfo) bool {
	return int64(len(data)) == e.Size && deb.PDiffSHA256(data) == e.SHA256
}

// readLocalIndex reads the copy of the index the lists directory holds, in
// whichever compression.
func (u *updater) readLocalIndex(src *Source, base string) ([]byte, bool) {
	for _, ext := range indexExts {
		p, err := u.listPath(src, base+ext)
		if err != nil || !fileExists(p) {
			continue
		}

		if data, err := readList(p); err == nil {
			return data, true
		}
	}

	return nil, false
}

// storeUncompressed writes an index as the plain list file and drops the
// other compressions.
func (u *updater) storeUncompressed(src *Source, base, dest string, data []byte) error {
	if err := httpclient.AtomicWrite(dest, func(w io.Writer) error {
		_, err := io.Copy(w, bytes.NewReader(data))

		return err //nolint:wrapcheck // file system error names the path
	}); err != nil {
		return err //nolint:wrapcheck // names the path
	}

	u.pruneVariants(src, base, dest)

	return nil
}

// fetchFromBases fetches a file under the dists directory from the first base
// that serves it.
func (u *updater) fetchFromBases(
	ctx context.Context, src *Source, fr *fetchedRelease, relPath string, maxBytes int64,
) ([]byte, error) {
	var lastErr error

	for _, base := range fr.bases {
		data, err := u.fetchBytes(ctx, distURLBase(base, src, relPath), maxBytes)
		if err == nil {
			return data, nil
		}

		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}

	if lastErr == nil {
		lastErr = errors.New("no mirror")
	}

	return nil, lastErr
}
