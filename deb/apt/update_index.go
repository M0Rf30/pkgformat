package apt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/download"
	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// indexExts are the compression suffixes an index list file may carry.
var indexExts = []string{"", ".xz", ".zst", ".gz", ".bz2", ".lz4"}

// indexTask is one index a source asks for. The first of bases (paths relative
// to the dists directory, without a compression suffix) the Release lists is
// the one fetched.
type indexTask struct {
	bases []string
	// what names the index in logs.
	what string
}

// supportedScheme reports whether Update can reach sources of the scheme.
func supportedScheme(src *Source) bool {
	switch src.Scheme() {
	case "http", "https", "file", "copy", "mirror", "mirror+http", "mirror+https", "mirror+file", "mirror+copy":
		return true
	}

	return false
}

// updateSource fetches the Release of a source and the indexes it asks for.
func (u *updater) updateSource(ctx context.Context, src *Source) (int, error) {
	if !supportedScheme(src) {
		return 0, fmt.Errorf("apt: %s: %w", src.URL, schemeError(src.URL))
	}

	fr, err := u.updateRelease(ctx, src)
	if err != nil {
		return 0, err
	}

	tasks := u.indexTasks(src, fr.rel)
	errs := make([]error, len(tasks))

	// Indexes fan out too: they hit one mirror, whose connection limit is
	// what bounds parallelism. Results are stored by task index.
	var wg sync.WaitGroup

	for i, task := range tasks {
		wg.Go(func() { errs[i] = u.fetchIndex(ctx, src, fr, task) })
	}

	wg.Wait()

	n := 0

	var failures []error

	for i, err := range errs {
		if err == nil {
			n++

			continue
		}

		// An index the Release does not list is nothing to fetch; every
		// other failure (network, size or digest mismatch, disk) surfaces.
		if !errors.Is(err, ErrNoPackagesIndex) {
			u.warn("apt: index update failed", "url", src.URL, "index", tasks[i].what, "error", err)

			failures = append(failures, err)
		}
	}

	return n, newUpdateError(failures)
}

// indexTasks lists the indexes src asks for, from its Targets, Languages and
// Architectures.
func (u *updater) indexTasks(src *Source, rel *deb.Release) []indexTask {
	targets := src.EffectiveTargets(u.opts.DefaultLanguages)
	wants := func(name string) bool {
		return slices.ContainsFunc(targets, func(t string) bool {
			// apt names the Contents target Contents-deb.
			return strings.EqualFold(t, name) || (name == "Contents" && strings.EqualFold(t, "Contents-deb"))
		})
	}

	var tasks []indexTask

	add := func(what string, bases ...string) {
		bases = slices.DeleteFunc(bases, func(b string) bool { return b == "" })
		if len(bases) > 0 {
			tasks = append(tasks, indexTask{bases: bases, what: what})
		}
	}

	if src.Flat() {
		if src.IsSource() && wants("Sources") {
			add("Sources", "Sources")
		}

		if !src.IsSource() && wants("Packages") {
			add("Packages", "Packages")
		}

		return tasks
	}

	if src.IsSource() {
		if wants("Sources") {
			for _, comp := range src.Components {
				add(comp+" Sources", deb.IndexPath(comp, "", deb.IndexSources))
			}
		}

		return tasks
	}

	archs := src.EffectiveArchitectures(u.defaultArch)

	if wants("Packages") {
		for _, comp := range src.Components {
			for _, arch := range archs {
				add(comp+" "+arch+" Packages", deb.IndexPath(comp, arch, deb.IndexPackages))
			}
		}
	}

	if wants("Translations") {
		for _, lang := range src.EffectiveLanguages(u.opts.DefaultLanguages) {
			if lang == "" || lang == "none" || lang == "environment" {
				continue
			}

			// de_DE falls back to de, as apt does.
			kinds := []string{deb.IndexTranslationPrefix + lang}
			if short, _, ok := strings.Cut(lang, "_"); ok {
				kinds = append(kinds, deb.IndexTranslationPrefix+short)
			}

			for _, comp := range src.Components {
				bases := make([]string, len(kinds))
				for i, kind := range kinds {
					bases[i] = deb.IndexPath(comp, "", kind)
				}

				add(comp+" Translation-"+lang, bases...)
			}
		}
	}

	if wants("Contents") {
		for _, arch := range archs {
			// Archives list one Contents file for the whole distribution,
			// others one per component.
			add("Contents-"+arch, deb.IndexPath("", arch, deb.IndexContents))

			for _, comp := range src.Components {
				add(comp+" Contents-"+arch, deb.IndexPath(comp, arch, deb.IndexContents))
			}
		}
	}

	return tasks
}

// fetchIndex brings one index up to date: the first alternative the Release
// lists, from the local copy when it is current, by the patches of the
// repository when it has them, otherwise whole. It tries the variants the
// Release lists, best compression first. A transport failure falls through to
// the next variant; if none succeeds the last transport error is returned, so
// the caller sees the real cause.
func (u *updater) fetchIndex(ctx context.Context, src *Source, fr *fetchedRelease, task indexTask) error {
	var (
		base     string
		variants []deb.IndexVariant
	)

	for _, b := range task.bases {
		if v := fr.rel.IndexVariants(b); len(v) > 0 {
			base, variants = b, v

			break
		}
	}

	if len(variants) == 0 {
		return fmt.Errorf("%w: %s", ErrNoPackagesIndex, task.what)
	}

	allowWeak := src.AllowWeak == SwitchYes

	// Warm cache: a list file that already has the size and digest of the
	// freshly verified Release entry needs no download.
	for _, v := range variants {
		d, ok := pickDigest(v.Info, allowWeak)
		if !ok {
			continue
		}

		if dest, err := u.listPath(src, v.Path); err == nil && fileMatchesWith(dest, v.Info.Size, d) {
			return nil
		}
	}

	if u.tryPDiff(ctx, src, fr, base, variants) {
		return nil
	}

	var lastErr error

	tried, weakOnly := false, false

	for _, v := range variants {
		if _, ok := pickDigest(v.Info, allowWeak); !ok {
			weakOnly = weakOnly || hasWeakDigest(v.Info)

			continue
		}

		tried = true

		stop, err := u.fetchIndexVariant(ctx, src, fr, base, v)
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
		return fmt.Errorf("apt: %s: no usable index", task.what)
	}

	if weakOnly {
		return fmt.Errorf("%w: %s", ErrWeakDigest, task.what)
	}

	return fmt.Errorf("%w: %s", ErrNoPackagesIndex, task.what)
}

// indexURLs lists where an index can be fetched from, in order: for every
// mirror its by-hash path when that is on offer, then its plain path (not at
// all when by-hash is forced).
func (u *updater) indexURLs(src *Source, fr *fetchedRelease, relPath string) []string {
	byHash := src.ByHash == ByHashForce ||
		(src.ByHash != ByHashNo && !u.opts.DisableByHash && fr.rel.AcquireByHash)

	var refs []deb.ByHashRef
	if byHash {
		refs = fr.rel.ByHashRefs(relPath)
	}

	var urls []string

	for _, base := range fr.bases {
		if len(refs) > 0 {
			urls = append(urls, distURLBase(base, src, refs[0].Path))
		}

		if src.ByHash != ByHashForce {
			urls = append(urls, distURLBase(base, src, relPath))
		}
	}

	return urls
}

// fetchIndexVariant fetches, verifies and atomically stores one variant of an
// index. stop reports a definitive error (integrity or I/O): no other
// compression variant is tried. A plain transport error leaves it false.
func (u *updater) fetchIndexVariant(
	ctx context.Context, src *Source, fr *fetchedRelease, base string, v deb.IndexVariant,
) (stop bool, err error) {
	entry := v.Info

	dest, err := u.listPath(src, v.Path)
	if err != nil {
		return true, err
	}

	unlock := u.lockPath(dest)
	defer unlock()

	// Also makes duplicate sources queued behind the path lock a no-op.
	digest, _ := pickDigest(entry, src.AllowWeak == SwitchYes)
	if fileMatchesWith(dest, entry.Size, digest) {
		return true, nil
	}

	sum, err := download.ParseChecksum(digest.alg, digest.hex)
	if err != nil || entry.Size < 0 || entry.Size > maxIndexBytes {
		return true, fmt.Errorf("%w: %s lists size %d, %s %q", ErrInvalidIndexEntry, v.Path, entry.Size, digest.alg, digest.hex)
	}

	if digest.weak {
		u.warn("apt: index verified with a weak digest (Allow-Weak)", "path", v.Path, "digest", digest.alg)
	}

	urls := u.indexURLs(src, fr, v.Path)
	if len(urls) == 0 {
		return true, fmt.Errorf("apt: %s: no URL to fetch from", v.Path)
	}

	var lastErr error

	for _, target := range urls {
		err = u.fetchFile(ctx, target, dest, sum, max(entry.Size, 1))
		if err == nil {
			lastErr = nil

			break
		}

		if errors.Is(err, download.ErrChecksumMismatch) || errors.Is(err, download.ErrTooLarge) {
			return true, fmt.Errorf("%w: %s: %w", ErrIntegrity, target, err)
		}

		lastErr = fmt.Errorf("apt: fetch %s: %w", target, err)
	}

	if lastErr != nil {
		return false, lastErr
	}

	// The digest matched; a shorter file than declared still means a lying
	// Release entry, and is refused like a mismatch.
	if fi, statErr := os.Stat(dest); statErr != nil || fi.Size() != entry.Size {
		_ = os.Remove(dest)

		return true, fmt.Errorf("%w: %s: size differs from the %d bytes the Release lists", ErrIntegrity, v.Path, entry.Size)
	}

	u.pruneVariants(src, base, dest)

	return true, nil
}

// fetchFile fetches rawURL into dest, verifying sum and the size cap; a plain
// http fetch that fails transiently is retried over https. file: and copy:
// URLs are copied.
func (u *updater) fetchFile(ctx context.Context, rawURL, dest string, sum *download.Checksum, maxBytes int64) error {
	if p, ok := localPath(rawURL); ok {
		return copyLocal(p, dest, sum, maxBytes)
	}

	if !isHTTPURL(rawURL) {
		return schemeError(rawURL)
	}

	return u.withHTTPSFallback(rawURL, func(target string) error {
		return download.Download(ctx, download.Request{
			URL:      target,
			Dest:     dest,
			Checksum: sum,
			MaxBytes: maxBytes,
		}, download.Options{Client: u.client})
	})
}

// pruneVariants removes the other compressions of an index the lists
// directory holds besides keep, so the loader reads one copy.
func (u *updater) pruneVariants(src *Source, base, keep string) {
	for _, ext := range indexExts {
		p, err := u.listPath(src, base+ext)
		if err != nil || p == keep {
			continue
		}

		_ = os.Remove(p)
	}
}

// readList reads a list file, decompressed by its extension, up to the cap
// of an index.
func readList(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err //nolint:wrapcheck // the *PathError names the file
	}

	rc, err := deb.OpenIndex(f, path)
	if err != nil {
		_ = f.Close()

		return nil, err //nolint:wrapcheck // names the file in the caller
	}

	defer func() { _ = rc.Close() }()

	return limitio.ReadAll(io.Reader(rc), deb.MaxIndexBytes, ErrTooLarge)
}

// ErrWeakDigest is returned for an index that the Release lists with MD5 or
// SHA1 digests only: they cannot vouch for it unless the source sets
// Allow-Weak.
var ErrWeakDigest = errors.New("apt: index listed with weak digests only")

// indexDigest is the digest an index is verified with.
type indexDigest struct {
	alg, hex string
	weak     bool
}

// pickDigest chooses the digest of a Release entry to verify the file with:
// SHA-256, else SHA-512, and with allowWeak SHA-1, else MD5. ok is false when
// none is usable.
func pickDigest(fi deb.FileInfo, allowWeak bool) (indexDigest, bool) {
	switch {
	case fi.SHA256 != "":
		return indexDigest{alg: "sha256", hex: fi.SHA256}, true
	case fi.SHA512 != "":
		return indexDigest{alg: "sha512", hex: fi.SHA512}, true
	case allowWeak && fi.SHA1 != "":
		return indexDigest{alg: "sha1", hex: fi.SHA1, weak: true}, true
	case allowWeak && fi.MD5sum != "":
		return indexDigest{alg: "md5", hex: fi.MD5sum, weak: true}, true
	}

	return indexDigest{}, false
}

// hasWeakDigest reports whether the entry lists a weak digest.
func hasWeakDigest(fi deb.FileInfo) bool { return fi.SHA1 != "" || fi.MD5sum != "" }
