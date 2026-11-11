package apt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/httpclient"
)

// ErrDowngradeToInsecure reports a repository whose Release was signed at the
// last update and is not now. The allow-downgrade-to-insecure source option
// accepts it.
var ErrDowngradeToInsecure = errors.New("apt: repository was signed before and is not any more")

// ErrReleaseFromFuture reports a Release whose Date lies in the future by more
// than the Date-Max-Future of the source (10 seconds by default), which a
// replayed or misdated Release would show. The check-date source option
// disables it.
var ErrReleaseFromFuture = errors.New("apt: release file is not valid yet")

// defaultDateMaxFuture is apt's Acquire::Max-FutureTime.
const defaultDateMaxFuture = 10 * time.Second

// fetchedRelease is a verified Release and where it came from.
type fetchedRelease struct {
	rel *deb.Release
	// bases are the URLs the source's files are fetched from, the mirror the
	// Release came from first.
	bases []string
}

// releaseCache deduplicates Release fetches within one Update. Stock
// sources.list files split one (url, suite) over several deb lines (Ubuntu
// ships main+restricted, universe and multiverse separately), and a deb and a
// deb-src line share one Release; without this every job would download and
// verify the same InRelease again. Failures are cached too, so a dead mirror
// fails each duplicate without a retry storm.
type releaseCache struct {
	mu sync.Mutex
	m  map[string]*releaseCacheEntry
}

type releaseCacheEntry struct {
	once sync.Once
	rel  *fetchedRelease
	err  error
}

// fetch returns the Release for the source, running load at most once per key
// even under concurrent callers.
func (c *releaseCache) fetch(key string, load func() (*fetchedRelease, error)) (*fetchedRelease, error) {
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

// releaseKey identifies the Release a source needs: the same repository read
// under the same trust options.
func releaseKey(src *Source, allowUnverified bool) string {
	var sb strings.Builder

	sb.WriteString(src.URL)
	sb.WriteByte(0)
	sb.WriteString(src.Suite)
	sb.WriteByte(0)
	sb.WriteString(src.SignedBy)
	sb.WriteByte(0)
	fmt.Fprintf(&sb, "%t/%d/%d/%d/%d/%d/%d", allowUnverified, src.Trusted, src.CheckValidUntil, src.CheckDate,
		src.ValidUntilMin, src.ValidUntilMax, src.DateMaxFuture)
	fmt.Fprintf(&sb, "/%d", src.AllowDowngradeToInsecure)

	return sb.String()
}

// trustOf resolves the verification policy of a source: trusted skips the
// check, and the allow-insecure option or the global one lets an unverified
// Release through unless the source says trusted=no.
func (u *updater) trustOf(src *Source) (skip, allowUnverified bool) {
	skip = src.Trusted == SwitchYes
	allowUnverified = (u.opts.AllowUnverified || src.AllowInsecure == SwitchYes) && src.Trusted != SwitchNo

	return skip, allowUnverified
}

// updateRelease returns the verified Release of a source, fetching, checking
// and storing it once per distinct (repository, trust) pair.
func (u *updater) updateRelease(ctx context.Context, src *Source) (*fetchedRelease, error) {
	_, allowUnverified := u.trustOf(src)

	return u.releases.fetch(releaseKey(src, allowUnverified), func() (*fetchedRelease, error) {
		bases, err := expandBase(ctx, src.URL, u.fetchBytes)
		if err != nil {
			return nil, err
		}

		fr, err := u.fetchRelease(ctx, src, bases)
		if err != nil {
			return nil, err
		}

		if err := u.checkRelease(src, fr.rel); err != nil {
			return nil, fmt.Errorf("apt: %s %s: %w", src.URL, src.Suite, err)
		}

		return fr, nil
	})
}

// releasePart is one file of a Release the lists directory keeps.
type releasePart struct {
	name string
	data []byte
}

// fetchRelease fetches and verifies the Release of a source from the first
// base that serves it: InRelease first, then Release with Release.gpg, which
// many third-party repositories still use. The verified files are kept in the
// lists directory, as apt does.
//
// The Release is verified against the trust anchor declared by Signed-By, or
// the default keyrings when unset; a signature that exists and fails to verify
// is fatal whatever AllowUnverified says.
func (u *updater) fetchRelease(ctx context.Context, src *Source, bases []string) (*fetchedRelease, error) {
	skip, allowUnverified := u.trustOf(src)

	var trust deb.Trust

	if !skip {
		keyring, krErr := LoadKeyring(src.SignedBy, u.opts.DefaultKeyrings)
		trust = deb.Trust{
			Keyring:         keyring,
			KeyringErr:      krErr,
			AllowUnverified: allowUnverified,
			Logger:          u.opts.Logger,
			Source:          src.URL,
		}
	}

	var lastErr error

	for i, base := range bases {
		parts, body, signed, err := u.fetchReleaseFrom(ctx, src, base, skip, trust)
		if err != nil {
			var tf *transportFailure
			if errors.As(err, &tf) {
				lastErr = tf.err

				continue
			}

			return nil, err
		}

		rel, err := deb.ParseRelease(body)
		if err != nil {
			return nil, err
		}

		if err := u.storeRelease(src, parts, signed); err != nil {
			return nil, err
		}

		ordered := append([]string{base}, bases[:i]...)
		ordered = append(ordered, bases[i+1:]...)

		return &fetchedRelease{rel: rel, bases: ordered}, nil
	}

	return nil, lastErr
}

// transportFailure marks an error of fetching, which another mirror may not
// have, as against a verification or parse error, which is final.
type transportFailure struct{ err error }

func (e *transportFailure) Error() string { return e.err.Error() }
func (e *transportFailure) Unwrap() error { return e.err }

// fetchReleaseFrom fetches the Release of src from one base. It returns the
// files to keep, the verified text and whether a signature was present.
func (u *updater) fetchReleaseFrom(
	ctx context.Context, src *Source, base string, skipVerify bool, trust deb.Trust,
) (parts []releasePart, body []byte, signed bool, err error) {
	data, inErr := u.fetchBytes(ctx, distURLBase(base, src, "InRelease"), deb.MaxReleaseBytes)
	if inErr == nil {
		body = deb.StripClearsign(data)
		if !skipVerify {
			body, err = trust.VerifyInRelease(data)
			if err != nil {
				return nil, nil, false, err
			}
		}

		signed = bytes.HasPrefix(bytes.TrimLeft(data, "\r\n "), []byte("-----BEGIN PGP SIGNED MESSAGE-----"))

		return []releasePart{{"InRelease", data}}, body, signed, nil
	}

	plain, err := u.fetchBytes(ctx, distURLBase(base, src, "Release"), deb.MaxReleaseBytes)
	if err != nil {
		return nil, nil, false, &transportFailure{err: err}
	}

	if skipVerify {
		return []releasePart{{"Release", plain}}, plain, false, nil
	}

	sig, sigErr := u.fetchBytes(ctx, distURLBase(base, src, "Release.gpg"), deb.MaxReleaseBytes)

	body, err = trust.VerifyReleaseGPG(plain, sig, sigErr)
	if err != nil {
		return nil, nil, false, err
	}

	parts = []releasePart{{"Release", plain}}
	if sigErr == nil {
		parts = append(parts, releasePart{"Release.gpg", sig})
	}

	return parts, body, sigErr == nil, nil
}

// storeRelease writes the verified Release files to the lists directory and
// removes the other forms of the Release, refusing to replace a signed
// repository by an unsigned one (unless the source allows it).
func (u *updater) storeRelease(src *Source, parts []releasePart, signed bool) error {
	names := []string{"InRelease", "Release", "Release.gpg"}
	paths := make(map[string]string, len(names))

	for _, n := range names {
		p, err := u.listPath(src, n)
		if err != nil {
			return err
		}

		paths[n] = p
	}

	if !signed && src.AllowDowngradeToInsecure != SwitchYes && src.Trusted != SwitchYes &&
		(fileExists(paths["InRelease"]) || fileExists(paths["Release.gpg"])) {
		return fmt.Errorf("%w: %s %s", ErrDowngradeToInsecure, src.URL, src.Suite)
	}

	kept := make(map[string]bool, len(parts))

	for _, part := range parts {
		kept[part.name] = true

		if err := httpclient.AtomicWrite(paths[part.name], func(w io.Writer) error {
			_, err := w.Write(part.data)

			return err //nolint:wrapcheck // file system error names the path
		}); err != nil {
			return fmt.Errorf("apt: store %s: %w", part.name, err)
		}
	}

	for _, n := range names {
		if !kept[n] {
			_ = os.Remove(paths[n])
		}
	}

	return nil
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)

	return err == nil && fi.Mode().IsRegular()
}

// checkRelease applies the date rules of a source to a Release: a Date in the
// future (Date-Max-Future) and an expired Valid-Until (Check-Valid-Until,
// Valid-Until-Min and -Max), as apt does. Valid-Until-Max also bounds a Release
// without a Valid-Until to Date plus that many seconds, and Valid-Until-Min
// extends a short one to Date plus that many.
func (u *updater) checkRelease(src *Source, rel *deb.Release) error {
	now := u.now()

	if src.CheckDate.Enabled(true) && !rel.Date.IsZero() {
		maxFuture := src.DateMaxFuture
		if maxFuture == 0 {
			maxFuture = defaultDateMaxFuture
		}

		if rel.Date.After(now.Add(maxFuture)) {
			return fmt.Errorf("%w: dated %s", ErrReleaseFromFuture, rel.Date.UTC().Format(time.RFC3339))
		}
	}

	if !src.CheckValidUntil.Enabled(true) {
		return nil
	}

	valid := rel.ValidUntil

	if !rel.Date.IsZero() {
		if src.ValidUntilMax > 0 {
			if limit := rel.Date.Add(src.ValidUntilMax); valid.IsZero() || limit.Before(valid) {
				valid = limit
			}
		}

		if src.ValidUntilMin > 0 && !valid.IsZero() {
			if floor := rel.Date.Add(src.ValidUntilMin); valid.Before(floor) {
				valid = floor
			}
		}
	}

	check := *rel
	check.ValidUntil = valid

	return check.CheckValidity(now)
}
