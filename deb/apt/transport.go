package apt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/M0Rf30/pkgformat/download"
	"github.com/M0Rf30/pkgformat/httpclient"
	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// MaxMirrorListBytes caps a mirror list document.
const MaxMirrorListBytes = 1 << 20

// maxMirrors caps how many mirrors of a list are used.
const maxMirrors = 256

// ErrEmptyMirrorList reports a mirror list without a single usable URL.
var ErrEmptyMirrorList = errors.New("apt: mirror list holds no usable URL")

// localPath returns the file a "file:" or "copy:" URL names. ok is false for
// any other URL or for one that names a remote host.
func localPath(rawURL string) (path string, ok bool) {
	rest, found := strings.CutPrefix(rawURL, "file:")
	if !found {
		rest, found = strings.CutPrefix(rawURL, "copy:")
		if !found {
			return "", false
		}
	}

	if auth, after, hasAuth := strings.Cut(strings.TrimPrefix(rest, "//"), "/"); strings.HasPrefix(rest, "//") && hasAuth {
		if auth != "" && auth != "localhost" {
			return "", false
		}

		rest = "/" + after
	}

	p, err := url.PathUnescape(rest)
	if err != nil || !filepath.IsAbs(p) {
		return "", false
	}

	return filepath.Clean(p), true
}

// mirrorListURL returns the URL of the mirror list a "mirror+<scheme>://" or
// "mirror://" base URL names, and whether base is one.
func mirrorListURL(base string) (string, bool) {
	if rest, ok := strings.CutPrefix(base, "mirror+"); ok {
		return rest, true
	}

	if rest, ok := strings.CutPrefix(base, "mirror://"); ok {
		return "http://" + rest, true
	}

	return "", false
}

// isMirrorURL reports whether base names a mirror list.
func isMirrorURL(base string) bool {
	_, ok := mirrorListURL(base)

	return ok
}

// parseMirrorList reads the URLs of a mirror list: one per line, the first
// blank-separated word of each (apt allows trailing options), comments and
// blank lines skipped. Each URL gets a trailing slash.
func parseMirrorList(data []byte) []string {
	var out []string

	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)

		u := fields[0]
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "file:") &&
			!strings.HasPrefix(u, "copy:") {
			continue
		}

		if !strings.HasSuffix(u, "/") {
			u += "/"
		}

		if !slices.Contains(out, u) {
			out = append(out, u)
		}

		if len(out) >= maxMirrors {
			break
		}
	}

	return out
}

// expandBase resolves a base URL to the URLs files are fetched from: the base
// itself, or, for a mirror list, the URLs the list names, in order.
func expandBase(
	ctx context.Context, base string, fetch func(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error),
) ([]string, error) {
	listURL, ok := mirrorListURL(base)
	if !ok {
		return []string{base}, nil
	}

	data, err := fetch(ctx, listURL, MaxMirrorListBytes)
	if err != nil {
		return nil, fmt.Errorf("apt: fetch mirror list %s: %w", listURL, err)
	}

	mirrors := parseMirrorList(data)
	if len(mirrors) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmptyMirrorList, listURL)
	}

	return mirrors, nil
}

// readLocal reads a local file, refusing more than maxBytes.
func readLocal(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err //nolint:wrapcheck // the *PathError names the file
	}

	defer func() { _ = f.Close() }()

	return limitio.ReadAll(f, maxBytes, ErrTooLarge)
}

// schemeError is the error for a URL whose scheme cannot be fetched.
func schemeError(rawURL string) error {
	scheme, _, _ := strings.Cut(rawURL, ":")
	if scheme == "cdrom" {
		return fmt.Errorf("%w: cdrom has no medium to read from", ErrUnsupportedScheme)
	}

	return fmt.Errorf("%w: %q", ErrUnsupportedScheme, scheme)
}

// copyLocal copies a local file to dest atomically, enforcing the size cap
// (download.ErrTooLarge) and, when sum is not nil, its digest
// (download.ErrChecksumMismatch).
func copyLocal(src, dest string, sum *download.Checksum, maxBytes int64) error {
	in, err := os.Open(src)
	if err != nil {
		return err //nolint:wrapcheck // the *PathError names the file
	}

	defer func() { _ = in.Close() }()

	return httpclient.AtomicWrite(dest, func(w io.Writer) error {
		var (
			h   hash.Hash
			dst = w
		)

		if sum != nil {
			h = sum.New()
			dst = io.MultiWriter(w, h)
		}

		var r io.Reader = in
		if maxBytes > 0 {
			// One byte more than allowed, to tell a file at the limit from one over it.
			r = io.LimitReader(in, maxBytes+1)
		}

		n, err := io.Copy(dst, r)
		if err != nil {
			return err //nolint:wrapcheck // the file system error names the path
		}

		if maxBytes > 0 && n > maxBytes {
			return download.ErrTooLarge
		}

		if h != nil && !bytes.Equal(h.Sum(nil), sum.Sum) {
			return download.ErrChecksumMismatch
		}

		return nil
	})
}

// isHTTPURL reports whether raw is an http or https URL.
func isHTTPURL(raw string) bool {
	return strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")
}
