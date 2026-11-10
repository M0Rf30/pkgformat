package httpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// newGet builds a GET request carrying the client's User-Agent.
func (c *Client) newGet(ctx context.Context, rawURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, err
	}

	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	return req, nil
}

// tooLarge wraps ErrTooLarge with the URL and the cap that was exceeded.
func tooLarge(rawURL string, maxBytes int64) error {
	return fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, rawURL, maxBytes)
}

// FetchBytesConditional is like FetchBytes but sends If-Modified-Since when
// ifModSince is non-zero. On HTTP 304 it returns (nil, true, nil) so the
// caller can use its on-disk copy. On 200 it returns (data, false, nil). On
// any other outcome it returns (nil, false, err).
//
// It is the warm-cache primitive that lets a repository client skip
// re-downloading metadata that has not changed on the server. Transient failures
// are retried per the client's RetryPolicy.
func (c *Client) FetchBytesConditional(
	ctx context.Context,
	rawURL string,
	maxBytes int64,
	ifModSince time.Time,
) (body []byte, notModified bool, err error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	err = c.WithRetry(ctx, rawURL, func() error {
		body, notModified, err = c.fetchBytesOnce(ctx, rawURL, maxBytes, ifModSince)

		return err
	})
	if err != nil {
		return nil, false, err
	}

	return body, notModified, nil
}

// FetchBytes downloads rawURL and returns the body, capped at maxBytes; a body
// over the cap fails with ErrTooLarge. A non-positive maxBytes falls back to
// DefaultMaxBytes. Transient failures are retried per the client's
// RetryPolicy.
func (c *Client) FetchBytes(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	data, _, err := c.FetchBytesConditional(ctx, rawURL, maxBytes, time.Time{})

	return data, err
}

// fetchBytesOnce performs a single (optionally conditional) GET attempt.
func (c *Client) fetchBytesOnce(
	ctx context.Context,
	rawURL string,
	maxBytes int64,
	ifModSince time.Time,
) (body []byte, notModified bool, err error) {
	req, err := c.newGet(ctx, rawURL)
	if err != nil {
		return nil, false, err
	}

	if !ifModSince.IsZero() {
		// RFC 7232 If-Modified-Since uses an HTTP-date in UTC.
		req.Header.Set("If-Modified-Since", ifModSince.UTC().Format(http.TimeFormat))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if !ifModSince.IsZero() && resp.StatusCode == http.StatusNotModified {
		return nil, true, nil
	}

	if err := CheckStatus(resp, rawURL); err != nil {
		return nil, false, err
	}

	if resp.ContentLength > maxBytes {
		return nil, false, tooLarge(rawURL, maxBytes)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, false, err
	}

	if int64(len(data)) > maxBytes {
		return nil, false, tooLarge(rawURL, maxBytes)
	}

	return data, false, nil
}

// FetchToFile downloads rawURL and writes it atomically to destPath, capped at
// maxBytes. Content-Length is checked as a cheap preflight when available. A
// non-positive maxBytes falls back to DefaultMaxBytes. Transient failures are
// retried per the client's RetryPolicy; the atomic temp-file and rename write
// guarantees a failed attempt leaves no partial file.
func (c *Client) FetchToFile(ctx context.Context, rawURL, destPath string, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	return c.WithRetry(ctx, rawURL, func() error {
		return c.fetchToFileOnce(ctx, rawURL, destPath, maxBytes)
	})
}

// fetchToFileOnce performs a single download attempt.
func (c *Client) fetchToFileOnce(ctx context.Context, rawURL, destPath string, maxBytes int64) error {
	req, err := c.newGet(ctx, rawURL)
	if err != nil {
		return err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if err := CheckStatus(resp, rawURL); err != nil {
		return err
	}

	// Cheap preflight: reject if Content-Length already exceeds the cap.
	if resp.ContentLength > maxBytes {
		return tooLarge(rawURL, maxBytes)
	}

	return AtomicWrite(destPath, func(w io.Writer) error {
		written, err := io.Copy(w, io.LimitReader(resp.Body, maxBytes+1))
		if err != nil {
			return err
		}

		if written > maxBytes {
			return tooLarge(rawURL, maxBytes)
		}

		return nil
	})
}

// AtomicWrite writes to destPath via a unique temp file in the destination
// directory, fsync and rename, so readers never see a partial file and
// concurrent writers to the same destination never share a temp file. fn
// receives a writer for the temp file; if fn returns an error the temp file
// is removed.
func AtomicWrite(destPath string, fn func(io.Writer) error) error {
	f, err := os.CreateTemp(filepath.Dir(destPath), filepath.Base(destPath)+".*.tmp")
	if err != nil {
		return err
	}

	tmpPath := f.Name()

	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmpPath)

		return err
	}

	// CreateTemp uses 0600; downloads are regular shareable files.
	if err := f.Chmod(0o644); err != nil {
		return fail(err)
	}

	if err := fn(f); err != nil {
		return fail(err)
	}

	if err := f.Sync(); err != nil {
		return fail(err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)

		return err
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)

		return err
	}

	return nil
}
