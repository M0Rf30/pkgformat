package download

import (
	"context"
	"crypto/md5"  //nolint:gosec // legacy repository checksums, not a security boundary of this package
	"crypto/sha1" //nolint:gosec // legacy repository checksums
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/M0Rf30/pkgformat/httpclient"
)

// DefaultConcurrency is the number of simultaneous transfers DownloadAll runs
// when Options.Concurrency is not positive.
const DefaultConcurrency = 4

// partSuffix and metaSuffix name the sidecar files next to a destination: the
// partial download and the validators it was started with.
const (
	partSuffix = ".part"
	metaSuffix = ".part.meta"
)

// Sentinel errors. Test with errors.Is.
var (
	// ErrBadLength is httpclient.ErrBadLength: the transfer ended with a length
	// other than the announced one. The partial file is discarded before the
	// error is reported, and it is retryable.
	ErrBadLength = httpclient.ErrBadLength
	// ErrTooLarge is httpclient.ErrTooLarge: the file exceeds Request.MaxBytes.
	ErrTooLarge = httpclient.ErrTooLarge
	// ErrChecksumMismatch is returned when the downloaded bytes do not match
	// Request.Checksum. The file is deleted and the error is not retryable.
	ErrChecksumMismatch = errors.New("download: checksum mismatch")
)

// StatusError is returned for a non-2xx answer. It is httpclient.HTTPStatusError,
// so httpclient.IsRetryable classifies it: 408, 429 and 5xx are retried, other
// 4xx are not.
type StatusError = httpclient.HTTPStatusError

// Checksum is an expected digest of the finished file.
type Checksum struct {
	// New constructs the hash, for example sha256.New.
	New func() hash.Hash
	// Sum is the expected digest.
	Sum []byte
}

// ParseChecksum builds a Checksum from an algorithm name (sha256, sha512,
// sha1 or md5, case-insensitive) and a hex digest, as repository indexes
// publish them.
func ParseChecksum(algorithm, hexSum string) (*Checksum, error) {
	var newHash func() hash.Hash

	switch strings.ToLower(algorithm) {
	case "sha256":
		newHash = sha256.New
	case "sha512":
		newHash = sha512.New
	case "sha1":
		newHash = sha1.New
	case "md5":
		newHash = md5.New
	default:
		return nil, fmt.Errorf("download: unsupported checksum algorithm %q", algorithm)
	}

	sum, err := hex.DecodeString(strings.TrimSpace(hexSum))
	if err != nil {
		return nil, fmt.Errorf("download: invalid %s digest: %w", algorithm, err)
	}

	if len(sum) != newHash().Size() {
		return nil, fmt.Errorf("download: %s digest has %d bytes, want %d", algorithm, len(sum), newHash().Size())
	}

	return &Checksum{New: newHash, Sum: sum}, nil
}

// Request describes one file to download.
type Request struct {
	// URL is the source.
	URL string
	// Dest is the final path. The data is written to Dest+".part" and renamed
	// on success, so Dest never holds a partial file. The directory must exist.
	Dest string
	// Checksum, when set, is verified before the rename. The hash also covers
	// the prefix of a resumed partial file.
	Checksum *Checksum
	// MaxBytes caps the file size; zero means no cap. A larger file fails with
	// ErrTooLarge, from the announced length when there is one and from the
	// stream otherwise.
	MaxBytes int64
	// Progress, when set, is called after each chunk with the bytes on disk so
	// far (a resumed prefix included) and the expected total, -1 when unknown.
	// It runs on the transfer's goroutine, so it must be quick and, with
	// DownloadAll, safe to call concurrently with other requests' callbacks.
	Progress func(done, total int64)
}

// Options configures Download and DownloadAll. The zero value is valid.
type Options struct {
	// Client carries the transfers (one transport, one retry classifier). Nil
	// builds a client without an overall timeout, so a large file on a slow
	// link is bounded by the context only.
	Client *httpclient.Client
	// Retry overrides the client's retry policy when it is not the zero value.
	// With a nil Client and a zero Retry the defaults apply.
	Retry httpclient.RetryPolicy
	// Concurrency bounds the transfers of DownloadAll; zero or negative selects
	// DefaultConcurrency.
	Concurrency int
}

// Result is the outcome of one request of DownloadAll.
type Result struct {
	Request Request
	// Err is nil on success.
	Err error
}

// DownloadAll runs the requests with at most opts.Concurrency transfers at a
// time and returns one Result per request, in the order given. A failure does
// not stop the others; cancelling ctx fails the ones not yet finished.
// Requests must not share a Dest.
func DownloadAll(ctx context.Context, reqs []Request, opts Options) []Result {
	results := make([]Result, len(reqs))

	client, release := opts.client()
	defer release()

	opts.Client = client

	limit := opts.Concurrency
	if limit <= 0 {
		limit = DefaultConcurrency
	}

	var group errgroup.Group

	group.SetLimit(limit)

	for i := range reqs {
		results[i].Request = reqs[i]

		group.Go(func() error {
			results[i].Err = Download(ctx, reqs[i], opts)

			return nil
		})
	}

	_ = group.Wait()

	return results
}

// client returns the client to use and a function that releases it.
func (o Options) client() (*httpclient.Client, func()) {
	c, release := o.Client, func() {}

	if c == nil {
		c = httpclient.New(httpclient.Options{Timeout: -1, Retry: o.Retry})
		release = c.HTTP().CloseIdleConnections
	} else if o.Retry != (httpclient.RetryPolicy{}) {
		c = c.WithRetryPolicy(o.Retry)
	}

	return c, release
}

// Download fetches req.URL into req.Dest. A partial file left by an earlier
// attempt or run is continued with a Range request guarded by If-Range (the
// ETag, else Last-Modified, saved beside it), so a file that changed on the server
// is fetched afresh instead of spliced. Transient failures are retried with
// the client's backoff; each retry resumes from the bytes already on disk.
//
// Cancelling ctx stops the transfer and keeps the partial file for the next
// run. The returned error wraps the last failure, so errors.As reaches
// *StatusError and errors.Is reaches the sentinels of this package.
func Download(ctx context.Context, req Request, opts Options) error {
	if req.URL == "" || req.Dest == "" {
		return errors.New("download: request needs a URL and a destination")
	}

	client, release := opts.client()
	defer release()

	return client.WithRetry(ctx, req.URL, func() error {
		return attempt(ctx, client, req)
	})
}

// meta is the sidecar that ties a partial file to the remote file it was
// started from.
type meta struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// validator returns the If-Range value, or "" when the partial cannot be
// resumed safely.
func (m meta) validator() string {
	if m.ETag != "" {
		return m.ETag
	}

	return m.LastModified
}

func readMeta(path string) meta {
	var m meta

	data, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(data, &m)
	}

	return m
}

func responseMeta(h http.Header) meta {
	m := meta{LastModified: h.Get("Last-Modified")}

	// A weak ETag is not valid in If-Range (RFC 9110 §13.1.5).
	if etag := h.Get("ETag"); etag != "" && !strings.HasPrefix(etag, "W/") {
		m.ETag = etag
	}

	return m
}

// attempt runs one transfer, resuming from the partial file. It restarts once
// by itself when the server rejects the range (416).
func attempt(ctx context.Context, client *httpclient.Client, req Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	part := req.Dest + partSuffix
	metaPath := req.Dest + metaSuffix

	restarted := false

	for {
		err := transfer(ctx, client, req, part, metaPath)
		if errors.Is(err, errRangeRejected) && !restarted {
			restarted = true

			discard(part, metaPath)

			continue
		}

		return err
	}
}

// errRangeRejected reports a 416 answer to a resume request.
var errRangeRejected = errors.New("download: range not satisfiable")

func discard(part, metaPath string) {
	_ = os.Remove(part)
	_ = os.Remove(metaPath)
}

// transfer performs one GET and streams it into the partial file.
func transfer(ctx context.Context, client *httpclient.Client, req Request, part, metaPath string) error {
	var offset int64

	saved := readMeta(metaPath)

	if info, err := os.Stat(part); err == nil && info.Mode().IsRegular() {
		offset = info.Size()
	}

	// Without a validator a partial cannot be proven to belong to the file
	// the server holds now, so it is not resumed.
	if saved.validator() == "" {
		offset = 0
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, http.NoBody)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	if offset > 0 {
		httpReq.Header.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
		httpReq.Header.Set("If-Range", saved.validator())
	}

	resp, err := client.HTTP().Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	appendMode, total, err := interpret(resp, req, offset)
	if err != nil {
		if errors.Is(err, ErrBadLength) {
			discard(part, metaPath)
		}

		return err
	}

	if !appendMode {
		offset = 0

		if err := writeMeta(metaPath, responseMeta(resp.Header)); err != nil {
			return err
		}
	}

	return stream(resp.Body, req, part, metaPath, offset, total, appendMode)
}

// interpret validates the response status and headers. It reports whether the
// body continues the partial file and the expected size of the whole file
// (-1 when unknown).
func interpret(resp *http.Response, req Request, offset int64) (appendMode bool, total int64, err error) {
	switch {
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		if offset > 0 {
			return false, 0, errRangeRejected
		}

		return false, 0, &StatusError{Code: resp.StatusCode, URL: req.URL}
	case resp.StatusCode == http.StatusPartialContent && offset > 0:
		start, size, ok := parseContentRange(resp.Header.Get("Content-Range"))
		if !ok || start != offset || (size >= 0 && size < offset) {
			return false, 0, fmt.Errorf("%w: %s answered Content-Range %q to a request from byte %d",
				ErrBadLength, req.URL, resp.Header.Get("Content-Range"), offset)
		}

		total = size
		if total < 0 && resp.ContentLength >= 0 {
			total = offset + resp.ContentLength
		}

		appendMode = true
	default:
		if err := httpclient.CheckStatus(resp, req.URL); err != nil {
			return false, 0, err
		}

		if resp.StatusCode == http.StatusPartialContent {
			// A 206 nobody asked for.
			return false, 0, fmt.Errorf("%w: %s answered 206 to a request without a range", ErrBadLength, req.URL)
		}

		// 200: the server ignored the range or the validator no longer matches;
		// the body is the whole file.
		total = resp.ContentLength
	}

	if total < 0 {
		total = -1
	}

	if req.MaxBytes > 0 && total > req.MaxBytes {
		return false, 0, fmt.Errorf("%w: %s is %d bytes, cap %d", ErrTooLarge, req.URL, total, req.MaxBytes)
	}

	return appendMode, total, nil
}

// parseContentRange parses "bytes start-end/size" (size may be "*", reported
// as -1).
func parseContentRange(v string) (start, size int64, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(v), "bytes ")
	if !found {
		return 0, 0, false
	}

	span, sizeText, found := strings.Cut(rest, "/")
	if !found {
		return 0, 0, false
	}

	startText, _, found := strings.Cut(span, "-")
	if !found {
		return 0, 0, false
	}

	start, err := strconv.ParseInt(startText, 10, 64)
	if err != nil || start < 0 {
		return 0, 0, false
	}

	if sizeText == "*" {
		return start, -1, true
	}

	size, err = strconv.ParseInt(sizeText, 10, 64)
	if err != nil || size < 0 {
		return 0, 0, false
	}

	return start, size, true
}

func writeMeta(path string, m meta) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("download: write resume state: %w", err)
	}

	return nil
}

// stream copies body into the partial file, hashing and reporting progress,
// then verifies and publishes it.
func stream(body io.Reader, req Request, part, metaPath string, offset, total int64, appendMode bool) error {
	flags := os.O_WRONLY | os.O_CREATE
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}

	f, err := os.OpenFile(part, flags, 0o644) //nolint:gosec // downloads are shareable regular files
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	closed := false

	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()

	var sum hash.Hash

	if req.Checksum != nil {
		sum = req.Checksum.New()

		// The digest must cover the whole file, so feed it the kept prefix.
		if offset > 0 {
			if err := hashPrefix(sum, part, offset); err != nil {
				return err
			}
		}
	}

	w := io.Writer(f)
	if sum != nil {
		w = io.MultiWriter(f, sum)
	}

	written, err := copyBody(w, body, req, offset, total)
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			discard(part, metaPath)
		}

		return err
	}

	size := offset + written
	if total >= 0 && size != total {
		discard(part, metaPath)

		return fmt.Errorf("%w: %s delivered %d bytes, announced %d", ErrBadLength, req.URL, size, total)
	}

	if sum != nil {
		if got := sum.Sum(nil); !bytesEqual(got, req.Checksum.Sum) {
			discard(part, metaPath)

			return fmt.Errorf("%w: %s: got %x, want %x", ErrChecksumMismatch, req.URL, got, req.Checksum.Sum)
		}
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("download: %w", err)
	}

	closed = true

	if err := f.Close(); err != nil {
		return fmt.Errorf("download: %w", err)
	}

	if err := os.Rename(part, req.Dest); err != nil {
		return fmt.Errorf("download: %w", err)
	}

	_ = os.Remove(metaPath)

	return nil
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

// hashPrefix feeds the first n bytes of the partial file to h.
func hashPrefix(h hash.Hash, path string, n int64) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	defer func() { _ = f.Close() }()

	if _, err := io.CopyN(h, f, n); err != nil {
		return fmt.Errorf("download: rehash partial file: %w", err)
	}

	return nil
}

// copyBody copies body to w, enforcing the size cap and reporting progress.
func copyBody(w io.Writer, body io.Reader, req Request, offset, total int64) (int64, error) {
	report := func(done int64) {
		if req.Progress != nil {
			req.Progress(done, total)
		}
	}

	report(offset)

	buf := make([]byte, 32<<10)

	var written int64

	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			if req.MaxBytes > 0 && offset+written+int64(n) > req.MaxBytes {
				return written, fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, req.URL, req.MaxBytes)
			}

			if _, err := w.Write(buf[:n]); err != nil {
				return written, fmt.Errorf("download: %w", err)
			}

			written += int64(n)

			report(offset + written)
		}

		if errors.Is(readErr, io.EOF) {
			return written, nil
		}

		if readErr != nil {
			return written, readErr
		}
	}
}
