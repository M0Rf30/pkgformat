package httpclient

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// DefaultMaxBytes caps individual HTTP responses to 2 GiB when the caller
// passes no tighter bound. Package indexes are typically a few MB; .deb, .apk
// and .rpm files top out around a few hundred MB. The cap prevents memory or
// disk exhaustion from a malicious or buggy mirror serving an unbounded
// stream.
const DefaultMaxBytes int64 = 2 << 30

// DefaultTimeout bounds a complete HTTP request (connection, TLS handshake,
// header read, body read) at 10 minutes. Large downloads over slow links
// still fit; stalled mirrors fail rather than hang.
const DefaultTimeout = 10 * time.Minute

// Default retry policy values, applied where a RetryPolicy field is zero.
const (
	DefaultRetryAttempts  = 3
	DefaultRetryBaseDelay = 500 * time.Millisecond
)

// ErrTooLarge is returned when a response body exceeds the configured cap.
var ErrTooLarge = errors.New("httpclient: response body exceeds size cap")

// ErrBadLength is returned when a transfer ends with a different number of
// bytes than the server announced, or when a resumed partial file does not fit
// the remote file. It is retryable: the fix is to discard the partial data and
// start over, which a resumable downloader does before it reports the error.
var ErrBadLength = errors.New("httpclient: transferred length does not match the announced length")

// HTTPStatusError is returned by CheckStatus when the response is not 2xx.
// Callers can use errors.As to extract the status code without parsing the
// Error() string.
type HTTPStatusError struct {
	Code int
	URL  string
}

// Error returns the error message for HTTPStatusError.
func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("httpclient: HTTP %d for %s", e.Code, e.URL)
}

// IsClientError reports whether the status is in the 4xx range. Useful for
// classifying transient repository failures (auth, rate limit, not found) as
// non-fatal against systemic failures (network, 5xx, disk full).
func (e *HTTPStatusError) IsClientError() bool {
	return e.Code >= 400 && e.Code < 500
}

// RetryPolicy controls how a logical fetch is retried on transient failures.
// The zero value selects the defaults.
type RetryPolicy struct {
	// Attempts is the total number of tries, including the first. Zero selects
	// DefaultRetryAttempts; 1 disables retrying.
	Attempts int
	// BaseDelay is the first backoff interval, doubled on every further retry
	// and jittered by ±25%. Zero selects DefaultRetryBaseDelay; a negative
	// value retries immediately.
	BaseDelay time.Duration
}

func (p RetryPolicy) normalized() RetryPolicy {
	if p.Attempts == 0 {
		p.Attempts = DefaultRetryAttempts
	}

	if p.Attempts < 1 {
		p.Attempts = 1
	}

	switch {
	case p.BaseDelay == 0:
		p.BaseDelay = DefaultRetryBaseDelay
	case p.BaseDelay < 0:
		p.BaseDelay = 0
	}

	return p
}

// Options configures a Client. The zero value is valid.
type Options struct {
	// HTTPClient, when set, is used as is and Timeout and Transport are
	// ignored. Leave nil to get a client tuned for metadata-heavy workloads
	// (many small fetches against a handful of mirrors).
	HTTPClient *http.Client
	// Transport replaces the built-in tuned transport.
	Transport http.RoundTripper
	// Timeout bounds one complete request; zero selects DefaultTimeout and a
	// negative value disables the bound (the request context governs).
	Timeout time.Duration
	// Retry is the transient-failure policy of the Fetch methods.
	Retry RetryPolicy
	// UserAgent, when non-empty, is sent with every request the Client builds.
	UserAgent string
	// Logger receives one warning per retried failure. Nil is silent.
	Logger *slog.Logger
}

// Client fetches size-capped, retried HTTP resources. It is safe for
// concurrent use and meant to be shared: it owns one connection pool.
type Client struct {
	http      *http.Client
	retry     RetryPolicy
	userAgent string
	logger    *slog.Logger
}

// New returns a Client configured by opts.
func New(opts Options) *Client {
	hc := opts.HTTPClient

	if hc == nil {
		timeout := opts.Timeout

		switch {
		case timeout == 0:
			timeout = DefaultTimeout
		case timeout < 0:
			timeout = 0
		}

		rt := opts.Transport
		if rt == nil {
			rt = newTransport()
		}

		hc = &http.Client{Timeout: timeout, Transport: rt}
	}

	return &Client{
		http:      hc,
		retry:     opts.Retry.normalized(),
		userAgent: opts.UserAgent,
		logger:    opts.Logger,
	}
}

// WithRetryPolicy returns a Client that shares c's connection pool, timeout, user
// agent and logger but retries according to p.
func (c *Client) WithRetryPolicy(p RetryPolicy) *Client {
	cp := *c
	cp.retry = p.normalized()

	return &cp
}

// HTTP returns the underlying *http.Client, for callers that need to issue
// their own requests over the same connection pool and timeout.
func (c *Client) HTTP() *http.Client { return c.http }

// newTransport tunes the default transport for many small fetches against a
// few mirrors. The stdlib keeps only 2 idle connections per host, which puts
// every concurrent fetch to the same mirror behind a fresh TLS handshake.
func newTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		MaxConnsPerHost:       16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// LimitedBody returns resp.Body capped at DefaultMaxBytes. Reading past the
// cap fails with ErrTooLarge instead of ending in a silent EOF. The caller
// still closes resp.Body.
func LimitedBody(resp *http.Response) io.Reader {
	return LimitedBodyN(resp, DefaultMaxBytes)
}

// LimitedBodyN is LimitedBody with a caller-supplied cap. A non-positive cap
// falls back to DefaultMaxBytes.
func LimitedBodyN(resp *http.Response, maxBytes int64) io.Reader {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	return limitio.Capped(resp.Body, maxBytes, ErrTooLarge)
}

// CheckStatus returns an *HTTPStatusError if resp.StatusCode is not 2xx.
// The caller still owns resp.Body.Close().
func CheckStatus(resp *http.Response, fetchURL string) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPStatusError{Code: resp.StatusCode, URL: fetchURL}
	}

	return nil
}

// UpgradeToHTTPS rewrites a plain-http URL to https. It returns ok=false for
// anything that is not parseable http, including URLs already on https.
//
// It helps recover from networks that reset or drop port-80 connections while
// leaving 443 untouched: many mirrors serve identical content on both
// schemes, so escalating after a transient http failure is safe.
func UpgradeToHTTPS(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" {
		return "", false
	}

	// An explicit ":80" must not survive the scheme swap, because TLS on
	// port 80 fails outright. Any other explicit port is kept as is, on the
	// assumption that it serves TLS too. TrimSuffix leaves the closing "]" of
	// a bracketed IPv6 host intact.
	u.Host = strings.TrimSuffix(u.Host, ":80")

	u.Scheme = "https"

	return u.String(), true
}
