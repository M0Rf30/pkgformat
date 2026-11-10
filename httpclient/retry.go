package httpclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// IsRetryable reports whether err looks like a transient network failure
// worth retrying: transport-level errors (DNS, connection reset or refused,
// timeouts, mid-body EOF) and HTTP 408, 429 and 5xx responses.
//
// A transfer that ended with the wrong length (ErrBadLength) is retryable too:
// the retry starts from a clean file. Context cancellation, response-size caps
// and all other HTTP 4xx codes are not retryable: they are definitive answers,
// not blips.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	if errors.Is(err, ErrTooLarge) || isPermanentTransportError(err) {
		return false
	}

	if errors.Is(err, ErrBadLength) {
		return true
	}

	if statusErr, ok := errors.AsType[*HTTPStatusError](err); ok {
		code := statusErr.Code

		return code == 408 || code == 429 || code >= 500
	}

	// Mid-body truncation (server closed early) surfaces as unexpected EOF.
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}

	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EPIPE) {
		return true
	}

	if _, ok := errors.AsType[net.Error](err); ok {
		return true
	}

	// Any other transport-level failure (http.Client.Do wraps everything in
	// *url.Error): DNS hiccups, TLS handshake resets, proxy errors.
	var urlErr *url.Error

	return errors.As(err, &urlErr)
}

// isPermanentTransportError reports whether err is a definitive transport
// failure that retrying cannot fix: certificate verification problems,
// redirect-limit exhaustion and unsupported URL schemes.
func isPermanentTransportError(err error) bool {
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return true
	}

	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
		return true
	}

	if _, ok := errors.AsType[x509.HostnameError](err); ok {
		return true
	}

	if _, ok := errors.AsType[x509.CertificateInvalidError](err); ok {
		return true
	}

	// net/http reports these as plain errors.New values wrapped in *url.Error.
	msg := err.Error()

	return strings.Contains(msg, "stopped after") && strings.Contains(msg, "redirects") ||
		strings.Contains(msg, "unsupported protocol scheme")
}

// WithRetry runs fn until it succeeds, fails with a non-retryable error, or
// the client's retry budget is exhausted. label identifies the fetch in retry
// logs (typically the URL). The last error is returned verbatim so callers can
// still classify it (errors.As on HTTPStatusError, and so on).
//
// Between attempts WithRetry sleeps an exponentially growing delay with ±25%
// jitter so concurrent workers hitting the same flaky mirror do not retry in
// lockstep; cancelling ctx ends the wait.
//
// fn must be safe to re-run from scratch: the Fetch methods re-issue the full
// request and rewrite their output atomically, so a half-read body from a
// failed attempt is never observable.
func (c *Client) WithRetry(ctx context.Context, label string, fn func() error) error {
	attempts, baseDelay := c.retry.Attempts, c.retry.BaseDelay

	var err error

	for attempt := 1; attempt <= attempts; attempt++ {
		err = fn()
		if err == nil || !IsRetryable(err) {
			return err
		}

		if attempt == attempts {
			break
		}

		delay := backoffDelay(baseDelay, attempt)

		if c.logger != nil {
			c.logger.LogAttrs(ctx, slog.LevelWarn, "transient fetch failure, retrying",
				slog.String("url", label),
				slog.Int("attempt", attempt),
				slog.Int("max_attempts", attempts),
				slog.Duration("retry_in", delay.Round(time.Millisecond)),
				slog.Any("error", err))
		}

		select {
		case <-ctx.Done():
			return err
		case <-time.After(delay):
		}
	}

	return err
}

// maxBackoff bounds one backoff interval, before jitter.
const maxBackoff = 5 * time.Minute

// backoffDelay computes the sleep before retry number attempt (1-based):
// baseDelay·2^(attempt−1) with ±25% jitter.
func backoffDelay(baseDelay time.Duration, attempt int) time.Duration {
	if baseDelay <= 0 {
		return 0
	}

	delay := maxBackoff
	if shift := attempt - 1; shift < 30 && baseDelay < maxBackoff>>shift {
		delay = baseDelay << shift
	}

	// math/rand is fine here: this is backoff spreading, not a security
	// boundary.
	jitter := time.Duration(rand.Int64N(int64(delay)/2+1)) - delay/4 //nolint:gosec

	return delay + jitter
}
