package httpclient_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/M0Rf30/pkgformat/httpclient"
)

// testClient returns a Client whose retry backoff is shrunk so error-path
// tests that exercise transient failures (5xx, refused connections) do not
// sleep through the production backoff schedule.
func testClient() *httpclient.Client {
	return httpclient.New(httpclient.Options{
		Retry: httpclient.RetryPolicy{Attempts: 3, BaseDelay: time.Millisecond},
	})
}

// TestIsRetryable tests the transient-vs-definitive error classification.
func TestIsRetryable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context canceled", context.Canceled, false},
		{"context deadline", context.DeadlineExceeded, false},
		{"too large", httpclient.ErrTooLarge, false},
		{"http 404", &httpclient.HTTPStatusError{Code: 404, URL: "u"}, false},
		{"http 403", &httpclient.HTTPStatusError{Code: 403, URL: "u"}, false},
		{"http 408", &httpclient.HTTPStatusError{Code: 408, URL: "u"}, true},
		{"http 429", &httpclient.HTTPStatusError{Code: 429, URL: "u"}, true},
		{"http 500", &httpclient.HTTPStatusError{Code: 500, URL: "u"}, true},
		{"http 503", &httpclient.HTTPStatusError{Code: 503, URL: "u"}, true},
		{"unexpected EOF", io.ErrUnexpectedEOF, true},
		{"conn reset", syscall.ECONNRESET, true},
		{"conn refused", syscall.ECONNREFUSED, true},
		{"generic", errors.New("boom"), false},
		{"x509 unknown authority", &url.Error{
			Op: "Get", URL: "https://x",
			Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}},
		}, false},
		{"redirect limit", &url.Error{
			Op: "Get", URL: "https://x", Err: errors.New("stopped after 10 redirects"),
		}, false},
		{"unsupported scheme", &url.Error{
			Op: "Get", URL: "ftp://x", Err: errors.New(`unsupported protocol scheme "ftp"`),
		}, false},
		{"transient url error", &url.Error{
			Op: "Get", URL: "https://x", Err: syscall.ECONNRESET,
		}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := httpclient.IsRetryable(tc.err); got != tc.want {
				t.Errorf("IsRetryable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestFetchBytesRetriesTransient5xx tests that FetchBytes survives a mirror
// that returns 5xx before recovering.
func TestFetchBytesRetriesTransient5xx(t *testing.T) {
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	data, err := testClient().FetchBytes(context.Background(), srv.URL, 1024)
	if err != nil {
		t.Fatalf("FetchBytes failed: %v", err)
	}

	if string(data) != "payload" {
		t.Errorf("unexpected body: %q", data)
	}

	if got := hits.Load(); got != 3 {
		t.Errorf("expected 3 attempts, got %d", got)
	}
}

// TestFetchBytesNoRetryOn404 tests that a definitive 404 is returned
// immediately without burning the retry budget.
func TestFetchBytesNoRetryOn404(t *testing.T) {
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := testClient().FetchBytes(context.Background(), srv.URL, 1024)
	if err == nil {
		t.Fatal("expected error")
	}

	var statusErr *httpclient.HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.Code != http.StatusNotFound {
		t.Errorf("expected HTTP 404 error, got %v", err)
	}

	if got := hits.Load(); got != 1 {
		t.Errorf("expected 1 attempt, got %d", got)
	}
}

// TestFetchBytesRetryBudgetExhausted tests that a permanently failing
// server fails after exactly the configured number of attempts.
func TestFetchBytesRetryBudgetExhausted(t *testing.T) {
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := testClient().FetchBytes(context.Background(), srv.URL, 1024)
	if err == nil {
		t.Fatal("expected error")
	}

	if got := hits.Load(); got != 3 {
		t.Errorf("expected 3 attempts, got %d", got)
	}
}

// TestFetchToFileRetriesTruncatedBody tests that a mid-body disconnect
// (server advertises more bytes than it sends) is retried and leaves a
// complete file on the recovered attempt.
func TestFetchToFileRetriesTruncatedBody(t *testing.T) {
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			// Advertise 100 bytes, send 5, then slam the connection.
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte("trunc"))

			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}

			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()

			return
		}

		_, _ = w.Write([]byte("complete"))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")

	if err := testClient().FetchToFile(context.Background(), srv.URL, dest, 1024); err != nil {
		t.Fatalf("FetchToFile failed: %v", err)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}

	if string(data) != "complete" {
		t.Errorf("unexpected file content: %q", data)
	}

	if got := hits.Load(); got != 2 {
		t.Errorf("expected 2 attempts, got %d", got)
	}
}

// TestFetchBytesConditionalRetries tests that the conditional fetch path is
// covered by the retry loop too.
func TestFetchBytesConditionalRetries(t *testing.T) {
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		_, _ = w.Write([]byte("fresh"))
	}))
	defer srv.Close()

	data, notModified, err := testClient().FetchBytesConditional(
		context.Background(), srv.URL, 1024, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("FetchBytesConditional failed: %v", err)
	}

	if notModified {
		t.Error("expected a fresh body, got notModified")
	}

	if string(data) != "fresh" {
		t.Errorf("unexpected body: %q", data)
	}

	if got := hits.Load(); got != 2 {
		t.Errorf("expected 2 attempts, got %d", got)
	}
}

// TestWithRetryContextCancelled tests that cancellation during backoff
// stops further attempts and surfaces the last error.
func TestWithRetryContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var calls atomic.Int32

	err := testClient().WithRetry(ctx, "test", func() error {
		calls.Add(1)
		cancel() // cancel while "in flight": backoff select must bail out

		return &httpclient.HTTPStatusError{Code: 503, URL: "test"}
	})
	if err == nil {
		t.Fatal("expected error")
	}

	if got := calls.Load(); got != 1 {
		t.Errorf("expected 1 attempt, got %d", got)
	}
}

// TestRetryPolicyNormalization tests that a single attempt disables retrying
// and that a negative delay retries immediately.
func TestRetryPolicySingleAttempt(t *testing.T) {
	c := httpclient.New(httpclient.Options{
		Retry: httpclient.RetryPolicy{Attempts: 1, BaseDelay: -time.Second},
	})

	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if _, err := c.FetchBytes(context.Background(), srv.URL, 1024); err == nil {
		t.Fatal("expected error")
	}

	if got := hits.Load(); got != 1 {
		t.Errorf("expected 1 attempt, got %d", got)
	}
}

// TestRetryPolicyDefaults tests that the zero policy retries DefaultRetryAttempts times.
func TestRetryPolicyDefaults(t *testing.T) {
	c := httpclient.New(httpclient.Options{Retry: httpclient.RetryPolicy{BaseDelay: -1}})

	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if _, err := c.FetchBytes(context.Background(), srv.URL, 1024); err == nil {
		t.Fatal("expected error")
	}

	if got := hits.Load(); got != httpclient.DefaultRetryAttempts {
		t.Errorf("attempts = %d, want %d", got, httpclient.DefaultRetryAttempts)
	}
}

func TestIsRetryableBadLength(t *testing.T) {
	err := fmt.Errorf("transfer: %w", httpclient.ErrBadLength)
	if !httpclient.IsRetryable(err) {
		t.Error("httpclient.ErrBadLength should be retryable")
	}
}

func TestWithRetryPolicyKeepsClientSettings(t *testing.T) {
	base := httpclient.New(httpclient.Options{UserAgent: "ua/1", Retry: httpclient.RetryPolicy{Attempts: 5, BaseDelay: time.Millisecond}})
	derived := base.WithRetryPolicy(httpclient.RetryPolicy{Attempts: 1})

	if derived.HTTP() != base.HTTP() {
		t.Error("derived client must share the HTTP client")
	}

	var hits int

	err := derived.WithRetry(context.Background(), "x", func() error {
		hits++

		return &httpclient.HTTPStatusError{Code: 503}
	})
	if err == nil || hits != 1 {
		t.Errorf("derived policy not applied: hits=%d err=%v", hits, err)
	}

	hits = 0
	_ = base.WithRetry(context.Background(), "x", func() error {
		hits++

		return &httpclient.HTTPStatusError{Code: 503}
	})

	if hits != 5 {
		t.Errorf("base policy changed: hits=%d", hits)
	}
}

func TestNegativeTimeoutDisablesOverallBound(t *testing.T) {
	if got := httpclient.New(httpclient.Options{Timeout: -1}).HTTP().Timeout; got != 0 {
		t.Errorf("Timeout = %v, want 0", got)
	}

	if got := httpclient.New(httpclient.Options{}).HTTP().Timeout; got != httpclient.DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", got, httpclient.DefaultTimeout)
	}
}
