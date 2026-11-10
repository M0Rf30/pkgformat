package download_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/M0Rf30/pkgformat/download"
	"github.com/M0Rf30/pkgformat/httpclient"
)

var modTime = time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)

// fastOpts retries immediately so retry tests do not sleep.
func fastOpts(attempts int) download.Options {
	return download.Options{Retry: httpclient.RetryPolicy{Attempts: attempts, BaseDelay: -1}}
}

func payload(n int) []byte {
	return bytes.Repeat([]byte("0123456789abcdef"), n/16+1)[:n]
}

func sha256Of(t *testing.T, data []byte) *download.Checksum {
	t.Helper()

	sum := sha256.Sum256(data)

	return &download.Checksum{New: sha256.New, Sum: sum[:]}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func notExist(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s should not exist (stat err = %v)", path, err)
	}
}

func seedPartial(t *testing.T, dest string, data []byte, etag, lastMod string) {
	t.Helper()

	if err := os.WriteFile(dest+".part", data, 0o600); err != nil {
		t.Fatal(err)
	}

	meta := fmt.Sprintf(`{"etag":%q,"last_modified":%q}`, etag, lastMod)
	if err := os.WriteFile(dest+".part.meta", []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadPlain(t *testing.T) {
	data := payload(100_000)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")

	var (
		last  int64
		total int64
		calls int
	)

	err := download.Download(context.Background(), download.Request{
		URL: srv.URL, Dest: dest, Checksum: sha256Of(t, data),
		Progress: func(done, tot int64) { last, total = done, tot; calls++ },
	}, download.Options{})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(mustRead(t, dest), data) {
		t.Error("content mismatch")
	}

	if last != int64(len(data)) || total != int64(len(data)) || calls < 2 {
		t.Errorf("progress last=%d total=%d calls=%d", last, total, calls)
	}

	notExist(t, dest+".part")
	notExist(t, dest+".part.meta")
}

func TestDownloadResumesWithRange(t *testing.T) {
	data := payload(50_000)

	var gotRange, gotIfRange atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRange.Store(r.Header.Get("Range"))
		gotIfRange.Store(r.Header.Get("If-Range"))
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "f", modTime, bytes.NewReader(data))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")
	seedPartial(t, dest, data[:12_345], `"v1"`, "")

	var firstDone int64 = -1

	err := download.Download(context.Background(), download.Request{
		URL: srv.URL, Dest: dest, Checksum: sha256Of(t, data),
		Progress: func(done, _ int64) {
			if firstDone < 0 {
				firstDone = done
			}
		},
	}, download.Options{})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(mustRead(t, dest), data) {
		t.Error("content mismatch")
	}

	if gotRange.Load() != "bytes=12345-" || gotIfRange.Load() != `"v1"` {
		t.Errorf("Range=%v If-Range=%v", gotRange.Load(), gotIfRange.Load())
	}

	if firstDone != 12_345 {
		t.Errorf("first progress report = %d, want the kept prefix 12345", firstDone)
	}
}

func TestDownloadResumeUsesLastModifiedWithoutETag(t *testing.T) {
	data := payload(10_000)

	var gotIfRange atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfRange.Store(r.Header.Get("If-Range"))
		http.ServeContent(w, r, "f", modTime, bytes.NewReader(data))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")
	seedPartial(t, dest, data[:100], "", modTime.Format(http.TimeFormat))

	if err := download.Download(context.Background(), download.Request{URL: srv.URL, Dest: dest}, download.Options{}); err != nil {
		t.Fatal(err)
	}

	if gotIfRange.Load() != modTime.Format(http.TimeFormat) {
		t.Errorf("If-Range = %v", gotIfRange.Load())
	}

	if !bytes.Equal(mustRead(t, dest), data) {
		t.Error("content mismatch")
	}
}

func TestDownloadPartialWithoutValidatorRestarts(t *testing.T) {
	data := payload(10_000)

	var ranged atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			ranged.Store(true)
		}

		_, _ = w.Write(data)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")
	if err := os.WriteFile(dest+".part", []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := download.Download(context.Background(), download.Request{URL: srv.URL, Dest: dest}, download.Options{}); err != nil {
		t.Fatal(err)
	}

	if ranged.Load() || !bytes.Equal(mustRead(t, dest), data) {
		t.Errorf("ranged=%v content ok=%v", ranged.Load(), bytes.Equal(mustRead(t, dest), data))
	}
}

func TestDownloadServerIgnoresRange(t *testing.T) {
	data := payload(20_000)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data) // always 200 with the whole body
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")
	seedPartial(t, dest, data[:5000], `"v1"`, "")

	err := download.Download(context.Background(), download.Request{
		URL: srv.URL, Dest: dest, Checksum: sha256Of(t, data),
	}, download.Options{})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(mustRead(t, dest), data) {
		t.Error("content mismatch: partial was not truncated")
	}
}

func TestDownload416RestartsOnce(t *testing.T) {
	data := payload(20_000)

	var hits, ranged atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)

		if r.Header.Get("Range") != "" {
			ranged.Add(1)
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)

			return
		}

		_, _ = w.Write(data)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")
	seedPartial(t, dest, data[:9000], `"v1"`, "")

	if err := download.Download(context.Background(), download.Request{URL: srv.URL, Dest: dest}, fastOpts(1)); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(mustRead(t, dest), data) {
		t.Error("content mismatch")
	}

	if hits.Load() != 2 || ranged.Load() != 1 {
		t.Errorf("hits=%d ranged=%d, want 2 and 1", hits.Load(), ranged.Load())
	}
}

func TestDownload416WithoutPartialIsStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
	}))
	defer srv.Close()

	err := download.Download(context.Background(),
		download.Request{URL: srv.URL, Dest: filepath.Join(t.TempDir(), "o")}, fastOpts(3))

	var se *download.StatusError
	if !errors.As(err, &se) || se.Code != 416 {
		t.Fatalf("err = %v, want *StatusError 416", err)
	}
}

// TestDownloadETagChangedBetweenAttempts: the first attempt dies mid-body on
// v1; by the retry the file is v2, so If-Range fails and a full v2 body must
// replace the v1 prefix instead of being spliced onto it.
func TestDownloadETagChangedBetweenAttempts(t *testing.T) {
	v1, v2 := payload(40_000), bytes.ToUpper(payload(40_000))

	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("ETag", `"v1"`)
			w.Header().Set("Content-Length", fmt.Sprint(len(v1)))
			_, _ = w.Write(v1[:10_000])
			w.(http.Flusher).Flush()

			// Abort the connection mid-body.
			panic(http.ErrAbortHandler)
		}

		w.Header().Set("ETag", `"v2"`)
		http.ServeContent(w, r, "f", modTime, bytes.NewReader(v2))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")

	err := download.Download(context.Background(), download.Request{
		URL: srv.URL, Dest: dest, Checksum: sha256Of(t, v2),
	}, fastOpts(3))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(mustRead(t, dest), v2) {
		t.Error("v1 prefix was spliced onto v2")
	}

	if hits.Load() != 2 {
		t.Errorf("hits = %d, want 2", hits.Load())
	}
}

// TestDownloadShortBodyResumes: a body shorter than announced is a transient
// failure and the retry continues from the bytes already received.
func TestDownloadShortBodyResumes(t *testing.T) {
	data := payload(30_000)

	var hits atomic.Int32

	var ranges sync.Map

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		ranges.Store(n, r.Header.Get("Range"))

		w.Header().Set("ETag", `"v1"`)

		if n == 1 {
			w.Header().Set("Content-Length", fmt.Sprint(len(data)))
			_, _ = w.Write(data[:7000])
			w.(http.Flusher).Flush()

			panic(http.ErrAbortHandler)
		}

		http.ServeContent(w, r, "f", modTime, bytes.NewReader(data))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")

	err := download.Download(context.Background(), download.Request{
		URL: srv.URL, Dest: dest, Checksum: sha256Of(t, data),
	}, fastOpts(3))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(mustRead(t, dest), data) {
		t.Error("content mismatch")
	}

	if r, _ := ranges.Load(int32(2)); r == "" || r == nil {
		t.Errorf("retry did not resume with a Range request: %v", r)
	}
}

func TestDownloadBadContentRangeIsBadLength(t *testing.T) {
	data := payload(20_000)

	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 && r.Header.Get("Range") != "" {
			// Wrong start: not what was asked for.
			w.Header().Set("Content-Range", "bytes 0-19999/20000")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(data)

			return
		}

		_, _ = w.Write(data)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")
	seedPartial(t, dest, data[:4000], `"v1"`, "")

	// Single attempt: the sentinel surfaces and the partial is cleared.
	err := download.Download(context.Background(), download.Request{URL: srv.URL, Dest: dest}, fastOpts(1))
	if !errors.Is(err, download.ErrBadLength) {
		t.Fatalf("err = %v, want ErrBadLength", err)
	}

	notExist(t, dest+".part")
	notExist(t, dest+".part.meta")

	if !httpclient.IsRetryable(err) {
		t.Error("ErrBadLength must be retryable")
	}

	// With a retry budget the second attempt starts clean and succeeds.
	hits.Store(0)
	seedPartial(t, dest, data[:4000], `"v1"`, "")

	if err := download.Download(context.Background(), download.Request{URL: srv.URL, Dest: dest}, fastOpts(2)); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(mustRead(t, dest), data) {
		t.Error("content mismatch")
	}
}

func TestDownloadChecksumMismatch(t *testing.T) {
	data := payload(10_000)

	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")
	wrong := sha256Of(t, []byte("something else"))

	err := download.Download(context.Background(), download.Request{URL: srv.URL, Dest: dest, Checksum: wrong}, fastOpts(3))
	if !errors.Is(err, download.ErrChecksumMismatch) {
		t.Fatalf("err = %v, want ErrChecksumMismatch", err)
	}

	if hits.Load() != 1 {
		t.Errorf("checksum mismatch was retried: %d hits", hits.Load())
	}

	notExist(t, dest)
	notExist(t, dest+".part")
	notExist(t, dest+".part.meta")
}

// TestDownloadChecksumCoversResumedPrefix: a corrupt kept prefix is caught by
// the digest of the whole file.
func TestDownloadChecksumCoversResumedPrefix(t *testing.T) {
	data := payload(20_000)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "f", modTime, bytes.NewReader(data))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.bin")
	seedPartial(t, dest, bytes.Repeat([]byte("X"), 5000), `"v1"`, "")

	err := download.Download(context.Background(), download.Request{URL: srv.URL, Dest: dest, Checksum: sha256Of(t, data)}, download.Options{})
	if !errors.Is(err, download.ErrChecksumMismatch) {
		t.Fatalf("err = %v, want ErrChecksumMismatch", err)
	}

	notExist(t, dest)
}

func TestParseChecksum(t *testing.T) {
	sum := sha256.Sum256([]byte("abc"))

	c, err := download.ParseChecksum("SHA256", fmt.Sprintf("%x", sum))
	if err != nil || !bytes.Equal(c.Sum, sum[:]) {
		t.Fatalf("ParseChecksum = %v, %v", c, err)
	}

	for _, bad := range [][2]string{{"sha256", "zz"}, {"sha256", "abcd"}, {"crc32", "00"}} {
		if _, err := download.ParseChecksum(bad[0], bad[1]); err == nil {
			t.Errorf("ParseChecksum(%q, %q) succeeded", bad[0], bad[1])
		}
	}

	for _, ok := range [][2]string{
		{"sha1", strings.Repeat("0", 40)}, {"md5", strings.Repeat("0", 32)}, {"sha512", strings.Repeat("0", 128)},
	} {
		if _, err := download.ParseChecksum(ok[0], ok[1]); err != nil {
			t.Errorf("ParseChecksum(%q): %v", ok[0], err)
		}
	}
}

func TestDownloadRetries5xxThenOK(t *testing.T) {
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)

			return
		}

		_, _ = w.Write([]byte("recovered content"))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "out.txt")

	if err := download.Download(context.Background(), download.Request{URL: srv.URL, Dest: dest}, fastOpts(3)); err != nil {
		t.Fatal(err)
	}

	if string(mustRead(t, dest)) != "recovered content" || hits.Load() != 3 {
		t.Errorf("content %q after %d hits", mustRead(t, dest), hits.Load())
	}
}

func TestDownloadHonorsAttemptBudget(t *testing.T) {
	for _, attempts := range []int{1, 2, 4} {
		t.Run(fmt.Sprint(attempts), func(t *testing.T) {
			var hits atomic.Int32

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer srv.Close()

			err := download.Download(context.Background(),
				download.Request{URL: srv.URL, Dest: filepath.Join(t.TempDir(), "o")}, fastOpts(attempts))

			var se *download.StatusError
			if !errors.As(err, &se) || se.Code != 503 {
				t.Fatalf("err = %v, want *StatusError 503", err)
			}

			if int(hits.Load()) != attempts {
				t.Errorf("hits = %d, want %d", hits.Load(), attempts)
			}
		})
	}
}

func TestDownloadNoRetryOn404(t *testing.T) {
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "o")

	err := download.Download(context.Background(), download.Request{URL: srv.URL, Dest: dest}, fastOpts(3))

	var se *download.StatusError
	if !errors.As(err, &se) || se.Code != 404 {
		t.Fatalf("err = %v, want *StatusError 404", err)
	}

	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}

	notExist(t, dest)
}

func TestDownloadCancelKeepsPartialAndStops(t *testing.T) {
	data := payload(1 << 20)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		_, _ = w.Write(data[:64<<10])
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dest := filepath.Join(t.TempDir(), "o")

	err := download.Download(ctx, download.Request{
		URL: srv.URL, Dest: dest,
		// Cancel once data has reached the disk.
		Progress: func(done, _ int64) {
			if done > 0 {
				cancel()
			}
		},
	}, fastOpts(5))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}

	notExist(t, dest)

	if info, statErr := os.Stat(dest + ".part"); statErr != nil || info.Size() == 0 {
		t.Errorf("partial file should be kept for a later resume (stat %v)", statErr)
	}
}

func TestDownloadAlreadyCancelled(t *testing.T) {
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := download.Download(ctx, download.Request{URL: srv.URL, Dest: filepath.Join(t.TempDir(), "o")}, fastOpts(3))
	if !errors.Is(err, context.Canceled) || hits.Load() != 0 {
		t.Errorf("err = %v, hits = %d", err, hits.Load())
	}
}

func TestDownloadSizeCap(t *testing.T) {
	data := payload(10_000)

	t.Run("announced", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) }))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "o")

		err := download.Download(context.Background(), download.Request{URL: srv.URL, Dest: dest, MaxBytes: 100}, fastOpts(3))
		if !errors.Is(err, download.ErrTooLarge) {
			t.Fatalf("err = %v", err)
		}

		notExist(t, dest)
		notExist(t, dest+".part")
	})

	t.Run("streamed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Chunked: no Content-Length to preflight.
			for range 10 {
				_, _ = w.Write(data[:1000])
				w.(http.Flusher).Flush()
			}
		}))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "o")

		err := download.Download(context.Background(), download.Request{URL: srv.URL, Dest: dest, MaxBytes: 2500}, fastOpts(3))
		if !errors.Is(err, download.ErrTooLarge) {
			t.Fatalf("err = %v", err)
		}

		notExist(t, dest)
		notExist(t, dest+".part")
	})

	t.Run("at the cap", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) }))
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "o")
		if err := download.Download(context.Background(), download.Request{URL: srv.URL, Dest: dest, MaxBytes: int64(len(data))}, download.Options{}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDownloadInvalidRequest(t *testing.T) {
	if err := download.Download(context.Background(), download.Request{}, download.Options{}); err == nil {
		t.Error("empty request accepted")
	}

	err := download.Download(context.Background(), download.Request{URL: "invalid://url", Dest: filepath.Join(t.TempDir(), "o")}, fastOpts(2))
	if err == nil {
		t.Error("expected error for unsupported scheme")
	}
}

func TestDownloadUsesGivenClient(t *testing.T) {
	var gotUA atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA.Store(r.UserAgent())
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	var used atomic.Bool

	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used.Store(true)

		return http.DefaultTransport.RoundTrip(r)
	})}

	c := httpclient.New(httpclient.Options{HTTPClient: hc})

	if err := download.Download(context.Background(),
		download.Request{URL: srv.URL, Dest: filepath.Join(t.TempDir(), "f")}, download.Options{Client: c}); err != nil {
		t.Fatal(err)
	}

	if !used.Load() {
		t.Error("custom client not used")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDownloadAllBoundedConcurrency(t *testing.T) {
	const (
		files = 12
		limit = 3
	)

	var current, peak atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := current.Add(1)
		defer current.Add(-1)

		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}

		time.Sleep(20 * time.Millisecond)

		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		_, _ = w.Write([]byte("file:" + r.URL.Path))
	}))
	defer srv.Close()

	dir := t.TempDir()

	reqs := make([]download.Request, 0, files+1)
	for i := range files {
		reqs = append(reqs, download.Request{URL: fmt.Sprintf("%s/f%d", srv.URL, i), Dest: filepath.Join(dir, fmt.Sprintf("f%d", i))})
	}

	reqs = append(reqs, download.Request{URL: srv.URL + "/missing", Dest: filepath.Join(dir, "missing")})

	var progress atomic.Int64

	for i := range reqs {
		reqs[i].Progress = func(done, _ int64) { progress.Add(done) }
	}

	results := download.DownloadAll(context.Background(), reqs, download.Options{
		Concurrency: limit, Retry: httpclient.RetryPolicy{Attempts: 1},
	})

	if len(results) != len(reqs) {
		t.Fatalf("got %d results, want %d", len(results), len(reqs))
	}

	for i, res := range results {
		if res.Request.URL != reqs[i].URL {
			t.Errorf("result %d out of order: %s", i, res.Request.URL)
		}

		if i == files {
			var se *download.StatusError
			if !errors.As(res.Err, &se) || se.Code != 404 {
				t.Errorf("missing: err = %v", res.Err)
			}

			continue
		}

		if res.Err != nil {
			t.Errorf("%s: %v", res.Request.URL, res.Err)

			continue
		}

		if got, want := string(mustRead(t, res.Request.Dest)), fmt.Sprintf("file:/f%d", i); got != want {
			t.Errorf("file %d = %q, want %q", i, got, want)
		}
	}

	if p := peak.Load(); p > limit || p < 2 {
		t.Errorf("peak concurrency = %d, want 2..%d", p, limit)
	}

	if progress.Load() == 0 {
		t.Error("no progress reported")
	}
}

func TestDownloadAllCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dir := t.TempDir()
	reqs := []download.Request{{URL: srv.URL, Dest: filepath.Join(dir, "a")}, {URL: srv.URL, Dest: filepath.Join(dir, "b")}}

	for _, res := range download.DownloadAll(ctx, reqs, download.Options{}) {
		if !errors.Is(res.Err, context.Canceled) {
			t.Errorf("%s: err = %v", res.Request.Dest, res.Err)
		}
	}
}
