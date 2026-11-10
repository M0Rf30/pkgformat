package httpclient_test

import (
	stderrors "errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/M0Rf30/pkgformat/httpclient"
)

func TestHTTPStatusError_ErrorString(t *testing.T) {
	e := &httpclient.HTTPStatusError{Code: 404, URL: "https://example.test/repo"}
	got := e.Error()

	if !strings.Contains(got, "404") || !strings.Contains(got, "https://example.test/repo") {
		t.Fatalf("Error() = %q, want code + URL", got)
	}
}

func TestHTTPStatusError_IsClientError(t *testing.T) {
	cases := []struct {
		code int
		want bool
	}{
		{399, false},
		{400, true},
		{404, true},
		{499, true},
		{500, false},
		{503, false},
	}

	for _, tc := range cases {
		e := &httpclient.HTTPStatusError{Code: tc.code}
		if got := e.IsClientError(); got != tc.want {
			t.Errorf("IsClientError(%d) = %v, want %v", tc.code, got, tc.want)
		}
	}
}

func TestCheckStatus_2xxReturnsNil(t *testing.T) {
	for _, code := range []int{200, 201, 204, 299} {
		resp := &http.Response{StatusCode: code}
		if err := httpclient.CheckStatus(resp, "https://example.test"); err != nil {
			t.Errorf("httpclient.CheckStatus(%d) returned %v, want nil", code, err)
		}
	}
}

func TestCheckStatus_NonSuccessReturnsTypedError(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusServiceUnavailable}

	err := httpclient.CheckStatus(resp, "https://example.test/key")
	if err == nil {
		t.Fatal("httpclient.CheckStatus(503) returned nil, want error")
	}

	var statusErr *httpclient.HTTPStatusError
	if !stderrors.As(err, &statusErr) {
		t.Fatalf("CheckStatus error is not *httpclient.HTTPStatusError: %T", err)
	}

	if statusErr.Code != 503 {
		t.Errorf("Code = %d, want 503", statusErr.Code)
	}

	if statusErr.URL != "https://example.test/key" {
		t.Errorf("URL = %q, want %q", statusErr.URL, "https://example.test/key")
	}
}

func TestLimitedBody_CapsAtDefault(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader("hello"))}

	r := httpclient.LimitedBody(resp)

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if string(got) != "hello" {
		t.Errorf("body = %q, want %q", got, "hello")
	}
}

func TestLimitedBodyN_RespectsTighterCap(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader("abcdefghij"))}

	got, err := io.ReadAll(httpclient.LimitedBodyN(resp, 4))
	if !stderrors.Is(err, httpclient.ErrTooLarge) {
		t.Fatalf("ReadAll error = %v, want ErrTooLarge", err)
	}

	if string(got) != "abcd" {
		t.Errorf("body = %q, want %q", got, "abcd")
	}
}

func TestLimitedBodyN_NonPositiveFallsBackToDefault(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader("xyz"))}

	got, err := io.ReadAll(httpclient.LimitedBodyN(resp, 0))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if string(got) != "xyz" {
		t.Errorf("body = %q, want %q", got, "xyz")
	}
}

func TestNew_Defaults(t *testing.T) {
	c := httpclient.New(httpclient.Options{})

	if c.HTTP().Timeout != httpclient.DefaultTimeout {
		t.Errorf("Client timeout = %v, want %v", c.HTTP().Timeout, httpclient.DefaultTimeout)
	}

	custom := &http.Client{Timeout: time.Second}
	if got := httpclient.New(httpclient.Options{HTTPClient: custom}).HTTP(); got != custom {
		t.Error("Options.HTTPClient must be used as is")
	}
}

func TestUpgradeToHTTPS(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"plain http", "http://archive.ubuntu.com/ubuntu/", "https://archive.ubuntu.com/ubuntu/", true},
		{
			"explicit port 80 is stripped",
			"http://archive.ubuntu.com:80/ubuntu/", "https://archive.ubuntu.com/ubuntu/", true,
		},
		{
			"non-80 port kept as-is",
			"http://mirror.example.com:8080/repo/", "https://mirror.example.com:8080/repo/", true,
		},
		{"ipv6 host with port 80 is stripped", "http://[::1]:80/repo/", "https://[::1]/repo/", true},
		{"ipv6 host without port", "http://[::1]/repo/", "https://[::1]/repo/", true},
		{"already https", "https://archive.ubuntu.com/ubuntu/", "", false},
		{"unsupported scheme", "ftp://archive.ubuntu.com/ubuntu/", "", false},
		{"malformed url", "http://%zz", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := httpclient.UpgradeToHTTPS(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("UpgradeToHTTPS(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
			}

			if ok && got != tc.want {
				t.Errorf("UpgradeToHTTPS(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
