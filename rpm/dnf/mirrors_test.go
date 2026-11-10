package dnf

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func serveText(t *testing.T, body string) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return srv
}

func TestResolveMirrorsPlainList(t *testing.T) {
	srv := serveText(t, "# comment\nhttp://plain.example/os\nhttps://one.example//os/\n\nftp://x/\nhttps://two.example/os\n")
	c := New(Options{})

	got, err := mirrorsOf(c, context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	// https first and only: plain http is the fallback for lists without it.
	want := []string{"https://one.example/os/", "https://two.example/os"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolveMirrorsPlainHTTPOnly(t *testing.T) {
	srv := serveText(t, "http://a.example/os\nhttp://b.example/os\n")
	c := New(Options{})

	got, err := mirrorsOf(c, context.Background(), srv.URL)
	if err != nil || len(got) != 2 {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestResolveMirrorsMetalink(t *testing.T) {
	srv := serveText(t, `<?xml version="1.0"?>
<metalink><files><file name="repomd.xml"><resources>
<url protocol="https" type="https" preference="100">https://m1.example/pub/x86_64/repodata/repomd.xml</url>
<url protocol="http" type="http" preference="99">http://m2.example/pub/x86_64/repodata/repomd.xml</url>
<url protocol="https" type="https" preference="98">https://m3.example//pub/x86_64/repodata/repomd.xml</url>
<url protocol="ftp">ftp://m4.example/pub/repodata/repomd.xml</url>
</resources></file></files></metalink>`)
	c := New(Options{})

	got, err := mirrorsOf(c, context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"https://m1.example/pub/x86_64/", "https://m3.example/pub/x86_64/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolveMirrorsCapped(t *testing.T) {
	var b strings.Builder
	for i := range 20 {
		fmt.Fprintf(&b, "https://m%d.example/os\n", i)
	}

	got, err := mirrorsOf(New(Options{}), context.Background(), serveText(t, b.String()).URL)
	if err != nil || len(got) != maxMirrors || got[0] != "https://m0.example/os" {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestResolveMirrorsEmpty(t *testing.T) {
	for name, body := range map[string]string{
		"nothing":      "",
		"comments":     "# nope\n",
		"only ftp":     "ftp://a/\nfile:///x\n",
		"empty xml":    "<metalink></metalink>",
		"not a mirror": "<html>mirror manager is down</html>",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := mirrorsOf(New(Options{}), context.Background(), serveText(t, body).URL)
			if !errors.Is(err, ErrNoMirror) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestResolveMirrorsRetriesMajorVersion(t *testing.T) {
	var asked atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)

		if strings.Contains(r.URL.RawQuery, "release=9.4") {
			http.NotFound(w, r)

			return
		}

		_, _ = w.Write([]byte("https://major.example/os\n"))
	}))
	defer srv.Close()

	c := New(Options{Releasever: "9.4"})

	got, err := mirrorsOf(c, context.Background(), srv.URL+"/list?release=9.4")
	if err != nil || !reflect.DeepEqual(got, []string{"https://major.example/os"}) {
		t.Errorf("got %v, %v", got, err)
	}

	if asked.Load() != 2 {
		t.Errorf("requests = %d, want 2", asked.Load())
	}
}

func TestResolveMirrorsNoRetryWithoutDottedRelease(t *testing.T) {
	var asked atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := New(Options{Releasever: "9"})
	if _, err := mirrorsOf(c, context.Background(), srv.URL+"/list?release=9"); err == nil {
		t.Error("a 404 list resolved")
	}

	if asked.Load() != 1 {
		t.Errorf("requests = %d, want 1", asked.Load())
	}
}

func TestCandidates(t *testing.T) {
	c := New(Options{Releasever: "9", Arch: "x86_64"})

	t.Run("baseurls expanded, non-http dropped, capped", func(t *testing.T) {
		repo := &Repo{ID: "r", BaseURLs: []string{
			"ftp://x/", "https://a/$releasever/$basearch/", "file:///srv", "https://b/", "https://c/",
			"https://d/", "https://e/", "https://f/",
		}}

		got, err := candidatesOf(c, repo)
		if err != nil {
			t.Fatal(err)
		}

		want := []string{"https://a/9/x86_64", "https://b", "https://c", "https://d", "https://e"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("mirror list when there is no baseurl", func(t *testing.T) {
		srv := serveText(t, "https://m.example/os/\n")

		got, err := candidatesOf(c, &Repo{ID: "r", MirrorList: srv.URL})
		if err != nil || !reflect.DeepEqual(got, []string{"https://m.example/os"}) {
			t.Errorf("got %v, %v", got, err)
		}
	})

	t.Run("nothing usable", func(t *testing.T) {
		_, err := candidatesOf(c, &Repo{ID: "r", BaseURLs: []string{"ftp://x/"}})
		if !errors.Is(err, ErrNoMirror) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestMirrorURL(t *testing.T) {
	for line, want := range map[string]string{
		`<url>https://h/p/repodata/repomd.xml</url>`: "https://h/p/",
		`<url>http://h/p/</url>`:                     "http://h/p/",
		`<url>http://h/p</url>`:                      "http://h/p/",
		`https://h/p/repodata/repomd.xml`:            "https://h/p/",
		`<url>no url here</url>`:                     "",
		``:                                           "",
	} {
		if got, _ := mirrorURL(line); got != want {
			t.Errorf("mirrorURL(%q) = %q, want %q", line, got, want)
		}
	}
}

// mirrorsOf resolves a mirror list over the client's own HTTP client.
func mirrorsOf(c *Client, ctx context.Context, listURL string) ([]string, error) {
	mirrors, _, err := c.resolveMirrors(ctx, c.opts.HTTP, listURL)

	return mirrors, err
}

// candidatesOf lists the candidate mirrors of a repository.
func candidatesOf(c *Client, repo *Repo) ([]string, error) {
	bases, _, err := c.candidates(context.Background(), c.opts.HTTP, repo)

	return bases, err
}
