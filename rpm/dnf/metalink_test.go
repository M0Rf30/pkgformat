package dnf

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func hexOf(sum []byte) string { return hex.EncodeToString(sum) }

// metalinkXML renders a metalink for repomd, in the shape the Fedora
// mirror manager serves, with the given mirror base URLs.
func metalinkXML(repomd []byte, bases ...string) string {
	m5 := md5.Sum(repomd)
	s1 := sha1.Sum(repomd)
	s256 := sha256.Sum256(repomd)
	s512 := sha512.Sum512(repomd)

	var urls strings.Builder

	for i, b := range bases {
		fmt.Fprintf(&urls, `<url protocol="http" type="http" location="US" preference="%d">%s/repodata/repomd.xml</url>`+"\n", 100-i, b)
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<metalink version="3.0" xmlns="http://www.metalinker.org/" xmlns:mm0="http://fedorahosted.org/mirrormanager">
 <files>
  <file name="repomd.xml">
   <mm0:timestamp>1700000000</mm0:timestamp>
   <size>%d</size>
   <verification>
    <hash type="md5">%s</hash>
    <hash type="sha1">%s</hash>
    <hash type="sha256">%s</hash>
    <hash type="sha512">%s</hash>
   </verification>
   <resources maxconnections="1">
%s   </resources>
  </file>
 </files>
</metalink>`, len(repomd), hexOf(m5[:]), hexOf(s1[:]), hexOf(s256[:]), hexOf(s512[:]), urls.String())
}

// repomdOf returns the repomd.xml a test repository serves.
func (r *testRepo) repomdOf() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.files["/repodata/repomd.xml"]
}

// metalinkServer serves a document that can be replaced.
type metalinkServer struct {
	*httptest.Server

	mu   sync.Mutex
	body string
}

func newMetalinkServer(t *testing.T, body string) *metalinkServer {
	t.Helper()

	m := &metalinkServer{body: body}

	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		_, _ = w.Write([]byte(m.body))
	}))
	t.Cleanup(m.Close)

	return m
}

func (m *metalinkServer) set(body string) {
	m.mu.Lock()
	m.body = body
	m.mu.Unlock()
}

func metalinkSection(link string) string {
	return "[test]\nname=Test\nmetalink=" + link + "\n"
}

func TestMetalinkVerifiesRepomd(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	link := newMetalinkServer(t, metalinkXML(repo.repomdOf(), repo.url()))
	env := newEnv(t, metalinkSection(link.URL))

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := ix.Lookup("a"); !ok {
		t.Error("a is not in the index")
	}
}

func TestMetalinkRejectsAMismatchingRepomd(t *testing.T) {
	good := newTestRepo(t, pkgOf("a", "1"))
	other := newTestRepo(t, pkgOf("b", "1"))
	goodMD := good.repomdOf()

	for name, doc := range map[string]string{
		"sha512 differs": strings.Replace(metalinkXML(goodMD, other.url()),
			hexOf(sum512(goodMD)), strings.Repeat("0", 128), 1),
		"sha256 differs": strings.Replace(metalinkXML(goodMD, other.url()),
			hexOf(sum256(goodMD)), strings.Repeat("0", 64), 1),
		"size differs": strings.Replace(metalinkXML(goodMD, other.url()),
			fmt.Sprintf("<size>%d</size>", len(goodMD)), "<size>1</size>", 1),
		// the mirror serves another repository than the metalink describes
		"another repository": metalinkXML(goodMD, other.url()),
	} {
		t.Run(name, func(t *testing.T) {
			link := newMetalinkServer(t, doc)
			env := newEnv(t, metalinkSection(link.URL))

			err := env.Update(context.Background())
			if !errors.Is(err, ErrMetalinkMismatch) {
				t.Fatalf("err = %v, want ErrMetalinkMismatch", err)
			}

			// nothing was committed
			if _, err := os.Stat(filepath.Join(env.cacheDir, "test", ".baseurl")); err == nil {
				t.Error("a mirror was recorded for a repomd.xml that failed verification")
			}

			if _, err := os.Stat(filepath.Join(env.cacheDir, "test", "repodata", "repomd.xml")); err == nil {
				t.Error("a repomd.xml that failed verification was cached")
			}
		})
	}
}

func sum256(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
func sum512(b []byte) []byte { s := sha512.Sum512(b); return s[:] }

func TestMetalinkSkipsAMirrorServingAnotherRepomd(t *testing.T) {
	bad := newTestRepo(t, pkgOf("b", "1"))
	good := newTestRepo(t, pkgOf("a", "1"))
	link := newMetalinkServer(t, metalinkXML(good.repomdOf(), bad.url(), good.url()))
	env := newEnv(t, metalinkSection(link.URL))

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := readFile(t, filepath.Join(env.cacheDir, "test", ".baseurl")); got != good.url() {
		t.Errorf(".baseurl = %q, want %q", got, good.url())
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got := pkgNamesOf(ix, "a", "b"); got != "a" {
		t.Errorf("index has %q", got)
	}
}

func TestMetalinkRefetchesAStaleCachedRepomd(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	link := newMetalinkServer(t, metalinkXML(repo.repomdOf(), repo.url()))
	env := newEnv(t, metalinkSection(link.URL))

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The repository moves on but its mirror still answers "not modified" to
	// a conditional request (the modification time did not change).
	repo.publish([]repoPkg{pkgOf("a", "2")}, "")
	link.set(metalinkXML(repo.repomdOf(), repo.url()))

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if p, ok := ix.Lookup("a"); !ok || p.Version != "2" {
		t.Errorf("a = %+v, want version 2", p)
	}

	// one conditional request that was answered 304, then the plain one
	if n := repo.count("/repodata/repomd.xml"); n != 3 {
		t.Errorf("repomd.xml was requested %d times, want 3", n)
	}
}

func TestParseMetalink(t *testing.T) {
	t.Run("not a metalink", func(t *testing.T) {
		for _, in := range []string{"", "plain text", "<html><body>no</body></html>", "<metalink><files></files></metalink>", "<metalink"} {
			if _, _, ok := parseMetalink(in); ok {
				t.Errorf("%q parsed as a metalink", in)
			}
		}
	})

	t.Run("the repomd entry is chosen, bad hashes ignored", func(t *testing.T) {
		urls, info, ok := parseMetalink(`<metalink><files>
<file name="other.xml"><resources><url>https://x.example/other</url></resources></file>
<file name="repomd.xml"><size>3</size><verification>
<hash type="sha256">not hex</hash><hash type="crc32">00</hash>
<hash type="sha1"> da39a3ee5e6b4b0d3255bfef95601890afd80709 </hash>
</verification><resources><url> https://y.example/r/repodata/repomd.xml </url></resources></file>
</files></metalink>`)
		if !ok || len(urls) != 1 || urls[0] != "https://y.example/r/repodata/repomd.xml" {
			t.Fatalf("urls = %v, ok = %v", urls, ok)
		}

		if info.size != 3 || len(info.hashes) != 1 {
			t.Errorf("info = %+v", info)
		}

		// the sha1 of the empty file, but the size says 3
		if err := info.verify([]byte("abc")); !errors.Is(err, ErrMetalinkMismatch) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("nothing to verify accepts anything", func(t *testing.T) {
		var none *metalinkInfo
		if err := none.verify([]byte("x")); err != nil {
			t.Error(err)
		}

		if err := (&metalinkInfo{}).verify([]byte("x")); err != nil {
			t.Error(err)
		}
	})
}
