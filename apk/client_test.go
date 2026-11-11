package apk

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/M0Rf30/pkgformat/httpclient"
)

// repoFixture serves a signed repository: one index and the package files.
type repoFixture struct {
	server  *httptest.Server
	keysDir string
	pkgs    []Package
	mu      sync.Mutex
	files   map[string][]byte // path -> body
}

func (fx *repoFixture) set(path string, body []byte) {
	fx.mu.Lock()
	defer fx.mu.Unlock()

	if body == nil {
		delete(fx.files, path)

		return
	}

	fx.files[path] = body
}

func (fx *repoFixture) get(path string) ([]byte, bool) {
	fx.mu.Lock()
	defer fx.mu.Unlock()

	b, ok := fx.files[path]

	return b, ok
}

func fastHTTP() *httpclient.Client {
	return httpclient.New(httpclient.Options{Retry: httpclient.RetryPolicy{Attempts: 2, BaseDelay: -1}})
}

func newRepo(t *testing.T, signer *Signer) *repoFixture {
	t.Helper()

	fx := &repoFixture{files: map[string][]byte{}, keysDir: t.TempDir()}

	pemKey, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(fx.keysDir, signer.KeyName()), pemKey, 0o644); err != nil {
		t.Fatal(err)
	}

	add := func(name, version, arch string, depends, provides []string) {
		spec := &Spec{Info: Info{
			Name: name, Version: version, Arch: arch, Description: name, Depends: depends,
			Provides: provides,
		}}

		var buf bytes.Buffer

		pkg, err := WritePackage(&buf, spec, WriteOptions{Signer: signer, TempDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}

		fx.pkgs = append(fx.pkgs, *pkg)
		fx.set("/main/x86_64/"+name+"-"+version+".apk", buf.Bytes())
	}

	add("app", "1.0-r0", "x86_64", []string{"libfoo>=1.0", "so:libbar.so.1", "!conflict"}, nil)
	add("libfoo", "1.1-r0", "x86_64", nil, nil)
	add("libbar", "2.0-r0", "x86_64", nil, []string{"so:libbar.so.1=2"})
	add("docs", "1.0-r0", "noarch", nil, nil)

	idx, err := BuildIndex(fx.pkgs, "test", signer)
	if err != nil {
		t.Fatal(err)
	}

	fx.set("/main/x86_64/APKINDEX.tar.gz", idx)

	fx.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := fx.get(r.URL.Path)
		if !ok {
			http.NotFound(w, r)

			return
		}

		_, _ = w.Write(body)
	}))
	t.Cleanup(fx.server.Close)

	return fx
}

func (fx *repoFixture) options(extra ...func(*ClientOptions)) ClientOptions {
	o := ClientOptions{
		Repos: []Repo{{URL: fx.server.URL + "/main"}}, Arch: "x86_64",
		KeysDir: fx.keysDir, Algorithms: []SigAlgorithm{SigRSASHA256}, HTTP: fastHTTP(),
	}
	for _, f := range extra {
		f(&o)
	}

	return o
}

func TestClient_updateAndDownload(t *testing.T) {
	fx := newRepo(t, testSigner(t))

	cache := filepath.Join(t.TempDir(), "cache")

	c, err := NewClient(fx.options(func(o *ClientOptions) { o.CacheDir = cache }))
	if err != nil {
		t.Fatal(err)
	}

	up, err := c.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if n, _ := up.Stats(); n != 4 || len(up.Failures) != 0 {
		t.Fatalf("%d packages, failures %v", n, up.Failures)
	}

	sum := sha1.Sum([]byte(fx.server.URL + "/main/x86_64/APKINDEX.tar.gz"))
	if got, err := os.ReadFile(filepath.Join(cache, "APKINDEX."+hex.EncodeToString(sum[:])+".tar.gz")); err != nil ||
		!bytes.Equal(got, mustGet(t, fx, "/main/x86_64/APKINDEX.tar.gz")) {
		t.Fatalf("cache copy: %v", err)
	}

	res, err := up.Solve(SolveRequest{World: []string{"app"}})
	if err != nil {
		t.Fatal(err)
	}

	var order []string
	for _, p := range res.Packages {
		order = append(order, p.Name)
	}

	if strings.Join(order, " ") != "libfoo libbar app" {
		t.Fatalf("order %q", order)
	}

	dest := t.TempDir()

	docs, _ := up.Lookup("docs")

	paths, err := c.Download(context.Background(), dest, append(res.Packages, docs)...)
	if err != nil {
		t.Fatal(err)
	}

	if len(paths) != 4 {
		t.Fatalf("paths %q", paths)
	}

	for i, p := range paths {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}

		pkg := append(res.Packages, docs)[i]
		if !bytes.Equal(got, mustGet(t, fx, "/main/x86_64/"+pkg.FileName())) {
			t.Fatalf("%s differs", p)
		}
	}
}

func TestClient_skipsBadRepos(t *testing.T) {
	fx := newRepo(t, testSigner(t))

	other, err := NewSigner("other.rsa.pub", testKey(t), SigRSASHA256)
	if err != nil {
		t.Fatal(err)
	}

	// A second repository signed by a key nobody trusts, and a missing one.
	untrusted := newRepo(t, other)
	untrusted.keysDir = fx.keysDir

	c, err := NewClient(fx.options(func(o *ClientOptions) {
		o.Repos = []Repo{
			{URL: untrusted.server.URL + "/main"},
			{URL: fx.server.URL + "/gone"},
			{URL: fx.server.URL + "/main", Tag: "t"},
		}
	}))
	if err != nil {
		t.Fatal(err)
	}

	up, err := c.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(up.Failures) != 2 || !errors.Is(up.Failures[0], ErrUntrusted) {
		t.Fatalf("failures %v", up.Failures)
	}

	var re *RepoError
	if !errors.As(up.Failures[1], &re) || re.Repo.URL != fx.server.URL+"/gone" {
		t.Fatalf("failure %v", up.Failures[1])
	}

	if p, ok := up.Lookup("app"); !ok || p.Repo.Tag != "t" {
		t.Fatalf("app from %+v", p)
	}
}

func TestClient_noIndex(t *testing.T) {
	fx := newRepo(t, testSigner(t))

	c, err := NewClient(fx.options(func(o *ClientOptions) { o.Repos = []Repo{{URL: fx.server.URL + "/gone"}} }))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.Update(context.Background()); !errors.Is(err, ErrNoIndex) {
		t.Fatalf("got %v", err)
	}
}

func TestClient_insecure(t *testing.T) {
	fx := newRepo(t, testSigner(t))

	c, err := NewClient(ClientOptions{
		Repos: []Repo{{URL: fx.server.URL + "/main"}}, Arch: "x86_64", InsecureSkipVerify: true, HTTP: fastHTTP(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNewClient_options(t *testing.T) {
	base := func() ClientOptions {
		return ClientOptions{
			Repos: []Repo{{URL: "https://example.org/main"}}, Arch: "x86_64",
			KeysDir: t.TempDir(), Algorithms: []SigAlgorithm{SigRSASHA1},
		}
	}

	pemKey, err := testSigner(t).PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}

	withKey := func() ClientOptions {
		o := base()
		if err := os.WriteFile(filepath.Join(o.KeysDir, "k.rsa.pub"), pemKey, 0o644); err != nil {
			t.Fatal(err)
		}

		return o
	}

	for name, tc := range map[string]struct {
		mutate func(*ClientOptions)
		want   error
	}{
		"no repos":     {func(o *ClientOptions) { o.Repos = nil }, ErrInvalidOptions},
		"bad arch":     {func(o *ClientOptions) { o.Arch = "../x" }, ErrInvalidOptions},
		"empty arch":   {func(o *ClientOptions) { o.Arch = "" }, ErrInvalidOptions},
		"ftp repo":     {func(o *ClientOptions) { o.Repos = []Repo{{URL: "ftp://x/y"}} }, ErrInvalidOptions},
		"hostless":     {func(o *ClientOptions) { o.Repos = []Repo{{URL: "https:///y"}} }, ErrInvalidOptions},
		"garbage url":  {func(o *ClientOptions) { o.Repos = []Repo{{URL: "http://%zz"}} }, ErrInvalidOptions},
		"no trust":     {func(o *ClientOptions) { o.KeysDir = "" }, ErrNoKeyring},
		"both":         {func(o *ClientOptions) { o.InsecureSkipVerify = true }, ErrInvalidOptions},
		"no algorithm": {func(o *ClientOptions) { o.Algorithms = nil }, ErrNoAlgorithm},
	} {
		t.Run(name, func(t *testing.T) {
			o := withKey()
			tc.mutate(&o)

			if _, err := NewClient(o); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("empty keys dir", func(t *testing.T) {
		if _, err := NewClient(base()); !errors.Is(err, ErrNoKeyring) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("missing keys dir", func(t *testing.T) {
		o := base()
		o.KeysDir = filepath.Join(o.KeysDir, "missing")

		if _, err := NewClient(o); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("valid", func(t *testing.T) {
		if _, err := NewClient(withKey()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestClient_downloadChecks(t *testing.T) {
	fx := newRepo(t, testSigner(t))

	c, err := NewClient(fx.options())
	if err != nil {
		t.Fatal(err)
	}

	up, err := c.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	app, _ := up.Lookup("app")
	libfoo, _ := up.Lookup("libfoo")

	t.Run("wrong content", func(t *testing.T) {
		// The server answers app's URL with another valid package.
		orig, _ := fx.get("/main/x86_64/app-1.0-r0.apk")
		other, _ := fx.get("/main/x86_64/libfoo-1.1-r0.apk")

		fx.set("/main/x86_64/app-1.0-r0.apk", other)
		defer fx.set("/main/x86_64/app-1.0-r0.apk", orig)

		dest := t.TempDir()

		_, err := c.Download(context.Background(), dest, app)
		if !errors.Is(err, ErrPackageMismatch) {
			t.Fatalf("got %v", err)
		}

		if _, err := os.Stat(filepath.Join(dest, "app-1.0-r0.apk")); !os.IsNotExist(err) {
			t.Fatalf("mismatching file kept: %v", err)
		}
	})

	t.Run("not a package", func(t *testing.T) {
		fx.set("/main/x86_64/libfoo-1.1-r0.apk", []byte("<html>captive portal</html>"))

		_, err := c.Download(context.Background(), t.TempDir(), libfoo)
		if !errors.Is(err, ErrInvalidPackage) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("missing", func(t *testing.T) {
		fx.set("/main/x86_64/libfoo-1.1-r0.apk", nil)

		if _, err := c.Download(context.Background(), t.TempDir(), libfoo); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("oversized", func(t *testing.T) {
		big := *libfoo
		big.Size = 10

		fx.set("/main/x86_64/libfoo-1.1-r0.apk", bytes.Repeat([]byte{1}, 4096))

		if _, err := c.Download(context.Background(), t.TempDir(), &big); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("size differs from index", func(t *testing.T) {
		wrong := *libfoo
		wrong.Size++

		raw, _ := mustWriteFixture(t)
		fx.set("/main/x86_64/libfoo-1.1-r0.apk", raw)

		if _, err := c.Download(context.Background(), t.TempDir(), &wrong); err == nil {
			t.Fatal("no error")
		}
	})

	for name, mutate := range map[string]func(*RepoPackage){
		"name traversal":    func(p *RepoPackage) { p.Name = "../evil" },
		"version traversal": func(p *RepoPackage) { p.Version = "1/../2" },
		"arch traversal":    func(p *RepoPackage) { p.IndexArch = ".." },
		"no repo":           func(p *RepoPackage) { p.Repo.URL = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *libfoo
			mutate(&bad)

			if _, err := c.Download(context.Background(), t.TempDir(), &bad); !errors.Is(err, ErrInvalidPackage) {
				t.Fatalf("got %v", err)
			}
		})
	}

	if _, err := c.Download(context.Background(), t.TempDir(), nil); !errors.Is(err, ErrPackageNotFound) {
		t.Fatalf("nil package: %v", err)
	}
}

func mustWriteFixture(t *testing.T) ([]byte, *Package) {
	t.Helper()

	return mustWrite(t, sampleSpec(), WriteOptions{TempDir: t.TempDir()})
}

func TestClient_insecureStillChecksIndexEntries(t *testing.T) {
	fx := newRepo(t, testSigner(t))

	c, err := NewClient(ClientOptions{
		Repos: []Repo{{URL: fx.server.URL + "/main"}}, Arch: "x86_64", InsecureSkipVerify: true, HTTP: fastHTTP(),
	})
	if err != nil {
		t.Fatal(err)
	}

	up, err := c.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	libfoo, _ := up.Lookup("libfoo")
	raw, _ := mustWriteFixture(t)
	fx.set("/main/x86_64/libfoo-1.1-r0.apk", raw)

	// An index entry without a size leaves the checksum as the only check.
	noSize := *libfoo
	noSize.Size = 0

	if _, err := c.Download(context.Background(), t.TempDir(), &noSize); !errors.Is(err, ErrPackageMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestClient_cancelled(t *testing.T) {
	fx := newRepo(t, testSigner(t))

	c, err := NewClient(fx.options())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.Update(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestClient_indexURL(t *testing.T) {
	c, err := NewClient(ClientOptions{
		Repos: []Repo{{URL: "https://example.org/a"}}, Arch: "aarch64", InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := c.IndexURL(Repo{URL: "https://example.org/a"}); got != "https://example.org/a/aarch64/APKINDEX.tar.gz" {
		t.Fatal(got)
	}
}

func mustGet(t *testing.T, fx *repoFixture, path string) []byte {
	t.Helper()

	b, ok := fx.get(path)
	if !ok {
		t.Fatalf("%s not served", path)
	}

	return b
}
