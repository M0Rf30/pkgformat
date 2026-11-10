package dnf

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/M0Rf30/pkgformat/httpclient"
	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

func TestRepoExcludes(t *testing.T) {
	pp := &repodata.PrimaryPackage{Name: "foo", Version: "1.2", Release: "3.el9", Arch: "x86_64", Epoch: 2}

	for pattern, want := range map[string]bool{
		"foo":                      true,
		"fo?":                      true,
		"f*":                       true,
		"bar":                      false,
		"foo.x86_64":               true,
		"foo.i686":                 false,
		"foo-1.2":                  true,
		"foo-1.3":                  false,
		"foo-1.2-3.el9":            true,
		"foo-1.2-3.el9.x86_64":     true,
		"2:foo-1.2-3.el9.x86_64":   true,
		"0:foo-1.2-3.el9.x86_64":   false,
		"foo-2:1.2-3.el9.x86_64":   true,
		"foo-1*":                   true,
		"foobar*":                  false,
		"[":                        false, // not a valid glob: matches nothing
		"foo-1.2-3.el9.noarch":     false,
		"2:foo-1.2-3.el9.x86_64.x": false,
	} {
		r := &Repo{Exclude: []string{pattern}}
		if got := r.excludes(pp); got != want {
			t.Errorf("exclude=%q: got %v, want %v", pattern, got, want)
		}
	}

	if (&Repo{}).excludes(pp) {
		t.Error("a repository without patterns excluded a package")
	}
}

func pkgNamesOf(ix *Index, names ...string) string {
	var got []string

	for _, n := range names {
		if _, ok := ix.Lookup(n); ok {
			got = append(got, n)
		}
	}

	return strings.Join(got, " ")
}

func TestExcludeLeavesPackagesOutOfTheIndex(t *testing.T) {
	repo := newTestRepo(t,
		pkgOf("kernel", "1"), pkgOf("kernel-core", "1"), pkgOf("foo", "1"), pkgOf("foo-old", "1"),
		pkgOf("bar", "2"), pkgOf("zip", "3"), pkgOf("keep", "1"))
	env := newEnv(t, baseurlSection(repo.url())+"exclude=kernel* foo-1 bar.x86_64\nexcludepkgs=zip\n")

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got := pkgNamesOf(ix, "kernel", "kernel-core", "foo", "foo-old", "bar", "zip", "keep"); got != "foo-old keep" {
		t.Errorf("index has %q, want \"foo-old keep\"", got)
	}
}

func TestPriorityLowerNumberWins(t *testing.T) {
	hi := newTestRepo(t, pkgOf("a", "1.0"))
	lo := newTestRepo(t, pkgOf("a", "2.0"), pkgOf("b", "1"))

	section := func(hiExtra string) string {
		return "[lo]\nbaseurl=" + lo.url() + "\n\n[hi]\nbaseurl=" + hi.url() + "\n" + hiExtra
	}

	for name, tc := range map[string]struct {
		hiExtra, version, repo string
	}{
		// the repository of the lower number wins although its version is older
		"priority beats version": {"priority=10\n", "1.0", "hi"},
		// without priorities the newest version wins
		"newest without priority": {"", "2.0", "lo"},
		// equal priorities are not special
		"equal priority": {"priority=99\n", "2.0", "lo"},
		// a higher number loses
		"higher number loses": {"priority=200\n", "2.0", "lo"},
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t, section(tc.hiExtra))
			if err := env.Update(context.Background()); err != nil {
				t.Fatal(err)
			}

			ix, err := env.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}

			p, ok := ix.Lookup("a")
			if !ok || p.Version != tc.version || p.Repo != tc.repo {
				t.Errorf("a = %+v, want version %s from %s", p, tc.version, tc.repo)
			}

			if _, ok := ix.Lookup("b"); !ok {
				t.Error("a package only the other repository has was lost")
			}

			res, err := ix.Resolve(context.Background(), []string{"a"})
			if err != nil || len(res.Packages) != 1 || res.Packages[0].Version != tc.version {
				t.Errorf("resolution = %+v, %v", res, err)
			}
		})
	}
}

func TestPriorityDecidesProviders(t *testing.T) {
	ix := newIndex("x86_64", nil, nil)
	near := &Package{Name: "near", Arch: "x86_64", Priority: 10}
	far := &Package{Name: "far", Arch: "x86_64", Priority: 99}
	noarch := &Package{Name: "generic", Arch: "noarch", Priority: 10}

	// the host architecture of a worse repository does not beat a better one
	if got := ix.pickProvider([]*Package{far, noarch}); got != noarch {
		t.Errorf("picked %s", got.Name)
	}

	if got := ix.pickProvider([]*Package{far, near, noarch}); got != near {
		t.Errorf("picked %s", got.Name)
	}

	if got := ix.pickProvider([]*Package{far}); got != far {
		t.Errorf("picked %s", got.Name)
	}
}

// proxyServer is a forward proxy that answers every request from repo and
// records what it was asked.
type proxyServer struct {
	*httptest.Server

	mu    sync.Mutex
	hosts []string
	auth  []string
}

func newProxyServer(t *testing.T, repo *testRepo) *proxyServer {
	t.Helper()

	p := &proxyServer{}

	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.hosts = append(p.hosts, r.Host)
		p.auth = append(p.auth, r.Header.Get("Proxy-Authorization"))
		p.mu.Unlock()

		repo.serve(w, r)
	}))
	t.Cleanup(p.Close)

	return p
}

func TestProxyCarriesTheRequestsOfARepository(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	proxy := newProxyServer(t, repo)

	// the host does not exist: only the proxy can answer
	env := newEnv(t, "[test]\nbaseurl=http://repo.invalid\nproxy="+proxy.URL+
		"\nproxy_username=alice\nproxy_password=s3cret\n")

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	p, ok := ix.Lookup("a")
	if !ok {
		t.Fatal("a is not in the index")
	}

	if _, err := env.Download(context.Background(), p, env.destDir); err != nil {
		t.Fatal(err)
	}

	proxy.mu.Lock()
	defer proxy.mu.Unlock()

	// repomd.xml, primary and the package
	if len(proxy.hosts) < 3 {
		t.Fatalf("the proxy saw %d requests", len(proxy.hosts))
	}

	for i, h := range proxy.hosts {
		if h != "repo.invalid" {
			t.Errorf("request %d was for host %q", i, h)
		}

		if !strings.HasPrefix(proxy.auth[i], "Basic ") {
			t.Errorf("request %d carried no proxy credentials: %q", i, proxy.auth[i])
		}
	}
}

func TestProxyNoneBypassesTheTransportProxy(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	dead, _ := url.Parse("http://127.0.0.1:1")
	hc := httpclient.New(httpclient.Options{
		Transport: &http.Transport{Proxy: http.ProxyURL(dead)},
		Retry:     httpclient.RetryPolicy{Attempts: 1},
	})

	via := func(extra string) error {
		env := newEnv(t, baseurlSection(repo.url())+extra, func(o *Options) { o.HTTP = hc })

		return env.Update(context.Background())
	}

	if err := via(""); err == nil {
		t.Fatal("the dead proxy of the transport was not used")
	}

	if err := via("proxy=_none_\n"); err != nil {
		t.Fatalf("proxy=_none_: %v", err)
	}
}

func TestProxyNeedsAnHTTPTransport(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	hc := httpclient.New(httpclient.Options{Transport: roundTripFunc(http.DefaultTransport.RoundTrip)})
	env := newEnv(t, baseurlSection(repo.url())+"proxy=http://proxy.example:3128\n", func(o *Options) { o.HTTP = hc })

	if err := env.Update(context.Background()); !errors.Is(err, ErrProxyUnsupported) {
		t.Errorf("err = %v", err)
	}
}

func TestProxyInvalidURL(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env := newEnv(t, baseurlSection(repo.url())+"proxy=:::\n")

	if err := env.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid proxy") {
		t.Errorf("err = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
