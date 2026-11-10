package dnf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/M0Rf30/pkgformat/httpclient"
)

func readFile(t *testing.T, p string) string {
	t.Helper()

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

func TestUpdateLoadRoundTrip(t *testing.T) {
	repo := newTestRepo(t, pkgOf("bash", "5.1"), pkgOf("hello", "1.0", "bash"))
	env := newEnv(t, baseurlSection(repo.url()))

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	cacheDir := filepath.Join(env.cacheDir, "test")
	if got := readFile(t, filepath.Join(cacheDir, ".baseurl")); got != repo.url() {
		t.Errorf(".baseurl = %q, want %q", got, repo.url())
	}

	for _, f := range []string{"repomd.xml", filepath.Base(repo.primaryPath())} {
		if _, err := os.Stat(filepath.Join(cacheDir, "repodata", f)); err != nil {
			t.Errorf("cache lacks %s: %v", f, err)
		}
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if ix.Len() != 2 {
		t.Fatalf("index has %d packages", ix.Len())
	}

	p, ok := ix.Lookup("hello")
	if !ok || p.Version != "1.0" || p.BaseURL != repo.url() || p.Requires[0] != "bash" ||
		p.Location != "Packages/hello-1.0-1.x86_64.rpm" || p.ChecksumType != "sha256" {
		t.Errorf("hello = %+v", p)
	}

	res, err := ix.Resolve(context.Background(), []string{"hello"})
	if err != nil {
		t.Fatal(err)
	}

	if names := pkgNames(res.Packages); names != "bash hello" || len(res.Unresolved) != 0 {
		t.Errorf("resolution = %s / %v", names, res.Unresolved)
	}

	paths, err := env.DownloadAll(context.Background(), res.Packages, env.destDir)
	if err != nil {
		t.Fatal(err)
	}

	if got := readFile(t, paths[0]); got != "rpm body of bash-5.1" {
		t.Errorf("downloaded %q", got)
	}
}

func pkgNames(pkgs []*Package) string {
	names := make([]string, len(pkgs))
	for i, p := range pkgs {
		names[i] = p.Name
	}

	return strings.Join(names, " ")
}

func TestUpdateSendsConditionalRequest(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env := newEnv(t, baseurlSection(repo.url()))

	for range 2 {
		if err := env.Update(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	// The second update got a 304 and reused the cached repomd.xml; the
	// primary document, already in the cache, was not fetched again.
	if n := repo.count(repo.primaryPath()); n != 1 {
		t.Errorf("primary fetched %d times, want 1", n)
	}

	if n := repo.count("/repodata/repomd.xml"); n != 2 {
		t.Errorf("repomd.xml fetched %d times, want 2", n)
	}

	if _, err := env.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestUpdatePicksUpNewGeneration(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env := newEnv(t, baseurlSection(repo.url()))

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	oldPrimary := repo.primaryPath()

	repo.mu.Lock()
	repo.modTime = time.Now().Add(time.Hour)
	repo.mu.Unlock()
	repo.publish([]repoPkg{pkgOf("a", "2"), pkgOf("b", "1")}, "")

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Load reads the generation repomd.xml names, not every file left in the
	// cache: the old primary is still on disk and must not contribute.
	if _, err := os.Stat(filepath.Join(env.cacheDir, "test", "repodata", filepath.Base(oldPrimary))); err != nil {
		t.Fatalf("test needs the old primary on disk: %v", err)
	}

	if p, _ := ix.Lookup("a"); ix.Len() != 2 || p.Version != "2" {
		t.Errorf("index = %d packages, a = %+v", ix.Len(), p)
	}
}

func TestUpdateFailsOverWithRepomdAndPrimaryFromOneMirror(t *testing.T) {
	// Mirror A serves a repomd.xml whose primary it does not have; mirror B is
	// consistent. The persisted mirror must be B, and A's repomd.xml must not
	// have been committed.
	a := newTestRepo(t, pkgOf("only-in-a", "1"))
	b := newTestRepo(t, pkgOf("only-in-b", "1"))
	a.set(a.primaryPath(), 404)

	env := newEnv(t, baseurlSection(a.url(), b.url()))
	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := readFile(t, filepath.Join(env.cacheDir, "test", ".baseurl")); got != b.url() {
		t.Errorf("persisted mirror = %q, want %q", got, b.url())
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := ix.Lookup("only-in-a"); ok {
		t.Error("metadata of the failed mirror leaked into the index")
	}

	if p, ok := ix.Lookup("only-in-b"); !ok || p.BaseURL != b.url() {
		t.Errorf("only-in-b = %+v, %v", p, ok)
	}
}

func TestUpdateRejectsCorruptPrimaryAndFailsOver(t *testing.T) {
	a := newTestRepo(t, pkgOf("pkg", "1"))
	b := newTestRepo(t, pkgOf("pkg", "1"))
	a.corrupt(a.primaryPath())

	env := newEnv(t, baseurlSection(a.url(), b.url()))
	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := readFile(t, filepath.Join(env.cacheDir, "test", ".baseurl")); got != b.url() {
		t.Errorf("persisted mirror = %q, want %q", got, b.url())
	}

	// No file with the wrong content may remain.
	entries, _ := os.ReadDir(filepath.Join(env.cacheDir, "test", "repodata"))
	for _, e := range entries {
		if strings.Contains(readFile(t, filepath.Join(env.cacheDir, "test", "repodata", e.Name())), "not what the checksum says") {
			t.Errorf("corrupt data was kept as %s", e.Name())
		}
	}
}

func TestUpdateFailureKeepsPreviousMetadata(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env := newEnv(t, baseurlSection(repo.url()))

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	repomd := readFile(t, filepath.Join(env.cacheDir, "test", "repodata", "repomd.xml"))

	repo.mu.Lock()
	repo.modTime = time.Now().Add(time.Hour)
	repo.mu.Unlock()
	repo.publish([]repoPkg{pkgOf("a", "2")}, "")
	repo.corrupt(repo.primaryPath())

	if err := env.Update(context.Background()); err == nil {
		t.Fatal("update with a corrupt primary succeeded")
	}

	if got := readFile(t, filepath.Join(env.cacheDir, "test", "repodata", "repomd.xml")); got != repomd {
		t.Error("a failed update replaced the cached repomd.xml")
	}

	if got := readFile(t, filepath.Join(env.cacheDir, "test", ".baseurl")); got != repo.url() {
		t.Errorf(".baseurl = %q", got)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if p, _ := ix.Lookup("a"); p == nil || p.Version != "1" {
		t.Errorf("index after a failed update: %+v", p)
	}
}

func TestUpdateClientErrorIsNonFatal(t *testing.T) {
	repo := newTestRepo(t)
	repo.set("/repodata/repomd.xml", 404)

	env := newEnv(t, baseurlSection(repo.url()))
	if err := env.Update(context.Background()); err != nil {
		t.Errorf("a 404 repository failed the update: %v", err)
	}
}

func TestUpdateServerErrorIsReported(t *testing.T) {
	repo := newTestRepo(t)
	repo.set("/repodata/repomd.xml", 503)

	env := newEnv(t, baseurlSection(repo.url()))

	err := env.Update(context.Background())
	if se, ok := errors.AsType[*httpclient.HTTPStatusError](err); !ok || se.Code != 503 {
		t.Errorf("err = %v", err)
	}
}

func TestUpdateOneBrokenRepositoryDoesNotStopTheOthers(t *testing.T) {
	good := newTestRepo(t, pkgOf("good", "1"))
	bad := newTestRepo(t)
	bad.set("/repodata/repomd.xml", 500)

	env := newEnv(t, "[bad]\nbaseurl="+bad.url()+"\n[good]\nbaseurl="+good.url()+"\n")
	if err := env.Update(context.Background()); err == nil {
		t.Error("the broken repository was not reported")
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := ix.Lookup("good"); !ok {
		t.Error("the healthy repository was not updated")
	}
}

func TestUpdateRepomdWithoutPrimary(t *testing.T) {
	repo := newTestRepo(t)
	repo.mu.Lock()
	repo.files["/repodata/repomd.xml"] = []byte(`<repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision></repomd>`)
	repo.mu.Unlock()

	env := newEnv(t, baseurlSection(repo.url()))
	if err := env.Update(context.Background()); !errors.Is(err, ErrNoPrimary) {
		t.Errorf("err = %v", err)
	}
}

func TestUpdateRefusesUnverifiablePrimary(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"sha1":    func(s string) string { return strings.ReplaceAll(s, `type="sha256"`, `type="sha1"`) },
		"unknown": func(s string) string { return strings.ReplaceAll(s, `type="sha256"`, `type="crc32"`) },
	} {
		t.Run(name, func(t *testing.T) {
			repo := newTestRepo(t, pkgOf("a", "1"))
			repo.mu.Lock()
			repo.files["/repodata/repomd.xml"] = []byte(edit(string(repo.files["/repodata/repomd.xml"])))
			repo.mu.Unlock()

			env := newEnv(t, baseurlSection(repo.url()))
			if err := env.Update(context.Background()); !errors.Is(err, ErrUnverifiable) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestUpdateRefusesUnsafeLocation(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	repo.mu.Lock()
	repo.files["/repodata/repomd.xml"] = []byte(strings.ReplaceAll(
		string(repo.files["/repodata/repomd.xml"]), `href="repodata/`, `href="../../../etc/`))
	repo.mu.Unlock()

	env := newEnv(t, baseurlSection(repo.url()))
	if err := env.Update(context.Background()); !errors.Is(err, ErrUnsafeLocation) {
		t.Errorf("err = %v", err)
	}
}

func TestUpdateModulesFailureIsNonFatal(t *testing.T) {
	repo := newTestRepo(t)
	repo.publish([]repoPkg{pkgOf("a", "1")}, "---\ndocument: modulemd\n")
	repo.mu.Lock()

	for p := range repo.files {
		if strings.HasSuffix(p, "-modules.yaml") {
			repo.files[p] = []byte("tampered")
		}
	}

	repo.mu.Unlock()

	env := newEnv(t, baseurlSection(repo.url()))
	if err := env.Update(context.Background()); err != nil {
		t.Fatalf("a bad modules file failed the update: %v", err)
	}

	ix, err := env.Load(context.Background())
	if err != nil || ix.Len() != 1 {
		t.Errorf("index: %v, %v", ix, err)
	}
}

func TestUpdateCanceled(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env := newEnv(t, baseurlSection(repo.url()))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := env.Update(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestUpdateUsesMirrorList(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	list := serveText(t, repo.url()+"\n")

	env := newEnv(t, "[test]\nmirrorlist="+list.URL+"\n")
	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if p, ok := ix.Lookup("a"); !ok || p.BaseURL != repo.url() || p.MirrorList != list.URL {
		t.Errorf("a = %+v", p)
	}
}

func TestUpdateSkipsDisabledAndNeedsCacheDir(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env := newEnv(t, "[test]\nenabled=0\nbaseurl="+repo.url()+"\n")

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	if n := repo.count("/repodata/repomd.xml"); n != 0 {
		t.Errorf("a disabled repository was fetched %d times", n)
	}

	if err := New(Options{}).Update(context.Background()); !errors.Is(err, ErrNoCacheDir) {
		t.Errorf("Update without CacheDir: %v", err)
	}

	if _, err := New(Options{}).Load(context.Background()); !errors.Is(err, ErrNoCacheDir) {
		t.Errorf("Load without CacheDir: %v", err)
	}
}

func TestLoadSkipsRepositoryWithoutCache(t *testing.T) {
	env := newEnv(t, baseurlSection("https://never-fetched.example/"))

	ix, err := env.Load(context.Background())
	if err != nil || ix.Len() != 0 {
		t.Errorf("ix.Len = %d, err %v", ix.Len(), err)
	}
}

func TestLoadReadsDNFCacheLayout(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env := newEnv(t, baseurlSection(repo.url()))

	// dnf names the directory <id>-<16 hex>; Update and Load must both use it
	// rather than create a sibling.
	dnfDir := filepath.Join(env.cacheDir, "test-0123456789abcdef")
	if err := os.MkdirAll(dnfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(env.cacheDir, "test")); err == nil {
		t.Error("a second cache directory was created")
	}

	if ix, err := env.Load(context.Background()); err != nil || ix.Len() != 1 {
		t.Errorf("Load: %v", err)
	}
}

func TestIsDNFCacheName(t *testing.T) {
	for name, want := range map[string]bool{
		"epel-0123456789abcdef":         true,
		"epel-0123456789abcde":          false,
		"epel-0123456789abcdeg":         false,
		"epel-modular-0123456789abcdef": false,
		"epel":                          false,
		"epel-modular":                  false,
	} {
		if got := isDNFCacheName(name, "epel"); got != want {
			t.Errorf("isDNFCacheName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestRepoIDCannotEscapeCache(t *testing.T) {
	env := newEnv(t, "[../../evil]\nbaseurl=https://x.example/\n")

	repos, err := env.Repos()
	if err != nil || len(repos) != 0 {
		t.Errorf("repos = %+v, %v", repos, err)
	}
}
