package dnf

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func filelistsPath(repo *testRepo) string {
	repo.mu.Lock()
	defer repo.mu.Unlock()

	for p := range repo.files {
		if strings.HasSuffix(p, "-filelists.xml.gz") {
			return p
		}
	}

	return ""
}

func lazyRepo(t *testing.T) *testRepo {
	t.Helper()

	return newTestRepo(t,
		pkgOf("app", "1", "/usr/bin/lazy", "(/etc/lazy.conf or ghost)", "/usr/bin/nobody"),
		repoPkgWithListed("tools", "/usr/bin/lazy", "/usr/bin/other"),
		repoPkgWithListed("conf", "/etc/lazy.conf"),
		repoPkgWithListed("unrelated", "/usr/bin/unrelated"),
	)
}

func loadIndex(t *testing.T, env *testEnv) *Index {
	t.Helper()

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	return ix
}

func TestFileRequirementsUseFilelistsLazily(t *testing.T) {
	repo := lazyRepo(t)
	env := newEnv(t, baseurlSection(repo.url()))
	ix := loadIndex(t, env)

	fl := filelistsPath(repo)
	if repo.count(fl) != 0 {
		t.Fatal("filelists was fetched before it was needed")
	}

	res, err := ix.Resolve(context.Background(), []string{"app"})
	if err != nil {
		t.Fatal(err)
	}

	if got := pkgNames(res.Packages); got != "tools conf app" {
		t.Errorf("packages = %q", got)
	}

	// /usr/bin/nobody is owned by nobody: reported by its path
	if len(res.Unresolved) != 1 || res.Unresolved[0] != "/usr/bin/nobody" {
		t.Errorf("unresolved = %v", res.Unresolved)
	}

	// one request for every file the packages require
	if repo.count(fl) != 1 {
		t.Errorf("filelists fetched %d times", repo.count(fl))
	}

	// the scan is remembered, as is the file in the cache
	if _, err := ix.Resolve(context.Background(), []string{"app"}); err != nil || repo.count(fl) != 1 {
		t.Errorf("second resolution: %v, %d requests", err, repo.count(fl))
	}

	ix2, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	owners, err := ix2.FileOwners(context.Background(), "/usr/bin/other")
	if err != nil || len(owners) != 1 || owners[0].Name != "tools" || repo.count(fl) != 1 {
		t.Errorf("owners = %v, %v, %d requests", owners, err, repo.count(fl))
	}
}

func TestFileSeedsAreResolvedThroughFilelists(t *testing.T) {
	repo := lazyRepo(t)
	ix := loadIndex(t, newEnv(t, baseurlSection(repo.url())))

	res, err := ix.Resolve(context.Background(), []string{"/etc/lazy.conf"})
	if err != nil || pkgNames(res.Packages) != "conf" {
		t.Errorf("resolution = %+v, %v", res, err)
	}
}

func TestFilelistsFetchedByUpdateAreNotFetchedAgain(t *testing.T) {
	repo := lazyRepo(t)
	ix := loadIndex(t, newEnv(t, baseurlSection(repo.url())+"enabled_metadata=filelists\n"))
	fl := filelistsPath(repo)

	if repo.count(fl) != 1 {
		t.Fatalf("Update fetched filelists %d times", repo.count(fl))
	}

	if owners, err := ix.FileOwners(context.Background(), "/usr/bin/lazy"); err != nil || len(owners) != 1 {
		t.Errorf("owners = %v, %v", owners, err)
	}

	if repo.count(fl) != 1 {
		t.Errorf("filelists fetched %d times", repo.count(fl))
	}
}

func TestFilelistsUnavailableIsReported(t *testing.T) {
	repo := lazyRepo(t)
	ix := loadIndex(t, newEnv(t, baseurlSection(repo.url())))
	repo.set(filelistsPath(repo), 500)

	owners, err := ix.FileOwners(context.Background(), "/usr/bin/lazy")
	if !errors.Is(err, ErrFilelists) || len(owners) != 0 {
		t.Errorf("owners = %v, err = %v", owners, err)
	}

	// the resolution goes on, and says what it could not find
	res, err := ix.Resolve(context.Background(), []string{"app"})
	if err != nil || len(res.Unresolved) == 0 {
		t.Errorf("resolution = %+v, %v", res, err)
	}
}

func TestFilelistsFromAnotherMirror(t *testing.T) {
	repo := lazyRepo(t)
	mirror := newTestRepo(t)

	env := newEnv(t, baseurlSection(repo.url(), mirror.url()))
	ix := loadIndex(t, env)

	// the repository that served the metadata loses the filelists; the second
	// mirror has the same files
	fl := filelistsPath(repo)

	repo.mu.Lock()
	body := repo.files[fl]
	repo.mu.Unlock()

	mirror.mu.Lock()
	mirror.files[fl] = body
	mirror.mu.Unlock()
	repo.set(fl, 404)

	if owners, err := ix.FileOwners(context.Background(), "/usr/bin/lazy"); err != nil || len(owners) != 1 {
		t.Errorf("owners = %v, %v", owners, err)
	}
}

func TestFilelistsCanceled(t *testing.T) {
	repo := lazyRepo(t)
	ix := loadIndex(t, newEnv(t, baseurlSection(repo.url())))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := ix.FileOwners(ctx, "/usr/bin/lazy"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestReadFilelists(t *testing.T) {
	const doc = `<?xml version="1.0"?>
<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="2">
<package pkgid="aaa" name="a" arch="x86_64"><version epoch="0" ver="1" rel="1"/>
<file>/usr/bin/a</file><file type="dir">/usr/share/a</file><file>/etc/a &amp; b</file></package>
<package pkgid="bbb" name="b" arch="noarch"><version epoch="0" ver="1" rel="1"/>
<file>/usr/bin/a</file><file>/usr/bin/b</file></package>
<package name="nopkgid"><file>/usr/bin/a</file></package>
</filelists>`

	var got []string

	wanted := map[string]struct{}{"/usr/bin/a": {}, "/etc/a & b": {}, "/usr/share/a": {}}

	err := readFilelists(strings.NewReader(doc), wanted, func(id, f string) { got = append(got, id+" "+f) })
	if err != nil {
		t.Fatal(err)
	}

	want := "aaa /usr/bin/a,aaa /usr/share/a,aaa /etc/a & b,bbb /usr/bin/a"
	if strings.Join(got, ",") != want {
		t.Errorf("found %q, want %q", got, want)
	}

	if err := readFilelists(strings.NewReader("<filelists><package pkgid=\"a\"><file>x</file></filelists>"), wanted, func(string, string) {}); err == nil {
		t.Error("malformed XML was accepted")
	}
}
