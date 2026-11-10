package dnf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/download"
)

func sumOf(body []byte) string {
	s := sha256.Sum256(body)

	return hex.EncodeToString(s[:])
}

// packageOf loads the index of a one-package repository and returns the
// package.
func packageOf(t *testing.T, repo *testRepo, name string) (*testEnv, *Package) {
	t.Helper()

	env := newEnv(t, baseurlSection(repo.url()))
	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	p, ok := ix.Lookup(name)
	if !ok {
		t.Fatalf("%s not in the index", name)
	}

	return env, p
}

func TestDownloadVerifiesChecksum(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env, p := packageOf(t, repo, "a")

	repo.mu.Lock()
	repo.files["/Packages/a-1-1.x86_64.rpm"] = []byte("tampered")
	repo.mu.Unlock()

	_, err := env.Download(context.Background(), p, env.destDir)
	if !errors.Is(err, download.ErrChecksumMismatch) {
		t.Fatalf("err = %v", err)
	}

	if _, err := os.Stat(filepath.Join(env.destDir, "a-1-1.x86_64.rpm")); err == nil {
		t.Error("a file with a wrong checksum was left at its final name")
	}

	// A mismatch is not retried: the next mirror is the remedy.
	if n := repo.count("/Packages/a-1-1.x86_64.rpm"); n != 1 {
		t.Errorf("fetched %d times", n)
	}
}

func TestDownloadKeepsExistingFileOnMismatch(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env, p := packageOf(t, repo, "a")

	dest := filepath.Join(env.destDir, "a-1-1.x86_64.rpm")
	if err := os.MkdirAll(env.destDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(dest, []byte("older good copy"), 0o644); err != nil {
		t.Fatal(err)
	}

	repo.mu.Lock()
	repo.files["/Packages/a-1-1.x86_64.rpm"] = []byte("tampered")
	repo.mu.Unlock()

	if _, err := env.Download(context.Background(), p, env.destDir); err == nil {
		t.Fatal("tampered download accepted")
	}

	if got := readFile(t, dest); got != "older good copy" {
		t.Errorf("existing file replaced by %q", got)
	}
}

func TestDownloadSkipsMatchingFile(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env, p := packageOf(t, repo, "a")

	for range 2 {
		if _, err := env.Download(context.Background(), p, env.destDir); err != nil {
			t.Fatal(err)
		}
	}

	if n := repo.count("/Packages/a-1-1.x86_64.rpm"); n != 1 {
		t.Errorf("fetched %d times, want 1", n)
	}
}

func TestDownloadAcceptsUppercaseChecksum(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env, p := packageOf(t, repo, "a")
	p.Checksum = strings.ToUpper(p.Checksum)
	p.ChecksumType = "SHA256"

	if _, err := env.Download(context.Background(), p, env.destDir); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadRefusesUnverifiable(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env, p := packageOf(t, repo, "a")

	for name, edit := range map[string]func(*Package){
		"no checksum":   func(p *Package) { p.Checksum, p.ChecksumType = "", "" },
		"weak checksum": func(p *Package) { p.ChecksumType = "sha1" },
		"bad digest":    func(p *Package) { p.Checksum = "xyz" },
		"short digest":  func(p *Package) { p.Checksum = "abcd" },
	} {
		t.Run(name, func(t *testing.T) {
			cp := *p
			edit(&cp)

			if _, err := env.Download(context.Background(), &cp, env.destDir); !errors.Is(err, ErrUnverifiable) {
				t.Errorf("err = %v", err)
			}
		})
	}

	if n := repo.count("/Packages/a-1-1.x86_64.rpm"); n != 0 {
		t.Errorf("an unverifiable package was fetched %d times", n)
	}
}

func TestDownloadRefusesUnsafeLocation(t *testing.T) {
	env := newEnv(t, baseurlSection("https://unused.example/"))
	sum := sumOf([]byte("x"))

	for _, loc := range []string{"", "../escape.rpm", "a/../../escape.rpm", "%2e%2e/escape.rpm", "a/%2e%2e/%2e%2e/x.rpm", ".", "%zz"} {
		p := &Package{Name: "a", Location: loc, Checksum: sum, ChecksumType: "sha256", BaseURL: "https://unused.example"}
		if _, err := env.Download(context.Background(), p, env.destDir); !errors.Is(err, ErrUnsafeLocation) {
			t.Errorf("location %q: err = %v", loc, err)
		}
	}

	if _, err := os.Stat(env.destDir); err == nil {
		t.Error("the destination directory was created for a refused package")
	}
}

func TestDownloadFallsBackToMirrorList(t *testing.T) {
	body := []byte("package body")
	good := newTestRepo(t, repoPkg{pkg: pkgOf("a", "1").pkg, body: body})
	bad := newTestRepo(t, repoPkg{pkg: pkgOf("a", "1").pkg, body: body})
	bad.set("/Packages/a-1-1.x86_64.rpm", 404)

	list := serveText(t, bad.url()+"/\n"+good.url()+"/\n")
	env := newEnv(t, baseurlSection(bad.url()))

	p := &Package{
		Name: "a", Location: "Packages/a-1-1.x86_64.rpm", Checksum: sumOf(body), ChecksumType: "sha256",
		BaseURL: bad.url(), MirrorList: list.URL,
	}

	dest, err := env.Download(context.Background(), p, env.destDir)
	if err != nil {
		t.Fatal(err)
	}

	if readFile(t, dest) != "package body" {
		t.Error("wrong content")
	}

	// The persisted mirror is tried once, not again as a mirror-list entry.
	if n := bad.count("/Packages/a-1-1.x86_64.rpm"); n != 1 {
		t.Errorf("failed mirror asked %d times, want 1", n)
	}
}

func TestDownloadFromMirrorListAlone(t *testing.T) {
	body := []byte("package body")
	good := newTestRepo(t, repoPkg{pkg: pkgOf("a", "1").pkg, body: body})
	list := serveText(t, good.url()+"/\n")
	env := newEnv(t, baseurlSection("https://unused.example/"))

	p := &Package{
		Name: "a", Location: "Packages/a-1-1.x86_64.rpm", Checksum: sumOf(body), ChecksumType: "sha256", MirrorList: list.URL,
	}

	if _, err := env.Download(context.Background(), p, env.destDir); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadNoSource(t *testing.T) {
	env := newEnv(t, baseurlSection("https://unused.example/"))
	p := &Package{Name: "a", Location: "a.rpm", Checksum: sumOf(nil), ChecksumType: "sha256"}

	if _, err := env.Download(context.Background(), p, env.destDir); !errors.Is(err, ErrNoMirror) {
		t.Errorf("err = %v", err)
	}
}

func TestDownloadHonorsSizeLimit(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env, p := packageOf(t, repo, "a")
	env.opts.MaxPackageBytes = 4

	if _, err := env.Download(context.Background(), p, env.destDir); err == nil {
		t.Error("a package over the limit was accepted")
	}
}

func TestDownloadEscapesLocation(t *testing.T) {
	body := []byte("odd name")
	p := pkgOf("odd", "1+2").pkg
	repo := newTestRepo(t, repoPkg{pkg: p, body: body})
	env, got := packageOf(t, repo, "odd")

	if _, err := env.Download(context.Background(), got, env.destDir); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(env.destDir, "odd-1+2-1.x86_64.rpm")); err != nil {
		t.Error(err)
	}
}

func TestDownloadAllKeepsOrderAndCancelsOnFailure(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"), pkgOf("b", "1"), pkgOf("c", "1"))
	env := newEnv(t, baseurlSection(repo.url()))

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var pkgs []*Package

	for _, n := range []string{"c", "a", "b"} {
		p, _ := ix.Lookup(n)
		pkgs = append(pkgs, p)
	}

	paths, err := env.DownloadAll(context.Background(), pkgs, env.destDir)
	if err != nil {
		t.Fatal(err)
	}

	for i, want := range []string{"c-1-1", "a-1-1", "b-1-1"} {
		if filepath.Base(paths[i]) != want+".x86_64.rpm" {
			t.Errorf("paths[%d] = %s", i, paths[i])
		}
	}

	repo.set("/Packages/b-1-1.x86_64.rpm", 404)

	if err := os.RemoveAll(env.destDir); err != nil {
		t.Fatal(err)
	}

	if _, err := env.DownloadAll(context.Background(), pkgs, env.destDir); err == nil {
		t.Error("a failed download was not reported")
	}

	if _, err := env.DownloadAll(context.Background(), nil, env.destDir); err != nil {
		t.Errorf("empty list: %v", err)
	}
}
