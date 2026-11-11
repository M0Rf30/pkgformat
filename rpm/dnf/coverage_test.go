package dnf

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/richdep"
)

func TestArchCompatTable(t *testing.T) {
	for _, arch := range []string{
		"x86_64", "amd64", "i686", "i586", "i486", "i386", "athlon", "aarch64", "armv8hl", "armv7hnl", "armv7hl",
		"armv7l", "armv6hl", "armv6l", "armv5tel", "ppc64le", "ppc64p7", "ppc64", "ppc", "s390x", "s390",
		"sparc64v", "sparc64", "ia64", "alpha", "riscv64", "loongarch64", "mips64el", "something-new",
	} {
		list := archCompat(arch)

		want := arch
		if arch == "amd64" {
			want = "x86_64"
		}

		if list[0] != want || list[len(list)-1] != archNoarch {
			t.Errorf("%s: %v", arch, list)
		}

		if len(slices.Compact(slices.Sorted(slices.Values(list)))) != len(list) {
			t.Errorf("%s: duplicates in %v", arch, list)
		}
	}

	if !slices.Contains(archCompat("x86_64"), "i686") || slices.Contains(archCompat("i686"), "x86_64") {
		t.Error("an x86_64 host runs i686, and not the other way round")
	}

	if got := archCompat("aarch64"); !slices.Equal(got, []string{"aarch64", archNoarch}) {
		t.Errorf("aarch64: %v", got)
	}
}

func TestRPMArch(t *testing.T) {
	for goarch, want := range map[string]string{
		"amd64": "x86_64", "arm64": "aarch64", "386": "i686", "arm": "armv7hl", "riscv64": "riscv64", "s390x": "s390x",
	} {
		if got := rpmArch(goarch); got != want {
			t.Errorf("rpmArch(%q) = %q, want %q", goarch, got, want)
		}
	}

	if goArchToRPM() == "" {
		t.Error("no architecture for this host")
	}
}

func TestPersistedBase(t *testing.T) {
	c := New(Options{Arch: "x86_64"})
	dir := t.TempDir()
	repo := &Repo{BaseURLs: []string{"http://example.test/os/"}}

	if got := c.persistedBase(dir, repo); got != "http://example.test/os" {
		t.Errorf("without a recorded mirror: %q", got)
	}

	write := func(s string) {
		if err := os.WriteFile(filepath.Join(dir, baseURLName), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("https://mirror.test/fedora/\n")

	if got := c.persistedBase(dir, repo); got != "https://mirror.test/fedora" {
		t.Errorf("recorded mirror: %q", got)
	}

	write("ftp://mirror.test/x")

	if got := c.persistedBase(dir, repo); got != "http://example.test/os" {
		t.Errorf("a recorded URL that is not http(s): %q", got)
	}

	if got := c.persistedBase(dir, &Repo{BaseURLs: []string{"file:///srv/repo"}}); got != "" {
		t.Errorf("no http(s) URL at all: %q", got)
	}
}

func TestMetadataPathAndOpen(t *testing.T) {
	dir := t.TempDir()

	if p, err := metadataPath(dir, "repodata/abc-primary.xml.gz"); err != nil || p != filepath.Join(dir, "abc-primary.xml.gz") {
		t.Errorf("metadataPath = %q, %v", p, err)
	}

	if _, err := metadataPath(dir, "../../etc/passwd"); !errors.Is(err, ErrUnsafeLocation) {
		t.Errorf("an escaping location: %v", err)
	}

	c := New(Options{Arch: "x86_64"})

	if _, err := c.openMetadata(filepath.Join(dir, "missing.xml")); err == nil {
		t.Error("a missing file opens")
	}

	bad := filepath.Join(dir, "bad.xml.gz")
	if err := os.WriteFile(bad, []byte("not gzip"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := c.openMetadata(bad); err == nil {
		t.Error("a file that is not gzip opens")
	}

	plain := filepath.Join(dir, "plain.xml")
	if err := os.WriteFile(plain, []byte("<a/>"), 0o644); err != nil {
		t.Fatal(err)
	}

	rc, err := c.openMetadata(plain)
	if err != nil {
		t.Fatal(err)
	}

	_ = rc.Close()
}

func newTestSolver(t *testing.T, installed Installed, pkgs ...tpkg) (*solver, *Index) {
	t.Helper()

	ix := testIndex(installed, pkgs...)

	s, err := newSolver(context.Background(), ix, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	return s, ix
}

func TestPreferOrder(t *testing.T) {
	s, ix := newTestSolver(t, fakeInstalled{pkgs: []*rpm.Package{installedPkg(tpkg{name: "have", provides: []string{"cap"}})}},
		tpkg{name: "cap", arch: "x86_64"},
		tpkg{name: "have", arch: "x86_64", version: "2", provides: []string{"cap"}},
		tpkg{name: "zed", arch: "x86_64", provides: []string{"cap"}},
		tpkg{name: "alpha", arch: "i686", provides: []string{"cap"}},
		tpkg{name: "beta", arch: "x86_64", provides: []string{"cap"}},
	)

	pick := func(name string) *Package { return ix.names[name][0] }
	a := richdep.Atom{Name: "cap"}

	// the name asked for beats everything
	if s.prefer(pick("cap"), pick("have"), a) >= 0 || s.prefer(pick("have"), pick("cap"), a) <= 0 {
		t.Error("the package named like the capability must come first")
	}

	// an installed name beats a new one
	if s.prefer(pick("have"), pick("beta"), a) >= 0 || s.prefer(pick("beta"), pick("have"), a) <= 0 {
		t.Error("an installed name must come before a new one")
	}

	// a better architecture beats a better name
	if s.prefer(pick("zed"), pick("alpha"), a) >= 0 {
		t.Error("x86_64 must come before i686 on an x86_64 host")
	}

	// else the name
	if s.prefer(pick("beta"), pick("zed"), a) >= 0 {
		t.Error("names compare in alphabetical order")
	}
}

func TestRemoveTakesAPackageOutOfEveryIndex(t *testing.T) {
	s, ix := newTestSolver(t, nil,
		tpkg{name: "app", arch: "x86_64", provides: []string{"cap"}, conflicts: []string{"other"}, obsoletes: []string{"old"}, files: []string{"/usr/bin/app"}},
	)

	p := ix.names["app"][0]
	s.install(p)

	if !s.st.selected[p] || len(s.st.prov["cap"]) != 1 || len(s.st.conf["other"]) != 1 || len(s.st.obs["old"]) != 1 {
		t.Fatalf("the install left no trace: %+v", s.st)
	}

	s.remove(p)

	if s.st.selected[p] || len(s.st.order) != 0 || len(s.st.byName["app"]) != 0 || len(s.st.prov["cap"]) != 0 ||
		len(s.st.files["/usr/bin/app"]) != 0 || len(s.st.conf["other"]) != 0 || len(s.st.obs["old"]) != 0 {
		t.Errorf("the package is still known: %+v", s.st)
	}
}

func TestFileOwnersWarnsOnceWhenTheFileListsFail(t *testing.T) {
	repo := lazyRepo(t)

	var log strings.Builder

	env := newEnv(t, baseurlSection(repo.url()), func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(&log, nil))
	})
	ix := loadIndex(t, env)
	repo.set(filelistsPath(repo), 500)

	s, err := newSolver(context.Background(), ix, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if owners := s.fileOwners("/usr/bin/lazy"); len(owners) != 0 {
			t.Errorf("owners = %v", owners)
		}
	}

	if n := strings.Count(log.String(), "file requirement looked up without the file lists"); n != 1 {
		t.Errorf("warned %d times:\n%s", n, log.String())
	}

	// a cancelled context is not a failure of the file lists
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s2, err := newSolver(ctx, ix, ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	log.Reset()
	s2.fileOwners("/usr/bin/lazy")

	if log.Len() != 0 {
		t.Errorf("a cancelled lookup warned: %s", log.String())
	}
}

func TestConfigInstallOnly(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader("[main]\ninstallonly_limit=5\ninstallonlypkgs=kernel, vm-image\n  extra-kernel\nbest=0\n"))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.InstallOnlyLimit != 5 || cfg.Best || !slices.Equal(cfg.InstallOnlyPkgs, []string{"kernel", "vm-image", "extra-kernel"}) {
		t.Errorf("config = %+v", cfg)
	}

	def := DefaultConfig()
	if def.InstallOnlyLimit != 3 || !slices.Contains(def.InstallOnlyPkgs, "installonlypkg(kernel)") {
		t.Errorf("defaults = %+v", def)
	}

	// a limit that is not a number leaves the default
	cfg, err = ParseConfig(strings.NewReader("[main]\ninstallonly_limit=many\n"))
	if err != nil || cfg.InstallOnlyLimit != 3 {
		t.Errorf("config = %+v, %v", cfg, err)
	}
}

func TestInstallOnlyKeepsOldVersionsAndRemovesBeyondTheLimit(t *testing.T) {
	kernel := func(v string) tpkg {
		return tpkg{name: "kernel", version: v, arch: "x86_64", provides: []string{"installonlypkg(kernel)"}}
	}

	installed := fakeInstalled{pkgs: []*rpm.Package{installedPkg(kernel("1")), installedPkg(kernel("2")), installedPkg(kernel("3"))}}

	for limit, want := range map[int][]string{0: nil, 1: nil, 3: {"1"}, 4: nil, 2: {"1", "2"}} {
		ix := testIndex(installed, kernel("4"))
		ix.cfg.InstallOnlyLimit = limit

		res, err := ix.Resolve(context.Background(), []string{"kernel"})
		if err != nil {
			t.Fatal(err)
		}

		if len(res.Packages) != 1 || res.Packages[0].Version != "4" || len(res.Upgrades) != 0 {
			t.Fatalf("limit %d: kernel 4 must be installed next to the others: %+v", limit, res)
		}

		var got []string
		for _, p := range res.Removed {
			got = append(got, p.Version)
		}

		if !slices.Equal(got, want) {
			t.Errorf("limit %d: removed %v, want %v", limit, got, want)
		}
	}

	// the limit applies to the names the transaction installs
	ix := testIndex(installed, tpkg{name: "other", arch: "x86_64"})
	ix.cfg.InstallOnlyLimit = 2

	if res, err := ix.Resolve(context.Background(), []string{"other"}); err != nil || len(res.Removed) != 0 {
		t.Errorf("removed %v, %v", res.Removed, err)
	}
}

func TestBestFallsBackToAnOlderVersionOnlyWithoutBest(t *testing.T) {
	pkgs := []tpkg{
		{name: "app", version: "1", arch: "x86_64"},
		{name: "app", version: "2", arch: "x86_64", requires: []string{"nothing-provides-this"}},
		{name: "user", arch: "x86_64", requires: []string{"lib"}},
		{name: "lib", version: "1", arch: "x86_64"},
		{name: "lib", version: "2", arch: "x86_64", requires: []string{"nothing-provides-this"}},
	}

	for _, best := range []bool{true, false} {
		ix := testIndex(nil, pkgs...)
		ix.cfg.Best = best

		res, err := ix.Resolve(context.Background(), []string{"app"})
		if err != nil {
			t.Fatal(err)
		}

		switch {
		case best && len(res.Unresolved) == 0:
			t.Errorf("best: the newest version cannot be installed, yet %s", pkgNames(res.Packages))
		case !best && (len(res.Unresolved) != 0 || len(res.Packages) != 1 || res.Packages[0].Version != "1"):
			t.Errorf("no best: %+v", res)
		}

		// what a package needs falls back whatever best says
		res, err = ix.Resolve(context.Background(), []string{"user"})
		if err != nil || len(res.Unresolved) != 0 || len(res.Packages) != 2 {
			t.Errorf("best=%v: %+v, %v", best, res, err)
		}
	}
}

func TestSupplementersFollowNewPackagesOnly(t *testing.T) {
	pkgs := []tpkg{
		{name: "app", arch: "x86_64"},
		{name: "app-docs", arch: "x86_64"},
		{name: "app-lang", arch: "x86_64"},
		{name: "lang", arch: "x86_64"},
		{name: "unrelated", arch: "x86_64"},
	}

	build := func(installed Installed) *Index {
		ix := testIndex(installed, pkgs...)
		for _, p := range ix.names["app-docs"] {
			p.Supplements = deps("app")
		}

		for _, p := range ix.names["app-lang"] {
			p.Supplements = deps("(app and lang)")
		}

		ix.supplements = map[string][]*Package{}
		for _, list := range ix.names {
			for _, p := range list {
				ix.indexSupplements(p)
			}
		}

		return ix
	}

	names := func(ix *Index, _ bool, specs ...string) []string {
		res, err := ix.ResolveWith(context.Background(), specs, ResolveOptions{WeakDeps: WeakEnabled})
		if err != nil {
			t.Fatal(err)
		}

		var got []string
		for _, p := range res.Packages {
			got = append(got, p.Name)
		}

		slices.Sort(got)

		return got
	}

	if got := names(build(nil), false, "app"); !slices.Equal(got, []string{"app", "app-docs"}) {
		t.Errorf("app: %v", got)
	}

	if got := names(build(nil), false, "app", "lang"); !slices.Equal(got, []string{"app", "app-docs", "app-lang", "lang"}) {
		t.Errorf("app lang: %v", got)
	}

	installed := fakeInstalled{pkgs: []*rpm.Package{installedPkg(tpkg{name: "app", arch: "x86_64"})}}

	if got := names(build(installed), true, "unrelated"); !slices.Equal(got, []string{"unrelated"}) {
		t.Errorf("an installed app draws nothing in: %v", got)
	}

	if got := names(build(installed), true, "lang"); !slices.Equal(got, []string{"app-lang", "lang"}) {
		t.Errorf("lang next to the installed app: %v", got)
	}

	// no weak dependencies, no supplements
	ix := build(nil)

	res, err := ix.ResolveWith(context.Background(), []string{"app"}, ResolveOptions{WeakDeps: WeakDisabled})
	if err != nil || len(res.Packages) != 1 {
		t.Errorf("weak off: %+v, %v", res, err)
	}
}
