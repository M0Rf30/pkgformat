package dnf

import (
	"context"
	"strings"
	"testing"
)

func TestShouldReplace(t *testing.T) {
	ix := newIndex("x86_64", nil, nil)

	for name, tc := range map[string]struct {
		existing, candidate Package
		want                bool
	}{
		"downloadable beats not":            {Package{Arch: "x86_64"}, Package{Arch: "x86_64", Location: "p"}, true},
		"not downloadable loses":            {Package{Arch: "x86_64", Location: "p"}, Package{Arch: "x86_64"}, false},
		"host arch beats foreign":           {Package{Arch: "i686", Location: "p"}, Package{Arch: "x86_64", Location: "p"}, true},
		"foreign loses to host":             {Package{Arch: "x86_64", Location: "p"}, Package{Arch: "i686", Location: "p"}, false},
		"noarch beats foreign":              {Package{Arch: "i686", Location: "p"}, Package{Arch: "noarch", Location: "p"}, true},
		"noarch loses to host":              {Package{Arch: "x86_64", Location: "p"}, Package{Arch: "noarch", Location: "p"}, false},
		"newer version wins":                {Package{Arch: "x86_64", Version: "1.9", Location: "p"}, Package{Arch: "x86_64", Version: "1.10", Location: "p"}, true},
		"older version loses":               {Package{Arch: "x86_64", Version: "1.10", Location: "p"}, Package{Arch: "x86_64", Version: "1.9", Location: "p"}, false},
		"epoch outranks version":            {Package{Arch: "x86_64", Version: "9", Location: "p"}, Package{Arch: "x86_64", Version: "1", Epoch: 1, Location: "p"}, true},
		"version is not fused with release": {Package{Arch: "x86_64", Version: "1.0", Release: "5", Location: "p"}, Package{Arch: "x86_64", Version: "1.0.1", Release: "1", Location: "p"}, true},
		"older version, newer release":      {Package{Arch: "x86_64", Version: "1.0.1", Release: "1", Location: "p"}, Package{Arch: "x86_64", Version: "1.0", Release: "5", Location: "p"}, false},
		"epoch 10 beats epoch 9":            {Package{Arch: "x86_64", Version: "1", Epoch: 9, Location: "p"}, Package{Arch: "x86_64", Version: "1", Epoch: 10, Location: "p"}, true},
		"missing epoch is zero":             {Package{Arch: "x86_64", Version: "2", Location: "p"}, Package{Arch: "x86_64", Version: "1", Epoch: 0, Location: "p"}, false},
		"caret release is newer":            {Package{Arch: "x86_64", Version: "1", Release: "1", Location: "p"}, Package{Arch: "x86_64", Version: "1", Release: "1^git1", Location: "p"}, true},
		"tilde release is older":            {Package{Arch: "x86_64", Version: "1", Release: "1", Location: "p"}, Package{Arch: "x86_64", Version: "1", Release: "1~rc1", Location: "p"}, false},
		"same release does not swap":        {Package{Arch: "x86_64", Version: "1", Release: "1", Location: "p"}, Package{Arch: "x86_64", Version: "1", Release: "1", Location: "p"}, false},
		"newer release wins":                {Package{Arch: "x86_64", Version: "1", Release: "1", Location: "p"}, Package{Arch: "x86_64", Version: "1", Release: "2", Location: "p"}, true},
	} {
		if got := ix.shouldReplace(&tc.existing, &tc.candidate); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

func TestIndexKeepsNewestOfAName(t *testing.T) {
	ix := testIndex(nil,
		&Package{Name: "a", Version: "1.0"},
		&Package{Name: "a", Version: "2.0"},
		&Package{Name: "a", Version: "1.5"},
		&Package{Name: "a", Version: "9.0", Arch: "i686"},
	)

	if p, _ := ix.Lookup("a"); p.Version != "2.0" || p.Arch != "x86_64" {
		t.Errorf("a = %+v", p)
	}
}

func TestPickProvider(t *testing.T) {
	ix := newIndex("x86_64", nil, nil)
	i686 := &Package{Name: "x", Arch: "i686"}
	noarch := &Package{Name: "y", Arch: "noarch"}
	host := &Package{Name: "z", Arch: "x86_64"}

	for name, tc := range map[string]struct {
		in   []*Package
		want *Package
	}{
		"host arch":     {[]*Package{i686, noarch, host}, host},
		"noarch":        {[]*Package{i686, noarch}, noarch},
		"foreign only":  {[]*Package{i686}, i686},
		"first noarch":  {[]*Package{noarch, {Name: "w", Arch: "noarch"}}, noarch},
		"host over all": {[]*Package{noarch, host}, host},
	} {
		if got := ix.pickProvider(tc.in); got != tc.want {
			t.Errorf("%s: got %s", name, got.Name)
		}
	}
}

func TestResolveVirtual(t *testing.T) {
	ix := testIndex(nil,
		&Package{Name: "real", Version: "1", Provides: []string{"cap"}},
		&Package{Name: "notdownloadable", Version: "1", Location: "-"},
	)
	ix.packages["hollow"] = &Package{Name: "hollow", Arch: "x86_64"}
	ix.providers["hollow"] = []*Package{ix.packages["real"]}

	for in, want := range map[string]string{
		"real":    "real",
		"cap":     "real",
		"hollow":  "real", // listed, but nothing to download: ask the providers
		"unknown": "unknown",
	} {
		if got := ix.ResolveVirtual(in); got != want {
			t.Errorf("ResolveVirtual(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIndexDoesNotListItsOwnNameAsProvider(t *testing.T) {
	ix := testIndex(nil, &Package{Name: "a", Version: "1", Provides: []string{"a = 1", "a", "b"}})
	if len(ix.providers["a"]) != 0 || len(ix.providers["b"]) != 1 {
		t.Errorf("providers = %v", ix.providers)
	}
}

const moduleDoc = `---
document: modulemd
version: 2
data:
  name: nodejs
  stream: "18"
  artifacts:
    rpms:
    - nodejs-0:18.1-1.module+el9+1+aaaa.x86_64
---
document: modulemd
version: 2
data:
  name: nodejs
  stream: "20"
  artifacts:
    rpms:
    - nodejs-0:20.1-1.module+el9+2+bbbb.x86_64
---
document: modulemd-defaults
version: 1
data:
  module: nodejs
  stream: "18"
`

func TestLoadFiltersNonDefaultModuleStreams(t *testing.T) {
	nodejs := func(ver, rel string) repoPkg {
		p := pkgOf("nodejs", ver)
		p.pkg.Release = rel

		return p
	}

	repo := newTestRepo(t)
	repo.publish([]repoPkg{
		nodejs("20.1", "1.module+el9+2+bbbb"),
		nodejs("18.1", "1.module+el9+1+aaaa"),
		pkgOf("plain", "1"),
	}, moduleDoc)

	env := newEnv(t, baseurlSection(repo.url()))
	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Without the filter the newer stream 20 would win.
	if p, ok := ix.Lookup("nodejs"); !ok || p.Version != "18.1" {
		t.Errorf("nodejs = %+v", p)
	}

	if ix.Len() != 2 {
		t.Errorf("index has %d names", ix.Len())
	}
}

func TestLoadIgnoresSourcePackages(t *testing.T) {
	src := pkgOf("srcpkg", "1")
	src.pkg.Arch = "src"

	repo := newTestRepo(t, src, pkgOf("bin", "1"))
	env := newEnv(t, baseurlSection(repo.url()))

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := ix.Lookup("srcpkg"); ok || ix.Len() != 1 {
		t.Errorf("index has %d names", ix.Len())
	}
}

func TestLoadIndexesFilesAndDropsRPMLib(t *testing.T) {
	p := pkgOf("tool", "1", "rpmlib(PayloadIsZstd)", "real >= 1")
	p.pkg.Files = append(p.pkg.Files, fileEntry("/usr/bin/tool"))

	repo := newTestRepo(t, p)
	env := newEnv(t, baseurlSection(repo.url()))

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	got, _ := ix.Lookup("tool")
	if got == nil || strings.Join(got.Requires, ",") != "real" {
		t.Fatalf("tool = %+v", got)
	}

	if ix.ResolveVirtual("/usr/bin/tool") != "tool" {
		t.Error("the file path is not a provider")
	}
}

func TestPackageEVR(t *testing.T) {
	if got := (&Package{Epoch: 2, Version: "1.0", Release: "3"}).EVR(); got != "2:1.0-3" {
		t.Errorf("EVR = %q", got)
	}
}

func TestPackageCompare(t *testing.T) {
	for name, tc := range map[string]struct {
		a, b Package
		want int
	}{
		"equal":                  {Package{Version: "1", Release: "1"}, Package{Version: "1", Release: "1"}, 0},
		"epoch first":            {Package{Version: "9", Epoch: 1}, Package{Version: "1", Epoch: 2}, -1},
		"version before release": {Package{Version: "1.0", Release: "5"}, Package{Version: "1.0.1", Release: "1"}, -1},
		"release last":           {Package{Version: "1", Release: "2"}, Package{Version: "1", Release: "1"}, 1},
	} {
		if got := tc.a.Compare(&tc.b); got != tc.want {
			t.Errorf("%s: Compare = %d, want %d", name, got, tc.want)
		}

		if got := tc.b.Compare(&tc.a); got != -tc.want {
			t.Errorf("%s: reverse Compare = %d, want %d", name, got, -tc.want)
		}
	}
}
