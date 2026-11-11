package dnf

import (
	"context"
	"testing"
)

func TestCompareOrdersCandidates(t *testing.T) {
	c := New(Options{Arch: "x86_64"})
	ix := newIndex(c, DefaultConfig())

	for name, tc := range map[string]struct {
		better, worse tpkg
	}{
		"better priority":    {tpkg{name: "a", priority: 10, arch: "i686"}, tpkg{name: "a", priority: 99}},
		"host arch":          {tpkg{name: "a"}, tpkg{name: "a", arch: "i686"}},
		"noarch last":        {tpkg{name: "a", arch: "i686"}, tpkg{name: "a", arch: "noarch"}},
		"newer version":      {tpkg{name: "a", version: "1.10"}, tpkg{name: "a", version: "1.9"}},
		"epoch outranks":     {tpkg{name: "a", version: "1", epoch: 1}, tpkg{name: "a", version: "9"}},
		"version vs release": {tpkg{name: "a", version: "1.0.1", release: "1"}, tpkg{name: "a", version: "1.0", release: "5"}},
		"epoch 10 over 9":    {tpkg{name: "a", epoch: 10}, tpkg{name: "a", epoch: 9}},
		"caret is newer":     {tpkg{name: "a", release: "1^git1"}, tpkg{name: "a", release: "1"}},
		"tilde is older":     {tpkg{name: "a", release: "1"}, tpkg{name: "a", release: "1~rc1"}},
		"newer release":      {tpkg{name: "a", release: "2"}, tpkg{name: "a", release: "1"}},
		"lower cost":         {tpkg{name: "a", cost: 100}, tpkg{name: "a", cost: 1000}},
	} {
		better, worse := tc.better.build(), tc.worse.build()
		if ix.compare(better, worse) >= 0 || ix.compare(worse, better) <= 0 {
			t.Errorf("%s: %s should come before %s", name, better, worse)
		}
	}
}

func TestIndexKeepsEveryVersion(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "a", version: "1.0"},
		tpkg{name: "a", version: "2.0"},
		tpkg{name: "a", version: "1.5"},
		tpkg{name: "a", version: "9.0", arch: "i686"},
		tpkg{name: "a", version: "9.0", arch: "aarch64"},
	)

	if p, _ := ix.Lookup("a"); p.Version != "2.0" || p.Arch != "x86_64" {
		t.Errorf("a = %v", p)
	}

	var got []string
	for _, p := range ix.Versions("a") {
		got = append(got, p.Version+"."+p.Arch)
	}

	if want := "2.0.x86_64 1.5.x86_64 1.0.x86_64 9.0.i686"; len(got) != 4 || got[0]+" "+got[1]+" "+got[2]+" "+got[3] != want {
		t.Errorf("versions = %v (the aarch64 one is foreign to the host)", got)
	}

	if ix.Len() != 1 {
		t.Errorf("Len = %d", ix.Len())
	}
}

func TestIndexPriorityHidesOtherRepositories(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "a", version: "9", priority: 99},
		tpkg{name: "a", version: "1", priority: 10},
		tpkg{name: "b", version: "1", priority: 99},
	)

	if got := ix.Versions("a"); len(got) != 1 || got[0].Version != "1" {
		t.Errorf("versions = %v", got)
	}

	if _, ok := ix.Lookup("b"); !ok {
		t.Error("a package only the other repository has was lost")
	}

	if len(ix.Providers("a")) != 1 {
		t.Error("the hidden package is still a provider")
	}
}

func TestProvidersAndResolveVirtual(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "real", provides: []string{"cap", "cap2 = 2"}},
		tpkg{name: "second", provides: []string{"cap"}, priority: 10},
		tpkg{name: "tool", files: []string{"/usr/bin/tool"}},
	)

	if got := ix.Providers("cap"); len(got) != 2 || got[0].Name != "second" {
		t.Errorf("Providers(cap) = %v", got)
	}

	if got := ix.Providers("cap2 >= 3"); len(got) != 0 {
		t.Errorf("Providers(cap2 >= 3) = %v", got)
	}

	if got := ix.Providers("cap2 < 3"); len(got) != 1 {
		t.Errorf("Providers(cap2 < 3) = %v", got)
	}

	for in, want := range map[string]string{
		"real":    "real",
		"cap":     "second",
		"unknown": "unknown",
	} {
		if got := ix.ResolveVirtual(in); got != want {
			t.Errorf("ResolveVirtual(%q) = %q, want %q", in, got, want)
		}
	}

	// a package without a location has nothing to download: ask the providers
	ix = testIndex(nil, tpkg{name: "real", provides: []string{"hollow"}})

	hollow := tpkg{name: "hollow"}.build()
	hollow.Location = ""
	ix.names["hollow"] = []*Package{hollow}

	if got := ix.ResolveVirtual("hollow"); got != "real" {
		t.Errorf("ResolveVirtual(hollow) = %q", got)
	}
}

func TestPackageHasItsOwnProvide(t *testing.T) {
	p := tpkg{name: "a", version: "1", release: "2", epoch: 3, provides: []string{"b"}}.build()
	if len(p.Provides) != 2 || p.Provides[1].Name != "a" || p.Provides[1].Version != "1-2" || p.Provides[1].Epoch != 3 {
		t.Errorf("provides = %+v", p.Provides)
	}

	q := tpkg{name: "a", provides: []string{"a = 1"}}.build()
	if len(q.Provides) != 1 {
		t.Errorf("provides = %+v", q.Provides)
	}
}

func TestMatchSpecs(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "foo", version: "1.0", release: "2"},
		tpkg{name: "foo", version: "2.0", release: "1", epoch: 1},
		tpkg{name: "foo-bar", version: "1"},
		tpkg{name: "py.12", version: "3"},
	)

	for spec, want := range map[string]int{
		"foo":                2,
		"foo.x86_64":         2,
		"foo.i686":           0,
		"foo-1.0":            1,
		"foo-1.0-2.x86_64":   1,
		"foo-1.0-3":          0,
		"foo-1:2.0":          1,
		"foo-0:2.0":          0,
		"foo-1:2.0-1.x86_64": 1,
		"1:foo-2.0-1.x86_64": 1,
		"0:foo-2.0-1.x86_64": 0,
		"2:foo-1.0-2.x86_64": 0,
		"foo-bar":            1,
		"foo-bar-1":          1,
		"py.12":              1,
		"py":                 0,
		"":                   0,
		"  foo-bar ":         1,
		"nothing":            0,
		"foo-":               0,
	} {
		if got := len(ix.Match(spec)); got != want {
			t.Errorf("Match(%q) = %d packages, want %d", spec, got, want)
		}
	}
}

func TestArchCompat(t *testing.T) {
	for arch, tc := range map[string]struct {
		runs   []string
		refuse []string
	}{
		"x86_64":  {[]string{"x86_64", "i686", "i386", "noarch"}, []string{"aarch64", "ppc64le"}},
		"i686":    {[]string{"i686", "i586", "noarch"}, []string{"x86_64"}},
		"aarch64": {[]string{"aarch64", "noarch"}, []string{"armv7hl", "x86_64"}},
		"armv7hl": {[]string{"armv7hl", "armv6hl", "noarch"}, []string{"aarch64"}},
		"s390x":   {[]string{"s390x", "s390", "noarch"}, []string{"ppc64le"}},
		"ppc64le": {[]string{"ppc64le", "noarch"}, []string{"ppc64"}},
		"riscv64": {[]string{"riscv64", "noarch"}, []string{"x86_64"}},
		"weird":   {[]string{"weird", "noarch"}, []string{"x86_64"}},
	} {
		ranks := archRanks(arch)
		for _, a := range tc.runs {
			if _, ok := ranks[a]; !ok {
				t.Errorf("%s should run %s", arch, a)
			}
		}

		for _, a := range tc.refuse {
			if _, ok := ranks[a]; ok {
				t.Errorf("%s should not run %s", arch, a)
			}
		}

		if ranks[arch] != 0 || ranks["noarch"] != len(archCompat(arch))-1 {
			t.Errorf("%s: ranks = %v", arch, ranks)
		}
	}

	if !isMultilibArch("x86_64", "i686") || isMultilibArch("x86_64", "noarch") || isMultilibArch("aarch64", "i686") {
		t.Error("isMultilibArch")
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

func moduleRepo(t *testing.T) *testRepo {
	t.Helper()

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

	return repo
}

func TestLoadFiltersNonDefaultModuleStreams(t *testing.T) {
	repo := moduleRepo(t)

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

	if ix.Len() != 2 || len(ix.Versions("nodejs")) != 1 {
		t.Errorf("index has %d names", ix.Len())
	}
}

func TestLoadModuleHotfixesRepositoryIsNotFiltered(t *testing.T) {
	repo := moduleRepo(t)

	env := newEnv(t, baseurlSection(repo.url())+"module_hotfixes=1\n")
	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if p, ok := ix.Lookup("nodejs"); !ok || p.Version != "20.1" || len(ix.Versions("nodejs")) != 2 {
		t.Errorf("nodejs = %v of %v", p, ix.Versions("nodejs"))
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
	if got == nil || len(got.Requires) != 1 || got.Requires[0].Name != "real" || got.Requires[0].Version != "1" {
		t.Fatalf("tool = %+v", got)
	}

	if len(got.Files) != 1 || got.Files[0] != "/usr/bin/tool" {
		t.Errorf("files = %v", got.Files)
	}

	owners, err := ix.FileOwners(context.Background(), "/usr/bin/tool")
	if err != nil || len(owners) != 1 || owners[0] != got {
		t.Errorf("FileOwners = %v, %v", owners, err)
	}
}

func TestPackageEVR(t *testing.T) {
	p := &Package{Name: "a", Arch: "noarch", Epoch: 2, Version: "1.0", Release: "3"}
	if got := p.EVR(); got != "2:1.0-3" {
		t.Errorf("EVR = %q", got)
	}

	if p.NEVRA() != "a-2:1.0-3.noarch" || p.String() != p.NEVRA() {
		t.Errorf("NEVRA = %q", p.NEVRA())
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
