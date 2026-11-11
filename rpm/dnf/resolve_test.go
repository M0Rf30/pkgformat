package dnf

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
)

func resolve(t *testing.T, ix *Index, seeds ...string) *Resolution {
	t.Helper()

	res, err := ix.Resolve(context.Background(), seeds)
	if err != nil {
		t.Fatal(err)
	}

	return res
}

func resolveNoWeak(t *testing.T, ix *Index, seeds ...string) *Resolution {
	t.Helper()

	res, err := ix.ResolveWith(context.Background(), seeds, ResolveOptions{WeakDeps: WeakDisabled})
	if err != nil {
		t.Fatal(err)
	}

	return res
}

func TestResolveOrdersDependenciesFirst(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "app", requires: []string{"libb >= 2", "liba"}},
		tpkg{name: "liba", requires: []string{"base"}},
		tpkg{name: "libb", version: "2", requires: []string{"base"}},
		tpkg{name: "base"},
		tpkg{name: "unrelated"},
	)

	res := resolve(t, ix, "app")
	if got := pkgNames(res.Packages); got != "base libb liba app" || len(res.Unresolved) != 0 {
		t.Errorf("packages = %q, unresolved %v", got, res.Unresolved)
	}
}

func TestResolveDeduplicatesSeedsAndHandlesCycles(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "a", requires: []string{"b"}},
		tpkg{name: "b", requires: []string{"a"}},
	)

	res := resolve(t, ix, "a", "b", "a >= 1")
	if got := pkgNames(res.Packages); got != "b a" {
		t.Errorf("packages = %q", got)
	}
}

func TestResolveVirtualCapabilities(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "app", requires: []string{"webserver", "/usr/bin/tool", "libz.so.1()(64bit)"}},
		tpkg{name: "httpd-i686", arch: "i686", provides: []string{"webserver"}},
		tpkg{name: "httpd", provides: []string{"webserver = 2.4"}},
		tpkg{name: "tools", provides: []string{"/usr/bin/tool"}},
		tpkg{name: "zlib", provides: []string{"libz.so.1()(64bit)"}},
	)

	res := resolve(t, ix, "app")
	if got := pkgNames(res.Packages); got != "httpd tools zlib app" || len(res.Unresolved) != 0 {
		t.Errorf("packages = %q, unresolved %v", got, res.Unresolved)
	}
}

func TestResolveVersionedProviders(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "app", requires: []string{"cap >= 2"}},
		tpkg{name: "old", provides: []string{"cap = 1"}},
		tpkg{name: "new", provides: []string{"cap = 2.5"}},
		tpkg{name: "app2", requires: []string{"cap < 1"}},
	)

	res := resolve(t, ix, "app", "app2")
	if got := pkgNames(res.Packages); got != "new app app2" {
		t.Errorf("packages = %q", got)
	}

	if !reflect.DeepEqual(res.Unresolved, []string{"cap < 1"}) {
		t.Errorf("unresolved = %v", res.Unresolved)
	}
}

func TestResolveUnresolved(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "app", requires: []string{"missing-a", "present", "missing-b"}},
		tpkg{name: "present"},
	)

	res := resolve(t, ix, "app", "missing-seed")
	if !reflect.DeepEqual(res.Unresolved, []string{"missing-a", "missing-b", "missing-seed"}) {
		t.Errorf("unresolved = %v", res.Unresolved)
	}

	if got := pkgNames(res.Packages); got != "present app" {
		t.Errorf("packages = %q", got)
	}
}

func TestResolveSkipsInstalledByVersion(t *testing.T) {
	// coreutils is installed and provides /usr/bin/ls; coreutils-single also
	// does, and must not be pulled in to satisfy it.
	installed := fakeInstalled{pkgs: []*rpm.Package{
		installedPkg(tpkg{name: "coreutils", files: []string{"/usr/bin/ls"}}),
		installedPkg(tpkg{name: "glibc", version: "2.40", provides: []string{"libc.so.6()(64bit)"}}),
	}}

	ix := testIndex(installed,
		tpkg{name: "app", requires: []string{"/usr/bin/ls", "glibc >= 2.38", "libc.so.6()(64bit)", "other"}},
		tpkg{name: "coreutils-single", provides: []string{"/usr/bin/ls"}},
		tpkg{name: "glibc", version: "2.41", requires: []string{"never-walked"}},
		tpkg{name: "other"},
	)

	res := resolve(t, ix, "app")
	if got := pkgNames(res.Packages); got != "other app" || len(res.Unresolved) != 0 || len(res.Upgrades) != 0 {
		t.Errorf("packages = %q, unresolved %v, upgrades %v", got, res.Unresolved, res.Upgrades)
	}
}

func TestResolveUpgradesInstalledWhenARequirementNeedsIt(t *testing.T) {
	installed := fakeInstalled{pkgs: []*rpm.Package{
		installedPkg(tpkg{name: "glibc", version: "2.40"}),
		installedPkg(tpkg{name: "libfoo", version: "1", requires: []string{"glibc >= 2.30"}}),
	}}

	ix := testIndex(installed,
		tpkg{name: "app", requires: []string{"glibc >= 2.41"}},
		tpkg{name: "glibc", version: "2.41"},
		tpkg{name: "glibc", version: "2.39"},
	)

	res := resolve(t, ix, "app")
	if got := pkgNames(res.Packages); got != "glibc app" || res.Packages[0].Version != "2.41" {
		t.Fatalf("packages = %v", res.Packages)
	}

	if len(res.Upgrades) != 1 || res.Upgrades[0].Old.Version != "2.40" || res.Upgrades[0].New.Version != "2.41" ||
		!res.Upgrades[0].Old.Installed() {
		t.Errorf("upgrades = %+v", res.Upgrades)
	}
}

func TestResolveSeedAlreadyInstalledOrOlder(t *testing.T) {
	installed := fakeInstalled{pkgs: []*rpm.Package{installedPkg(tpkg{name: "a", version: "2"})}}
	ix := testIndex(installed, tpkg{name: "a", version: "2"}, tpkg{name: "a", version: "1", release: "5"}, tpkg{name: "b"})

	if res := resolve(t, ix, "a", "a-1-5"); len(res.Packages) != 0 || len(res.Conflicts) != 0 || len(res.Unresolved) != 0 {
		t.Errorf("resolution = %+v", res)
	}

	// a newer one is an upgrade
	ix = testIndex(installed, tpkg{name: "a", version: "3"})
	if res := resolve(t, ix, "a"); len(res.Upgrades) != 1 || res.Packages[0].Version != "3" {
		t.Errorf("resolution = %+v", res)
	}
}

func TestResolveInstalledErrors(t *testing.T) {
	boom := errors.New("database locked")
	ix := testIndex(fakeInstalled{err: boom}, tpkg{name: "a"})

	if _, err := ix.Resolve(context.Background(), []string{"a"}); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
}

func TestResolveSpecs(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "foo", version: "1.0", release: "2"},
		tpkg{name: "foo", version: "2.0", release: "1", epoch: 1},
		tpkg{name: "foo", version: "2.0", release: "1", epoch: 1, arch: "i686"},
		tpkg{name: "py.12", version: "3"},
	)

	for spec, want := range map[string]string{
		"foo":                "foo-1:2.0-1.x86_64",
		"foo.i686":           "foo-1:2.0-1.i686",
		"foo-1.0":            "foo-0:1.0-2.x86_64",
		"foo-1.0-2":          "foo-0:1.0-2.x86_64",
		"foo-1.0-2.x86_64":   "foo-0:1.0-2.x86_64",
		"foo-1:2.0-1":        "foo-1:2.0-1.x86_64",
		"1:foo-2.0-1.x86_64": "foo-1:2.0-1.x86_64",
		"foo-1:2.0-1.i686":   "foo-1:2.0-1.i686",
		"py.12":              "py.12-0:3-1.x86_64",
		"py.12-3":            "py.12-0:3-1.x86_64",
		"foo >= 1.5":         "foo-1:2.0-1.x86_64",
	} {
		res := resolve(t, ix, spec)
		if len(res.Packages) != 1 || res.Packages[0].NEVRA() != want {
			t.Errorf("%q: packages = %v (unresolved %v), want %s", spec, res.Packages, res.Unresolved, want)
		}
	}
}

func TestResolveWeakDependencies(t *testing.T) {
	ix := testIndex(nil,
		tpkg{
			name:       "app",
			requires:   []string{"(plugin if app)", "(libA or libB)"},
			recommends: []string{"extra", "absent-recommend"},
		},
		tpkg{name: "extra", requires: []string{"extra-lib"}},
		tpkg{name: "extra-lib"},
		tpkg{name: "plugin"},
		tpkg{name: "libB"},
	)

	res := resolve(t, ix, "app")
	if got := pkgNames(res.Packages); got != "plugin libB extra-lib extra app" && got != "plugin libB app extra-lib extra" {
		t.Errorf("packages = %q", got)
	}

	if len(res.Unresolved) != 0 {
		t.Errorf("a weak dependency was reported: %v", res.Unresolved)
	}

	res = resolveNoWeak(t, ix, "app")
	if got := pkgNames(res.Packages); got != "plugin libB app" {
		t.Errorf("without weak dependencies: packages = %q", got)
	}
}

func TestResolveWeakDependencyWithUnsatisfiableRequirementIsDropped(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "app", recommends: []string{"extra"}},
		tpkg{name: "extra", requires: []string{"ghost"}, conflicts: nil},
	)

	res := resolve(t, ix, "app")
	if got := pkgNames(res.Packages); got != "app" || len(res.Unresolved) != 0 {
		t.Errorf("packages = %q, unresolved %v", got, res.Unresolved)
	}
}

func TestResolveWeakDepsFromConfig(t *testing.T) {
	ix := testIndex(nil, tpkg{name: "app", recommends: []string{"extra"}}, tpkg{name: "extra"})
	ix.cfg = &Config{InstallWeakDeps: false}

	if got := pkgNames(resolve(t, ix, "app").Packages); got != "app" {
		t.Errorf("packages = %q", got)
	}

	res, err := ix.ResolveWith(context.Background(), []string{"app"}, ResolveOptions{WeakDeps: WeakEnabled})
	if err != nil || pkgNames(res.Packages) != "app extra" {
		t.Errorf("packages = %v, %v", res, err)
	}
}

func TestResolveLateHardRequirementOfWeakMiss(t *testing.T) {
	// "ghost" is first reached weakly (a Recommends) and found missing; the
	// hard Requires that follows must still report it.
	ix := testIndex(nil,
		tpkg{name: "a", recommends: []string{"ghost"}, requires: []string{"b"}},
		tpkg{name: "b", requires: []string{"ghost"}},
	)

	res := resolve(t, ix, "a")
	if !reflect.DeepEqual(res.Unresolved, []string{"ghost"}) {
		t.Errorf("unresolved = %v", res.Unresolved)
	}
}

func TestResolveRichDependencies(t *testing.T) {
	for name, tc := range map[string]struct {
		requires  string
		installed []string
		want      string
		unres     []string
	}{
		"and":                             {"(x and y)", nil, "x y app", nil},
		"and missing":                     {"(x and ghost)", nil, "x app", []string{"ghost"}},
		"or first":                        {"(x or y)", nil, "x app", nil},
		"or second when first is missing": {"(ghost or y)", nil, "y app", nil},
		"or already satisfied":            {"(x or y)", []string{"y"}, "app", nil},
		"or none":                         {"(ghost or ghost2)", nil, "app", []string{"(ghost or ghost2)"}},
		"if holds":                        {"(x if z)", []string{"z"}, "x app", nil},
		"if does not hold":                {"(x if z)", nil, "app", nil},
		"if holds in transaction":         {"(x if app)", nil, "x app", nil},
		"unless holds":                    {"(x unless z)", []string{"z"}, "app", nil},
		"unless does not hold":            {"(x unless z)", nil, "x app", nil},
		"if else":                         {"(x if z else y)", nil, "y app", nil},
		"if else true":                    {"(x if z else y)", []string{"z"}, "x app", nil},
		"unless else":                     {"(x unless z else y)", []string{"z"}, "y app", nil},
		"with":                            {"(cap with other)", nil, "both app", nil},
		"without":                         {"(cap without other)", nil, "plain app", nil},
		"nested":                          {"((x or ghost) and (y if x))", nil, "x y app", nil},
		"syntax error":                    {"(x and", nil, "app", []string{"(x and"}},
	} {
		t.Run(name, func(t *testing.T) {
			var inst []*rpm.Package
			for _, n := range tc.installed {
				inst = append(inst, installedPkg(tpkg{name: n}))
			}

			ix := testIndex(fakeInstalled{pkgs: inst},
				tpkg{name: "app", requires: []string{tc.requires}},
				tpkg{name: "x"}, tpkg{name: "y"}, tpkg{name: "z"},
				tpkg{name: "both", provides: []string{"cap", "other"}},
				tpkg{name: "plain", provides: []string{"cap"}},
			)

			if name == "with" {
				// "plain" must not satisfy "with other"
				ix = testIndex(fakeInstalled{}, tpkg{name: "app", requires: []string{tc.requires}},
					tpkg{name: "both", provides: []string{"cap", "other"}}, tpkg{name: "plain", provides: []string{"cap"}})
			}

			if name == "without" {
				ix = testIndex(fakeInstalled{}, tpkg{name: "app", requires: []string{tc.requires}},
					tpkg{name: "both", provides: []string{"cap", "other"}}, tpkg{name: "plain", provides: []string{"cap"}})
			}

			res := resolveNoWeak(t, ix, "app")
			if got := pkgNames(res.Packages); got != tc.want {
				t.Errorf("packages = %q, want %q", got, tc.want)
			}

			if !reflect.DeepEqual(res.Unresolved, tc.unres) {
				t.Errorf("unresolved = %v, want %v", res.Unresolved, tc.unres)
			}
		})
	}
}

func TestResolveConditionalLooksAgainWhenTheTransactionGrows(t *testing.T) {
	// "(plugin if lib)": lib is only pulled in by the second requirement.
	ix := testIndex(nil,
		tpkg{name: "app", requires: []string{"(plugin if lib)", "lib"}},
		tpkg{name: "lib"},
		tpkg{name: "plugin"},
	)

	if got := pkgNames(resolveNoWeak(t, ix, "app").Packages); got != "lib plugin app" && got != "lib app plugin" && got != "plugin lib app" {
		t.Errorf("packages = %q", got)
	}
}

func TestResolveFileRequirementFromPrimaryFiles(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "app", requires: []string{"/usr/bin/tool", "(/etc/conf or ghost)"}},
		tpkg{name: "tools", files: []string{"/usr/bin/tool"}},
		tpkg{name: "conf", files: []string{"/etc/conf"}},
	)

	res := resolve(t, ix, "app")
	if got := pkgNames(res.Packages); got != "tools conf app" || len(res.Unresolved) != 0 {
		t.Errorf("packages = %q, unresolved %v", got, res.Unresolved)
	}

	// a file seed
	res = resolve(t, ix, "/usr/bin/tool")
	if got := pkgNames(res.Packages); got != "tools" {
		t.Errorf("file seed: packages = %q", got)
	}
}

func TestResolveObsoletes(t *testing.T) {
	installed := fakeInstalled{pkgs: []*rpm.Package{
		installedPkg(tpkg{name: "old", version: "1.5"}),
		installedPkg(tpkg{name: "keep", version: "3"}),
	}}

	ix := testIndex(installed,
		tpkg{name: "new", obsoletes: []string{"old < 2", "keep < 2"}, provides: []string{"old = 2"}},
		tpkg{name: "app", requires: []string{"old"}},
	)

	res := resolve(t, ix, "new")
	if len(res.Obsoleted) != 1 || res.Obsoleted[0].Old.Name != "old" || res.Obsoleted[0].New.Name != "new" {
		t.Errorf("obsoleted = %+v", res.Obsoleted)
	}

	// A package that is obsoleted by the host is not installed to meet a need.
	ix = testIndex(fakeInstalled{pkgs: []*rpm.Package{
		installedPkg(tpkg{name: "successor", obsoletes: []string{"old"}}),
	}}, tpkg{name: "old", provides: []string{"cap"}}, tpkg{name: "app", requires: []string{"cap"}})

	if res := resolve(t, ix, "app"); !reflect.DeepEqual(res.Unresolved, []string{"cap"}) {
		t.Errorf("unresolved = %v, packages %v", res.Unresolved, res.Packages)
	}

	// obsoletes are off
	ix = testIndex(installed, tpkg{name: "new", obsoletes: []string{"old"}})
	ix.cfg = &Config{Obsoletes: false}

	if res := resolve(t, ix, "new"); len(res.Obsoleted) != 0 {
		t.Errorf("obsoleted = %+v", res.Obsoleted)
	}
}

func TestResolveConflicts(t *testing.T) {
	installed := fakeInstalled{pkgs: []*rpm.Package{installedPkg(tpkg{name: "sendmail", provides: []string{"mta"}})}}

	ix := testIndex(installed,
		tpkg{name: "postfix", provides: []string{"mta"}, conflicts: []string{"sendmail"}},
		tpkg{name: "exim", provides: []string{"mta"}},
		tpkg{name: "mailer", requires: []string{"mta"}},
		tpkg{name: "other-conflict", conflicts: []string{"mta"}},
		tpkg{name: "reverse", provides: []string{"x"}},
	)

	// the host already has an mta
	if res := resolve(t, ix, "mailer"); pkgNames(res.Packages) != "mailer" {
		t.Errorf("packages = %q", pkgNames(res.Packages))
	}

	// asking for postfix explicitly conflicts with sendmail
	res := resolve(t, ix, "postfix")
	if len(res.Packages) != 0 || len(res.Conflicts) != 1 || res.Conflicts[0].With == nil ||
		res.Conflicts[0].With.Name != "sendmail" || res.Conflicts[0].Package.Name != "postfix" {
		t.Errorf("resolution = %+v", res)
	}

	// the other way round: an installed package conflicts with the provider
	res = resolve(t, ix, "other-conflict")
	if len(res.Conflicts) != 1 {
		t.Errorf("conflicts = %+v", res.Conflicts)
	}

	// of two providers, the one that does not conflict is taken
	ix = testIndex(nil,
		tpkg{name: "app", requires: []string{"sendmail", "mta"}},
		tpkg{name: "sendmail", provides: []string{"mta"}},
		tpkg{name: "aaa-postfix", provides: []string{"mta"}, conflicts: []string{"sendmail"}},
	)

	if res := resolve(t, ix, "app"); pkgNames(res.Packages) != "sendmail app" {
		t.Errorf("packages = %q, conflicts %+v", pkgNames(res.Packages), res.Conflicts)
	}

	// a rich conflict
	ix = testIndex(installed, tpkg{name: "rich", conflicts: []string{"(sendmail or ghost)"}})
	if res := resolve(t, ix, "rich"); len(res.Conflicts) != 1 || res.Conflicts[0].With != nil {
		t.Errorf("conflicts = %+v", res.Conflicts)
	}
}

func TestResolveProvidersPreference(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "app", requires: []string{"cap"}},
		tpkg{name: "zeta", provides: []string{"cap"}},
		tpkg{name: "alpha", provides: []string{"cap"}},
		tpkg{name: "cap"},
		tpkg{name: "app2", requires: []string{"cap2"}},
		tpkg{name: "beta", provides: []string{"cap2"}, priority: 10},
		tpkg{name: "alpha2", provides: []string{"cap2"}},
		tpkg{name: "app3", requires: []string{"cap3"}},
		tpkg{name: "p-old", version: "1", provides: []string{"cap3"}},
		tpkg{name: "p-old", version: "2", provides: []string{"cap3"}},
		tpkg{name: "p-old", version: "9", arch: "i686", provides: []string{"cap3"}},
	)

	// the name asked for wins over any other provider
	if got := pkgNames(resolve(t, ix, "app").Packages); got != "cap app" {
		t.Errorf("by name: %q", got)
	}

	// the better priority wins
	if got := pkgNames(resolve(t, ix, "app2").Packages); got != "beta app2" {
		t.Errorf("by priority: %q", got)
	}

	// of one name: host architecture, then the highest version
	res := resolve(t, ix, "app3")
	if got := pkgNames(res.Packages); got != "p-old app3" || res.Packages[0].Version != "2" {
		t.Errorf("by version: %v", res.Packages)
	}
}

func TestResolveCostDecidesBetweenIdenticalPackages(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "a", cost: 2000},
		tpkg{name: "a", cost: 500},
	)

	if p, _ := ix.Lookup("a"); p.Cost != 500 {
		t.Errorf("cost = %d", p.Cost)
	}
}

func TestResolveMultilib(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "lib", arch: "i686", version: "2"},
		tpkg{name: "lib", version: "2"},
		tpkg{name: "other-lib", arch: "i686"},
		tpkg{name: "other-lib", arch: "i686", version: "5"},
	)

	if res := resolve(t, ix, "lib"); len(res.Packages) != 1 || res.Packages[0].Arch != "x86_64" {
		t.Errorf("packages = %v", res.Packages)
	}

	// MultilibAll also takes the 32-bit one
	ix.cfg = &Config{MultilibPolicy: MultilibAll, InstallWeakDeps: true, Obsoletes: true}
	if res := resolve(t, ix, "lib"); len(res.Packages) != 2 {
		t.Errorf("multilib all: packages = %v", res.Packages)
	}

	// the 32-bit only package is installable on a 64-bit host
	if res := resolve(t, ix, "other-lib"); len(res.Packages) != 1 || res.Packages[0].Version != "5" {
		t.Errorf("packages = %v", res.Packages)
	}

	// versions of the two architectures of one name must be the same
	ix = testIndex(fakeInstalled{pkgs: []*rpm.Package{installedPkg(tpkg{name: "lib", version: "1"})}},
		tpkg{name: "lib", arch: "i686", version: "2"},
		tpkg{name: "app", requires: []string{"lib(x86-32)"}},
		tpkg{name: "lib32", provides: []string{"lib(x86-32)"}},
	)

	if res := resolve(t, ix, "app"); pkgNames(res.Packages) != "lib32 app" {
		t.Errorf("packages = %v, conflicts %v", res.Packages, res.Conflicts)
	}
}

func TestResolveRepairsInstalledPackagesThatAnUpgradeBreaks(t *testing.T) {
	installed := fakeInstalled{pkgs: []*rpm.Package{
		installedPkg(tpkg{name: "core", version: "1"}),
		installedPkg(tpkg{name: "plugin", version: "1", requires: []string{"core < 2"}}),
		installedPkg(tpkg{name: "stuck", version: "1", requires: []string{"core < 2"}}),
	}}

	ix := testIndex(installed,
		tpkg{name: "core", version: "2"},
		tpkg{name: "plugin", version: "2", requires: []string{"core >= 2"}},
		tpkg{name: "stuck", version: "1", release: "2", requires: []string{"core < 2"}},
	)

	res := resolve(t, ix, "core")
	if got := pkgNames(res.Packages); got != "core plugin" && got != "plugin core" {
		t.Errorf("packages = %q", got)
	}

	if len(res.Conflicts) != 1 || res.Conflicts[0].With.Name != "stuck" || res.Conflicts[0].Package == nil ||
		res.Conflicts[0].Package.Name != "core" {
		t.Errorf("conflicts = %+v", res.Conflicts)
	}
}

func TestResolveRepairsByAnotherProvider(t *testing.T) {
	installed := fakeInstalled{pkgs: []*rpm.Package{
		installedPkg(tpkg{name: "provider", version: "1", provides: []string{"cap"}}),
		installedPkg(tpkg{name: "user", requires: []string{"cap"}}),
	}}

	ix := testIndex(installed,
		tpkg{name: "provider", version: "2"},
		tpkg{name: "backup", provides: []string{"cap"}},
	)

	res := resolve(t, ix, "provider")
	if got := pkgNames(res.Packages); got != "provider backup" {
		t.Errorf("packages = %q", got)
	}
}

func TestResolveSeedNotInstallableIsReported(t *testing.T) {
	ix := testIndex(nil,
		tpkg{name: "a", conflicts: []string{"b"}},
		tpkg{name: "b"},
	)

	res := resolve(t, ix, "b", "a")
	if pkgNames(res.Packages) != "b" || len(res.Conflicts) != 1 || res.Conflicts[0].Package.Name != "a" {
		t.Errorf("resolution = %+v", res)
	}
}

func TestResolveMissingSeedWithConstraint(t *testing.T) {
	res := resolve(t, testIndex(nil), "gone >= 1.0", "")
	if !reflect.DeepEqual(res.Unresolved, []string{"gone >= 1.0"}) {
		t.Errorf("unresolved = %v", res.Unresolved)
	}
}

func TestResolveCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := testIndex(nil, tpkg{name: "a"}).Resolve(ctx, []string{"a"}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}
