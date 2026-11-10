package dnf

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// testIndex builds an index of the given packages without a repository.
func testIndex(installed Installed, pkgs ...*Package) *Index {
	ix := newIndex("x86_64", installed, nil)
	for _, p := range pkgs {
		if p.Location == "" {
			p.Location = "Packages/" + p.Name + ".rpm"
		}

		if p.Arch == "" {
			p.Arch = "x86_64"
		}

		ix.add(p)
	}

	return ix
}

func resolve(t *testing.T, ix *Index, seeds ...string) *Resolution {
	t.Helper()

	res, err := ix.Resolve(context.Background(), seeds)
	if err != nil {
		t.Fatal(err)
	}

	return res
}

func TestResolveOrdersDependenciesFirst(t *testing.T) {
	ix := testIndex(nil,
		&Package{Name: "app", Version: "1", Requires: []string{"libb >= 2", "liba"}},
		&Package{Name: "liba", Version: "1", Requires: []string{"base"}},
		&Package{Name: "libb", Version: "2", Requires: []string{"base"}},
		&Package{Name: "base", Version: "1"},
		&Package{Name: "unrelated", Version: "1"},
	)

	res := resolve(t, ix, "app")
	if got := pkgNames(res.Packages); got != "base libb liba app" || len(res.Unresolved) != 0 {
		t.Errorf("packages = %q, unresolved %v", got, res.Unresolved)
	}
}

func TestResolveDeduplicatesSeedsAndHandlesCycles(t *testing.T) {
	ix := testIndex(nil,
		&Package{Name: "a", Version: "1", Requires: []string{"b"}},
		&Package{Name: "b", Version: "1", Requires: []string{"a"}},
	)

	res := resolve(t, ix, "a", "b", "a >= 1")
	if got := pkgNames(res.Packages); got != "b a" {
		t.Errorf("packages = %q", got)
	}
}

func TestResolveVirtualCapabilities(t *testing.T) {
	ix := testIndex(nil,
		&Package{Name: "app", Version: "1", Requires: []string{"webserver", "/usr/bin/tool", "libz.so.1()(64bit)"}},
		&Package{Name: "httpd-i686", Version: "1", Arch: "i686", Provides: []string{"webserver"}},
		&Package{Name: "httpd", Version: "1", Provides: []string{"webserver = 2.4"}},
		&Package{Name: "tools", Version: "1", Provides: []string{"/usr/bin/tool"}},
		&Package{Name: "zlib", Version: "1", Provides: []string{"libz.so.1()(64bit)"}},
	)

	res := resolve(t, ix, "app")
	if got := pkgNames(res.Packages); got != "httpd tools zlib app" || len(res.Unresolved) != 0 {
		t.Errorf("packages = %q, unresolved %v", got, res.Unresolved)
	}
}

func TestResolveUnresolved(t *testing.T) {
	ix := testIndex(nil,
		&Package{Name: "app", Version: "1", Requires: []string{"missing-a", "present", "missing-b"}},
		&Package{Name: "present", Version: "1"},
	)

	res := resolve(t, ix, "app", "missing-seed")
	if !reflect.DeepEqual(res.Unresolved, []string{"missing-a", "missing-b", "missing-seed"}) {
		t.Errorf("unresolved = %v", res.Unresolved)
	}

	if got := pkgNames(res.Packages); got != "present app" {
		t.Errorf("packages = %q", got)
	}
}

func TestResolveSkipsInstalled(t *testing.T) {
	// coreutils is installed and provides /usr/bin/ls; coreutils-single also
	// does, and must not be pulled in to satisfy it.
	ix := testIndex(fakeInstalled{
		names:    []string{"coreutils", "glibc"},
		provides: []string{"/usr/bin/ls", "libc.so.6()(64bit)", "config(x) = 1"},
	},
		&Package{Name: "app", Version: "1", Requires: []string{"/usr/bin/ls", "glibc", "libc.so.6()(64bit)", "other"}},
		&Package{Name: "coreutils-single", Version: "1", Provides: []string{"/usr/bin/ls"}},
		&Package{Name: "glibc", Version: "1", Requires: []string{"never-walked"}},
		&Package{Name: "other", Version: "1"},
	)

	res := resolve(t, ix, "app")
	if got := pkgNames(res.Packages); got != "other app" || len(res.Unresolved) != 0 {
		t.Errorf("packages = %q, unresolved %v", got, res.Unresolved)
	}
}

func TestResolveInstalledErrors(t *testing.T) {
	boom := errors.New("database locked")
	ix := testIndex(fakeInstalled{err: boom}, &Package{Name: "a", Version: "1"})

	if _, err := ix.Resolve(context.Background(), []string{"a"}); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
}

func TestResolveWeakDependencies(t *testing.T) {
	ix := testIndex(nil,
		&Package{
			Name: "app", Version: "1",
			Requires:   []string{"(plugin if app)", "(libA or libB)"},
			Recommends: []string{"extra", "absent-recommend"},
		},
		&Package{Name: "extra", Version: "1"},
		&Package{Name: "plugin", Version: "1"},
		&Package{Name: "libB", Version: "1"},
	)

	res := resolve(t, ix, "app")
	if got := pkgNames(res.Packages); got != "plugin libB extra app" {
		t.Errorf("packages = %q", got)
	}

	if len(res.Unresolved) != 0 {
		t.Errorf("a weak dependency was reported: %v", res.Unresolved)
	}
}

func TestResolveLateHardRequirementOfWeakMiss(t *testing.T) {
	// "ghost" is first reached weakly (a Recommends) and found missing; the
	// hard Requires that follows must still report it.
	ix := testIndex(nil,
		&Package{Name: "a", Version: "1", Recommends: []string{"ghost"}, Requires: []string{"b"}},
		&Package{Name: "b", Version: "1", Requires: []string{"ghost"}},
	)

	res := resolve(t, ix, "a")
	if !reflect.DeepEqual(res.Unresolved, []string{"ghost"}) {
		t.Errorf("unresolved = %v", res.Unresolved)
	}
}

func TestResolveMissingSeedWithStrippedConstraint(t *testing.T) {
	res := resolve(t, testIndex(nil), "gone >= 1.0", "")
	if !reflect.DeepEqual(res.Unresolved, []string{"gone"}) {
		t.Errorf("unresolved = %v", res.Unresolved)
	}
}

func TestResolveCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := testIndex(nil).Resolve(ctx, []string{"a"}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestStripRPMConstraint(t *testing.T) {
	for in, want := range map[string]string{
		"glibc >= 2.17":                 "glibc",
		"  glibc  ":                     "glibc",
		"libfoo(x86-64)":                "libfoo(x86-64)",
		"/usr/bin/sh":                   "/usr/bin/sh",
		"(a if b)":                      "(a if b)",
		"foo = 1:2.0-3":                 "foo",
		"":                              "",
		"libc.so.6(GLIBC_2.2.5)(64bit)": "libc.so.6(GLIBC_2.2.5)(64bit)",
	} {
		if got := StripRPMConstraint(in); got != want {
			t.Errorf("StripRPMConstraint(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpandBooleanDep(t *testing.T) {
	for in, want := range map[string][]string{
		"(gcc-plugin-annobin if gcc)":          {"gcc-plugin-annobin", "gcc"},
		"(libA or libB)":                       {"libA", "libB"},
		"(a and (b or c))":                     {"a", "b", "c"},
		"(foo >= 1.2 with bar)":                {"foo", "bar"},
		"(foo = 1 unless bar)":                 {"foo", "bar"},
		"(langpacks-%{lang} if %{name})":       {"langpacks-%{lang}", "%{name}"},
		"(a if (b and rpmlib(PayloadIsZstd)))": {"a", "b"},
		"(libfoo(x86-64) or libbar(x86-64))":   {"libfoo(x86-64)", "libbar(x86-64)"},
		"(a, b)":                               {"a", "b"},
		"(A IF B)":                             {"A", "B"},
		"( )":                                  nil,
		"plain":                                nil,
		"":                                     nil,
		"(a else b then c)":                    {"a", "b", "c"},
		"(foo > 1 or bar < 2 or baz <= 3 or qux == 4)": {"foo", "bar", "baz", "qux"},
	} {
		if got := ExpandBooleanDep(in); !reflect.DeepEqual(got, want) {
			t.Errorf("ExpandBooleanDep(%q) = %q, want %q", in, got, want)
		}
	}

	if !IsBooleanDep(" (a or b)") || IsBooleanDep("a") {
		t.Error("IsBooleanDep")
	}
}
