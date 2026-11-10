package apt

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/deb"
)

var fuzzIndexSeeds = []string{
	"",
	"Package: a\nVersion: 1\nArchitecture: amd64\nFilename: pool/a.deb\nSize: 3\nSHA256: aa\n\n",
	"Package: a\nVersion: 1\nArchitecture: amd64\nDepends: b (>= 1), c | d\nPre-Depends: e\nProvides: v, w (= 1)\n\n" +
		"Package: b\nVersion: 2:1.0-1\nArchitecture: all\nMulti-Arch: foreign\nEssential: yes\n\n" +
		"Package: e\nVersion: 1\nArchitecture: arm64\nDepends: a\n\n",
	"Package: loop\nVersion: 1\nArchitecture: amd64\nDepends: loop, loop:arm64\n\n",
	"Package: x\nVersion: 1\nDescription: first\n second\n .\n third\nDepends: y,\n z\n\n",
	"Package: only-virtual\nArchitecture: amd64\nProvides: p1, p2\n\n",
	"Package:\nVersion:\n\n\n\nPackage: z\n",
	"Package: a\nStatus: install ok installed\nVersion: 1\n\n",
	"\x00\xff\xfe garbage",
}

// FuzzLoadIndex feeds arbitrary bytes to the index loader as a plain,
// gzip-framed and mislabelled Packages file.
func FuzzLoadIndex(f *testing.F) {
	for _, seed := range fuzzIndexSeeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()

		files := map[string][]byte{
			"example.org_dists_x_main_binary-amd64_Packages":      data,
			"example.org_dists_x_gz_binary-amd64_Packages.gz":     gzipBytes(t, data),
			"example.org_dists_x_badgz_binary-amd64_Packages.gz":  data,
			"example.org_dists_x_badxz_binary-arm64_Packages.xz":  data,
			"example.org_dists_x_badbz_binary-arm64_Packages.bz2": data,
		}

		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
				t.Fatal(err)
			}
		}

		c, err := Load(LoadOptions{ListsDir: dir, HostArch: "amd64", Sources: []Source{{URL: "http://example.org/"}}})
		if c == nil {
			t.Fatalf("Load returned a nil cache (err %v)", err)
		}

		for _, versions := range c.slots {
			for i, info := range versions {
				if info.Name == "" || info.Version == "" {
					t.Fatalf("entry without a name or version: %+v", info)
				}

				if i > 0 && deb.CompareVersions(versions[i-1].Version, info.Version) < 0 {
					t.Fatalf("versions of %q are not sorted: %q before %q", info.Name, versions[i-1].Version, info.Version)
				}

				// A name with a colon is no Debian package name, and Lookup
				// reads the colon as an architecture qualifier.
				if _, ok := c.Lookup(info.Name); !ok && !strings.Contains(info.Name, ":") {
					t.Fatalf("entry %q is not found by Lookup", info.Name)
				}

				c.ResolveVirtual(info.Name)
			}
		}

		_ = c.InstalledNames()
	})
}

// FuzzResolveDeps loads arbitrary index text and resolves every package in it,
// plus names it does not hold. The walk has to end without panicking.
func FuzzResolveDeps(f *testing.F) {
	for _, seed := range fuzzIndexSeeds {
		f.Add(seed)
	}

	f.Add("Package: a\nVersion: 2\nArchitecture: amd64\nDepends: b (>= 1) | c, d:any\nConflicts: e\nBreaks: b (<< 2)\n\n" +
		"Package: a\nVersion: 1\nArchitecture: amd64\nDepends: b\n\n" +
		"Package: b\nVersion: 1\nArchitecture: amd64\nProvides: c (= 1), d\nMulti-Arch: allowed\n\n" +
		"Package: e\nVersion: 3\nArchitecture: arm64\nConflicts: a (<< 2)\nPre-Depends: b\n\n")
	f.Add("Package: a\nVersion: 1\nArchitecture: amd64\nDepends: a:arm64\n\nPackage: a\nVersion: 1\nArchitecture: arm64\nMulti-Arch: foreign\nDepends: a\n\n")

	f.Fuzz(func(t *testing.T, text string) {
		dir := t.TempDir()

		if err := os.WriteFile(filepath.Join(dir, "example.org_dists_x_main_binary-amd64_Packages"), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}

		c, _ := Load(LoadOptions{ListsDir: dir, HostArch: "amd64"})
		if c == nil {
			t.Fatal("nil cache")
		}

		// Install the lowest version of every third package, so that
		// upgrades, conflicts with installed packages and dependents of
		// replaced versions are exercised too.
		var status strings.Builder

		for i, key := range slices.Sorted(maps.Keys(c.slots)) {
			versions := c.slots[key]
			low := versions[len(versions)-1]

			if i%3 == 0 {
				fmt.Fprintf(&status, "Package: %s\nStatus: install ok installed\nArchitecture: %s\nVersion: %s\nDepends: %s\n\n",
					low.Name, low.Architecture, low.Version, flatDepends(low))
			}
		}

		statusFile := filepath.Join(dir, "status")
		if err := os.WriteFile(statusFile, []byte(status.String()), 0o644); err != nil {
			t.Fatal(err)
		}

		c, _ = Load(LoadOptions{ListsDir: dir, StatusFile: statusFile, HostArch: "amd64"})

		seeds := []string{"unknown", "unknown:arm64", "a|b", "x (>= 1)"}

		for _, key := range slices.Sorted(maps.Keys(c.slots)) {
			info := c.slots[key][0]
			seeds = append(seeds, info.Name, info.Name+":arm64", info.Name+":"+info.Architecture, info.Name+" (= "+info.Version+")")

			if len(seeds) > 64 {
				break
			}
		}

		order, unresolved, err := c.ResolveDeps(seeds)
		if err != nil {
			if !errors.Is(err, ErrDependencyDepth) && !errors.Is(err, ErrUnsatisfiable) && !errors.Is(err, ErrResolveLimit) &&
				!errors.Is(err, deb.ErrInvalidControlFormat) {
				t.Fatalf("unexpected error: %v", err)
			}

			again, _, err2 := c.ResolveDeps(seeds)
			if again != nil || err2 == nil || err2.Error() != err.Error() {
				t.Fatalf("the error is not deterministic: %v then %v", err, err2)
			}

			return
		}

		again, againUnresolved, err := c.ResolveDeps(seeds)
		if err != nil || !slices.Equal(names(order), names(again)) || !slices.Equal(unresolved, againUnresolved) {
			t.Fatalf("not deterministic: %v then %v (%v)", names(order), names(again), err)
		}

		assertClosure(t, c, order)
	})
}

// flatDepends writes the Depends of a version back as a field.
func flatDepends(p *pkg) string {
	return deb.FormatRelations(p.Depends)
}

// assertClosure checks the invariants of a successful resolution: nothing
// installed is listed, no slot twice, and every dependency of a listed package
// that names something the index knows is met by the installed and listed
// packages together.
func assertClosure(t *testing.T, c *Cache, order []*PackageInfo) {
	t.Helper()

	r := newResolution(c)
	slots := map[string]bool{}

	for _, info := range order {
		key := entryKey(info.Name, info.Architecture)
		if slots[key] {
			t.Fatalf("package %q listed twice", key)
		}

		slots[key] = true

		for _, p := range c.slots[key] {
			if &p.PackageInfo == info {
				r.sel[key] = p
			}
		}

		if r.sel[key] == nil {
			t.Fatalf("listed package %q is not a version of the cache", key)
		}

		if in := c.installed[key]; in != nil && in == r.sel[key] {
			t.Fatalf("installed package %q listed", key)
		}
	}

	for _, p := range r.sel {
		goal := goal{owner: p}

		for _, group := range slices.Concat(p.PreDepends, p.Depends) {
			known := slices.ContainsFunc(group, func(rel deb.Relation) bool { return c.known(rel.Name) })
			if known && !r.groupSatisfied(group, goal.arch(r.native), false) {
				t.Fatalf("%s: dependency %s is not met by the result", label(p), group)
			}
		}
	}
}
