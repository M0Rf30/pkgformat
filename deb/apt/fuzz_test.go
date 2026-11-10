package apt

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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

		for _, info := range c.entries {
			if info.Name == "" {
				t.Fatalf("entry without a name: %+v", info)
			}

			// A name with a colon is no Debian package name, and Lookup reads
			// the colon as an architecture qualifier.
			if _, ok := c.Lookup(info.Name); !ok && !strings.Contains(info.Name, ":") {
				t.Fatalf("entry %q is not found by Lookup", info.Name)
			}

			c.ResolveVirtual(info.Name)
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

		seeds := []string{"unknown", "unknown:arm64", ""}

		for _, info := range c.entries {
			seeds = append(seeds, info.Name, info.Name+":arm64", info.Name+":"+info.Architecture)

			if len(seeds) > 64 {
				break
			}
		}

		order, _, err := c.ResolveDeps(seeds)
		if err != nil {
			if !errors.Is(err, ErrDependencyDepth) {
				t.Fatalf("unexpected error: %v", err)
			}

			return
		}

		ids := make([]string, 0, len(order))

		for _, p := range order {
			if p.Installed {
				t.Fatalf("installed package %q listed", p.Name)
			}

			id := resolvedEntryID(p)
			if slices.Contains(ids, id) {
				t.Fatalf("package %q listed twice", id)
			}

			ids = append(ids, id)
		}
	})
}
