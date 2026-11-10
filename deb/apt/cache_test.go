package apt

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageInfoPredicates(t *testing.T) {
	t.Parallel()

	assert.True(t, PackageInfo{Architecture: "all"}.ArchitectureAll())
	assert.True(t, PackageInfo{Architecture: "ALL"}.ArchitectureAll())
	assert.False(t, PackageInfo{Architecture: "amd64"}.ArchitectureAll())

	for ma, want := range map[string][3]bool{ // foreign, same, ... see below
		"foreign": {true, false, false},
		"Allowed": {true, false, false},
		"same":    {false, true, false},
		"SAME":    {false, true, false},
		"":        {false, false, false},
		"no":      {false, false, false},
	} {
		p := PackageInfo{MultiArch: ma}
		assert.Equal(t, want[0], p.MultiArchForeign(), "foreign %q", ma)
		assert.Equal(t, want[1], p.MultiArchSame(), "same %q", ma)
	}
}

func TestArchFromGoarch(t *testing.T) {
	t.Parallel()

	for goarch, want := range map[string]string{
		"amd64": "amd64", "arm64": "arm64", "arm": "armhf", "386": "i386",
		"ppc64le": "ppc64el", "s390x": "s390x", "riscv64": "riscv64",
	} {
		assert.Equal(t, want, ArchFromGoarch(goarch), goarch)
	}
}

func TestNewCache(t *testing.T) {
	t.Parallel()

	assert.Equal(t, ArchFromGoarch(runtime.GOARCH), NewCache("").HostArch())
	assert.Equal(t, "arm64", NewCache("arm64").HostArch())

	c := NewCache("amd64")
	assert.Zero(t, c.PackageCount())
	assert.Zero(t, c.CapabilityCount())
	assert.Empty(t, c.InstalledNames())

	_, ok := c.Lookup("nothing")
	assert.False(t, ok)
}

func TestLookupOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []PackageInfo
		query   string
		wantVer string // Version of the entry expected; "" means a miss
	}{
		{
			name:    "bare all entry beats the host architecture",
			entries: []PackageInfo{{Name: "foo", Architecture: "all", Version: "all"}, {Name: "foo", Architecture: "amd64", Version: "host"}},
			query:   "foo", wantVer: "all",
		},
		{
			name:    "entry without architecture is bare",
			entries: []PackageInfo{{Name: "foo", Version: "bare"}, {Name: "foo", Architecture: "amd64", Version: "host"}},
			query:   "foo", wantVer: "bare",
		},
		{
			name:    "host architecture beats another one",
			entries: []PackageInfo{{Name: "foo", Architecture: "arm64", Version: "arm"}, {Name: "foo", Architecture: "amd64", Version: "host"}},
			query:   "foo", wantVer: "host",
		},
		{
			name:    "any architecture is the last resort",
			entries: []PackageInfo{{Name: "foo", Architecture: "arm64", Version: "arm"}},
			query:   "foo", wantVer: "arm",
		},
		{
			name:    "qualified name finds its architecture",
			entries: []PackageInfo{{Name: "foo", Architecture: "arm64", Version: "arm"}, {Name: "foo", Architecture: "amd64", Version: "host"}},
			query:   "foo:arm64", wantVer: "arm",
		},
		{
			name:    "qualified miss falls back to the bare name",
			entries: []PackageInfo{{Name: "foo", Architecture: "all", Version: "all"}, {Name: "foo", Architecture: "amd64", Version: "host"}},
			query:   "foo:s390x", wantVer: "all",
		},
		{
			name:    "qualified miss falls back to the host architecture",
			entries: []PackageInfo{{Name: "foo", Architecture: "amd64", Version: "host"}},
			query:   "foo:s390x", wantVer: "host",
		},
		{
			name:    "qualified miss falls back to any architecture",
			entries: []PackageInfo{{Name: "foo", Architecture: "arm64", Version: "arm"}},
			query:   "foo:s390x", wantVer: "arm",
		},
		{
			name:    "unknown name",
			entries: []PackageInfo{{Name: "foo", Architecture: "amd64"}},
			query:   "bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := NewCache("amd64")
			for i := range tt.entries {
				c.AddEntry(&tt.entries[i])
			}

			got, ok := c.Lookup(tt.query)
			if tt.wantVer == "" {
				assert.False(t, ok)

				return
			}

			require.True(t, ok)
			assert.Equal(t, tt.wantVer, got.Version)
		})
	}
}

func TestAddEntryCopiesAndReplaces(t *testing.T) {
	t.Parallel()

	c := NewCache("amd64")
	info := &PackageInfo{Name: "foo", Architecture: "amd64", Version: "1"}
	c.AddEntry(info)

	info.Version = "mutated"

	got, ok := c.Lookup("foo")
	require.True(t, ok)
	assert.Equal(t, "1", got.Version, "the cache keeps its own copy")

	c.AddEntry(&PackageInfo{Name: "foo", Architecture: "amd64", Version: "2"})
	got, _ = c.Lookup("foo")
	assert.Equal(t, "2", got.Version)
	assert.Equal(t, 1, c.PackageCount())
	assert.Len(t, c.byBareName["foo"], 1, "the bare-name index has no duplicate")
}

func TestResolveVirtual(t *testing.T) {
	t.Parallel()

	c := cacheFromText(t, para("Package: exim4", "Version: 1", "Architecture: amd64", "Provides: mail-transport-agent, foo (= 1.0), bar:any")+
		para("Package: postfix", "Version: 1", "Architecture: amd64", "Provides: mail-transport-agent")+
		para("Package: real", "Version: 1", "Architecture: amd64", "Provides: virt")+
		para("Package: virt", "Version: 2", "Architecture: amd64")+
		para("Package: allpkg", "Version: 1", "Architecture: all", "Provides: allvirt")+
		para("Package: ghost", "Architecture: amd64", "Provides: ghostly")+
		para("Package: star", "Version: 1", "Architecture: amd64", "Priority: standard", "Provides: ranked")+
		para("Package: moon", "Version: 1", "Architecture: amd64", "Priority: optional", "Provides: ranked"))

	assert.Equal(t, "postfix", c.ResolveVirtual("mail-transport-agent"), "the provider read last, as apt prefers it")
	assert.Equal(t, "exim4", c.ResolveVirtual("foo"), "version suffix of a provide is dropped")
	assert.Equal(t, "exim4", c.ResolveVirtual("bar"), "architecture qualifier of a provide is dropped")
	assert.Equal(t, "star", c.ResolveVirtual("ranked"), "the higher priority beats the later provider")
	assert.Equal(t, "virt", c.ResolveVirtual("virt"), "a real package is not replaced by its providers")
	assert.Equal(t, "allpkg", c.ResolveVirtual("allpkg"))
	assert.Equal(t, "allpkg", c.ResolveVirtual("allvirt"))
	assert.Equal(t, "ghostly", c.ResolveVirtual("ghostly"), "a stanza without Version is not kept")
	assert.Equal(t, "unknown", c.ResolveVirtual("unknown"))
	assert.Positive(t, c.CapabilityCount())
}

func TestResolveVirtualBareAllWithQualifiedProbe(t *testing.T) {
	t.Parallel()

	c := NewCache("amd64")
	c.AddEntry(&PackageInfo{Name: "tool", Architecture: "all", HasCandidate: true})

	assert.Equal(t, "tool", c.ResolveVirtual("tool"))
}

func TestResolveDepsOrder(t *testing.T) {
	t.Parallel()

	c := cacheFromText(t, para("Package: app", "Version: 1", "Architecture: amd64", "Depends: lib (>= 1), tool | other", "Pre-Depends: base", "Filename: pool/app.deb")+
		para("Package: lib", "Version: 1", "Architecture: amd64", "Depends: deep", "Filename: pool/lib.deb")+
		para("Package: deep", "Version: 1", "Architecture: amd64", "Filename: pool/deep.deb")+
		para("Package: base", "Version: 1", "Architecture: amd64", "Filename: pool/base.deb")+
		para("Package: tool", "Version: 1", "Architecture: amd64", "Filename: pool/tool.deb")+
		para("Package: other", "Version: 1", "Architecture: amd64", "Filename: pool/other.deb"))

	order, unresolved, err := c.ResolveDeps([]string{"app"})
	require.NoError(t, err)
	assert.Empty(t, unresolved)
	assert.Equal(t, []string{"base:amd64", "deep:amd64", "lib:amd64", "tool:amd64", "app:amd64"}, names(order),
		"Pre-Depends first, dependencies before dependents, first alternative that installs")
}

func TestResolveDepsCycle(t *testing.T) {
	t.Parallel()

	c := cacheFromText(t, para("Package: a", "Version: 1", "Architecture: amd64", "Depends: b", "Filename: a.deb")+
		para("Package: b", "Version: 1", "Architecture: amd64", "Depends: c", "Filename: b.deb")+
		para("Package: c", "Version: 1", "Architecture: amd64", "Depends: a, c", "Filename: c.deb"))

	order, unresolved, err := c.ResolveDeps([]string{"a"})
	require.NoError(t, err)
	assert.Empty(t, unresolved)
	assert.ElementsMatch(t, []string{"a:amd64", "b:amd64", "c:amd64"}, names(order))
}

func TestResolveDepsVirtualAndUnresolved(t *testing.T) {
	t.Parallel()

	c := cacheFromText(t, para("Package: app", "Version: 1", "Architecture: amd64", "Depends: mta, missing, mta", "Filename: app.deb")+
		para("Package: exim4", "Version: 1", "Architecture: amd64", "Provides: mta", "Filename: exim4.deb"))

	order, unresolved, err := c.ResolveDeps([]string{"app", "", "  ", "nothere (>= 1)"})
	require.NoError(t, err)
	assert.Equal(t, []string{"exim4:amd64", "app:amd64"}, names(order))
	assert.Equal(t, []string{"missing", "nothere"}, unresolved)
}

func TestResolveDepsSeedForms(t *testing.T) {
	t.Parallel()

	c := cacheFromText(t, para("Package: foo", "Version: 1", "Architecture: amd64", "Filename: foo.deb"))

	for _, seed := range []string{"foo", " foo ", "foo (>= 1)", "foo:amd64", "foo:amd64 (>= 1)"} {
		order, unresolved, err := c.ResolveDeps([]string{seed})
		require.NoError(t, err, seed)
		assert.Equal(t, []string{"foo:amd64"}, names(order), seed)
		assert.Empty(t, unresolved, seed)
	}

	order, unresolved, err := c.ResolveDeps(nil)
	require.NoError(t, err)
	assert.Empty(t, order)
	assert.Empty(t, unresolved)
}

func TestResolveDepsInstalledSkippedAndNotWalked(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, dir+"/example.org_dists_x_main_binary-amd64_Packages",
		para("Package: app", "Version: 1", "Architecture: amd64", "Depends: libx", "Filename: app.deb")+
			para("Package: libx", "Version: 1", "Architecture: amd64", "Depends: libdeep", "Filename: libx.deb")+
			para("Package: libdeep", "Version: 1", "Architecture: amd64", "Filename: libdeep.deb"))
	writeFile(t, dir+"/status", para("Package: libx", "Status: install ok installed", "Architecture: amd64", "Version: 1"))

	c, err := Load(LoadOptions{ListsDir: dir, StatusFile: dir + "/status", HostArch: hostArch})
	require.NoError(t, err)

	order, _, err := c.ResolveDeps([]string{"app"})
	require.NoError(t, err)
	assert.Equal(t, []string{"app:amd64"}, names(order), "libx is installed, and is taken to have its dependencies")

	order, _, err = c.ResolveDeps([]string{"libx"})
	require.NoError(t, err)
	assert.Empty(t, order, "an installed seed at the newest version is skipped")
}

func TestResolveDepsArchitectureInheritance(t *testing.T) {
	t.Parallel()

	c := cacheFromFiles(t, map[string]string{
		indexName("x", "main", "amd64"): para("Package: libc6", "Version: 1", "Architecture: amd64", "Multi-Arch: same", "Filename: libc6_amd64.deb") +
			para("Package: libc6-dev", "Version: 1", "Architecture: amd64", "Depends: libc6", "Filename: libc6-dev_amd64.deb"),
		indexName("x", "main", "arm64"): para("Package: libc6", "Version: 1", "Architecture: arm64", "Multi-Arch: same", "Filename: libc6_arm64.deb") +
			para("Package: libc6-dev", "Version: 1", "Architecture: arm64", "Depends: libc6", "Filename: libc6-dev_arm64.deb"),
	})

	order, unresolved, err := c.ResolveDeps([]string{"libc6-dev:arm64"})
	require.NoError(t, err)
	assert.Empty(t, unresolved)
	assert.Equal(t, []string{"libc6:arm64", "libc6-dev:arm64"}, names(order))

	order, _, err = c.ResolveDeps([]string{"libc6-dev"})
	require.NoError(t, err)
	assert.Equal(t, []string{"libc6:amd64", "libc6-dev:amd64"}, names(order))
}

func TestResolveDepsForeignPackageForeignEntryHandsItsArchitecture(t *testing.T) {
	t.Parallel()

	// Only an arm64 entry exists; an amd64 request lands on it and its
	// dependencies are then resolved for arm64.
	c := cacheFromFiles(t, map[string]string{
		indexName("x", "main", "arm64"): para("Package: only-arm", "Version: 1", "Architecture: arm64", "Depends: dep", "Filename: only-arm.deb") +
			para("Package: dep", "Version: 1", "Architecture: arm64", "Filename: dep_arm64.deb"),
		indexName("x", "main", "amd64"): para("Package: dep", "Version: 1", "Architecture: amd64", "Filename: dep_amd64.deb"),
	})

	order, _, err := c.ResolveDeps([]string{"only-arm"})
	require.NoError(t, err)
	assert.Equal(t, []string{"dep:arm64", "only-arm:arm64"}, names(order))
}

func TestResolveDepsMultiArchForeignRedirect(t *testing.T) {
	t.Parallel()

	c := cacheFromFiles(t, map[string]string{
		indexName("x", "main", "amd64"): para("Package: gawk", "Version: 1", "Architecture: amd64", "Multi-Arch: foreign", "Depends: libgmp", "Filename: gawk_amd64.deb") +
			para("Package: libgmp", "Version: 1", "Architecture: amd64", "Filename: libgmp_amd64.deb") +
			para("Package: only-host-tool", "Version: 1", "Architecture: amd64", "Multi-Arch: foreign", "Filename: oht_amd64.deb"),
		indexName("x", "main", "arm64"): para("Package: app", "Version: 1", "Architecture: arm64", "Depends: gawk, only-host-tool", "Filename: app_arm64.deb") +
			para("Package: gawk", "Version: 1", "Architecture: arm64", "Multi-Arch: foreign", "Depends: libgmp", "Filename: gawk_arm64.deb") +
			para("Package: libgmp", "Version: 1", "Architecture: arm64", "Filename: libgmp_arm64.deb"),
	})

	order, _, err := c.ResolveDeps([]string{"app:arm64"})
	require.NoError(t, err)
	assert.Equal(t, []string{"libgmp:amd64", "gawk:amd64", "only-host-tool:amd64", "app:arm64"}, names(order),
		"a foreign package, and what it needs, come from the host architecture")
}

func TestResolveDepsForeignWithoutHostEntryStays(t *testing.T) {
	t.Parallel()

	c := cacheFromFiles(t, map[string]string{
		indexName("x", "main", "arm64"): para("Package: app", "Version: 1", "Architecture: arm64", "Depends: tool", "Filename: app.deb") +
			para("Package: tool", "Version: 1", "Architecture: arm64", "Multi-Arch: allowed", "Filename: tool_arm64.deb"),
	})

	order, _, err := c.ResolveDeps([]string{"app:arm64"})
	require.NoError(t, err)
	assert.Equal(t, []string{"tool:arm64", "app:arm64"}, names(order))
}

func TestResolveDepsEmittedDedup(t *testing.T) {
	t.Parallel()

	c := cacheFromFiles(t, map[string]string{
		indexName("x", "main", "amd64"): para("Package: a", "Version: 1", "Architecture: amd64", "Depends: docs", "Filename: a.deb") +
			para("Package: docs", "Version: 1", "Architecture: all", "Filename: docs_all.deb"),
		indexName("x", "main", "arm64"): para("Package: b", "Version: 1", "Architecture: arm64", "Depends: docs", "Filename: b.deb"),
	})

	order, _, err := c.ResolveDeps([]string{"a:amd64", "b:arm64"})
	require.NoError(t, err)
	assert.Equal(t, []string{"docs:all", "a:amd64", "b:arm64"}, names(order), "the all package is listed once")

	// Hand-built entries without a Filename or Version: name and architecture
	// are the identity.
	c3 := NewCache("amd64")
	c3.AddEntry(&PackageInfo{Name: "r", Architecture: "amd64", Version: "1"})
	c3.AddEntry(&PackageInfo{Name: "r", Architecture: "arm64", Version: "1"})

	order, _, err = c3.ResolveDeps([]string{"r", "r:arm64", "r"})
	require.NoError(t, err)
	assert.Len(t, order, 2)
}

func TestResolveDepsHostFallbackForQualifiedSeed(t *testing.T) {
	t.Parallel()

	c := cacheFromText(t, para("Package: gcc-cross", "Version: 1", "Architecture: amd64", "Filename: gcc.deb"))

	order, unresolved, err := c.ResolveDeps([]string{"gcc-cross:arm64"})
	require.NoError(t, err)
	assert.Empty(t, unresolved)
	assert.Equal(t, []string{"gcc-cross:amd64"}, names(order))
}

func TestResolveDepsBareAllForForeignRequest(t *testing.T) {
	t.Parallel()

	c := cacheFromText(t, para("Package: docs", "Version: 1", "Architecture: all", "Filename: docs.deb"))

	order, _, err := c.ResolveDeps([]string{"docs:arm64"})
	require.NoError(t, err)
	assert.Equal(t, []string{"docs:all"}, names(order))
}

// chain builds n packages p0 -> p1 -> ... -> p(n-1).
func chain(n int) string {
	var sb strings.Builder

	for i := range n {
		lines := []string{fmt.Sprintf("Package: p%d", i), "Version: 1", "Architecture: amd64", fmt.Sprintf("Filename: p%d.deb", i)}
		if i+1 < n {
			lines = append(lines, fmt.Sprintf("Depends: p%d", i+1))
		}

		sb.WriteString(para(lines...))
	}

	return sb.String()
}

func TestResolveDepsDepthLimit(t *testing.T) {
	t.Parallel()

	c := cacheFromText(t, chain(maxResolveDepth+10))

	order, unresolved, err := c.ResolveDeps([]string{"p0"})
	require.ErrorIs(t, err, ErrDependencyDepth)
	assert.Nil(t, order)
	assert.Nil(t, unresolved)

	c = cacheFromText(t, chain(500))
	order, _, err = c.ResolveDeps([]string{"p0"})
	require.NoError(t, err)
	assert.Len(t, order, 500)
	assert.Equal(t, "p499:amd64", names(order)[0])
}

func TestInstalledNames(t *testing.T) {
	t.Parallel()

	c := NewCache("amd64")
	c.AddEntry(&PackageInfo{Name: "sudo", Architecture: "amd64", Installed: true})
	c.AddEntry(&PackageInfo{Name: "sudo", Architecture: "arm64"})
	c.AddEntry(&PackageInfo{Name: "libfoo", Architecture: "arm64"})
	c.AddEntry(&PackageInfo{Name: "docs", Architecture: "all", Installed: true})

	assert.Equal(t, map[string]bool{"sudo": true, "docs": true}, c.InstalledNames())
}

func TestCacheConcurrentUse(t *testing.T) {
	t.Parallel()

	c := cacheFromText(t, chain(50))

	var wg sync.WaitGroup

	for i := range 16 {
		wg.Go(func() {
			if i%4 == 0 {
				c.AddEntry(&PackageInfo{Name: fmt.Sprintf("extra%d", i), Architecture: "amd64"})
			}

			_, ok := c.Lookup("p3")
			assert.True(t, ok)

			order, _, err := c.ResolveDeps([]string{"p0"})
			assert.NoError(t, err)
			assert.Len(t, order, 50)

			_ = c.ResolveVirtual("p1")
			_ = c.InstalledNames()
			_ = c.PackageCount()
			_ = c.CapabilityCount()
		})
	}

	wg.Wait()
}
