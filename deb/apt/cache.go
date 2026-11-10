package apt

import (
	"errors"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/M0Rf30/pkgformat/deb"
)

// ErrDependencyDepth is returned by ResolveDeps for a dependency chain deeper
// than maxResolveDepth, which only a hostile or corrupt index produces.
var ErrDependencyDepth = errors.New("apt: dependency chain too deep")

// maxResolveDepth bounds the recursion of ResolveDeps. Real Debian chains are
// shorter than 50.
const maxResolveDepth = 4096

// archAll is the Architecture value of architecture-independent packages.
const archAll = "all"

// PackageInfo is the subset of a package's control fields that dependency
// resolution and downloading need.
type PackageInfo struct {
	// Name is the package name ("gcc", "libssl-dev").
	Name string
	// Architecture is the Architecture field ("amd64", "all", "arm64").
	Architecture string
	// Essential is true for "Essential: yes".
	Essential bool
	// MultiArch is the Multi-Arch field ("same", "foreign", "allowed" or "").
	MultiArch string
	// Installed is true when the dpkg status database reports the package as
	// installed (see [deb.Status.Installed]).
	Installed bool
	// HasCandidate is true when the package has a version in an apt index, that
	// is, it is a real installable package and not a pure virtual one.
	HasCandidate bool
	// Filename is the path of the .deb relative to the repository base URL
	// ("pool/main/g/gcc/gcc_12.2.0-14_amd64.deb").
	Filename string
	// SHA256 is the expected SHA-256 of the .deb, hex encoded.
	SHA256 string
	// Size is the expected size of the .deb in bytes.
	Size int64
	// BaseURL is the repository URL Filename is relative to, such as
	// "https://ports.ubuntu.com/ubuntu-ports/". Empty for packages that only
	// come from the dpkg status database, which cannot be downloaded.
	BaseURL string
	// Depends lists the package names of the Depends field: the first
	// alternative of every entry, without version constraint.
	Depends []string
	// PreDepends is the same for Pre-Depends.
	PreDepends []string
	// Version is the Version field. When one name and architecture comes from
	// several repositories, the highest version wins.
	Version string
}

// ArchitectureAll reports whether the package is architecture-independent.
func (p PackageInfo) ArchitectureAll() bool { //nolint:gocritic // small value type
	return strings.EqualFold(p.Architecture, archAll)
}

// MultiArchForeign reports whether one copy of the package on the host
// satisfies dependencies from any architecture (Multi-Arch: foreign or
// allowed): tools and daemons that run on the build host, which must not be
// qualified with a target architecture during cross-compilation. Multi-Arch:
// same, the -dev libraries, is deliberately excluded.
func (p PackageInfo) MultiArchForeign() bool { //nolint:gocritic // small value type
	ma := strings.ToLower(p.MultiArch)

	return ma == "foreign" || ma == "allowed"
}

// MultiArchSame reports whether the package must be installed once per
// architecture (Multi-Arch: same).
func (p PackageInfo) MultiArchSame() bool { //nolint:gocritic // small value type
	return strings.EqualFold(p.MultiArch, "same")
}

// ArchFromGoarch maps a runtime.GOARCH value to the Debian architecture name.
func ArchFromGoarch(goarch string) string {
	switch goarch {
	case "arm":
		return "armhf"
	case "386":
		return "i386"
	case "ppc64le":
		return "ppc64el"
	default:
		return goarch
	}
}

// Cache is an in-memory index of package metadata keyed by name and
// architecture, merged from apt package indexes and the dpkg status database.
// It is safe for concurrent use.
type Cache struct {
	hostArch string

	mu      sync.RWMutex
	entries map[string]*PackageInfo
	// providers maps a virtual package name to the concrete packages providing
	// it, in index order.
	providers map[string][]string
	// byBareName maps a package name to the entry keys of its architecture
	// qualified entries ("gcc-11:amd64", "gcc-11:arm64"), so the any-architecture
	// fallback does not scan every entry.
	byBareName map[string][]string
}

// NewCache returns an empty cache. hostArch is the architecture packages are
// looked up for when a name carries no qualifier; empty selects the one of the
// running program.
func NewCache(hostArch string) *Cache {
	if hostArch == "" {
		hostArch = ArchFromGoarch(runtime.GOARCH)
	}

	return &Cache{
		hostArch:   hostArch,
		entries:    make(map[string]*PackageInfo),
		providers:  make(map[string][]string),
		byBareName: make(map[string][]string),
	}
}

// HostArch is the architecture unqualified names resolve to.
func (c *Cache) HostArch() string { return c.hostArch }

// entryKey builds the key of a package: name and architecture. Entries of
// architecture all, or without one, are stored under the bare name.
func entryKey(name, arch string) string {
	if arch == "" || arch == archAll {
		return name
	}

	return name + ":" + arch
}

// addToBareName records an entry key in the byBareName index; c.mu must be held.
func (c *Cache) addToBareName(name, key string) {
	// Bare keys are found directly and need no index entry.
	if key != name && !slices.Contains(c.byBareName[name], key) {
		c.byBareName[name] = append(c.byBareName[name], key)
	}
}

// AddEntry inserts or replaces an entry. Use it to set a cache up by hand,
// before it is shared.
func (c *Cache) AddEntry(info *PackageInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cp := *info
	key := entryKey(info.Name, info.Architecture)
	c.entries[key] = &cp
	c.addToBareName(info.Name, key)
}

// Lookup returns the entry of the named package. The name may carry an
// architecture qualifier ("gcc-11:arm64"). Without one, or when the qualified
// entry is missing, it tries the bare name (architecture all), the host
// architecture, then any architecture.
func (c *Cache) Lookup(name string) (PackageInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if idx := strings.IndexByte(name, ':'); idx >= 0 {
		if p, ok := c.entries[name]; ok {
			return *p, true
		}

		name = name[:idx]
	}

	if p, ok := c.entries[name]; ok {
		return *p, true
	}

	if p, ok := c.entries[name+":"+c.hostArch]; ok {
		return *p, true
	}

	if p, ok := c.entries[name+":"+archAll]; ok {
		return *p, true
	}

	// A package that exists only for a foreign architecture. Misses are the
	// common case here (virtual packages), so this stays an index lookup.
	if p, ok := c.scanEntryByName(name); ok {
		return *p, true
	}

	return PackageInfo{}, false
}

// PackageCount is the number of entries in the cache.
func (c *Cache) PackageCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}

// CapabilityCount is the number of virtual package names (Provides) known.
func (c *Cache) CapabilityCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.providers)
}

// ResolveVirtual returns the first concrete provider of a virtual package, or
// name itself when it is a real package (it has a candidate) or unknown.
func (c *Cache) ResolveVirtual(name string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, key := range []string{name, name + ":" + c.hostArch, name + ":" + archAll} {
		if p, ok := c.entries[key]; ok && p.HasCandidate {
			return name
		}

		if bare, _, found := strings.Cut(key, ":"); found {
			if p, ok := c.entries[bare]; ok && p.HasCandidate {
				return name
			}
		}
	}

	if providers := c.providers[name]; len(providers) > 0 {
		return providers[0]
	}

	return name
}

// InstalledNames returns the names, without architecture qualifier, of the
// packages the dpkg status database reports as installed. A name counts when
// at least one architecture of it is installed.
//
// Cross-build extractors use it to avoid overlaying a foreign-architecture
// payload on host binaries whose path is shared between architectures
// (/usr/bin/sudo is one file, and may be in use).
func (c *Cache) InstalledNames() map[string]bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make(map[string]bool)

	for _, info := range c.entries {
		if !info.Installed {
			continue
		}

		name, _, _ := strings.Cut(info.Name, ":")
		out[name] = true
	}

	return out
}

// ResolveDeps resolves the transitive dependencies of seeds. It returns the
// packages to download in dependency order (dependencies before dependents),
// and the names that are not in the index.
//
// Installed packages are not listed, but their dependencies are still walked.
// Virtual packages resolve to their first provider, alternatives to their first
// option, and version constraints are ignored. A seed may carry an
// architecture qualifier ("libc6-dev:arm64"); it is inherited by every
// dependency, so that resolution is consistent when several architectures'
// indexes are loaded. A chain deeper than a few thousand packages fails with
// ErrDependencyDepth.
func (c *Cache) ResolveDeps(seeds []string) ([]*PackageInfo, []string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	r := &resolver{c: c, visited: make(map[string]bool), emitted: make(map[string]bool)}

	for _, seed := range seeds {
		seed = strings.TrimSpace(seed)

		name, arch, _ := strings.Cut(seed, ":")

		if i := strings.Index(arch, "("); i >= 0 {
			arch = strings.TrimSpace(arch[:i])
		}

		if i := strings.Index(name, "("); i >= 0 {
			name = strings.TrimSpace(name[:i])
		}

		if err := r.visit(name, arch); err != nil {
			return nil, nil, err
		}
	}

	return r.order, r.unresolved, nil
}

// resolver is the state of one ResolveDeps walk, a post-order DFS keyed by
// name:arch. Cycles end at the visited set, which is filled before recursing.
type resolver struct {
	c       *Cache
	visited map[string]bool
	// emitted dedupes on the resolved entry. visited is keyed by the requested
	// name:arch, but several requests can land on one entry (architecture all
	// packages, host-only or Multi-Arch: foreign packages reached as both
	// :arm64 and :amd64); listing it twice would make the download stage fetch
	// one .deb twice, concurrently, into one file.
	emitted    map[string]bool
	order      []*PackageInfo
	unresolved []string
	depth      int
}

func (r *resolver) visit(name, arch string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}

	if arch == "" {
		arch = r.c.hostArch
	}

	key := entryKey(name, arch)
	if r.visited[key] {
		return nil
	}

	r.visited[key] = true

	if r.depth >= maxResolveDepth {
		return ErrDependencyDepth
	}

	r.depth++
	defer func() { r.depth-- }()

	info, ok := r.c.find(name, arch)
	if !ok {
		if resolved := r.c.tryResolveVirtual(name); resolved != "" {
			return r.visit(resolved, arch)
		}

		r.unresolved = append(r.unresolved, name)

		return nil
	}

	info, arch = r.c.redirectForeignToHost(info, name, arch)

	// A package found for another architecture than requested (an arm64 entry
	// for an amd64 request) hands its own architecture to its dependencies.
	if info.Architecture != "" && info.Architecture != arch && info.Architecture != archAll {
		arch = info.Architecture
	}

	for _, d := range info.PreDepends {
		if err := r.visit(d, arch); err != nil {
			return err
		}
	}

	for _, d := range info.Depends {
		if err := r.visit(d, arch); err != nil {
			return err
		}
	}

	if info.Installed {
		return nil
	}

	if id := resolvedEntryID(info); !r.emitted[id] {
		r.emitted[id] = true

		r.order = append(r.order, info)
	}

	return nil
}

// find locates the entry for name and arch: the exact key, the bare name
// (architecture all), the host architecture, then any architecture. The host
// fallback covers a host-only package that a cross build qualified with the
// target architecture (gcc-aarch64-linux-gnu has no arm64 variant).
func (c *Cache) find(name, arch string) (*PackageInfo, bool) {
	if info, ok := c.entries[entryKey(name, arch)]; ok {
		return info, true
	}

	if info, ok := c.entries[name]; ok {
		return info, true
	}

	if info, ok := c.entries[name+":"+c.hostArch]; ok {
		return info, true
	}

	return c.scanEntryByName(name)
}

// resolvedEntryID identifies a concrete index entry independently of the
// name:arch it was requested under. The pool Filename is unique per package,
// version and architecture.
func resolvedEntryID(info *PackageInfo) string {
	if info.Filename != "" {
		return info.Filename
	}

	return info.Name + ":" + info.Architecture + "=" + info.Version
}

// redirectForeignToHost sends Multi-Arch: foreign packages to the host
// architecture. One copy of such a package serves every architecture, and by
// definition it is a host tool (gawk, perl, m4, autoconf): pulling the arm64
// build into a cross-extract would overlay an arm64 gawk on the host's and
// break later configure scripts with "Exec format error".
func (c *Cache) redirectForeignToHost(info *PackageInfo, name, arch string) (*PackageInfo, string) {
	if !info.MultiArchForeign() || arch == c.hostArch {
		return info, arch
	}

	hostInfo, ok := c.entries[entryKey(name, c.hostArch)]
	if !ok {
		return info, arch
	}

	return hostInfo, c.hostArch
}

// tryResolveVirtual returns the first provider of a virtual package, or "".
func (c *Cache) tryResolveVirtual(name string) string {
	if providers := c.providers[name]; len(providers) > 0 {
		return providers[0]
	}

	return ""
}

// scanEntryByName returns the first architecture qualified entry of a bare
// name.
func (c *Cache) scanEntryByName(name string) (*PackageInfo, bool) {
	keys := c.byBareName[name]
	if len(keys) == 0 {
		return nil, false
	}

	info, ok := c.entries[keys[0]]

	return info, ok
}

// versionWins reports whether candidate is a strictly higher Debian version.
func versionWins(candidate, existing string) bool {
	return deb.CompareVersions(candidate, existing) > 0
}
