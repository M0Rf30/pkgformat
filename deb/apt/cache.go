package apt

import (
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/M0Rf30/pkgformat/deb"
)

// archAll is the Architecture value of architecture-independent packages.
const archAll = "all"

// PackageInfo is the subset of a package's control fields that dependency
// resolution and downloading need. One value describes one version of one
// package on one architecture.
type PackageInfo struct {
	// Name is the package name ("gcc", "libssl-dev").
	Name string
	// Architecture is the Architecture field ("amd64", "all", "arm64").
	Architecture string
	// Essential is true for "Essential: yes".
	Essential bool
	// MultiArch is the Multi-Arch field ("same", "foreign", "allowed" or "").
	MultiArch string
	// Priority is the Priority field ("required", "optional", ...). It orders
	// the candidates of a virtual package.
	Priority string
	// Installed is true when the dpkg status database reports this version as
	// installed (see [deb.Status.Installed]).
	Installed bool
	// HasCandidate is true when this version is in an apt index, that is, it
	// can be downloaded. An installed version that no index carries any more
	// has none.
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
	// Depends is the Depends field, one [deb.Alternatives] per entry.
	Depends []deb.Alternatives
	// PreDepends is the same for Pre-Depends. Resolution treats both alike.
	PreDepends []deb.Alternatives
	// Conflicts is the Conflicts field.
	Conflicts []deb.Relation
	// Breaks is the Breaks field.
	Breaks []deb.Relation
	// Provides is the Provides field: the virtual packages, with the version
	// of a versioned one ("foo (= 1.2)").
	Provides []deb.Relation
	// Version is the Version field.
	Version string
}

// ArchitectureAll reports whether the package is architecture-independent.
func (p PackageInfo) ArchitectureAll() bool { //nolint:gocritic // small value type
	return strings.EqualFold(p.Architecture, archAll)
}

// MultiArchForeign reports whether one copy of the package on the host is
// meant to serve every architecture (Multi-Arch: foreign or allowed): tools
// and daemons that run on the build host, which must not be qualified with a
// target architecture during cross-compilation. Multi-Arch: same, the -dev
// libraries, is deliberately excluded. The resolver itself follows apt more
// closely: only "foreign" satisfies a dependency from another architecture,
// and only "allowed" satisfies one written "name:any".
func (p PackageInfo) MultiArchForeign() bool { //nolint:gocritic // small value type
	ma := strings.ToLower(p.MultiArch)

	return ma == "foreign" || ma == "allowed"
}

// MultiArchSame reports whether the package must be installed once per
// architecture (Multi-Arch: same).
func (p PackageInfo) MultiArchSame() bool { //nolint:gocritic // small value type
	return strings.EqualFold(p.MultiArch, "same")
}

// available reports whether the version can be installed: it is in an index,
// or it is a hand-built entry that says nothing about being installed.
func (p *PackageInfo) available() bool { return p.HasCandidate || !p.Installed }

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

// pkg is the stored form of one version of a package.
type pkg struct {
	PackageInfo

	// seq is the insertion order: apt prefers the provider it read last.
	seq int
	// slot is the key of the name:arch group the version belongs to.
	slot string
}

// Cache is an in-memory index of package metadata, merged from apt package
// indexes and the dpkg status database. Every version of a package that any
// index carries is kept, grouped by name and architecture. It is safe for
// concurrent use.
type Cache struct {
	hostArch string
	logger   *slog.Logger

	mu sync.RWMutex
	// slots maps a name:arch key to the versions of that package, the highest
	// version first.
	slots map[string][]*pkg
	// providers maps a virtual package name to the versions that provide it,
	// in insertion order.
	providers map[string][]*pkg
	// byBareName maps a package name to the slot keys of its architecture
	// qualified groups ("gcc-11:amd64", "gcc-11:arm64"), so the
	// any-architecture fallback does not scan every slot.
	byBareName map[string][]string
	// installed maps a slot key to its installed version.
	installed map[string]*pkg
	seq       int
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
		slots:      make(map[string][]*pkg),
		providers:  make(map[string][]*pkg),
		byBareName: make(map[string][]string),
		installed:  make(map[string]*pkg),
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

// addToBareName records a slot key in the byBareName index; c.mu must be held.
func (c *Cache) addToBareName(name, key string) {
	// Bare keys are found directly and need no index entry.
	if key != name && !slices.Contains(c.byBareName[name], key) {
		c.byBareName[name] = append(c.byBareName[name], key)
	}
}

// AddEntry adds a version of a package. An entry with the same name,
// architecture and version replaces the old one; another version is kept next
// to the others. Use it to set a cache up by hand, before it is shared.
func (c *Cache) AddEntry(info *PackageInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.insert(info, false)
}

// insert adds a version to its slot. When the slot already has that version,
// merge folds info into it, else info replaces it. c.mu must be held.
func (c *Cache) insert(info *PackageInfo, merge bool) {
	key := entryKey(info.Name, info.Architecture)
	versions := c.slots[key]

	if i := slices.IndexFunc(versions, func(e *pkg) bool { return e.Version == info.Version }); i >= 0 {
		existing := versions[i]

		c.unindexProvides(existing)

		if merge {
			mergeVersion(&existing.PackageInfo, info)
		} else {
			existing.PackageInfo = *info
		}

		c.indexVersion(existing)

		return
	}

	c.seq++
	p := &pkg{PackageInfo: *info, seq: c.seq, slot: key}

	pos, _ := slices.BinarySearchFunc(versions, p, func(e, target *pkg) int {
		// highest version first
		return deb.CompareVersions(target.Version, e.Version)
	})
	c.slots[key] = slices.Insert(versions, pos, p)

	c.addToBareName(info.Name, key)
	c.indexVersion(p)
}

// indexVersion adds a stored version to the providers and installed indexes.
func (c *Cache) indexVersion(p *pkg) {
	for _, prov := range p.Provides {
		if !slices.Contains(c.providers[prov.Name], p) {
			c.providers[prov.Name] = append(c.providers[prov.Name], p)
		}
	}

	if p.Installed {
		if cur, ok := c.installed[p.slot]; !ok || cur == p || deb.CompareVersions(p.Version, cur.Version) > 0 {
			c.installed[p.slot] = p
		}
	} else if c.installed[p.slot] == p {
		delete(c.installed, p.slot)
	}
}

// unindexProvides removes a stored version from the providers index; the
// version is about to change its Provides.
func (c *Cache) unindexProvides(p *pkg) {
	for _, prov := range p.Provides {
		list := slices.DeleteFunc(c.providers[prov.Name], func(e *pkg) bool { return e == p })
		if len(list) == 0 {
			delete(c.providers, prov.Name)
		} else {
			c.providers[prov.Name] = list
		}
	}
}

// mergeVersion folds info into the stored version existing, for the same name,
// architecture and version read from another file. Flags and provides
// accumulate; the artifact fields of an index follow the later file, so a tie
// favours the last index by file name, and a status-only version takes the
// artifacts of an index. The repository of an architecture all package stays
// the first one, so an _all.deb is never pointed at a foreign-architecture
// mirror (ports.ubuntu.com).
func mergeVersion(existing, info *PackageInfo) {
	existing.Essential = existing.Essential || info.Essential
	existing.Installed = existing.Installed || info.Installed

	if info.MultiArch != "" {
		existing.MultiArch = info.MultiArch
	}

	for _, prov := range info.Provides {
		if !slices.ContainsFunc(existing.Provides, func(r deb.Relation) bool { return r.String() == prov.String() }) {
			existing.Provides = append(existing.Provides, prov)
		}
	}

	if !info.HasCandidate {
		if !existing.HasCandidate && len(existing.Depends)+len(existing.PreDepends)+len(existing.Conflicts)+len(existing.Breaks) == 0 {
			existing.Depends, existing.PreDepends = info.Depends, info.PreDepends
			existing.Conflicts, existing.Breaks = info.Conflicts, info.Breaks
		}

		if existing.Priority == "" {
			existing.Priority = info.Priority
		}

		return
	}

	existing.HasCandidate = true
	existing.Depends, existing.PreDepends = info.Depends, info.PreDepends
	existing.Conflicts, existing.Breaks = info.Conflicts, info.Breaks

	if info.Priority != "" {
		existing.Priority = info.Priority
	}

	if info.Filename != "" {
		existing.Filename = info.Filename

		if info.BaseURL != "" && (existing.BaseURL == "" || !strings.EqualFold(info.Architecture, archAll)) {
			existing.BaseURL = info.BaseURL
		}
	}

	if info.SHA256 != "" {
		existing.SHA256 = info.SHA256
	}

	if info.Size > 0 {
		existing.Size = info.Size
	}
}

// slotKeysFor lists the slot keys a name can be found under, in the order
// Lookup tries them: the name as given, the bare name (architecture all), the
// host architecture, then every other architecture. c.mu must be held.
func (c *Cache) slotKeysFor(name string) []string {
	keys := make([]string, 0, 4)

	base := name
	if idx := strings.IndexByte(name, ':'); idx >= 0 {
		keys = append(keys, name)
		base = name[:idx]
	}

	keys = append(keys, base, base+":"+c.hostArch)

	for _, k := range c.byBareName[base] {
		if k != base+":"+c.hostArch {
			keys = append(keys, k)
		}
	}

	return keys
}

// pick returns the first version of a slot that accept admits, preferring one
// that can be installed over an installed-only one.
func pick(versions []*pkg, accept func(*pkg) bool) *pkg {
	var fallback *pkg

	for _, p := range versions {
		if accept != nil && !accept(p) {
			continue
		}

		if p.available() {
			return p
		}

		if fallback == nil {
			fallback = p
		}
	}

	return fallback
}

// lookup finds the version of the named package that Lookup returns, among
// those accept admits (nil admits all). c.mu must be held.
func (c *Cache) lookup(name string, accept func(*pkg) bool) *pkg {
	for _, key := range c.slotKeysFor(name) {
		if p := pick(c.slots[key], accept); p != nil {
			return p
		}
	}

	return nil
}

// Lookup returns the highest installable version of the named package. The
// name may carry an architecture qualifier ("gcc-11:arm64"). Without one, or
// when the qualified package is missing, it tries the bare name (architecture
// all), the host architecture, then any architecture. A package that is only
// installed, with no index version, is returned too, with HasCandidate false.
func (c *Cache) Lookup(name string) (PackageInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if p := c.lookup(name, nil); p != nil {
		return p.PackageInfo, true
	}

	return PackageInfo{}, false
}

// lookupSpec finds the version a package spec names: "name", "name:arch" or
// either with a version constraint ("name:arch (= 1.2)"), in which case the
// highest version that meets it. It returns the name part of the spec for
// error messages.
func (c *Cache) lookupSpec(spec string) (string, PackageInfo, bool) {
	spec = strings.TrimSpace(spec)

	groups, err := deb.ParseRelations(spec)
	if err != nil || len(groups) != 1 || len(groups[0]) != 1 {
		name, _, _ := strings.Cut(spec, "(")
		name = strings.TrimSpace(name)

		info, ok := c.Lookup(name)

		return name, info, ok
	}

	rel := groups[0][0]

	name := rel.Name
	if rel.Arch != "" {
		name += ":" + rel.Arch
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if p := c.lookup(name, func(p *pkg) bool { return rel.Satisfied(p.Version) }); p != nil {
		return name, p.PackageInfo, true
	}

	return name, PackageInfo{}, false
}

// Versions returns every known version of the named package, the highest
// first, from the first architecture Lookup would find it under.
func (c *Cache) Versions(name string) []PackageInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, key := range c.slotKeysFor(name) {
		if versions := c.slots[key]; len(versions) > 0 {
			out := make([]PackageInfo, len(versions))
			for i, p := range versions {
				out[i] = p.PackageInfo
			}

			return out
		}
	}

	return nil
}

// PackageCount is the number of packages in the cache, counting a name on two
// architectures twice and every version of one once.
func (c *Cache) PackageCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.slots)
}

// CapabilityCount is the number of virtual package names (Provides) known.
func (c *Cache) CapabilityCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.providers)
}

// notCandidate is 0 for the highest version of a name and architecture and 1
// for the others. c.mu is not needed: the resolver works on a snapshot taken
// under it.
func (c *Cache) notCandidate(p *pkg) int {
	if versions := c.slots[p.slot]; len(versions) > 0 && versions[0] == p {
		return 0
	}

	return 1
}

// priorityRank orders the Priority values; an unknown or missing one ranks
// lowest.
func priorityRank(priority string) int {
	switch strings.ToLower(priority) {
	case "required":
		return 5
	case "important":
		return 4
	case "standard":
		return 3
	case "optional":
		return 2
	case "extra":
		return 1
	default:
		return 0
	}
}

// providerOrder compares two providers of a virtual package the way apt picks
// among them without a preference: the higher priority first, then the one
// read later (apt prepends to the provider list). seq is unique to a version,
// so the order is total.
func providerOrder(a, b *pkg) int {
	if d := priorityRank(b.Priority) - priorityRank(a.Priority); d != 0 {
		return d
	}

	return b.seq - a.seq
}

// hasAvailable reports whether a real package of that name has an installable
// version on any architecture. c.mu must be held.
func (c *Cache) hasAvailable(name string) bool {
	for _, key := range c.slotKeysFor(name) {
		if slices.ContainsFunc(c.slots[key], func(p *pkg) bool { return p.available() }) {
			return true
		}
	}

	return false
}

// ResolveVirtual returns the name of the concrete package ResolveDeps prefers
// for a virtual package (the highest priority, then the provider read last),
// or name itself when it is a real package (it has a candidate) or unknown.
func (c *Cache) ResolveVirtual(name string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.hasAvailable(name) {
		return name
	}

	providers := slices.Clone(c.providers[name])
	providers = slices.DeleteFunc(providers, func(p *pkg) bool { return !p.available() })

	if len(providers) == 0 {
		return name
	}

	slices.SortStableFunc(providers, providerOrder)

	return providers[0].Name
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

	out := make(map[string]bool, len(c.installed))

	for _, p := range c.installed {
		out[p.Name] = true
	}

	return out
}
