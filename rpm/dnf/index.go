package dnf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/repodata"
	"github.com/M0Rf30/pkgformat/rpm/richdep"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// SystemRepo is the Repo of a [Package] that is installed on the host.
const SystemRepo = "@System"

// Package is a package, from a repository or installed: what the index keeps
// of an entry of primary.xml, enough to resolve its dependencies and to
// download it.
type Package struct {
	Name    string
	Arch    string
	Version string
	Release string
	Epoch   uint32
	// Location is the path of the .rpm relative to the repository; empty for
	// an installed package.
	Location string
	// Checksum is the hex digest of the .rpm and ChecksumType its algorithm
	// (sha256 or sha512 can be verified).
	Checksum     string
	ChecksumType string
	// Size is the size of the .rpm in bytes.
	Size int64
	// BaseURL is the mirror the metadata came from, where Location is
	// relative to. It is empty for a repository that was never fetched with a
	// working baseurl.
	BaseURL string
	// MirrorList is the repository's mirror list or metalink URL, with its
	// variables expanded. It supplies the fallbacks of a download.
	MirrorList string
	// The dependency lists of the package. Provides always has the package's
	// own name at its own version. Requires leaves out the rpmlib() features,
	// which no package provides. An entry may be a rich dependency: its Name
	// is the text in parentheses, see [richdep].
	Provides    []rpm.Dependency
	Requires    []rpm.Dependency
	Conflicts   []rpm.Dependency
	Obsoletes   []rpm.Dependency
	Recommends  []rpm.Dependency
	Suggests    []rpm.Dependency
	Supplements []rpm.Dependency
	Enhances    []rpm.Dependency
	// Files are the file paths the package owns that its repository lists in
	// primary.xml (the ones under /etc, /usr/bin, ...), or all of an installed
	// package's. The others are in filelists.xml, which a resolution reads
	// when a requirement of a file needs it.
	Files []string
	// Repo is the id of the repository the package comes from, [SystemRepo]
	// for an installed one.
	Repo string
	// Priority and Cost are those of that repository (see [Repo.Priority] and
	// [Repo.Cost]).
	Priority int
	Cost     int

	// repo carries the settings a download needs (proxy, gpgcheck, gpgkey).
	// It is nil for a Package not built by [Client.Load].
	repo *Repo
	// src is the repository source of a package from the index.
	src *repoSource
	// seq is the position of the package in the metadata, the last tie-break
	// of a choice.
	seq int
}

// Installed reports whether the package is one the host has.
func (p *Package) Installed() bool { return p.Repo == SystemRepo }

// EVR renders "epoch:version-release". It is for display: the string is not
// comparable with [rpm.Vercmp], which would run the version into the release
// ("1.0-5" would sort after "1.0.1-1"); use [Package.Compare].
func (p *Package) EVR() string {
	return strconv.FormatUint(uint64(p.Epoch), 10) + ":" + p.Version + "-" + p.Release
}

// NEVRA renders "name-epoch:version-release.arch", the way dnf shows a
// package.
func (p *Package) NEVRA() string {
	return p.Name + "-" + p.EVR() + "." + p.Arch
}

// String is [Package.NEVRA].
func (p *Package) String() string { return p.NEVRA() }

// Compare orders the versions of two packages the way rpm does: the epoch
// numerically, then the version and then the release with [rpm.Vercmp], each
// on its own. It returns -1 if p is older than other, 1 if it is newer, and 0
// if the versions are the same.
func (p *Package) Compare(other *Package) int {
	switch {
	case p.Epoch < other.Epoch:
		return -1
	case p.Epoch > other.Epoch:
		return 1
	}

	if c := rpm.Vercmp(p.Version, other.Version); c != 0 {
		return c
	}

	return rpm.Vercmp(p.Release, other.Release)
}

// self is the provide every package has of its own name and version.
func (p *Package) self() rpm.Dependency {
	return rpm.Dependency{
		Name:    p.Name,
		Flags:   tag.RPMSENSE_EQUAL,
		Version: p.Version + "-" + p.Release,
		Epoch:   p.Epoch,
	}
}

// addSelfProvide appends the own-name provide when the list lacks one.
func (p *Package) addSelfProvide() {
	for _, d := range p.Provides {
		if d.Name == p.Name {
			return
		}
	}

	p.Provides = append(p.Provides, p.self())
}

// provRef is one entry of the provides index.
type provRef struct {
	pkg  *Package
	atom richdep.Atom
}

// Index is an in-memory view of the metadata of the repositories, keyed by
// package name and by provided capability. It keeps every version and
// architecture of a package. It is safe for concurrent use once [Client.Load]
// returns it: the file lists a resolution needs are read lazily under a lock.
type Index struct {
	arch      string
	ranks     map[string]int
	cfg       *Config
	client    *Client
	installed Installed
	logger    *slog.Logger
	modules   *repodata.ModuleIndex

	// pending collects the packages as they are added, before finalize.
	pending []*Package
	// names holds the packages by name, the preferred first.
	names    map[string][]*Package
	provides map[string][]provRef
	// files maps a path of primary.xml to the packages that own it.
	files map[string][]*Package
	// wantFiles are the file paths some package requires, the ones a file
	// list is scanned for.
	wantFiles map[string]struct{}
	sources   []*repoSource

	lazyMu  sync.Mutex
	scanned map[string]struct{}
	owners  map[string][]*Package
}

func newIndex(c *Client, cfg *Config) *Index {
	return &Index{
		arch:      c.opts.Arch,
		ranks:     archRanks(c.opts.Arch),
		cfg:       cfg,
		client:    c,
		installed: c.opts.Installed,
		logger:    c.opts.Logger,
		modules:   &repodata.ModuleIndex{},
		names:     make(map[string][]*Package),
		provides:  make(map[string][]provRef),
		files:     make(map[string][]*Package),
		wantFiles: make(map[string]struct{}),
		scanned:   make(map[string]struct{}),
		owners:    make(map[string][]*Package),
	}
}

// Len returns the number of distinct package names in the index.
func (ix *Index) Len() int { return len(ix.names) }

// Versions returns every package of the given name (versions and
// architectures) the index keeps, the one a resolution prefers first. The
// result is not to be modified.
func (ix *Index) Versions(name string) []*Package { return ix.names[name] }

// Lookup returns the package of the given name that a resolution would choose,
// and whether there is one: of the best repository priority, the host
// architecture, the highest version.
func (ix *Index) Lookup(name string) (*Package, bool) {
	if list := ix.names[name]; len(list) > 0 {
		return list[0], true
	}

	return nil, false
}

// Providers returns the packages that provide the capability, written as
// "name" or "name >= 1.2" (a file path is a name), the ones a resolution
// prefers first. File paths that only filelists.xml lists are not found here.
func (ix *Index) Providers(capability string) []*Package {
	a := parseCapability(capability)
	list := ix.providersOf(a)
	slices.SortStableFunc(list, ix.compare)

	return list
}

// ResolveVirtual returns the name of the package to take for a capability: the
// name itself when it is a downloadable package, else the best provider, else
// the name unchanged.
func (ix *Index) ResolveVirtual(name string) string {
	if p, ok := ix.Lookup(name); ok && p.Location != "" {
		return name
	}

	if providers := ix.Providers(name); len(providers) > 0 {
		return providers[0].Name
	}

	return name
}

// rank returns the rank of an architecture on the host (0 is the best), and
// false for one the host cannot run.
func (ix *Index) rank(arch string) (int, bool) {
	r, ok := ix.ranks[arch]

	return r, ok
}

// compare orders candidates by preference: the lower priority number, the
// better architecture, the higher version, the lower cost, the earlier in the
// metadata come first. It is a total order on the packages of an index.
func (ix *Index) compare(a, b *Package) int {
	switch {
	case a.Priority != b.Priority:
		return a.Priority - b.Priority
	}

	ra, _ := ix.rank(a.Arch)
	rb, _ := ix.rank(b.Arch)

	if ra != rb {
		return ra - rb
	}

	if c := a.Compare(b); c != 0 {
		return -c
	}

	if a.Cost != b.Cost {
		return a.Cost - b.Cost
	}

	return a.seq - b.seq
}

// add queues p, unless the host cannot run its architecture or it belongs to a
// module stream that is not the default (and its repository does not set
// module_hotfixes); finalize puts the queue in the index.
func (ix *Index) add(p *Package) {
	if _, ok := ix.rank(p.Arch); !ok {
		return
	}

	if p.repo == nil || !p.repo.ModuleHotfixes {
		nevra := repodata.PackageNEVRA(p.Name, strconv.FormatUint(uint64(p.Epoch), 10), p.Version, p.Release, p.Arch)
		if ix.modules.Blocked(p.Release, nevra) {
			return
		}
	}

	p.seq = len(ix.pending)
	ix.pending = append(ix.pending, p)
}

// finalize builds the lookups: of the packages of one name only those of the
// repositories of the best priority stay (a repository of a better priority
// hides the packages of the others, whatever their versions), and the lists
// are put in order of preference.
func (ix *Index) finalize() {
	bestPrio := make(map[string]int)

	for _, p := range ix.pending {
		if cur, ok := bestPrio[p.Name]; !ok || p.Priority < cur {
			bestPrio[p.Name] = p.Priority
		}
	}

	for _, p := range ix.pending {
		if p.Priority == bestPrio[p.Name] {
			ix.names[p.Name] = append(ix.names[p.Name], p)
		}
	}

	ix.pending = nil

	for _, list := range ix.names {
		slices.SortStableFunc(list, ix.compare)

		for _, p := range list {
			ix.index(p)
		}
	}
}

// index adds p to the capability and file lookups.
func (ix *Index) index(p *Package) {
	for _, d := range p.Provides {
		ix.provides[d.Name] = append(ix.provides[d.Name], provRef{pkg: p, atom: richdep.AtomOf(d)})
	}

	for _, f := range p.Files {
		ix.files[f] = append(ix.files[f], p)
	}

	for _, d := range p.Requires {
		ix.noteFileRequires(d.Name)
	}
}

// noteFileRequires records the file paths a requirement names, in a rich
// dependency too.
func (ix *Index) noteFileRequires(name string) {
	switch {
	case strings.HasPrefix(name, "/"):
		ix.wantFiles[name] = struct{}{}
	case strings.HasPrefix(name, "(") && strings.Contains(name, "/"):
		if n, err := richdep.Parse(name); err == nil {
			for _, a := range richdep.Atoms(n) {
				if strings.HasPrefix(a.Name, "/") {
					ix.wantFiles[a.Name] = struct{}{}
				}
			}
		}
	}
}

// providersOf returns the packages with a provide that meets the atom, in no
// particular order.
func (ix *Index) providersOf(a richdep.Atom) []*Package {
	var out []*Package

	for _, ref := range ix.provides[a.Name] {
		if ref.atom.Overlaps(a) && !slices.Contains(out, ref.pkg) {
			out = append(out, ref.pkg)
		}
	}

	return out
}

// repoSource is a repository whose metadata is in the cache.
type repoSource struct {
	repo       *Repo
	baseURL    string
	mirrorList string
	primary    string
	modules    string
	dataDir    string
	// filelists is the cached filelists.xml, which may not be on disk yet
	// (see filelistsEntry); empty when the repository has none.
	filelists      string
	filelistsEntry repodata.RepomdData
	// bySum finds the package of the repository by the checksum filelists.xml
	// names it with.
	bySum map[string]*Package
}

// Load builds an Index from the metadata Update left in Options.CacheDir. A
// repository without usable cached metadata is skipped with a warning; an
// empty cache yields an empty index.
func (c *Client) Load(ctx context.Context) (*Index, error) {
	if c.opts.CacheDir == "" {
		return nil, ErrNoCacheDir
	}

	cfg, err := c.Config()
	if err != nil {
		return nil, err
	}

	repos, err := c.enabledRepos()
	if err != nil {
		return nil, err
	}

	var sources []*repoSource

	for i := range repos {
		src, err := c.cachedSource(&repos[i])
		if err != nil {
			c.opts.Logger.Warn("repository has no cached metadata", "repo", repos[i].ID, "error", err)

			continue
		}

		sources = append(sources, src)
	}

	ix := newIndex(c, cfg)
	ix.sources = sources

	// The module filter must be complete before the first package is added.
	for _, src := range sources {
		if src.modules == "" {
			continue
		}

		if err := c.readModules(ix.modules, src.modules); err != nil {
			c.opts.Logger.Warn("ignoring module metadata", "repo", src.repo.ID, "error", err)
		}
	}

	// Parse in parallel, merge in repository order so that the choice between
	// equal candidates does not depend on timing.
	parsed := make([][]*Package, len(sources))

	var group errgroup.Group

	group.SetLimit(min(c.opts.Concurrency, max(len(sources), 1)))

	for i := range sources {
		group.Go(func() error {
			pkgs, err := c.readPrimary(cfg, sources[i])
			if err != nil {
				c.opts.Logger.Warn("ignoring unreadable repository metadata", "repo", sources[i].repo.ID, "error", err)
			}

			parsed[i] = pkgs

			return nil
		})
	}

	_ = group.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for _, pkgs := range parsed {
		for _, p := range pkgs {
			ix.add(p)
		}
	}

	ix.finalize()

	return ix, nil
}

// cachedSource locates the cached metadata of a repository through its cached
// repomd.xml, so that only the generation Update committed is read.
func (c *Client) cachedSource(repo *Repo) (*repoSource, error) {
	cacheDir := c.repoCacheDir(repo.ID)
	dataDir := filepath.Join(cacheDir, repodataDir)

	raw, err := readCapped(filepath.Join(dataDir, repomdName), maxRepomdBytes)
	if err != nil {
		return nil, err
	}

	md, err := repodata.ParseRepomd(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}

	src := &repoSource{repo: repo, dataDir: dataDir, bySum: make(map[string]*Package)}

	entry, ok := md.Find("primary")
	if !ok {
		return nil, ErrNoPrimary
	}

	if src.primary, err = metadataPath(dataDir, entry.Location); err != nil {
		return nil, err
	}

	if _, err := os.Stat(src.primary); err != nil {
		return nil, err
	}

	if entry, ok := md.Find("modules"); ok {
		if p, err := metadataPath(dataDir, entry.Location); err == nil {
			if _, err := os.Stat(p); err == nil {
				src.modules = p
			}
		}
	}

	if entry, ok := md.Find("filelists"); ok {
		if p, err := metadataPath(dataDir, entry.Location); err == nil {
			src.filelists = p
			src.filelistsEntry = entry
		}
	}

	if repo.MirrorList != "" {
		src.mirrorList = c.expandVars(repo.MirrorList)
	}

	src.baseURL = c.persistedBase(cacheDir, repo)

	return src, nil
}

// persistedBase returns the mirror recorded by the last update, else the first
// configured baseurl, else "".
func (c *Client) persistedBase(cacheDir string, repo *Repo) string {
	if data, err := readCapped(filepath.Join(cacheDir, baseURLName), maxVarBytes); err == nil {
		if u := strings.TrimSpace(string(data)); isHTTP(u) {
			return strings.TrimSuffix(u, "/")
		}
	}

	for _, raw := range repo.BaseURLs {
		if u := c.expandVars(raw); isHTTP(u) {
			return strings.TrimSuffix(u, "/")
		}
	}

	return ""
}

func metadataPath(dataDir, location string) (string, error) {
	loc, ok := repodata.SafeLocation(location)
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnsafeLocation, location)
	}

	return filepath.Join(dataDir, path.Base(loc)), nil
}

func (c *Client) openMetadata(p string) (io.ReadCloser, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}

	rc, err := repodata.OpenMetadata(f, p, c.opts.MaxDocumentBytes)
	if err != nil {
		_ = f.Close()

		return nil, err
	}

	return rc, nil
}

func (c *Client) readModules(m *repodata.ModuleIndex, p string) error {
	rc, err := c.openMetadata(p)
	if err != nil {
		return err
	}

	defer func() { _ = rc.Close() }()

	return m.Add(rc, c.opts.MaxDocumentBytes)
}

// readPrimary parses the primary metadata of one repository. Source packages,
// those the excludepkgs and includepkgs of the repository and of dnf.conf
// leave out, and those of an architecture the host cannot run are left out.
func (c *Client) readPrimary(cfg *Config, src *repoSource) ([]*Package, error) {
	rc, err := c.openMetadata(src.primary)
	if err != nil {
		return nil, err
	}

	defer func() { _ = rc.Close() }()

	ranks := archRanks(c.opts.Arch)

	var pkgs []*Package

	err = repodata.ReadPrimary(rc, repodata.PrimaryLimits{}, func(pp *repodata.PrimaryPackage) error {
		if _, ok := ranks[pp.Arch]; !ok {
			return nil
		}

		epoch := strconv.FormatUint(uint64(pp.Epoch), 10)
		if !cfg.allowed(src.repo, pp.Name, epoch, pp.Version, pp.Release, pp.Arch) {
			return nil
		}

		p := newPackage(pp, src)
		pkgs = append(pkgs, p)

		if pp.Checksum != "" {
			src.bySum[pp.Checksum] = p
		}

		return nil
	})

	return pkgs, err
}

// newPackage condenses a primary.xml entry.
func newPackage(pp *repodata.PrimaryPackage, src *repoSource) *Package {
	p := &Package{
		Name:         pp.Name,
		Arch:         pp.Arch,
		Version:      pp.Version,
		Release:      pp.Release,
		Epoch:        pp.Epoch,
		Location:     pp.Location,
		Checksum:     pp.Checksum,
		ChecksumType: pp.ChecksumType,
		Size:         pp.PackageSize,
		Repo:         src.repo.ID,
		Priority:     src.repo.Priority,
		Cost:         src.repo.Cost,
		repo:         src.repo,
		src:          src,
		BaseURL:      src.baseURL,
		MirrorList:   src.mirrorList,
		Provides:     pp.Provides,
		Requires:     withoutRPMLib(pp.Requires),
		Conflicts:    pp.Conflicts,
		Obsoletes:    pp.Obsoletes,
		Recommends:   pp.Recommends,
		Suggests:     pp.Suggests,
		Supplements:  pp.Supplements,
		Enhances:     pp.Enhances,
	}

	for _, f := range pp.Files {
		p.Files = append(p.Files, f.Path)
	}

	p.addSelfProvide()

	return p
}

// withoutRPMLib drops the rpmlib() feature requirements, which only the rpm of
// the host can satisfy.
func withoutRPMLib(deps []rpm.Dependency) []rpm.Dependency {
	if !slices.ContainsFunc(deps, isRPMLib) {
		return deps
	}

	return slices.DeleteFunc(slices.Clone(deps), isRPMLib)
}

func isRPMLib(d rpm.Dependency) bool {
	return d.Flags&tag.RPMSENSE_RPMLIB != 0 || strings.HasPrefix(d.Name, "rpmlib(")
}

// fromInstalled converts a package of the host's database.
func fromInstalled(p *rpm.Package) *Package {
	ip := &Package{
		Name:        p.Name,
		Arch:        p.Arch,
		Version:     p.Version,
		Release:     p.Release,
		Epoch:       p.Epoch,
		Repo:        SystemRepo,
		Provides:    p.Provides,
		Requires:    withoutRPMLib(p.Requires),
		Conflicts:   p.Conflicts,
		Obsoletes:   p.Obsoletes,
		Recommends:  p.Recommends,
		Suggests:    p.Suggests,
		Supplements: p.Supplements,
		Enhances:    p.Enhances,
	}

	for _, f := range p.Files {
		ip.Files = append(ip.Files, f.Path)
	}

	ip.addSelfProvide()

	return ip
}

// parseCapability reads "name", "name >= 1.2" or "name = 1:1.2-3" as written
// in a command line.
func parseCapability(s string) richdep.Atom {
	if n, err := richdep.Parse(s); err == nil {
		if a, ok := n.(richdep.Atom); ok {
			return a
		}
	}

	return richdep.Atom{Name: strings.TrimSpace(s)}
}
