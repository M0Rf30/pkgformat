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
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

const archNoarch = "noarch"

// Package is what the index keeps of a package of primary.xml: enough to
// resolve its dependencies and to download it.
type Package struct {
	Name    string
	Arch    string
	Version string
	Release string
	Epoch   uint32
	// Location is the path of the .rpm relative to the repository.
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
	// Requires, Provides and Recommends are capability names with the
	// version constraints dropped; Requires leaves out rpmlib() features.
	// Provides also lists the file paths the package owns.
	Requires   []string
	Provides   []string
	Recommends []string
	// Repo is the id of the repository the package comes from.
	Repo string
	// Priority is the priority of that repository (see [Repo.Priority]): of
	// two packages with the same name the lower number wins, whatever the
	// versions.
	Priority int

	// repo carries the settings a download needs (proxy, gpgcheck, gpgkey).
	// It is nil for a Package not built by [Client.Load].
	repo *Repo
}

// EVR renders "epoch:version-release". It is for display: the string is not
// comparable with [rpm.Vercmp], which would run the version into the release
// ("1.0-5" would sort after "1.0.1-1"); use [Package.Compare].
func (p *Package) EVR() string {
	return strconv.FormatUint(uint64(p.Epoch), 10) + ":" + p.Version + "-" + p.Release
}

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

// Index is an in-memory view of the primary metadata of the repositories,
// keyed by package name and by provided capability. It is read-only once
// [Client.Load] returns it, so it is safe for concurrent use.
type Index struct {
	arch      string
	installed Installed
	logger    *slog.Logger
	packages  map[string]*Package
	providers map[string][]*Package
	modules   *repodata.ModuleIndex
}

func newIndex(arch string, installed Installed, logger *slog.Logger) *Index {
	return &Index{
		arch:      arch,
		installed: installed,
		logger:    logger,
		packages:  make(map[string]*Package),
		providers: make(map[string][]*Package),
		modules:   &repodata.ModuleIndex{},
	}
}

// Len returns the number of distinct package names in the index.
func (ix *Index) Len() int { return len(ix.packages) }

// Lookup returns the package of the given name that a resolution would choose,
// and whether there is one.
func (ix *Index) Lookup(name string) (*Package, bool) {
	p, ok := ix.packages[name]

	return p, ok
}

// ResolveVirtual returns the name of the package to take for a capability: the
// name itself when it is a downloadable package, else the best provider, else
// the name unchanged.
func (ix *Index) ResolveVirtual(name string) string {
	if p, ok := ix.packages[name]; ok && p.Location != "" {
		return name
	}

	if providers := ix.providers[name]; len(providers) > 0 {
		return ix.pickProvider(providers).Name
	}

	return name
}

// pickProvider chooses the best concrete provider of a capability: among the
// providers of the best repository priority, the host architecture, then
// noarch, then whatever comes first. This keeps a foreign architecture (i686
// on x86_64) from being pulled in by a capability lookup.
func (ix *Index) pickProvider(providers []*Package) *Package {
	best := providers[0].Priority
	for _, p := range providers[1:] {
		best = min(best, p.Priority)
	}

	var noarch, first *Package

	for _, p := range providers {
		if p.Priority != best {
			continue
		}

		if first == nil {
			first = p
		}

		if p.Arch == ix.arch {
			return p
		}

		if p.Arch == archNoarch && noarch == nil {
			noarch = p
		}
	}

	if noarch != nil {
		return noarch
	}

	return first
}

// shouldReplace reports whether candidate should take the place of existing as
// the package of its name: downloadable beats not, a repository with a lower
// priority number beats any other, the host architecture beats another, noarch
// beats a foreign architecture, and on the same architecture the higher version
// wins.
func (ix *Index) shouldReplace(existing, candidate *Package) bool {
	if existing.Location == "" && candidate.Location != "" {
		return true
	}

	if existing.Priority != candidate.Priority {
		return candidate.Priority < existing.Priority
	}

	if existing.Arch != candidate.Arch {
		if candidate.Arch == ix.arch {
			return true
		}

		return candidate.Arch == archNoarch && existing.Arch != ix.arch
	}

	return candidate.Compare(existing) > 0
}

// add inserts p, unless it belongs to a non-default module stream, and indexes
// the capabilities it provides.
func (ix *Index) add(p *Package) {
	nevra := repodata.PackageNEVRA(p.Name, strconv.FormatUint(uint64(p.Epoch), 10), p.Version, p.Release, p.Arch)
	if ix.modules.Blocked(p.Release, nevra) {
		return
	}

	if existing, ok := ix.packages[p.Name]; !ok || ix.shouldReplace(existing, p) {
		ix.packages[p.Name] = p
	}

	for _, prov := range p.Provides {
		if name := StripRPMConstraint(prov); name != "" && name != p.Name {
			ix.providers[name] = append(ix.providers[name], p)
		}
	}
}

// repoSource is a repository whose metadata is in the cache.
type repoSource struct {
	repo       *Repo
	baseURL    string
	mirrorList string
	primary    string
	modules    string
}

// Load builds an Index from the metadata Update left in Options.CacheDir. A
// repository without usable cached metadata is skipped with a warning; an
// empty cache yields an empty index.
func (c *Client) Load(ctx context.Context) (*Index, error) {
	if c.opts.CacheDir == "" {
		return nil, ErrNoCacheDir
	}

	repos, err := c.enabledRepos()
	if err != nil {
		return nil, err
	}

	var sources []repoSource

	for i := range repos {
		src, err := c.cachedSource(&repos[i])
		if err != nil {
			c.opts.Logger.Warn("repository has no cached metadata", "repo", repos[i].ID, "error", err)

			continue
		}

		sources = append(sources, src)
	}

	ix := newIndex(c.opts.Arch, c.opts.Installed, c.opts.Logger)

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
			pkgs, err := c.readPrimary(&sources[i])
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

	return ix, nil
}

// cachedSource locates the cached metadata of a repository through its cached
// repomd.xml, so that only the generation Update committed is read.
func (c *Client) cachedSource(repo *Repo) (repoSource, error) {
	cacheDir := c.repoCacheDir(repo.ID)
	dataDir := filepath.Join(cacheDir, repodataDir)

	raw, err := readCapped(filepath.Join(dataDir, repomdName), maxRepomdBytes)
	if err != nil {
		return repoSource{}, err
	}

	md, err := repodata.ParseRepomd(bytes.NewReader(raw))
	if err != nil {
		return repoSource{}, err
	}

	src := repoSource{repo: repo}

	entry, ok := md.Find("primary")
	if !ok {
		return repoSource{}, ErrNoPrimary
	}

	if src.primary, err = metadataPath(dataDir, entry.Location); err != nil {
		return repoSource{}, err
	}

	if _, err := os.Stat(src.primary); err != nil {
		return repoSource{}, err
	}

	if entry, ok := md.Find("modules"); ok {
		if p, err := metadataPath(dataDir, entry.Location); err == nil {
			if _, err := os.Stat(p); err == nil {
				src.modules = p
			}
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

// readPrimary parses the primary metadata of one repository. Source packages
// are left out.
func (c *Client) readPrimary(src *repoSource) ([]*Package, error) {
	rc, err := c.openMetadata(src.primary)
	if err != nil {
		return nil, err
	}

	defer func() { _ = rc.Close() }()

	var pkgs []*Package

	err = repodata.ReadPrimary(rc, repodata.PrimaryLimits{}, func(pp *repodata.PrimaryPackage) error {
		if pp.Arch == "src" {
			return nil
		}

		if src.repo.excludes(pp) {
			return nil
		}

		pkgs = append(pkgs, newPackage(pp, src))

		return nil
	})
	if err != nil {
		return pkgs, err
	}

	return pkgs, nil
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
		repo:         src.repo,
		BaseURL:      src.baseURL,
		MirrorList:   src.mirrorList,
		Requires:     depNames(pp.Requires, true),
		Recommends:   depNames(pp.Recommends, true),
		Provides:     depNames(pp.Provides, false),
	}

	for _, f := range pp.Files {
		p.Provides = append(p.Provides, f.Path)
	}

	return p
}

// depNames lists the capability names of deps without constraints. With
// skipRPMLib the rpmlib() feature requirements, which no package provides, are
// left out.
func depNames(deps []rpm.Dependency, skipRPMLib bool) []string {
	var out []string

	for _, d := range deps {
		name := StripRPMConstraint(d.Name)
		if name == "" || (skipRPMLib && strings.HasPrefix(name, "rpmlib(")) {
			continue
		}

		out = append(out, name)
	}

	return out
}
