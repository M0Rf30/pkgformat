package apt

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/M0Rf30/pkgformat/deb"
)

// LoadOptions says where a Cache is read from. Every field is optional.
type LoadOptions struct {
	// ListsDir is the directory holding the downloaded Packages indexes, named
	// the way apt names them ("<host>_<path>_dists_<suite>_<comp>_binary-<arch>_Packages[.ext]").
	// Empty loads no index.
	ListsDir string
	// StatusFile is the dpkg status database to overlay, to set Installed. Empty
	// skips it.
	StatusFile string
	// Sources resolve the BaseURL of every index: an index file named after a
	// source's host and path takes that source's URL.
	Sources []Source
	// HostArch is the architecture unqualified names resolve to. Empty selects
	// the one of the running program.
	HostArch string
	// Logger receives one debug record per file loaded. Nil is silent.
	Logger *slog.Logger
}

// Load reads the apt indexes of opts.ListsDir, then the dpkg status database
// of opts.StatusFile.
//
// Like apt itself, Load tolerates what it cannot read: a missing directory,
// an unreadable or corrupt index. The returned Cache is never nil and holds
// everything that did load; the error, when not nil, joins one error per file
// that did not, so a caller can warn about them.
func Load(opts LoadOptions) (*Cache, error) {
	c := NewCache(opts.HostArch)

	var errs []error

	if opts.ListsDir != "" {
		if err := c.loadLists(opts); err != nil {
			errs = append(errs, err)
		}
	}

	if opts.StatusFile != "" {
		if err := c.parseFile(opts.StatusFile, true, ""); err != nil {
			errs = append(errs, err)
		}
	}

	return c, errors.Join(errs...)
}

// packagesIndexSuffixes are the file name endings of the Packages index
// variants apt writes.
var packagesIndexSuffixes = []string{
	"_Packages", "_Packages.gz", "_Packages.bz2", "_Packages.xz", "_Packages.lz4", "_Packages.zst",
}

func isPackagesIndexName(name string) bool {
	return slices.ContainsFunc(packagesIndexSuffixes, func(s string) bool {
		return strings.HasSuffix(name, s)
	})
}

// loadLists parses every Packages index of the lists directory. Each file is
// parsed concurrently into a private Cache, because decompression and line
// scanning dominate and a stanza-level lock would serialise them; the partial
// caches are then merged in file order. The pool is capped at min(GOMAXPROCS,
// 8), as the work is CPU bound.
func (c *Cache) loadLists(opts LoadOptions) error {
	dirEntries, err := os.ReadDir(opts.ListsDir)
	if err != nil {
		return fmt.Errorf("apt: read lists directory: %w", err)
	}

	bases := BaseURLs(opts.Sources)

	type job struct {
		path    string
		baseURL string
	}

	jobs := make([]job, 0, len(dirEntries))

	for _, entry := range dirEntries {
		name := entry.Name()
		if entry.IsDir() || !isPackagesIndexName(name) {
			continue
		}

		jobs = append(jobs, job{path: filepath.Join(opts.ListsDir, name), baseURL: deriveBaseURL(name, bases)})
	}

	if len(jobs) == 0 {
		return nil
	}

	partials := make([]*Cache, len(jobs))
	fileErrs := make([]error, len(jobs))
	jobCh := make(chan int, len(jobs))

	for i := range jobs {
		jobCh <- i
	}

	close(jobCh)

	var wg sync.WaitGroup

	for range min(runtime.GOMAXPROCS(0), 8, len(jobs)) {
		wg.Go(func() {
			for idx := range jobCh {
				local := NewCache(c.hostArch)
				fileErrs[idx] = local.parseFile(jobs[idx].path, false, jobs[idx].baseURL)
				partials[idx] = local

				if opts.Logger != nil {
					opts.Logger.Debug("apt: index loaded", "path", jobs[idx].path, "packages", len(local.entries))
				}
			}
		})
	}

	wg.Wait()

	for _, p := range partials {
		c.mergeFrom(p)
	}

	return errors.Join(fileErrs...)
}

// deriveBaseURL returns the URL of the source an index file name belongs to, or
// "". The name is <encoded-hostpath>_dists_<suite>_<component>_binary-<arch>_Packages[.ext].
func deriveBaseURL(filename string, bases map[string]string) string {
	prefix, _, found := strings.Cut(filename, "_dists_")
	if !found {
		return ""
	}

	return bases[prefix]
}

// mergeFrom folds a Cache built by one worker into c. Iteration is sorted so
// that byBareName, and with it the any-architecture fallback, is deterministic.
func (c *Cache) mergeFrom(other *Cache) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, name := range slices.Sorted(maps.Keys(other.entries)) {
		info := other.entries[name]

		existing, ok := c.entries[name]
		if !ok {
			c.entries[name] = info
			c.addToBareName(info.Name, name)

			continue
		}

		mergeEntryFields(existing, info)
	}

	for virt, providers := range other.providers {
		c.providers[virt] = append(c.providers[virt], providers...)
	}
}

// mergeEntryFields merges info into existing. Artifact fields follow the
// higher Debian version; see infoArtifactsWin.
func mergeEntryFields(existing, info *PackageInfo) {
	if info.Architecture != "" {
		existing.Architecture = info.Architecture
	}

	if info.MultiArch != "" {
		existing.MultiArch = info.MultiArch
	}

	if info.Essential {
		existing.Essential = true
	}

	if info.HasCandidate {
		existing.HasCandidate = true
	}

	if info.Installed {
		existing.Installed = true
	}

	if infoArtifactsWin(existing, info) {
		copyInfoArtifacts(existing, info)
	}
}

// infoArtifactsWin decides whether info overwrites the artifact fields of
// existing: the higher Debian version wins; a tie, or a missing version on both
// sides, favours info if it carries any artifact data.
func infoArtifactsWin(existing, info *PackageInfo) bool {
	switch {
	case existing.Version == "" && info.Version == "":
		return info.Filename != "" || info.SHA256 != "" || info.Size > 0 ||
			len(info.Depends) > 0 || len(info.PreDepends) > 0
	case existing.Version == "":
		return true
	case info.Version == "":
		return false
	default:
		return deb.CompareVersions(info.Version, existing.Version) >= 0
	}
}

// copyInfoArtifacts overwrites the artifact fields of existing with the
// non-empty ones of info. BaseURL follows Filename only for architectures other
// than all, so an _all.deb is never pointed at a foreign-architecture mirror
// (ports.ubuntu.com).
func copyInfoArtifacts(existing, info *PackageInfo) {
	if info.Version != "" {
		existing.Version = info.Version
	}

	if info.Filename != "" {
		existing.Filename = info.Filename

		if info.BaseURL != "" && info.Architecture != "" && info.Architecture != archAll {
			existing.BaseURL = info.BaseURL
		}
	}

	if info.SHA256 != "" {
		existing.SHA256 = info.SHA256
	}

	if info.Size > 0 {
		existing.Size = info.Size
	}

	if len(info.Depends) > 0 {
		existing.Depends = info.Depends
	}

	if len(info.PreDepends) > 0 {
		existing.PreDepends = info.PreDepends
	}
}

// parseFile reads a deb822 file, compressed or not by its extension, into the
// cache. dpkgStatus selects the status database flavour, where the Status field
// sets Installed and the index-only fields are ignored. baseURL is the
// repository URL of an apt index.
func (c *Cache) parseFile(path string, dpkgStatus bool, baseURL string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("apt: open index: %w", err)
	}

	defer func() { _ = f.Close() }()

	var r io.Reader = f

	if !dpkgStatus {
		rc, err := deb.OpenIndex(f, path)
		if err != nil {
			return fmt.Errorf("apt: open %s: %w", filepath.Base(path), err)
		}

		defer func() { _ = rc.Close() }()

		r = rc
	}

	err = deb.ScanControl(r, func(cf *deb.ControlFile) error {
		c.flushStanza(stanzaOf(cf, dpkgStatus, baseURL), dpkgStatus)

		return nil
	})
	if err != nil {
		return fmt.Errorf("apt: parse %s: %w", filepath.Base(path), err)
	}

	return nil
}

// stanza holds the fields of one paragraph that the cache keeps.
type stanza struct {
	pkgName    string
	arch       string
	multiArch  string
	provides   string
	depends    string
	preDepends string
	essential  bool
	installed  bool
	hasVersion bool
	version    string
	filename   string
	sha256     string
	size       int64
	baseURL    string
}

func stanzaOf(cf *deb.ControlFile, dpkgStatus bool, baseURL string) *stanza {
	s := &stanza{
		baseURL:    baseURL,
		pkgName:    cf.Get("Package"),
		version:    cf.Get("Version"),
		arch:       cf.Get("Architecture"),
		essential:  strings.EqualFold(cf.Get("Essential"), "yes"),
		multiArch:  cf.Get("Multi-Arch"),
		provides:   cf.Get("Provides"),
		depends:    cf.Get("Depends"),
		preDepends: cf.Get("Pre-Depends"),
		filename:   cf.Get("Filename"),
	}

	s.hasVersion = s.version != ""

	if dpkgStatus {
		s.installed = cf.Get("Status") == "install ok installed"

		return s
	}

	s.sha256 = cf.Get("SHA256")
	s.size, _ = strconv.ParseInt(cf.Get("Size"), 10, 64)

	return s
}

// flushStanza merges a paragraph into the cache under its name:arch key, so
// that arm64 entries never overwrite amd64 ones when both indexes are loaded.
func (c *Cache) flushStanza(s *stanza, dpkgStatus bool) {
	if s.pkgName == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := entryKey(s.pkgName, s.arch)

	existing, ok := c.entries[key]
	if !ok {
		existing = &PackageInfo{}
		c.entries[key] = existing
	}

	mergePackageInfo(existing, s, dpkgStatus)
	c.flushProvides(s.pkgName, s.provides)
	c.addToBareName(s.pkgName, key)
}

// mergePackageInfo merges a paragraph into an entry. An apt index paragraph
// replaces the artifact fields of an entry that already has a candidate only
// when its version is strictly greater: the newest version wins across
// repositories that index the same name and architecture, as apt does without
// pinning.
func mergePackageInfo(existing *PackageInfo, s *stanza, dpkgStatus bool) {
	existing.Name = s.pkgName

	if s.arch != "" {
		existing.Architecture = s.arch
	}

	if s.essential {
		existing.Essential = true
	}

	if s.multiArch != "" {
		existing.MultiArch = s.multiArch
	}

	if dpkgStatus && s.installed {
		existing.Installed = true
	}

	if !s.hasVersion {
		return // a pure virtual carries no artifact
	}

	existing.HasCandidate = true

	if existing.Version != "" && !versionWins(s.version, existing.Version) {
		return
	}

	copyStanzaArtifacts(existing, s)
}

// copyStanzaArtifacts overwrites the artifact fields of existing with a
// paragraph's.
func copyStanzaArtifacts(existing *PackageInfo, s *stanza) {
	existing.Version = s.version

	if s.filename != "" {
		existing.Filename = s.filename
	}

	if s.sha256 != "" {
		existing.SHA256 = s.sha256
	}

	if s.size > 0 {
		existing.Size = s.size
	}

	if s.baseURL != "" {
		existing.BaseURL = s.baseURL
	}

	if s.depends != "" {
		existing.Depends = deb.DependencyNames(s.depends)
	}

	if s.preDepends != "" {
		existing.PreDepends = deb.DependencyNames(s.preDepends)
	}
}

// flushProvides records the Provides of a package in the reverse index.
func (c *Cache) flushProvides(pkgName, provides string) {
	for prov := range strings.SplitSeq(provides, ",") {
		// "foo (= 1.0)" provides foo.
		vname, _, _ := strings.Cut(strings.TrimSpace(prov), " (")
		vname, _, _ = strings.Cut(vname, ":")

		if vname = strings.TrimSpace(vname); vname != "" {
			c.providers[vname] = append(c.providers[vname], pkgName)
		}
	}
}
