package apt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
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
	// Logger receives one debug record per file loaded and one per stanza that
	// is skipped. Nil is silent.
	Logger *slog.Logger
}

// Load reads the apt indexes of opts.ListsDir, then the dpkg status database
// of opts.StatusFile.
//
// Every version of a package that an index carries is kept. A stanza without
// Version, or whose relation fields do not parse, is skipped.
//
// Like apt itself, Load tolerates what it cannot read: a missing directory,
// an unreadable or corrupt index. The returned Cache is never nil and holds
// everything that did load; the error, when not nil, joins one error per file
// that did not, so a caller can warn about them.
func Load(opts LoadOptions) (*Cache, error) {
	c := NewCache(opts.HostArch)
	c.logger = opts.Logger

	var errs []error

	if opts.ListsDir != "" {
		if err := c.loadLists(opts); err != nil {
			errs = append(errs, err)
		}
	}

	if opts.StatusFile != "" {
		if err := c.parseStatus(opts.StatusFile, opts.Logger); err != nil {
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
		release *ReleaseInfo
	}

	releases := make(map[string]*deb.Release)

	jobs := make([]job, 0, len(dirEntries))

	for _, entry := range dirEntries {
		name := entry.Name()
		if entry.IsDir() || !isPackagesIndexName(name) {
			continue
		}

		jobs = append(jobs, job{
			path:    filepath.Join(opts.ListsDir, name),
			baseURL: deriveBaseURL(name, bases),
			release: releaseInfoFor(opts.ListsDir, name, bases, releases),
		})
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
				local.logger = opts.Logger
				fileErrs[idx] = local.parseFile(jobs[idx].path, jobs[idx].baseURL, jobs[idx].release)
				partials[idx] = local

				if opts.Logger != nil {
					opts.Logger.Debug("apt: index loaded", "path", jobs[idx].path, "packages", len(local.slots))
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

// releaseInfoFor reads the Release file the lists directory keeps for the
// index named filename and describes it for pin matching, or returns nil when
// there is none. Files are parsed once per (source, suite); releases caches
// them.
func releaseInfoFor(listsDir, filename string, bases map[string]string, releases map[string]*deb.Release) *ReleaseInfo {
	prefix, rest, found := strings.Cut(filename, "_dists_")
	if !found {
		return nil
	}

	suite, rest, found := strings.Cut(rest, "_")
	if !found {
		return nil
	}

	comp, rest, found := strings.Cut(rest, "_binary-")
	if !found {
		return nil
	}

	arch, _, _ := strings.Cut(rest, "_")
	key := prefix + "_dists_" + suite + "_"

	rel, seen := releases[key]
	if !seen {
		for _, name := range []string{"InRelease", "Release"} {
			data, err := readLocal(filepath.Join(listsDir, key+name), deb.MaxReleaseBytes)
			if err != nil {
				continue
			}

			if parsed, err := deb.ParseRelease(data); err == nil {
				rel = parsed

				break
			}
		}

		releases[key] = rel
	}

	if rel == nil {
		return nil
	}

	info := &ReleaseInfo{
		Origin: rel.Origin, Label: rel.Label, Suite: rel.Suite, Codename: rel.Codename, Version: rel.Version,
		Component:    strings.ReplaceAll(comp, "_", "/"),
		Architecture: arch,
		NotAutomatic: rel.NotAutomatic, ButAutomaticUpgrades: rel.ButAutomaticUpgrades,
	}

	if base := bases[prefix]; base != "" {
		if u, err := url.Parse(strings.TrimPrefix(base, "mirror+")); err == nil {
			info.Site = u.Hostname()
		}
	}

	return info
}

// mergeFrom folds a Cache built by one worker into c, keeping the order its
// versions were read in, which decides between providers.
func (c *Cache) mergeFrom(other *Cache) {
	c.mu.Lock()
	defer c.mu.Unlock()

	all := make([]*pkg, 0, len(other.slots))

	for _, versions := range other.slots {
		all = append(all, versions...)
	}

	slices.SortFunc(all, func(a, b *pkg) int { return a.seq - b.seq })

	for _, p := range all {
		c.insert(&p.PackageInfo, true)
	}
}

// parseFile reads an apt Packages index, compressed or not by its extension,
// into the cache. baseURL is the repository URL of the index and release what
// is known of its Release file, or nil.
func (c *Cache) parseFile(path, baseURL string, release *ReleaseInfo) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("apt: open index: %w", err)
	}

	defer func() { _ = f.Close() }()

	rc, err := deb.OpenIndex(f, path)
	if err != nil {
		return fmt.Errorf("apt: open %s: %w", filepath.Base(path), err)
	}

	defer func() { _ = rc.Close() }()

	err = deb.ScanControl(rc, func(cf *deb.ControlFile) error {
		info, err := packageInfoOf(cf, baseURL)
		if err != nil {
			c.skipStanza(path, cf, err)

			return nil
		}

		if info.Version == "" {
			c.skipStanza(path, cf, errors.New("no Version"))

			return nil
		}

		info.HasCandidate = true

		if release != nil {
			info.Releases = []*ReleaseInfo{release}
		}

		c.mu.Lock()
		c.insert(info, true)
		c.mu.Unlock()

		return nil
	})
	if err != nil {
		return fmt.Errorf("apt: parse %s: %w", filepath.Base(path), err)
	}

	return nil
}

// skipStanza logs a stanza the cache does not keep.
func (c *Cache) skipStanza(path string, cf *deb.ControlFile, err error) {
	if c.logger != nil {
		c.logger.Debug("apt: stanza skipped", "path", path, "package", cf.Get("Package"), "reason", err)
	}
}

// parseStatus overlays the dpkg status database at path: every stanza of an
// installed package adds that version and sets Installed, and a version an
// index carries too keeps the artifacts of the index. The other states are not
// installed and add nothing. A nil logger is silent.
func (c *Cache) parseStatus(path string, logger *slog.Logger) error {
	db, err := deb.OpenStatus(path, deb.StatusOptions{Logger: logger})
	if err != nil {
		return fmt.Errorf("apt: open status: %w", err)
	}

	defer func() { _ = db.Close() }()

	for entry, err := range db.Entries(context.Background()) {
		if err != nil {
			return fmt.Errorf("apt: parse %s: %w", filepath.Base(path), err)
		}

		if !entry.Status.Installed() {
			continue
		}

		info, err := packageInfoOf(entry.Control, "")
		if err != nil {
			c.skipStanza(path, entry.Control, err)

			continue
		}

		if info.Version == "" {
			c.skipStanza(path, entry.Control, errors.New("no Version"))

			continue
		}

		// The index-only fields of a status stanza are not meaningful.
		info.Filename, info.SHA256, info.Size = "", "", 0
		info.Installed = true

		c.mu.Lock()
		c.insert(info, true)
		c.mu.Unlock()
	}

	return nil
}

// packageInfoOf reads the fields of a paragraph of an index or of the status
// database that the cache keeps. HasCandidate and Installed are the caller's
// to set. A paragraph without a name or with a relation field that does not
// parse is an error.
func packageInfoOf(cf *deb.ControlFile, baseURL string) (*PackageInfo, error) {
	name := cf.Get("Package")
	if name == "" {
		return nil, errors.New("no Package")
	}

	info := &PackageInfo{
		Name:         name,
		Version:      cf.Get("Version"),
		Architecture: cf.Get("Architecture"),
		Essential:    strings.EqualFold(cf.Get("Essential"), "yes"),
		MultiArch:    cf.Get("Multi-Arch"),
		Priority:     cf.Get("Priority"),
		Filename:     cf.Get("Filename"),
		SHA256:       cf.Get("SHA256"),
		BaseURL:      baseURL,
	}

	info.Size, _ = strconv.ParseInt(cf.Get("Size"), 10, 64)

	info.SourceName, info.SourceVersion = sourceFieldOf(cf, name, info.Version)

	if v := strings.TrimSpace(cf.Get("Phased-Update-Percentage")); v != "" {
		if pct, err := strconv.Atoi(v); err == nil && pct >= 0 && pct <= 100 {
			info.PhasedUpdatePercentage = &pct
		}
	}

	if info.Filename == "" {
		info.BaseURL = ""
	}

	var err error

	if info.Depends, err = parseGroups(cf, "Depends"); err != nil {
		return nil, err
	}

	if info.PreDepends, err = parseGroups(cf, "Pre-Depends"); err != nil {
		return nil, err
	}

	if info.Conflicts, err = parseFlat(cf, "Conflicts"); err != nil {
		return nil, err
	}

	if info.Breaks, err = parseFlat(cf, "Breaks"); err != nil {
		return nil, err
	}

	if info.Provides, err = parseFlat(cf, "Provides"); err != nil {
		return nil, err
	}

	return info, nil
}

// parseGroups reads a dependency field of a paragraph.
func parseGroups(cf *deb.ControlFile, field string) ([]deb.Alternatives, error) {
	text := cf.Get(field)
	if text == "" {
		return nil, nil
	}

	groups, err := deb.ParseRelations(text)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}

	return groups, nil
}

// parseFlat reads a field whose entries are plain relations (Conflicts,
// Breaks, Provides); an alternative in one is an error.
func parseFlat(cf *deb.ControlFile, field string) ([]deb.Relation, error) {
	groups, err := parseGroups(cf, field)
	if err != nil {
		return nil, err
	}

	out := make([]deb.Relation, 0, len(groups))

	for _, alts := range groups {
		// dpkg rejects "a | b" here; keep every term as its own relation
		// rather than lose a package a hand-edited field names.
		out = append(out, alts...)
	}

	if len(out) == 0 {
		return nil, nil
	}

	return out, nil
}

// sourceFieldOf reads the Source field of a paragraph: the source package the
// version was built from and its version, which are the package's own name
// and version when the field is absent or carries no version.
func sourceFieldOf(cf *deb.ControlFile, name, version string) (srcName, srcVersion string) {
	src := strings.TrimSpace(cf.Get("Source"))
	if src == "" {
		return name, version
	}

	srcName, rest, hasVersion := strings.Cut(src, "(")
	srcName = strings.TrimSpace(srcName)

	if !hasVersion {
		return srcName, version
	}

	v, _, _ := strings.Cut(rest, ")")
	if v = strings.TrimSpace(v); v != "" {
		return srcName, v
	}

	return srcName, version
}
