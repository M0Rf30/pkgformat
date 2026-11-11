package apk

import (
	"errors"
	"strings"
)

// ErrPackageNotFound is wrapped by the errors of a lookup that finds neither a
// package nor a provider of the name.
var ErrPackageNotFound = errors.New("apk: package not found")

// RepoPackage is an index entry together with where it was found.
type RepoPackage struct {
	Package
	// Repo is the repository whose index lists the package.
	Repo Repo
	// IndexArch is the architecture directory of that index. The package file
	// is in it whatever the package's own Arch is: noarch packages sit next to
	// the architecture-specific ones.
	IndexArch string

	// repoOrder is the position of the repository among those added.
	repoOrder int
	// seq is the position of the package among those added.
	seq int
	// deps and provides are the parsed Depends, Provides and InstallIf;
	// entries that are not valid dependencies are left out, as apk ignores
	// them.
	deps, installIf []Dependency
	provides        []provided
}

// provided is one capability a package provides: its name and the version it
// declares for it, empty for an unversioned virtual.
type provided struct {
	name, version string
}

// URL returns the download URL of the package file:
// <repository>/<index arch>/<name>-<version>.apk.
func (p *RepoPackage) URL() string {
	return p.Repo.URL + "/" + p.IndexArch + "/" + p.FileName()
}

// Index is the set of packages of one or more repositories, for lookups and
// dependency resolution. It is filled with [Index.Add] and then only read; it
// is not safe for concurrent Add.
type Index struct {
	pkgs      []*RepoPackage
	byName    map[string][]*RepoPackage // name -> packages of that name, in order added
	providers map[string][]*RepoPackage // capability -> packages providing it, in order added
	repos     int                       // repositories added
	tags      map[string]int            // repository tag -> bit number, 1.. (0 is untagged)
	seen      map[string]struct{}       // name + version + checksum of every package added
}

// maxTags is the number of distinct repository tags an Index tracks; the
// packages of a tag beyond it are not installable.
const maxTags = 62

// NewIndex returns an empty Index.
func NewIndex() *Index {
	return &Index{
		byName:    make(map[string][]*RepoPackage),
		providers: make(map[string][]*RepoPackage),
		tags:      make(map[string]int),
		seen:      make(map[string]struct{}),
	}
}

// Add lists the packages of repo's index for indexArch. Every version of a
// package is kept; one that an earlier repository lists with the same name,
// version and checksum is ignored, so the repository added first wins like the
// order of a repositories file. A package registers the capabilities of its
// Provides with their versions. A repository with a Tag is only used by a
// request that names the tag ("pkg@tag").
func (idx *Index) Add(repo Repo, indexArch string, pkgs []Package) {
	order := idx.repos
	idx.repos++

	if repo.Tag != "" {
		if _, ok := idx.tags[repo.Tag]; !ok {
			idx.tags[repo.Tag] = len(idx.tags) + 1
		}
	}

	for i := range pkgs {
		key := pkgs[i].Name + "\x00" + pkgs[i].Version + "\x00" + pkgs[i].Checksum
		if _, dup := idx.seen[key]; dup {
			continue
		}

		idx.seen[key] = struct{}{}

		rp := &RepoPackage{Package: pkgs[i], Repo: repo, IndexArch: indexArch, repoOrder: order, seq: len(idx.pkgs)}
		rp.parseRelations()

		idx.pkgs = append(idx.pkgs, rp)
		idx.byName[rp.Name] = append(idx.byName[rp.Name], rp)

		for _, pr := range rp.provides {
			if pr.name != rp.Name {
				idx.providers[pr.name] = append(idx.providers[pr.name], rp)
			}
		}
	}
}

// parseRelations parses the dependency lists of p.
func (p *RepoPackage) parseRelations() {
	for _, s := range p.Depends {
		if d, err := ParseDependency(s); err == nil {
			p.deps = append(p.deps, d)
		}
	}

	for _, s := range p.InstallIf {
		if d, err := ParseDependency(s); err == nil {
			p.installIf = append(p.installIf, d)
		}
	}

	for _, s := range p.Provides {
		d, err := ParseDependency(s)
		if err != nil || d.Conflict {
			continue
		}

		p.provides = append(p.provides, provided{name: d.Name, version: providedVersion(d)})
	}
}

// better reports whether a is preferred to b as the package called by a
// name: a package of an untagged repository, then the higher version, then
// the earlier repository.
func better(a, b *RepoPackage) bool {
	if (a.Repo.Tag == "") != (b.Repo.Tag == "") {
		return a.Repo.Tag == ""
	}

	if c := CompareVersions(a.Version, b.Version); c != 0 {
		return c > 0
	}

	return a.repoOrder < b.repoOrder
}

// Lookup returns the package of that name: the highest version of an
// untagged repository, the earlier repository among equals; a package that
// only a tagged repository lists is returned when no untagged one has the
// name. The name has no version constraint.
func (idx *Index) Lookup(name string) (*RepoPackage, bool) {
	var best *RepoPackage

	for _, p := range idx.byName[name] {
		if best == nil || better(p, best) {
			best = p
		}
	}

	return best, best != nil
}

// Versions returns every package called name, in the order they were added.
func (idx *Index) Versions(name string) []*RepoPackage {
	return append([]*RepoPackage(nil), idx.byName[name]...)
}

// ResolveVirtual returns the package that provides the capability name: the
// one with the highest provider priority, the first added among equals.
func (idx *Index) ResolveVirtual(name string) (*RepoPackage, bool) {
	var best *RepoPackage

	for _, p := range idx.providers[name] {
		switch {
		case best == nil:
			best = p
		case (p.Repo.Tag == "") != (best.Repo.Tag == ""):
			if p.Repo.Tag == "" {
				best = p
			}
		case p.ProviderPriority > best.ProviderPriority:
			best = p
		}
	}

	return best, best != nil
}

// Find returns the package called name or, failing that, the provider of the
// capability name.
func (idx *Index) Find(name string) (*RepoPackage, bool) {
	if p, ok := idx.Lookup(name); ok {
		return p, true
	}

	return idx.ResolveVirtual(name)
}

// Stats returns the number of packages and of provided capabilities.
func (idx *Index) Stats() (packages, capabilities int) {
	return len(idx.pkgs), len(idx.providers)
}

// stripConstraint returns the name of a dependency or provides entry:
// "musl-dev>=1.2" gives "musl-dev", "so:libc.so.6=1" gives "so:libc.so.6".
func stripConstraint(spec string) string {
	spec = strings.TrimSpace(spec)

	if i := strings.IndexAny(spec, "<>=~!"); i >= 0 {
		return strings.TrimSpace(spec[:i])
	}

	return spec
}

// DependencyName returns the package or capability name of a dependency
// entry, without its version constraint: "musl-dev>=1.2" gives "musl-dev".
func DependencyName(spec string) string { return stripConstraint(spec) }
