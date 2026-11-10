package apk

import (
	"errors"
	"fmt"
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
	packages  map[string]*RepoPackage   // name -> first package added with it
	providers map[string][]*RepoPackage // capability -> providers, in order added
}

// NewIndex returns an empty Index.
func NewIndex() *Index {
	return &Index{
		packages:  make(map[string]*RepoPackage),
		providers: make(map[string][]*RepoPackage),
	}
}

// Add lists the packages of repo's index for indexArch. A package whose name is
// already in the Index is ignored: the repository added first wins, like the
// order of a repositories file. Every package registers the capabilities of
// its Provides, without their versions.
func (idx *Index) Add(repo Repo, indexArch string, pkgs []Package) {
	for i := range pkgs {
		rp := &RepoPackage{Package: pkgs[i], Repo: repo, IndexArch: indexArch}

		if _, ok := idx.packages[rp.Name]; ok {
			continue
		}

		idx.packages[rp.Name] = rp

		for _, p := range rp.Provides {
			if name := stripConstraint(p); name != "" {
				idx.providers[name] = append(idx.providers[name], rp)
			}
		}
	}
}

// Lookup returns the package of that name. The name has no version
// constraint.
func (idx *Index) Lookup(name string) (*RepoPackage, bool) {
	p, ok := idx.packages[name]

	return p, ok
}

// ResolveVirtual returns the package that provides the capability name: the
// one with the highest provider priority, the first added among equals.
func (idx *Index) ResolveVirtual(name string) (*RepoPackage, bool) {
	var best *RepoPackage

	for _, p := range idx.providers[name] {
		if best == nil || p.ProviderPriority > best.ProviderPriority {
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
	return len(idx.packages), len(idx.providers)
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

// Resolution is the result of [Index.ResolveDeps].
type Resolution struct {
	// Packages are the packages to install, dependencies before the packages
	// that need them.
	Packages []*RepoPackage
	// Virtual lists the capabilities that were resolved to a provider.
	Virtual []string
	// Unresolved lists the dependencies nothing provides. They are skipped,
	// not an error: apk itself rejects them at install time if they matter.
	Unresolved []string
}

// ResolveDeps resolves names and their transitive dependencies with a
// depth-first walk: a name is a package or a capability, version constraints
// are dropped, and "!conflict" and "/path" dependencies are skipped. It is
// not a solver; it picks the first package that matches. A requested name
// that nothing provides is [ErrPackageNotFound]. The walk keeps its own stack,
// so a chain of dependencies as long as a hostile index can make it costs
// memory, not call depth.
func (idx *Index) ResolveDeps(names []string) (*Resolution, error) {
	type frame struct {
		pkg  *RepoPackage
		next int // the next entry of pkg.Depends to follow
	}

	var (
		res   = &Resolution{}
		seen  = make(map[string]bool)
		stack []frame
	)

	// push starts the walk of a dependency unless it was already reached.
	push := func(spec string) {
		name := stripConstraint(spec)
		if seen[name] {
			return
		}

		seen[name] = true

		pkg, ok := idx.Lookup(name)
		if !ok {
			if pkg, ok = idx.ResolveVirtual(name); !ok {
				res.Unresolved = append(res.Unresolved, name)

				return
			}

			res.Virtual = append(res.Virtual, name)
		}

		// The same package can be reached by its name and by a capability it
		// provides.
		if pkg.Name != name {
			if seen[pkg.Name] {
				return
			}

			seen[pkg.Name] = true
		}

		stack = append(stack, frame{pkg: pkg})
	}

	for _, n := range names {
		if _, ok := idx.Find(stripConstraint(n)); !ok {
			return nil, fmt.Errorf("%w: %s", ErrPackageNotFound, short(n))
		}

		push(n)

		for len(stack) > 0 {
			top := &stack[len(stack)-1]

			if top.next >= len(top.pkg.Depends) {
				res.Packages = append(res.Packages, top.pkg)
				stack = stack[:len(stack)-1]

				continue
			}

			dep := top.pkg.Depends[top.next]
			top.next++

			if dep != "" && dep[0] != '!' && dep[0] != '/' {
				push(dep)
			}
		}
	}

	return res, nil
}
