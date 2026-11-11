package pacman

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
)

// Errors of transaction planning. Test with errors.Is; errors.As reaches the
// details in ConflictError and BrokenDependencyError.
var (
	// ErrConflict reports packages that cannot be installed together, or a
	// package that conflicts with an installed one that is not removed.
	ErrConflict = errors.New("pacman: conflicting packages")
	// ErrBrokenDependency reports a transaction that leaves an installed
	// package without a dependency it had.
	ErrBrokenDependency = errors.New("pacman: transaction breaks a dependency")
)

// ConflictError names the two packages of a conflict. It matches ErrConflict.
type ConflictError struct {
	// Package is the package to install whose (or whose counterpart's)
	// conflict is reported.
	Package string
	// With is the package it conflicts with.
	With string
	// Installed reports that With is installed, not part of the transaction.
	Installed bool
	// Expr is the conflict expression that matched, such as "vlib<2".
	Expr string
}

// Error implements error.
func (e *ConflictError) Error() string {
	where := "in the transaction"
	if e.Installed {
		where = "installed"
	}

	return fmt.Sprintf("%v: %s and %s (%s) conflict (%s)", ErrConflict, e.Package, e.With, where, e.Expr)
}

// Unwrap returns ErrConflict.
func (e *ConflictError) Unwrap() error { return ErrConflict }

// BrokenDependencyError reports an installed package whose dependency the
// transaction stops satisfying. It matches ErrBrokenDependency.
type BrokenDependencyError struct {
	// Package is the installed package that would lose the dependency.
	Package string
	// Dependency is the dependency expression, such as "libold=1-1".
	Dependency string
	// By is the package that satisfied it and is upgraded or removed.
	By string
}

// Error implements error.
func (e *BrokenDependencyError) Error() string {
	return fmt.Sprintf("%v: %s breaks dependency %s of %s", ErrBrokenDependency, e.By, e.Dependency, e.Package)
}

// Unwrap returns ErrBrokenDependency.
func (e *BrokenDependencyError) Unwrap() error { return ErrBrokenDependency }

// Upgrade is an installed package and the sync package that takes its place.
// The versions can be equal (a reinstall) or the installed one newer when the
// package was asked for by name.
type Upgrade struct {
	Installed *InstalledPackage
	Package   *IndexedPackage
}

// Replacement is an installed package that Package replaces, through its
// "replaces" entry, in a system upgrade.
type Replacement struct {
	Installed *InstalledPackage
	Package   *IndexedPackage
}

// Transaction is what installing packages or upgrading a system changes.
type Transaction struct {
	// Packages is every package to install or upgrade, each after the ones it
	// depends on.
	Packages []*IndexedPackage
	// Installs are the packages of Packages that are new to the system and
	// replace nothing.
	Installs []*IndexedPackage
	// Upgrades are the packages of Packages that take the place of an installed
	// package of the same name.
	Upgrades []Upgrade
	// Replacements are the packages of Packages that replace installed ones of
	// another name; the replaced packages are in Removals too.
	Replacements []Replacement
	// Removals are the installed packages to remove: the replaced ones.
	Removals []*InstalledPackage
}

// provision is what a package offers under a name: itself, with its version,
// or a "provides" entry, with the version it carries, if any.
type provision struct {
	owner     string
	version   string
	versioned bool
}

// provIndex maps a name to everything that can satisfy a dependency on it.
type provIndex map[string][]provision

func (m provIndex) addPackage(name, version string, provides []string) {
	m[name] = append(m[name], provision{owner: name, version: version, versioned: true})

	for _, prov := range provides {
		n, v, hasVersion := strings.Cut(prov, "=")
		m[n] = append(m[n], provision{owner: name, version: v, versioned: hasVersion})
	}
}

// satisfies reports whether pr fulfils dep: a versioned dependency needs a
// provision that has a version, as in libalpm.
func (pr provision) satisfies(dep Dependency) bool {
	if dep.Op == "" {
		return true
	}

	return pr.versioned && dep.Allows(pr.version)
}

// find returns the owner of a provision that satisfies dep and is not
// skipped, preferring a package of that very name.
func (m provIndex) find(dep Dependency, skip func(owner string) bool) (string, bool) {
	found := ""
	ok := false

	for _, pr := range m[dep.Name] {
		if (skip != nil && skip(pr.owner)) || !pr.satisfies(dep) {
			continue
		}

		if pr.owner == dep.Name {
			return pr.owner, true
		}

		if !ok {
			found, ok = pr.owner, true
		}
	}

	return found, ok
}

// all returns the distinct owners of the provisions that satisfy dep and are
// not skipped, in the order they were added.
func (m provIndex) all(dep Dependency, skip func(owner string) bool) []string {
	var out []string

	for _, pr := range m[dep.Name] {
		if (skip != nil && skip(pr.owner)) || !pr.satisfies(dep) || slices.Contains(out, pr.owner) {
			continue
		}

		out = append(out, pr.owner)
	}

	return out
}

// depRef is a dependency of a package and whether it is optional.
type depRef struct {
	Dependency
	optional bool
}

// resolver plans one transaction.
type resolver struct {
	x    *Index
	opts ResolveOptions

	local       []*InstalledPackage
	localByName map[string]*InstalledPackage
	localIdx    provIndex

	// removed holds the names of the installed packages the transaction removes.
	removed      map[string]bool
	removals     []*InstalledPackage
	replacements []Replacement

	// adds are the packages to install by name: the targets first, then what
	// they need.
	adds     map[string]*IndexedPackage
	addOrder []*IndexedPackage
	addIdx   provIndex

	visited map[*IndexedPackage]bool
	order   []*IndexedPackage
	// ordering is set while the packages are being ordered, once everything
	// they need has been chosen: dependencies are then only looked up among the
	// packages of the transaction.
	ordering bool
}

func newResolver(x *Index, opts ResolveOptions) *resolver {
	r := &resolver{
		x:           x,
		opts:        opts,
		local:       opts.Local,
		localByName: make(map[string]*InstalledPackage, len(opts.Local)),
		localIdx:    provIndex{},
		removed:     map[string]bool{},
		adds:        map[string]*IndexedPackage{},
		addIdx:      provIndex{},
		visited:     map[*IndexedPackage]bool{},
	}

	for _, l := range opts.Local {
		r.localByName[l.Name] = l
		r.localIdx.addPackage(l.Name, l.Version, l.Provides)
	}

	return r
}

// adopt puts p among the packages to install.
func (r *resolver) adopt(p *IndexedPackage) {
	r.adds[p.Name] = p
	r.addOrder = append(r.addOrder, p)
	r.addIdx.addPackage(p.Name, p.Version, p.Provides)
}

// ignored reports whether IgnorePkg or IgnoreGroup covers p.
func (r *resolver) ignored(p *IndexedPackage) bool {
	return matchesAny(r.opts.IgnorePkg, p.Name) || slices.ContainsFunc(p.Groups, func(g string) bool {
		return matchesAny(r.opts.IgnoreGroup, g)
	})
}

// matchesAny reports whether s equals or matches, as a shell glob, one of the
// patterns. An invalid pattern matches nothing.
func matchesAny(patterns []string, s string) bool {
	for _, pat := range patterns {
		if pat == s {
			return true
		}

		if ok, err := path.Match(pat, s); err == nil && ok {
			return true
		}
	}

	return false
}

// satisfiedLocal reports whether the system already satisfies dep for the
// package named requester: an installed package other than requester itself
// and than the ones being removed.
func (r *resolver) satisfiedLocal(dep Dependency, requester string) bool {
	if r.opts.Installed != nil && r.opts.Installed(dep) {
		return true
	}

	_, ok := r.localIdx.find(dep, func(owner string) bool { return owner == requester || r.removed[owner] })

	return ok
}

// pickable reports whether p may satisfy a dependency: it is not ignored and
// no package of that name is part of the transaction already.
func (r *resolver) pickable(p *IndexedPackage) bool {
	return !r.ignored(p) && r.adds[p.Name] == nil
}

// preferred reports whether p is already installed.
func (r *resolver) preferred(p *IndexedPackage) bool {
	_, ok := r.localByName[p.Name]

	return ok && !r.removed[p.Name]
}

// need returns the package to walk into for dep of who: nil when the system
// satisfies it or the package that does is already visited.
func (r *resolver) need(d depRef, who *IndexedPackage) (*IndexedPackage, error) {
	// A package of the transaction that satisfies dep is walked into first,
	// even when an installed one does too, so that it is ordered before who.
	if owner, ok := r.addIdx.find(d.Dependency, func(o string) bool { return o == who.Name }); ok {
		return r.unvisited(r.adds[owner]), nil
	}

	if r.ordering || r.satisfiedLocal(d.Dependency, who.Name) {
		return nil, nil
	}

	p, ok := r.x.pick(d.Dependency, r.pickable, r.preferred)
	if !ok {
		if d.optional {
			return nil, nil
		}

		return nil, fmt.Errorf("%w: %s (required by %s)", ErrUnresolved, d.Dependency, who.Name)
	}

	r.adopt(p)

	return r.unvisited(p), nil
}

func (r *resolver) unvisited(p *IndexedPackage) *IndexedPackage {
	if p == nil || r.visited[p] {
		return nil
	}

	return p
}

// depRefs parses the dependencies of p, and its optional ones when asked.
func (r *resolver) depRefs(p *IndexedPackage) ([]depRef, error) {
	deps := make([]depRef, 0, len(p.Depends))

	for _, s := range p.Depends {
		d, err := ParseDependency(s)
		if err != nil {
			return nil, fmt.Errorf("package %s: %w", p.Name, err)
		}

		deps = append(deps, depRef{Dependency: d})
	}

	if r.opts.WithOptional {
		for _, s := range p.OptDepends {
			if o, err := ParseOptionalDep(s); err == nil {
				deps = append(deps, depRef{Dependency: o.Dependency, optional: true})
			}
		}
	}

	return deps, nil
}

// walk visits start and what it needs depth first, appending every package to
// the order after its dependencies. It is iterative, so a long chain does not
// grow the call stack.
func (r *resolver) walk(start *IndexedPackage) error {
	type frame struct {
		pkg  *IndexedPackage
		deps []depRef
		next int
	}

	var stack []frame

	push := func(p *IndexedPackage) error {
		deps, err := r.depRefs(p)
		if err != nil {
			return err
		}

		r.visited[p] = true
		stack = append(stack, frame{pkg: p, deps: deps})

		return nil
	}

	if r.visited[start] {
		return nil
	}

	if err := push(start); err != nil {
		return err
	}

	for len(stack) > 0 {
		top := &stack[len(stack)-1]

		if top.next == len(top.deps) {
			r.order = append(r.order, top.pkg)
			stack = stack[:len(stack)-1]

			continue
		}

		d := top.deps[top.next]
		top.next++

		next, err := r.need(d, top.pkg)
		if err != nil {
			return err
		}

		if next != nil {
			if err := push(next); err != nil {
				return err
			}
		}
	}

	return nil
}

// addRoots resolves the targets: a package, a provider, or a group of
// packages.
func (r *resolver) addRoots(roots []string) error {
	for _, s := range roots {
		dep, err := ParseDependency(s)
		if err != nil {
			return err
		}

		if r.opts.Installed != nil && r.opts.Installed(dep) {
			continue
		}

		pkgs, err := r.rootPackages(dep)
		if err != nil {
			return err
		}

		for _, p := range pkgs {
			if r.adds[p.Name] == nil {
				r.adopt(p)
			}
		}
	}

	return nil
}

func (r *resolver) rootPackages(dep Dependency) ([]*IndexedPackage, error) {
	if p, ok := r.x.pick(dep, nil, r.preferred); ok {
		return []*IndexedPackage{p}, nil
	}

	if dep.Op == "" {
		if members := r.x.Group(dep.Name); len(members) > 0 {
			return members, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrUnresolved, dep)
}

// finish resolves the dependencies of everything adopted so far, orders the
// packages and checks the result.
func (r *resolver) finish() (*Transaction, error) {
	for _, t := range slices.Clone(r.addOrder) {
		if err := r.walk(t); err != nil {
			return nil, err
		}
	}

	// Now that the transaction is complete, order it: a package comes after the
	// ones of the transaction it depends on, even when an installed package
	// satisfied that dependency while it was being resolved.
	r.visited = map[*IndexedPackage]bool{}
	r.order = nil
	r.ordering = true

	for _, t := range slices.Clone(r.addOrder) {
		if err := r.walk(t); err != nil {
			return nil, err
		}
	}

	r.ordering = false

	if err := r.innerConflicts(); err != nil {
		return nil, err
	}

	if err := r.outerConflicts(); err != nil {
		return nil, err
	}

	if err := r.checkBroken(); err != nil {
		return nil, err
	}

	return r.transaction(), nil
}

func (r *resolver) transaction() *Transaction {
	tx := &Transaction{Packages: r.order, Removals: r.removals}

	replacing := map[*IndexedPackage]bool{}

	for _, rep := range r.replacements {
		if r.adds[rep.Package.Name] == rep.Package {
			replacing[rep.Package] = true

			tx.Replacements = append(tx.Replacements, rep)
		}
	}

	for _, p := range r.order {
		switch l := r.localByName[p.Name]; {
		case l != nil && !r.removed[p.Name]:
			tx.Upgrades = append(tx.Upgrades, Upgrade{Installed: l, Package: p})
		case !replacing[p]:
			tx.Installs = append(tx.Installs, p)
		}
	}

	return tx
}

// Install plans installing roots, as "pacman -S" does: each root is a
// dependency expression ("foo", "bar>=2"; a provider of the name when no
// package has it) or the name of a group, and is installed with what it
// needs that the system, ResolveOptions.Local or ResolveOptions.Installed,
// does not satisfy. A package of the transaction takes the place of an
// installed one of the same name.
//
// The plan is checked as libalpm checks it. Two packages of the transaction
// that conflict are an error, except that when one provides the name of the
// other the provided one is left out. A package that conflicts with an
// installed one is an error. A package that stops satisfying a dependency of
// an installed package is an error. The errors wrap ErrConflict,
// ErrBrokenDependency and ErrUnresolved.
func (x *Index) Install(roots []string, opts ResolveOptions) (*Transaction, error) {
	r := newResolver(x, opts)

	if err := r.addRoots(roots); err != nil {
		return nil, err
	}

	return r.finish()
}
