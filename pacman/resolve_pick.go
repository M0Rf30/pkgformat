package pacman

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// maxOptionalDescLen bounds the description of an optional dependency.
const maxOptionalDescLen = 4096

// allows reports whether the repository may be used for use: one with no Usage
// set may be used for everything.
func (x *Index) allows(repo string, use Usage) bool {
	u, ok := x.usage[repo]

	return !ok || u.Allows(use)
}

// installable reports whether packages of the repository may be chosen to
// satisfy a dependency or a target. libalpm accepts a repository whose Usage
// has Install or Upgrade, so one that is only kept up to date still supplies
// the dependencies of the upgraded packages.
func (x *Index) installable(repo string) bool {
	return x.allows(repo, UsageInstall) || x.allows(repo, UsageUpgrade)
}

// pick returns the package that satisfies dep the way libalpm chooses one. A
// package of that name and an acceptable version comes first (the newest of
// the first repository that has one). Otherwise the providers compete: one for
// which prefer reports true wins, then the earliest repository, then the
// lowest name. Only repositories that are installable, and packages ok
// accepts (every package when ok is nil), are considered.
func (x *Index) pick(dep Dependency, ok, prefer func(*IndexedPackage) bool) (*IndexedPackage, bool) {
	usable := func(p *IndexedPackage) bool {
		return x.installable(p.Repo) && (ok == nil || ok(p))
	}

	if p, found := newest(x.byName[dep.Name], func(p *IndexedPackage) bool {
		return usable(p) && dep.Allows(p.Version)
	}); found {
		return p, true
	}

	var (
		best     *IndexedPackage
		bestPref bool
	)

	for _, p := range x.byProvide[dep.Name] {
		if !p.satisfiesByProvides(dep) || !usable(p) {
			continue
		}

		pref := prefer != nil && prefer(p)
		if best == nil || x.betterProvider(p, pref, best, bestPref) {
			best, bestPref = p, pref
		}
	}

	return best, best != nil
}

// betterProvider reports whether a (preferred or not) beats b as a provider.
func (x *Index) betterProvider(a *IndexedPackage, aPref bool, b *IndexedPackage, bPref bool) bool {
	if aPref != bPref {
		return aPref
	}

	if c := cmp.Compare(x.rank[a.Repo], x.rank[b.Repo]); c != 0 {
		return c < 0
	}

	if c := strings.Compare(a.Name, b.Name); c != 0 {
		return c < 0
	}

	return a.Repo == b.Repo && Vercmp(a.Version, b.Version) > 0
}

// Group returns the members of the group called name, as "pacman -S name"
// installs them: a package of the first repository that has it, its newest
// version, whatever the other repositories hold. Repositories whose Usage has
// neither Install nor Upgrade are left out. The members are ordered by repository, then
// by name.
func (x *Index) Group(name string) []*IndexedPackage {
	members := map[string]*IndexedPackage{}

	for _, p := range x.byGroup[name] {
		if !x.installable(p.Repo) {
			continue
		}

		cur, ok := members[p.Name]
		if !ok || x.betterProvider(p, false, cur, false) {
			members[p.Name] = p
		}
	}

	out := make([]*IndexedPackage, 0, len(members))
	for _, p := range members {
		out = append(out, p)
	}

	slices.SortFunc(out, func(a, b *IndexedPackage) int {
		if c := cmp.Compare(x.rank[a.Repo], x.rank[b.Repo]); c != 0 {
			return c
		}

		return strings.Compare(a.Name, b.Name)
	})

	return out
}

// Search returns the packages whose name or description contains query,
// ignoring case, as "pacman -Ss" lists them: only repositories that allow
// UsageSearch are searched, in the order they were added. An empty query
// matches every package.
func (x *Index) Search(query string) []*IndexedPackage {
	query = strings.ToLower(query)

	var out []*IndexedPackage

	for _, p := range x.pkgs {
		if !x.allows(p.Repo, UsageSearch) {
			continue
		}

		if strings.Contains(strings.ToLower(p.Name), query) || strings.Contains(strings.ToLower(p.Description), query) {
			out = append(out, p)
		}
	}

	return out
}

// OptionalDep is an optional dependency: "name[: description]" in the
// optdepends of a package. It is a dependency that pacman suggests but does not
// install.
type OptionalDep struct {
	Dependency
	// Description says what the dependency adds; it can be empty.
	Description string
	// Package is the package of the index that would satisfy it, set by
	// Index.OptionalDeps; nil when none does.
	Package *IndexedPackage
}

// ParseOptionalDep parses "name[(<=|>=|=|<|>)version][: description]".
func ParseOptionalDep(s string) (OptionalDep, error) {
	expr, desc, _ := strings.Cut(s, ": ")

	// A trailing colon with no description is a description left empty.
	expr = strings.TrimSuffix(expr, ":")

	d, err := ParseDependency(strings.TrimSpace(expr))
	if err != nil {
		return OptionalDep{}, err
	}

	if len(desc) > maxOptionalDescLen {
		return OptionalDep{}, fmt.Errorf("%w: description too long", ErrInvalidDependency)
	}

	return OptionalDep{Dependency: d, Description: strings.TrimSpace(desc)}, nil
}

// String returns the optdepends entry ParseOptionalDep accepts.
func (o OptionalDep) String() string {
	if o.Description == "" {
		return o.Dependency.String()
	}

	return o.Dependency.String() + ": " + o.Description
}

// OptionalDeps parses the optional dependencies of the package, in order. They
// are never installed unless ResolveOptions.WithOptional says so.
func (p *IndexedPackage) OptionalDeps() ([]OptionalDep, error) {
	out := make([]OptionalDep, 0, len(p.OptDepends))

	for _, s := range p.OptDepends {
		o, err := ParseOptionalDep(s)
		if err != nil {
			return nil, fmt.Errorf("package %s: %w", p.Name, err)
		}

		out = append(out, o)
	}

	return out, nil
}

// OptionalDeps returns the optional dependencies of p with, for each, the
// package of the index that would satisfy it (nil when none does).
func (x *Index) OptionalDeps(p *IndexedPackage) ([]OptionalDep, error) {
	opts, err := p.OptionalDeps()
	if err != nil {
		return nil, err
	}

	for i := range opts {
		opts[i].Package, _ = x.pick(opts[i].Dependency, nil, nil)
	}

	return opts, nil
}
