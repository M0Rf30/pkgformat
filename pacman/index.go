package pacman

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxIndexPackages bounds the packages an Index holds.
const MaxIndexPackages = 2_000_000

// maxDependencyLen bounds a dependency expression.
const maxDependencyLen = 1024

// Errors of dependency parsing and resolution. Test with errors.Is.
var (
	// ErrInvalidDependency reports a dependency expression that cannot be parsed.
	ErrInvalidDependency = errors.New("pacman: invalid dependency")
	// ErrUnresolved reports a dependency no package of the index satisfies.
	ErrUnresolved = errors.New("pacman: unresolvable dependency")
	// ErrIndexTooLarge reports an index that would exceed MaxIndexPackages.
	ErrIndexTooLarge = errors.New("pacman: index exceeds the package limit")
)

// Dependency is a parsed dependency, provision or conflict expression:
// "name", or "name" followed by a comparison operator and a version.
type Dependency struct {
	Name string
	// Op is "", "=", "<", "<=", ">" or ">=".
	Op string
	// Version is the compared version; empty exactly when Op is empty.
	Version string
}

// ParseDependency parses "name[(<=|>=|=|<|>)version]".
func ParseDependency(s string) (Dependency, error) {
	if len(s) > maxDependencyLen {
		return Dependency{}, fmt.Errorf("%w: too long", ErrInvalidDependency)
	}

	i := strings.IndexAny(s, "<>=")
	if i < 0 {
		i = len(s)
	}

	d := Dependency{Name: s[:i]}

	if !validDepName(d.Name) {
		return Dependency{}, fmt.Errorf("%w: %q", ErrInvalidDependency, s)
	}

	if i == len(s) {
		return d, nil
	}

	rest := s[i:]

	for _, op := range []string{"<=", ">=", "=", "<", ">"} {
		if v, ok := strings.CutPrefix(rest, op); ok {
			if v == "" || strings.ContainsAny(v, "<>= \t") {
				return Dependency{}, fmt.Errorf("%w: %q", ErrInvalidDependency, s)
			}

			d.Op, d.Version = op, v

			return d, nil
		}
	}

	return Dependency{}, fmt.Errorf("%w: %q", ErrInvalidDependency, s)
}

func validDepName(n string) bool {
	if n == "" || n[0] == '-' || n[0] == '.' {
		return false
	}

	for i := range len(n) {
		c := n[i]
		if c <= ' ' || c >= 0x7f || c == '/' || c == ':' {
			return false
		}
	}

	return true
}

// String returns the expression ParseDependency accepts.
func (d Dependency) String() string { return d.Name + d.Op + d.Version }

// Allows reports whether version satisfies the constraint of d. A dependency
// without constraint allows every version.
func (d Dependency) Allows(version string) bool {
	if d.Op == "" {
		return true
	}

	c := Vercmp(version, d.Version)

	switch d.Op {
	case "=":
		return c == 0
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	}

	return false
}

// IndexedPackage is a package of an Index and the repository it comes from.
type IndexedPackage struct {
	Repo string
	DBEntry
}

// Satisfies reports whether the package fulfils dep by its own name and
// version, or by one of its provisions. A provision without version fulfils
// only a dependency without constraint, as in libalpm.
func (p *IndexedPackage) Satisfies(dep Dependency) bool {
	return p.satisfiesByName(dep) || p.satisfiesByProvides(dep)
}

func (p *IndexedPackage) satisfiesByName(dep Dependency) bool {
	return p.Name == dep.Name && dep.Allows(p.Version)
}

func (p *IndexedPackage) satisfiesByProvides(dep Dependency) bool {
	for _, prov := range p.Provides {
		name, version, hasVersion := strings.Cut(prov, "=")
		if name != dep.Name {
			continue
		}

		switch {
		case dep.Op == "":
			return true
		case hasVersion && dep.Allows(version):
			return true
		}
	}

	return false
}

// Index is a set of sync databases that can be searched and whose dependencies
// can be resolved. The zero value is an empty index. Repositories are
// searched in the order they were added; an Index is not safe for concurrent
// modification, but is for concurrent reads.
type Index struct {
	pkgs   []*IndexedPackage
	byName map[string][]*IndexedPackage
	// byProvide maps a provided name to the packages that provide it, never
	// listing a package for its own name.
	byProvide map[string][]*IndexedPackage
}

// Len returns the number of packages.
func (x *Index) Len() int { return len(x.pkgs) }

// Add appends the entries of repo to the index.
func (x *Index) Add(repo string, entries []DBEntry) error {
	if len(x.pkgs)+len(entries) > MaxIndexPackages {
		return ErrIndexTooLarge
	}

	if x.byName == nil {
		x.byName = map[string][]*IndexedPackage{}
		x.byProvide = map[string][]*IndexedPackage{}
	}

	for i := range entries {
		p := &IndexedPackage{Repo: repo, DBEntry: entries[i]}

		x.pkgs = append(x.pkgs, p)
		x.byName[p.Name] = append(x.byName[p.Name], p)

		seen := map[string]bool{}

		for _, prov := range p.Provides {
			name, _, _ := strings.Cut(prov, "=")
			if (name == p.Name && !strings.Contains(prov, "=")) || seen[name] {
				continue
			}

			seen[name] = true

			x.byProvide[name] = append(x.byProvide[name], p)
		}
	}

	return nil
}

// AddDatabase reads a sync database (as ReadDB does) and adds it as repo.
func (x *Index) AddDatabase(repo string, r io.Reader) error {
	entries, err := ReadDB(r)
	if err != nil {
		return err
	}

	return x.Add(repo, entries)
}

// Packages returns every package in the order it was added.
func (x *Index) Packages() []*IndexedPackage { return x.pkgs }

// Lookup returns the package called name: of the first repository that has
// it, its newest version.
func (x *Index) Lookup(name string) (*IndexedPackage, bool) {
	return newest(x.byName[name], func(*IndexedPackage) bool { return true })
}

// newest returns, among the packages of the first repository with an
// accepted one, the one with the highest version.
func newest(pkgs []*IndexedPackage, ok func(*IndexedPackage) bool) (*IndexedPackage, bool) {
	var best *IndexedPackage

	for _, p := range pkgs {
		if !ok(p) {
			continue
		}

		switch {
		case best == nil:
			best = p
		case p.Repo != best.Repo:
			// Packages are listed repository by repository: stop at the first
			// repository that had a match.
			return best, true
		case Vercmp(p.Version, best.Version) > 0:
			best = p
		}
	}

	return best, best != nil
}

// Providers returns the packages that satisfy dep other than by their own
// name: those with a matching provision.
func (x *Index) Providers(dep Dependency) []*IndexedPackage {
	var out []*IndexedPackage

	for _, p := range x.byProvide[dep.Name] {
		if p.satisfiesByProvides(dep) {
			out = append(out, p)
		}
	}

	return out
}

// Resolve returns the package that satisfies dep. A package of that name with
// an acceptable version wins (the newest one of the first repository that has
// one); otherwise the first provider, in repository order, does. It fails with
// ErrUnresolved when nothing does.
func (x *Index) Resolve(dep Dependency) (*IndexedPackage, error) {
	if p, ok := newest(x.byName[dep.Name], func(p *IndexedPackage) bool { return dep.Allows(p.Version) }); ok {
		return p, nil
	}

	if prov := x.Providers(dep); len(prov) > 0 {
		return prov[0], nil
	}

	return nil, fmt.Errorf("%w: %s", ErrUnresolved, dep)
}

// ResolveOptions tunes ResolveDeps.
type ResolveOptions struct {
	// Installed, when set, reports a dependency the system already satisfies;
	// such dependencies are not resolved further.
	Installed func(Dependency) bool
}

// ResolveDeps returns the packages needed to install roots (dependency
// expressions such as "foo" or "bar>=2"), the roots included, with every
// package after the ones it depends on. A dependency cycle is tolerated: the
// package that closes it is placed before the one that needed it. A
// dependency nothing satisfies fails with an error wrapping ErrUnresolved that
// names the package that asked for it.
func (x *Index) ResolveDeps(roots []string, opts ResolveOptions) ([]*IndexedPackage, error) {
	type frame struct {
		pkg  *IndexedPackage
		deps []Dependency
		next int
	}

	var (
		order   []*IndexedPackage
		visited = map[*IndexedPackage]bool{}
		stack   []frame
	)

	// enter resolves dep (asked for by who) and, when its package is new,
	// pushes it onto the stack.
	enter := func(dep Dependency, who string) error {
		if opts.Installed != nil && opts.Installed(dep) {
			return nil
		}

		p, err := x.Resolve(dep)
		if err != nil {
			if who != "" {
				return fmt.Errorf("%w (required by %s)", err, who)
			}

			return err
		}

		if visited[p] {
			return nil
		}

		visited[p] = true

		deps := make([]Dependency, 0, len(p.Depends))

		for _, s := range p.Depends {
			d, err := ParseDependency(s)
			if err != nil {
				return fmt.Errorf("package %s: %w", p.Name, err)
			}

			deps = append(deps, d)
		}

		stack = append(stack, frame{pkg: p, deps: deps})

		return nil
	}

	for _, r := range roots {
		dep, err := ParseDependency(r)
		if err != nil {
			return nil, err
		}

		if err := enter(dep, ""); err != nil {
			return nil, err
		}

		for len(stack) > 0 {
			top := &stack[len(stack)-1]

			if top.next == len(top.deps) {
				order = append(order, top.pkg)
				stack = stack[:len(stack)-1]

				continue
			}

			d := top.deps[top.next]
			top.next++

			if err := enter(d, top.pkg.Name); err != nil {
				return nil, err
			}
		}
	}

	return order, nil
}
