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
	// usage holds the Usage of the repositories that have one set.
	usage map[string]Usage
	// rank is the position of each repository in the order it was added.
	rank map[string]int
	// byGroup maps a group name to its members.
	byGroup map[string][]*IndexedPackage
	// replacers are the packages with a replaces entry, in the order added.
	replacers []*IndexedPackage
}

// SetUsage sets what the repository repo may be used for. A repository never
// set is usable for everything, as one without a Usage line in pacman.conf.
func (x *Index) SetUsage(repo string, u Usage) {
	if x.usage == nil {
		x.usage = map[string]Usage{}
	}

	x.usage[repo] = u
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
		x.byGroup = map[string][]*IndexedPackage{}
		x.rank = map[string]int{}
	}

	if _, ok := x.rank[repo]; !ok {
		x.rank[repo] = len(x.rank)
	}

	for i := range entries {
		p := &IndexedPackage{Repo: repo, DBEntry: entries[i]}

		x.pkgs = append(x.pkgs, p)
		x.byName[p.Name] = append(x.byName[p.Name], p)

		for _, g := range p.Groups {
			x.byGroup[g] = append(x.byGroup[g], p)
		}

		if len(p.Replaces) > 0 {
			x.replacers = append(x.replacers, p)
		}

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

// Resolve returns the package that satisfies dep, as libalpm picks one: a
// package of that name with an acceptable version wins (the newest one of the
// first repository that has one); otherwise a provider does, the first one in
// repository order and then name order. Repositories whose Usage does not
// allow UsageInstall are not searched. It fails with ErrUnresolved when
// nothing satisfies dep.
func (x *Index) Resolve(dep Dependency) (*IndexedPackage, error) {
	if p, ok := x.pick(dep, nil, nil); ok {
		return p, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrUnresolved, dep)
}

// ResolveOptions tunes ResolveDeps, Index.Install and Index.Sysupgrade.
type ResolveOptions struct {
	// Installed, when set, reports a dependency the system already satisfies;
	// such dependencies are not resolved further.
	Installed func(Dependency) bool
	// Local is the set of installed packages (LocalDB.List). A dependency one
	// of them satisfies is not resolved further, and Index.Install and
	// Index.Sysupgrade check the transaction against them for conflicts and
	// broken dependencies. Index.Sysupgrade uses its own installed argument
	// instead.
	Local []*InstalledPackage
	// IgnorePkg lists package names or glob patterns, as pacman's IgnorePkg
	// option does. An ignored package is not upgraded or replaced by
	// Index.Sysupgrade and is not picked to satisfy a dependency. A package
	// asked for explicitly is installed all the same, as pacman does when it is
	// not asked.
	IgnorePkg []string
	// IgnoreGroup lists group names or glob patterns, as pacman's IgnoreGroup
	// option does; a package is ignored when one of its groups matches.
	IgnoreGroup []string
	// WithOptional also installs the optional dependencies the index can
	// satisfy. Without it they are never installed, as in pacman.
	WithOptional bool
}

// ResolveDeps returns the packages needed to install roots (dependency
// expressions such as "foo" or "bar>=2", or a group name), the roots included,
// with every package after the ones it depends on. A dependency cycle is
// tolerated: the package that closes it is placed before the one that needed
// it. A dependency nothing satisfies fails with an error wrapping ErrUnresolved
// that names the package that asked for it. It is Index.Install without the
// classification of the result.
func (x *Index) ResolveDeps(roots []string, opts ResolveOptions) ([]*IndexedPackage, error) {
	tx, err := x.Install(roots, opts)
	if err != nil {
		return nil, err
	}

	return tx.Packages, nil
}
