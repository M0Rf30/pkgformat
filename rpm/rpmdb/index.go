package rpmdb

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"path"
	"slices"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/richdep"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// depKind selects one of the dependency lists of a package.
type depKind int

const (
	kindProvides depKind = iota
	kindRequires
	kindRecommends
	kindSuggests
	kindSupplements
	kindEnhances
	kindConflicts
	kindObsoletes
	numKinds
)

// list returns the dependency list of the package that kind selects.
func (k depKind) list(p *rpm.Package) []rpm.Dependency {
	switch k {
	case kindProvides:
		return p.Provides
	case kindRequires:
		return p.Requires
	case kindRecommends:
		return p.Recommends
	case kindSuggests:
		return p.Suggests
	case kindSupplements:
		return p.Supplements
	case kindEnhances:
		return p.Enhances
	case kindConflicts:
		return p.Conflicts
	case kindObsoletes:
		return p.Obsoletes
	default:
		return nil
	}
}

// depRef is an entry of a dependency index: dependency dep of package pkg.
// A capability found inside a rich dependency carries its own atom; a plain
// dependency is read from the package.
type depRef struct {
	pkg, dep int32
	atom     *richdep.Atom
}

// queryIndex is the in-memory index behind the query methods. It is built once
// from the database and never changes: a refresh builds a new one.
type queryIndex struct {
	// pkgs is every installed package, ordered by name, then version, then
	// architecture; ids are positions in it.
	pkgs   []*rpm.Package
	byName map[string][]int32
	deps   [numKinds]map[string][]depRef
	files  map[string][]int32
}

// pending is a package read from the database, before it is indexed.
type pending struct {
	pkg *rpm.Package
	// skip lists the files of the package that are not installed.
	skip []int
}

// rpmlibPrefix names the capabilities rpm itself provides, which rpm leaves
// out of its dependency indexes.
const rpmlibPrefix = "rpmlib("

// buildIndex reads the whole database into a [queryIndex].
func (db *DB) buildIndex(ctx context.Context) (*queryIndex, error) {
	var (
		all     []pending
		entries int
	)

	for rec, err := range db.records(ctx) {
		if err != nil {
			return nil, err
		}

		entries += len(rec.pkg.Files) + 1
		for k := range numKinds {
			entries += len(k.list(rec.pkg))
		}

		if entries > db.opts.MaxIndexEntries || len(all) >= math.MaxInt32 {
			return nil, fmt.Errorf("%w: the query index would hold more than %d entries", ErrTooLarge, db.opts.MaxIndexEntries)
		}

		p := pending{pkg: rec.pkg}
		if !db.opts.IncludeUninstalledFiles {
			p.skip = notInstalled(rec.hdr, len(rec.pkg.Files))
		}

		all = append(all, p)
	}

	slices.SortStableFunc(all, func(a, b pending) int { return comparePackages(a.pkg, b.pkg) })

	ix := &queryIndex{
		pkgs:   make([]*rpm.Package, len(all)),
		byName: make(map[string][]int32),
		files:  make(map[string][]int32),
	}

	for k := range ix.deps {
		ix.deps[k] = make(map[string][]depRef)
	}

	for id, p := range all {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		ix.pkgs[id] = p.pkg
		entries = ix.add(int32(id), p, entries, db.opts.MaxIndexEntries)

		if entries > db.opts.MaxIndexEntries {
			return nil, fmt.Errorf("%w: the query index would hold more than %d entries", ErrTooLarge, db.opts.MaxIndexEntries)
		}
	}

	return ix, nil
}

// notInstalled returns the positions among the first n files of a header
// whose state says they are not on disk, as rpm -qf sees them: any state
// but normal or netshared.
func notInstalled(hdr *rpm.RpmHeader, n int) []int {
	states, err := hdr.GetUint32s(tag.FILESTATES)
	if err != nil {
		return nil
	}

	var skip []int

	for i, s := range states[:min(len(states), n)] {
		if s != tag.RPMFILE_STATE_NORMAL && s != tag.RPMFILE_STATE_NETSHARED {
			skip = append(skip, i)
		}
	}

	return skip
}

// comparePackages orders packages by name, then version, then architecture.
func comparePackages(a, b *rpm.Package) int {
	return cmp.Or(
		strings.Compare(a.Name, b.Name),
		cmp.Compare(a.Epoch, b.Epoch),
		rpm.Vercmp(a.Version, b.Version),
		rpm.Vercmp(a.Release, b.Release),
		strings.Compare(a.Version, b.Version),
		strings.Compare(a.Release, b.Release),
		strings.Compare(a.Arch, b.Arch),
		cmp.Compare(a.InstallTime, b.InstallTime),
	)
}

// add indexes package id and returns the running entry count, which stops
// growing the index once it passes limit.
func (ix *queryIndex) add(id int32, p pending, entries, limit int) int {
	pkg := p.pkg

	ix.byName[pkg.Name] = append(ix.byName[pkg.Name], id)

	skip := p.skip

	for i, f := range pkg.Files {
		if len(skip) > 0 && skip[0] == i {
			skip = skip[1:]

			continue
		}

		name := path.Clean(f.Path)
		ix.files[name] = appendOnce(ix.files[name], id)
	}

	for k := range numKinds {
		for i, d := range k.list(pkg) {
			ix.deps[k][d.Name] = append(ix.deps[k][d.Name], depRef{pkg: id, dep: int32(i)})

			// rpm also indexes the capabilities inside a rich dependency, which
			// a query for the plain name must find.
			if k != kindProvides && strings.HasPrefix(d.Name, "(") {
				entries = ix.addRich(k, id, int32(i), d.Name, entries, limit)
			}
		}
	}

	return entries
}

// addRich indexes the capabilities of the rich dependency text, as rpm does:
// those in the condition of an "if" or "unless" are left out, since they are
// not required by themselves, except when an "else" follows.
func (ix *queryIndex) addRich(k depKind, id, dep int32, text string, entries, limit int) int {
	node, err := richdep.Parse(text)
	if err != nil {
		return entries
	}

	walkRich(node, false, func(a richdep.Atom) {
		if entries > limit || strings.HasPrefix(a.Name, rpmlibPrefix) {
			return
		}

		entries++

		atom := a
		ix.deps[k][atom.Name] = append(ix.deps[k][atom.Name], depRef{pkg: id, dep: dep, atom: &atom})
	})

	return entries
}

// walkRich calls fn for each capability of n that rpm indexes by name. neg
// says the subtree is a condition that rpm indexes negated, which is skipped.
func walkRich(n richdep.Node, neg bool, fn func(richdep.Atom)) {
	switch n := n.(type) {
	case richdep.Atom:
		if !neg {
			fn(n)
		}
	case *richdep.Expr:
		if (n.Op == richdep.OpIf || n.Op == richdep.OpUnless) && len(n.Args) >= 2 {
			walkRich(n.Args[0], neg, fn)
			// The condition counts as negated; an else branch turns it back.
			walkRich(n.Args[1], !neg, fn)

			if len(n.Args) > 2 {
				walkRich(n.Args[1], neg, fn)
				walkRich(n.Args[2], neg, fn)
			}

			return
		}

		for _, a := range n.Args {
			walkRich(a, neg, fn)
		}
	}
}

// appendOnce appends id to ids unless it is the last one: a package lists a
// path once, but directories and ghosts can repeat.
func appendOnce(ids []int32, id int32) []int32 {
	if len(ids) > 0 && ids[len(ids)-1] == id {
		return ids
	}

	return append(ids, id)
}

// matches reports whether the dependency a reference stands for overlaps q.
func (ix *queryIndex) matches(k depKind, r depRef, q richdep.Atom) bool {
	if r.atom != nil {
		return r.atom.Overlaps(q)
	}

	return richdep.AtomOf(k.list(ix.pkgs[r.pkg])[r.dep]).Overlaps(q)
}

// lookup returns the packages with an entry of kind k that overlaps q, in the
// order of the index, without repeats.
func (ix *queryIndex) lookup(k depKind, q richdep.Atom) []*rpm.Package {
	var ids []int32

	for _, r := range ix.deps[k][q.Name] {
		if ix.matches(k, r, q) {
			ids = append(ids, r.pkg)
		}
	}

	return ix.packages(ids)
}

// packages returns the packages with the given ids, sorted by id and without
// repeats.
func (ix *queryIndex) packages(ids []int32) []*rpm.Package {
	if len(ids) == 0 {
		return nil
	}

	slices.Sort(ids)
	ids = slices.Compact(ids)

	out := make([]*rpm.Package, len(ids))
	for i, id := range ids {
		out[i] = ix.pkgs[id]
	}

	return out
}

// provides returns the packages that provide q, see [queryIndex.providerIDs].
func (ix *queryIndex) provides(q richdep.Atom) []*rpm.Package {
	return ix.packages(ix.providerIDs(q))
}

// providerIDs returns the ids of the packages that provide q: through an
// entry of their provides, through the implicit provide of their own name and
// version, or, for a path, through owning that file.
func (ix *queryIndex) providerIDs(q richdep.Atom) []int32 {
	var ids []int32

	for _, r := range ix.deps[kindProvides][q.Name] {
		if ix.matches(kindProvides, r, q) {
			ids = append(ids, r.pkg)
		}
	}

	// Every package provides its own name and version; rpm adds the entry
	// when it builds one, an old or foreign header may lack it.
	for _, id := range ix.byName[q.Name] {
		if self := selfProvide(ix.pkgs[id]); self.Overlaps(q) {
			ids = append(ids, id)
		}
	}

	if strings.HasPrefix(q.Name, "/") {
		ids = append(ids, ix.files[path.Clean(q.Name)]...)
	}

	return ids
}

// selfProvide is the capability every package provides: its own name equal to
// its version.
func selfProvide(p *rpm.Package) richdep.Atom {
	v := p.Version
	if p.Release != "" {
		v += "-" + p.Release
	}

	if p.Epoch != 0 {
		v = fmt.Sprintf("%d:%s", p.Epoch, v)
	}

	return richdep.Atom{Name: p.Name, Cmp: richdep.Equal, Version: v}
}
