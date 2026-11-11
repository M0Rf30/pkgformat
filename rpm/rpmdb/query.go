package rpmdb

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/richdep"
)

// maxQueryBytes bounds the argument of a query: longer than any name, path or
// version rpm can store.
const maxQueryBytes = 1 << 16

// index returns the query index, building it on the first call. Callers that
// arrive while it is built wait for it, or for their ctx; a build that failed
// or was cancelled leaves nothing behind, the next call tries again.
func (db *DB) index(ctx context.Context) (*queryIndex, error) {
	if ix := db.ix.Load(); ix != nil {
		return ix, nil
	}

	select {
	case db.building <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	defer func() { <-db.building }()

	if ix := db.ix.Load(); ix != nil {
		return ix, nil
	}

	ix, err := db.buildIndex(ctx)
	if err != nil {
		return nil, err
	}

	db.ix.Store(ix)

	return ix, nil
}

// Refresh drops the query index and builds it again from the database, so
// that the queries see what rpm has installed or removed since. Queries that
// run meanwhile use the old index; no query ever sees a half-built one. On an
// error the old index stays.
func (db *DB) Refresh(ctx context.Context) error {
	select {
	case db.building <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}

	defer func() { <-db.building }()

	ix, err := db.buildIndex(ctx)
	if err != nil {
		return err
	}

	db.ix.Store(ix)

	return nil
}

// checkArg rejects an empty or oversized argument.
func checkArg(what, s string) error {
	switch {
	case s == "":
		return fmt.Errorf("%w: empty %s", ErrInvalidQuery, what)
	case len(s) > maxQueryBytes:
		return fmt.Errorf("%w: %s of %d bytes", ErrInvalidQuery, what, len(s))
	case strings.IndexByte(s, 0) >= 0:
		return fmt.Errorf("%w: %s holds a NUL byte", ErrInvalidQuery, what)
	}

	return nil
}

// InstalledPackages returns every installed package, ordered by name, then
// version, then architecture. A package installed in several versions or for
// several architectures appears once for each. The packages are shared with
// the query index: callers must not modify them. The first call, like the
// first of any query method, reads the whole database; the later ones do not
// touch it until [DB.Refresh].
func (db *DB) InstalledPackages(ctx context.Context) ([]*rpm.Package, error) {
	ix, err := db.index(ctx)
	if err != nil {
		return nil, err
	}

	return slices.Clone(ix.pkgs), nil
}

// ParseCapability reads a capability as it is written in a spec file or in
// rpm -q --whatprovides: a name, or a name with a comparison and a version,
// "name >= [epoch:]version[-release]". The comparison is one of <, <=, =, ==,
// >=, >, with the spellings rpm accepts. A rich dependency is not a
// capability and fails with [ErrInvalidQuery].
func ParseCapability(s string) (richdep.Atom, error) {
	if err := checkArg("capability", s); err != nil {
		return richdep.Atom{}, err
	}

	node, err := richdep.Parse(s)
	if err != nil {
		return richdep.Atom{}, fmt.Errorf("%w: %w", ErrInvalidQuery, err)
	}

	a, ok := node.(richdep.Atom)
	if !ok {
		return richdep.Atom{}, fmt.Errorf("%w: %q is a rich dependency, not a capability", ErrInvalidQuery, s)
	}

	return a, nil
}

// ByName returns the installed packages with the name, in every version and
// architecture, in the order of [DB.InstalledPackages]. The result is empty
// when there is none.
func (db *DB) ByName(ctx context.Context, name string) ([]*rpm.Package, error) {
	if err := checkArg("name", name); err != nil {
		return nil, err
	}

	ix, err := db.index(ctx)
	if err != nil {
		return nil, err
	}

	return ix.packages(slices.Clone(ix.byName[name])), nil
}

// ByNEVRA returns the installed packages that match the fields of n that are
// set: an empty field matches anything. Name, version, release and architecture
// are compared as written, the epoch as a number, so "0" does not match a
// package with an epoch of 1 but matches one without. A non-numeric epoch
// fails with [ErrInvalidQuery].
func (db *DB) ByNEVRA(ctx context.Context, n rpm.NEVRA) ([]*rpm.Package, error) {
	for what, s := range map[string]string{"name": n.Name, "epoch": n.Epoch, "version": n.Version, "release": n.Release, "arch": n.Arch} {
		if len(s) > maxQueryBytes || strings.IndexByte(s, 0) >= 0 {
			return nil, fmt.Errorf("%w: unusable %s", ErrInvalidQuery, what)
		}
	}

	filter, err := newFilter(n)
	if err != nil {
		return nil, err
	}

	ix, err := db.index(ctx)
	if err != nil {
		return nil, err
	}

	var out []*rpm.Package

	if n.Name != "" {
		for _, id := range ix.byName[n.Name] {
			if filter.match(ix.pkgs[id]) {
				out = append(out, ix.pkgs[id])
			}
		}

		return out, nil
	}

	for _, p := range ix.pkgs {
		if filter.match(p) {
			out = append(out, p)
		}
	}

	return out, nil
}

// nevraFilter is an [rpm.NEVRA] with its epoch read as a number.
type nevraFilter struct {
	rpm.NEVRA
	epoch    uint32
	hasEpoch bool
}

func newFilter(n rpm.NEVRA) (nevraFilter, error) {
	f := nevraFilter{NEVRA: n}

	if n.Epoch != "" {
		e, err := strconv.ParseUint(n.Epoch, 10, 32)
		if err != nil {
			return f, fmt.Errorf("%w: epoch %q is not a number", ErrInvalidQuery, n.Epoch)
		}

		f.epoch, f.hasEpoch = uint32(e), true
	}

	return f, nil
}

func (f nevraFilter) match(p *rpm.Package) bool {
	return (f.Name == "" || p.Name == f.Name) &&
		(!f.hasEpoch || p.Epoch == f.epoch) &&
		(f.Version == "" || p.Version == f.Version) &&
		(f.Release == "" || p.Release == f.Release) &&
		(f.Arch == "" || p.Arch == f.Arch)
}

// ByLabel finds installed packages the way rpm -q does for its argument: the
// label is a name ("bash"), or name-version, name-version-release, each with
// an optional epoch before the version ("bash-1:5.2"), and each optionally
// followed by .arch ("bash-5.2-1.fc40.x86_64"). The whole label is tried as a
// name first. Versions, releases and architectures are compared as written,
// without the wildcards rpm's command line accepts. The result is empty when
// nothing matches.
func (db *DB) ByLabel(ctx context.Context, label string) ([]*rpm.Package, error) {
	if err := checkArg("label", label); err != nil {
		return nil, err
	}

	ix, err := db.index(ctx)
	if err != nil {
		return nil, err
	}

	if out := ix.labelMatches(label, ""); len(out) > 0 {
		return out, nil
	}

	// The label may end in the architecture.
	if i := strings.LastIndexByte(label, '.'); i > 0 && i < len(label)-1 { //nolint:modernize // CutLast is not in every supported toolchain
		return ix.labelMatches(label[:i], label[i+1:]), nil
	}

	return nil, nil
}

// labelMatches tries label as name, name-version and name-version-release.
func (ix *queryIndex) labelMatches(label, arch string) []*rpm.Package {
	try := func(name, version, release string) []*rpm.Package {
		var ids []int32

		for _, id := range ix.byName[name] {
			if p := ix.pkgs[id]; (arch == "" || p.Arch == arch) && versionMatches(p, version, release) {
				ids = append(ids, id)
			}
		}

		return ix.packages(ids)
	}

	if out := try(label, "", ""); len(out) > 0 {
		return out
	}

	i := strings.LastIndexByte(label, '-') //nolint:modernize // CutLast is not in every supported toolchain
	if i <= 0 {
		return nil
	}

	if out := try(label[:i], label[i+1:], ""); len(out) > 0 {
		return out
	}

	j := strings.LastIndexByte(label[:i], '-') //nolint:modernize // CutLast is not in every supported toolchain
	if j <= 0 {
		return nil
	}

	return try(label[:j], label[j+1:i], label[i+1:])
}

// versionMatches compares a package with "[epoch:]version" and a release; an
// empty version matches anything, as does an empty release.
func versionMatches(p *rpm.Package, version, release string) bool {
	if version == "" {
		return true
	}

	if before, after, ok := strings.Cut(version, ":"); ok {
		e, err := strconv.ParseUint(before, 10, 32)
		if err != nil || uint32(e) != p.Epoch {
			return false
		}

		version = after
	}

	return p.Version == version && (release == "" || p.Release == release)
}

// WhatProvides returns the installed packages that provide the capability: a
// provide whose version range overlaps q (see [richdep.Atom.Overlaps]; a
// provide of "foo = 1.2-3" satisfies "foo >= 1.0"), the implicit provide of a
// package's own name and version, and, when q is a path, the packages that own
// the file as [DB.FileOwners] finds them.
func (db *DB) WhatProvides(ctx context.Context, q richdep.Atom) ([]*rpm.Package, error) {
	return db.query(ctx, q, func(ix *queryIndex) []*rpm.Package { return ix.provides(q) })
}

// WhatRequires returns the installed packages with a requirement whose range
// overlaps q: with a bare name, every package that requires it in any
// version. As rpm does, it also finds a name inside a rich requirement
// "(a if b)" when the capability is required by itself, here "a"; the
// condition "b" is not found.
func (db *DB) WhatRequires(ctx context.Context, q richdep.Atom) ([]*rpm.Package, error) {
	return db.whatKind(ctx, kindRequires, q)
}

// WhatRecommends is [DB.WhatRequires] for Recommends.
func (db *DB) WhatRecommends(ctx context.Context, q richdep.Atom) ([]*rpm.Package, error) {
	return db.whatKind(ctx, kindRecommends, q)
}

// WhatSuggests is [DB.WhatRequires] for Suggests.
func (db *DB) WhatSuggests(ctx context.Context, q richdep.Atom) ([]*rpm.Package, error) {
	return db.whatKind(ctx, kindSuggests, q)
}

// WhatSupplements is [DB.WhatRequires] for Supplements.
func (db *DB) WhatSupplements(ctx context.Context, q richdep.Atom) ([]*rpm.Package, error) {
	return db.whatKind(ctx, kindSupplements, q)
}

// WhatEnhances is [DB.WhatRequires] for Enhances.
func (db *DB) WhatEnhances(ctx context.Context, q richdep.Atom) ([]*rpm.Package, error) {
	return db.whatKind(ctx, kindEnhances, q)
}

// WhatConflicts returns the installed packages with a Conflicts entry whose
// range overlaps q: those that conflict with a package that provides q. It is
// rpm --whatconflicts.
func (db *DB) WhatConflicts(ctx context.Context, q richdep.Atom) ([]*rpm.Package, error) {
	return db.whatKind(ctx, kindConflicts, q)
}

// WhatObsoletes returns the installed packages with an Obsoletes entry whose
// range overlaps q. It is rpm --whatobsoletes.
func (db *DB) WhatObsoletes(ctx context.Context, q richdep.Atom) ([]*rpm.Package, error) {
	return db.whatKind(ctx, kindObsoletes, q)
}

func (db *DB) whatKind(ctx context.Context, k depKind, q richdep.Atom) ([]*rpm.Package, error) {
	return db.query(ctx, q, func(ix *queryIndex) []*rpm.Package { return ix.lookup(k, q) })
}

// query checks q and runs fn on the index.
func (db *DB) query(ctx context.Context, q richdep.Atom, fn func(*queryIndex) []*rpm.Package) ([]*rpm.Package, error) {
	if err := checkArg("capability name", q.Name); err != nil {
		return nil, err
	}

	if len(q.Version) > maxQueryBytes {
		return nil, fmt.Errorf("%w: version of %d bytes", ErrInvalidQuery, len(q.Version))
	}

	ix, err := db.index(ctx)
	if err != nil {
		return nil, err
	}

	return fn(ix), nil
}

// FileOwners returns the installed packages that own the file at p, as rpm -qf
// finds them. The path is cleaned first (path.Clean: duplicate and trailing
// slashes, "." and ".." elements go), and a relative path is taken from the
// root "/". Symbolic links are not followed: the database knows the paths
// packages ship, not the file system. Ghost files, which a package owns
// without shipping, are owners; so are the directories a package lists. Files
// a package lists but did not install (excluded documentation, files another
// package replaced) are not, unless [Options.IncludeUninstalledFiles] is set.
// A path nobody owns gives an empty result.
func (db *DB) FileOwners(ctx context.Context, p string) ([]*rpm.Package, error) {
	if err := checkArg("path", p); err != nil {
		return nil, err
	}

	ix, err := db.index(ctx)
	if err != nil {
		return nil, err
	}

	return ix.packages(slices.Clone(ix.files[path.Join("/", p)])), nil
}

// ConflictsOf returns the installed packages in conflict with pkg, in either
// direction: those whose Conflicts match something pkg provides (its name and
// version included), and those that provide something pkg's Conflicts match.
// pkg itself is not part of the result. It does not look at files.
func (db *DB) ConflictsOf(ctx context.Context, pkg *rpm.Package) ([]*rpm.Package, error) {
	if pkg == nil || pkg.Name == "" {
		return nil, fmt.Errorf("%w: no package", ErrInvalidQuery)
	}

	ix, err := db.index(ctx)
	if err != nil {
		return nil, err
	}

	var ids []int32

	provided := append(providedBy(pkg), selfProvide(pkg))
	for _, a := range provided {
		for _, r := range ix.deps[kindConflicts][a.Name] {
			if ix.matches(kindConflicts, r, a) {
				ids = append(ids, r.pkg)
			}
		}
	}

	for _, d := range pkg.Conflicts {
		ids = append(ids, ix.providerIDs(richdep.AtomOf(d))...)
	}

	return ix.packages(ix.without(ids, pkg)), nil
}

// ObsoletedBy returns the installed packages whose Obsoletes entries match
// pkg: an entry names the package, in a version range that covers pkg's
// version when it has one. As in rpm, only the name and version of pkg are
// compared, not what it provides. pkg itself is not part of the result.
func (db *DB) ObsoletedBy(ctx context.Context, pkg *rpm.Package) ([]*rpm.Package, error) {
	if pkg == nil || pkg.Name == "" {
		return nil, fmt.Errorf("%w: no package", ErrInvalidQuery)
	}

	ix, err := db.index(ctx)
	if err != nil {
		return nil, err
	}

	self := selfProvide(pkg)

	var ids []int32

	for _, r := range ix.deps[kindObsoletes][pkg.Name] {
		if ix.matches(kindObsoletes, r, self) {
			ids = append(ids, r.pkg)
		}
	}

	return ix.packages(ix.without(ids, pkg)), nil
}

// ObsoletesOf returns the installed packages that pkg obsoletes: for each of
// its Obsoletes entries, the packages of that name whose version is in the
// entry's range. pkg itself is not part of the result.
func (db *DB) ObsoletesOf(ctx context.Context, pkg *rpm.Package) ([]*rpm.Package, error) {
	if pkg == nil || pkg.Name == "" {
		return nil, fmt.Errorf("%w: no package", ErrInvalidQuery)
	}

	ix, err := db.index(ctx)
	if err != nil {
		return nil, err
	}

	var ids []int32

	for _, d := range pkg.Obsoletes {
		q := richdep.AtomOf(d)

		for _, id := range ix.byName[q.Name] {
			if selfProvide(ix.pkgs[id]).Overlaps(q) {
				ids = append(ids, id)
			}
		}
	}

	return ix.packages(ix.without(ids, pkg)), nil
}

// providedBy returns the capabilities of the provides of a package.
func providedBy(p *rpm.Package) []richdep.Atom {
	out := make([]richdep.Atom, len(p.Provides))
	for i, d := range p.Provides {
		out[i] = richdep.AtomOf(d)
	}

	return out
}

// without drops from ids the package that is pkg: the same pointer, or the
// same installed package decoded elsewhere, or a package that is not installed
// (no install time) with the name, version and architecture of an installed one.
func (ix *queryIndex) without(ids []int32, pkg *rpm.Package) []int32 {
	return slices.DeleteFunc(ids, func(id int32) bool {
		p := ix.pkgs[id]

		return p == pkg || (sameNEVRA(p, pkg) && (pkg.InstallTime == 0 || p.InstallTime == pkg.InstallTime))
	})
}
