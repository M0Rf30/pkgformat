package apt

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
)

// maxResolveDepth bounds the dependency chain of ResolveDeps. Real Debian
// chains are shorter than 50.
const maxResolveDepth = 4096

// maxResolveSteps bounds the candidates ResolveDeps tries in one call, so that
// backtracking over a hostile index ends.
const maxResolveSteps = 1 << 20

// ResolveDeps resolves what installing seeds would add. It returns the
// packages to download, dependencies before dependents (Pre-Depends and
// Depends alike, in the order they are written), and the names that neither a
// package nor a Provides of the index covers.
//
// A seed is a dependency in control-file syntax: "foo", "foo:arm64",
// "foo (>= 1.2)", "a | b"; one seed string may hold several, comma
// separated. A malformed one fails with an error wrapping
// [deb.ErrInvalidControlFormat]. A seed also asks for the newest version, as
// apt-get install does: an installed package with a newer version in the index
// is listed again, to be upgraded. A seed qualified with an architecture that
// has no such package falls back to the host architecture, then to any.
//
// The resolution follows apt, over every version the indexes carry:
//
//   - A dependency is met by an installed or already selected package first,
//     in the order of its alternatives; only then is a package chosen, the
//     first alternative that can be installed, and of it the highest version
//     that satisfies the constraint ("<<", "<=", "=", ">=", ">>"). Versions
//     older than the installed one are not offered, and an installed package
//     is upgraded only when a dependency needs it.
//   - A virtual package is met by a package that Provides it. A versioned
//     dependency is met only by a versioned Provides ("foo (= 1.2)"), never
//     by a bare one (Debian Policy 7.5). Among providers the higher Priority
//     wins, then the one read last from the indexes, as apt does.
//   - A package that Conflicts with or Breaks an installed or selected one, or
//     the other way round, is refused and the next candidate is tried; when
//     none is left the error is a [*ConflictError] inside an
//     [*UnsatisfiedError]. Unlike apt, installed packages are never removed.
//   - Multi-Arch: a dependency of an architecture A package is met by an A or
//     all package, or by a Multi-Arch: foreign package of any architecture
//     (the host's is preferred); "name:any" only by Multi-Arch: allowed;
//     "name:native" by the host architecture; "name:arch" by that one.
//     Dependencies are read for the architecture of the package that declares
//     them.
//
// Differences from apt-get install --no-install-recommends, on purpose (use
// [Cache.Plan] for the behaviour of apt itself):
//
//   - apt looks only at the candidate (the highest version), so a constraint
//     it fails ("foo (<< 3)" with 3 available) is unsatisfiable to it; here
//     the highest version that does satisfy it is taken.
//   - apt resolves a clash with an installed package by removing it, and a
//     Breaks by upgrading or removing the broken one. Here the candidate is
//     refused and the next one tried, and the clash is an error when none is
//     left; nothing is ever removed or upgraded to make room, which is what
//     an extractor that must leave the host's packages alone needs.
//   - Pin priorities and apt's pkgProblemResolver scoring are not modelled,
//     nor is the ordering of configuration (Pre-Depends loops).
//
// A dependency that no candidate satisfies fails with an
// [*UnsatisfiedError] ([ErrUnsatisfiable]); an installed package a new version
// would break counts as one too. A name the index does not know at all is not
// an error: it is listed in the second result. The result is deterministic.
// A chain deeper than a few thousand packages fails with ErrDependencyDepth,
// and a hostile index that makes backtracking explode with ErrResolveLimit.
func (c *Cache) ResolveDeps(seeds []string) ([]*PackageInfo, []string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var goals []goal

	for _, seed := range seeds {
		seed = strings.TrimSpace(seed)
		if seed == "" {
			continue
		}

		groups, err := deb.ParseRelations(seed)
		if err != nil {
			return nil, nil, fmt.Errorf("apt: seed %q: %w", seed, err)
		}

		for _, alts := range groups {
			goals = append(goals, goal{group: alts, seed: true})
		}
	}

	r := newResolution(c)

	var list *node

	for i := len(goals) - 1; i >= 0; i-- {
		list = &node{g: goals[i], next: list}
	}

	if err := r.solve(list); err != nil {
		return nil, nil, err
	}

	out := make([]*PackageInfo, len(r.order))
	for i, p := range r.order {
		out[i] = &p.PackageInfo
	}

	return out, r.unresolved, nil
}

// goal is one step of a resolution: a dependency group to satisfy, or the
// marker that lists a package once all its dependencies are in.
type goal struct {
	// group is the dependency to satisfy; nil for an emit marker.
	group deb.Alternatives
	// owner is the package whose dependency it is; nil for a seed.
	owner *pkg
	// depth is the length of the dependency chain that led here.
	depth int
	// seed marks a name the caller asked for.
	seed bool
	// emit, when set, is the package to list.
	emit *pkg
}

// arch is the architecture the group is read for: that of the owner, the
// host's for a seed or an all package.
func (g *goal) arch(native string) string {
	if g.owner == nil || g.owner.Architecture == "" || g.owner.Architecture == archAll {
		return native
	}

	return g.owner.Architecture
}

// node is a persistent stack of goals: pushing shares the tail, so
// backtracking never copies.
type node struct {
	g    goal
	next *node
}

type undoKind uint8

const (
	undoSelect undoKind = iota
	undoEmit
	undoUnresolved
)

type undoRec struct {
	kind undoKind
	p    *pkg
}

// resolution is the state of one ResolveDeps call: a depth-first search with
// backtracking over the candidates of every dependency.
type resolution struct {
	c      *Cache
	native string
	steps  int

	// sel maps a slot to the version selected for it; selOrder lists the slots
	// in selection order.
	sel      map[string]*pkg
	selOrder []string
	emitted  map[*pkg]bool
	order    []*pkg
	// unresolved are the names nothing in the index covers.
	unresolved []string
	// neg indexes the selected packages by what they Conflict with or Break;
	// instNeg does the same for the installed ones.
	neg     map[string][]*pkg
	instNeg map[string][]*pkg
	// instKeys are the installed slots, sorted.
	instKeys []string
	undo     []undoRec
}

func newResolution(c *Cache) *resolution {
	r := &resolution{
		c:       c,
		native:  c.hostArch,
		sel:     make(map[string]*pkg),
		emitted: make(map[*pkg]bool),
		neg:     make(map[string][]*pkg),
		instNeg: make(map[string][]*pkg),
	}

	for key, p := range c.installed {
		r.instKeys = append(r.instKeys, key)

		for _, name := range negNames(p) {
			r.instNeg[name] = append(r.instNeg[name], p)
		}
	}

	slices.Sort(r.instKeys)

	// installed packages were appended in map order
	for _, owners := range r.instNeg {
		slices.SortFunc(owners, func(a, b *pkg) int { return strings.Compare(a.slot, b.slot) })
	}

	return r
}

// negNames lists, without duplicates, the names a package Conflicts with or
// Breaks.
func negNames(p *pkg) []string {
	var names []string

	for _, rels := range [][]deb.Relation{p.Conflicts, p.Breaks} {
		for i := range rels {
			if !slices.Contains(names, rels[i].Name) {
				names = append(names, rels[i].Name)
			}
		}
	}

	return names
}

// eff is the version that holds a slot at this point of the search: the one
// selected, else the installed one.
func (r *resolution) eff(key string) *pkg {
	if p, ok := r.sel[key]; ok {
		return p
	}

	return r.c.installed[key]
}

// rollback undoes the search state back to a mark of the undo log.
func (r *resolution) rollback(mark int) {
	for len(r.undo) > mark {
		rec := r.undo[len(r.undo)-1]
		r.undo = r.undo[:len(r.undo)-1]

		switch rec.kind {
		case undoSelect:
			delete(r.sel, rec.p.slot)
			r.selOrder = r.selOrder[:len(r.selOrder)-1]

			for _, name := range negNames(rec.p) {
				r.neg[name] = r.neg[name][:len(r.neg[name])-1]
			}
		case undoEmit:
			delete(r.emitted, rec.p)
			r.order = r.order[:len(r.order)-1]
		case undoUnresolved:
			r.unresolved = r.unresolved[:len(r.unresolved)-1]
		}
	}
}

// label names a version for an error message.
func label(p *pkg) string {
	arch := p.Architecture
	if arch == "" {
		arch = archAll
	}

	return p.Name + ":" + arch + " " + p.Version
}

// solve works through the goals. Choices recurse; everything else loops.
func (r *resolution) solve(list *node) error {
	for list != nil {
		g := &list.g

		switch {
		case g.emit != nil:
			r.emitted[g.emit] = true
			r.order = append(r.order, g.emit)
			r.undo = append(r.undo, undoRec{kind: undoEmit, p: g.emit})
		case r.groupSatisfied(g.group, g.arch(r.native), g.seed):
		default:
			done, err := r.choose(g, list.next)
			if err != nil || done {
				return err
			}
		}

		list = list.next
	}

	return nil
}

// groupSatisfied reports whether an installed or selected package meets one of
// the alternatives.
func (r *resolution) groupSatisfied(group deb.Alternatives, arch string, seed bool) bool {
	for i := range group {
		if r.satisfied(&group[i], arch, true, seed) {
			return true
		}
	}

	return false
}

// choose installs a candidate for a group that nothing installed or selected
// meets, and solves the rest of the goals with it; the next candidate is tried
// when that fails. It reports done when the whole rest is solved, and neither
// done nor an error when the group was skipped because nothing in the index
// names it.
func (r *resolution) choose(g *goal, rest *node) (bool, error) {
	if g.depth > maxResolveDepth {
		return false, ErrDependencyDepth
	}

	arch := g.arch(r.native)

	var (
		causes []error
		known  bool
	)

	for i := range g.group {
		rel := &g.group[i]
		known = known || r.c.known(rel.Name)

		for _, cand := range r.candidates(rel, arch, g.seed) {
			r.steps++
			if r.steps > maxResolveSteps {
				return false, ErrResolveLimit
			}

			mark := len(r.undo)

			list, err := r.install(cand, g, rest)
			if err == nil {
				err = r.solve(list)
				if err == nil {
					return true, nil
				}
			}

			if errors.Is(err, ErrDependencyDepth) || errors.Is(err, ErrResolveLimit) {
				return false, err
			}

			causes = append(causes, err)

			r.rollback(mark)
		}
	}

	if len(causes) == 0 {
		// A seed for a foreign architecture that is installed already.
		if g.seed && r.groupSatisfiedAnyArch(g.group) {
			return false, nil
		}

		if !known {
			r.noteUnresolved(g.group[0].Name)

			return false, nil
		}
	}

	unmet := &UnsatisfiedError{Dependency: g.group.String(), Causes: causes}

	if g.owner != nil {
		unmet.Package = label(g.owner)
	}

	if len(causes) == 0 {
		unmet.Reason = r.whyNone(g.group)
	}

	return false, unmet
}

// groupSatisfiedAnyArch is groupSatisfied without the architecture rules.
func (r *resolution) groupSatisfiedAnyArch(group deb.Alternatives) bool {
	for i := range group {
		if r.satisfied(&group[i], r.native, false, false) {
			return true
		}
	}

	return false
}

// noteUnresolved records a name nothing in the index covers, once.
func (r *resolution) noteUnresolved(name string) {
	if slices.Contains(r.unresolved, name) {
		return
	}

	r.unresolved = append(r.unresolved, name)
	r.undo = append(r.undo, undoRec{kind: undoUnresolved})
}

// whyNone says why a known name has no candidate: which versions exist and why
// they do not do.
func (r *resolution) whyNone(group deb.Alternatives) string {
	var parts []string

	for i := range group {
		rel := &group[i]

		var have []string

		r.c.eachSlot(rel.Name, func(key string) bool {
			for _, p := range r.c.slots[key] {
				state := ""
				if r.eff(key) == p {
					state = " installed"
				}

				have = append(have, label(p)+state)
			}

			return true
		})

		for _, p := range r.c.providers[rel.Name] {
			have = append(have, "provided by "+label(p))
		}

		if len(have) == 0 {
			have = []string{"no such package"}
		}

		parts = append(parts, rel.String()+": "+strings.Join(have, ", "))
	}

	return "no candidate (" + strings.Join(parts, "; ") + ")"
}

// install selects a version: it must not clash with what is installed or
// selected, and must not break what depends on the version it replaces. It
// returns the goals to run next, the version's dependencies and its emit
// marker in front of rest. The caller rolls the state back on an error.
func (r *resolution) install(p *pkg, g *goal, rest *node) (*node, error) {
	old := r.c.installed[p.slot]

	r.sel[p.slot] = p
	r.selOrder = append(r.selOrder, p.slot)

	for _, name := range negNames(p) {
		r.neg[name] = append(r.neg[name], p)
	}

	r.undo = append(r.undo, undoRec{kind: undoSelect, p: p})

	if err := r.checkConflicts(p); err != nil {
		return nil, err
	}

	if old != nil {
		if err := r.checkDependents(old, p); err != nil {
			return nil, err
		}
	}

	list := &node{g: goal{emit: p}, next: rest}
	groups := slices.Concat(p.PreDepends, p.Depends)

	for i := len(groups) - 1; i >= 0; i-- {
		list = &node{g: goal{group: groups[i], owner: p, depth: g.depth + 1}, next: list}
	}

	return list, nil
}

// checkDependents refuses a version that replaces old when it leaves a
// dependency unmet that old met: of an installed package, or of a selected one
// whose dependencies are all settled.
func (r *resolution) checkDependents(old, p *pkg) error {
	affected := append([]string{old.Name}, providedNames(old)...)

	check := func(q *pkg) error {
		if q.slot == p.slot {
			return nil
		}

		qArch := (&goal{owner: q}).arch(r.native)

		for _, groups := range [][]deb.Alternatives{q.PreDepends, q.Depends} {
			for _, group := range groups {
				if !slices.ContainsFunc(group, func(rel deb.Relation) bool { return slices.Contains(affected, rel.Name) }) {
					continue
				}

				if !r.metBy(group, qArch, old) || r.groupSatisfied(group, qArch, false) {
					continue
				}

				return &UnsatisfiedError{
					Package: label(q), Dependency: group.String(),
					Reason: fmt.Sprintf("%s would replace %s", label(p), label(old)),
				}
			}
		}

		return nil
	}

	for _, key := range r.instKeys {
		if _, selected := r.sel[key]; selected {
			continue
		}

		if err := check(r.c.installed[key]); err != nil {
			return err
		}
	}

	for _, key := range r.selOrder {
		if q := r.sel[key]; r.emitted[q] {
			if err := check(q); err != nil {
				return err
			}
		}
	}

	return nil
}

// metBy reports whether the version meets one alternative of the group.
func (r *resolution) metBy(group deb.Alternatives, arch string, p *pkg) bool {
	for i := range group {
		rel := &group[i]

		if (r.realMatch(rel, p) || providesMatch(rel, p)) && r.archOK(rel, arch, p) {
			return true
		}
	}

	return false
}

// providedNames lists the virtual names a version provides.
func providedNames(p *pkg) []string {
	names := make([]string, len(p.Provides))
	for i := range p.Provides {
		names[i] = p.Provides[i].Name
	}

	return names
}

// realMatch reports whether the version is the package the relation names, at
// a version that meets its constraint.
func (r *resolution) realMatch(rel *deb.Relation, p *pkg) bool {
	return p.Name == rel.Name && rel.Satisfied(p.Version)
}

// providesMatch reports whether the version Provides what the relation names:
// a versioned relation only by a versioned Provides that meets it.
func providesMatch(rel *deb.Relation, p *pkg) bool {
	for i := range p.Provides {
		prov := &p.Provides[i]

		if prov.Name != rel.Name {
			continue
		}

		if rel.Op == "" || (prov.Op == "=" && rel.Satisfied(prov.Version)) {
			return true
		}
	}

	return false
}

// archOK applies the Multi-Arch rules of a dependency written for arch to a
// version of another or the same architecture.
func (r *resolution) archOK(rel *deb.Relation, arch string, p *pkg) bool {
	return relArchOK(r.native, rel, arch, p)
}

// relArchOK is archOK for a host architecture native.
func relArchOK(native string, rel *deb.Relation, arch string, p *pkg) bool {
	pa := p.Architecture
	if pa == "" || pa == archAll {
		return true
	}

	switch rel.Arch {
	case "":
		return pa == arch || strings.EqualFold(p.MultiArch, "foreign")
	case "any":
		return strings.EqualFold(p.MultiArch, "allowed")
	case "native":
		return pa == native
	default:
		return pa == rel.Arch
	}
}

// satisfied reports whether an installed or selected package meets a relation.
// With seed, an installed package for which the index has a newer version that
// meets it does not count: it is to be upgraded.
func (r *resolution) satisfied(rel *deb.Relation, arch string, checkArch, seed bool) bool {
	found := false

	r.c.eachSlot(rel.Name, func(key string) bool {
		e := r.eff(key)
		if e == nil || !r.realMatch(rel, e) || (checkArch && !r.archOK(rel, arch, e)) || (seed && r.upgradable(e, rel)) {
			return true
		}

		found = true

		return false
	})

	if found {
		return true
	}

	for _, p := range r.c.providers[rel.Name] {
		if r.eff(p.slot) == p && providesMatch(rel, p) && (!checkArch || r.archOK(rel, arch, p)) {
			return true
		}
	}

	return false
}

// upgradable reports whether an installed version has a newer one in the
// index that meets the relation.
func (r *resolution) upgradable(e *pkg, rel *deb.Relation) bool {
	if _, selected := r.sel[e.slot]; selected {
		return false
	}

	return slices.ContainsFunc(r.c.slots[e.slot], func(p *pkg) bool {
		return p.available() && !p.Installed && deb.CompareVersions(p.Version, e.Version) > 0 && rel.Satisfied(p.Version)
	})
}

// known reports whether the index knows the name, as a package or a virtual
// one.
func (c *Cache) known(name string) bool {
	return len(c.providers[name]) > 0 || len(c.slots[name]) > 0 || len(c.byBareName[name]) > 0
}

// eachSlot calls fn for every slot key a package name has, the bare one (all)
// first, until fn returns false.
func (c *Cache) eachSlot(name string, fn func(key string) bool) {
	if _, ok := c.slots[name]; ok && !fn(name) {
		return
	}

	for _, key := range c.byBareName[name] {
		if !fn(key) {
			return
		}
	}
}

// usable reports whether a version may be selected: it can be installed, its
// slot is free of another selection, and it is newer than what is installed.
func (r *resolution) usable(p *pkg) bool {
	if !p.available() {
		return false
	}

	if _, selected := r.sel[p.slot]; selected {
		return false
	}

	if in := r.c.installed[p.slot]; in != nil {
		return in != p && deb.CompareVersions(p.Version, in.Version) > 0
	}

	return true
}

// candidates lists, best first, the versions that can meet a relation: real
// packages, then providers of the name.
func (r *resolution) candidates(rel *deb.Relation, arch string, seed bool) []*pkg {
	var real, virtual []*pkg

	r.c.eachSlot(rel.Name, func(key string) bool {
		for _, p := range r.c.slots[key] {
			if r.usable(p) && rel.Satisfied(p.Version) && (seed || r.archOK(rel, arch, p)) {
				real = append(real, p)
			}
		}

		return true
	})

	for _, p := range r.c.providers[rel.Name] {
		if p.Name != rel.Name && r.usable(p) && providesMatch(rel, p) && (seed || r.archOK(rel, arch, p)) {
			virtual = append(virtual, p)
		}
	}

	slices.SortStableFunc(real, func(a, b *pkg) int { return r.compareReal(rel, arch, seed, a, b) })
	slices.SortStableFunc(virtual, func(a, b *pkg) int {
		if d := r.archRank(rel, arch, seed, a) - r.archRank(rel, arch, seed, b); d != 0 {
			return d
		}

		// apt reads the Provides of the candidate version of a package only;
		// those of its older versions come last.
		if d := r.c.notCandidate(a) - r.c.notCandidate(b); d != 0 {
			return d
		}

		return providerOrder(a, b)
	})

	return append(real, virtual...)
}

// archRank orders the architectures a candidate may come from. A Multi-Arch:
// foreign package is taken from the host architecture first, as apt does, a
// ":any" one too; a name given to ResolveDeps prefers the architecture it
// names, then all, then the host's, then the others.
func (r *resolution) archRank(rel *deb.Relation, arch string, seed bool, p *pkg) int {
	pa := p.Architecture
	if pa == "" {
		pa = archAll
	}

	switch {
	case seed:
		want := r.native
		if rel.Arch != "" && rel.Arch != "any" && rel.Arch != "native" {
			want = rel.Arch
		}

		switch pa {
		case want:
			return 0
		case archAll:
			return 1
		case r.native:
			return 2
		default:
			return 3
		}
	case pa == archAll:
		return 0
	case rel.Arch == "any":
		switch pa {
		case r.native:
			return 0
		case arch:
			return 1
		default:
			return 2
		}
	case rel.Arch == "" && pa != arch && strings.EqualFold(p.MultiArch, "foreign"):
		if pa == r.native {
			return 0
		}

		return 2
	default:
		return 1
	}
}

// compareReal orders versions of real packages: by architecture rank, then
// architecture name, the higher version first.
func (r *resolution) compareReal(rel *deb.Relation, arch string, seed bool, a, b *pkg) int {
	if d := r.archRank(rel, arch, seed, a) - r.archRank(rel, arch, seed, b); d != 0 {
		return d
	}

	if d := strings.Compare(a.Architecture, b.Architecture); d != 0 {
		return d
	}

	// Two versions of one architecture differ, so this orders them totally.
	return deb.CompareVersions(b.Version, a.Version)
}

// eachEffective calls fn for every installed or selected version that is the
// named package or provides it, until fn returns false.
func (r *resolution) eachEffective(name string, fn func(e *pkg) bool) {
	stop := false

	r.c.eachSlot(name, func(key string) bool {
		if e := r.eff(key); e != nil && !fn(e) {
			stop = true
		}

		return !stop
	})

	if stop {
		return
	}

	for _, p := range r.c.providers[name] {
		if r.eff(p.slot) == p && !fn(p) {
			return
		}
	}
}

// negMatches reports whether a Conflicts or Breaks relation hits a version:
// the package it names at a version in range, or a package that provides it
// (a versioned relation only through a versioned Provides). A qualified
// relation hits only that architecture.
func (r *resolution) negMatches(rel *deb.Relation, p *pkg) bool {
	return relNegMatches(r.native, rel, p)
}

// relNegMatches is negMatches for a host architecture native.
func relNegMatches(native string, rel *deb.Relation, p *pkg) bool {
	if rel.Arch != "" && rel.Arch != "any" {
		want := rel.Arch
		if want == "native" {
			want = native
		}

		if pa := p.Architecture; pa != want && pa != archAll && pa != "" {
			return false
		}
	}

	return (p.Name == rel.Name && rel.Satisfied(p.Version)) || providesMatch(rel, p)
}

// checkConflicts refuses a selected version that Conflicts with or Breaks an
// installed or selected package, or that one of them Conflicts with or Breaks.
func (r *resolution) checkConflicts(p *pkg) error {
	for _, set := range []struct {
		kind string
		rels []deb.Relation
	}{{"Conflicts", p.Conflicts}, {"Breaks", p.Breaks}} {
		for i := range set.rels {
			rel := &set.rels[i]

			var hit *pkg

			r.eachEffective(rel.Name, func(e *pkg) bool {
				if e.Name == p.Name || !r.negMatches(rel, e) {
					return true
				}

				hit = e

				return false
			})

			if hit != nil {
				return &ConflictError{
					Package: label(p), With: label(hit), WithInstalled: r.sel[hit.slot] != hit,
					Kind: set.kind, Relation: rel.String(),
				}
			}
		}
	}

	for _, name := range append([]string{p.Name}, providedNames(p)...) {
		for _, owners := range [][]*pkg{r.neg[name], r.instNeg[name]} {
			for _, o := range owners {
				if o.Name == p.Name || r.eff(o.slot) != o {
					continue
				}

				if err := r.reverseConflict(o, p, name); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// reverseConflict reports the relation of owner o on name that hits p.
func (r *resolution) reverseConflict(o, p *pkg, name string) error {
	for _, set := range []struct {
		kind string
		rels []deb.Relation
	}{{"Conflicts", o.Conflicts}, {"Breaks", o.Breaks}} {
		for i := range set.rels {
			rel := &set.rels[i]
			if rel.Name != name || !r.negMatches(rel, p) {
				continue
			}

			return &ConflictError{
				Package: label(p), With: label(o), WithInstalled: r.sel[o.slot] != o,
				Kind: set.kind, Relation: rel.String(), Reverse: true,
			}
		}
	}

	return nil
}
