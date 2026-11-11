package apk

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Errors of [Index.Solve].
var (
	// ErrUnsatisfiable is wrapped by the error of a request that no set of
	// packages meets; the error is a [*SolveError].
	ErrUnsatisfiable = errors.New("apk: unable to select packages")
	// ErrSolveLimit is returned when the search for a solution exceeds its
	// step budget (a hostile index can make the search exponential).
	ErrSolveLimit = errors.New("apk: dependency search limit reached")
)

// maxSolveSteps bounds the packages the search tries in one Solve call.
const maxSolveSteps = 1 << 20

// SolveProblem is one dependency that could not be met.
type SolveProblem struct {
	// Name is the package or capability that could not be selected.
	Name string
	// Reason says why: no package provides it, no candidate meets the
	// constraints, or the candidates conflict with the rest of the selection.
	Reason string
	// RequiredBy are the requesters: "world[name]" or "package-version[dep]".
	RequiredBy []string
}

// SolveError is the error of an unsatisfiable request. It wraps
// [ErrUnsatisfiable].
type SolveError struct {
	Problems []SolveProblem
}

// Error renders the problems the way apk prints them.
func (e *SolveError) Error() string {
	var b strings.Builder

	b.WriteString(ErrUnsatisfiable.Error())

	for _, p := range e.Problems {
		fmt.Fprintf(&b, "\n  %s (%s)", p.Name, p.Reason)

		for _, r := range p.RequiredBy {
			fmt.Fprintf(&b, "\n    required by: %s", r)
		}
	}

	return b.String()
}

// Unwrap returns [ErrUnsatisfiable].
func (e *SolveError) Unwrap() error { return ErrUnsatisfiable }

// SolveRequest is what [Index.Solve] resolves.
type SolveRequest struct {
	// World is the set of dependencies the system must meet, the entries of
	// /etc/apk/world: "name", "name=1.2", "name>=1.2", "name@tag",
	// "name@tag>=1.2" and "!name". Dependencies of the packages are
	// followed; everything installed that the world does not lead to is
	// removed.
	World []string
	// Installed are the packages installed now. A package that stays is
	// preferred to a different version of it, unless Upgrade is set.
	Installed []Package
	// Upgrade selects the latest version of everything (apk upgrade) instead
	// of keeping what is installed.
	Upgrade bool
}

// ChangeKind is what a [Change] does to a package.
type ChangeKind uint8

// The kinds of change.
const (
	// ChangeInstall installs a package that is not installed.
	ChangeInstall ChangeKind = iota + 1
	// ChangeRemove removes an installed package (apk's "Purging").
	ChangeRemove
	// ChangeUpgrade replaces an installed package by a higher version.
	ChangeUpgrade
	// ChangeDowngrade replaces an installed package by a lower version.
	ChangeDowngrade
	// ChangeReinstall replaces an installed package by the same version (a
	// different build of it).
	ChangeReinstall
)

// String returns "install", "remove", "upgrade", "downgrade" or "reinstall".
func (k ChangeKind) String() string {
	switch k {
	case ChangeInstall:
		return "install"
	case ChangeRemove:
		return "remove"
	case ChangeUpgrade:
		return "upgrade"
	case ChangeDowngrade:
		return "downgrade"
	case ChangeReinstall:
		return "reinstall"
	default:
		return "unknown"
	}
}

// Change is one step to get from the installed packages to the solution.
type Change struct {
	// Old is the installed package that is removed or replaced; nil for an
	// install.
	Old *Package
	// New is the package to install; nil for a removal.
	New *RepoPackage
}

// Kind returns what the change does.
func (c Change) Kind() ChangeKind {
	switch {
	case c.Old == nil:
		return ChangeInstall
	case c.New == nil:
		return ChangeRemove
	}

	switch CompareVersions(c.New.Version, c.Old.Version) {
	case 1:
		return ChangeUpgrade
	case -1:
		return ChangeDowngrade
	default:
		return ChangeReinstall
	}
}

// Solution is the result of [Index.Solve].
type Solution struct {
	// Packages are all the packages of the resulting system that the index
	// lists or that are installed, dependencies before the packages that need
	// them. A package that is installed and stays is in it too.
	Packages []*RepoPackage
	// Changes are the removals, then the installs and replacements in the
	// order of Packages.
	Changes []Change
}

// Solve finds the set of packages that meets the request and returns the
// changes that lead to it from the installed packages. It follows the
// semantics of apk's solver: versioned constraints with every operator,
// conflicts ("!name"), versioned and unversioned provides, provider_priority
// to choose among providers (an unversioned virtual without priority is not
// chosen on its own), install_if triggers, repository tags ("name@tag") and
// the preference for the installed version, the highest version and the
// earlier repository. Unlike a greedy walk it backtracks when a choice leads
// to a conflict, within a step budget ([ErrSolveLimit]).
//
// The error of a request that cannot be met is a [*SolveError].
func (idx *Index) Solve(req SolveRequest) (*Solution, error) {
	s, err := newSolver(idx, req)
	if err != nil {
		return nil, err
	}

	if !s.run() {
		if s.limited {
			return nil, ErrSolveLimit
		}

		return nil, s.failure()
	}

	return s.solution(), nil
}

// cand is a package under consideration.
type cand struct {
	pkg       *RepoPackage
	seq       int // position in the order the solver lists providers
	installed bool
	// installedPkg is the installed record this is, when installed.
	installedPkg *Package
	repoMask     uint64 // bit 0: an untagged repository, bit n: the tag numbered n
	allowed      uint64 // the repository masks the requesters allow
	preferred    bool   // from a repository the world dependency prefers
	disq         bool
	selected     bool
	names        []provided // own name first, then the provides
}

// tagOK reports whether the package may be chosen: it is installed or comes
// from a repository some requester allows.
func (c *cand) tagOK() bool { return c.installed || c.allowed&c.repoMask != 0 }

// provider is a package as a provider of one name.
type provider struct {
	c       *cand
	version string // the version it provides the name at; "" for none
}

// constraint is a requirement on a name and who made it.
type constraint struct {
	dep   Dependency
	owner *cand // nil for a world dependency
}

type nameState struct {
	name      string
	providers []provider
	pos, neg  []constraint
	locked    bool
	chosen    provider
	order     bool // already in the list of required names
}

type frame struct {
	ns     *nameState
	cands  []provider
	idx    int
	mark   int // length of the trail when the decision was made
	cursor int
}

type solver struct {
	idx   *Index
	req   SolveRequest
	cands map[*RepoPackage]*cand
	extra map[string][]provider // installed packages the index does not list, by name
	// orphans are the installed packages the index does not list.
	orphans []*RepoPackage
	names map[string]*nameState

	reqOrder []*nameState
	cursor   int
	selOrder []*cand
	stack    []frame
	trail    []func()

	steps   int
	limited bool
	problem *SolveProblem
}

func newSolver(idx *Index, req SolveRequest) (*solver, error) {
	s := &solver{
		idx:   idx,
		req:   req,
		cands: make(map[*RepoPackage]*cand),
		extra: make(map[string][]provider),
		names: make(map[string]*nameState),
	}

	// Installed packages first: a package the index lists is that package,
	// the others are candidates of their own.
	for i := range req.Installed {
		ip := &req.Installed[i]
		var match *RepoPackage

		for _, rp := range idx.byName[ip.Name] {
			if rp.Version == ip.Version && (ip.Checksum == "" || ip.Checksum == rp.Checksum) {
				match = rp

				break
			}
		}

		if match != nil {
			c := s.cand(match)
			c.installed, c.installedPkg = true, ip

			continue
		}

		rp := &RepoPackage{Package: *ip, repoOrder: -1}
		rp.parseRelations()

		c := s.cand(rp)
		c.installed, c.installedPkg = true, ip
		c.seq = -len(req.Installed) + i
		c.repoMask = 0

		s.orphans = append(s.orphans, rp)

		for _, pr := range c.names {
			s.extra[pr.name] = append(s.extra[pr.name], provider{c: c, version: pr.version})
		}
	}

	return s, nil
}

// cand returns the candidate for rp, creating it.
func (s *solver) cand(rp *RepoPackage) *cand {
	if c, ok := s.cands[rp]; ok {
		return c
	}

	c := &cand{pkg: rp, seq: rp.seq, allowed: 1}
	c.names = append(c.names, provided{name: rp.Name, version: rp.Version})

	for _, pr := range rp.provides {
		if pr.name != rp.Name {
			c.names = append(c.names, pr)
		}
	}

	switch {
	case rp.Repo.Tag == "":
		c.repoMask = 1
	case s.idx.tags[rp.Repo.Tag] > 0 && s.idx.tags[rp.Repo.Tag] <= maxTags:
		c.repoMask = 1 << uint(s.idx.tags[rp.Repo.Tag])
	}

	c.preferred = c.repoMask&1 != 0
	s.cands[rp] = c

	return c
}

// name returns the state of a name, listing its providers on first use.
func (s *solver) name(n string) *nameState {
	if ns, ok := s.names[n]; ok {
		return ns
	}

	ns := &nameState{name: n}
	s.names[n] = ns

	ns.providers = append(ns.providers, s.extra[n]...)

	for _, rp := range s.idx.byName[n] {
		ns.providers = append(ns.providers, provider{c: s.cand(rp), version: rp.Version})
	}

	for _, rp := range s.idx.providers[n] {
		for _, pr := range rp.provides {
			if pr.name == n {
				ns.providers = append(ns.providers, provider{c: s.cand(rp), version: pr.version})

				break
			}
		}
	}

	slices.SortStableFunc(ns.providers, func(a, b provider) int { return a.c.seq - b.c.seq })

	return ns
}

// do runs f and records how to undo it.
func (s *solver) do(f, undo func()) {
	f()

	s.trail = append(s.trail, undo)
}

func (s *solver) undoTo(mark int) {
	for len(s.trail) > mark {
		last := len(s.trail) - 1
		s.trail[last]()
		s.trail = s.trail[:last]
	}
}

// fail records the problem that stopped the search, for the error message.
func (s *solver) fail(name, reason string, by []string) {
	s.problem = &SolveProblem{Name: name, Reason: reason, RequiredBy: by}
}

func (s *solver) failure() error {
	if s.problem == nil {
		return &SolveError{Problems: []SolveProblem{{Name: "world", Reason: "unsatisfiable"}}}
	}

	return &SolveError{Problems: []SolveProblem{*s.problem}}
}

// ownerName renders the owner of a constraint for an error.
func ownerName(c constraint) string {
	if c.owner == nil {
		return "world[" + c.dep.String() + "]"
	}

	return c.owner.pkg.Name + "-" + c.owner.pkg.Version + "[" + c.dep.String() + "]"
}

// matches reports whether provider p meets dependency d (before the conflict
// flag).
func matches(d Dependency, p provider) bool {
	if d.Op == OpChecksum {
		return p.c.pkg.Checksum == d.Version
	}

	return d.MatchVersion(p.version)
}

// mark records a new constraint on a name and queues it when positive.
func (s *solver) addConstraint(ns *nameState, c constraint) {
	if c.dep.Conflict {
		s.do(func() { ns.neg = append(ns.neg, c) }, func() { ns.neg = ns.neg[:len(ns.neg)-1] })

		return
	}

	s.do(func() { ns.pos = append(ns.pos, c) }, func() { ns.pos = ns.pos[:len(ns.pos)-1] })

	if !ns.order {
		s.do(func() {
			ns.order = true
			s.reqOrder = append(s.reqOrder, ns)
		}, func() {
			ns.order = false
			s.reqOrder = s.reqOrder[:len(s.reqOrder)-1]
		})
	}
}

// disqualify rules a package out; it fails when the package is already part
// of the selection.
func (s *solver) disqualify(c *cand) bool {
	if c.selected {
		return false
	}

	if !c.disq {
		s.do(func() { c.disq = true }, func() { c.disq = false })
	}

	return true
}

// inherit lets the repositories of mask supply c.
func (s *solver) inherit(c *cand, mask uint64) {
	if c.allowed|mask == c.allowed {
		return
	}

	old := c.allowed

	s.do(func() { c.allowed |= mask }, func() { c.allowed = old })
}

// apply imposes dependency d, required by owner (nil for the world), on the
// selection. It reports false when it cannot hold.
func (s *solver) apply(owner *cand, d Dependency) bool {
	ns := s.name(d.Name)
	con := constraint{dep: d, owner: owner}

	if d.Conflict {
		for _, p := range ns.providers {
			if p.c == owner || !matches(d, p) {
				continue
			}

			if !s.disqualify(p.c) {
				s.fail(d.Name, "conflicts with "+p.c.pkg.Name+"-"+p.c.pkg.Version, []string{ownerName(con)})

				return false
			}
		}

		s.addConstraint(ns, con)

		return true
	}

	if ns.locked && !matches(d, ns.chosen) {
		s.fail(d.Name, "conflicting versions", []string{ownerName(con)})

		return false
	}

	s.addConstraint(ns, con)

	for _, p := range ns.providers {
		if !matches(d, p) {
			continue
		}

		if owner == nil {
			s.worldPin(p.c, d)
		} else {
			s.inherit(p.c, owner.allowed)
		}
	}

	return true
}

// worldPin applies the repository pinning of a world dependency to a provider
// that meets it: the dependency's tag (or the untagged repositories) is
// allowed and preferred.
func (s *solver) worldPin(c *cand, d Dependency) {
	mask := uint64(1)

	if d.Tag != "" {
		if n, ok := s.idx.tags[d.Tag]; ok && n <= maxTags {
			mask = 1 << uint(n)
		} else {
			mask = 0
		}
	}

	s.inherit(c, mask)

	pref := c.repoMask&mask != 0
	if c.preferred == pref {
		return
	}

	old := c.preferred

	s.do(func() { c.preferred = pref }, func() { c.preferred = old })
}

// choose selects c: it takes every name c provides and imposes its
// dependencies.
func (s *solver) choose(c *cand) bool {
	s.steps++
	if s.steps > maxSolveSteps {
		s.limited = true

		return false
	}

	s.do(func() { c.selected = true; s.selOrder = append(s.selOrder, c) },
		func() { c.selected = false; s.selOrder = s.selOrder[:len(s.selOrder)-1] })

	for _, pr := range c.names {
		if !s.take(c, pr) {
			return false
		}
	}

	for _, d := range c.pkg.deps {
		if !s.apply(c, d) {
			return false
		}
	}

	return true
}

// take makes c the provider of the name pr.
func (s *solver) take(c *cand, pr provided) bool {
	ns := s.name(pr.name)
	me := provider{c: c, version: pr.version}

	if ns.locked {
		if ns.chosen.c == c || pr.version == "" && ns.chosen.version == "" {
			return true
		}

		s.fail(pr.name, "conflict: "+c.pkg.Name+"-"+c.pkg.Version+" and "+
			ns.chosen.c.pkg.Name+"-"+ns.chosen.c.pkg.Version+" provide it", nil)

		return false
	}

	for _, k := range ns.pos {
		if !matches(k.dep, me) {
			s.fail(pr.name, "unsatisfiable constraints", []string{ownerName(k)})

			return false
		}
	}

	for _, k := range ns.neg {
		if k.owner != c && matches(k.dep, me) {
			s.fail(pr.name, "conflicts", []string{ownerName(k)})

			return false
		}
	}

	s.do(func() { ns.locked, ns.chosen = true, me }, func() { ns.locked, ns.chosen = false, provider{} })

	for _, p0 := range ns.providers {
		if p0.c == c || pr.version == "" && p0.version == "" {
			continue
		}

		if !s.disqualify(p0.c) {
			s.fail(pr.name, "conflict: "+c.pkg.Name+"-"+c.pkg.Version+" and "+
				p0.c.pkg.Name+"-"+p0.c.pkg.Version+" provide it", nil)

			return false
		}
	}

	return true
}

// required reports whether some package or the world needs the name.
func (s *solver) required(n string) bool {
	ns, ok := s.names[n]

	return ok && len(ns.pos) > 0
}

// candidates lists the providers of a name that can be chosen, best first.
func (s *solver) candidates(ns *nameState) []provider {
	var out []provider

next:
	for _, p := range ns.providers {
		c := p.c

		if c.disq || !c.tagOK() {
			continue
		}

		for _, k := range ns.pos {
			if !matches(k.dep, p) {
				continue next
			}
		}

		for _, k := range ns.neg {
			if k.owner != c && matches(k.dep, p) {
				continue next
			}
		}

		// A virtual that declares no version and no provider priority is
		// only chosen when its package is wanted for its own name.
		if p.version == "" && c.pkg.ProviderPriority == 0 && !s.required(c.pkg.Name) {
			continue
		}

		out = append(out, p)
	}

	slices.SortStableFunc(out, func(a, b provider) int { return -s.compare(a, b) })

	return out
}

func b2i(b bool) int {
	if b {
		return 1
	}

	return 0
}

// compareVersionsOrEmpty orders versions with the empty (absent) one lowest.
func compareVersionsOrEmpty(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return -1
	case b == "":
		return 1
	}

	return CompareVersions(a, b)
}

// compare orders two providers of a name, positive when a is preferred: the
// preference order of apk's solver.
func (s *solver) compare(a, b provider) int {
	if s.req.Upgrade {
		if r := b2i(a.c.pkg.repoOrder >= 0) - b2i(b.c.pkg.repoOrder >= 0); r != 0 {
			return r
		}
	}

	if r := b2i(a.c.preferred) - b2i(b.c.preferred); r != 0 {
		return r
	}

	if !s.req.Upgrade && (a.c.pkg.Name == b.c.pkg.Name || a.version != "" || b.version != "") {
		if r := b2i(a.c.installed) - b2i(b.c.installed); r != 0 {
			return r
		}
	}

	if r := compareVersionsOrEmpty(a.version, b.version); r != 0 {
		return r
	}

	if a.c.pkg.Name == b.c.pkg.Name {
		if r := CompareVersions(a.c.pkg.Version, b.c.pkg.Version); r != 0 {
			return r
		}
	}

	if r := a.c.pkg.ProviderPriority - b.c.pkg.ProviderPriority; r != 0 {
		return r
	}

	if r := b2i(a.c.installed) - b2i(b.c.installed); r != 0 {
		return r
	}

	// The lower repository wins.
	return b.c.pkg.repoOrder - a.c.pkg.repoOrder
}

// nextRequired returns the first required name that is not assigned yet.
func (s *solver) nextRequired() *nameState {
	for s.cursor < len(s.reqOrder) {
		ns := s.reqOrder[s.cursor]
		if !ns.locked {
			return ns
		}

		s.cursor++
	}

	return nil
}

// run applies the world and decides the required names until none is left.
func (s *solver) run() bool {
	for _, w := range s.req.World {
		d, err := ParseDependency(w)
		if err != nil {
			s.fail(w, "invalid dependency", []string{"world"})

			return false
		}

		if d.Tag != "" {
			if n, ok := s.idx.tags[d.Tag]; !ok || n > maxTags {
				s.fail(d.Name, "unknown repository tag @"+d.Tag, []string{"world[" + d.String() + "]"})

				return false
			}
		}

		if !s.apply(nil, d) {
			return false
		}
	}

	for {
		ns := s.nextRequired()
		if ns == nil {
			if s.installIf() {
				continue
			}

			return true
		}

		if !s.decide(ns) {
			return false
		}
	}
}

// decide chooses a provider for ns, backtracking on a dead end.
func (s *solver) decide(ns *nameState) bool {
	cands := s.candidates(ns)

	if len(cands) == 0 {
		reason := "unsatisfiable constraints"
		if len(ns.providers) == 0 {
			reason = "no such package"
		}

		by := make([]string, 0, len(ns.pos))
		for _, k := range ns.pos {
			by = append(by, ownerName(k))
		}

		s.fail(ns.name, reason, by)

		if len(s.stack) == 0 {
			return false
		}

		return s.retreat()
	}

	s.stack = append(s.stack, frame{ns: ns, cands: cands, mark: len(s.trail), cursor: s.cursor})

	return s.advance()
}

// retreat gives up the latest decision for its next candidate.
func (s *solver) retreat() bool {
	f := &s.stack[len(s.stack)-1]
	s.undoTo(f.mark)
	s.cursor = f.cursor
	f.idx++

	return s.advance()
}

// advance tries the candidates of the latest decision, going back to earlier
// decisions as each is used up.
func (s *solver) advance() bool {
	for len(s.stack) > 0 {
		f := &s.stack[len(s.stack)-1]

		for f.idx < len(f.cands) {
			if s.choose(f.cands[f.idx].c) {
				return true
			}

			if s.limited {
				return false
			}

			s.undoTo(f.mark)
			s.cursor = f.cursor
			f.idx++
		}

		s.stack = s.stack[:len(s.stack)-1]
		if len(s.stack) == 0 {
			return false
		}

		prev := &s.stack[len(s.stack)-1]
		s.undoTo(prev.mark)
		s.cursor = prev.cursor
		prev.idx++
	}

	return false
}

// installIf selects the packages whose install_if condition the selection
// meets now and reports whether it selected any.
func (s *solver) installIf() bool {
	best := make(map[string]provider)

	var order []string

	for _, rp := range slices.Concat(s.idx.pkgs, s.orphans) {
		if len(rp.installIf) == 0 {
			continue
		}

		c := s.cand(rp)
		if c.disq || c.selected || !c.tagOK() || !s.triggered(c) || s.name(rp.Name).locked {
			continue
		}

		p := provider{c: c, version: rp.Version}

		cur, ok := best[rp.Name]
		if !ok {
			order = append(order, rp.Name)
		}

		if !ok || s.compare(p, cur) > 0 {
			best[rp.Name] = p
		}
	}

	for _, n := range order {
		mark := len(s.trail)
		cursor := s.cursor

		// A trigger that cannot be installed is ignored, not a failure.
		if s.choose(best[n].c) {
			// The decision cannot be revisited: it is not a choice but a
			// consequence of the selection.
			s.stack = append(s.stack, frame{ns: s.name(n), cands: []provider{best[n]}, idx: 0, mark: mark, cursor: cursor})

			return true
		}

		s.undoTo(mark)
		s.cursor = cursor
	}

	return false
}

// triggered reports whether every install_if condition of c holds.
func (s *solver) triggered(c *cand) bool {
	for _, d := range c.pkg.installIf {
		ns, ok := s.names[d.Name]
		held := ok && ns.locked && ns.chosen.c != nil && matches(d, ns.chosen)

		if held == d.Conflict {
			return false
		}
	}

	return true
}

// solution builds the result from the selection.
func (s *solver) solution() *Solution {
	chosen := make(map[*cand]bool, len(s.selOrder))
	for _, c := range s.selOrder {
		chosen[c] = true
	}

	// Dependencies first: a post-order walk over the selection.
	var (
		out   []*cand
		state = make(map[*cand]uint8)
	)

	var visit func(c *cand)

	visit = func(root *cand) {
		type item struct {
			c    *cand
			next int
		}

		stack := []item{{c: root}}
		state[root] = 1

		for len(stack) > 0 {
			top := &stack[len(stack)-1]

			if top.next >= len(top.c.pkg.deps) {
				state[top.c] = 2
				out = append(out, top.c)
				stack = stack[:len(stack)-1]

				continue
			}

			d := top.c.pkg.deps[top.next]
			top.next++

			if d.Conflict {
				continue
			}

			ns, ok := s.names[d.Name]
			if !ok || !ns.locked || ns.chosen.c == nil || state[ns.chosen.c] != 0 || !chosen[ns.chosen.c] {
				continue
			}

			state[ns.chosen.c] = 1
			stack = append(stack, item{c: ns.chosen.c})
		}
	}

	for _, c := range s.selOrder {
		if state[c] == 0 {
			visit(c)
		}
	}

	sol := &Solution{}
	for _, c := range out {
		sol.Packages = append(sol.Packages, c.pkg)
	}

	keep := make(map[string]bool, len(out))
	for _, c := range out {
		keep[c.pkg.Name] = true
	}

	for i := range s.req.Installed {
		ip := &s.req.Installed[i]
		if !keep[ip.Name] {
			sol.Changes = append(sol.Changes, Change{Old: ip})
		}
	}

	for _, c := range out {
		if c.installed {
			continue
		}

		var old *Package

		for i := range s.req.Installed {
			if s.req.Installed[i].Name == c.pkg.Name {
				old = &s.req.Installed[i]

				break
			}
		}

		sol.Changes = append(sol.Changes, Change{Old: old, New: c.pkg})
	}

	return sol
}
