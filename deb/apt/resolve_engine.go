package apt

import (
	"cmp"
	"slices"
	"sort"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
)

// This file is the state machine of [Cache.Plan]: a port of the part of apt's
// pkgDepCache that decides what installing, keeping or removing a package
// drags along (MarkInstall, MarkDelete, MarkKeep and the helpers around
// them). resolve_problem.go holds the pkgProblemResolver on top of it.
//
// apt keeps the state of every dependency in counters that it updates as
// packages change. The engine computes a dependency's state from the packages
// when it is asked instead, which gives the same answers at a higher cost per
// question.

// when selects which version of a package a dependency is checked against.
type when uint8

const (
	// whenNow is the installed version.
	whenNow when = iota
	// whenInstall is the version the plan installs (or keeps).
	whenInstall
	// whenCandidate is the policy's candidate.
	whenCandidate
)

// changeMode is what the plan does with one package.
type changeMode uint8

const (
	modeKeep changeMode = iota
	modeInstall
	modeDelete
)

// maxMarkDepth bounds the recursion of MarkInstall, as in apt.
const maxMarkDepth = 3000

// depKind is the relationship of a dependency group the solver reads.
type depKind uint8

const (
	kindPreDepends depKind = iota
	kindDepends
	kindConflicts
	kindBreaks
)

// depGroup is one entry of the dependencies of a version: a dependency group
// (Depends, Pre-Depends) of alternatives, or one relation of Conflicts or
// Breaks.
type depGroup struct {
	owner *pkg
	kind  depKind
	alts  deb.Alternatives
}

// negative reports a Conflicts or Breaks entry.
func (g *depGroup) negative() bool { return g.kind >= kindConflicts }

// pstate is the plan's view of one package (a name:arch slot).
type pstate struct {
	key string
	// cur is the installed version; cand the version a policy offers; inst
	// the version the plan leaves installed (nil: not installed).
	cur, cand, inst *pkg
	// status compares cand with cur: 2 when the package is not installed or
	// has no candidate, else -1, 0 or 1.
	status int8
	mode   changeMode
	// protect is apt's Protected flag: a decision the user made.
	protect bool
	// held is a package whose state dpkg or the user froze.
	held bool
	// auto is the automatic-installation flag of a package new to the system.
	auto bool
	// why is the reason of the last change of mode.
	why Reason
}

// engine is one planning run over a cache; c.mu is held for its duration.
type engine struct {
	c      *Cache
	native string
	pol    candidatePolicy
	held   map[string]bool

	st     map[string]*pstate
	deps   map[*pkg][]depGroup
	active map[string]struct{}
	order  []string
	every  []string
	revCur map[string][]revEntry
	bySrc  map[string][]*pkg

	steps    int
	maxSteps int
	exceeded bool

	// ctx is the reason recorded for the changes made while it is set.
	ctx Reason
	// upgradable is the installed packages with a newer candidate when the
	// solver started.
	upgradable []*pstate
}

// revEntry is one dependency of an installed version on a package name.
type revEntry struct {
	owner *pkg
	rel   *deb.Relation
}

// newEngine sets up the states of the installed packages.
func newEngine(c *Cache, pol candidatePolicy, held []string, maxSteps int) *engine {
	e := &engine{
		c:        c,
		native:   c.hostArch,
		pol:      pol,
		held:     make(map[string]bool, len(held)),
		st:       make(map[string]*pstate, len(c.installed)),
		deps:     make(map[*pkg][]depGroup),
		active:   make(map[string]struct{}, len(c.installed)),
		maxSteps: maxSteps,
	}

	for _, h := range held {
		e.held[h] = true
	}

	for key := range c.installed {
		e.state(key)
		e.active[key] = struct{}{}
	}

	return e
}

// keyName is the package name of a slot key.
func keyName(key string) string {
	if i := strings.IndexByte(key, ':'); i >= 0 {
		return key[:i]
	}

	return key
}

// state returns the state of a slot, creating it on first use.
func (e *engine) state(key string) *pstate {
	if s, ok := e.st[key]; ok {
		return s
	}

	s := &pstate{key: key, cur: e.c.installed[key]}
	s.inst = s.cur
	s.cand = selectCandidate(e.pol, e.c.slots[key], s.cur)
	s.updateStatus()
	s.held = e.held[key] || e.held[keyName(key)]
	e.st[key] = s

	return s
}

// updateStatus recomputes status from cur and cand.
func (s *pstate) updateStatus() {
	if s.cur == nil || s.cand == nil {
		s.status = 2

		return
	}

	s.status = int8(cmp.Compare(deb.CompareVersions(s.cand.Version, s.cur.Version), 0))
}

// touch records that a slot may differ from the installed system.
func (e *engine) touch(s *pstate) {
	if _, ok := e.active[s.key]; !ok {
		e.active[s.key] = struct{}{}
		e.order = nil
	}
}

// keys lists the slots that are installed or were touched, sorted.
func (e *engine) keys() []string {
	if e.order == nil {
		e.order = make([]string, 0, len(e.active))
		for k := range e.active {
			e.order = append(e.order, k)
		}

		sort.Strings(e.order)
	}

	return e.order
}

// tick counts one unit of work and reports whether the budget is spent.
func (e *engine) tick() bool {
	e.steps++
	if e.maxSteps > 0 && e.steps > e.maxSteps {
		e.exceeded = true
	}

	return e.exceeded
}

// ver returns the version of a slot in a given state.
func (e *engine) ver(key string, w when) *pkg {
	s := e.state(key)

	switch w {
	case whenNow:
		return s.cur
	case whenInstall:
		return s.inst
	default:
		return s.cand
	}
}

// ownerArch is the architecture a dependency of p is read for.
func (e *engine) ownerArch(p *pkg) string {
	if p.Architecture == "" || p.Architecture == archAll {
		return e.native
	}

	return p.Architecture
}

// depsOf lists the dependency groups of a version the solver reads, in the
// order apt stores them: Pre-Depends, Depends, Conflicts, Breaks.
func (e *engine) depsOf(p *pkg) []depGroup {
	if g, ok := e.deps[p]; ok {
		return g
	}

	out := make([]depGroup, 0, len(p.PreDepends)+len(p.Depends)+len(p.Conflicts)+len(p.Breaks))

	for _, a := range p.PreDepends {
		out = append(out, depGroup{owner: p, kind: kindPreDepends, alts: a})
	}

	for _, a := range p.Depends {
		out = append(out, depGroup{owner: p, kind: kindDepends, alts: a})
	}

	for _, r := range p.Conflicts {
		out = append(out, depGroup{owner: p, kind: kindConflicts, alts: deb.Alternatives{r}})
	}

	for _, r := range p.Breaks {
		out = append(out, depGroup{owner: p, kind: kindBreaks, alts: deb.Alternatives{r}})
	}

	e.deps[p] = out

	return out
}

// relMatch reports whether v meets a relation of group owner: the Multi-Arch
// rules of a dependency, or the architecture qualifier of a Conflicts.
func (e *engine) relMatch(owner *pkg, rel *deb.Relation, neg bool, v *pkg) bool {
	if neg {
		if !relNegMatches(e.native, rel, v) {
			return false
		}

		if v.Name == owner.Name {
			// A package never conflicts with itself, and a provide is never
			// applied to its own name group; another architecture of a
			// Multi-Arch: same package is its sibling.
			return v.Name == rel.Name && rel.Satisfied(v.Version) && v.slot != owner.slot &&
				!strings.EqualFold(owner.MultiArch, "same")
		}

		return true
	}

	return ((v.Name == rel.Name && rel.Satisfied(v.Version)) || providesMatch(rel, v)) &&
		relArchOK(e.native, rel, e.ownerArch(owner), v)
}

// allTargets is apt's AllTargets: every version of the package alternative i
// names that meets the relation's version constraint, then every version that
// provides it, whatever their state.
func (e *engine) allTargets(g *depGroup, i int) []*pkg {
	rel := &g.alts[i]
	neg := g.negative()

	var out []*pkg

	for _, v := range e.c.slots[e.targetSlot(rel, e.ownerArch(g.owner))] {
		if neg && v.Name == g.owner.Name && (v.slot == g.owner.slot || strings.EqualFold(g.owner.MultiArch, "same")) {
			continue
		}

		if rel.Satisfied(v.Version) {
			out = append(out, v)
		}
	}

	provs := e.c.providers[rel.Name]
	for j := len(provs) - 1; j >= 0; j-- {
		p := provs[j]
		if neg && p.Name == g.owner.Name {
			continue
		}

		if providesMatch(rel, p) && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}

	return out
}

// allKeys lists every slot key of the cache, sorted.
func (e *engine) allKeys() []string {
	if e.every == nil {
		e.every = make([]string, 0, len(e.c.slots))
		for k := range e.c.slots {
			e.every = append(e.every, k)
		}

		sort.Strings(e.every)
	}

	return e.every
}

// matches lists, for a relation, the versions of every package in state w
// that meet it: the package it names first, then the providers (the one read
// last first, as apt walks its provider list).
func (e *engine) matches(owner *pkg, rel *deb.Relation, neg bool, w when) []*pkg {
	var out []*pkg

	e.c.eachSlot(rel.Name, func(key string) bool {
		if v := e.ver(key, w); v != nil && e.relMatch(owner, rel, neg, v) {
			out = append(out, v)
		}

		return true
	})

	provs := e.c.providers[rel.Name]
	for i := len(provs) - 1; i >= 0; i-- {
		p := provs[i]
		if e.ver(p.slot, w) == p && e.relMatch(owner, rel, neg, p) && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}

	return out
}

// anyMatch is matches without the list.
func (e *engine) anyMatch(owner *pkg, rel *deb.Relation, neg bool, w when) bool {
	found := false

	e.c.eachSlot(rel.Name, func(key string) bool {
		if v := e.ver(key, w); v != nil && e.relMatch(owner, rel, neg, v) {
			found = true

			return false
		}

		return true
	})

	if found {
		return true
	}

	for _, p := range e.c.providers[rel.Name] {
		if e.ver(p.slot, w) == p && e.relMatch(owner, rel, neg, p) {
			return true
		}
	}

	return false
}

// altOK is the state of one alternative of a group: for a dependency, some
// package in state w meets it; for a Conflicts or Breaks, none does.
func (e *engine) altOK(g *depGroup, i int, w when) bool {
	hit := e.anyMatch(g.owner, &g.alts[i], g.negative(), w)

	return hit != g.negative()
}

// groupOK is the state of a whole group in state w.
func (e *engine) groupOK(g *depGroup, w when) bool {
	if g.negative() {
		return e.altOK(g, 0, w)
	}

	for i := range g.alts {
		if e.altOK(g, i, w) {
			return true
		}
	}

	return false
}

// instBroken reports a package the plan installs (or keeps) whose
// dependencies do not hold.
func (e *engine) instBroken(s *pstate) bool {
	if s.inst == nil {
		return false
	}

	for _, g := range e.depsOf(s.inst) {
		if !e.groupOK(&g, whenInstall) {
			return true
		}
	}

	return false
}

// nowBroken reports an installed package whose dependencies do not hold on the
// installed system.
func (e *engine) nowBroken(s *pstate) bool {
	if s.cur == nil {
		return false
	}

	for _, g := range e.depsOf(s.cur) {
		if !e.groupOK(&g, whenNow) {
			return true
		}
	}

	return false
}

// brokenCount counts the packages that are installed or to be and broken.
func (e *engine) brokenCount() int {
	n := 0

	for _, k := range e.keys() {
		if e.instBroken(e.state(k)) {
			n++
		}
	}

	return n
}

// essential reports a package any version of which is Essential.
func (e *engine) essential(key string) bool {
	return slices.ContainsFunc(e.c.slots[key], func(p *pkg) bool { return p.Essential })
}

// downloadable reports a version an index offers.
func downloadable(p *pkg) bool { return p.HasCandidate || !p.Installed }

// enumPriority is apt's version-priority enumeration: required 1 to extra 5,
// unknown 0.
func enumPriority(p *pkg) int {
	if r := priorityRank(p.Priority); r > 0 {
		return 6 - r
	}

	return 0
}

// targetSlot is the slot a relation of a version of architecture arch names.
func (e *engine) targetSlot(rel *deb.Relation, ownerArch string) string {
	if rel.Arch != "" && rel.Arch != "any" && rel.Arch != "native" {
		ownerArch = rel.Arch
	}

	if rel.Arch == "native" {
		ownerArch = e.native
	}

	if k := entryKey(rel.Name, ownerArch); e.c.slots[k] != nil {
		return k
	}

	if e.c.slots[rel.Name] != nil {
		return rel.Name
	}

	var first string

	e.c.eachSlot(rel.Name, func(key string) bool {
		first = key

		return false
	})

	if first != "" {
		return first
	}

	return entryKey(rel.Name, ownerArch)
}

// smartTarget is the package a dependency is about, as apt's
// SmartTargetPkg: the named package, or for a purely virtual name its first
// provider other than the owner. ok is false when there is none.
func (e *engine) smartTarget(owner *pkg, rel *deb.Relation) (string, bool) {
	key := e.targetSlot(rel, e.ownerArch(owner))
	if e.c.slots[key] != nil {
		return key, true
	}

	provs := e.c.providers[rel.Name]
	for i := len(provs) - 1; i >= 0; i-- {
		if provs[i].Name != owner.Name {
			return provs[i].slot, true
		}
	}

	return "", false
}

// isDeleteOK refuses to remove a new package the user chose on a whim of the
// resolver.
func (e *engine) isDeleteOK(s *pstate, fromUser bool) bool {
	if !fromUser && s.cur == nil && s.inst != nil && s.status == 2 && !s.auto {
		return false
	}

	return true
}

// modeChangeOK is apt's IsModeChangeOk.
func (e *engine) modeChangeOK(m changeMode, s *pstate, depth int, fromUser bool) bool {
	if depth > maxMarkDepth || len(e.c.slots[s.key]) == 0 {
		return false
	}

	if fromUser {
		return true
	}

	if s.mode == m {
		return true
	}

	if s.protect {
		return false
	}

	if s.held && m != modeKeep {
		return false
	}

	return m != modeDelete || !e.essential(s.key)
}

// setCandidate is apt's SetCandidateVersion.
func (e *engine) setCandidate(s *pstate, v *pkg) {
	if s.cand == s.inst && s.mode == modeInstall {
		s.inst = v
	}

	s.cand = v
	s.updateStatus()
}

// markKeep is apt's MarkKeep: leave the package as installed.
func (e *engine) markKeep(s *pstate, fromUser bool, depth int) bool {
	if e.tick() || !e.modeChangeOK(modeKeep, s, depth, fromUser) {
		return false
	}

	if s.mode == modeKeep {
		return true
	}

	s.mode = modeKeep
	s.inst = s.cur
	s.why = Reason{}
	e.touch(s)

	return true
}

// markDelete is apt's MarkDelete.
func (e *engine) markDelete(s *pstate, depth int, fromUser bool) bool {
	if e.tick() || !e.modeChangeOK(modeDelete, s, depth, fromUser) {
		return false
	}

	if s.mode == modeDelete || s.inst == nil {
		return true
	}

	if !e.isDeleteOK(s, fromUser) {
		return false
	}

	if s.cur == nil {
		s.mode = modeKeep
	} else {
		s.mode = modeDelete
		s.why = e.reason(fromUser)
	}

	s.inst = nil
	e.touch(s)

	return true
}

// reason is the reason to record for a change: the request itself when the
// user made it, else the context the caller set.
func (e *engine) reason(fromUser bool) Reason {
	if fromUser {
		return Reason{Kind: ReasonRequested}
	}

	return e.ctx
}

// stateChange is apt's MarkInstall_StateChange.
func (e *engine) stateChange(s *pstate, fromUser bool) bool {
	if s.protect && s.inst == s.cand {
		return true
	}

	s.mode = modeInstall
	s.inst = s.cand
	s.why = e.reason(fromUser)

	if fromUser {
		if s.status == 2 {
			s.auto = false
		}
	} else if s.status == 2 {
		s.auto = true
	}

	if s.cand == s.cur {
		s.mode = modeKeep
	}

	e.touch(s)

	return true
}

// sameGroup returns the slots of the other architectures of a package name.
func (e *engine) sameGroup(name string) []string {
	var keys []string

	e.c.eachSlot(name, func(key string) bool {
		keys = append(keys, key)

		return true
	})

	return keys
}

// multiArchSynced reports whether installing cv (Multi-Arch: same) keeps the
// installed siblings of the package on other architectures in version sync.
func (e *engine) multiArchSynced(s *pstate, cv *pkg) bool {
	for _, key := range e.sameGroup(cv.Name) {
		o := e.state(key)
		if o.cur == nil || o == s {
			continue
		}

		if o.cand == nil || o.cand.Version == cv.Version || !strings.EqualFold(o.cand.MultiArch, "same") ||
			!downloadable(o.cand) {
			continue
		}

		return false
	}

	return true
}

// isInstallOK is apt's IsInstallOk: Multi-Arch: same siblings stay in step,
// and with auto-install the candidate must be installable.
func (e *engine) isInstallOK(s *pstate, autoInst, fromUser bool) bool {
	cv := s.cand
	if cv == nil {
		return false
	}

	if !fromUser && (s.mode != modeInstall || s.inst != s.cand) && cv != s.cur &&
		strings.EqualFold(cv.MultiArch, "same") && !e.multiArchSynced(s, cv) {
		return false
	}

	if !autoInst || cv == s.cur {
		return true
	}

	for _, g := range e.depsOf(cv) {
		if g.negative() {
			continue
		}

		ok := false

		for i := range g.alts {
			if e.altOK(&g, i, whenInstall) || e.altOK(&g, i, whenCandidate) {
				ok = true

				break
			}
		}

		if ok {
			continue
		}

		if !s.protect {
			if s.cur != nil {
				e.setCandidate(s, s.cur)
			} else {
				s.cand = nil
				s.updateStatus()
			}

			if s.mode != modeDelete {
				s.mode = modeKeep
				s.inst = s.cur
				e.touch(s)
			}
		}

		return false
	}

	return true
}

// collectDependencies splits the unmet dependency groups of a version into
// those to install and those to remove (apt's MarkInstall_CollectDependencies).
func (e *engine) collectDependencies(s *pstate, pv *pkg) (toInstall, toRemove []*depGroup) {
	groups := e.depsOf(pv)

	for i := range groups {
		g := &groups[i]

		found := e.groupOK(g, whenInstall)
		if found && !s.protect {
			continue
		}

		if g.negative() {
			toRemove = append(toRemove, g)
		} else {
			toInstall = append(toInstall, g)
		}
	}

	return toInstall, toRemove
}

// selector says which versions of a dependency's target packages are looked
// at.
type selector uint8

const (
	selCandidate selector = iota
	selInstalled
	selBoth
)

// fromDependency lists the versions of the packages a relation reaches that
// meet it, for the versions a selector names.
func (e *engine) fromDependency(g *depGroup, i int, sel selector) []*pkg {
	rel := &g.alts[i]
	neg := g.negative()

	var out []*pkg

	add := func(v *pkg) {
		if v != nil && e.relMatch(g.owner, rel, neg, v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}

	pick := func(key string) {
		s := e.state(key)
		if sel == selCandidate || sel == selBoth {
			add(s.cand)
		}

		if sel == selInstalled || sel == selBoth {
			add(s.cur)
		}
	}

	e.c.eachSlot(rel.Name, func(key string) bool {
		pick(key)

		return true
	})

	provs := e.c.providers[rel.Name]
	for j := len(provs) - 1; j >= 0; j-- {
		p := provs[j]
		s := e.state(p.slot)

		if (sel == selCandidate || sel == selBoth) && s.cand == p {
			add(p)
		}

		if (sel == selInstalled || sel == selBoth) && s.cur == p {
			add(p)
		}
	}

	return out
}

// compareProviders orders two versions the way apt prefers them as the
// solution of a dependency on target: a negative result puts a first.
func (e *engine) compareProviders(target string, a, b *pkg) int {
	sa, sb := e.state(a.slot), e.state(b.slot)

	if sa.protect != sb.protect {
		return boolFirst(sa.protect)
	}

	if strings.EqualFold(a.MultiArch, "same") || strings.EqualFold(b.MultiArch, "same") {
		ia := strings.EqualFold(a.MultiArch, "same") && e.groupInstalled(a.Name)
		ib := strings.EqualFold(b.MultiArch, "same") && e.groupInstalled(b.Name)

		if ia != ib {
			return boolFirst(ia)
		}
	}

	if (sa.cur == nil || sb.cur == nil) && sa.cur != sb.cur {
		return boolFirst(sa.cur != nil)
	}

	if a.Name != b.Name {
		switch {
		case a.Name == target && b.Name != target:
			return -1
		case b.Name == target && a.Name != target:
			return 1
		}
	}

	if ea, eb := e.essential(a.slot), e.essential(b.slot); ea != eb {
		return boolFirst(ea)
	}

	if aa, ab := e.slotArch(a), e.slotArch(b); aa != ab {
		switch {
		case aa == e.native:
			return -1
		case ab == e.native:
			return 1
		}
	}

	if pa, pb := enumPriority(a), enumPriority(b); pa != pb {
		return pa - pb
	}

	return b.seq - a.seq
}

// slotArch is the architecture of a version as apt names it.
func (e *engine) slotArch(p *pkg) string {
	if p.Architecture == "" {
		return archAll
	}

	return p.Architecture
}

// groupInstalled reports an installed package of a name on any architecture.
func (e *engine) groupInstalled(name string) bool {
	for _, key := range e.sameGroup(name) {
		if e.state(key).cur != nil {
			return true
		}
	}

	return false
}

// boolFirst orders the side a condition holds for first.
func boolFirst(aFirst bool) int {
	if aFirst {
		return -1
	}

	return 1
}

// solutions is apt's getAllPossibleSolutions: the versions that can solve (or,
// for a Conflicts, are hit by) a dependency group, installed packages first.
func (e *engine) solutions(g *depGroup, sel selector, sorted bool) []*pkg {
	var upgrade, fresh []*pkg

	for i := range g.alts {
		list := e.fromDependency(g, i, sel)

		if !sorted {
			upgrade = append(upgrade, list...)

			continue
		}

		target := g.alts[i].Name

		slices.SortStableFunc(list, func(a, b *pkg) int { return e.compareProviders(target, a, b) })

		for _, v := range list {
			if e.state(v.slot).cur != nil {
				upgrade = append(upgrade, v)
			} else {
				fresh = append(fresh, v)
			}
		}
	}

	if len(upgrade) == 0 {
		upgrade = fresh
	} else {
		upgrade = append(upgrade, fresh...)
	}

	if !sorted {
		slices.SortStableFunc(upgrade, func(a, b *pkg) int { return a.seq - b.seq })
	}

	out := upgrade[:0:0]
	seen := make(map[*pkg]bool, len(upgrade))

	for _, v := range upgrade {
		if seen[v] {
			continue
		}

		seen[v] = true

		if !g.negative() {
			s := e.state(v.slot)
			if s.protect && (s.mode == modeDelete || (s.mode == modeKeep && s.cur == nil)) {
				continue
			}
		}

		out = append(out, v)
	}

	return out
}
