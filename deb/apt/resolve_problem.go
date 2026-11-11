package apt

import (
	"slices"
	"sort"
)

// This file is the port of apt's pkgProblemResolver: the scored pass that
// repairs the dependencies MarkInstall could not (algorithms.cc).

// Resolver flags, apt's pkgProblemResolver::Flags.
const (
	flagProtected uint8 = 1 << iota
	flagPreInstalled
	flagUpgradable
	flagReInstateTried
	flagToRemove
)

// Score constants of apt's MakeScores.
const (
	scoreEssential    = 100
	scoreNotObsolete  = 1
	scoreProtectedAdd = 10000
	scoreEssentialAdd = 5000
	maxResolveRounds  = 20
)

// scorePrio maps the version priority enumeration to a score: unknown 0,
// required 3, important 2, standard 1, optional -1, extra -2.
var scorePrio = [...]int{0, 3, 2, 1, -1, -2}

// resolver is one pkgProblemResolver: the scores and flags it keeps.
type resolver struct {
	e      *engine
	flags  map[string]uint8
	scores map[string]int
	// allUpgradable is set once ResolveInternal has marked every package
	// upgradable: a package without an entry of its own then counts as one.
	allUpgradable bool
}

// newResolver returns a resolver over the engine's state.
func newResolver(e *engine) *resolver {
	return &resolver{e: e, flags: make(map[string]uint8), scores: make(map[string]int)}
}

// flag returns the flags of a package.
func (r *resolver) flag(key string) uint8 {
	if v, ok := r.flags[key]; ok {
		return v
	}

	if r.allUpgradable {
		return flagUpgradable
	}

	return 0
}

// protect is apt's Protect: the resolver and the depcache both leave the
// package alone.
func (r *resolver) protect(s *pstate) {
	r.flags[s.key] = r.flag(s.key) | flagProtected
	s.protect = true
}

// markRemove is apt's Remove: the user asked for the package to go.
func (r *resolver) markRemove(s *pstate) {
	r.flags[s.key] = r.flag(s.key) | flagToRemove
}

// clear is apt's Clear.
func (r *resolver) clear(s *pstate) {
	r.flags[s.key] = r.flag(s.key) &^ (flagProtected | flagToRemove)
}

// ignorableNeg reports a negative dependency on its own package group.
func (e *engine) ignorableNeg(g *depGroup, target string) bool {
	if !g.negative() || keyName(target) != g.owner.Name {
		return false
	}

	return target == g.owner.slot || (g.owner.MultiArch == "same")
}

// makeScores is apt's MakeScores: a score per package from its priority, the
// packages that depend on it and the ones it conflicts with.
func (r *resolver) makeScores() {
	e := r.e
	r.scores = make(map[string]int)

	depScore := [...]int{kindPreDepends: 1, kindDepends: 1, kindConflicts: -1, kindBreaks: -1}

	for _, key := range e.keys() {
		s := e.state(key)
		if s.inst == nil {
			continue
		}

		score := 0
		if e.essential(key) {
			score += scoreEssential
		}

		if p := enumPriority(s.inst); p <= len(scorePrio)-1 && downloadable(s.inst) {
			score += scorePrio[p]
		} else {
			score += scorePrio[len(scorePrio)-1]
		}

		if s.cur != nil && s.cand != nil && downloadable(s.cand) {
			score += scoreNotObsolete
		}

		r.scores[key] += score

		for _, g := range e.depsOf(s.inst) {
			for i := range g.alts {
				rel := &g.alts[i]
				target := e.targetSlot(rel, e.ownerArch(s.inst))

				if !e.ignorableNeg(&g, target) {
					if rel.Op != "" {
						iv := e.state(target).inst
						if iv == nil || !rel.Satisfied(iv.Version) {
							continue
						}
					}

					r.scores[target] += depScore[g.kind]
				}

				var seen []string

				for _, p := range e.c.providers[rel.Name] {
					if g.negative() && p.Name == g.owner.Name {
						continue
					}

					if e.state(p.slot).inst != p || !providesMatch(rel, p) || slices.Contains(seen, p.slot) {
						continue
					}

					seen = append(seen, p.slot)
					r.scores[p.slot] += depScore[g.kind]
				}
			}
		}
	}

	old := make(map[string]int, len(r.scores))
	for k, v := range r.scores {
		old[k] = v
	}

	// One level of dependency inheritance: the score of a depending package
	// adds to its dependency, never a negative one.
	for _, key := range e.keys() {
		s := e.state(key)
		if s.inst == nil || old[key] <= 0 {
			continue
		}

		for _, g := range e.depsOf(s.inst) {
			if g.negative() {
				continue
			}

			for i := range g.alts {
				target := e.targetSlot(&g.alts[i], e.ownerArch(s.inst))
				if e.state(target).inst != nil {
					r.scores[target] += old[key]
				}
			}
		}
	}

	// Along provides: a package that provides an important one is important.
	keys := make([]string, 0, len(r.scores))
	for k := range r.scores {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, key := range keys {
		transfer := r.scores[key] - old[key]
		if transfer < 0 {
			transfer = -transfer
		}

		if transfer == 0 {
			continue
		}

		var seen []string

		for _, p := range e.c.providers[keyName(key)] {
			if e.state(p.slot).inst != p || slices.Contains(seen, p.slot) {
				continue
			}

			seen = append(seen, p.slot)
		}

		for _, slot := range seen {
			r.scores[slot] += transfer
		}
	}

	for _, key := range e.allKeys() {
		if r.flag(key)&flagProtected != 0 {
			r.scores[key] += scoreProtectedAdd
		}

		if e.essential(key) {
			r.scores[key] += scoreEssentialAdd
		}
	}
}

// scoreOrder lists the packages by decreasing score, ties by name.
func (r *resolver) scoreOrder() []string {
	keys := append([]string(nil), r.e.allKeys()...)
	sort.SliceStable(keys, func(i, j int) bool { return r.scores[keys[i]] > r.scores[keys[j]] })

	return keys
}

// altGroups walks the dependency groups of an installed version the way
// apt's GlobOr loops do.
type altCursor struct {
	groups []depGroup
	gi     int
	g      *depGroup
	si, ei int
	begun  bool
}

// more reports whether the walk has groups left.
func (c *altCursor) more() bool { return c.gi < len(c.groups) }

// atGroupEnd reports that the cursor stands on the last alternative of its
// group (or has not started): apt's Start == End.
func (c *altCursor) atGroupEnd() bool { return !c.begun || c.si == c.ei }

// nextGroup moves to the first alternative of the next group.
func (c *altCursor) nextGroup() bool {
	if c.gi >= len(c.groups) {
		return false
	}

	c.g = &c.groups[c.gi]
	c.gi++
	c.si, c.ei = 0, len(c.g.alts)-1
	c.begun = true

	return true
}

// killEntry is a package the pass may have to remove or keep.
type killEntry struct {
	s *pstate
	g *depGroup
}

// resolveInternal is apt's pkgProblemResolver::ResolveInternal: run the scored
// pass until every dependency holds or nothing changes. With brokenFix the
// resolver may upgrade a package to cure a problem.
func (r *resolver) resolveInternal(brokenFix bool) error {
	e := r.e

	for again := true; again; {
		again = false

		for _, key := range append([]string(nil), e.keys()...) {
			s := e.state(key)

			if s.mode == modeInstall {
				r.flags[key] = r.flag(key) | flagPreInstalled
			} else {
				if brokenFix && e.instBroken(s) {
					e.markInstall(s, false, 0, false)

					if s.mode == modeInstall {
						again = true
					}
				}

				r.flags[key] = r.flag(key) &^ flagPreInstalled
			}

			r.flags[key] = r.flag(key) | flagUpgradable
		}
	}

	r.allUpgradable = true

	r.makeScores()

	plist := r.scoreOrder()

	change := true

	for counter := 0; counter < maxResolveRounds && change; counter++ {
		change = false

		for _, key := range plist {
			if e.tick() {
				return ErrResolveLimit
			}

			s, ok := e.st[key]
			if !ok {
				continue
			}

			r.reinstate(s, counter)

			if s.inst == nil || !e.instBroken(s) {
				continue
			}

			if r.investigate(s, counter, brokenFix) {
				change = true
			}
		}
	}

	if e.brokenCount() != 0 {
		return e.planError()
	}

	return nil
}

// reinstate attempts to install a package kept below its candidate and keeps
// it again if that breaks something (the "Re-Instate" step).
func (r *resolver) reinstate(s *pstate, counter int) {
	e := r.e
	_ = counter

	if s.cand == s.inst || s.cur == nil || s.inst == nil ||
		r.flag(s.key)&flagPreInstalled == 0 || s.protect || r.flag(s.key)&flagReInstateTried != 0 {
		return
	}

	oldBreaks := e.brokenCount()
	oldVer := s.inst
	// apt masks the flags with ReInstateTried here, which clears all the
	// others; the port keeps that behaviour.
	r.flags[s.key] = r.flag(s.key) & flagReInstateTried

	e.markInstall(s, false, 0, false)

	if e.instBroken(s) || oldBreaks < e.brokenCount() {
		if oldVer == nil {
			e.markDelete(s, 0, false)
		} else {
			e.markKeep(s, false, 0)
		}
	}
}

// investigate walks the broken dependencies of one package, in the order of
// apt's loop, and keeps, removes or upgrades packages to repair them. It
// reports whether anything changed.
func (r *resolver) investigate(s *pstate, counter int, brokenFix bool) bool {
	e := r.e
	change := false

	cur := &altCursor{groups: e.depsOf(s.inst)}

	var (
		inOr    bool
		oldSize int
		kill    []killEntry
		orKeep  bool
	)

	for cur.more() || inOr {
		if cur.atGroupEnd() {
			if inOr && oldSize == len(kill) {
				if !orKeep {
					if !s.protect {
						e.ctx = Reason{Kind: ReasonBrokenDependency, Cause: cur.g.alts.String()}
						e.markDelete(s, 0, false)

						change = true
					}
				} else {
					e.markKeep(s, false, 0)

					change = true
				}
			}

			orKeep = false

			if !cur.nextGroup() {
				break
			}

			inOr = cur.si != cur.ei
			oldSize = len(kill)
		} else {
			cur.si++
		}

		g := cur.g

		if e.groupOK(g, whenInstall) {
			inOr = false

			continue
		}

		neg := g.negative()
		vlist := e.allTargets(g, cur.si)

		if len(vlist) == 0 && !s.protect && !neg && !e.nowBroken(s) {
			if inOr {
				continue
			}

			change = true

			e.markKeep(s, false, 0)

			break
		}

		done := false

		for _, v := range vlist {
			ps := e.state(v.slot)

			if ps.inst != v && neg {
				continue
			}

			if r.scores[s.key] <= r.scores[ps.key] || (!e.altOK(g, cur.si, whenNow) && !neg) {
				if s.protect {
					if r.doUpgrade(ps) {
						if r.scores[ps.key] > r.scores[s.key] {
							r.scores[ps.key] = r.scores[s.key]
						}

						break
					}

					continue
				}

				wasInstall := s.mode == modeInstall

				e.markKeep(s, false, 0)

				if !e.instBroken(s) {
					orKeep = true

					if inOr && wasInstall {
						e.markInstall(s, false, 0, false)
					}
				} else if !brokenFix || !r.doUpgrade(s) {
					r.removeOrInstall(s, ps, g, cur.si, counter, inOr, &orKeep)
				}

				change = true
				done = true

				break
			}

			if g.kind == kindBreaks && e.groupOK(g, whenCandidate) {
				e.markInstall(ps, false, 0, false)

				continue
			}

			if ps.protect && ps.mode != modeDelete {
				continue
			}

			kill = append(kill, killEntry{s: ps, g: g})

			if !neg {
				break
			}
		}

		if len(vlist) == 0 && !neg && !s.protect {
			wasInstall := s.mode == modeInstall

			e.markKeep(s, true, 0)

			if !e.instBroken(s) {
				orKeep = true

				if inOr && wasInstall {
					e.markInstall(s, false, 0, false)
				}
			} else if !inOr {
				e.ctx = Reason{Kind: ReasonBrokenDependency, Cause: g.alts.String()}
				e.markDelete(s, 0, false)
			}

			change = true
			done = true
		}

		if inOr {
			continue
		}

		if done {
			break
		}
	}

	if s.inst != nil {
		for _, j := range kill {
			found := false

			if !e.groupOK(j.g, whenNow) {
				if j.g.negative() {
					e.ctx = conflictReason(j.g)

					if e.markDelete(j.s, 0, false) {
						found = true
					}
				}
			} else if e.markKeep(j.s, false, 0) {
				found = true
			}

			if !found || counter > 1 {
				if r.scores[s.key] > r.scores[j.s.key] {
					r.scores[j.s.key] = r.scores[s.key]
					change = true
				}
			}

			if found {
				change = true
			}
		}
	}

	return change
}

// removeOrInstall is the branch of the pass for a package that cannot be kept
// and cannot be upgraded: remove it, or, inside an or-group, try installing
// the missing dependency first.
func (r *resolver) removeOrInstall(s, ps *pstate, g *depGroup, si, counter int, inOr bool, orKeep *bool) {
	e := r.e

	if !inOr {
		e.ctx = Reason{Kind: ReasonBrokenDependency, Cause: g.alts[si].String()}
		e.markDelete(s, 0, false)

		if counter > 1 && r.scores[ps.key] > r.scores[s.key] {
			r.scores[s.key] = r.scores[ps.key]
		}

		return
	}

	key := e.targetSlot(&g.alts[si], e.ownerArch(g.owner))
	if e.c.slots[key] == nil {
		return
	}

	t := e.state(key)
	if t.cur != nil || t.mode == modeDelete || r.flag(key)&flagToRemove != 0 || t.cand == nil {
		return
	}

	oldBroken := e.brokenCount()

	e.ctx = Reason{Kind: ReasonDependency, Cause: label(g.owner), Relation: g.alts.String()}
	e.markInstall(t, true, 1, false)

	*orKeep = true

	if e.instBroken(t) || e.brokenCount() > oldBroken {
		e.markDelete(t, 1, false)

		*orKeep = false
	}
}

// doUpgrade is apt's DoUpgrade: install the candidate of a package and, for
// every dependency that is still unmet, try to upgrade the package that
// could meet it. On failure the package is put back.
func (r *resolver) doUpgrade(s *pstate) bool {
	e := r.e

	if r.flag(s.key)&flagUpgradable == 0 || s.status < 1 || s.cand == nil {
		return false
	}

	if r.flag(s.key)&flagProtected != 0 {
		return false
	}

	r.flags[s.key] = r.flag(s.key) &^ flagUpgradable

	wasKept := s.mode == modeKeep

	if !e.markInstall(s, false, 0, false) {
		return false
	}

	if s.inst == nil {
		return false
	}

	fail := false

	for gi := range e.depsOf(s.inst) {
		g := &e.depsOf(s.inst)[gi]

		for si := range g.alts {
			if e.groupOK(g, whenInstall) {
				break
			}

			key, ok := e.smartTarget(g.owner, &g.alts[si])

			if ok && e.state(key).protect {
				fail = true
			} else if e.altOK(g, si, whenCandidate) {
				if !ok || !r.doUpgrade(e.state(key)) {
					fail = true
				} else {
					fail = false

					break
				}
			} else {
				if g.negative() {
					break
				}

				fail = true
			}
		}

		if fail {
			break
		}
	}

	if fail {
		if wasKept {
			e.markKeep(s, false, 0)
		} else {
			e.markDelete(s, 0, false)
		}

		return false
	}

	return true
}

// keepPhased is apt's KeepPhasedUpdates: keep back the upgrades the policy
// phases.
func (r *resolver) keepPhased() {
	e := r.e

	for _, key := range append([]string(nil), e.keys()...) {
		s := e.state(key)
		if !e.phased(s) {
			continue
		}

		e.markKeep(s, false, 0)
		r.protect(s)
	}
}

// phased reports a package whose candidate is a phased update the policy
// withholds from this system.
func (e *engine) phased(s *pstate) bool {
	if e.pol == nil || s.cur == nil || s.cand == nil {
		return false
	}

	return e.pol.Phased(&s.cand.PackageInfo, &s.cur.PackageInfo)
}

// resolveByKeep is apt's ResolveByKeepInternal: repair the broken packages by
// keeping packages at their installed version, never installing or removing.
func (r *resolver) resolveByKeep() error {
	e := r.e

	r.makeScores()

	plist := r.scoreOrder()

	lastStop := -1

	for restart := true; restart; {
		restart = false

		for ki, key := range plist {
			if e.tick() {
				return ErrResolveLimit
			}

			s, ok := e.st[key]
			if !ok || s.inst == nil || !e.instBroken(s) {
				continue
			}

			if !s.protect {
				e.markKeep(s, false, 0)

				if !e.instBroken(s) {
					restart = true

					break
				}
			}

			r.keepAround(s)

			if e.instBroken(s) {
				continue
			}

			if ki == lastStop {
				return &PlanError{Broken: []error{&ConflictError{Package: label(s.inst), Kind: "Conflicts", Relation: "keep loop"}}}
			}

			lastStop = ki
			restart = true

			break
		}
	}

	if e.brokenCount() != 0 {
		return e.planError()
	}

	return nil
}

// keepAround keeps the installed packages that could meet each unmet
// dependency of s until s is whole.
func (r *resolver) keepAround(s *pstate) {
	e := r.e

	for gi := range e.depsOf(s.inst) {
		g := &e.depsOf(s.inst)[gi]

		if e.groupOK(g, whenInstall) {
			continue
		}

		for si := range g.alts {
			for _, v := range e.allTargets(g, si) {
				ps := e.state(v.slot)
				if ps.cur == nil {
					continue
				}

				if !ps.protect {
					e.markKeep(ps, false, 0)
				}

				if !e.instBroken(s) {
					break
				}
			}

			if !e.instBroken(s) {
				break
			}
		}

		if !e.instBroken(s) {
			break
		}
	}
}
