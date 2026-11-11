package apt

import (
	"slices"
	"sort"
)

// This file continues resolve_engine.go with MarkInstall itself and the steps
// it is made of, in the order apt runs them.

// installWork collects what markInstall decides before it changes anything:
// the dependency groups to satisfy, the Conflicts and Breaks to clear, the
// installed packages to upgrade, and the ones to remove once the rest worked.
type installWork struct {
	toInstall []*depGroup
	toRemove  []*depGroup
	toUpgrade []*pstate
	delayed   []*pstate
	// delayedWhy records why each delayed removal is wanted.
	delayedWhy map[*pstate]Reason
}

// conflictReason describes a clash of a version with a package.
func conflictReason(g *depGroup) Reason {
	kind := ReasonConflict
	if g.kind == kindBreaks {
		kind = ReasonBreaks
	}

	return Reason{Kind: kind, Cause: label(g.owner), Relation: g.alts.String()}
}

// removeConflictsIfNotUpgradeable is apt's
// MarkInstall_RemoveConflictsIfNotUpgradeable. Negative dependencies have no
// alternatives. If the candidate of the package a Conflicts or Breaks hits is
// being installed, the package is kept instead (or its candidate discarded); an
// installed package that is hit is queued for an upgrade, or removed when it
// has none.
func (e *engine) removeConflictsIfNotUpgradeable(pv *pkg, depth int, w *installWork, propagate, fromUser bool) bool {
	failed := false
	stop := !propagate && !fromUser

	var bad []*pstate

	for _, g := range w.toRemove {
		why := conflictReason(g)

		for _, ver := range e.solutions(g, selCandidate, true) {
			ps := e.state(ver.slot)
			if ps.cand != ver {
				continue
			}

			if ps.cur != ver {
				switch {
				case ps.mode == modeInstall && !e.markKeep(ps, false, depth):
					failed = true
				case propagate:
					e.discardCandidate(ps)

					if ps.cur == nil {
						ps.protect = true
					}
				default:
					bad = append(bad, ps)
				}

				if failed && stop {
					break
				}

				continue
			}

			if !e.markDeleteForNotUpgradeable(ps, depth, w, propagate, why) {
				failed = true

				if stop {
					break
				}
			}
		}

		if failed && stop {
			break
		}

		for _, ver := range e.solutions(g, selInstalled, true) {
			ps := e.state(ver.slot)

			switch {
			case ps.cand != ver && ps.cand != nil && !slices.Contains(bad, ps):
				w.toUpgrade = append(w.toUpgrade, ps)
			case ps.cand == ps.cur:
				// Already dealt with by the loop above.
			default:
				if !e.markDeleteForNotUpgradeable(ps, depth, w, propagate, why) {
					failed = true
				}
			}

			if failed && stop {
				break
			}
		}

		if failed && stop {
			break
		}
	}

	return !failed
}

// markDeleteForNotUpgradeable is apt's MarkInstall_MarkDeleteForNotUpgradeable:
// remove a package its upgrade cannot save, at once when its dependants are
// protected, else after the rest of the install.
func (e *engine) markDeleteForNotUpgradeable(ps *pstate, depth int, w *installWork, propagate bool, why Reason) bool {
	if !propagate {
		if ps.mode == modeDelete {
			return true
		}

		if !e.modeChangeOK(modeDelete, ps, depth, false) || !e.isDeleteOK(ps, false) {
			return false
		}

		if !slices.Contains(w.delayed, ps) {
			w.delayed = append(w.delayed, ps)

			if w.delayedWhy == nil {
				w.delayedWhy = make(map[*pstate]Reason)
			}

			w.delayedWhy[ps] = why
		}

		return true
	}

	if ps.mode != modeDelete {
		saved := e.ctx
		e.ctx = why
		ok := e.markDelete(ps, depth+1, false)
		e.ctx = saved

		if !ok {
			return false
		}
	}

	e.discardCandidate(ps)
	ps.protect = true

	return true
}

// discardCandidate is apt's DiscardCandidate: the package has no candidate but
// what the plan installs. Its status is kept.
func (e *engine) discardCandidate(s *pstate) {
	old := s.status
	s.cand = s.inst
	s.updateStatus()
	s.status = old
}

// discardInstall is apt's MarkInstall_DiscardInstall: undo the marking of a
// package that failed to install.
func (e *engine) discardInstall(s *pstate) {
	if s.mode == modeKeep && s.inst == s.cand && s.cand == s.cur {
		return
	}

	s.inst = s.cur
	s.mode = modeKeep
	s.why = Reason{}

	e.discardCandidate(s)
}

// revDeps lists the dependencies of the installed versions on a package name.
func (e *engine) revDeps(name string) []revEntry {
	if e.revCur == nil {
		e.revCur = make(map[string][]revEntry)

		keys := make([]string, 0, len(e.c.installed))
		for k := range e.c.installed {
			keys = append(keys, k)
		}

		sort.Strings(keys)

		for _, k := range keys {
			p := e.c.installed[k]
			for _, g := range e.depsOf(p) {
				if g.negative() {
					continue
				}

				for i := range g.alts {
					rel := &g.alts[i]
					e.revCur[rel.Name] = append(e.revCur[rel.Name], revEntry{owner: p, rel: rel})
				}
			}
		}
	}

	return e.revCur[name]
}

// collectReverseDepends queues the installed packages whose dependency on this
// package the new version no longer meets (apt's
// MarkInstall_CollectReverseDepends).
func (e *engine) collectReverseDepends(s *pstate, pv *pkg, w *installWork) {
	if s.cur == nil {
		return
	}

	for _, r := range e.revDeps(s.cur.Name) {
		if e.targetSlot(r.rel, e.ownerArch(r.owner)) != s.key {
			continue
		}

		ps := e.state(r.owner.slot)
		if ps.cur != r.owner || ps.mode == modeInstall {
			continue
		}

		if ps.mode == modeDelete || slices.Contains(w.delayed, ps) {
			continue
		}

		if !r.rel.Satisfied(s.cur.Version) || r.rel.Satisfied(pv.Version) {
			continue
		}

		if !slices.Contains(w.toUpgrade, ps) {
			w.toUpgrade = append(w.toUpgrade, ps)
		}
	}
}

// sourceOf is the source package name and version of a version; a binary that
// names no source is its own.
func sourceOf(p *pkg) (string, string) {
	name, ver := p.SourceName, p.SourceVersion

	if name == "" {
		name = p.Name
	}

	if ver == "" {
		ver = p.Version
	}

	return name, ver
}

// binariesOf lists the versions of the binaries of a source package.
func (e *engine) binariesOf(source string) []*pkg {
	if e.bySrc == nil {
		e.bySrc = make(map[string][]*pkg)

		keys := make([]string, 0, len(e.c.slots))
		for k := range e.c.slots {
			keys = append(keys, k)
		}

		sort.Strings(keys)

		for _, k := range keys {
			for _, v := range e.c.slots[k] {
				name, _ := sourceOf(v)
				e.bySrc[name] = append(e.bySrc[name], v)
			}
		}
	}

	return e.bySrc[source]
}

// upgradeOtherBinaries upgrades the installed binaries of the source package
// and version of the one being installed (apt's
// MarkInstall_UpgradeOtherBinaries).
func (e *engine) upgradeOtherBinaries(s *pstate, pv *pkg, depth int) {
	name, srcVer := sourceOf(pv)

	var todo []*pstate

	for _, other := range e.binariesOf(name) {
		os := e.state(other.slot)
		if os == s || os.cur == nil || os.cur == other || (os.mode == modeInstall && os.inst == other) {
			continue
		}

		if _, v := sourceOf(other); v != srcVer || os.cand != other {
			continue
		}

		if !slices.Contains(todo, os) {
			todo = append(todo, os)
		}
	}

	saved := e.ctx
	e.ctx = Reason{Kind: ReasonSameSource, Cause: label(pv)}

	for _, os := range todo {
		e.markInstall(os, false, depth+1, false)
	}

	for _, os := range todo {
		e.markInstall(os, true, depth+1, false)
	}

	e.ctx = saved
}

// upgradeOrRemoveConflicts is apt's MarkInstall_UpgradeOrRemoveConflicts:
// upgrade the queued packages, removing the ones that cannot be.
func (e *engine) upgradeOrRemoveConflicts(pv *pkg, depth int, w *installWork, propagate, fromUser bool) bool {
	failed := false

	saved := e.ctx
	defer func() { e.ctx = saved }()

	for _, ps := range w.toUpgrade {
		if ps.mode == modeInstall {
			continue
		}

		e.ctx = Reason{Kind: ReasonUpgradeDependency, Cause: label(pv)}

		if e.markInstall(ps, true, depth+1, false) {
			continue
		}

		e.ctx = Reason{Kind: ReasonBrokenDependency, Cause: label(pv)}

		if !e.markDelete(ps, depth+1, false) {
			failed = true

			if !propagate && !fromUser {
				break
			}
		} else if propagate {
			ps.protect = true
		}
	}

	return !failed
}

// installDependencies is apt's MarkInstall_InstallDependencies: install the
// best candidate of every dependency group that is not met.
func (e *engine) installDependencies(pv *pkg, depth int, w *installWork, propagate, fromUser bool) bool {
	failed := false

	saved := e.ctx
	defer func() { e.ctx = saved }()

	for _, g := range w.toInstall {
		e.ctx = Reason{Kind: ReasonDependency, Cause: label(pv), Relation: g.alts.String()}

		found := false

		for i := range g.alts {
			if e.altOK(g, i, whenInstall) {
				found = true

				break
			}
		}

		if found && !propagate {
			continue
		}

		if found {
			// Propagate the protection to the one package that meets it.
			sols := e.solutions(g, selBoth, false)
			if len(sols) != 1 {
				continue
			}

			ip := e.state(sols[0].slot)
			if ip.protect {
				continue
			}

			ip.protect = true

			if !e.markInstall(ip, true, depth+1, false) {
				failed = true
			}

			continue
		}

		sols := e.solutions(g, selCandidate, true)

		for _, v := range sols {
			ip := e.state(v.slot)
			if ip.cand != v {
				continue
			}

			if propagate && len(sols) == 1 {
				if !e.markInstall(ip, false, depth+1, false) {
					continue
				}

				ip.protect = true
			}

			if !e.markInstall(ip, true, depth+1, false) {
				continue
			}

			found = true

			break
		}

		if !found {
			failed = true

			if !propagate && !fromUser {
				break
			}
		}
	}

	return !failed
}

// markInstall is apt's MarkInstall: select the candidate of a package and, with
// autoInst, everything it needs, removing or upgrading what it clashes with.
// It reports false when the package cannot be installed.
func (e *engine) markInstall(s *pstate, autoInst bool, depth int, fromUser bool) bool {
	if e.tick() {
		return false
	}

	// A protected package kept at its candidate is here to protect its
	// dependencies: no state changes.
	keptProtector := s.protect && s.mode == modeKeep && s.cand != nil && s.cand == s.cur
	if !keptProtector && !e.modeChangeOK(modeInstall, s, depth, fromUser) {
		return false
	}

	if s.cand == nil {
		return false
	}

	if !s.protect && !e.instBroken(s) {
		if s.cand == s.cur {
			if s.inst == nil {
				return e.markKeep(s, fromUser, depth+1)
			}

			return true
		} else if s.mode == modeInstall {
			return true
		}
	}

	if !e.isInstallOK(s, autoInst, fromUser) {
		return false
	}

	if fromUser && !e.stateChange(s, fromUser) {
		return false
	}

	failEarly := !s.protect && !fromUser
	hasFailed := false

	var w installWork

	pv := s.cand

	if autoInst {
		w.toInstall, w.toRemove = e.collectDependencies(s, pv)

		if !e.removeConflictsIfNotUpgradeable(pv, depth, &w, s.protect, fromUser) {
			if failEarly {
				return false
			}

			hasFailed = true
		}

		e.collectReverseDepends(s, pv, &w)
	}

	if !fromUser && !e.stateChange(s, fromUser) {
		return false
	}

	if !autoInst {
		return !hasFailed
	}

	propagate := s.protect
	if !propagate {
		s.protect = true

		defer func() { s.protect = false }()
	}

	if s.cand != nil {
		e.upgradeOtherBinaries(s, s.cand, depth)
	}

	if !e.upgradeOrRemoveConflicts(pv, depth, &w, propagate, fromUser) {
		if failEarly {
			e.discardInstall(s)

			return false
		}

		hasFailed = true
	}

	if !e.installDependencies(pv, depth, &w, propagate, fromUser) {
		if failEarly {
			e.discardInstall(s)

			return false
		}

		hasFailed = true
	}

	for _, r := range w.delayed {
		saved := e.ctx
		e.ctx = w.delayedWhy[r]
		ok := e.markDelete(r, depth, false)
		e.ctx = saved

		if !ok {
			if failEarly {
				e.discardInstall(s)

				return false
			}

			hasFailed = true
		}
	}

	return !hasFailed
}
