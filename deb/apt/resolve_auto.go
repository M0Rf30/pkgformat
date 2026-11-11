package apt

import (
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
)

// This file is the part of apt's pkgDepCache that decides which
// automatically installed packages nothing needs (MarkAndSweep) and
// apt-get's DoAutomaticRemove that acts on it.

// neverMarkAutoSections are the sections of APT::Never-MarkAuto-Sections: the
// dependencies of a metapackage that is removed become manually installed.
var neverMarkAutoSections = []string{"metapackages", "tasks"}

// moveAutobitSections are the sections of APT::Move-Autobit-Sections: a
// manually installed package that moves into one gives its manual mark to the
// dependencies it brings.
var moveAutobitSections = []string{"oldlibs"}

// maxMarkChain is the depth at which the mark phase gives up, as in apt.
const maxMarkChain = 3000

// sectionIn is apt's SectionInSubTree: the section, or its last path
// component, is one of the list.
func sectionIn(section string, list []string) bool {
	if section == "" {
		return false
	}

	if i := strings.LastIndexByte(section, '/'); i >= 0 {
		section = section[i+1:]
	}

	return slices.Contains(list, section)
}

// boring reports a package the mark phase ignores: not installed and staying
// so, or installed and going.
func (e *engine) boring(s *pstate) bool {
	if s.cur == nil {
		return s.mode == modeKeep
	}

	return s.mode == modeDelete
}

// sweepResult is the outcome of the mark phase.
type sweepResult struct {
	// marked is the slots something needs.
	marked map[string]bool
	// garbage is the slots that are installed (or to be) and not needed.
	garbage map[string]bool
}

// versionOf is the version the mark phase reads of a package: the one the
// plan installs, else the installed one.
func (e *engine) versionOf(s *pstate) *pkg {
	if s.mode == modeInstall {
		return s.inst
	}

	return s.cur
}

// isRoot reports whether a package is needed for its own sake (the reasons of
// apt's MarkRequired).
func (e *engine) isRoot(s *pstate) bool {
	switch {
	case !s.auto:
		return true
	case e.essential(s.key):
		return true
	case s.cur != nil && strings.EqualFold(s.cur.Priority, "required"):
		return true
	case slices.ContainsFunc(e.cfg.neverRemove, func(re *regexp.Regexp) bool {
		return re.MatchString(keyName(s.key))
	}):
		return true
	default:
		// A protected or held package cannot change mode, which apt
		// treats as a reason to keep it.
		return s.protect || s.held
	}
}

// markWalk is the state of one run of the mark phase.
type markWalk struct {
	e        *engine
	marked   map[string]bool
	explored map[string]bool
	failed   bool
}

// sweep is apt's MarkAndSweep: mark what the packages that are needed for
// their own sake lead to, and call garbage the rest. The mark phase does not
// follow the versioned-kernel rules apt reads from APT::VersionedKernelPackages.
func (e *engine) sweep() sweepResult {
	w := &markWalk{e: e, marked: make(map[string]bool), explored: make(map[string]bool)}

	for _, key := range e.keys() {
		s := e.state(key)
		if w.marked[key] || e.boring(s) || !e.isRoot(s) {
			continue
		}

		w.mark(s, e.versionOf(s), 0)
	}

	res := sweepResult{marked: w.marked, garbage: make(map[string]bool)}
	if w.failed {
		return res
	}

	for _, key := range e.keys() {
		s := e.state(key)
		if s.cur != nil && strings.EqualFold(s.cur.Priority, "required") {
			continue
		}

		if !w.marked[key] && (s.cur != nil || s.mode == modeInstall) {
			res.garbage[key] = true
		}
	}

	return res
}

// followsSoft reports whether the mark phase follows a kind of dependency.
func (w *markWalk) follows(g *depGroup) bool {
	switch g.kind {
	case kindRecommends:
		return w.e.cfg.followRecommends
	case kindSuggests:
		return w.e.cfg.followSuggests
	default:
		return !g.negative()
	}
}

// mark is apt's MarkPackage: mark a package and, for every relation of the
// version it keeps, the packages that meet it.
func (w *markWalk) mark(s *pstate, v *pkg, depth int) {
	e := w.e

	if v == nil || w.marked[s.key] || w.failed {
		return
	}

	if e.boring(s) {
		w.explored[s.key] = true

		return
	}

	if depth > maxMarkChain {
		w.failed = true

		return
	}

	w.marked[s.key] = true

	groups := slices.Concat(e.depsOf(v), e.softOf(v))

	for gi := range groups {
		g := &groups[gi]
		if !w.follows(g) {
			continue
		}

		for i := range g.alts {
			w.markRelation(g, &g.alts[i], depth)
		}
	}
}

// markRelation marks the packages that meet one alternative of a dependency:
// the installed (or to be installed) version of the package it names, and of
// the packages that provide it, keeping for each source package only its
// highest version.
func (w *markWalk) markRelation(g *depGroup, rel *deb.Relation, depth int) {
	e := w.e
	target := e.targetSlot(rel, e.ownerArch(g.owner))

	if w.explored[target] {
		return
	}

	unsatisfied := false
	bySource := make(map[string][]*pkg)

	if ts := e.state(target); !e.boring(ts) {
		if tv := e.versionOf(ts); tv != nil {
			if rel.Satisfied(tv.Version) {
				name, _ := sourceOf(tv)
				bySource[name] = append(bySource[name], tv)
			} else {
				unsatisfied = true
			}
		}
	}

	for _, p := range e.c.providers[rel.Name] {
		ps := e.state(p.slot)
		if e.boring(ps) || e.versionOf(ps) != p {
			continue
		}

		if providesMatch(rel, p) {
			name, _ := sourceOf(p)
			bySource[name] = append(bySource[name], p)
		} else {
			unsatisfied = true
		}
	}

	names := make([]string, 0, len(bySource))
	for name, list := range bySource {
		names = append(names, name)
		bySource[name] = highestSource(list)
	}

	sort.Strings(names)

	if !unsatisfied {
		w.explored[target] = true
	}

	// Newly installed providers are not followed when an installed one
	// serves as well.
	if len(names) >= 2 {
		installed := false

		for _, list := range bySource {
			installed = installed || slices.ContainsFunc(list, func(p *pkg) bool { return e.state(p.slot).cur != nil })
		}

		if installed {
			for _, name := range names {
				bySource[name] = slices.DeleteFunc(bySource[name], func(p *pkg) bool { return e.state(p.slot).cur == nil })
			}
		}
	}

	for _, name := range names {
		for _, p := range bySource[name] {
			w.mark(e.state(p.slot), p, depth+1)
		}
	}
}

// highestSource keeps the versions built from the highest source version.
func highestSource(list []*pkg) []*pkg {
	if len(list) < 2 {
		return list
	}

	best := ""

	for i, p := range list {
		_, v := sourceOf(p)
		if i == 0 || deb.CompareVersions(v, best) > 0 {
			best = v
		}
	}

	return slices.DeleteFunc(slices.Clone(list), func(p *pkg) bool {
		_, v := sourceOf(p)

		return v != best
	})
}

// isMarked reports whether the mark phase, as of the end of the previous
// top-level action, found something that needs the package.
func (e *engine) isMarked(key string) bool { return e.marked[key] }

// refreshMarks runs the mark phase as apt does at the end of every top-level
// action, so that the next one reads what the state before it needed. Only a
// system with automatically installed packages can tell the difference, so
// others skip the work.
func (e *engine) refreshMarks() {
	if e.anyAuto {
		e.marked = e.sweep().marked
	}
}

// markAuto sets or clears the automatic mark of a package.
func (e *engine) markAuto(s *pstate, auto bool) { s.auto = auto }

// releaseDependencies is the part of apt's MarkDelete that keeps removing a
// metapackage from turning its dependencies into removal candidates: they
// become manually installed.
func (e *engine) releaseDependencies(s *pstate) {
	if s.inst == nil || !sectionIn(s.inst.Section, neverMarkAutoSections) {
		return
	}

	for _, g := range e.importantOf(s.inst) {
		if g.negative() {
			continue
		}

		for i := range g.alts {
			for _, v := range e.fromDependency(&g, i, selInstalled) {
				e.markAuto(e.state(v.slot), false)
			}
		}
	}
}

// movesAutoBit reports whether installing the version moves the manual mark of
// the package to its new dependencies: a manually installed package that
// changes from a section that is not an Autobit one into one that is.
func (e *engine) movesAutoBit(s *pstate, pv *pkg) bool {
	if pv.Section == "" || s.auto || s.cur == nil || s.cur.Section == "" || s.cur.Section == pv.Section {
		return false
	}

	return !sectionIn(s.cur.Section, moveAutobitSections) && sectionIn(pv.Section, moveAutobitSections)
}

// policyBrokenCount counts the packages that are installed or to be whose
// important dependencies, Recommends and Suggests included, do not hold.
func (e *engine) policyBrokenCount() int {
	n := 0

	for _, k := range e.keys() {
		if e.instPolicyBroken(e.state(k)) {
			n++
		}
	}

	return n
}

// autoRemove is apt-get's DoAutomaticRemove. With remove, the packages
// nothing needs are removed (or, for new installs, dropped); without it a
// package the plan would newly install for nothing is dropped, and the
// installed ones are reported in plan.AutoRemovable.
func (e *engine) autoRemove(remove bool, plan *Plan) error {
	sw := e.sweep()

	var tooMuch []*pstate

	saved := e.ctx
	e.ctx = Reason{Kind: ReasonAutoRemove}

	for _, key := range e.keys() {
		if !sw.garbage[key] {
			continue
		}

		s := e.state(key)

		switch {
		case remove:
			if s.cur != nil {
				e.markDelete(s, 0, false)
			} else {
				e.markKeep(s, false, 0)
			}
		case s.mode == modeInstall && s.cur == nil:
			// Already garbage, so it need not be installed at all.
			tooMuch = append(tooMuch, s)

			e.markDelete(s, 0, false)
		}
	}

	e.ctx = saved

	if len(tooMuch) > 0 && (e.brokenCount() != 0 || e.policyBrokenCount() != 0) {
		e.restoreNeeded(tooMuch)
	}

	if e.brokenCount() != 0 {
		return e.planError()
	}

	if !remove {
		sw = e.sweep()

		for _, key := range e.keys() {
			if s := e.state(key); sw.garbage[key] && s.mode != modeDelete && s.cur != nil {
				plan.AutoRemovable = append(plan.AutoRemovable, &s.cur.PackageInfo)
			}
		}
	}

	return nil
}

// restoreNeeded installs again a package autoRemove dropped when another
// package that is installed, or will be, depends on it after all.
func (e *engine) restoreNeeded(tooMuch []*pstate) {
	for changed := true; changed; {
		changed = false

		for i, s := range tooMuch {
			if e.neededByInstalled(s) {
				e.markInstall(s, false, 0, false)

				tooMuch = slices.Delete(tooMuch, i, i+1)
				changed = true

				break
			}
		}
	}
}

// neededByInstalled reports whether a dependency of a package that stays (or
// is about to be installed or upgraded) is for the candidate of s, or for a
// package it provides, and no installed package serves it.
func (e *engine) neededByInstalled(s *pstate) bool {
	cand := s.cand
	if cand == nil {
		return false
	}

	type target struct{ name, version string }

	targets := []target{{cand.Name, cand.Version}}
	for _, p := range cand.Provides {
		targets = append(targets, target{p.Name, p.Version})
	}

	for _, t := range targets {
		for _, r := range e.reverseImportant(t.name) {
			if !e.interesting(r.owner) {
				continue
			}

			if r.rel.Op != "" && !r.rel.Satisfied(t.version) {
				continue
			}

			if s.cur == nil && e.servedByInstalled(r.group) {
				continue
			}

			return true
		}
	}

	return false
}

// interesting reports whether a dependency of this version counts: it is the
// installed version of a package that is kept, or the candidate of one that is
// being installed or upgraded.
func (e *engine) interesting(v *pkg) bool {
	rs := e.state(v.slot)

	switch {
	case rs.cur == v:
		return rs.mode == modeKeep
	case rs.cand == v:
		return rs.mode == modeInstall && rs.inst != rs.cur
	default:
		return false
	}
}

// servedByInstalled reports an installed package that stays and meets a
// dependency group.
func (e *engine) servedByInstalled(g *depGroup) bool {
	for i := range g.alts {
		for _, v := range e.allTargets(g, i) {
			ps := e.state(v.slot)
			if ps.cur != nil && ps.inst == v {
				return true
			}
		}
	}

	return false
}

// reverseImportant lists the positive important dependencies of every version
// on a package name.
func (e *engine) reverseImportant(name string) []revAllEntry {
	if e.revAll == nil {
		e.revAll = make(map[string][]revAllEntry)

		for _, key := range e.allKeys() {
			for _, v := range e.c.slots[key] {
				groups := e.importantOf(v)
				for gi := range groups {
					g := &groups[gi]
					if g.negative() {
						continue
					}

					for i := range g.alts {
						rel := &g.alts[i]
						e.revAll[rel.Name] = append(e.revAll[rel.Name], revAllEntry{owner: v, group: g, rel: rel})
					}
				}
			}
		}
	}

	return e.revAll[name]
}
