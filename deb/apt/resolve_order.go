package apt

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
)

// This file is the part of apt that decides in which order a plan is carried
// out and whether it can be: pkgOrderList (orderlist.cc), the unpack and
// configure logic of pkgPackageManager (packagemanager.cc) and the checks of
// pkgSimulate that make "apt-get -s" fail on a plan whose steps cannot be
// put in a working order. A plan whose resolver result is fine can still
// fail here: two packages that Pre-Depend on each other leave no package that
// can be configured first.
//
// The port is of the default configuration (APT::Immediate-Configure on,
// PackageManager::Configure "smart", PackageManager::UnpackAll on). The
// reverse dependencies the ordering reads are those of the installed and the
// planned versions, which are the only ones apt's checks look at.

// ErrOrderLoop is matched by a [*OrderError] for a plan whose packages cannot
// be configured in any order, such as a Pre-Depends cycle.
var ErrOrderLoop = errors.New("apt: dependency cycle: packages cannot be configured")

// ErrOrderRemoval is matched by a [*OrderError] for a plan that would have to
// remove an essential package temporarily to break a Conflicts or
// Pre-Depends loop.
var ErrOrderRemoval = errors.New("apt: plan needs a temporary removal that apt refuses")

// ErrOrderSimulation is matched by a [*OrderError] for a plan whose steps,
// replayed in the order apt chooses, leave a Conflicts violated or configure
// a package whose dependencies do not hold yet.
var ErrOrderSimulation = errors.New("apt: plan steps break a dependency")

// OrderKind says why a plan could not be ordered.
type OrderKind uint8

const (
	// OrderLoop: a package cannot be configured because its Pre-Depends
	// form a cycle ("Couldn't configure X, probably a dependency cycle").
	OrderLoop OrderKind = iota
	// OrderUnconfigured: packages were left unconfigured.
	OrderUnconfigured
	// OrderEssentialRemoval: an essential (or depended-on-by-essential)
	// package would have to be removed temporarily.
	OrderEssentialRemoval
	// OrderEarlyRemove: a package could not be removed or deconfigured to
	// make way for another.
	OrderEarlyRemove
	// OrderSimulation: replaying the steps broke a dependency.
	OrderSimulation
)

// String names the kind.
func (k OrderKind) String() string {
	switch k {
	case OrderLoop:
		return "loop"
	case OrderUnconfigured:
		return "unconfigured"
	case OrderEssentialRemoval:
		return "essential removal"
	case OrderEarlyRemove:
		return "early remove"
	case OrderSimulation:
		return "simulation"
	default:
		return "unknown"
	}
}

// OrderError reports a plan the unpack and configure steps cannot carry out.
// It matches [ErrOrderLoop], [ErrOrderRemoval] or [ErrOrderSimulation]
// according to its Kind.
type OrderError struct {
	// Kind says what went wrong.
	Kind OrderKind
	// Package is the package the failure is about, as "name:arch".
	Package string
	// Cycle lists the packages being configured when the failure came up,
	// from the first appearance of Package to Package again: for two
	// packages that Pre-Depend on each other, "a b a".
	Cycle []string
	// Detail is apt's wording of the failure.
	Detail string
}

// Error gives apt's message and the cycle.
func (e *OrderError) Error() string {
	msg := "apt: " + e.Detail
	if len(e.Cycle) > 1 {
		msg += " (" + strings.Join(e.Cycle, " -> ") + ")"
	}

	return msg
}

// Is matches the sentinel of the Kind.
func (e *OrderError) Is(target error) bool {
	switch target {
	case ErrOrderLoop:
		return e.Kind == OrderLoop || e.Kind == OrderUnconfigured
	case ErrOrderRemoval:
		return e.Kind == OrderEssentialRemoval || e.Kind == OrderEarlyRemove
	case ErrOrderSimulation:
		return e.Kind == OrderSimulation
	default:
		return false
	}
}

// orderFlag is a per-package flag of the order list.
type orderFlag uint16

const (
	ofAdded orderFlag = 1 << iota
	ofAddPending
	ofImmediate
	ofLoop
	ofUnPacked
	ofConfigured
	ofRemoved
	ofInList
)

// ofStates are the flags that say a package was dealt with.
const ofStates = ofUnPacked | ofConfigured | ofRemoved

// maxOrderLoops is apt's APT::pkgPackageManager::MaxLoopCount.
const maxOrderLoops = 5000

// depFn selects the dependency function pkgOrderList applies while it walks.
type depFn uint8

const (
	fnNone depFn = iota
	fnUnPackCrit
	fnUnPackPreD
	fnUnPackPre
	fnUnPackDep
	fnConfigure
	fnRemove
)

// orderDep is one dependency record as apt stores it: one alternative of a
// group, or a Conflicts or Breaks relation, forwards or as a reverse
// dependency of its target.
type orderDep struct {
	g   *depGroup
	i   int
	rev bool
}

func (d orderDep) rel() *deb.Relation { return &d.g.alts[d.i] }

// orderEnv is what the order lists of one plan share.
type orderEnv struct {
	e *engine
	// fwd caches the critical dependency records of a version.
	fwd map[*pkg][]orderDep
	// idx is the cache's reverse dependency index; rev caches the records
	// of a package that revFor resolved.
	idx *revIndex
	rev map[string][]orderDep
}

func newOrderEnv(e *engine) *orderEnv {
	return &orderEnv{
		e:   e,
		fwd: make(map[*pkg][]orderDep),
		idx: e.c.revIndex(),
		rev: make(map[string][]orderDep),
	}
}

// revFor lists the records that name a package, in apt's order, those of
// installed packages only: the ordering never acts on the others.
func (env *orderEnv) revFor(key string) []orderDep {
	if out, ok := env.rev[key]; ok {
		return out
	}

	var out []orderDep

	env.idx.list(key, func(p *pkg) bool { return env.e.c.installed[p.slot] != nil }, func(r revRec) {
		groups := env.e.depsOf(r.owner)
		if r.kind >= kindRecommends {
			groups = env.e.softOf(r.owner)
		}

		out = append(out, orderDep{g: &groups[r.gi], i: int(r.alt), rev: true})
	})

	env.rev[key] = out

	return out
}

// forward lists the dependency records of a version in apt's order: the
// alternatives of a group are separate records.
func (env *orderEnv) forward(v *pkg) []orderDep {
	if out, ok := env.fwd[v]; ok {
		return out
	}

	groups := env.e.depsOf(v)

	var out []orderDep

	for gi := range groups {
		g := &groups[gi]
		if g.negative() {
			out = append(out, orderDep{g: g})

			continue
		}

		for i := range g.alts {
			out = append(out, orderDep{g: g, i: i})
		}
	}

	env.fwd[v] = out

	return out
}

// orderer is pkgOrderList.
type orderer struct {
	env   *orderEnv
	e     *engine
	flags map[string]orderFlag
	list  []string
	out   []string
	depth int

	primary, secondary, revDepends, remove depFn
}

func newOrderer(env *orderEnv) *orderer {
	return &orderer{env: env, e: env.e, flags: make(map[string]orderFlag)}
}

func (o *orderer) is(key string, f orderFlag) bool { return o.flags[key]&f != 0 }
func (o *orderer) set(key string, f orderFlag)     { o.flags[key] |= f }
func (o *orderer) clear(key string, f orderFlag)   { o.flags[key] &^= f }

// setState sets one of the states, clearing the others (apt's
// Flag(Pkg, State, States)).
func (o *orderer) setState(key string, f orderFlag) {
	o.flags[key] = o.flags[key]&^ofStates | f
}

// isNow reports a package nothing was done to yet.
func (o *orderer) isNow(key string) bool { return o.flags[key]&ofStates == 0 }

func (o *orderer) wipe(mask orderFlag) {
	for k := range o.flags {
		o.flags[k] &^= mask
	}
}

// target is the package a record names.
func (o *orderer) target(d orderDep) string {
	return o.e.targetSlot(d.rel(), o.e.ownerArch(d.g.owner))
}

// score orders the packages: higher scores go first.
func (o *orderer) score(key string) int {
	s := o.e.state(key)
	if s.mode == modeDelete {
		return 100
	}

	if s.inst == nil {
		return -1
	}

	sc := 0
	if o.e.essential(key) {
		sc += 200
	}

	if o.is(key, ofImmediate) {
		sc += 10
	}

	for _, g := range o.e.depsOf(s.inst) {
		if g.kind == kindPreDepends {
			sc += 50

			break
		}
	}

	prio := [...]int{0, 5, 4, 3, 1, 0}
	if p := enumPriority(s.inst); p <= 5 {
		sc += prio[p]
	}

	return sc
}

// sortA is OrderCompareA: by score, then by name.
func (o *orderer) sortA() {
	scores := make(map[string]int, len(o.list))
	for _, k := range o.list {
		scores[k] = o.score(k)
	}

	slices.SortFunc(o.list, func(a, b string) int {
		if scores[a] != scores[b] {
			return scores[b] - scores[a]
		}

		if c := strings.Compare(keyName(a), keyName(b)); c != 0 {
			return c
		}

		return strings.Compare(a, b)
	})
}

// doRun rebuilds the list by visiting every package.
func (o *orderer) doRun() {
	o.depth = 0
	o.wipe(ofAdded | ofAddPending | ofLoop | ofInList)

	for _, k := range o.list {
		o.set(k, ofInList)
	}

	old := o.list
	o.out = make([]string, 0, len(old))

	for _, k := range old {
		o.visitNode(k)
	}

	o.list = o.out
}

// orderUnpack is OrderUnpack: the four passes that settle the unpack order.
func (o *orderer) orderUnpack() {
	o.primary, o.secondary, o.revDepends, o.remove = fnUnPackCrit, fnConfigure, fnUnPackDep, fnRemove
	o.sortA()
	o.doRun()

	o.secondary = fnNone
	o.doRun()

	o.revDepends, o.remove = fnNone, fnNone
	o.doRun()

	o.primary = fnUnPackPre
	o.doRun()
}

// dispatch applies a dependency function to a list of records.
func (o *orderer) dispatch(fn depFn, deps []orderDep) {
	switch fn {
	case fnNone:
	case fnUnPackCrit:
		o.depUnPackCrit(deps)
	case fnUnPackPreD:
		o.depUnPackPreD(deps)
	case fnUnPackPre:
		o.depUnPackPre(deps)
	case fnUnPackDep:
		o.depUnPackDep(deps)
	case fnConfigure:
		o.depConfigure(deps)
	case fnRemove:
		o.depRemove(deps)
	}
}

func (o *orderer) visitDeps(fn depFn, v *pkg) {
	if fn == fnNone || v == nil {
		return
	}

	o.dispatch(fn, o.env.forward(v))
}

func (o *orderer) visitRDeps(fn depFn, key string) {
	if fn == fnNone {
		return
	}

	o.dispatch(fn, o.env.revFor(key))
}

func (o *orderer) visitRProvides(fn depFn, v *pkg) {
	if fn == fnNone || v == nil {
		return
	}

	for i := range v.Provides {
		rel := deb.Relation{Name: v.Provides[i].Name}
		o.dispatch(fn, o.env.revFor(o.e.targetSlot(&rel, o.e.ownerArch(v))))
	}
}

// visitProvides visits the packages that can satisfy a record. A negative
// record visits the packages to be removed first.
func (o *orderer) visitProvides(d orderDep) {
	targets := o.e.allTargets(d.g, d.i)
	neg := d.g.negative()

	for _, v := range targets {
		s := o.e.state(v.slot)
		if neg && s.mode != modeDelete {
			continue
		}

		if s.mode == modeKeep {
			continue
		}

		if !neg && s.inst != v {
			continue
		}

		if neg && s.cur != v {
			continue
		}

		o.visitNode(v.slot)
	}

	if !neg {
		return
	}

	for _, v := range targets {
		s := o.e.state(v.slot)
		if s.mode == modeDelete || s.mode == modeKeep || s.cur != v {
			continue
		}

		o.visitNode(v.slot)
	}
}

// visitNode is the recursive director of the ordering.
func (o *orderer) visitNode(key string) {
	if o.is(key, ofAdded) || o.is(key, ofAddPending) || !o.is(key, ofInList) {
		return
	}

	o.depth++
	o.set(key, ofAddPending)

	old := o.primary
	if o.is(key, ofImmediate) && o.primary != fnUnPackPre {
		o.primary = fnUnPackPreD
	}

	if o.isNow(key) {
		s := o.e.state(key)

		if s.mode != modeDelete {
			o.visitDeps(o.primary, s.inst)
			o.visitRDeps(o.primary, key)
			o.visitRProvides(o.primary, s.cur)
			o.visitRProvides(o.primary, s.inst)

			o.visitRDeps(o.revDepends, key)
			o.visitRProvides(o.revDepends, s.cur)
			o.visitRProvides(o.revDepends, s.inst)

			o.visitDeps(o.secondary, s.inst)
			o.visitRDeps(o.secondary, key)
			o.visitRProvides(o.secondary, s.cur)
			o.visitRProvides(o.secondary, s.inst)
		} else {
			o.visitRDeps(o.remove, key)
			o.visitRProvides(o.remove, s.cur)
		}
	}

	if !o.is(key, ofAdded) {
		o.clear(key, ofAddPending)
		o.set(key, ofAdded)
		o.out = append(o.out, key)
	}

	o.primary = old
	o.depth--
}

// checkDep reports whether a record holds once every step done so far and
// the packages ordered before it have taken effect.
func (o *orderer) checkDep(d orderDep) bool {
	parent := d.g.owner.slot
	target := o.target(d)
	neg := d.g.negative()

	for _, v := range o.e.allTargets(d.g, d.i) {
		key := v.slot
		s := o.e.state(key)

		if o.is(key, ofAdded) || (o.is(key, ofAddPending) && d.rev) {
			if s.inst != v {
				continue
			}
		} else if s.cur != v {
			continue
		}

		if neg {
			return false
		}

		// Ignore provides by older versions of this package.
		if ((!d.rev && key == parent) || (d.rev && key == target)) && s.inst != v {
			continue
		}

		return true
	}

	// Of the negative records only Conflicts is satisfied by finding
	// nothing: a Breaks that matches no version counts as unsatisfied.
	return d.g.kind == kindConflicts
}

// depUnPackCrit is the critical unpack ordering: Conflicts and Pre-Depends.
func (o *orderer) depUnPackCrit(deps []orderDep) {
	for _, d := range deps {
		if d.rev {
			if d.g.kind != kindConflicts {
				continue
			}

			if o.e.state(d.g.owner.slot).cur != d.g.owner {
				continue
			}

			if o.checkDep(d) {
				continue
			}

			o.visitNode(d.g.owner.slot)

			continue
		}

		if !d.g.negative() && d.g.kind != kindPreDepends {
			continue
		}

		target := o.target(d)

		if o.checkDep(d) && (!o.is(target, ofAddPending) || d.g.kind != kindPreDepends) {
			continue
		}

		if o.is(target, ofAdded) || o.is(target, ofAddPending) {
			continue
		}

		old := o.primary
		if d.g.kind == kindPreDepends {
			o.primary = fnUnPackPreD
		}

		o.visitProvides(d)
		o.primary = old
	}
}

// depUnPackPreD is the critical unpack ordering that also wants the package
// configurable once unpacked.
func (o *orderer) depUnPackPreD(deps []orderDep) {
	if len(deps) > 0 && deps[0].rev {
		o.depUnPackCrit(deps)

		return
	}

	for _, d := range deps {
		if !d.g.critical() {
			continue
		}

		target := o.target(d)

		if o.checkDep(d) && (!o.is(target, ofAddPending) || d.g.kind != kindPreDepends) {
			continue
		}

		if o.is(target, ofAdded) || o.is(target, ofAddPending) {
			continue
		}

		o.visitProvides(d)
	}
}

// depUnPackPre is the last pass: Pre-Depends, and Depends at the lowest
// depth or of an immediately configured package.
func (o *orderer) depUnPackPre(deps []orderDep) {
	if len(deps) > 0 && deps[0].rev {
		return
	}

	for _, d := range deps {
		if d.g.kind != kindPreDepends {
			if d.g.kind != kindDepends {
				continue
			}

			if o.depth == 1 && !o.is(d.g.owner.slot, ofImmediate) {
				continue
			}
		}

		target := o.target(d)

		if o.checkDep(d) && !o.is(target, ofAddPending) {
			continue
		}

		if o.is(target, ofAdded) || o.is(target, ofAddPending) {
			continue
		}

		o.visitProvides(d)
	}
}

// depUnPackDep orders the packages an unpack would break before it. It is
// only ever applied to a reverse dependency list (apt's forward branch of it
// is never reached), so the records are the dependents of the package.
func (o *orderer) depUnPackDep(deps []orderDep) {
	for _, d := range deps {
		if !d.rev || !d.g.critical() {
			continue
		}

		parent := d.g.owner.slot
		if cur := o.e.state(parent).cur; cur == nil || cur != d.g.owner {
			continue
		}

		if o.checkDep(d) {
			continue
		}

		o.visitNode(parent)
	}
}

// depConfigure orders by Depends only.
func (o *orderer) depConfigure(deps []orderDep) {
	if len(deps) > 0 && deps[0].rev {
		return
	}

	for _, d := range deps {
		if d.g.kind == kindDepends {
			o.visitProvides(d)
		}
	}
}

// depRemove looks, for each package that depends on one about to be
// removed, for a way to keep it working: another installed provider, a
// provider to be installed (visited first) or its own upgrade.
func (o *orderer) depRemove(deps []orderDep) {
	if len(deps) > 0 && !deps[0].rev {
		return
	}

	for _, broken := range deps {
		if broken.g.kind != kindDepends && broken.g.kind != kindPreDepends {
			continue
		}

		bp := broken.g.owner.slot
		bs := o.e.state(bp)

		if bs.cur == nil || o.is(bp, ofAddPending) || o.is(bp, ofAdded) {
			continue
		}

		if bs.mode == modeDelete {
			o.visitNode(bp)

			return
		}

		groups := o.e.depsOf(bs.cur)

		for gi := range groups {
			g := &groups[gi]
			if g.kind != kindDepends && g.kind != kindPreDepends {
				continue
			}

			if g != broken.g {
				continue
			}

			if o.replacementReady(g) {
				break
			}

			if o.visitReplacement(g, bp) {
				break
			}

			o.visitNode(bp)

			break
		}
	}
}

// replacementReady reports an installed package that stays and meets the
// group.
func (o *orderer) replacementReady(g *depGroup) bool {
	for i := range g.alts {
		for _, v := range o.e.allTargets(g, i) {
			s := o.e.state(v.slot)
			if s.cur == v && s.mode != modeDelete {
				return true
			}
		}
	}

	return false
}

// visitReplacement visits the first planned version that meets the group,
// making it immediate when the broken package is.
func (o *orderer) visitReplacement(g *depGroup, broken string) bool {
	for i := range g.alts {
		for _, v := range o.e.allTargets(g, i) {
			s := o.e.state(v.slot)
			if s.mode != modeInstall || s.inst != v || o.is(v.slot, ofAddPending) {
				continue
			}

			if o.is(broken, ofImmediate) {
				o.set(v.slot, ofImmediate)
			}

			o.visitNode(v.slot)

			return true
		}
	}

	return false
}

// opKind is a step of the carried-out plan.
type opKind uint8

const (
	opInstall opKind = iota
	opConfigure
	opRemove
)

// orderOp is one step apt hands to dpkg: unpack, configure or remove.
type orderOp struct {
	kind opKind
	key  string
}

// packageManager is pkgPackageManager with pkgSimulate's recording of the
// steps.
type packageManager struct {
	env *orderEnv
	e   *engine
	l   *orderer
	ops []orderOp
	// stack lists the packages being unpacked or configured, innermost
	// last, to name the cycle of a failure.
	stack []string
}

func newPackageManager(e *engine) *packageManager {
	env := newOrderEnv(e)

	return &packageManager{env: env, e: e, l: newOrderer(env)}
}

// fail builds an OrderError for key with the current stack as the cycle.
func (m *packageManager) fail(kind OrderKind, key, format string, args ...any) *OrderError {
	var cycle []string
	if i := slices.Index(m.stack, key); i >= 0 {
		cycle = slices.Clone(m.stack[i:])
	}

	if len(cycle) == 0 || cycle[len(cycle)-1] != key {
		cycle = append(cycle, key)
	}

	return &OrderError{Kind: kind, Package: key, Cycle: cycle, Detail: fmt.Sprintf(format, args...)}
}

func (m *packageManager) install(key string)   { m.ops = append(m.ops, orderOp{opInstall, key}) }
func (m *packageManager) configure(key string) { m.ops = append(m.ops, orderOp{opConfigure, key}) }
func (m *packageManager) removeOp(key string)  { m.ops = append(m.ops, orderOp{opRemove, key}) }

// immediateAdd flags the targets of the Depends and Pre-Depends of the
// planned (planned true) or the installed version of a package for
// immediate configuration, and theirs in turn.
func (m *packageManager) immediateAdd(key string, planned bool) {
	s := m.e.state(key)

	v := s.cur
	if planned {
		v = s.inst
	}

	if v == nil {
		return
	}

	for _, d := range m.env.forward(v) {
		if d.g.kind != kindDepends && d.g.kind != kindPreDepends {
			continue
		}

		t := m.l.target(d)
		if m.l.is(t, ofImmediate) {
			continue
		}

		m.l.set(t, ofImmediate)
		m.immediateAdd(t, planned)
	}
}

// createOrderList fills the list with the packages that change and flags
// the essential ones, and what they depend on, for immediate configuration.
func (m *packageManager) createOrderList() {
	for _, k := range m.e.keys() {
		s := m.e.state(k)
		if len(m.e.c.slots[k]) == 0 {
			continue
		}

		if m.e.essential(k) {
			m.l.set(k, ofImmediate)
			m.immediateAdd(k, true)
			m.immediateAdd(k, false)
		}

		if s.mode == modeKeep || s.inst == s.cur {
			continue
		}

		m.l.list = append(m.l.list, k)
	}
}

// groupMates lists the other architectures of a package's name.
func (m *packageManager) groupMates(key string) []string {
	var out []string

	for _, k := range m.e.sameGroup(keyName(key)) {
		if k != key {
			out = append(out, k)
		}
	}

	return out
}

// nonLooping runs one of the smart steps on a dependency while marking the
// package as looping, so that a cycle does not recurse for ever.
func (m *packageManager) nonLooping(action opKind, imm bool, key, dep string, depth int, pkgLoop bool, bad, changed *bool) error {
	if !pkgLoop {
		m.l.set(key, ofLoop)
	}

	var err error

	switch action {
	case opConfigure:
		err = m.smartConfigure(dep, depth+1)
	default:
		err = m.smartUnPack(dep, imm, depth+1)
	}

	if !pkgLoop {
		m.l.clear(key, ofLoop)
	}

	if err != nil {
		return err
	}

	if bad != nil {
		*bad = false
	}

	if changed != nil && !m.l.is(dep, ofLoop) {
		*changed = true
	}

	return nil
}

// okNow reports the installed version v with nothing done to it yet.
func (m *packageManager) okNow(v *pkg) bool {
	s := m.e.state(v.slot)

	return s.cur == v && m.l.isNow(v.slot)
}

// smartUnPack puts the system in a state where the package can be unpacked
// and unpacks it; immediate also configures it.
func (m *packageManager) smartUnPack(key string, immediate bool, depth int) error {
	m.stack = append(m.stack, key)
	defer func() { m.stack = m.stack[:len(m.stack)-1] }()

	pkgLoop := m.l.is(key, ofLoop)
	s := m.e.state(key)
	inst := s.inst
	somethingBad := false
	couldBeTemporaryRemoved := depth != 0 && !m.l.is(key, ofRemoved)

	if inst == nil {
		return m.fail(OrderLoop, key, "Internal error, %s has no version to unpack", key)
	}

	for i := 0; ; i++ {
		changed := false
		groups := m.e.depsOf(inst)

		for gi := range groups {
			g := &groups[gi]

			switch {
			case g.kind == kindPreDepends:
				bad, err := m.preDepends(key, g, depth, pkgLoop, &changed)
				if err != nil {
					return err
				}

				if bad {
					somethingBad = true
				}
			case g.negative():
				bad, err := m.conflictsOf(key, g, depth, pkgLoop, &changed)
				if err != nil {
					return err
				}

				if bad {
					somethingBad = true
				}
			}
		}

		if i > maxOrderLoops {
			return m.fail(OrderLoop, key, "MaxLoopCount reached in SmartUnPack for %s, aborting", key)
		}

		if !changed {
			break
		}
	}

	if somethingBad {
		return m.fail(OrderLoop, key, "Couldn't configure %s, probably a dependency cycle.", key)
	}

	if couldBeTemporaryRemoved && m.l.is(key, ofRemoved) {
		return nil
	}

	if err := m.checkRConflicts(key, inst); err != nil {
		return err
	}

	if pkgLoop {
		return nil
	}

	m.l.setState(key, ofUnPacked)

	if immediate && inst.MultiArchSame() {
		if err := m.unpackSameGroup(key, s, depth); err != nil {
			return err
		}
	} else if inst != s.cur {
		m.install(key)
	}

	if immediate {
		// An immediate configuration that fails is not an error here: the
		// final configuration pass picks the package up.
		_ = m.smartConfigure(key, depth+1)
	}

	return nil
}

// unpackSameGroup is the lockstep unpack of Multi-Arch: same packages: the
// installed architectures first, then the others.
func (m *packageManager) unpackSameGroup(key string, s *pstate, depth int) error {
	installed := s.cur != nil
	mates := m.groupMates(key)

	if installed && s.inst != s.cur {
		m.install(key)
	}

	for _, p := range mates {
		ps := m.e.state(p)
		if ps.cur == nil || m.l.is(p, ofUnPacked) || ps.inst == nil || ps.cur == ps.inst {
			continue
		}

		if err := m.smartUnPack(p, false, depth+1); err != nil {
			return err
		}
	}

	if !installed {
		m.install(key)
	}

	for _, p := range mates {
		ps := m.e.state(p)
		if ps.cur != nil || m.l.is(p, ofUnPacked) || m.l.is(p, ofConfigured) || ps.inst == nil || ps.cur == ps.inst {
			continue
		}

		if err := m.smartUnPack(p, false, depth+1); err != nil {
			return err
		}
	}

	return nil
}

// preDepends makes one Pre-Depends group of the package met; bad is true when
// it cannot be.
func (m *packageManager) preDepends(key string, g *depGroup, depth int, pkgLoop bool, changed *bool) (bool, error) {
	bad := true

	// Easy targets: a package that is already fine.
	for i := range g.alts {
		for _, v := range m.e.allTargets(g, i) {
			if m.okNow(v) {
				bad = false

				break
			}
		}

		if !bad {
			break
		}
	}

	// Something that could be unpacked or configured.
	for i := 0; bad && i < len(g.alts); i++ {
		for _, v := range m.e.allTargets(g, i) {
			dk := v.slot
			ds := m.e.state(dk)

			if ds.inst != v || ds.mode == modeKeep {
				continue
			}

			if m.l.is(dk, ofConfigured) {
				bad = false

				break
			}

			if !m.l.is(dk, ofUnPacked) {
				// Two packages that Pre-Depend on each other cannot be
				// handled; something else may still satisfy the group.
				if m.l.is(dk, ofLoop) && pkgLoop {
					continue
				}

				if err := m.nonLooping(opInstall, true, key, dk, depth, pkgLoop, &bad, changed); err != nil {
					return false, err
				}
			} else if err := m.nonLooping(opConfigure, false, key, dk, depth, pkgLoop, &bad, changed); err != nil {
				return false, err
			}

			break
		}
	}

	return bad, nil
}

// conflictsOf removes or deconfigures, or unpacks past, what a Conflicts or
// Breaks relation of the package to unpack names.
func (m *packageManager) conflictsOf(key string, g *depGroup, depth int, pkgLoop bool, changed *bool) (bool, error) {
	bad := false

	for _, v := range m.e.allTargets(g, 0) {
		ck := v.slot
		cs := m.e.state(ck)

		if cs.cur != v || !m.l.isNow(ck) || m.l.is(ck, ofRemoved) {
			continue
		}

		if m.l.is(ck, ofLoop) && pkgLoop {
			if err := m.earlyRemove(ck, g); err != nil {
				return false, err
			}

			bad = true

			continue
		}

		if cs.mode == modeDelete {
			m.smartRemove(ck)

			continue
		}

		// A plain unpack of the conflicting package, when it is to change,
		// avoids a temporary removal; when that fails, remove or
		// deconfigure it, unless it or this package went in the meantime.
		if err := m.nonLooping(opInstall, false, key, ck, depth, pkgLoop, nil, changed); err == nil {
			continue
		}

		if m.l.is(ck, ofRemoved) || m.l.is(key, ofRemoved) {
			continue
		}

		if err := m.earlyRemove(ck, g); err != nil {
			return false, err
		}
	}

	return bad, nil
}

// smartConfigure puts the system in a state where the package can be
// configured and configures it.
func (m *packageManager) smartConfigure(key string, depth int) error {
	m.stack = append(m.stack, key)
	defer func() { m.stack = m.stack[:len(m.stack)-1] }()

	pkgLoop := m.l.is(key, ofLoop)
	s := m.e.state(key)

	inst := s.inst
	if inst == nil {
		return m.fail(OrderLoop, key, "Internal error, %s has no version to configure", key)
	}

	var (
		need    []*depGroup
		bad     bool
		changed bool
	)

	for i := 0; ; i++ {
		changed = false
		groups := m.e.depsOf(inst)

		for gi := range groups {
			g := &groups[gi]
			if g.kind != kindDepends && g.kind != kindPreDepends {
				continue
			}

			var err error

			bad, err = m.configureGroup(key, g, depth, pkgLoop, &changed)
			if err != nil {
				return err
			}

			if bad {
				need = append(need, g)
			}
		}

		if i > maxOrderLoops {
			return m.fail(OrderLoop, key, "MaxLoopCount reached in SmartUnPack (1) for %s, aborting", key)
		}

		if !changed {
			break
		}
	}

	bad = false

	for i := 0; ; i++ {
		changed = false

		for _, g := range need {
			var err error

			bad, err = m.configureUnpacked(key, g, depth, pkgLoop, &changed)
			if err != nil {
				return err
			}
		}

		if i > maxOrderLoops {
			return m.fail(OrderLoop, key, "MaxLoopCount reached in SmartUnPack (2) for %s, aborting", key)
		}

		if !changed {
			break
		}
	}

	if bad {
		return m.fail(OrderLoop, key, "Could not configure '%s'. ", key)
	}

	if err := m.checkRBreaks(key, inst); err != nil {
		return err
	}

	if pkgLoop {
		return nil
	}

	if m.l.is(key, ofConfigured) {
		return m.fail(OrderLoop, key, "Internal configure error on '%s'.", key)
	}

	m.configure(key)
	m.l.setState(key, ofConfigured)

	if inst.MultiArchSame() && !m.l.is(key, ofImmediate) {
		for _, p := range m.groupMates(key) {
			ps := m.e.state(p)
			if m.l.is(p, ofConfigured) || !m.l.is(p, ofUnPacked) || ps.inst == nil || ps.cur == ps.inst {
				continue
			}

			if err := m.smartConfigure(p, depth+1); err != nil {
				return err
			}
		}
	}

	if !m.l.is(key, ofConfigured) {
		return m.fail(OrderLoop, key, "Could not configure '%s'. ", key)
	}

	return nil
}

// configureGroup is the first pass of SmartConfigure over one group: it
// unpacks what is missing and reports whether the group still needs a
// configured package.
func (m *packageManager) configureGroup(key string, g *depGroup, depth int, pkgLoop bool, changed *bool) (bool, error) {
	bad := true

	for i := range g.alts {
		for _, v := range m.e.allTargets(g, i) {
			dk := v.slot
			ds := m.e.state(dk)

			if ds.cur == v && m.l.isNow(dk) && !m.l.is(dk, ofRemoved) {
				bad = false

				break
			}

			if ds.inst != v || !m.l.isNow(dk) {
				continue
			}

			if pkgLoop && m.l.is(dk, ofUnPacked) {
				bad = false
			}
		}

		if !bad {
			break
		}
	}

	if !bad {
		return false, nil
	}

	for i := range g.alts {
		for _, v := range m.e.allTargets(g, i) {
			dk := v.slot
			ds := m.e.state(dk)

			if ds.cur == v && m.l.isNow(dk) && !m.l.is(dk, ofRemoved) {
				continue
			}

			if ds.inst != v || !m.l.isNow(dk) {
				continue
			}

			if pkgLoop {
				if m.l.is(dk, ofUnPacked) {
					bad = false
				}
			} else if err := m.nonLooping(opInstall, true, key, dk, depth, pkgLoop, &bad, changed); err != nil {
				return false, err
			}

			break
		}

		if !bad {
			break
		}
	}

	return bad, nil
}

// configureUnpacked is the second pass of SmartConfigure over one group: it
// configures an unpacked package the group names.
func (m *packageManager) configureUnpacked(key string, g *depGroup, depth int, pkgLoop bool, changed *bool) (bool, error) {
	bad := true

	for i := range g.alts {
		for _, v := range m.e.allTargets(g, i) {
			dk := v.slot
			if m.e.state(dk).inst != v {
				continue
			}

			if m.l.is(dk, ofUnPacked) {
				if m.l.is(dk, ofLoop) && pkgLoop {
					bad = false

					break
				}

				if err := m.nonLooping(opConfigure, false, key, dk, depth, pkgLoop, &bad, changed); err != nil {
					return false, err
				}

				break
			} else if m.l.is(dk, ofConfigured) {
				bad = false

				break
			}
		}

		if !bad {
			break
		}
	}

	return bad, nil
}

// checkRConflicts removes early the installed packages whose Conflicts match
// the version about to be unpacked.
func (m *packageManager) checkRConflicts(key string, inst *pkg) error {
	for _, d := range m.env.revFor(key) {
		if d.g.kind != kindConflicts || !m.l.isNow(key) {
			continue
		}

		parent := d.g.owner.slot
		if m.ignorable(d, key) || m.e.state(parent).cur != d.g.owner {
			continue
		}

		if !d.rel().Satisfied(inst.Version) {
			continue
		}

		if err := m.earlyRemove(parent, d.g); err != nil {
			return err
		}
	}

	return nil
}

// checkRBreaks removes, for the unpacked version, the packages whose Breaks
// match it and that are to go anyway.
func (m *packageManager) checkRBreaks(key string, inst *pkg) error {
	for _, d := range m.env.revFor(key) {
		if d.g.kind != kindBreaks {
			continue
		}

		parent := d.g.owner.slot
		if m.e.state(parent).mode != modeDelete {
			continue
		}

		if m.ignorable(d, key) || m.e.state(parent).cur != d.g.owner {
			continue
		}

		if !d.rel().Satisfied(inst.Version) {
			continue
		}

		m.smartRemove(parent)
	}

	return nil
}

// ignorable is apt's IsIgnorable: a negative relation that names its own
// package or, for Multi-Arch: same, a sibling architecture.
func (m *packageManager) ignorable(d orderDep, key string) bool {
	if !d.g.negative() || keyName(d.g.owner.slot) != keyName(key) {
		return false
	}

	return d.g.owner.slot == key || d.g.owner.MultiArchSame()
}

// earlyRemove removes a package before its time, to break a Conflicts or
// Pre-Depends loop; a package apt will not remove is an error.
func (m *packageManager) earlyRemove(key string, g *depGroup) error {
	if !m.l.isNow(key) || m.l.is(key, ofRemoved) {
		return nil
	}

	if !m.l.is(key, ofInList) {
		return m.fail(OrderEarlyRemove, key, "Internal Error, Could not early remove %s", key)
	}

	essential := m.e.essential(key)

	if s := m.e.state(key); s.cur != nil && !essential {
		for _, d := range m.env.revFor(key) {
			if (d.g.kind == kindDepends || d.g.kind == kindPreDepends) && m.e.essential(d.g.owner.slot) {
				essential = true

				break
			}
		}
	}

	// dpkg deconfigures a package a Breaks names by itself.
	if g != nil && g.kind == kindBreaks {
		return nil
	}

	if essential {
		return m.fail(OrderEssentialRemoval, key,
			"This installation run will require temporarily removing the essential package %s "+
				"due to a Conflicts/Pre-Depends loop", key)
	}

	m.smartRemove(key)

	if m.e.state(key).mode != modeDelete {
		m.l.setState(key, ofRemoved)
	}

	return nil
}

// smartRemove removes a package.
func (m *packageManager) smartRemove(key string) {
	if !m.l.isNow(key) {
		return
	}

	m.l.setState(key, ofConfigured)
	m.removeOp(key)
}

// configureAll marks every unpacked package configured: apt's default
// ("smart") configures only the packages flagged immediate as it goes and
// leaves the rest to the closing configure run.
func (m *packageManager) configureAll() {
	for _, k := range m.l.list {
		if m.l.is(k, ofUnPacked) && !m.l.is(k, ofConfigured) {
			m.l.setState(k, ofConfigured)
		}
	}
}

// orderInstall is OrderInstall: it orders the changes and walks them.
func (m *packageManager) orderInstall() error {
	m.createOrderList()
	m.l.orderUnpack()

	for _, k := range slices.Clone(m.l.list) {
		if !m.l.isNow(k) {
			continue
		}

		if m.e.state(k).mode == modeDelete {
			m.smartRemove(k)

			continue
		}

		if err := m.smartUnPack(k, m.l.is(k, ofImmediate), 0); err != nil {
			return err
		}
	}

	m.configureAll()

	for _, k := range m.l.list {
		if !m.l.is(k, ofConfigured) {
			return m.fail(OrderUnconfigured, k, "Internal error, packages left unconfigured. %s", k)
		}
	}

	return nil
}

// expand appends what dpkg is left to do, as ExpandPendingCalls does: the
// removals not done yet, then the configuration of every unpacked package.
func (m *packageManager) expand() {
	removed := make(map[string]bool)
	configured := make(map[string]bool)

	for _, op := range m.ops {
		switch op.kind {
		case opRemove:
			removed[op.key] = true
		case opConfigure:
			configured[op.key] = true
		case opInstall:
		}
	}

	for _, k := range m.e.keys() {
		if m.e.state(k).mode == modeDelete && m.e.state(k).cur != nil && !removed[k] {
			removed[k] = true
			m.ops = append(m.ops, orderOp{opRemove, k})
		}
	}

	for _, op := range slices.Clone(m.ops) {
		if op.kind == opInstall && !configured[op.key] {
			configured[op.key] = true
			m.ops = append(m.ops, orderOp{opConfigure, op.key})
		}
	}
}

// simulate replays the steps on the installed system the way pkgSimulate
// does and fails where it does: an unpack that violates a Conflicts, a
// configuration of a package whose dependencies do not hold yet.
func (m *packageManager) simulate() error {
	type saved struct {
		s    *pstate
		inst *pkg
	}

	var restore []saved

	for _, k := range m.e.keys() {
		s := m.e.state(k)
		restore = append(restore, saved{s, s.inst})
		s.inst = s.cur
	}

	defer func() {
		for _, r := range restore {
			r.s.inst = r.inst
		}
	}()

	planned := make(map[string]*pkg, len(restore))
	for _, r := range restore {
		planned[r.s.key] = r.inst
	}

	for _, op := range m.ops {
		s := m.e.state(op.key)

		switch op.kind {
		case opInstall:
			s.inst = planned[op.key]

			if err := m.checkUnpacked(); err != nil {
				return err
			}
		case opConfigure:
			if m.e.instBroken(s) {
				return &OrderError{
					Kind: OrderSimulation, Package: op.key, Cycle: []string{op.key},
					Detail: "Conf Broken " + op.key,
				}
			}
		case opRemove:
			s.inst = nil
		}
	}

	return nil
}

// checkUnpacked is the check pkgSimulate makes after each unpack: no
// Conflicts of an installed or planned version may be violated.
func (m *packageManager) checkUnpacked() error {
	for _, k := range m.e.keys() {
		s := m.e.state(k)
		if s.inst == nil {
			continue
		}

		for _, g := range m.e.depsOf(s.inst) {
			if g.kind == kindConflicts && !m.e.groupOK(&g, whenInstall) {
				return &OrderError{
					Kind: OrderSimulation, Package: k, Cycle: []string{k},
					Detail: "Fatal, conflicts violated " + keyName(k),
				}
			}
		}
	}

	return nil
}

// checkOrder runs the ordering of a finished plan and the simulation of its
// steps.
func (e *engine) checkOrder() error {
	m := newPackageManager(e)

	if err := m.orderInstall(); err != nil {
		return err
	}

	m.expand()

	if err := m.simulate(); err != nil {
		return err
	}

	for _, op := range m.ops {
		if op.kind != opConfigure {
			e.unpackSeq = append(e.unpackSeq, op.key)
		}
	}

	return nil
}
