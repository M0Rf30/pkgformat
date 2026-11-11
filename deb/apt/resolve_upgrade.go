package apt

import (
	"sort"
	"strings"
)

// This file is the port of apt's upgrade.cc: the system upgrade modes.

// installedKeys lists the slots of the installed packages, sorted.
func (e *engine) installedKeys() []string {
	keys := make([]string, 0, len(e.c.installed))
	for k := range e.c.installed {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

// eachActive calls fn for every touched package in key order, including ones
// the calls themselves touch further along, as a walk over apt's package
// table does.
func (e *engine) eachActive(fn func(s *pstate)) {
	last := ""
	started := false

	for {
		keys := e.keys()
		i := sort.SearchStrings(keys, last)

		if started && i < len(keys) && keys[i] == last {
			i++
		}

		if i >= len(keys) {
			return
		}

		last = keys[i]
		started = true

		fn(e.state(last))
	}
}

// protectHeld is the hold step of the upgrade modes: held packages stay as
// they are and the resolver may not touch them.
func (r *resolver) protectHeld() {
	e := r.e

	for _, key := range e.installedKeys() {
		s := e.state(key)
		if !s.held {
			continue
		}

		r.protect(s)
		e.markKeep(s, false, 0)
	}
}

// groupPreferred returns the slot apt prefers for a package name: the native
// architecture, else the first one.
func (e *engine) groupPreferred(keys []string) string {
	for _, k := range keys {
		if k == keyName(k) || strings.HasSuffix(k, ":"+e.native) {
			return k
		}
	}

	return keys[0]
}

// groupKeys lists the slots of a package name.
func (e *engine) groupKeys(name string) []string {
	var keys []string

	e.c.eachSlot(name, func(k string) bool {
		keys = append(keys, k)

		return true
	})

	return keys
}

// markInstalled marks every installed package for installation of its
// candidate, skipping the phased ones.
func (e *engine) markInstalled(autoInst bool) {
	for _, key := range e.installedKeys() {
		s := e.state(key)
		if e.phased(s) {
			continue
		}

		e.ctx = Reason{Kind: ReasonRequested}
		e.markInstall(s, autoInst, 0, false)
	}
}

// distUpgrade is apt's pkgDistUpgrade: mark everything installed for upgrade,
// pull in the essential packages that are missing, then let the problem
// resolver repair what that broke.
func (e *engine) distUpgrade() error {
	e.markInstalled(false)
	e.markInstalled(true)

	// Every essential package that is not installed.
	seen := make(map[string]bool)

	for _, key := range e.allKeys() {
		name := keyName(key)
		if seen[name] {
			continue
		}

		seen[name] = true

		keys := e.groupKeys(name)
		isEssential, instEssential := false, false

		for _, k := range keys {
			if !e.essential(k) {
				continue
			}

			isEssential = true

			if e.state(k).mode == modeInstall {
				instEssential = true

				break
			}
		}

		if !isEssential || instEssential {
			continue
		}

		s := e.state(e.groupPreferred(keys))
		if e.phased(s) {
			continue
		}

		e.ctx = Reason{Kind: ReasonDependency}
		e.markInstall(s, true, 0, false)
	}

	e.markInstalled(false)

	r := newResolver(e)
	r.protectHeld()

	if err := r.resolveInternal(false); err != nil {
		return err
	}

	// Revert the phased updates with keeps, on a resolver of its own.
	fix := newResolver(e)
	fix.keepPhased()

	return fix.resolveByKeep()
}

// allUpgrade is apt's pkgAllUpgradeNoNewPackages (withNew false) and
// pkgAllUpgradeWithNewPackages (withNew true).
func (e *engine) allUpgrade(withNew bool) error {
	r := newResolver(e)

	if withNew {
		for _, key := range e.installedKeys() {
			s := e.state(key)
			if s.inst == nil || s.held || e.phased(s) {
				continue
			}

			e.ctx = Reason{Kind: ReasonRequested}
			e.markInstall(s, false, 0, false)
		}

		e.eachActive(func(s *pstate) {
			if s.mode == modeInstall {
				e.ctx = Reason{Kind: ReasonRequested}
				e.markInstall(s, true, 0, false)
			}
		})

		for _, key := range e.keys() {
			if s := e.state(key); s.mode == modeDelete {
				e.markKeep(s, false, 0)
			}
		}
	} else {
		e.eachActive(func(s *pstate) {
			if s.mode == modeInstall {
				r.protect(s)
			}

			if s.held || e.phased(s) {
				return
			}

			if s.cur != nil && s.inst != nil {
				e.ctx = Reason{Kind: ReasonRequested}
				e.markInstall(s, false, 0, false)
			}
		})
	}

	r.keepPhased()

	return r.resolveByKeep()
}
