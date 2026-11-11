package pacman

// Sysupgrade plans a system upgrade, as "pacman -Su" does, for the installed
// packages. Every installed package for which the first repository that has it
// (among those allowing UsageUpgrade) holds a newer version is upgraded.
// A sync package whose "replaces" entry matches an installed package of
// another name replaces it: it is installed and the installed one removed.
// Packages covered by ResolveOptions.IgnorePkg or ResolveOptions.IgnoreGroup
// are neither upgraded nor used as replacements, and are not picked to satisfy
// a dependency. What the upgraded and replacing packages need that the system
// lacks is installed too, and the plan is checked for conflicts and broken
// dependencies as Index.Install does. The errors wrap ErrUnresolved,
// ErrConflict and ErrBrokenDependency. ResolveOptions.Local is ignored: the
// installed argument is the system.
func (x *Index) Sysupgrade(installed []*InstalledPackage, opts ResolveOptions) (*Transaction, error) {
	opts.Local = installed
	r := newResolver(x, opts)

	r.queueReplacements()
	r.queueUpgrades()

	return r.finish()
}

// queueReplacements adopts the packages that replace installed ones and marks
// the installed packages for removal.
func (r *resolver) queueReplacements() {
	for _, p := range r.x.replacers {
		if !r.x.allows(p.Repo, UsageUpgrade) || r.ignored(p) {
			continue
		}

		// Only the newest version of a package of a repository replaces.
		if best, _ := newest(r.x.byName[p.Name], func(q *IndexedPackage) bool { return q.Repo == p.Repo }); best != p {
			continue
		}

		for _, s := range p.Replaces {
			d, err := ParseDependency(s)
			if err != nil {
				continue
			}

			l := r.localByName[d.Name]
			if l == nil || l.Name == p.Name || r.removed[l.Name] || !d.Allows(l.Version) {
				continue
			}

			if r.ignoredInstalled(l) {
				continue
			}

			if r.adds[p.Name] == nil {
				r.adopt(p)
			}

			r.removed[l.Name] = true
			r.removals = append(r.removals, l)
			r.replacements = append(r.replacements, Replacement{Installed: l, Package: p})
		}
	}
}

// ignoredInstalled reports whether IgnorePkg or IgnoreGroup covers the
// installed package.
func (r *resolver) ignoredInstalled(l *InstalledPackage) bool {
	return r.ignored(&IndexedPackage{DBEntry: DBEntry{Name: l.Name, Groups: l.Groups}})
}

// queueUpgrades adopts the newer version of every installed package.
func (r *resolver) queueUpgrades() {
	for _, l := range r.local {
		if r.removed[l.Name] || r.adds[l.Name] != nil {
			continue
		}

		p, ok := newest(r.x.byName[l.Name], func(p *IndexedPackage) bool { return r.x.allows(p.Repo, UsageUpgrade) })
		if !ok || Vercmp(p.Version, l.Version) <= 0 || r.ignored(p) {
			continue
		}

		r.adopt(p)
	}
}
