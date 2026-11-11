package pacman

import (
	"fmt"
	"slices"
)

// dropAdd removes p from the packages to install, as libalpm leaves a package
// out of the target list when another one provides it.
func (r *resolver) dropAdd(p *IndexedPackage) {
	delete(r.adds, p.Name)

	r.addOrder = filterOut(r.addOrder, p)
	r.order = filterOut(r.order, p)
	r.addIdx = provIndex{}

	for _, q := range r.addOrder {
		r.addIdx.addPackage(q.Name, q.Version, q.Provides)
	}
}

func filterOut(pkgs []*IndexedPackage, p *IndexedPackage) []*IndexedPackage {
	out := pkgs[:0]

	for _, q := range pkgs {
		if q != p {
			out = append(out, q)
		}
	}

	return out
}

// parseConflicts parses the conflict expressions of a package.
func parseConflicts(name string, conflicts []string) ([]Dependency, error) {
	out := make([]Dependency, 0, len(conflicts))

	for _, s := range conflicts {
		c, err := ParseDependency(s)
		if err != nil {
			return nil, fmt.Errorf("package %s: %w", name, err)
		}

		out = append(out, c)
	}

	return out, nil
}

// innerConflicts checks the packages to install against each other. When one
// provides the name of the other the provided package is dropped, otherwise the
// conflict is an error.
func (r *resolver) innerConflicts() error {
	for _, p := range slices.Clone(r.order) {
		if r.adds[p.Name] != p {
			continue
		}

		conflicts, err := parseConflicts(p.Name, p.Conflicts)
		if err != nil {
			return err
		}

		for _, c := range conflicts {
			for _, owner := range r.addIdx.all(c, func(o string) bool { return o == p.Name }) {
				q := r.adds[owner]
				if q == nil || r.adds[p.Name] != p {
					continue
				}

				switch {
				case p.Satisfies(Dependency{Name: q.Name}):
					r.dropAdd(q)
				case q.Satisfies(Dependency{Name: p.Name}):
					r.dropAdd(p)
				default:
					return &ConflictError{Package: p.Name, With: q.Name, Expr: c.String()}
				}
			}
		}
	}

	return nil
}

// outerConflicts checks the packages to install against the installed ones that
// stay: those neither removed nor replaced by a package of the same name.
func (r *resolver) outerConflicts() error {
	stays := func(owner string) bool { return r.adds[owner] == nil && !r.removed[owner] }
	skip := func(owner string) bool { return !stays(owner) }

	for _, p := range r.order {
		conflicts, err := parseConflicts(p.Name, p.Conflicts)
		if err != nil {
			return err
		}

		for _, c := range conflicts {
			if owners := r.localIdx.all(c, skip); len(owners) > 0 {
				return &ConflictError{Package: p.Name, With: owners[0], Installed: true, Expr: c.String()}
			}
		}
	}

	for _, l := range r.local {
		if !stays(l.Name) {
			continue
		}

		conflicts, err := parseConflicts(l.Name, l.Conflicts)
		if err != nil {
			return err
		}

		for _, c := range conflicts {
			if owners := r.addIdx.all(c, func(o string) bool { return o == l.Name }); len(owners) > 0 {
				return &ConflictError{Package: owners[0], With: l.Name, Installed: true, Expr: c.String()}
			}
		}
	}

	return nil
}

// checkBroken reports an installed package that stays but loses a dependency
// the transaction takes away: one that was satisfied before and is not after,
// because its provider is upgraded to a version that no longer fits or is
// removed.
func (r *resolver) checkBroken() error {
	if len(r.adds) == 0 && len(r.removed) == 0 {
		return nil
	}

	after := provIndex{}

	for _, l := range r.local {
		if r.adds[l.Name] == nil && !r.removed[l.Name] {
			after.addPackage(l.Name, l.Version, l.Provides)
		}
	}

	for _, p := range r.addOrder {
		after.addPackage(p.Name, p.Version, p.Provides)
	}

	for _, l := range r.local {
		if r.adds[l.Name] != nil || r.removed[l.Name] {
			continue
		}

		for _, s := range l.Depends {
			d, err := ParseDependency(s)
			if err != nil {
				continue
			}

			if _, ok := after.find(d, nil); ok || (r.opts.Installed != nil && r.opts.Installed(d)) {
				continue
			}

			if by, ok := r.localIdx.find(d, func(o string) bool { return r.adds[o] == nil && !r.removed[o] }); ok {
				return &BrokenDependencyError{Package: l.Name, Dependency: d.String(), By: by}
			}
		}
	}

	return nil
}
