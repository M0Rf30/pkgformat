package dnf

import (
	"context"
	"fmt"
	"strings"
)

// Resolution is the outcome of [Index.Resolve].
type Resolution struct {
	// Packages are the packages to install, dependencies before the packages
	// that need them.
	Packages []*Package
	// Unresolved are the required names no package or provider satisfies.
	Unresolved []string
}

// Resolve walks the dependencies of the seed names transitively.
//
// What the host has installed, according to Options.Installed, is skipped with
// its dependency edges: neither the package nor an alternative provider of the
// capability it supplies is pulled in. Requirements are hard and missing ones
// are reported; Recommends and the names inside rich dependencies, such as
// "(a if b)", are best effort and a missing one is dropped. A capability is
// satisfied by a package of that name or else by the best provider of it.
// Dependencies are matched by name; version constraints are not compared.
func (ix *Index) Resolve(ctx context.Context, seeds []string) (*Resolution, error) {
	installed, provides, err := ix.installedSets(ctx)
	if err != nil {
		return nil, err
	}

	var (
		res         Resolution
		seen        = make(map[string]bool)
		softMissing = make(map[string]bool)
		visit       func(name string, soft bool)
	)

	visit = func(name string, soft bool) {
		name = StripRPMConstraint(name)
		if name == "" {
			return
		}

		if seen[name] {
			// A name first reached by a weak edge and found missing is still
			// missing when a hard requirement asks for it later.
			if !soft && softMissing[name] {
				delete(softMissing, name)

				res.Unresolved = append(res.Unresolved, name)
			}

			return
		}

		seen[name] = true

		if IsBooleanDep(name) {
			for _, tok := range ExpandBooleanDep(name) {
				visit(tok, true)
			}

			return
		}

		// A capability the host already has must not gain a second provider:
		// coreutils and coreutils-single both own /usr/bin/ls.
		if installed[name] || provides[name] {
			return
		}

		pkg, ok := ix.packages[name]
		if !ok {
			if providers := ix.providers[name]; len(providers) > 0 {
				visit(ix.pickProvider(providers).Name, soft)

				return
			}

			if soft {
				softMissing[name] = true
			} else {
				res.Unresolved = append(res.Unresolved, name)
			}

			return
		}

		for _, req := range pkg.Requires {
			visit(req, false)
		}

		for _, rec := range pkg.Recommends {
			visit(rec, true)
		}

		res.Packages = append(res.Packages, pkg)
	}

	for _, seed := range seeds {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		visit(seed, false)
	}

	return &res, nil
}

// installedSets reads the installed names and capabilities.
func (ix *Index) installedSets(ctx context.Context) (names, provides map[string]bool, err error) {
	if ix.installed == nil {
		return nil, nil, nil
	}

	list, err := ix.installed.InstalledNames(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("dnf: listing installed packages: %w", err)
	}

	names = make(map[string]bool, len(list))
	for _, n := range list {
		names[n] = true
	}

	caps, err := ix.installed.InstalledProvides(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("dnf: listing installed capabilities: %w", err)
	}

	provides = make(map[string]bool, len(caps))

	for _, c := range caps {
		if name := StripRPMConstraint(c); name != "" {
			provides[name] = true
		}
	}

	return names, provides, nil
}

// StripRPMConstraint drops the version constraint of a dependency written as
// "name >= 1.2". A rich dependency, which starts with "(", is returned as is,
// whole, for [ExpandBooleanDep].
func StripRPMConstraint(name string) string {
	name = strings.TrimSpace(name)

	if strings.HasPrefix(name, "(") {
		return name
	}

	if before, _, ok := strings.Cut(name, " "); ok {
		return strings.TrimSpace(before)
	}

	return name
}

// IsBooleanDep reports whether name is a rich dependency such as "(a if b)".
func IsBooleanDep(name string) bool {
	return strings.HasPrefix(strings.TrimSpace(name), "(")
}

// ExpandBooleanDep returns the capability names of a rich dependency, without
// its operators (and, or, if, else, unless, with, without, then), version
// constraints and rpmlib() features: "(gcc-plugin-annobin if gcc)" gives
// gcc-plugin-annobin and gcc. It returns nil for a name that is not a rich
// dependency.
func ExpandBooleanDep(name string) []string {
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, "(") {
		return nil
	}

	name = strings.ReplaceAll(name, ",", " ")

	var (
		out      []string
		skipNext bool
	)

	for tok := range strings.FieldsSeq(name) {
		tok = trimGrouping(tok)
		if tok == "" {
			continue
		}

		if skipNext {
			skipNext = false

			continue
		}

		switch tok {
		case ">=", "<=", "=", ">", "<", "==":
			// The next token is a version, not a name.
			skipNext = true

			continue
		}

		if isBooleanKeyword(tok) || strings.HasPrefix(tok, "rpmlib(") {
			continue
		}

		out = append(out, tok)
	}

	return out
}

// trimGrouping removes the parentheses that group a rich dependency from the
// ends of a token, and only those: the ")" of "libfoo(x86-64)" is part of the
// capability name.
func trimGrouping(tok string) string {
	tok = strings.TrimLeft(tok, "(")

	for strings.HasSuffix(tok, ")") && strings.Count(tok, ")") > strings.Count(tok, "(") {
		tok = tok[:len(tok)-1]
	}

	return tok
}

func isBooleanKeyword(tok string) bool {
	switch strings.ToLower(tok) {
	case "and", "or", "if", "else", "unless", "with", "without", "then":
		return true
	}

	return false
}
