package dnf

import (
	"slices"
	"strconv"
	"strings"
)

// Match returns the packages that a command-line spec names, the ones a
// resolution prefers first, or none. The spec is, as in dnf:
//
//	name
//	name.arch
//	name-version
//	name-version-release
//	name-version-release.arch
//	name-epoch:version-release[.arch]
//	epoch:name-version-release.arch
//
// The first of these forms that names a package decides, in that order, so a
// package called "python3.12" is found by its name and not read as
// "python3" for the architecture "12".
func (ix *Index) Match(spec string) []*Package {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}

	// "epoch:name-version-release.arch" has its epoch in front.
	wantEpoch := ""

	if e, rest, ok := strings.Cut(spec, ":"); ok && isDigits(e) && strings.Contains(rest, "-") {
		wantEpoch, spec = e, rest
	}

	forms := []string{spec}
	arch := ""

	if i := strings.LastIndexByte(spec, '.'); i > 0 {
		if _, known := ix.ranks[spec[i+1:]]; known {
			forms = append(forms, spec[:i])
			arch = spec[i+1:]
		}
	}

	var out []*Package

	// name, then name.arch
	if wantEpoch == "" {
		if list := ix.names[spec]; len(list) > 0 {
			return slices.Clone(list)
		}

		if arch != "" {
			for _, p := range ix.names[forms[1]] {
				if p.Arch == arch {
					out = append(out, p)
				}
			}

			if len(out) > 0 {
				return out
			}
		}
	}

	// name-version[-release][.arch]
	for fi, form := range forms {
		for i := range len(form) {
			if form[i] != '-' {
				continue
			}

			for _, p := range ix.names[form[:i]] {
				if fi == 1 && p.Arch != arch {
					continue
				}

				if matchVersion(p, form[i+1:], wantEpoch) {
					out = append(out, p)
				}
			}
		}

		if len(out) > 0 {
			return out
		}
	}

	return nil
}

// matchVersion reports whether s, the part of a spec after the name, is the
// version of p: "version", "version-release", with an epoch in front or not.
func matchVersion(p *Package, s, wantEpoch string) bool {
	epoch := strconv.FormatUint(uint64(p.Epoch), 10)

	if wantEpoch != "" && wantEpoch != epoch {
		return false
	}

	if e, rest, ok := strings.Cut(s, ":"); ok && isDigits(e) {
		if wantEpoch != "" || e != epoch {
			return false
		}

		s = rest
	}

	return s == p.Version || s == p.Version+"-"+p.Release
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}

	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}
