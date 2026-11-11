package pacman

import "slices"

// AllowedArchitectures returns the Architecture values in file order with
// "auto" replaced by ArchFromGOARCH(goarch), as pacman does (a value listed
// twice stays twice). goarch is a GOARCH value such as runtime.GOARCH, or an
// Arch Linux architecture name (for instance the output of "uname -m"), which
// is used as is. It is nil when the option is absent: pacman then makes no
// architecture check.
func (c *Config) AllowedArchitectures(goarch string) []string {
	var out []string

	for _, a := range c.Architectures {
		if a == "auto" {
			a = ArchFromGOARCH(goarch)
		}

		out = append(out, a)
	}

	return out
}

// Arch returns the architecture $arch stands for: the first Architecture value,
// with "auto" resolved as AllowedArchitectures does. It is empty when the
// option is absent.
func (c *Config) Arch(goarch string) string {
	if len(c.Architectures) == 0 {
		return ""
	}

	return c.AllowedArchitectures(goarch)[0]
}

// IsHeld reports whether name matches a HoldPkg entry, a package pacman asks
// confirmation for before removing. Entries are shell-style patterns, matched
// as fnmatch(3) does.
func (c *Config) IsHeld(name string) bool {
	return matchAny(c.HoldPkg, name)
}

// IsIgnored reports whether pacman skips upgrades of a package: its name
// matches an IgnorePkg entry, or one of its groups matches an IgnoreGroup
// entry. Entries are shell-style patterns, matched as fnmatch(3) does.
func (c *Config) IsIgnored(name string, groups ...string) bool {
	if matchAny(c.IgnorePkg, name) {
		return true
	}

	for _, g := range groups {
		if matchAny(c.IgnoreGroup, g) {
			return true
		}
	}

	return false
}

// ResolveOptions returns ResolveOptions carrying the IgnorePkg and IgnoreGroup
// of the configuration.
func (c *Config) ResolveOptions() ResolveOptions {
	return ResolveOptions{
		IgnorePkg:   slices.Clone(c.IgnorePkg),
		IgnoreGroup: slices.Clone(c.IgnoreGroup),
	}
}

// ApplyUsage sets the Usage of every repository of the configuration on x, so
// that resolution, upgrades and searches skip the repositories whose Usage does
// not allow them.
func (c *Config) ApplyUsage(x *Index) {
	for i := range c.Repos {
		x.SetUsage(c.Repos[i].Name, c.Repos[i].Usage)
	}
}

// ReposFor returns the repositories whose Usage allows every use in use, in
// configuration order. ReposFor(UsageSync) is what a database refresh (see
// Client.Sync) works on.
func (c *Config) ReposFor(use Usage) []Repo {
	var out []Repo

	for _, r := range c.Repos {
		if r.Usage.Allows(use) {
			out = append(out, r)
		}
	}

	return out
}

// Repo returns the repository called name.
func (c *Config) Repo(name string) (Repo, bool) {
	for _, r := range c.Repos {
		if r.Name == name {
			return r, true
		}
	}

	return Repo{}, false
}
