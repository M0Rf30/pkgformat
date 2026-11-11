package dnf

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// MultilibBest and MultilibAll are the values of [Config.MultilibPolicy].
const (
	// MultilibBest installs, of a package that exists for several
	// compatible architectures, the one that suits the host best.
	MultilibBest = "best"
	// MultilibAll also installs the other compatible architectures when a
	// package is requested by name (the 32-bit libraries next to the 64-bit
	// ones).
	MultilibAll = "all"
)

// Config is the [main] section of dnf.conf: the settings that apply to
// every repository and to a resolution.
type Config struct {
	// Defaults is what every repository starts from: the options a .repo
	// file does not set are taken from here (gpgcheck, repo_gpgcheck, gpgkey,
	// priority, cost, the ssl*, proxy*, username and password options,
	// module_hotfixes, skip_if_unavailable, metadata_expire, countme,
	// enabled_metadata). ID and the URLs are not used.
	Defaults Repo
	// Exclude and IncludePkgs are the global excludepkgs (also spelled
	// exclude) and includepkgs patterns, of the forms of [Repo.Exclude]: a
	// package that matches Exclude, or does not match IncludePkgs when it has
	// entries, is left out of every repository.
	Exclude     []string
	IncludePkgs []string
	// InstallWeakDeps is install_weak_deps, true by default: Recommends are
	// installed with the package that recommends them.
	InstallWeakDeps bool
	// Obsoletes is obsoletes, true by default: a package that obsoletes
	// another replaces it.
	Obsoletes bool
	// Best is best, true by default: a package that is asked for is installed
	// in its newest version, and the resolution fails when that cannot be
	// done. With best=0 an older version is installed instead. The versions of
	// what a package needs are always chosen with that fallback.
	Best bool
	// InstallOnlyPkgs is installonlypkgs: names, or capabilities provided
	// (installonlypkg(kernel)), of packages that are never upgraded or
	// replaced; a new version is installed next to the old ones, and the
	// oldest are removed beyond InstallOnlyLimit.
	InstallOnlyPkgs []string
	// InstallOnlyLimit is installonly_limit: how many versions of such a
	// package stay installed. Less than 2 means no limit.
	InstallOnlyLimit int
	// MultilibPolicy is [MultilibBest] (the default) or [MultilibAll].
	MultilibPolicy string
	// LocalPkgGPGCheck is localpkg_gpgcheck: [Client.VerifyLocal] checks the
	// signature of package files that are not from a repository.
	LocalPkgGPGCheck bool
	// VarsDirs are the varsdir directories, used when [Options.VarsDirs] is
	// empty.
	VarsDirs []string
}

// DefaultConfig returns the configuration of a dnf.conf without a [main]
// section: dnf's own defaults.
func DefaultConfig() *Config {
	return &Config{
		Defaults:        defaultRepo(),
		InstallWeakDeps: true,
		Obsoletes:       true,
		Best:            true,
		MultilibPolicy:  MultilibBest,

		InstallOnlyPkgs:  defaultInstallOnly(),
		InstallOnlyLimit: 3,
	}
}

// defaultInstallOnly is the installonlypkgs of dnf.
func defaultInstallOnly() []string {
	return []string{
		"kernel", "kernel-PAE", "installonlypkg(kernel)", "installonlypkg(kernel-module)",
		"installonlypkg(vm)", "multiversion(kernel)",
	}
}

// ParseConfig parses the INI-style content of a dnf.conf and returns its [main]
// section over the defaults of dnf. Other sections are ignored. Unknown keys
// are ignored, as dnf ignores them in a repository section. A line over 1 MiB
// fails with [ErrRepoFileTooLarge].
func ParseConfig(r io.Reader) (*Config, error) {
	cfg := DefaultConfig()

	var (
		inMain  bool
		lastKey string
	)

	err := scanINI(r, func(l iniLine) {
		if l.header {
			inMain = l.section == "main"
			lastKey = ""

			return
		}

		if !inMain {
			return
		}

		key, val, ok := splitKeyValue(l.text)
		if !ok {
			cfg.appendList(lastKey, l.text)

			return
		}

		lastKey = key

		cfg.apply(key, val)
	})
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// apply folds one "key = value" of the [main] section into c.
func (c *Config) apply(key, val string) {
	switch key {
	case "exclude", "excludepkgs", "includepkgs", "varsdir":
		c.appendList(key, val)
	case "install_weak_deps":
		setBool(&c.InstallWeakDeps, val)
	case "obsoletes":
		setBool(&c.Obsoletes, val)
	case "best":
		setBool(&c.Best, val)
	case "installonlypkgs":
		c.InstallOnlyPkgs = splitList(val)
	case "installonly_limit":
		if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && n >= 0 {
			c.InstallOnlyLimit = n
		}
	case "localpkg_gpgcheck":
		setBool(&c.LocalPkgGPGCheck, val)
	case "multilib_policy":
		switch v := strings.ToLower(val); v {
		case MultilibBest, MultilibAll:
			c.MultilibPolicy = v
		}
	case "name", "type", "baseurl", "mirrorlist", "metalink", "enabled":
		// Options of one repository, not defaults of all.
	default:
		applyRepoKey(&c.Defaults, key, val)
	}
}

// appendList adds the values of a list key of the [main] section.
func (c *Config) appendList(key, val string) {
	switch key {
	case "exclude", "excludepkgs":
		c.Exclude = append(c.Exclude, splitList(val)...)
	case "includepkgs":
		c.IncludePkgs = append(c.IncludePkgs, splitList(val)...)
	case "installonlypkgs":
		c.InstallOnlyPkgs = append(c.InstallOnlyPkgs, splitList(val)...)
	case "varsdir":
		c.VarsDirs = append(c.VarsDirs, strings.Fields(val)...)
	default:
		appendRepoList(&c.Defaults, key, val)
	}
}

// LoadConfig reads the dnf.conf at path.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dnf: %w", err)
	}

	defer func() { _ = f.Close() }()

	return ParseConfig(f)
}

// Config returns the settings of the [main] section of Options.ConfigFile, or
// Options.Config when that is set, or dnf's defaults when there is neither.
// The file is read once.
func (c *Client) Config() (*Config, error) {
	c.cfgOnce.Do(func() {
		switch {
		case c.opts.Config != nil:
			c.cfg = c.opts.Config
		case c.opts.ConfigFile != "":
			c.cfg, c.cfgErr = LoadConfig(c.opts.ConfigFile)
		default:
			c.cfg = DefaultConfig()
		}
	})

	return c.cfg, c.cfgErr
}

// allowed reports whether a package of a repository is in the index: it
// matches no exclude pattern, and matches the includepkgs patterns of the
// repository and of dnf.conf when there are any.
func (c *Config) allowed(r *Repo, name, epoch, version, release, arch string) bool {
	if len(c.Exclude)+len(r.Exclude)+len(c.IncludePkgs)+len(r.IncludePkgs) == 0 {
		return true
	}

	forms := nevraForms(name, epoch, version, release, arch)

	switch {
	case matchesAny(c.Exclude, forms), matchesAny(r.Exclude, forms):
		return false
	case len(c.IncludePkgs) > 0 && !matchesAny(c.IncludePkgs, forms):
		return false
	case len(r.IncludePkgs) > 0 && !matchesAny(r.IncludePkgs, forms):
		return false
	}

	return true
}
