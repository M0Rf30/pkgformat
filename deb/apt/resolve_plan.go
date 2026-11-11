package apt

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
)

// UpgradeMode selects a system upgrade a [PlanRequest] asks for.
type UpgradeMode uint8

const (
	// UpgradeNone upgrades nothing beyond what the request needs.
	UpgradeNone UpgradeMode = iota
	// UpgradeSafe is "apt-get upgrade": every installed package that can be
	// upgraded is, without installing a new package or removing one. A
	// package that would need either is kept back.
	UpgradeSafe
	// UpgradeWithNew is "apt upgrade" (apt-get upgrade --with-new-pkgs): as
	// UpgradeSafe, but new packages may be installed to meet the new
	// dependencies of an upgrade.
	UpgradeWithNew
	// UpgradeFull is "apt-get dist-upgrade": the best upgrade, removing or
	// installing packages as needed.
	UpgradeFull
)

// String names the mode the way the apt command line does.
func (m UpgradeMode) String() string {
	switch m {
	case UpgradeNone:
		return "none"
	case UpgradeSafe:
		return "upgrade"
	case UpgradeWithNew:
		return "upgrade-with-new-packages"
	case UpgradeFull:
		return "dist-upgrade"
	default:
		return fmt.Sprintf("UpgradeMode(%d)", uint8(m))
	}
}

// PlanRequest says what a plan is to achieve.
type PlanRequest struct {
	// Install names the packages to install, as a dependency field is
	// written: "curl", "curl:arm64", "curl (>= 8)", "libfoo (= 1.2)". A
	// relation with a version constraint selects the highest version that
	// meets it as the candidate, as "apt-get install curl=VERSION" does.
	// Several alternatives ("a | b") pick the first that exists.
	Install []string
	// Remove names installed packages to remove ("apt-get remove"). What
	// depends on them goes too, unless the dependency can be met otherwise.
	Remove []string
	// Upgrade asks for a system upgrade on top of Install and Remove.
	Upgrade UpgradeMode
	// FixBroken is "apt-get -f" (and "apt-get install -f" with no packages):
	// repair the installed packages whose dependencies are unmet, installing
	// what they need and removing what cannot be saved, then do the upgrade
	// the request asks for. As in apt it acts only on a request that names no
	// package. Without it a broken system makes a request without packages
	// fail, and one with packages fail unless the packages themselves repair
	// every problem.
	FixBroken bool
	// AutoRemove is "apt-get autoremove" and "--auto-remove": after the rest
	// of the request, remove the installed packages that were installed
	// automatically (see [PackageInfo.AutoInstalled]) and that nothing
	// installed needs any more. Without it such packages are only listed in
	// [Plan.AutoRemovable]. "apt-get purge" and "autopurge" differ from the
	// removal only in what dpkg does with configuration files, so they plan
	// the same changes.
	AutoRemove bool
}

// PlanOptions configures [Cache.Plan].
type PlanOptions struct {
	// Policy selects the candidate version of every package from the pins of
	// a preferences file. Nil selects the highest version of the most
	// trusted index: priority 500, 100 for a NotAutomatic index that is
	// ButAutomaticUpgrades, 1 for one that is NotAutomatic, and never a
	// version older than the installed one.
	Policy *Policy
	// Held lists packages dpkg holds ("hold" in the status database): they
	// are neither upgraded nor removed by the resolver. A name without an
	// architecture holds every architecture of the package.
	//
	// Packages that the status database holds ([PackageInfo.Held]) are held
	// as well; Held adds to them, for a caller that keeps its holds elsewhere.
	Held []string
	// InstallRecommends is APT::Install-Recommends: install the Recommends of
	// every package the plan installs or upgrades, when they can be met
	// without removing anything; one that cannot is skipped. Nil is apt's
	// default for "apt-get install", true.
	InstallRecommends *bool
	// InstallSuggests is APT::Install-Suggests, the same for Suggests. Nil is
	// apt's default, false.
	InstallSuggests *bool
	// AutoRemoveRecommendsImportant is APT::AutoRemove::RecommendsImportant:
	// a package an installed package Recommends counts as needed by it, so
	// [PlanRequest.AutoRemove] keeps it. Nil is apt's default, true.
	AutoRemoveRecommendsImportant *bool
	// AutoRemoveSuggestsImportant is APT::AutoRemove::SuggestsImportant, the
	// same for Suggests. Nil is apt's default, true.
	AutoRemoveSuggestsImportant *bool
	// NeverAutoRemove lists regular expressions (APT::NeverAutoRemove) of
	// package names that auto-removal keeps. Nil selects
	// [DefaultNeverAutoRemove]; an empty non-nil slice keeps nothing.
	NeverAutoRemove []string
	// MaxSteps bounds the work of a plan, so a hostile index cannot make it
	// run for ever. Zero selects DefaultPlanSteps.
	MaxSteps int
}

// DefaultNeverAutoRemove is apt's APT::NeverAutoRemove of a stock install
// (/etc/apt/apt.conf.d/01autoremove): firmware and the kernel image
// packages, which auto-removal keeps even when nothing needs them.
var DefaultNeverAutoRemove = []string{
	"^firmware-linux.*",
	"^linux-firmware$",
	"^linux-image-[a-z0-9]*$",
	"^linux-image-[a-z0-9]*-[a-z0-9]*$",
}

// DefaultPlanSteps is the work budget of a plan when PlanOptions.MaxSteps
// is zero.
const DefaultPlanSteps = 200000

// ReasonKind says why a package is in a [Plan].
type ReasonKind uint8

const (
	// ReasonRequested: the request named the package, or an upgrade mode
	// selected it.
	ReasonRequested ReasonKind = iota + 1
	// ReasonDependency: a new package that a dependency of Cause needs.
	ReasonDependency
	// ReasonRecommends: a new package that a Recommends of Cause brings, with
	// [PlanOptions.InstallRecommends].
	ReasonRecommends
	// ReasonSuggests: a new package that a Suggests of Cause brings, with
	// [PlanOptions.InstallSuggests].
	ReasonSuggests
	// ReasonAutoRemove: removed because it was installed to satisfy a
	// dependency and nothing that is installed needs it any more
	// ([PlanRequest.AutoRemove]).
	ReasonAutoRemove
	// ReasonUpgradeDependency: an installed package upgraded because the new
	// version of Cause needs it, or no longer fits with it.
	ReasonUpgradeDependency
	// ReasonSameSource: an installed package upgraded along with the other
	// binaries of the source package of Cause.
	ReasonSameSource
	// ReasonConflict: removed because Cause Conflicts with it.
	ReasonConflict
	// ReasonBreaks: removed because Cause Breaks it and it has no version
	// that Cause allows.
	ReasonBreaks
	// ReasonBrokenDependency: removed because a dependency of it can no
	// longer be met after the other changes (Cause names the dependency or
	// the package that went).
	ReasonBrokenDependency
)

// String names the kind.
func (k ReasonKind) String() string {
	switch k {
	case ReasonRequested:
		return "requested"
	case ReasonDependency:
		return "dependency"
	case ReasonRecommends:
		return "recommends"
	case ReasonSuggests:
		return "suggests"
	case ReasonAutoRemove:
		return "auto-remove"
	case ReasonUpgradeDependency:
		return "upgrade-dependency"
	case ReasonSameSource:
		return "same-source"
	case ReasonConflict:
		return "conflict"
	case ReasonBreaks:
		return "breaks"
	case ReasonBrokenDependency:
		return "broken-dependency"
	default:
		return ""
	}
}

// Reason records why a package is in a plan.
type Reason struct {
	// Kind is the cause category; zero when the engine has nothing to say.
	Kind ReasonKind
	// Cause is the package ("name:arch version") whose installation led to
	// the change.
	Cause string
	// Relation is the dependency or conflict as written, when there is one.
	Relation string
}

// String renders the reason on one line.
func (r Reason) String() string {
	var sb strings.Builder

	sb.WriteString(r.Kind.String())

	if r.Cause != "" {
		sb.WriteString(" of ")
		sb.WriteString(r.Cause)
	}

	if r.Relation != "" {
		sb.WriteString(" (")
		sb.WriteString(r.Relation)
		sb.WriteByte(')')
	}

	return sb.String()
}

// ChangeKind is what a plan does to one package.
type ChangeKind uint8

const (
	// ChangeInstall installs a package that is not installed.
	ChangeInstall ChangeKind = iota + 1
	// ChangeUpgrade replaces an installed version by a higher one.
	ChangeUpgrade
	// ChangeDowngrade replaces an installed version by a lower one (a pin
	// above 1000 asks for it).
	ChangeDowngrade
	// ChangeRemove removes an installed package.
	ChangeRemove
)

// String names the kind.
func (k ChangeKind) String() string {
	switch k {
	case ChangeInstall:
		return "install"
	case ChangeUpgrade:
		return "upgrade"
	case ChangeDowngrade:
		return "downgrade"
	case ChangeRemove:
		return "remove"
	default:
		return ""
	}
}

// Change is one step of a [Plan].
type Change struct {
	// Kind is what happens to the package.
	Kind ChangeKind
	// Package is the version installed afterwards; for a removal the
	// installed version that goes.
	Package *PackageInfo
	// From is the installed version an upgrade or downgrade replaces; nil
	// otherwise.
	From *PackageInfo
	// Reason says why.
	Reason Reason
	// Auto is true for an install or upgrade that leaves the package marked
	// as automatically installed: a dependency, not a request. A caller that
	// writes apt's extended states file records these.
	Auto bool
}

// Plan is what [Cache.Plan] decides: the changes that bring the installed
// system to the state the request asks for, the way "apt-get -s" computes
// them.
//
// Install lists the packages new to the system, Upgrade and Downgrade the
// installed packages that change version, Remove the installed packages that
// go. Changes lists them in the order apt carries the steps out, which each
// of the other lists keeps: the order of the "Inst" and "Remv" lines of
// "apt-get -s" (see the Planning section of the package documentation). Held lists
// the installed packages that have a newer candidate the plan did not take
// (the "kept back" of apt). Unresolved lists the names of the request that no
// index knows.
//
// The PackageInfo values point into the cache and must not be modified.
type Plan struct {
	// Install is the packages to install.
	Install []*PackageInfo
	// Upgrade is the new versions of installed packages.
	Upgrade []*PackageInfo
	// Downgrade is the older versions to install over installed ones.
	Downgrade []*PackageInfo
	// Remove is the installed versions to remove.
	Remove []*PackageInfo
	// Held is the installed packages kept at their version though a newer
	// candidate exists.
	Held []*PackageInfo
	// Manual is the installed packages that were automatically installed and
	// that the request names without the plan changing them: they become
	// manually installed ("set to manually installed" of apt-get), so a later
	// auto-removal keeps them. A named package the plan installs or upgrades
	// is manually installed too; [Change.Auto] reports it.
	Manual []*PackageInfo
	// AutoRemovable is the installed packages that were installed
	// automatically and that nothing needs any more, though the plan does
	// not remove them (apt-get's "no longer required" list). With
	// [PlanRequest.AutoRemove] they are in Remove instead.
	AutoRemovable []*PackageInfo
	// Unresolved is the requested names no package matched.
	Unresolved []string
	// Changes lists every change with its reason, in the order apt unpacks
	// and removes the packages.
	Changes []Change
}

// Empty reports a plan that changes nothing.
func (p *Plan) Empty() bool { return len(p.Changes) == 0 }

// Sentinel errors of planning.
var (
	// ErrUnresolvable is matched by a [PlanError]: the problem resolver
	// could not find a state in which every dependency holds.
	ErrUnresolvable = errors.New("apt: unable to correct problems")
	// ErrVirtualPackage is matched by a [VirtualPackageError].
	ErrVirtualPackage = errors.New("apt: ambiguous virtual package")
)

// PlanError reports that no consistent plan exists: the packages that remain
// broken after the resolver has done all it can, one error each (an
// [*UnsatisfiedError] or a [*ConflictError]). It matches [ErrUnresolvable];
// the causes are visible to errors.Is and errors.As, so a plan that fails on
// a conflict matches [ErrConflict] too.
type PlanError struct {
	// Broken is why each broken package is broken.
	Broken []error
}

// maxShownBroken bounds how many causes Error prints.
const maxShownBroken = 4

// Error lists the first causes.
func (e *PlanError) Error() string {
	var sb strings.Builder

	sb.WriteString(ErrUnresolvable.Error())

	for i, err := range e.Broken {
		if i == maxShownBroken {
			fmt.Fprintf(&sb, "; and %d more", len(e.Broken)-i)

			break
		}

		sb.WriteString("; ")
		sb.WriteString(err.Error())
	}

	return sb.String()
}

// Is matches ErrUnresolvable.
func (e *PlanError) Is(target error) bool { return target == ErrUnresolvable }

// Unwrap exposes the causes to errors.Is and errors.As.
func (e *PlanError) Unwrap() []error { return e.Broken }

// VirtualPackageError reports a request for a virtual package that several
// packages provide: apt does not choose between them for the user. It
// matches [ErrVirtualPackage].
type VirtualPackageError struct {
	// Name is the virtual package.
	Name string
	// Providers are the packages that could be installed for it
	// ("name:arch version").
	Providers []string
}

// Error names the providers.
func (e *VirtualPackageError) Error() string {
	return fmt.Sprintf("apt: %s is a virtual package provided by %s; select one to install",
		e.Name, strings.Join(e.Providers, ", "))
}

// Is matches ErrVirtualPackage.
func (e *VirtualPackageError) Is(target error) bool { return target == ErrVirtualPackage }

// Plan works out the changes the request needs, the way apt does: the
// candidates are installed together with their dependencies, an installed
// package that a new package Conflicts with is removed, one it Breaks is
// upgraded (or removed when it cannot be), installed packages whose
// dependencies a new version no longer meets are upgraded too, and what
// cannot be saved is removed. It is a port of the decisions of apt's
// pkgDepCache::MarkInstall and pkgProblemResolver (the "internal" solver of
// "apt-get install", "remove", "upgrade" and "dist-upgrade"), so for a system
// described the same way the plan is the one "apt-get -s" prints.
//
// The system is the one the cache holds: packages of the dpkg status
// database are installed, those of the indexes can be installed. Candidates
// come from [PlanOptions.Policy], pins included: a version of priority below
// zero is never a candidate. [Cache.ResolveDeps] differs in that it never
// removes anything and may pick any version that fits; use that to extract a
// toolchain, and Plan to predict what a package manager would do.
//
// Recommends of the packages being installed are installed too when they can
// be, and skipped silently when not, as apt does with Install-Recommends
// ([PlanOptions.InstallRecommends], on by default); Suggests only with
// [PlanOptions.InstallSuggests]. Nothing is removed to satisfy a soft
// dependency, except that a recommended package that conflicts with an
// installed one removes it, as in apt. The automatic-installation marks of
// /var/lib/apt/extended_states ([LoadOptions.ExtendedStatesFile]) and the
// dpkg holds of the status file are read by [Load]; new dependencies are
// marked automatic in the result ([Change.Auto], [Plan.Manual]), and
// [PlanRequest.AutoRemove], like "remove" with --auto-remove, removes the
// automatically installed packages nothing manual needs any more
// ([Plan.AutoRemovable] lists them). [PlanOptions.Held] adds holds the
// status database does not carry; an explicit request for a held package
// overrides its hold, as it does in apt.
//
// Once the resolver has decided, the plan is ordered the way apt orders it:
// unpack and configure steps are replayed with a port of apt's ordering of
// Pre-Depends and Depends (pkgOrderList and pkgPackageManager), so
// [Plan.Changes] come in the order "apt-get -s" prints them (removals first)
// and a system apt cannot configure fails as it does: an [*OrderError] that
// wraps [ErrOrderLoop], [ErrOrderRemoval] or [ErrOrderSimulation] and names
// the cycle.
//
// What is not modelled: the fallback to apt's second solver when the first
// one fails (such a request fails here), the versioned-kernel protection of
// autoremove (APT::VersionedKernelPackages and the protected kernels, which
// depend on the running system), purge as distinct from remove (the state of
// configuration files is not known), the Important and Protected package
// flags beyond Essential, implicit Breaks and reinstalls. Where apt's choice
// rests on the order of its internal hash tables (a tie between packages of
// equal score) the plan takes the order of the package names; the order of
// reverse dependencies follows apt's package table as far as the loaded
// indexes tell, so it may differ for versions that only a larger archive
// holds.
//
// An error is a [*PlanError] when the resolver fails, an [*OrderError] when
// the steps cannot be ordered, a [*VirtualPackageError] for an ambiguous
// request, a [*PlanOptionError] for an invalid option, ErrResolveLimit when
// the work budget runs out, or a parse error of a request (it wraps
// [deb.ErrInvalidControlFormat]).
func (c *Cache) Plan(req PlanRequest, opts PlanOptions) (*Plan, error) {
	var pol candidatePolicy
	if opts.Policy != nil {
		pol = opts.Policy
	}

	return c.plan(req, opts, pol)
}

// plan is Plan with the policy given as the interface the engine uses.
func (c *Cache) plan(req PlanRequest, opts PlanOptions, pol candidatePolicy) (*Plan, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cfg, err := opts.engineConfig()
	if err != nil {
		return nil, err
	}

	e := newEngine(c, pol, cfg)
	r := newResolver(e)

	plan := &Plan{}

	if err := e.apply(r, req, plan); err != nil {
		return nil, err
	}

	if e.exceeded {
		return nil, ErrResolveLimit
	}

	if err := e.checkOrder(); err != nil {
		return nil, err
	}

	e.collect(plan)

	return plan, nil
}

// ErrPlanOption is matched by a [*PlanOptionError]: a [PlanOptions] value
// that cannot be used.
var ErrPlanOption = errors.New("apt: invalid plan option")

// PlanOptionError reports a [PlanOptions] value that cannot be used, such as a
// NeverAutoRemove entry that is not a regular expression. It matches
// [ErrPlanOption].
type PlanOptionError struct {
	// Option is the name of the field.
	Option string
	// Value is the offending value.
	Value string
	// Err is the cause.
	Err error
}

// Error names the option, the value and the cause.
func (e *PlanOptionError) Error() string {
	return fmt.Sprintf("apt: invalid plan option %s %q: %v", e.Option, e.Value, e.Err)
}

// Is matches ErrPlanOption.
func (e *PlanOptionError) Is(target error) bool { return target == ErrPlanOption }

// Unwrap exposes the cause.
func (e *PlanOptionError) Unwrap() error { return e.Err }

// orDefault is the value of an optional switch.
func orDefault(v *bool, def bool) bool {
	if v == nil {
		return def
	}

	return *v
}

// engineConfig resolves the options to the values the engine reads.
func (o PlanOptions) engineConfig() (engineConfig, error) {
	cfg := engineConfig{
		held:             o.Held,
		maxSteps:         o.MaxSteps,
		recommends:       orDefault(o.InstallRecommends, true),
		suggests:         orDefault(o.InstallSuggests, false),
		followRecommends: orDefault(o.AutoRemoveRecommendsImportant, true),
		followSuggests:   orDefault(o.AutoRemoveSuggestsImportant, true),
	}

	if cfg.maxSteps <= 0 {
		cfg.maxSteps = DefaultPlanSteps
	}

	patterns := o.NeverAutoRemove
	if patterns == nil {
		patterns = DefaultNeverAutoRemove
	}

	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return engineConfig{}, &PlanOptionError{Option: "NeverAutoRemove", Value: p, Err: err}
		}

		cfg.neverRemove = append(cfg.neverRemove, re)
	}

	return cfg, nil
}

// apply runs the request on the engine: removals, installs, then the upgrade
// or the resolver, as "apt-get" does.
func (e *engine) apply(r *resolver, req PlanRequest, plan *Plan) error {
	startBroken := e.brokenCount()

	if startBroken != 0 {
		// apt repairs the system first only for a request without packages;
		// with packages "-f" has no effect and the request itself must
		// repair every problem.
		if len(req.Install) == 0 && len(req.Remove) == 0 {
			if !req.FixBroken {
				// apt refuses to run a system upgrade over a broken system.
				return e.planError()
			}

			if err := e.fixBroken(); err != nil {
				return err
			}

			startBroken = 0
		}
	}

	var (
		later  []*pstate
		manual []*PackageInfo
	)

	for _, name := range req.Remove {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		keys := e.installedKeysOf(name)
		if len(keys) == 0 {
			plan.Unresolved = append(plan.Unresolved, name)

			continue
		}

		for _, key := range keys {
			s := e.state(key)
			e.refreshMarks()
			r.clear(s)
			r.protect(s)
			r.markRemove(s)
			e.markDelete(s, 0, true)
		}
	}

	seeds, err := e.parseSeeds(req.Install)
	if err != nil {
		return err
	}

	brokenFix := startBroken != 0 && (len(seeds) > 0 || len(req.Remove) > 0)

	for _, seed := range seeds {
		s, unresolved, err := e.resolveSeed(seed)
		if err != nil {
			return err
		}

		if s == nil {
			if unresolved != "" {
				plan.Unresolved = append(plan.Unresolved, unresolved)
			}

			continue
		}

		e.refreshMarks()
		r.clear(s)
		r.protect(s)
		e.markInstall(s, false, 0, true)

		// A package the request names that stays as it is becomes
		// manually installed (apt's TryToInstall).
		if s.mode != modeInstall && s.cur != nil && s.auto {
			e.markAuto(s, false)

			manual = append(manual, &s.cur.PackageInfo)
		}

		if !brokenFix && !slices.Contains(later, s) {
			later = append(later, s)
		}
	}

	sort.Slice(later, func(i, j int) bool { return later[i].key < later[j].key })

	// apt records the upgradable packages before it runs the solver; those
	// that end up neither upgraded nor removed are the ones it lists as kept
	// back.
	for _, key := range e.installedKeys() {
		if s := e.state(key); s.cand != nil && s.status > 0 {
			e.upgradable = append(e.upgradable, s)
		}
	}

	e.ctx = Reason{}

	for _, s := range later {
		e.refreshMarks()
		e.markInstall(s, true, 0, true)
	}

	if e.exceeded {
		return ErrResolveLimit
	}

	if brokenFix && e.brokenCount() != 0 {
		return e.planError()
	}

	var rerr error

	switch req.Upgrade {
	case UpgradeFull:
		rerr = e.distUpgrade()
	case UpgradeWithNew:
		rerr = e.allUpgrade(true)
	case UpgradeSafe:
		rerr = e.allUpgrade(false)
	default:
		rerr = r.resolveInternal(true)
	}

	if e.exceeded {
		return ErrResolveLimit
	}

	if rerr != nil {
		return rerr
	}

	plan.Manual = manual

	return e.autoRemove(req.AutoRemove, plan)
}

// fixBroken is apt's pkgFixBroken followed by pkgMinimizeUpgrade: upgrade
// and install around every broken package, run the resolver, then keep every
// upgrade that turns out not to be needed.
func (e *engine) fixBroken() error {
	e.ctx = Reason{Kind: ReasonUpgradeDependency}

	for _, key := range e.installedKeys() {
		if s := e.state(key); e.nowBroken(s) {
			e.markInstall(s, true, 0, false)
		}
	}

	e.ctx = Reason{}

	if err := newResolver(e).resolveInternal(true); err != nil {
		return err
	}

	if e.exceeded {
		return ErrResolveLimit
	}

	e.minimizeUpgrade()

	return nil
}

// maxMinimizePasses is apt's bound on the passes of pkgMinimizeUpgrade.
const maxMinimizePasses = 10

// minimizeUpgrade is apt's pkgMinimizeUpgrade: keep an upgraded package at
// its version when nothing breaks by it.
func (e *engine) minimizeUpgrade() {
	for range maxMinimizePasses {
		changed := false

		for _, key := range e.keys() {
			s := e.state(key)
			if s.mode != modeInstall || s.status <= 0 || s.cur == nil {
				continue
			}

			e.markKeep(s, false, 0)

			switch {
			case e.brokenCount() != 0:
				e.markInstall(s, false, 0, false)
			case s.mode != modeInstall || s.status <= 0:
				changed = true
			}
		}

		if !changed {
			return
		}
	}
}

// installedKeysOf lists the installed slots a name selects: the exact slot of
// "name:arch", else every installed architecture of the name.
func (e *engine) installedKeysOf(name string) []string {
	var keys []string

	for _, key := range e.c.slotKeysFor(name) {
		if e.c.installed[key] != nil && !slices.Contains(keys, key) {
			keys = append(keys, key)

			if strings.Contains(name, ":") {
				break
			}
		}
	}

	return keys
}

// parseSeeds reads the install requests, one dependency group each.
func (e *engine) parseSeeds(seeds []string) ([]deb.Alternatives, error) {
	var out []deb.Alternatives

	for _, seed := range seeds {
		seed = strings.TrimSpace(seed)
		if seed == "" {
			continue
		}

		groups, err := deb.ParseRelations(seed)
		if err != nil {
			return nil, fmt.Errorf("apt: request %q: %w", seed, err)
		}

		out = append(out, groups...)
	}

	return out, nil
}

// resolveSeed finds the package a request names, selects the candidate its
// version constraint asks for and returns its state. Without one it returns
// the name no package matched.
func (e *engine) resolveSeed(alts deb.Alternatives) (*pstate, string, error) {
	var first string

	for i := range alts {
		rel := &alts[i]

		if first == "" {
			first = rel.String()
		}

		name := rel.Name

		switch rel.Arch {
		case "", "any":
		case "native":
			name += ":" + e.c.hostArch
		default:
			name += ":" + rel.Arch
		}

		for _, key := range e.c.slotKeysFor(name) {
			versions := e.c.slots[key]
			if len(versions) == 0 {
				continue
			}

			s := e.state(key)

			// The candidate stands when it meets the constraint; else the
			// highest version that does.
			var pick *pkg

			if s.cand != nil && rel.Satisfied(s.cand.Version) {
				pick = s.cand
			} else if rel.Op != "" {
				for _, v := range versions {
					if rel.Satisfied(v.Version) && downloadable(v) {
						pick = v

						break
					}
				}
			}

			if pick == nil {
				continue
			}

			if s.cand != pick {
				e.setCandidate(s, pick)
			}

			return s, "", nil
		}

		if s, err := e.resolveVirtual(rel); s != nil || err != nil {
			return s, "", err
		}
	}

	return nil, first, nil
}

// resolveVirtual selects the package that provides a virtual name when
// exactly one package does.
func (e *engine) resolveVirtual(rel *deb.Relation) (*pstate, error) {
	var slots []string

	for _, p := range e.c.providers[rel.Name] {
		s := e.state(p.slot)
		if s.cand != p || !providesMatch(rel, p) || slices.Contains(slots, p.slot) {
			continue
		}

		slots = append(slots, p.slot)
	}

	switch len(slots) {
	case 0:
		return nil, nil
	case 1:
		return e.state(slots[0]), nil
	default:
		sort.Strings(slots)

		names := make([]string, len(slots))
		for i, k := range slots {
			names[i] = label(e.state(k).cand)
		}

		return nil, &VirtualPackageError{Name: rel.Name, Providers: names}
	}
}

// planError builds the error for the packages that stay broken.
func (e *engine) planError() error {
	var causes []error

	for _, k := range e.keys() {
		s := e.state(k)
		if !e.instBroken(s) {
			continue
		}

		for i := range e.depsOf(s.inst) {
			g := &e.depsOf(s.inst)[i]
			if e.groupOK(g, whenInstall) {
				continue
			}

			causes = append(causes, e.brokenCause(g))

			break
		}
	}

	return &PlanError{Broken: causes}
}

// brokenCause describes one unmet dependency or clash of the planned system.
func (e *engine) brokenCause(g *depGroup) error {
	if !g.negative() {
		return &UnsatisfiedError{
			Package: label(g.owner), Dependency: g.alts.String(),
			Reason: "no package in the planned system meets it",
		}
	}

	kind := "Conflicts"
	if g.kind == kindBreaks {
		kind = "Breaks"
	}

	ce := &ConflictError{Package: label(g.owner), Kind: kind, Relation: g.alts[0].String()}

	if hit := e.matches(g.owner, &g.alts[0], true, whenInstall); len(hit) > 0 {
		ce.With = label(hit[0])
		ce.WithInstalled = e.state(hit[0].slot).cur == hit[0]
	}

	return ce
}

// collect turns the final state into the lists of the plan, in the order the
// unpack and remove steps run (see [Plan]).
func (e *engine) collect(plan *Plan) {
	for _, k := range e.unpackSeq {
		s := e.state(k)

		if s.mode == modeDelete && s.cur != nil {
			plan.Changes = append(plan.Changes, Change{
				Kind: ChangeRemove, Package: &s.cur.PackageInfo, Reason: s.why,
			})
			plan.Remove = append(plan.Remove, &s.cur.PackageInfo)

			continue
		}

		ch := Change{Package: &s.inst.PackageInfo, Reason: s.why, Auto: s.auto}

		switch {
		case s.cur == nil:
			ch.Kind = ChangeInstall
			plan.Install = append(plan.Install, ch.Package)
		case deb.CompareVersions(s.inst.Version, s.cur.Version) < 0:
			ch.Kind = ChangeDowngrade
			ch.From = &s.cur.PackageInfo
			plan.Downgrade = append(plan.Downgrade, ch.Package)
		default:
			ch.Kind = ChangeUpgrade
			ch.From = &s.cur.PackageInfo
			plan.Upgrade = append(plan.Upgrade, ch.Package)
		}

		plan.Changes = append(plan.Changes, ch)
	}

	for _, s := range e.upgradable {
		if s.mode != modeDelete && (s.mode != modeInstall || s.status <= 0) {
			plan.Held = append(plan.Held, &s.cur.PackageInfo)
		}
	}
}
