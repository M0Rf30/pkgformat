package dnf

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/richdep"
)

// WeakDeps says whether a resolution installs the Recommends of the packages it
// installs.
type WeakDeps int

const (
	// WeakDefault takes install_weak_deps of the configuration, true unless
	// dnf.conf says otherwise.
	WeakDefault WeakDeps = iota
	// WeakEnabled installs Recommends, as install_weak_deps=1.
	WeakEnabled
	// WeakDisabled installs no Recommends, as install_weak_deps=0 or
	// --setopt=install_weak_deps=False.
	WeakDisabled
)

// ResolveOptions tunes [Index.ResolveWith].
type ResolveOptions struct {
	// WeakDeps overrides install_weak_deps of the configuration.
	WeakDeps WeakDeps
}

// Replacement is an installed package that the transaction takes away: Old is
// replaced by New, either a newer version of the same package (an upgrade) or
// a package that obsoletes it.
type Replacement struct {
	Old *Package
	New *Package
}

// Conflict is a package the transaction cannot have: Package, which is
// requested or required, conflicts with With, which is installed or chosen,
// by Capability. Capability is the text of the Conflicts entry of the package
// that declares it. With is nil for a conflict declared by a rich dependency.
// For an installed package that a newer version of the transaction breaks,
// Package is the one that breaks it and Capability the requirement.
type Conflict struct {
	Package    *Package
	With       *Package
	Capability string
}

// Resolution is the outcome of [Index.Resolve].
type Resolution struct {
	// Packages are the packages to install or upgrade, dependencies before the
	// packages that need them.
	Packages []*Package
	// Upgrades are the installed packages that Packages replace with a newer
	// version, Obsoleted those replaced by a package of another name.
	Upgrades  []Replacement
	Obsoleted []Replacement
	// Unresolved are the requirements no package satisfies: the capability as
	// written, "name >= 1.2" or a rich dependency "(a if b)", for hard
	// requirements of the packages and the requested specs.
	Unresolved []string
	// Conflicts are the packages left out, or the installed packages broken,
	// because of a conflict.
	Conflicts []Conflict
	// Removed are the installed packages of installonly kinds (kernels) that
	// the transaction removes because more than installonly_limit versions
	// would be left, the oldest first.
	Removed []*Package
}

// Resolve is [Index.ResolveWith] with the default options.
func (ix *Index) Resolve(ctx context.Context, seeds []string) (*Resolution, error) {
	return ix.ResolveWith(ctx, seeds, ResolveOptions{})
}

// ResolveWith chooses the packages to install so that the seeds, which are
// specs ([Index.Match]) or else capabilities (a name, "name >= 1.2" or a file
// path), are installed with everything they need.
//
// It looks at what the host has, per Options.Installed, with versions: a
// requirement that an installed package provides is met, and so is one met by
// the packages already chosen; otherwise the best provider is installed, and a
// provider newer than an installed package of its name upgrades it. Of
// several providers, those of the best repository priority are considered,
// then those of the name asked for, then per name the host's architecture
// before the compatible ones, the highest version, the lowest cost and the
// earliest in the metadata; see [Index.Match] for the specs.
//
// Obsoletes of a chosen package remove the installed packages they name;
// Conflicts rule candidates out, and a conflict that leaves no candidate is
// reported in Resolution.Conflicts. Rich dependencies are evaluated with
// [richdep]: "and" needs every part, "or" the first part that can be had, "if",
// "unless" and their "else" depend on what the transaction holds, so they are
// looked at again once it is complete, and "with" and "without" need one
// package that matches. A requirement of a file path is looked up in the primary
// metadata and, when nothing is satisfied there, in the file lists of the
// repositories, which are fetched then. Installed packages whose requirements
// an upgrade breaks are upgraded in turn when a newer version helps.
//
// It is a greedy search over the dependency graph, not a SAT solver, and does not
// backtrack on a choice it has made: see the package documentation for how it
// differs from dnf's.
func (ix *Index) ResolveWith(ctx context.Context, seeds []string, opts ResolveOptions) (*Resolution, error) {
	s, err := newSolver(ctx, ix, opts)
	if err != nil {
		return nil, err
	}

	s.run(seeds)

	if s.err == nil {
		s.dropRedundant()
	}

	if s.err != nil {
		return nil, s.err
	}

	return s.result(), nil
}

// confRef is an entry of the conflicts or obsoletes of a package.
type confRef struct {
	pkg  *Package
	atom richdep.Atom
}

// state is what a transaction holds so far. The maps and slices it points to
// are replaced, not changed in place, once cloned, so a clone is cheap and a
// failed attempt is undone by dropping it.
type state struct {
	order      []*Package
	selected   map[*Package]bool
	prov       map[string][]provRef
	byName     map[string][]*Package
	files      map[string][]*Package
	conf       map[string][]confRef
	obs        map[string][]confRef
	gone       map[*Package]*Package
	upgrades   []Replacement
	obsoleted  []Replacement
	unresolved []string
	conflicts  []Conflict
	deferred   []deferred
	pending    []request
	failed     bool
}

// deferred is a conditional requirement to look at again once the
// transaction has grown.
type deferred struct {
	owner *Package
	node  *richdep.Expr
}

func (st *state) clone() *state {
	c := *st
	c.order = slices.Clone(st.order)
	c.selected = maps.Clone(st.selected)
	c.prov = maps.Clone(st.prov)
	c.byName = maps.Clone(st.byName)
	c.files = maps.Clone(st.files)
	c.conf = maps.Clone(st.conf)
	c.obs = maps.Clone(st.obs)
	c.gone = maps.Clone(st.gone)
	c.upgrades = slices.Clone(st.upgrades)
	c.obsoleted = slices.Clone(st.obsoleted)
	c.unresolved = slices.Clone(st.unresolved)
	c.conflicts = slices.Clone(st.conflicts)
	c.deferred = slices.Clone(st.deferred)
	c.pending = slices.Clone(st.pending)

	return &c
}

// appendTo adds v to m[key] without writing to the backing array of the list a
// clone of the map shares.
func appendTo[K comparable, V any](m map[K][]V, key K, v V) {
	m[key] = append(slices.Clip(m[key]), v)
}

type solver struct {
	ctx  context.Context //nolint:containedctx // the solver lives for one call
	ix   *Index
	weak bool
	best bool
	err  error

	// installOnly caches which packages are never replaced by a newer
	// version; onlyNames are the installonlypkgs.
	installOnly map[*Package]bool
	onlyNames   map[string]bool

	inst       []*Package
	instProv   map[string][]provRef
	instFiles  map[string][]*Package
	instByName map[string][]*Package
	instConf   map[string][]confRef
	instObs    map[string][]confRef

	st *state

	// omit is a package of the transaction that satisfiers leaves out, to see
	// what holds without it.
	omit *Package
	// requested are the packages the seeds name; wanted the capabilities they
	// name; kept the packages chosen for the weak dependencies.
	requested map[*Package]bool
	wanted    []richdep.Atom
	kept      map[*Package]bool

	nodes     map[string]richdep.Node
	ids       map[*Package]string
	byID      map[string]*Package
	weakDone  map[*Package]bool
	reported  map[string]bool
	fileFails map[string]bool
}

func newSolver(ctx context.Context, ix *Index, opts ResolveOptions) (*solver, error) {
	s := &solver{
		ctx:        ctx,
		ix:         ix,
		instProv:   make(map[string][]provRef),
		instFiles:  make(map[string][]*Package),
		instByName: make(map[string][]*Package),
		instConf:   make(map[string][]confRef),
		instObs:    make(map[string][]confRef),
		nodes:      make(map[string]richdep.Node),
		ids:        make(map[*Package]string),
		byID:       make(map[string]*Package),
		weakDone:   make(map[*Package]bool),
		reported:   make(map[string]bool),
		requested:  make(map[*Package]bool),
		kept:       make(map[*Package]bool),
		fileFails:  make(map[string]bool),
		st: &state{
			selected: make(map[*Package]bool),
			prov:     make(map[string][]provRef),
			byName:   make(map[string][]*Package),
			files:    make(map[string][]*Package),
			conf:     make(map[string][]confRef),
			obs:      make(map[string][]confRef),
			gone:     make(map[*Package]*Package),
		},
	}

	cfg := ix.cfg
	if cfg == nil {
		cfg = DefaultConfig()
	}

	s.best = cfg.Best
	s.onlyNames = make(map[string]bool, len(cfg.InstallOnlyPkgs))
	s.installOnly = make(map[*Package]bool)

	for _, n := range cfg.InstallOnlyPkgs {
		s.onlyNames[n] = true
	}

	switch opts.WeakDeps {
	case WeakEnabled:
		s.weak = true
	case WeakDisabled:
		s.weak = false
	default:
		s.weak = ix.cfg == nil || ix.cfg.InstallWeakDeps
	}

	if ix.installed == nil {
		return s, nil
	}

	pkgs, err := ix.installed.InstalledPackages(ctx)
	if err != nil {
		return nil, fmt.Errorf("dnf: reading installed packages: %w", err)
	}

	for _, rp := range pkgs {
		p := fromInstalled(rp)
		s.inst = append(s.inst, p)
		s.instByName[p.Name] = append(s.instByName[p.Name], p)

		for _, d := range p.Provides {
			s.instProv[d.Name] = append(s.instProv[d.Name], provRef{pkg: p, atom: richdep.AtomOf(d)})
		}

		for _, f := range p.Files {
			s.instFiles[f] = append(s.instFiles[f], p)
		}

		for _, d := range p.Conflicts {
			s.instConf[d.Name] = append(s.instConf[d.Name], confRef{pkg: p, atom: richdep.AtomOf(d)})
		}

		for _, d := range p.Obsoletes {
			s.instObs[d.Name] = append(s.instObs[d.Name], confRef{pkg: p, atom: richdep.AtomOf(d)})
		}
	}

	return s, nil
}

func (s *solver) id(p *Package) string {
	if id, ok := s.ids[p]; ok {
		return id
	}

	id := strconv.Itoa(len(s.ids))
	s.ids[p] = id
	s.byID[id] = p

	return id
}

// canceled records the context error and reports whether the work stops.
func (s *solver) canceled() bool {
	if s.err == nil {
		s.err = s.ctx.Err()
	}

	return s.err != nil
}

// result assembles the outcome from the state.
func (s *solver) result() *Resolution {
	return &Resolution{
		Packages:   s.dependencyOrder(),
		Upgrades:   slices.Clone(s.st.upgrades),
		Obsoleted:  slices.Clone(s.st.obsoleted),
		Unresolved: slices.Clone(s.st.unresolved),
		Conflicts:  slices.Clone(s.st.conflicts),
		Removed:    s.removedOnly(),
	}
}

// onlyKind reports whether p is of an installonly kind: its name or a
// capability it provides is in installonlypkgs. Such a package is installed
// next to its older versions instead of replacing them.
func (s *solver) onlyKind(p *Package) bool {
	if v, ok := s.installOnly[p]; ok {
		return v
	}

	v := s.onlyNames[p.Name] ||
		slices.ContainsFunc(p.Provides, func(d rpm.Dependency) bool { return s.onlyNames[d.Name] })
	s.installOnly[p] = v

	return v
}

// removedOnly returns the installed packages of installonly kinds to remove so
// that no more than installonly_limit versions of a name stay, once the
// transaction has added its own. Only names the transaction installs are
// looked at, the oldest versions go first, and the packages of the
// transaction stay.
func (s *solver) removedOnly() []*Package {
	limit := DefaultConfig().InstallOnlyLimit
	if s.ix.cfg != nil {
		limit = s.ix.cfg.InstallOnlyLimit
	}

	if limit < 2 {
		return nil
	}

	groups := make(map[string][]*Package)
	touched := make(map[string]bool)

	for _, q := range s.inst {
		if s.st.gone[q] == nil && s.onlyKind(q) {
			groups[q.Name] = append(groups[q.Name], q)
		}
	}

	for _, p := range s.st.order {
		if s.onlyKind(p) {
			groups[p.Name] = append(groups[p.Name], p)
			touched[p.Name] = true
		}
	}

	var out []*Package

	for _, name := range slices.Sorted(maps.Keys(touched)) {
		list := groups[name]
		slices.SortStableFunc(list, func(a, b *Package) int { return a.Compare(b) })

		excess := len(list) - limit

		for _, q := range list {
			if excess <= 0 {
				break
			}

			if q.Installed() && !s.st.selected[q] {
				out = append(out, q)
				excess--
			}
		}
	}

	return out
}

// maxRounds bounds the passes that look at conditional, weak and repair work
// again after the transaction grew.
const maxRounds = 64

// run resolves the seeds and then the work they leave: conditional
// dependencies, weak dependencies and the repair of installed packages.
func (s *solver) run(seeds []string) {
	for _, spec := range seeds {
		if s.canceled() {
			return
		}

		s.seed(spec)
	}

	s.drain()

	for range maxRounds {
		if s.canceled() {
			return
		}

		grew := s.runDeferred()
		grew = s.repairInstalled() || grew

		if s.weak {
			grew = s.runWeak() || grew
		}

		if !grew {
			return
		}
	}
}

// seed installs what a spec names.
func (s *solver) seed(spec string) {
	if strings.TrimSpace(spec) == "" {
		return
	}

	matches := s.ix.Match(spec)
	if len(matches) == 0 {
		a := parseCapability(spec)
		if len(s.satisfiers(a)) > 0 {
			s.replaceObsoleted(a)

			return
		}

		s.wanted = append(s.wanted, a)
		s.want(a, nil, false)

		return
	}

	// With best, the newest version asked for is the one to have: when it
	// cannot be installed, nothing is.
	if head := matches[0]; s.best && !s.st.selected[head] && !s.isInstalledAs(head) && !s.installable(head) {
		s.reportConflict(head)

		return
	}

	// The package asked for is the preferred one of the matches that is not
	// a version already installed or an older one.
	var first *Package

	for _, p := range matches {
		if !s.st.selected[p] && s.installable(p) {
			first = p

			break
		}
	}

	if first == nil {
		if !slices.ContainsFunc(matches, func(p *Package) bool { return s.st.selected[p] || s.isInstalledAs(p) }) {
			s.reportConflict(matches[0])
		}

		return
	}

	chosen := first
	if s.best {
		s.install(first)
	} else {
		chosen = s.installOrOlder(matches, first)
	}

	s.requested[chosen] = true

	if s.ix.cfg != nil && s.ix.cfg.MultilibPolicy == MultilibAll {
		for _, p := range matches {
			if p != chosen && p.Name == chosen.Name && isMultilibArch(s.ix.arch, p.Arch) && s.installable(p) {
				s.requested[p] = true
				s.install(p)
			}
		}
	}
}

// replaceObsoleted installs, for a name that is asked for and already
// installed, the package that obsoletes the installed one, as dnf does.
func (s *solver) replaceObsoleted(a richdep.Atom) {
	if s.ix.cfg != nil && !s.ix.cfg.Obsoletes {
		return
	}

	var cands []*Package

	for _, q := range s.instByName[a.Name] {
		if s.st.gone[q] != nil {
			continue
		}

		self := richdep.AtomOf(q.self())

		for _, p := range s.ix.obsoleters[q.Name] {
			if !slices.Contains(cands, p) && s.installable(p) && slices.ContainsFunc(p.Obsoletes, func(d rpm.Dependency) bool {
				return d.Name == q.Name && richdep.AtomOf(d).Overlaps(self)
			}) {
				cands = append(cands, p)
			}
		}
	}

	if len(cands) == 0 {
		return
	}

	for _, p := range s.bestPerName(cands) {
		s.requested[p] = true
		s.install(p)
	}
}

// installOrOlder installs first, or, when that leaves a requirement unmet or
// a conflict, the next best version of the same package that does not; when
// none does, first is installed so that its problems are reported.
func (s *solver) installOrOlder(cands []*Package, first *Package) *Package {
	alts := []*Package{first}

	for _, p := range cands {
		if p != first && p.Name == first.Name && p.Arch == first.Arch && s.installable(p) {
			alts = append(alts, p)
		}
	}

	if len(alts) == 1 {
		s.install(first)

		return first
	}

	slices.SortStableFunc(alts[1:], s.ix.compare)

	for _, p := range alts {
		if s.try(func() { s.install(p) }) {
			return p
		}
	}

	s.install(first)

	return first
}

// isInstalledAs reports whether an installed package is p or newer than p.
func (s *solver) isInstalledAs(p *Package) bool {
	only := s.onlyKind(p)

	for _, q := range s.instByName[p.Name] {
		if s.st.gone[q] != nil || !sameSlot(q, p) {
			continue
		}

		if c := q.Compare(p); c == 0 || (c > 0 && !only) {
			return true
		}
	}

	return false
}

// reportConflict records why a requested package cannot be installed.
func (s *solver) reportConflict(p *Package) {
	if other, cap := s.conflictOf(p); other != nil || cap != "" {
		s.st.conflicts = append(s.st.conflicts, Conflict{Package: p, With: other, Capability: cap})

		return
	}

	s.st.conflicts = append(s.st.conflicts, Conflict{Package: p, Capability: p.Name})
}

// sameSlot reports whether two packages are versions of one installed slot:
// the same name for the same architecture, or either being noarch.
func sameSlot(a, b *Package) bool {
	return a.Name == b.Name && (a.Arch == b.Arch || a.Arch == archNoarch || b.Arch == archNoarch)
}

// node returns the parsed form of a dependency entry.
func (s *solver) node(d rpm.Dependency) (richdep.Node, error) {
	if !strings.HasPrefix(d.Name, "(") {
		return richdep.AtomOf(d), nil
	}

	if n, ok := s.nodes[d.Name]; ok {
		return n, nil
	}

	n, err := richdep.Parse(d.Name)
	if err != nil {
		return nil, err
	}

	s.nodes[d.Name] = n

	return n, nil
}

// satisfiers returns the packages of the host and of the transaction that
// provide the capability. For a file path the owners count too.
func (s *solver) satisfiers(a richdep.Atom) []*Package {
	var out []*Package

	for _, r := range s.instProv[a.Name] {
		if s.st.gone[r.pkg] == nil && r.atom.Overlaps(a) {
			out = append(out, r.pkg)
		}
	}

	for _, r := range s.st.prov[a.Name] {
		if r.pkg != s.omit && r.atom.Overlaps(a) {
			out = append(out, r.pkg)
		}
	}

	if len(out) > 0 || !strings.HasPrefix(a.Name, "/") {
		return out
	}

	for _, p := range s.instFiles[a.Name] {
		if s.st.gone[p] == nil {
			out = append(out, p)
		}
	}

	for _, p := range s.st.files[a.Name] {
		if p != s.omit {
			out = append(out, p)
		}
	}

	if len(out) > 0 || s.st.order == nil {
		return out
	}

	// A file that only filelists.xml lists, owned by a package of the
	// transaction.
	for _, o := range s.fileOwners(a.Name) {
		if s.st.selected[o] && o != s.omit {
			out = append(out, o)
		}
	}

	return out
}

// fileOwners returns the repository packages that own the path, reading the
// file lists when they have to be; a failure to read them is logged once and
// the lookup then has what primary.xml gave.
func (s *solver) fileOwners(p string) []*Package {
	owners, err := s.ix.FileOwners(s.ctx, p)
	if err != nil && s.ctx.Err() == nil && !s.fileFails[p] {
		s.fileFails[p] = true
		s.ix.logger.Warn("file requirement looked up without the file lists", "file", p, "error", err)
	}

	return owners
}

// oracle answers richdep questions from what the transaction and the host
// hold, or, for the sets of "with" and "without", from everything that could
// be installed too.
type oracle struct {
	s    *solver
	repo bool
}

func (o oracle) Satisfiers(a richdep.Atom) []string {
	var ids []string

	for _, p := range o.s.satisfiers(a) {
		ids = append(ids, o.s.id(p))
	}

	if !o.repo {
		return ids
	}

	for _, p := range o.s.providers(a) {
		if id := o.s.id(p); !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}

	return ids
}

// eval reports whether a dependency holds in the current state.
func (s *solver) eval(n richdep.Node) bool {
	return richdep.Eval(n, oracle{s: s})
}

// providers returns the packages of the repositories that provide the
// capability, owners of a file path included.
func (s *solver) providers(a richdep.Atom) []*Package {
	list := s.ix.providersOf(a)

	if strings.HasPrefix(a.Name, "/") {
		for _, o := range s.fileOwners(a.Name) {
			if !slices.Contains(list, o) {
				list = append(list, o)
			}
		}
	}

	return list
}

// unresolve records a requirement nothing satisfies.
func (s *solver) unresolve(text string) {
	if !slices.Contains(s.st.unresolved, text) {
		s.st.unresolved = append(s.st.unresolved, text)
	}
}

// request is a requirement of the transaction that is not met yet.
type request struct {
	node  richdep.Node
	owner *Package
	// soft: failing to meet it is not recorded as unresolved, it only makes the
	// attempt that holds it fail.
	soft bool
}

// outcome is what looking at a request led to.
type outcome int

const (
	dropped  outcome = iota // met already, or recorded as unmet
	acted                   // a package was added
	expanded                // replaced by the requests it is made of
	waiting                 // several packages meet it: left for later
)

// want queues a requirement.
func (s *solver) want(n richdep.Node, owner *Package, soft bool) {
	s.st.pending = append(s.st.pending, request{node: n, owner: owner, soft: soft})
}

// wantDep queues the requirement of a dependency entry.
func (s *solver) wantDep(d rpm.Dependency, owner *Package, soft bool) {
	n, err := s.node(d)
	if err != nil {
		s.fail(d.Name, soft)

		return
	}

	s.want(n, owner, soft)
}

// fail records that a requirement cannot be met.
func (s *solver) fail(text string, soft bool) {
	if soft {
		s.st.failed = true

		return
	}

	s.unresolve(text)
}

// drain meets the queued requirements, the way a SAT solver does: those that
// only one package can meet first, in the order they were queued, and a choice
// among several packages only when nothing is forced, for the earliest
// requirement.
func (s *solver) drain() {
	for len(s.st.pending) > 0 && !s.canceled() {
		if s.pass() {
			continue
		}

		if len(s.st.pending) == 0 {
			return
		}

		r := s.st.pending[0]
		s.st.pending = s.st.pending[1:]
		s.step(r, true)
	}
}

// pass goes through the queue once, taking every package that is forced, and
// reports whether it took one.
func (s *solver) pass() bool {
	queue := s.st.pending
	s.st.pending = nil

	var wait []request

	progressed := false

	for len(queue) > 0 && !s.canceled() {
		r := queue[0]
		queue = queue[1:]

		out, repl := s.step(r, false)
		switch out {
		case acted:
			progressed = true
		case expanded:
			queue = append(repl, queue...)
		case waiting:
			wait = append(wait, r)
		case dropped:
		}
	}

	s.st.pending = append(wait, s.st.pending...)

	return progressed
}

// step looks at one request. With force, a choice among several packages is
// made instead of being left for later.
func (s *solver) step(r request, force bool) (outcome, []request) {
	switch n := r.node.(type) {
	case richdep.Atom:
		return s.stepAtom(n, r, force), nil
	case *richdep.Expr:
		return s.stepExpr(n, r, force)
	}

	return dropped, nil
}

func (s *solver) stepAtom(a richdep.Atom, r request, force bool) outcome {
	if len(s.satisfiers(a)) > 0 {
		return dropped
	}

	cands := s.filterInstallable(s.providers(a))
	if len(cands) == 0 {
		s.fail(a.String(), r.soft)

		return dropped
	}

	if !force && len(s.bestPerName(cands)) > 1 {
		return waiting
	}

	s.installOrOlder(cands, s.pick(cands, a))

	return acted
}

func (s *solver) stepExpr(e *richdep.Expr, r request, force bool) (outcome, []request) {
	if s.eval(e) && e.Op != richdep.OpIf && e.Op != richdep.OpUnless {
		return dropped, nil
	}

	sub := func(nodes ...richdep.Node) []request {
		out := make([]request, len(nodes))
		for i, n := range nodes {
			out[i] = request{node: n, owner: r.owner, soft: r.soft}
		}

		return out
	}

	switch e.Op {
	case richdep.OpAnd:
		return expanded, sub(e.Args...)
	case richdep.OpOr:
		if !force {
			return waiting, nil
		}

		for _, branch := range e.Args {
			if s.try(func() { s.want(branch, r.owner, true) }) {
				return acted, nil
			}
		}

		s.fail(e.String(), r.soft)

		return dropped, nil
	case richdep.OpIf, richdep.OpUnless:
		if d := (deferred{owner: r.owner, node: e}); !slices.Contains(s.st.deferred, d) {
			s.st.deferred = append(s.st.deferred, d)
		}

		switch {
		case s.eval(e.Args[1]) == (e.Op == richdep.OpIf):
			return expanded, sub(e.Args[0])
		case len(e.Args) > 2:
			return expanded, sub(e.Args[2])
		default:
			return dropped, nil
		}
	case richdep.OpWith, richdep.OpWithout:
		return s.stepSet(e, r, force), nil
	case richdep.OpElse:
		return expanded, sub(e.Args[0])
	}

	return dropped, nil
}

// stepSet meets a "with" or "without" by one package that meets it.
func (s *solver) stepSet(e *richdep.Expr, r request, force bool) outcome {
	var cands []*Package

	for _, id := range richdep.Set(e, oracle{s: s, repo: true}) {
		if p := s.byID[id]; p != nil && !p.Installed() {
			cands = append(cands, p)
		}
	}

	cands = s.filterInstallable(cands)
	if len(cands) == 0 {
		s.fail(e.String(), r.soft)

		return dropped
	}

	if !force && len(s.bestPerName(cands)) > 1 {
		return waiting
	}

	s.install(s.pick(cands, richdep.Atom{}))

	return acted
}

// try runs fn, which queues requirements or adds packages, and meets what it
// queued, all on a copy of the state, and keeps the result only when nothing
// failed.
func (s *solver) try(fn func()) bool {
	saved := s.st
	s.st = saved.clone()
	outer := s.st.pending
	s.st.pending = nil

	fn()
	s.drain()

	if !s.st.failed && len(s.st.unresolved) == len(saved.unresolved) && len(s.st.conflicts) == len(saved.conflicts) {
		s.st.pending = outer

		return true
	}

	s.st = saved

	return false
}

// filterInstallable keeps the candidates the transaction can take.
func (s *solver) filterInstallable(list []*Package) []*Package {
	out := list[:0:0]

	for _, p := range list {
		if s.installable(p) {
			out = append(out, p)
		}
	}

	return out
}

// installable reports whether p can be added to the transaction: it is not one
// already chosen or installed, it does not clash with another version of its
// name, and it neither conflicts with nor is obsoleted by anything the
// transaction holds.
func (s *solver) installable(p *Package) bool {
	if s.st.selected[p] {
		return false
	}

	if s.onlyKind(p) {
		// every version may be there, but not twice
		for _, q := range s.st.byName[p.Name] {
			if sameSlot(q, p) && q.Compare(p) == 0 {
				return false
			}
		}

		for _, q := range s.instByName[p.Name] {
			if s.st.gone[q] == nil && sameSlot(q, p) && q.Compare(p) == 0 {
				return false
			}
		}
	} else if !s.versionFree(p) {
		return false
	}

	if s.obsoletedByState(p) {
		return false
	}

	other, cap := s.conflictOf(p)

	return other == nil && cap == ""
}

// versionFree reports whether p fits next to the packages of its name that the
// transaction and the host hold: only another architecture of the same version,
// or an installed older version that p replaces, may be there.
func (s *solver) versionFree(p *Package) bool {
	for _, q := range s.st.byName[p.Name] {
		if sameSlot(q, p) || q.Compare(p) != 0 {
			return false
		}
	}

	for _, q := range s.instByName[p.Name] {
		if s.st.gone[q] != nil {
			continue
		}

		if sameSlot(q, p) {
			if p.Compare(q) <= 0 {
				return false
			}
		} else if q.Compare(p) != 0 {
			return false
		}
	}

	return true
}

// obsoletedByState reports whether an installed or chosen package obsoletes p.
func (s *solver) obsoletedByState(p *Package) bool {
	if s.ix.cfg != nil && !s.ix.cfg.Obsoletes {
		return false
	}

	self := richdep.AtomOf(p.self())

	for _, r := range s.instObs[p.Name] {
		if r.pkg.Name != p.Name && s.st.gone[r.pkg] == nil && r.atom.Overlaps(self) {
			return true
		}
	}

	for _, r := range s.st.obs[p.Name] {
		if r.pkg.Name != p.Name && r.atom.Overlaps(self) {
			return true
		}
	}

	return false
}

// replacedBy returns the installed packages that installing p takes away: the
// older version of its name and the packages it obsoletes.
func (s *solver) replacedBy(p *Package) []*Package {
	var out []*Package

	if !s.onlyKind(p) {
		for _, q := range s.instByName[p.Name] {
			if s.st.gone[q] == nil && sameSlot(q, p) && p.Compare(q) > 0 {
				out = append(out, q)
			}
		}
	}

	if s.ix.cfg != nil && !s.ix.cfg.Obsoletes {
		return out
	}

	for _, ob := range p.Obsoletes {
		if ob.Name == p.Name {
			continue
		}

		a := richdep.AtomOf(ob)

		for _, q := range s.instByName[ob.Name] {
			if s.st.gone[q] == nil && !slices.Contains(out, q) && richdep.AtomOf(q.self()).Overlaps(a) {
				out = append(out, q)
			}
		}
	}

	return out
}

// conflictOf returns what p conflicts with in the host and the transaction: a
// package and the capability, or only the text of a rich conflict.
func (s *solver) conflictOf(p *Package) (*Package, string) {
	replaced := s.replacedBy(p)

	for _, d := range p.Conflicts {
		if strings.HasPrefix(d.Name, "(") {
			if n, err := s.node(d); err == nil && s.eval(n) {
				return nil, d.Name
			}

			continue
		}

		a := richdep.AtomOf(d)

		for _, q := range s.provided(a) {
			if q != p && !slices.Contains(replaced, q) {
				return q, a.String()
			}
		}
	}

	for _, pr := range p.Provides {
		self := richdep.AtomOf(pr)

		for _, r := range s.instConf[pr.Name] {
			if r.pkg != p && s.st.gone[r.pkg] == nil && !slices.Contains(replaced, r.pkg) && r.atom.Overlaps(self) {
				return r.pkg, r.atom.String()
			}
		}

		for _, r := range s.st.conf[pr.Name] {
			if r.pkg != p && r.atom.Overlaps(self) {
				return r.pkg, r.atom.String()
			}
		}
	}

	return nil, ""
}

// provided returns the installed and chosen packages with a provide that
// meets a, without looking at files.
func (s *solver) provided(a richdep.Atom) []*Package {
	var out []*Package

	for _, r := range s.instProv[a.Name] {
		if s.st.gone[r.pkg] == nil && r.atom.Overlaps(a) {
			out = append(out, r.pkg)
		}
	}

	for _, r := range s.st.prov[a.Name] {
		if r.atom.Overlaps(a) {
			out = append(out, r.pkg)
		}
	}

	return out
}

// install adds p to the transaction, takes away what it replaces, and makes its
// requirements hold; the packages those pull in come before it in the order.
func (s *solver) install(p *Package) {
	if s.st.selected[p] {
		return
	}

	for _, q := range s.replacedBy(p) {
		s.st.gone[q] = p

		if q.Name == p.Name {
			s.st.upgrades = append(s.st.upgrades, Replacement{Old: q, New: p})
		} else {
			s.st.obsoleted = append(s.st.obsoleted, Replacement{Old: q, New: p})
		}
	}

	s.st.selected[p] = true

	appendTo(s.st.byName, p.Name, p)

	for _, d := range p.Provides {
		appendTo(s.st.prov, d.Name, provRef{pkg: p, atom: richdep.AtomOf(d)})
	}

	for _, f := range p.Files {
		appendTo(s.st.files, f, p)
	}

	for _, d := range p.Conflicts {
		if !strings.HasPrefix(d.Name, "(") {
			appendTo(s.st.conf, d.Name, confRef{pkg: p, atom: richdep.AtomOf(d)})
		}
	}

	for _, d := range p.Obsoletes {
		appendTo(s.st.obs, d.Name, confRef{pkg: p, atom: richdep.AtomOf(d)})
	}

	s.st.order = append(s.st.order, p)

	for _, d := range p.Requires {
		s.wantDep(d, p, false)
	}
}

// bestPerName keeps, of the candidates of the best repository priority, the
// best package of each name.
func (s *solver) bestPerName(cands []*Package) []*Package {
	prio := cands[0].Priority
	for _, p := range cands[1:] {
		prio = min(prio, p.Priority)
	}

	var best []*Package

	for _, p := range cands {
		if p.Priority != prio {
			continue
		}

		i := slices.IndexFunc(best, func(b *Package) bool { return b.Name == p.Name })
		switch {
		case i < 0:
			best = append(best, p)
		case s.ix.compare(p, best[i]) < 0:
			best[i] = p
		}
	}

	return best
}

// pick chooses the package to take among candidates that provide a.
func (s *solver) pick(cands []*Package, a richdep.Atom) *Package {
	best := s.bestPerName(cands)
	if len(best) == 1 {
		return best[0]
	}

	best = s.favored(best, func(p *Package) []rpm.Dependency { return p.Recommends })
	best = s.favored(best, func(p *Package) []rpm.Dependency { return p.Suggests })

	slices.SortStableFunc(best, func(x, y *Package) int { return s.prefer(x, y, a) })

	return best[0]
}

// favored narrows candidates of different names to those that a package of
// the transaction or of the host names in the weak dependency list that list
// returns, which libsolv does too when it has to choose, whether or not weak
// dependencies are installed. When none is named, all stay.
func (s *solver) favored(cands []*Package, list func(*Package) []rpm.Dependency) []*Package {
	if len(cands) < 2 {
		return cands
	}

	var out []*Package

	named := func(owner *Package) {
		for _, d := range list(owner) {
			if strings.HasPrefix(d.Name, "(") {
				continue
			}

			a := richdep.AtomOf(d)

			for _, c := range cands {
				if !slices.Contains(out, c) && c != owner && provides(c, a) {
					out = append(out, c)
				}
			}
		}
	}

	for _, p := range s.st.order {
		named(p)
	}

	for _, q := range s.inst {
		if s.st.gone[q] == nil {
			named(q)
		}
	}

	if len(out) == 0 {
		return cands
	}

	return out
}

// provides reports whether p provides something that meets a.
func provides(p *Package, a richdep.Atom) bool {
	for _, d := range p.Provides {
		if d.Name == a.Name && richdep.AtomOf(d).Overlaps(a) {
			return true
		}
	}

	return false
}

// prefer orders the packages of different names that provide a capability:
// the name asked for, then a name that is installed (an upgrade over a new
// package), then the better architecture, then the name.
func (s *solver) prefer(x, y *Package, a richdep.Atom) int {
	if ex, ey := x.Name == a.Name, y.Name == a.Name; ex != ey {
		if ex {
			return -1
		}

		return 1
	}

	if ix, iy := s.hasInstalled(x), s.hasInstalled(y); ix != iy {
		if ix {
			return -1
		}

		return 1
	}

	if c := s.ix.compare(x, y); c != 0 && x.Arch != y.Arch {
		return c
	}

	return strings.Compare(x.Name, y.Name)
}

func (s *solver) hasInstalled(p *Package) bool {
	return len(s.instByName[p.Name]) > 0
}

// runDeferred looks at the conditional dependencies again and reports whether
// the transaction grew.
func (s *solver) runDeferred() bool {
	grew := false

	// ensure may add entries: the ones it adds are looked at in the next round.
	for _, d := range slices.Clone(s.st.deferred) {
		before := len(s.st.order)

		s.want(d.node, d.owner, false)
		s.drain()

		if len(s.st.order) != before {
			grew = true
		}
	}

	return grew
}

// runWeak installs the Recommends of the packages of the transaction that can
// be had, and reports whether the transaction grew.
func (s *solver) runWeak() bool {
	grew := false

	for i := 0; i < len(s.st.order); i++ {
		p := s.st.order[i]
		if s.weakDone[p] {
			continue
		}

		s.weakDone[p] = true

		for _, d := range p.Recommends {
			before := len(s.st.order)

			s.try(func() { s.wantDep(d, p, true) })

			if len(s.st.order) != before {
				grew = true

				for _, q := range s.st.order[before:] {
					s.kept[q] = true
				}
			}
		}

		for _, q := range s.supplementers(p) {
			before := len(s.st.order)

			s.try(func() { s.install(q) })

			if len(s.st.order) != before {
				grew = true

				for _, k := range s.st.order[before:] {
					s.kept[k] = true
				}
			}
		}
	}

	return grew
}

// supplementers returns the packages to install because they supplement p
// and what the transaction and the host hold: the best of each name that is
// not there yet, can be installed, and has a Supplements entry that holds.
func (s *solver) supplementers(p *Package) []*Package {
	names := []string{p.Name}
	for _, d := range p.Provides {
		names = append(names, d.Name)
	}

	var cands []*Package

	for _, name := range names {
		for _, q := range s.ix.supplements[name] {
			if !slices.Contains(cands, q) && s.supplemented(q) {
				cands = append(cands, q)
			}
		}
	}

	cands = s.filterInstallable(cands)
	if len(cands) == 0 {
		return nil
	}

	return s.bestPerName(cands)
}

// supplemented reports whether a Supplements entry of q holds.
func (s *solver) supplemented(q *Package) bool {
	for _, d := range q.Supplements {
		if n, err := s.node(d); err == nil && s.eval(n) {
			return true
		}
	}

	return false
}

// repairInstalled looks at the installed packages that need something the
// transaction takes away, and tries to keep them working: by satisfying the
// requirement from another package, or by upgrading them. What it cannot
// mend is reported as a conflict. It reports whether the transaction grew.
func (s *solver) repairInstalled() bool {
	if len(s.st.gone) == 0 {
		return false
	}

	lost := make(map[string]bool)

	for q := range s.st.gone {
		for _, d := range q.Provides {
			lost[d.Name] = true
		}

		for _, f := range q.Files {
			lost[f] = true
		}
	}

	grew := false

	for _, q := range s.inst {
		if s.st.gone[q] != nil {
			continue
		}

		for _, d := range q.Requires {
			if s.canceled() {
				return grew
			}

			if !touches(d, lost) || s.reported[q.NEVRA()+"|"+d.Name] {
				continue
			}

			n, err := s.node(d)
			if err != nil || s.eval(n) {
				continue
			}

			before := len(s.st.order)

			switch {
			case s.try(func() { s.want(n, q, true) }):
			case s.upgradeInstalled(q):
			default:
				s.reported[q.NEVRA()+"|"+d.Name] = true
				s.st.conflicts = append(s.st.conflicts, Conflict{Package: s.goneBy(d), With: q, Capability: n.String()})
			}

			if len(s.st.order) != before {
				grew = true
			}
		}
	}

	return grew
}

// goneBy returns the package of the transaction that took away what d needs.
func (s *solver) goneBy(d rpm.Dependency) *Package {
	for old, by := range s.st.gone {
		if slices.ContainsFunc(old.Provides, func(p rpm.Dependency) bool { return p.Name == d.Name }) {
			return by
		}
	}

	return nil
}

// touches reports whether a requirement may involve a capability in the set,
// looking inside rich dependencies.
func touches(d rpm.Dependency, set map[string]bool) bool {
	if !strings.HasPrefix(d.Name, "(") {
		return set[d.Name]
	}

	n, err := richdep.Parse(d.Name)
	if err != nil {
		return false
	}

	return slices.ContainsFunc(richdep.Atoms(n), func(a richdep.Atom) bool { return set[a.Name] })
}

// upgradeInstalled replaces an installed package by its best newer version
// when that can be installed without problems.
func (s *solver) upgradeInstalled(q *Package) bool {
	for _, p := range s.ix.names[q.Name] {
		if !sameSlot(q, p) || p.Compare(q) <= 0 {
			continue
		}

		if s.installable(p) && s.try(func() { s.install(p) }) {
			return true
		}
	}

	return false
}

// dependencyOrder returns the packages of the transaction with those a package
// needs before it: the order is the one in which they were chosen, each
// package after what its requirements pulled in, as far as the requirements
// allow it.
func (s *solver) dependencyOrder() []*Package {
	out := make([]*Package, 0, len(s.st.order))
	seen := make(map[*Package]bool, len(s.st.order))

	var visit func(p *Package)

	visit = func(p *Package) {
		if seen[p] {
			return
		}

		seen[p] = true

		for _, d := range p.Requires {
			n, err := s.node(d)
			if err != nil {
				continue
			}

			for _, a := range richdep.Atoms(n) {
				for _, q := range s.satisfiers(a) {
					if q != p && s.st.selected[q] {
						visit(q)
					}
				}
			}
		}

		out = append(out, p)
	}

	for _, p := range s.st.order {
		visit(p)
	}

	return out
}

// dropRedundant takes out the packages that were chosen for a requirement and
// that nothing needs once the transaction is complete: a requirement met by
// one provider when it was looked at may be met by a provider chosen later too,
// and the first one is then left over. Packages that were asked for, that
// upgrade or obsolete something, or that were chosen as weak dependencies stay.
func (s *solver) dropRedundant() {
	replacing := make(map[*Package]bool, len(s.st.gone))
	for _, by := range s.st.gone {
		replacing[by] = true
	}

	for changed := true; changed && !s.canceled(); {
		changed = false

		for i := len(s.st.order) - 1; i >= 0; i-- {
			p := s.st.order[i]
			if s.requested[p] || s.kept[p] || replacing[p] || !s.removable(p) {
				continue
			}

			s.remove(p)

			changed = true
		}
	}
}

// removable reports whether every requirement of the other packages of the
// transaction and every capability asked for still holds without p.
func (s *solver) removable(p *Package) bool {
	s.omit = p
	defer func() { s.omit = nil }()

	lost := make(map[string]bool, len(p.Provides)+len(p.Files))
	for _, d := range p.Provides {
		lost[d.Name] = true
	}

	for _, f := range p.Files {
		lost[f] = true
	}

	for _, a := range s.wanted {
		if len(s.satisfiers(a)) == 0 {
			return false
		}
	}

	holds := func(q *Package) bool {
		for _, d := range q.Requires {
			// a file may be owned by p in the file lists only
			if !touches(d, lost) && !needsFile(d) {
				continue
			}

			if n, err := s.node(d); err == nil && !s.eval(n) {
				return false
			}
		}

		return true
	}

	for _, q := range s.st.order {
		if q != p && !holds(q) {
			return false
		}
	}

	for _, q := range s.inst {
		if s.st.gone[q] == nil && !holds(q) {
			return false
		}
	}

	return true
}

// needsFile reports whether a requirement involves a file path.
func needsFile(d rpm.Dependency) bool {
	if !strings.HasPrefix(d.Name, "(") {
		return strings.HasPrefix(d.Name, "/")
	}

	n, err := richdep.Parse(d.Name)
	if err != nil {
		return false
	}

	return slices.ContainsFunc(richdep.Atoms(n), func(a richdep.Atom) bool { return strings.HasPrefix(a.Name, "/") })
}

// remove takes p out of the transaction.
func (s *solver) remove(p *Package) {
	delete(s.st.selected, p)

	s.st.order = slices.DeleteFunc(slices.Clone(s.st.order), func(q *Package) bool { return q == p })
	s.st.byName[p.Name] = slices.DeleteFunc(slices.Clone(s.st.byName[p.Name]), func(q *Package) bool { return q == p })

	for _, d := range p.Provides {
		s.st.prov[d.Name] = slices.DeleteFunc(slices.Clone(s.st.prov[d.Name]), func(r provRef) bool { return r.pkg == p })
	}

	for _, f := range p.Files {
		s.st.files[f] = slices.DeleteFunc(slices.Clone(s.st.files[f]), func(q *Package) bool { return q == p })
	}

	for _, d := range p.Conflicts {
		s.st.conf[d.Name] = slices.DeleteFunc(slices.Clone(s.st.conf[d.Name]), func(r confRef) bool { return r.pkg == p })
	}

	for _, d := range p.Obsoletes {
		s.st.obs[d.Name] = slices.DeleteFunc(slices.Clone(s.st.obs[d.Name]), func(r confRef) bool { return r.pkg == p })
	}
}
