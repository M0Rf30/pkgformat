package repodata

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
)

// WriteModules writes a modules.yaml the way libmodulemd does: documents
// grouped by module in name order, and in each group the defaults, the
// obsoletes, the translations and then the streams by [ModuleStream.NSVCA],
// every document opened by "---" and closed by "...", keys in libmodulemd's
// order and sets sorted. libmodulemd reads the output, and writes it back
// unchanged.
//
// A document that libmodulemd would refuse to write (an empty name, a missing
// summary, ...) fails with [ErrInvalidModulemd], before anything is written
// for it. An empty set writes nothing; compress the result with
// [CompressMetadataStream] to register it in repomd.xml as "modules".
func WriteModules(w io.Writer, set *ModuleSet) error {
	type group struct {
		defaults     []*ModuleDefaults
		obsoletes    []*ModuleObsoletes
		translations []*ModuleTranslations
		streams      []*ModuleStream
	}

	groups := make(map[string]*group)
	at := func(name string) *group {
		g := groups[name]
		if g == nil {
			g = &group{}
			groups[name] = g
		}

		return g
	}

	for _, d := range set.Defaults {
		at(d.Module).defaults = append(at(d.Module).defaults, d)
	}

	for _, o := range set.Obsoletes {
		at(o.Module).obsoletes = append(at(o.Module).obsoletes, o)
	}

	for _, t := range set.Translations {
		at(t.Module).translations = append(at(t.Module).translations, t)
	}

	for _, s := range set.Streams {
		at(s.Name).streams = append(at(s.Name).streams, s)
	}

	for _, name := range slices.Sorted(maps.Keys(groups)) {
		g := groups[name]

		slices.SortStableFunc(g.defaults, func(a, b *ModuleDefaults) int { return cmp.Compare(a.Modified, b.Modified) })
		slices.SortStableFunc(g.obsoletes, func(a, b *ModuleObsoletes) int {
			return cmp.Or(
				cmp.Compare(a.Stream, b.Stream),
				cmp.Compare(a.Context, b.Context),
				a.Modified.Compare(b.Modified),
			)
		})
		slices.SortStableFunc(g.translations, func(a, b *ModuleTranslations) int { return cmp.Compare(a.Stream, b.Stream) })
		slices.SortStableFunc(g.streams, func(a, b *ModuleStream) int { return cmp.Compare(a.NSVCA(), b.NSVCA()) })

		for _, d := range g.defaults {
			if err := WriteModuleDocument(w, d); err != nil {
				return err
			}
		}

		for _, o := range g.obsoletes {
			if err := WriteModuleDocument(w, o); err != nil {
				return err
			}
		}

		for _, t := range g.translations {
			if err := WriteModuleDocument(w, t); err != nil {
				return err
			}
		}

		for _, s := range g.streams {
			if err := WriteModuleDocument(w, s); err != nil {
				return err
			}
		}
	}

	return nil
}

// WriteModuleDocument writes one document, from "---" to "...", in the layout
// [WriteModules] uses.
func WriteModuleDocument(w io.Writer, doc ModuleDocument) error {
	var (
		kind    string
		version int
		data    *yamlNode
		err     error
	)

	switch d := doc.(type) {
	case *ModuleStream:
		kind, version = moduleKindStream, 2
		data, err = d.node()
	case *ModuleDefaults:
		kind, version = moduleKindDefaults, 1
		data, err = d.node()
	case *ModuleObsoletes:
		kind, version = moduleKindObsoletes, 1
		data, err = d.node()
	case *ModuleTranslations:
		kind, version = moduleKindTranslations, 1
		data, err = d.node()
	default:
		return fmt.Errorf("%w: %T is not a modulemd document", ErrUnsupportedModulemd, doc)
	}

	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidModulemd, err)
	}

	if err := checkYAMLText(data); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidModulemd, err)
	}

	root := yamlMapNode()
	root.set(mmKey("document"), mmPlain(kind))
	root.set(mmKey("version"), mmPlain(strconv.Itoa(version)))
	root.set(mmKey("data"), data)

	var out bytes.Buffer

	emitYAMLDocument(&out, root)

	_, err = w.Write(out.Bytes())

	return err
}

// The scalar helpers follow libmodulemd's choices: fixed keys and numbers are
// plain, and a text is double-quoted only when it is empty or reads as a
// number, so that a reader keeps it a string.

func mmKey(s string) *yamlNode   { return yamlScalarNode(s, yamlPlain) }
func mmPlain(s string) *yamlNode { return yamlScalarNode(s, yamlPlain) }
func mmQuoted(s string) *yamlNode {
	return yamlScalarNode(s, yamlDoubleQuoted)
}

// mmStr is a text value or a dynamic key.
func mmStr(s string) *yamlNode {
	if mmLooksNumeric(s) {
		return mmQuoted(s)
	}

	return mmPlain(s)
}

// mmLooksNumeric reports whether s is empty or could be read as a number
// (a sign, decimal, hexadecimal 0x, octal 0o, a fraction or an exponent,
// .nan, .inf).
func mmLooksNumeric(s string) bool {
	if s == "" || s == ".nan" {
		return true
	}

	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}

	if s == ".inf" {
		return true
	}

	var fractional, exponent, hexadecimal, octal bool

	switch {
	case s != "" && s[0] == '.':
		fractional = true
		s = s[1:]
	case strings.HasPrefix(s, "0x"):
		hexadecimal = true
		s = s[2:]
	case strings.HasPrefix(s, "0o"):
		octal = true
		s = s[2:]
	}

	if s == "" {
		return false
	}

	exponentSign := false

	for i := range len(s) {
		c := s[i]

		switch {
		case hexadecimal:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		case octal:
			if c < '0' || c > '7' {
				return false
			}
		case c == '.':
			if fractional {
				return false
			}

			fractional = true
		case fractional && (c == 'e' || c == 'E'):
			if exponent {
				return false
			}

			exponent = true
		case exponent && !exponentSign && (c == '+' || c == '-'):
			exponentSign = true
		case c < '0' || c > '9':
			return false
		}
	}

	return true
}

// mmSet sorts and deduplicates a list of strings.
func mmSet(items []string) []string {
	out := slices.Clone(items)
	slices.Sort(out)

	return slices.Compact(out)
}

// mmList is a sorted set of texts as a block or flow sequence.
func mmList(items []string, flow bool) *yamlNode {
	seq := yamlSeqNode(flow)

	for _, it := range mmSet(items) {
		seq.append(mmStr(it))
	}

	return seq
}

// mmPlainList is a sequence kept in the given order, its items written as
// plain scalars.
func mmPlainList(items []string) *yamlNode {
	seq := yamlSeqNode(false)

	for _, it := range mmSet(items) {
		seq.append(mmPlain(it))
	}

	return seq
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

func (s *ModuleStream) validate() error {
	switch {
	case s.Name == "":
		return errors.New("the module name is empty")
	case s.Stream == "":
		return errors.New("the stream name is empty")
	case s.Summary == "":
		return errors.New("the summary is empty")
	case s.Description == "":
		return errors.New("the description is empty")
	case len(s.License.Module) == 0:
		return errors.New("the module license list is empty")
	}

	for name, p := range s.Components.RPMs {
		if p.BuildOrder != 0 && len(p.BuildAfter) != 0 {
			return fmt.Errorf("the rpm component %q sets both buildorder and buildafter", name)
		}
	}

	for name, m := range s.Components.Modules {
		if m.BuildOrder != 0 && len(m.BuildAfter) != 0 {
			return fmt.Errorf("the module component %q sets both buildorder and buildafter", name)
		}
	}

	for digest, sums := range s.Artifacts.RPMMap {
		for sum, e := range sums {
			if e.Name == "" || e.Version == "" || e.Release == "" || e.Arch == "" {
				return fmt.Errorf("the rpm-map entry %s %s lacks a name, version, release or arch", digest, sum)
			}
		}
	}

	for name, level := range s.ServiceLevels {
		if level.EOL == "" {
			continue
		}

		if _, err := time.Parse(time.DateOnly, level.EOL); err != nil {
			return fmt.Errorf("the end of life of service level %q is not a YYYY-MM-DD date: %q", name, level.EOL)
		}
	}

	return validateXMD(s.XMD, 0)
}

func validateXMD(v any, depth int) error {
	if depth > DefaultMaxModulemdDepth {
		return fmt.Errorf("xmd nests deeper than %d levels", DefaultMaxModulemdDepth)
	}

	switch x := v.(type) {
	case nil:
		return nil
	case string, bool:
		return nil
	case []any:
		for _, it := range x {
			if err := validateXMD(it, depth+1); err != nil {
				return err
			}
		}

		return nil
	case map[string]any:
		for _, it := range x {
			if err := validateXMD(it, depth+1); err != nil {
				return err
			}
		}

		return nil
	}

	return fmt.Errorf("xmd holds a %T; only strings, booleans, lists and mappings are allowed", v)
}

// node builds the "data" mapping of the document.
func (s *ModuleStream) node() (*yamlNode, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	d := yamlMapNode()
	d.set(mmKey("name"), mmStr(s.Name))
	d.set(mmKey("stream"), mmQuoted(s.Stream))

	if s.Version != 0 {
		d.set(mmKey("version"), mmPlain(strconv.FormatUint(s.Version, 10)))
	}

	if s.Context != "" {
		d.set(mmKey("context"), mmStr(s.Context))
	}

	if s.StaticContext {
		d.set(mmKey("static_context"), mmPlain("true"))
	}

	if s.Arch != "" {
		d.set(mmKey("arch"), mmStr(s.Arch))
	}

	d.set(mmKey("summary"), mmStr(s.Summary))
	d.set(mmKey("description"), yamlScalarNode(s.Description, yamlFolded))

	if len(s.ServiceLevels) != 0 {
		levels := yamlMapNode()

		for _, name := range sortedKeys(s.ServiceLevels) {
			level := yamlMapNode()
			if eol := s.ServiceLevels[name].EOL; eol != "" {
				level.set(mmKey("eol"), mmPlain(eol))
			}

			levels.set(mmStr(name), level)
		}

		d.set(mmKey("servicelevels"), levels)
	}

	license := yamlMapNode()
	license.set(mmKey("module"), mmList(s.License.Module, false))

	if len(s.License.Content) != 0 {
		license.set(mmKey("content"), mmList(s.License.Content, false))
	}

	d.set(mmKey("license"), license)

	if s.XMD != nil {
		d.set(mmKey("xmd"), xmdNode(s.XMD))
	}

	if len(s.Dependencies) != 0 {
		deps := yamlSeqNode(false)

		for _, dep := range s.Dependencies {
			m := yamlMapNode()
			if len(dep.BuildRequires) != 0 {
				m.set(mmKey("buildrequires"), streamsNode(dep.BuildRequires))
			}

			if len(dep.Requires) != 0 {
				m.set(mmKey("requires"), streamsNode(dep.Requires))
			}

			deps.append(m)
		}

		d.set(mmKey("dependencies"), deps)
	}

	if r := s.References; r.Community != "" || r.Documentation != "" || r.Tracker != "" {
		refs := yamlMapNode()

		for _, kv := range [...]struct{ key, value string }{
			{"community", r.Community}, {"documentation", r.Documentation}, {"tracker", r.Tracker},
		} {
			if kv.value != "" {
				refs.set(mmKey(kv.key), mmStr(kv.value))
			}
		}

		d.set(mmKey("references"), refs)
	}

	if len(s.Profiles) != 0 {
		profiles := yamlMapNode()

		for _, name := range sortedKeys(s.Profiles) {
			p := s.Profiles[name]
			m := yamlMapNode()

			if p.Description != "" {
				m.set(mmKey("description"), mmStr(p.Description))
			}

			if len(p.RPMs) != 0 {
				m.set(mmKey("rpms"), mmList(p.RPMs, false))
			}

			if p.Default {
				m.set(mmKey("default"), mmPlain("true"))
			}

			profiles.set(mmStr(name), m)
		}

		d.set(mmKey("profiles"), profiles)
	}

	for _, kv := range [...]struct {
		key   string
		rpms  []string
		inUse bool
	}{
		{"api", s.API, len(s.API) != 0},
		{"filter", s.Filter, len(s.Filter) != 0},
		{"demodularized", s.Demodularized, len(s.Demodularized) != 0},
	} {
		if kv.inUse {
			m := yamlMapNode()
			m.set(mmKey("rpms"), mmList(kv.rpms, false))
			d.set(mmKey(kv.key), m)
		}
	}

	if s.BuildOpts != nil {
		d.set(mmKey("buildopts"), s.BuildOpts.node())
	}

	if len(s.Components.RPMs) != 0 || len(s.Components.Modules) != 0 {
		comps := yamlMapNode()

		if len(s.Components.RPMs) != 0 {
			rpms := yamlMapNode()

			for _, name := range sortedKeys(s.Components.RPMs) {
				rpms.set(mmStr(name), s.Components.RPMs[name].node())
			}

			comps.set(mmKey("rpms"), rpms)
		}

		if len(s.Components.Modules) != 0 {
			mods := yamlMapNode()

			for _, name := range sortedKeys(s.Components.Modules) {
				mods.set(mmStr(name), s.Components.Modules[name].node())
			}

			comps.set(mmKey("modules"), mods)
		}

		d.set(mmKey("components"), comps)
	}

	if len(s.Artifacts.RPMs) != 0 || len(s.Artifacts.RPMMap) != 0 {
		arts := yamlMapNode()

		if len(s.Artifacts.RPMs) != 0 {
			arts.set(mmKey("rpms"), mmList(s.Artifacts.RPMs, false))
		}

		if len(s.Artifacts.RPMMap) != 0 {
			arts.set(mmKey("rpm-map"), rpmMapNode(s.Artifacts.RPMMap))
		}

		d.set(mmKey("artifacts"), arts)
	}

	return d, nil
}

func streamsNode(deps map[string][]string) *yamlNode {
	m := yamlMapNode()

	for _, name := range sortedKeys(deps) {
		m.set(mmStr(name), mmList(deps[name], true))
	}

	return m
}

func xmdNode(v any) *yamlNode {
	switch x := v.(type) {
	case bool:
		if x {
			return mmPlain("TRUE")
		}

		return mmPlain("FALSE")
	case []any:
		seq := yamlSeqNode(false)
		for _, it := range x {
			seq.append(xmdNode(it))
		}

		return seq
	case map[string]any:
		m := yamlMapNode()
		for _, k := range sortedKeys(x) {
			m.set(mmStr(k), xmdNode(x[k]))
		}

		return m
	case string:
		return mmStr(x)
	}

	return mmStr("")
}

func (b *ModuleBuildOpts) node() *yamlNode {
	m := yamlMapNode()
	rpms := yamlMapNode()

	if b.Macros != "" {
		rpms.set(mmKey("macros"), yamlScalarNode(b.Macros, yamlFolded))
	}

	if len(b.Whitelist) != 0 {
		rpms.set(mmKey("whitelist"), mmList(b.Whitelist, false))
	}

	m.set(mmKey("rpms"), rpms)

	if len(b.Arches) != 0 {
		m.set(mmKey("arches"), mmList(b.Arches, true))
	}

	return m
}

// componentBuild adds the build ordering fields the components share.
func componentBuild(m *yamlNode, order int64, after []string, only bool) {
	switch {
	case order != 0:
		m.set(mmKey("buildorder"), mmPlain(strconv.FormatInt(order, 10)))
	case len(after) != 0:
		m.set(mmKey("buildafter"), mmPlainList(after))
	}

	if only {
		m.set(mmKey("buildonly"), mmPlain("true"))
	}
}

func (c ModuleRPMComponent) node() *yamlNode {
	m := yamlMapNode()

	if c.Rationale != "" {
		m.set(mmKey("rationale"), mmStr(c.Rationale))
	}

	for _, kv := range [...]struct{ key, value string }{
		{"name", c.Name}, {"repository", c.Repository}, {"cache", c.Cache}, {"ref", c.Ref},
	} {
		if kv.value != "" {
			m.set(mmKey(kv.key), mmStr(kv.value))
		}
	}

	if c.Buildroot {
		m.set(mmKey("buildroot"), mmPlain("true"))
	}

	if c.SRPMBuildroot {
		m.set(mmKey("srpm-buildroot"), mmPlain("true"))
	}

	componentBuild(m, c.BuildOrder, c.BuildAfter, c.BuildOnly)

	if len(c.Arches) != 0 {
		m.set(mmKey("arches"), mmList(c.Arches, true))
	}

	if len(c.Multilib) != 0 {
		m.set(mmKey("multilib"), mmList(c.Multilib, true))
	}

	return m
}

func (c ModuleModuleComponent) node() *yamlNode {
	m := yamlMapNode()

	if c.Rationale != "" {
		m.set(mmKey("rationale"), mmStr(c.Rationale))
	}

	if c.Repository != "" {
		m.set(mmKey("repository"), mmStr(c.Repository))
	}

	if c.Ref != "" {
		m.set(mmKey("ref"), mmStr(c.Ref))
	}

	componentBuild(m, c.BuildOrder, c.BuildAfter, c.BuildOnly)

	return m
}

func rpmMapNode(rm map[string]map[string]ModuleRPMMapEntry) *yamlNode {
	m := yamlMapNode()

	for _, digest := range sortedKeys(rm) {
		sums := yamlMapNode()

		for _, sum := range sortedKeys(rm[digest]) {
			e := rm[digest][sum]
			em := yamlMapNode()
			em.set(mmKey("name"), mmStr(e.Name))
			em.set(mmKey("epoch"), mmPlain(strconv.FormatUint(e.Epoch, 10)))
			em.set(mmKey("version"), mmStr(e.Version))
			em.set(mmKey("release"), mmStr(e.Release))
			em.set(mmKey("arch"), mmStr(e.Arch))
			em.set(mmKey("nevra"), mmStr(e.NEVRA()))
			sums.set(mmStr(sum), em)
		}

		m.set(mmStr(digest), sums)
	}

	return m
}

func (d *ModuleDefaults) validate() error {
	if d.Module == "" {
		return errors.New("the module name is empty")
	}

	return nil
}

func (d *ModuleDefaults) node() (*yamlNode, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}

	m := yamlMapNode()
	m.set(mmKey("module"), mmStr(d.Module))

	if d.Modified != 0 {
		m.set(mmKey("modified"), mmPlain(strconv.FormatUint(d.Modified, 10)))
	}

	if d.Stream != "" {
		m.set(mmKey("stream"), mmQuoted(d.Stream))
	}

	if len(d.Profiles) != 0 {
		m.set(mmKey("profiles"), defaultProfilesNode(d.Profiles))
	}

	if len(d.Intents) != 0 {
		intents := yamlMapNode()

		for _, name := range sortedKeys(d.Intents) {
			in := d.Intents[name]
			im := yamlMapNode()

			if in.Stream != "" {
				im.set(mmKey("stream"), mmQuoted(in.Stream))
			}

			if len(in.Profiles) != 0 {
				im.set(mmKey("profiles"), defaultProfilesNode(in.Profiles))
			}

			intents.set(mmStr(name), im)
		}

		m.set(mmKey("intents"), intents)
	}

	return m, nil
}

func defaultProfilesNode(profiles map[string][]string) *yamlNode {
	m := yamlMapNode()

	for _, stream := range sortedKeys(profiles) {
		m.set(mmStr(stream), mmList(profiles[stream], true))
	}

	return m
}

func (o *ModuleObsoletes) validate() error {
	switch {
	case o.Module == "":
		return errors.New("the module name is empty")
	case o.Stream == "":
		return errors.New("the stream name is empty")
	case o.Modified.IsZero():
		return errors.New("the modified date is empty")
	case o.Message == "":
		return errors.New("the message is empty")
	}

	return nil
}

func (o *ModuleObsoletes) node() (*yamlNode, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}

	m := yamlMapNode()
	m.set(mmKey("modified"), mmPlain(o.Modified.UTC().Format(moduleTimeLayout)))

	if o.Reset {
		m.set(mmKey("reset"), mmPlain("true"))
	}

	m.set(mmKey("module"), mmStr(o.Module))
	m.set(mmKey("stream"), mmQuoted(o.Stream))

	if o.Context != "" {
		m.set(mmKey("context"), mmStr(o.Context))
	}

	if !o.EOLDate.IsZero() {
		m.set(mmKey("eol_date"), mmPlain(o.EOLDate.UTC().Format(moduleTimeLayout)))
	}

	m.set(mmKey("message"), mmStr(o.Message))

	if b := o.ObsoletedBy; b != nil && b.Module != "" && b.Stream != "" {
		by := yamlMapNode()
		by.set(mmKey("module"), mmStr(b.Module))
		by.set(mmKey("stream"), mmQuoted(b.Stream))
		m.set(mmKey("obsoleted_by"), by)
	}

	return m, nil
}

func (t *ModuleTranslations) validate() error {
	switch {
	case t.Module == "":
		return errors.New("the module name is empty")
	case t.Stream == "":
		return errors.New("the stream name is empty")
	}

	return nil
}

func (t *ModuleTranslations) node() (*yamlNode, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}

	m := yamlMapNode()
	m.set(mmKey("module"), mmStr(t.Module))
	m.set(mmKey("stream"), mmQuoted(t.Stream))
	m.set(mmKey("modified"), mmPlain(strconv.FormatUint(t.Modified, 10)))

	if len(t.Locales) != 0 {
		locales := yamlMapNode()

		for _, locale := range sortedKeys(t.Locales) {
			tr := t.Locales[locale]
			lm := yamlMapNode()

			if tr.Summary != "" {
				lm.set(mmKey("summary"), mmStr(tr.Summary))
			}

			if tr.Description != "" {
				lm.set(mmKey("description"), mmStr(tr.Description))
			}

			if len(tr.Profiles) != 0 {
				profiles := yamlMapNode()
				for _, name := range sortedKeys(tr.Profiles) {
					profiles.set(mmStr(name), mmStr(tr.Profiles[name]))
				}

				lm.set(mmKey("profiles"), profiles)
			}

			locales.set(mmStr(locale), lm)
		}

		m.set(mmKey("translations"), locales)
	}

	return m, nil
}
