package repodata

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// Defaults of [ModulemdLimits].
const (
	// DefaultMaxModulemdDocument bounds one document of a modules.yaml; the
	// largest real ones are a few hundred kilobytes.
	DefaultMaxModulemdDocument = 16 << 20
	// DefaultMaxModulemdEntries bounds each list and mapping of a document.
	DefaultMaxModulemdEntries = 1 << 20
	// DefaultMaxModulemdDepth bounds the nesting of the xmd block.
	DefaultMaxModulemdDepth = 64
)

// ModulemdLimits bounds [ReadModulemd] and [ParseModulemd]. A zero field
// selects its default.
type ModulemdLimits struct {
	// MaxBytes bounds the whole modules.yaml; a larger one fails the read
	// with [ErrTooLarge]. The default is [DefaultMaxModulesDocument].
	MaxBytes int64
	// MaxDocumentBytes bounds one document, the unit kept in memory. The
	// default is [DefaultMaxModulemdDocument].
	MaxDocumentBytes int
	// MaxEntries bounds every list and mapping of a document. The default
	// is [DefaultMaxModulemdEntries].
	MaxEntries int
	// MaxDepth bounds the nesting of the xmd block. The default is
	// [DefaultMaxModulemdDepth].
	MaxDepth int
}

func (l ModulemdLimits) normalized() ModulemdLimits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxModulesDocument
	}

	if l.MaxDocumentBytes <= 0 {
		l.MaxDocumentBytes = DefaultMaxModulemdDocument
	}

	if l.MaxEntries <= 0 {
		l.MaxEntries = DefaultMaxModulemdEntries
	}

	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultMaxModulemdDepth
	}

	return l
}

// ParseModulemd reads every document of a modules.yaml (already
// decompressed, see [OpenMetadata]) into a [ModuleSet], in the order they
// appear. It fails on the first document [ReadModulemd] rejects.
func ParseModulemd(r io.Reader, lim ModulemdLimits) (*ModuleSet, error) {
	set := &ModuleSet{}

	err := ReadModulemd(r, lim, func(doc ModuleDocument) error {
		switch d := doc.(type) {
		case *ModuleStream:
			set.Streams = append(set.Streams, d)
		case *ModuleDefaults:
			set.Defaults = append(set.Defaults, d)
		case *ModuleObsoletes:
			set.Obsoletes = append(set.Obsoletes, d)
		case *ModuleTranslations:
			set.Translations = append(set.Translations, d)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return set, nil
}

// ReadModulemd decodes a modules.yaml (already decompressed, see
// [OpenMetadata]) one document at a time and calls fn with each: a
// *[ModuleStream], *[ModuleDefaults], *[ModuleObsoletes] or
// *[ModuleTranslations]. Only the document being decoded is held in memory.
//
// Keys this package does not model are ignored, as libmodulemd does when it
// is not strict. A malformed document fails the read with
// [ErrInvalidModulemd], a document of another kind or version with
// [ErrUnsupportedModulemd], a limit exceeded with [ErrTooLarge]; an error of
// fn stops the read and is returned.
func ReadModulemd(r io.Reader, lim ModulemdLimits, fn func(ModuleDocument) error) error {
	lim = lim.normalized()

	sc := bufio.NewScanner(limitio.Capped(r, lim.MaxBytes+1, ErrTooLarge))
	sc.Buffer(make([]byte, 0, min(64<<10, lim.MaxDocumentBytes)), lim.MaxDocumentBytes)

	var (
		text  bytes.Buffer
		index int
	)

	// flush decodes the text collected so far. It is one document, unless
	// the text holds a "--- ..." line that is not alone on its line; the
	// decoder then yields every document of the text.
	flush := func() error {
		defer text.Reset()

		dec := yaml.NewDecoder(bytes.NewReader(text.Bytes()))

		for {
			var node yaml.Node

			err := dec.Decode(&node)
			if errors.Is(err, io.EOF) {
				return nil
			}

			index++

			if err != nil {
				return fmt.Errorf("%w: document %d: %w", ErrInvalidModulemd, index, err)
			}

			p := &moduleParser{lim: lim, doc: index}

			doc, err := p.document(&node)
			if err != nil {
				return err
			}

			if err := fn(doc); err != nil {
				return err
			}
		}
	}

	for sc.Scan() {
		line := sc.Bytes()

		switch string(bytes.TrimRight(line, " \t\r")) {
		case "---", "...":
			if err := flush(); err != nil {
				return err
			}

			continue
		}

		text.Write(line)
		text.WriteByte('\n')

		if text.Len() > lim.MaxDocumentBytes {
			return fmt.Errorf("%w: a modulemd document exceeds %d bytes", ErrTooLarge, lim.MaxDocumentBytes)
		}
	}

	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("%w: a line of a modulemd document exceeds %d bytes", ErrTooLarge, lim.MaxDocumentBytes)
		}

		return fmt.Errorf("repodata: reading modules.yaml: %w", err)
	}

	return flush()
}

// moduleParser turns the YAML tree of one document into the model.
type moduleParser struct {
	lim ModulemdLimits
	doc int
}

func (p *moduleParser) fail(n *yaml.Node, format string, args ...any) error {
	return fmt.Errorf("%w: document %d, line %d: %s", ErrInvalidModulemd, p.doc, n.Line, fmt.Sprintf(format, args...))
}

func (p *moduleParser) tooLarge(n *yaml.Node, what string) error {
	return fmt.Errorf("%w: document %d, line %d: %s has more than %d entries", ErrTooLarge, p.doc, n.Line, what, p.lim.MaxEntries)
}

// fields calls fn for every key of a mapping; a key that repeats or is not a
// scalar is an error.
func (p *moduleParser) fields(n *yaml.Node, what string, fn func(key string, value *yaml.Node) error) error {
	if n.Kind != yaml.MappingNode {
		return p.fail(n, "%s must be a mapping", what)
	}

	if len(n.Content)/2 > p.lim.MaxEntries {
		return p.tooLarge(n, what)
	}

	seen := make(map[string]struct{}, len(n.Content)/2)

	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]

		if k.Kind != yaml.ScalarNode {
			return p.fail(k, "a key of %s must be a scalar", what)
		}

		if v.Kind == yaml.AliasNode {
			return p.fail(v, "aliases are not allowed")
		}

		if _, dup := seen[k.Value]; dup {
			return p.fail(k, "%s repeats the key %q", what, k.Value)
		}

		seen[k.Value] = struct{}{}

		if err := fn(k.Value, v); err != nil {
			return err
		}
	}

	return nil
}

func (p *moduleParser) scalar(n *yaml.Node, what string) (string, error) {
	if n.Kind != yaml.ScalarNode {
		return "", p.fail(n, "%s must be a scalar", what)
	}

	if !utf8.ValidString(n.Value) {
		return "", p.fail(n, "%s is not valid UTF-8", what)
	}

	return n.Value, nil
}

func (p *moduleParser) uint(n *yaml.Node, what string) (uint64, error) {
	s, err := p.scalar(n, what)
	if err != nil {
		return 0, err
	}

	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, p.fail(n, "%s must be an unsigned integer, got %q", what, s)
	}

	return v, nil
}

func (p *moduleParser) int(n *yaml.Node, what string) (int64, error) {
	s, err := p.scalar(n, what)
	if err != nil {
		return 0, err
	}

	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, p.fail(n, "%s must be an integer, got %q", what, s)
	}

	return v, nil
}

func (p *moduleParser) bool(n *yaml.Node, what string) (bool, error) {
	s, err := p.scalar(n, what)
	if err != nil {
		return false, err
	}

	switch strings.ToLower(s) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}

	return false, p.fail(n, "%s must be true or false, got %q", what, s)
}

// list reads a sequence of scalars; with single set, a lone scalar is a list
// of one.
func (p *moduleParser) list(n *yaml.Node, what string, single bool) ([]string, error) {
	if single && n.Kind == yaml.ScalarNode {
		s, err := p.scalar(n, what)
		if err != nil {
			return nil, err
		}

		return []string{s}, nil
	}

	if n.Kind != yaml.SequenceNode {
		return nil, p.fail(n, "%s must be a list", what)
	}

	if len(n.Content) > p.lim.MaxEntries {
		return nil, p.tooLarge(n, what)
	}

	out := make([]string, 0, len(n.Content))

	for _, item := range n.Content {
		s, err := p.scalar(item, what)
		if err != nil {
			return nil, err
		}

		out = append(out, s)
	}

	return out, nil
}

// listIn reads the list under one key of a mapping, as in "api: {rpms: [...]}".
func (p *moduleParser) listIn(n *yaml.Node, what, key string) ([]string, error) {
	var out []string

	err := p.fields(n, what, func(k string, v *yaml.Node) error {
		if k != key {
			return nil
		}

		var err error

		out, err = p.list(v, what+"."+key, false)

		return err
	})

	return out, err
}

func (p *moduleParser) listMap(n *yaml.Node, what string) (map[string][]string, error) {
	out := make(map[string][]string)

	err := p.fields(n, what, func(k string, v *yaml.Node) error {
		l, err := p.list(v, what+"."+k, true)
		if err != nil {
			return err
		}

		out[k] = l

		return nil
	})

	return out, err
}

// document dispatches on the document kind and format version.
func (p *moduleParser) document(n *yaml.Node) (ModuleDocument, error) {
	if n.Kind != yaml.DocumentNode || len(n.Content) != 1 {
		return nil, p.fail(n, "not a YAML document")
	}

	root := n.Content[0]

	var (
		kind    string
		version uint64
		data    *yaml.Node
	)

	err := p.fields(root, "the document", func(k string, v *yaml.Node) error {
		var err error

		switch k {
		case "document":
			kind, err = p.scalar(v, "document")
		case "version":
			version, err = p.uint(v, "version")
		case "data":
			data = v
		}

		return err
	})
	if err != nil {
		return nil, err
	}

	if kind == "" || data == nil {
		return nil, p.fail(root, "the document needs a document type, a version and data")
	}

	want := uint64(1)
	if kind == moduleKindStream {
		want = 2
	}

	switch kind {
	case moduleKindStream, moduleKindDefaults, moduleKindObsoletes, moduleKindTranslations:
	default:
		return nil, fmt.Errorf("%w: document %d: line %d: document type %q", ErrUnsupportedModulemd, p.doc, root.Line, kind)
	}

	if version != want {
		return nil, fmt.Errorf("%w: document %d: line %d: %s version %d", ErrUnsupportedModulemd, p.doc, root.Line, kind, version)
	}

	switch kind {
	case moduleKindStream:
		return p.stream(data)
	case moduleKindDefaults:
		return p.defaults(data)
	case moduleKindObsoletes:
		return p.obsoletes(data)
	default:
		return p.translations(data)
	}
}

func (p *moduleParser) stream(data *yaml.Node) (*ModuleStream, error) {
	s := &ModuleStream{}

	err := p.fields(data, "data", func(k string, v *yaml.Node) error {
		var err error

		switch k {
		case "name":
			s.Name, err = p.scalar(v, k)
		case "stream":
			s.Stream, err = p.scalar(v, k)
		case "version":
			s.Version, err = p.uint(v, k)
		case "context":
			s.Context, err = p.scalar(v, k)
		case "static_context":
			s.StaticContext, err = p.bool(v, k)
		case "arch":
			s.Arch, err = p.scalar(v, k)
		case "summary":
			s.Summary, err = p.scalar(v, k)
		case "description":
			s.Description, err = p.scalar(v, k)
		case "servicelevels":
			s.ServiceLevels, err = p.serviceLevels(v)
		case "license":
			s.License, err = p.license(v)
		case "xmd":
			s.XMD, err = p.xmd(v)
		case "dependencies":
			s.Dependencies, err = p.dependencies(v)
		case "references":
			s.References, err = p.references(v)
		case "profiles":
			s.Profiles, err = p.profiles(v)
		case "api":
			s.API, err = p.listIn(v, k, "rpms")
		case "filter":
			s.Filter, err = p.listIn(v, k, "rpms")
		case "demodularized":
			s.Demodularized, err = p.listIn(v, k, "rpms")
		case "buildopts":
			s.BuildOpts, err = p.buildOpts(v)
		case "components":
			s.Components, err = p.components(v)
		case "artifacts":
			s.Artifacts, err = p.artifacts(v)
		}

		return err
	})
	if err != nil {
		return nil, err
	}

	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("%w: document %d: %w", ErrInvalidModulemd, p.doc, err)
	}

	return s, nil
}

func (p *moduleParser) serviceLevels(n *yaml.Node) (map[string]ModuleServiceLevel, error) {
	out := make(map[string]ModuleServiceLevel)

	err := p.fields(n, "servicelevels", func(name string, v *yaml.Node) error {
		var level ModuleServiceLevel

		err := p.fields(v, "servicelevels."+name, func(k string, vv *yaml.Node) error {
			if k != "eol" {
				return nil
			}

			s, err := p.scalar(vv, "eol")
			if err != nil {
				return err
			}

			if _, err := time.Parse(time.DateOnly, s); err != nil {
				return p.fail(vv, "eol must be a YYYY-MM-DD date, got %q", s)
			}

			level.EOL = s

			return nil
		})
		out[name] = level

		return err
	})

	return out, err
}

func (p *moduleParser) license(n *yaml.Node) (ModuleLicense, error) {
	var l ModuleLicense

	err := p.fields(n, "license", func(k string, v *yaml.Node) error {
		var err error

		switch k {
		case "module":
			l.Module, err = p.list(v, "license.module", false)
		case "content":
			l.Content, err = p.list(v, "license.content", false)
		}

		return err
	})

	return l, err
}

func (p *moduleParser) references(n *yaml.Node) (ModuleReferences, error) {
	var r ModuleReferences

	err := p.fields(n, "references", func(k string, v *yaml.Node) error {
		var err error

		switch k {
		case "community":
			r.Community, err = p.scalar(v, k)
		case "documentation":
			r.Documentation, err = p.scalar(v, k)
		case "tracker":
			r.Tracker, err = p.scalar(v, k)
		}

		return err
	})

	return r, err
}

func (p *moduleParser) dependencies(n *yaml.Node) ([]ModuleDependency, error) {
	if n.Kind != yaml.SequenceNode {
		return nil, p.fail(n, "dependencies must be a list")
	}

	if len(n.Content) > p.lim.MaxEntries {
		return nil, p.tooLarge(n, "dependencies")
	}

	out := make([]ModuleDependency, 0, len(n.Content))

	for _, item := range n.Content {
		var d ModuleDependency

		err := p.fields(item, "a dependency", func(k string, v *yaml.Node) error {
			var err error

			switch k {
			case "buildrequires":
				d.BuildRequires, err = p.listMap(v, k)
			case "requires":
				d.Requires, err = p.listMap(v, k)
			}

			return err
		})
		if err != nil {
			return nil, err
		}

		out = append(out, d)
	}

	return out, nil
}

func (p *moduleParser) profiles(n *yaml.Node) (map[string]ModuleProfile, error) {
	out := make(map[string]ModuleProfile)

	err := p.fields(n, "profiles", func(name string, v *yaml.Node) error {
		var prof ModuleProfile

		err := p.fields(v, "profile "+name, func(k string, vv *yaml.Node) error {
			var err error

			switch k {
			case "description":
				prof.Description, err = p.scalar(vv, k)
			case "rpms":
				prof.RPMs, err = p.list(vv, "profile "+name+" rpms", false)
			case "default":
				prof.Default, err = p.bool(vv, k)
			}

			return err
		})
		out[name] = prof

		return err
	})

	return out, err
}

func (p *moduleParser) buildOpts(n *yaml.Node) (*ModuleBuildOpts, error) {
	b := &ModuleBuildOpts{}

	err := p.fields(n, "buildopts", func(k string, v *yaml.Node) error {
		switch k {
		case "rpms":
			return p.fields(v, "buildopts.rpms", func(kk string, vv *yaml.Node) error {
				var err error

				switch kk {
				case "macros":
					b.Macros, err = p.scalar(vv, kk)
				case "whitelist":
					b.Whitelist, err = p.list(vv, "buildopts.rpms.whitelist", false)
				}

				return err
			})
		case "arches":
			var err error

			b.Arches, err = p.list(v, "buildopts.arches", false)

			return err
		}

		return nil
	})

	return b, err
}

func (p *moduleParser) components(n *yaml.Node) (ModuleComponents, error) {
	var c ModuleComponents

	err := p.fields(n, "components", func(k string, v *yaml.Node) error {
		switch k {
		case "rpms":
			c.RPMs = make(map[string]ModuleRPMComponent)

			return p.fields(v, "components.rpms", func(name string, vv *yaml.Node) error {
				comp, err := p.rpmComponent(name, vv)
				c.RPMs[name] = comp

				return err
			})
		case "modules":
			c.Modules = make(map[string]ModuleModuleComponent)

			return p.fields(v, "components.modules", func(name string, vv *yaml.Node) error {
				comp, err := p.moduleComponent(name, vv)
				c.Modules[name] = comp

				return err
			})
		}

		return nil
	})

	return c, err
}

// componentField reads the fields rpm and module components share.
func (p *moduleParser) componentField(k string, v *yaml.Node, what string, rationale, repository, ref *string, order *int64, after *[]string, only *bool) (bool, error) {
	var err error

	switch k {
	case "rationale":
		*rationale, err = p.scalar(v, what+" "+k)
	case "repository":
		*repository, err = p.scalar(v, what+" "+k)
	case "ref":
		*ref, err = p.scalar(v, what+" "+k)
	case "buildorder":
		*order, err = p.int(v, what+" "+k)
	case "buildafter":
		*after, err = p.list(v, what+" "+k, false)
	case "buildonly":
		*only, err = p.bool(v, what+" "+k)
	default:
		return false, nil
	}

	return true, err
}

func (p *moduleParser) rpmComponent(name string, n *yaml.Node) (ModuleRPMComponent, error) {
	var c ModuleRPMComponent

	what := "rpm component " + name

	err := p.fields(n, what, func(k string, v *yaml.Node) error {
		if ok, err := p.componentField(k, v, what, &c.Rationale, &c.Repository, &c.Ref, &c.BuildOrder, &c.BuildAfter, &c.BuildOnly); ok || err != nil {
			return err
		}

		var err error

		switch k {
		case "name":
			c.Name, err = p.scalar(v, what+" "+k)
		case "cache":
			c.Cache, err = p.scalar(v, what+" "+k)
		case "buildroot":
			c.Buildroot, err = p.bool(v, what+" "+k)
		case "srpm-buildroot":
			c.SRPMBuildroot, err = p.bool(v, what+" "+k)
		case "arches":
			c.Arches, err = p.list(v, what+" "+k, false)
		case "multilib":
			c.Multilib, err = p.list(v, what+" "+k, false)
		}

		return err
	})

	return c, err
}

func (p *moduleParser) moduleComponent(name string, n *yaml.Node) (ModuleModuleComponent, error) {
	var c ModuleModuleComponent

	what := "module component " + name

	err := p.fields(n, what, func(k string, v *yaml.Node) error {
		_, err := p.componentField(k, v, what, &c.Rationale, &c.Repository, &c.Ref, &c.BuildOrder, &c.BuildAfter, &c.BuildOnly)

		return err
	})

	return c, err
}

func (p *moduleParser) artifacts(n *yaml.Node) (ModuleArtifacts, error) {
	var a ModuleArtifacts

	err := p.fields(n, "artifacts", func(k string, v *yaml.Node) error {
		var err error

		switch k {
		case "rpms":
			a.RPMs, err = p.list(v, "artifacts.rpms", false)
		case "rpm-map":
			a.RPMMap, err = p.rpmMap(v)
		}

		return err
	})

	return a, err
}

func (p *moduleParser) rpmMap(n *yaml.Node) (map[string]map[string]ModuleRPMMapEntry, error) {
	out := make(map[string]map[string]ModuleRPMMapEntry)

	err := p.fields(n, "rpm-map", func(digest string, v *yaml.Node) error {
		sums := make(map[string]ModuleRPMMapEntry)
		out[digest] = sums

		return p.fields(v, "rpm-map "+digest, func(sum string, vv *yaml.Node) error {
			var e ModuleRPMMapEntry

			err := p.fields(vv, "rpm-map entry "+sum, func(k string, vvv *yaml.Node) error {
				var err error

				switch k {
				case "name":
					e.Name, err = p.scalar(vvv, k)
				case "epoch":
					e.Epoch, err = p.uint(vvv, k)
				case "version":
					e.Version, err = p.scalar(vvv, k)
				case "release":
					e.Release, err = p.scalar(vvv, k)
				case "arch":
					e.Arch, err = p.scalar(vvv, k)
				}

				return err
			})
			sums[sum] = e

			return err
		})
	})

	return out, err
}

// xmd reads the opaque block the way libmodulemd does: mappings and lists
// keep their shape, "TRUE" and "FALSE" become booleans and every other scalar
// is a string.
func (p *moduleParser) xmd(n *yaml.Node) (map[string]any, error) {
	v, err := p.xmdValue(n, 0)
	if err != nil {
		return nil, err
	}

	m, ok := v.(map[string]any)
	if !ok {
		return nil, p.fail(n, "xmd must be a mapping")
	}

	return m, nil
}

func (p *moduleParser) xmdValue(n *yaml.Node, depth int) (any, error) {
	if depth > p.lim.MaxDepth {
		return nil, fmt.Errorf("%w: document %d, line %d: xmd nests deeper than %d levels", ErrTooLarge, p.doc, n.Line, p.lim.MaxDepth)
	}

	switch n.Kind {
	case yaml.ScalarNode:
		s, err := p.scalar(n, "an xmd value")
		if err != nil {
			return nil, err
		}

		switch s {
		case "TRUE":
			return true, nil
		case "FALSE":
			return false, nil
		}

		return s, nil
	case yaml.SequenceNode:
		if len(n.Content) > p.lim.MaxEntries {
			return nil, p.tooLarge(n, "an xmd list")
		}

		out := make([]any, 0, len(n.Content))

		for _, item := range n.Content {
			v, err := p.xmdValue(item, depth+1)
			if err != nil {
				return nil, err
			}

			out = append(out, v)
		}

		return out, nil
	case yaml.MappingNode:
		out := make(map[string]any)

		err := p.fields(n, "an xmd mapping", func(k string, v *yaml.Node) error {
			val, err := p.xmdValue(v, depth+1)
			out[k] = val

			return err
		})

		return out, err
	}

	return nil, p.fail(n, "aliases are not allowed")
}

func (p *moduleParser) defaults(data *yaml.Node) (*ModuleDefaults, error) {
	d := &ModuleDefaults{}

	err := p.fields(data, "data", func(k string, v *yaml.Node) error {
		var err error

		switch k {
		case "module":
			d.Module, err = p.scalar(v, k)
		case "modified":
			d.Modified, err = p.uint(v, k)
		case "stream":
			d.Stream, err = p.scalar(v, k)
		case "profiles":
			d.Profiles, err = p.listMap(v, k)
		case "intents":
			d.Intents, err = p.intents(v)
		}

		return err
	})
	if err != nil {
		return nil, err
	}

	if err := d.validate(); err != nil {
		return nil, fmt.Errorf("%w: document %d: %w", ErrInvalidModulemd, p.doc, err)
	}

	return d, nil
}

func (p *moduleParser) intents(n *yaml.Node) (map[string]ModuleDefaultsIntent, error) {
	out := make(map[string]ModuleDefaultsIntent)

	err := p.fields(n, "intents", func(name string, v *yaml.Node) error {
		var in ModuleDefaultsIntent

		err := p.fields(v, "intent "+name, func(k string, vv *yaml.Node) error {
			var err error

			switch k {
			case "stream":
				in.Stream, err = p.scalar(vv, k)
			case "profiles":
				in.Profiles, err = p.listMap(vv, k)
			}

			return err
		})
		out[name] = in

		return err
	})

	return out, err
}

// moduleTimeLayout is the date format of modulemd-obsoletes: UTC to the
// minute.
const moduleTimeLayout = "2006-01-02T15:04Z"

func (p *moduleParser) moduleTime(n *yaml.Node, what string) (time.Time, error) {
	s, err := p.scalar(n, what)
	if err != nil {
		return time.Time{}, err
	}

	t, err := time.Parse(moduleTimeLayout, s)
	if err != nil {
		return time.Time{}, p.fail(n, "%s must be a UTC date as YYYY-MM-DDTHH:MMZ, got %q", what, s)
	}

	return t.UTC(), nil
}

func (p *moduleParser) obsoletes(data *yaml.Node) (*ModuleObsoletes, error) {
	o := &ModuleObsoletes{}

	err := p.fields(data, "data", func(k string, v *yaml.Node) error {
		var err error

		switch k {
		case "modified":
			o.Modified, err = p.moduleTime(v, k)
		case "eol_date":
			o.EOLDate, err = p.moduleTime(v, k)
		case "reset":
			o.Reset, err = p.bool(v, k)
		case "module":
			o.Module, err = p.scalar(v, k)
		case "stream":
			o.Stream, err = p.scalar(v, k)
		case "context":
			o.Context, err = p.scalar(v, k)
		case "message":
			o.Message, err = p.scalar(v, k)
		case "obsoleted_by":
			o.ObsoletedBy, err = p.obsoletedBy(v)
		}

		return err
	})
	if err != nil {
		return nil, err
	}

	if err := o.validate(); err != nil {
		return nil, fmt.Errorf("%w: document %d: %w", ErrInvalidModulemd, p.doc, err)
	}

	return o, nil
}

func (p *moduleParser) obsoletedBy(n *yaml.Node) (*ModuleObsoletedBy, error) {
	b := &ModuleObsoletedBy{}

	err := p.fields(n, "obsoleted_by", func(k string, v *yaml.Node) error {
		var err error

		switch k {
		case "module":
			b.Module, err = p.scalar(v, k)
		case "stream":
			b.Stream, err = p.scalar(v, k)
		}

		return err
	})
	if err != nil {
		return nil, err
	}

	if b.Module == "" || b.Stream == "" {
		return nil, p.fail(n, "obsoleted_by needs a module and a stream")
	}

	return b, nil
}

func (p *moduleParser) translations(data *yaml.Node) (*ModuleTranslations, error) {
	t := &ModuleTranslations{}

	err := p.fields(data, "data", func(k string, v *yaml.Node) error {
		var err error

		switch k {
		case "module":
			t.Module, err = p.scalar(v, k)
		case "stream":
			t.Stream, err = p.scalar(v, k)
		case "modified":
			t.Modified, err = p.uint(v, k)
		case "translations":
			t.Locales, err = p.locales(v)
		}

		return err
	})
	if err != nil {
		return nil, err
	}

	if err := t.validate(); err != nil {
		return nil, fmt.Errorf("%w: document %d: %w", ErrInvalidModulemd, p.doc, err)
	}

	return t, nil
}

func (p *moduleParser) locales(n *yaml.Node) (map[string]ModuleTranslation, error) {
	out := make(map[string]ModuleTranslation)

	err := p.fields(n, "translations", func(locale string, v *yaml.Node) error {
		var tr ModuleTranslation

		err := p.fields(v, "translation "+locale, func(k string, vv *yaml.Node) error {
			var err error

			switch k {
			case "summary":
				tr.Summary, err = p.scalar(vv, k)
			case "description":
				tr.Description, err = p.scalar(vv, k)
			case "profiles":
				tr.Profiles = make(map[string]string)

				err = p.fields(vv, "translated profiles", func(name string, vvv *yaml.Node) error {
					var err error

					tr.Profiles[name], err = p.scalar(vvv, "a profile description")

					return err
				})
			}

			return err
		})
		out[locale] = tr

		return err
	})

	return out, err
}
