package repodata

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// Default limits of [ReadComps].
const (
	// DefaultMaxCompsBytes bounds the size of the document read.
	DefaultMaxCompsBytes = 256 << 20
	// DefaultMaxCompsEntries bounds the groups, categories, environments,
	// language packs, blacklisted packages and ignored dependencies together.
	DefaultMaxCompsEntries = 1 << 20
	// DefaultMaxCompsListItems bounds each list of an element: the packages
	// of a group, the groups of a category or environment, the translations
	// of a text.
	DefaultMaxCompsListItems = 100_000
	// DefaultMaxCompsFieldBytes bounds one text value.
	DefaultMaxCompsFieldBytes = 1 << 20
)

// maxCompsDepth bounds the nesting of elements; a comps.xml nests four deep.
const maxCompsDepth = 32

// CompsLimits bounds [ReadComps] and [ParseComps]. A zero field selects its
// default.
type CompsLimits struct {
	// MaxBytes bounds the document; reading more fails with [ErrTooLarge].
	MaxBytes int64
	// MaxEntries bounds the top-level entries of the document.
	MaxEntries int
	// MaxListItems bounds each list of one element.
	MaxListItems int
	// MaxFieldBytes bounds one text value.
	MaxFieldBytes int
}

func (l CompsLimits) normalized() CompsLimits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxCompsBytes
	}

	if l.MaxEntries <= 0 {
		l.MaxEntries = DefaultMaxCompsEntries
	}

	if l.MaxListItems <= 0 {
		l.MaxListItems = DefaultMaxCompsListItems
	}

	if l.MaxFieldBytes <= 0 {
		l.MaxFieldBytes = DefaultMaxCompsFieldBytes
	}

	return l
}

// CompsVisitor receives the entries of a comps.xml as [ReadComps] decodes
// them; a nil field skips that kind of entry. The callee owns the value it is
// given. An error returned by a callback stops the read and is returned as
// is.
type CompsVisitor struct {
	Group       func(*CompsGroup) error
	Category    func(*CompsCategory) error
	Environment func(*CompsEnvironment) error
	// Langpack, Blacklisted and IgnoredDep receive the entries of
	// <langpacks>, <blacklist> and <whiteout> one by one.
	Langpack    func(CompsLangpack) error
	Blacklisted func(CompsBlacklisted) error
	IgnoredDep  func(CompsIgnoredDep) error
}

// ParseComps decodes a whole comps.xml into a model. See [ReadComps] for what
// is accepted and how the limits apply.
func ParseComps(r io.Reader, lim CompsLimits) (*Comps, error) {
	var c Comps

	err := ReadComps(r, lim, CompsVisitor{
		Group:       func(g *CompsGroup) error { c.Groups = append(c.Groups, *g); return nil },
		Category:    func(g *CompsCategory) error { c.Categories = append(c.Categories, *g); return nil },
		Environment: func(e *CompsEnvironment) error { c.Environments = append(c.Environments, *e); return nil },
		Langpack:    func(l CompsLangpack) error { c.Langpacks = append(c.Langpacks, l); return nil },
		Blacklisted: func(b CompsBlacklisted) error { c.Blacklist = append(c.Blacklist, b); return nil },
		IgnoredDep:  func(w CompsIgnoredDep) error { c.Whiteout = append(c.Whiteout, w); return nil },
	})
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// ReadComps decodes the comps.xml in r entry by entry and hands each to v, so
// memory use is that of one entry. The document must be UTF-8 with a <comps>
// root; elements and attributes this package does not model (such as the
// <groupreq> of old Fedora releases) are skipped, and the surrounding
// whitespace around an id, a package name, a number or a flag is dropped, the
// names and descriptions are kept as they are.
//
// A document that is not well-formed, or whose entry breaks a rule of the
// format (an empty id, an unknown package type, a boolean that is not
// true/false/1/0, a non-numeric display_order) fails with [ErrInvalidComps]
// or the XML error. A limit exceeded fails with [ErrTooLarge]. The input is
// read to its end so trailing garbage is reported, but entries before the
// error have been delivered already. Bound the decompressed size with
// [OpenMetadata].
func ReadComps(r io.Reader, lim CompsLimits, v CompsVisitor) error {
	lim = lim.normalized()

	cr := &compsReader{
		dec: xml.NewDecoder(limitio.Capped(r, lim.MaxBytes+1, ErrTooLarge)),
		lim: lim,
	}

	if err := cr.document(v); err != nil {
		if errors.Is(err, ErrInvalidComps) || errors.Is(err, ErrTooLarge) {
			return fmt.Errorf("repodata: reading comps.xml: %w", err)
		}

		return fmt.Errorf("repodata: parsing comps.xml: %w", err)
	}

	return nil
}

// compsReader decodes tokens and tracks the element depth and the entry
// count.
type compsReader struct {
	dec     *xml.Decoder
	lim     CompsLimits
	depth   int
	entries int
}

func (r *compsReader) next() (xml.Token, error) {
	tok, err := r.dec.Token()
	if err != nil {
		return nil, err
	}

	switch tok.(type) {
	case xml.StartElement:
		r.depth++
		if r.depth > maxCompsDepth {
			return nil, fmt.Errorf("%w: elements nested deeper than %d", ErrTooLarge, maxCompsDepth)
		}
	case xml.EndElement:
		r.depth--
	}

	return tok, nil
}

// skip consumes the rest of the element whose start tag was just read.
func (r *compsReader) skip() error {
	for target := r.depth - 1; r.depth > target; {
		if _, err := r.next(); err != nil {
			return err
		}
	}

	return nil
}

// rawText returns the text of the element whose start tag was just read and
// consumes its end tag; nested elements are skipped.
func (r *compsReader) rawText() (string, error) {
	var sb strings.Builder

	for target := r.depth - 1; r.depth > target; {
		tok, err := r.next()
		if err != nil {
			return "", err
		}

		switch t := tok.(type) {
		case xml.CharData:
			if r.depth == target+1 {
				if sb.Len()+len(t) > r.lim.MaxFieldBytes {
					return "", fmt.Errorf("%w: a text of more than %d bytes", ErrTooLarge, r.lim.MaxFieldBytes)
				}

				sb.Write(t)
			}
		case xml.StartElement:
			if err := r.skip(); err != nil {
				return "", err
			}
		}
	}

	return sb.String(), nil
}

// text is rawText without the whitespace around the value, for the values
// that name something: ids, packages, numbers and flags.
func (r *compsReader) text() (string, error) {
	s, err := r.rawText()

	return strings.Trim(s, compsSpace), err
}

func (r *compsReader) count() error {
	r.entries++
	if r.entries > r.lim.MaxEntries {
		return fmt.Errorf("%w: more than %d comps entries", ErrTooLarge, r.lim.MaxEntries)
	}

	return nil
}

func (r *compsReader) document(v CompsVisitor) error {
	for {
		tok, err := r.next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: no <comps> element", ErrInvalidComps)
		}

		if err != nil {
			return err
		}

		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		if start.Name.Local != "comps" {
			return fmt.Errorf("%w: the root element is <%s>, not <comps>", ErrInvalidComps, start.Name.Local)
		}

		break
	}

	if err := r.entriesOf(v); err != nil {
		return err
	}

	// The root is closed; the rest must still be well-formed.
	for {
		_, err := r.next()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return err
		}
	}
}

func (r *compsReader) entriesOf(v CompsVisitor) error {
	for target := r.depth - 1; r.depth > target; {
		tok, err := r.next()
		if err != nil {
			return err
		}

		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		switch start.Name.Local {
		case "group":
			err = r.group(start, v.Group)
		case "category":
			err = r.category(start, v.Category)
		case "environment":
			err = r.environment(start, v.Environment)
		case "langpacks":
			err = r.rules(v.Langpack != nil, "match", func(a attrs) error {
				return r.langpack(a, v.Langpack)
			})
		case "blacklist":
			err = r.rules(v.Blacklisted != nil, "package", func(a attrs) error {
				return r.blacklisted(a, v.Blacklisted)
			})
		case "whiteout":
			err = r.rules(v.IgnoredDep != nil, "ignoredep", func(a attrs) error {
				return r.ignoredDep(a, v.IgnoredDep)
			})
		default:
			err = r.skip()
		}

		if err != nil {
			return err
		}
	}

	return nil
}

// attrs holds the attributes of a start element by local name; xml:lang is
// stored as "xml:lang".
type attrs map[string]string

func attrsOf(start xml.StartElement) attrs {
	if len(start.Attr) == 0 {
		return nil
	}

	a := make(attrs, len(start.Attr))

	for _, at := range start.Attr {
		name := at.Name.Local
		if at.Name.Space == "xml" || at.Name.Space == "http://www.w3.org/XML/1998/namespace" {
			name = "xml:" + name
		}

		a[name] = at.Value
	}

	return a
}

// archList splits an arch attribute at commas and spaces.
func archList(s string) []string {
	list := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	if len(list) == 0 {
		return nil
	}

	return list
}

func parseBool(s, what string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	}

	return false, fmt.Errorf("%w: %s is %q, not a boolean", ErrInvalidComps, what, s)
}

func parseOrder(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%w: display_order %q is not a number", ErrInvalidComps, s)
	}

	return n, nil
}

// heading collects the id, names, descriptions and display order that groups,
// categories and environments share.
type heading struct {
	id           string
	name, desc   string
	names, descs map[string]string
	order        int
}

// field stores the text of a child element if it is one of the shared ones
// and reports whether it was.
func (r *compsReader) field(h *heading, start xml.StartElement) (bool, error) {
	switch start.Name.Local {
	case "id", "name", "description", "display_order":
	default:
		return false, nil
	}

	a := attrsOf(start)

	var text string

	var err error

	switch start.Name.Local {
	case "id", "display_order":
		text, err = r.text()
	default:
		text, err = r.rawText()
	}

	if err != nil {
		return true, err
	}

	switch start.Name.Local {
	case "id":
		h.id = text
	case "display_order":
		h.order, err = parseOrder(text)
	case "name":
		h.name, err = r.localizedText(&h.names, h.name, a["xml:lang"], text)
	case "description":
		h.desc, err = r.localizedText(&h.descs, h.desc, a["xml:lang"], text)
	}

	return true, err
}

// localizedText returns the new value of the unlocalized text, or stores text
// in the map under lang.
func (r *compsReader) localizedText(m *map[string]string, cur, lang, text string) (string, error) {
	if lang == "" {
		return text, nil
	}

	if *m == nil {
		*m = map[string]string{}
	}

	if _, dup := (*m)[lang]; !dup && len(*m) >= r.lim.MaxListItems {
		return cur, fmt.Errorf("%w: more than %d translations of a text", ErrTooLarge, r.lim.MaxListItems)
	}

	(*m)[lang] = text

	return cur, nil
}

func (r *compsReader) group(start xml.StartElement, fn func(*CompsGroup) error) error {
	g := &CompsGroup{Arch: archList(attrsOf(start)["arch"]), UserVisible: true}
	h := heading{}

	for target := r.depth - 1; r.depth > target; {
		tok, err := r.next()
		if err != nil {
			return err
		}

		child, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		if handled, err := r.field(&h, child); handled || err != nil {
			if err != nil {
				return err
			}

			continue
		}

		switch child.Name.Local {
		case "default", "uservisible", "biarchonly":
			text, err := r.text()
			if err != nil {
				return err
			}

			b, err := parseBool(text, child.Name.Local)
			if err != nil {
				return err
			}

			switch child.Name.Local {
			case "default":
				g.Default = b
			case "uservisible":
				g.UserVisible = b
			default:
				g.BiarchOnly = b
			}
		case "langonly":
			if g.LangOnly, err = r.text(); err != nil {
				return err
			}
		case "packagelist":
			if err := r.packages(g); err != nil {
				return err
			}
		default:
			if err := r.skip(); err != nil {
				return err
			}
		}
	}

	g.ID, g.Name, g.NameLocalized, g.Description, g.DescriptionLocalized, g.DisplayOrder = h.id, h.name, h.names, h.desc, h.descs, h.order

	if g.ID == "" {
		return fmt.Errorf("%w: group without an id", ErrInvalidComps)
	}

	if err := r.count(); err != nil {
		return err
	}

	if fn == nil {
		return nil
	}

	return fn(g)
}

func (r *compsReader) packages(g *CompsGroup) error {
	for target := r.depth - 1; r.depth > target; {
		tok, err := r.next()
		if err != nil {
			return err
		}

		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		if start.Name.Local != "packagereq" {
			if err := r.skip(); err != nil {
				return err
			}

			continue
		}

		if len(g.Packages) >= r.lim.MaxListItems {
			return fmt.Errorf("%w: more than %d packages in group %q", ErrTooLarge, r.lim.MaxListItems, g.ID)
		}

		a := attrsOf(start)

		name, err := r.text()
		if err != nil {
			return err
		}

		p := CompsPackage{Name: name, Type: a["type"], Requires: a["requires"], Arch: archList(a["arch"])}

		switch p.Type {
		case "":
			p.Type = CompsDefault
		case CompsMandatory, CompsDefault, CompsOptional, CompsConditional:
		default:
			return fmt.Errorf("%w: package %q has the type %q", ErrInvalidComps, name, p.Type)
		}

		if name == "" {
			return fmt.Errorf("%w: a package without a name", ErrInvalidComps)
		}

		if v, ok := a["basearchonly"]; ok {
			if p.BaseArchOnly, err = parseBool(v, "basearchonly"); err != nil {
				return err
			}
		}

		g.Packages = append(g.Packages, p)
	}

	return nil
}

func (r *compsReader) category(start xml.StartElement, fn func(*CompsCategory) error) error {
	c := &CompsCategory{Arch: archList(attrsOf(start)["arch"])}
	h := heading{}

	for target := r.depth - 1; r.depth > target; {
		tok, err := r.next()
		if err != nil {
			return err
		}

		child, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		handled, err := r.field(&h, child)
		if err != nil {
			return err
		}

		if handled {
			continue
		}

		if child.Name.Local == "grouplist" {
			c.Groups, err = r.refs(c.Groups)
		} else {
			err = r.skip()
		}

		if err != nil {
			return err
		}
	}

	c.ID, c.Name, c.NameLocalized, c.Description, c.DescriptionLocalized, c.DisplayOrder = h.id, h.name, h.names, h.desc, h.descs, h.order

	if c.ID == "" {
		return fmt.Errorf("%w: category without an id", ErrInvalidComps)
	}

	if err := r.count(); err != nil {
		return err
	}

	if fn == nil {
		return nil
	}

	return fn(c)
}

func (r *compsReader) environment(start xml.StartElement, fn func(*CompsEnvironment) error) error {
	e := &CompsEnvironment{Arch: archList(attrsOf(start)["arch"])}
	h := heading{}

	for target := r.depth - 1; r.depth > target; {
		tok, err := r.next()
		if err != nil {
			return err
		}

		child, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		handled, err := r.field(&h, child)
		if err != nil {
			return err
		}

		if handled {
			continue
		}

		switch child.Name.Local {
		case "grouplist":
			e.Groups, err = r.refs(e.Groups)
		case "optionlist":
			e.Options, err = r.refs(e.Options)
		default:
			err = r.skip()
		}

		if err != nil {
			return err
		}
	}

	e.ID, e.Name, e.NameLocalized, e.Description, e.DescriptionLocalized, e.DisplayOrder = h.id, h.name, h.names, h.desc, h.descs, h.order

	if e.ID == "" {
		return fmt.Errorf("%w: environment without an id", ErrInvalidComps)
	}

	if err := r.count(); err != nil {
		return err
	}

	if fn == nil {
		return nil
	}

	return fn(e)
}

// refs appends the <groupid> entries of the list element just opened to list.
func (r *compsReader) refs(list []CompsGroupRef) ([]CompsGroupRef, error) {
	for target := r.depth - 1; r.depth > target; {
		tok, err := r.next()
		if err != nil {
			return nil, err
		}

		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		if start.Name.Local != "groupid" {
			if err := r.skip(); err != nil {
				return nil, err
			}

			continue
		}

		if len(list) >= r.lim.MaxListItems {
			return nil, fmt.Errorf("%w: more than %d groups in a list", ErrTooLarge, r.lim.MaxListItems)
		}

		a := attrsOf(start)

		id, err := r.text()
		if err != nil {
			return nil, err
		}

		if id == "" {
			return nil, fmt.Errorf("%w: a groupid without a group", ErrInvalidComps)
		}

		ref := CompsGroupRef{ID: id, Arch: archList(a["arch"])}

		if v, ok := a["default"]; ok {
			if ref.Default, err = parseBool(v, "default"); err != nil {
				return nil, err
			}
		}

		list = append(list, ref)
	}

	return list, nil
}

// rules walks the children named child of the list element just opened
// (<langpacks>, <blacklist> or <whiteout>) and calls fn with the attributes
// of each; with want false the list is skipped.
func (r *compsReader) rules(want bool, child string, fn func(attrs) error) error {
	if !want {
		return r.skip()
	}

	for target := r.depth - 1; r.depth > target; {
		tok, err := r.next()
		if err != nil {
			return err
		}

		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		if start.Name.Local != child {
			if err := r.skip(); err != nil {
				return err
			}

			continue
		}

		a := attrsOf(start)

		if err := r.skip(); err != nil {
			return err
		}

		if err := r.count(); err != nil {
			return err
		}

		if err := fn(a); err != nil {
			return err
		}
	}

	return nil
}

func (r *compsReader) langpack(a attrs, fn func(CompsLangpack) error) error {
	if a["name"] == "" {
		return fmt.Errorf("%w: langpack without a name", ErrInvalidComps)
	}

	return fn(CompsLangpack{Name: a["name"], Install: a["install"]})
}

func (r *compsReader) blacklisted(a attrs, fn func(CompsBlacklisted) error) error {
	if a["name"] == "" {
		return fmt.Errorf("%w: blacklisted package without a name", ErrInvalidComps)
	}

	return fn(CompsBlacklisted{Name: a["name"], Arch: a["arch"]})
}

func (r *compsReader) ignoredDep(a attrs, fn func(CompsIgnoredDep) error) error {
	if a["requires"] == "" {
		return fmt.Errorf("%w: ignoredep without requires", ErrInvalidComps)
	}

	return fn(CompsIgnoredDep{Requires: a["requires"], Package: a["package"]})
}
