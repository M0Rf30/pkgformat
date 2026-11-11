package repodata

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// Package types of a comps group, as dnf reads them.
const (
	CompsMandatory   = "mandatory"
	CompsDefault     = "default"
	CompsOptional    = "optional"
	CompsConditional = "conditional"
)

// ErrInvalidComps means a comps.xml document or model breaks a rule of the
// format: a missing id, a package type that is not one of the Comps*
// constants, a malformed number or boolean.
var ErrInvalidComps = errors.New("repodata: invalid comps")

// compsDoctype is the document type declaration of a comps.xml; no client
// loads the DTD it names.
const compsDoctype = `<!DOCTYPE comps PUBLIC "-//Red Hat, Inc.//DTD Comps info//EN" "comps.dtd">` + "\n"

// Comps is the content of a comps.xml: the package groups, categories and
// environments of a repository, and the language support and package
// filtering rules dnf reads next to them.
//
// Names, descriptions and localized texts that are empty are not written.
// Localized texts are keyed by their xml:lang value and written in the order of the keys, so
// the output is the same for the same model.
type Comps struct {
	Groups       []CompsGroup
	Categories   []CompsCategory
	Environments []CompsEnvironment
	// Langpacks maps a package to the name pattern of its language packs.
	Langpacks []CompsLangpack
	// Blacklist lists packages that dependency resolution must not pull in.
	Blacklist []CompsBlacklisted
	// Whiteout lists dependencies that are ignored.
	Whiteout []CompsIgnoredDep
}

// CompsGroup is a <group> of comps.xml: a set of packages installed together.
type CompsGroup struct {
	ID string
	// Arch restricts the group to these architectures; empty means all.
	Arch []string
	// Name and Description are the texts without xml:lang, the localized
	// ones are in NameLocalized and DescriptionLocalized.
	Name                 string
	NameLocalized        map[string]string
	Description          string
	DescriptionLocalized map[string]string
	// Default marks a group that is installed by default. A comps.xml
	// without <default> reads as false; the writer always emits it.
	Default bool
	// UserVisible is false for a group that only other groups and
	// environments pull in. A comps.xml without <uservisible> reads as true;
	// the writer always emits it.
	UserVisible bool
	// BiarchOnly marks a group that only applies to a multilib system; it is
	// written only when true.
	BiarchOnly bool
	// DisplayOrder sorts the groups in a listing; 0 is not written.
	DisplayOrder int
	// LangOnly is the language code of a group that is only installed along
	// with that language.
	LangOnly string
	Packages []CompsPackage
}

// CompsPackage is a <packagereq> of a group.
type CompsPackage struct {
	Name string
	// Type is one of the Comps* constants; empty means [CompsDefault].
	Type string
	// Requires is the package a conditional package needs to be installed.
	Requires string
	// BaseArchOnly installs the package for the base architecture only,
	// not for the secondary one of a multilib system.
	BaseArchOnly bool
	// Arch restricts the package to these architectures; empty means all.
	Arch []string
}

// CompsGroupRef is a <groupid> entry of a category, environment or option
// list.
type CompsGroupRef struct {
	ID string
	// Default is the default attribute: the group is selected by default
	// in the option list of an environment.
	Default bool
	// Arch restricts the entry to these architectures; empty means all.
	Arch []string
}

// CompsCategory is a <category> of comps.xml: a list of groups.
type CompsCategory struct {
	ID                   string
	Arch                 []string
	Name                 string
	NameLocalized        map[string]string
	Description          string
	DescriptionLocalized map[string]string
	DisplayOrder         int
	Groups               []CompsGroupRef
}

// CompsEnvironment is an <environment> of comps.xml: the groups an install
// profile consists of.
type CompsEnvironment struct {
	ID                   string
	Arch                 []string
	Name                 string
	NameLocalized        map[string]string
	Description          string
	DescriptionLocalized map[string]string
	DisplayOrder         int
	// Groups are the groups of the environment and Options the optional
	// ones the user can add.
	Groups  []CompsGroupRef
	Options []CompsGroupRef
}

// CompsLangpack is a <match> of <langpacks>: Install is the name of the
// language pack of the package Name, with %s for the language code.
type CompsLangpack struct {
	Name    string
	Install string
}

// CompsBlacklisted is a <package> of <blacklist>.
type CompsBlacklisted struct {
	Name string
	Arch string
}

// CompsIgnoredDep is an <ignoredep> of <whiteout>: the dependency Requires of
// Package is ignored, of every package when Package is empty.
type CompsIgnoredDep struct {
	Requires string
	Package  string
}

// ValidateCompsXML reports whether data is well-formed XML.
func ValidateCompsXML(data []byte) error {
	r := compsReader{dec: xml.NewDecoder(limitio.Capped(bytes.NewReader(data), DefaultMaxCompsBytes+1, ErrTooLarge))}

	for {
		_, err := r.next()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("repodata: invalid comps XML: %w", err)
		}
	}
}

// Validate reports the first rule of the format the model breaks, wrapping
// [ErrInvalidComps]: an empty id, name or language, an id or a package name
// that starts or ends with white space (a reader trims it), a package type that
// is not one of the Comps* constants, an architecture that holds a comma or a
// space.
func (c *Comps) Validate() error {
	for i := range c.Groups {
		if err := c.Groups[i].validate(); err != nil {
			return err
		}
	}

	for i := range c.Categories {
		if err := c.Categories[i].validate(); err != nil {
			return err
		}
	}

	for i := range c.Environments {
		if err := c.Environments[i].validate(); err != nil {
			return err
		}
	}

	return validateRules(c.Langpacks, c.Blacklist, c.Whiteout)
}

func validateRules(lp []CompsLangpack, bl []CompsBlacklisted, wo []CompsIgnoredDep) error {
	for _, l := range lp {
		if l.Name == "" {
			return fmt.Errorf("%w: langpack without a name", ErrInvalidComps)
		}
	}

	for _, b := range bl {
		if b.Name == "" {
			return fmt.Errorf("%w: blacklisted package without a name", ErrInvalidComps)
		}
	}

	for _, w := range wo {
		if w.Requires == "" {
			return fmt.Errorf("%w: ignoredep without requires", ErrInvalidComps)
		}
	}

	return nil
}

func (g *CompsGroup) validate() error {
	if err := validateHead("group", g.ID, g.Arch, g.NameLocalized, g.DescriptionLocalized); err != nil {
		return err
	}

	if g.LangOnly != strings.Trim(g.LangOnly, compsSpace) {
		return fmt.Errorf("%w: group %q has the language %q", ErrInvalidComps, g.ID, g.LangOnly)
	}

	for i := range g.Packages {
		p := &g.Packages[i]

		if !isCompsToken(p.Name) {
			return fmt.Errorf("%w: group %q has a package named %q", ErrInvalidComps, g.ID, p.Name)
		}

		switch p.Type {
		case "", CompsMandatory, CompsDefault, CompsOptional, CompsConditional:
		default:
			return fmt.Errorf("%w: package %q of group %q has the type %q", ErrInvalidComps, p.Name, g.ID, p.Type)
		}

		if err := validateArch("package "+p.Name, p.Arch); err != nil {
			return err
		}
	}

	return nil
}

func (c *CompsCategory) validate() error {
	if err := validateHead("category", c.ID, c.Arch, c.NameLocalized, c.DescriptionLocalized); err != nil {
		return err
	}

	return validateRefs("category", c.ID, c.Groups)
}

func (e *CompsEnvironment) validate() error {
	if err := validateHead("environment", e.ID, e.Arch, e.NameLocalized, e.DescriptionLocalized); err != nil {
		return err
	}

	if err := validateRefs("environment", e.ID, e.Groups); err != nil {
		return err
	}

	return validateRefs("environment", e.ID, e.Options)
}

func validateHead(kind, id string, arch []string, names, descs map[string]string) error {
	if !isCompsToken(id) {
		return fmt.Errorf("%w: %s has the id %q", ErrInvalidComps, kind, id)
	}

	if err := validateArch(kind+" "+id, arch); err != nil {
		return err
	}

	if _, ok := names[""]; ok {
		return fmt.Errorf("%w: %s %q has a localized name without a language", ErrInvalidComps, kind, id)
	}

	if _, ok := descs[""]; ok {
		return fmt.Errorf("%w: %s %q has a localized description without a language", ErrInvalidComps, kind, id)
	}

	return nil
}

func validateRefs(kind, id string, refs []CompsGroupRef) error {
	for i := range refs {
		if !isCompsToken(refs[i].ID) {
			return fmt.Errorf("%w: %s %q lists a group with the id %q", ErrInvalidComps, kind, id, refs[i].ID)
		}

		if err := validateArch(kind+" "+id, refs[i].Arch); err != nil {
			return err
		}
	}

	return nil
}

// compsSpace is the white space a reader trims around ids, package names and
// the other values that name something.
const compsSpace = " \t\r\n"

// isCompsToken reports whether s survives a round trip as an element whose
// text a reader trims: it is not empty and has no white space at either end.
func isCompsToken(s string) bool {
	return s != "" && strings.Trim(s, compsSpace) == s
}

func validateArch(what string, arch []string) error {
	for _, a := range arch {
		if a == "" || strings.ContainsAny(a, ", ") {
			return fmt.Errorf("%w: %s has the architecture %q", ErrInvalidComps, what, a)
		}
	}

	return nil
}

// CompsWriter writes a comps.xml element by element, for a caller that merges
// the groups of several documents without holding them all in memory. Write
// the elements in the order groups, categories, environments, langpacks,
// blacklist, whiteout, then call [CompsWriter.Close].
type CompsWriter struct {
	o      *xmlOut
	closed bool
}

// NewCompsWriter writes the document header to w.
func NewCompsWriter(w io.Writer) *CompsWriter {
	cw := &CompsWriter{o: newXMLOut(w)}

	cw.o.raw(xmlHeader)
	cw.o.raw(compsDoctype)
	cw.o.raw("<comps>")

	return cw
}

// Group writes g. An invalid group fails with [ErrInvalidComps] and writes
// nothing.
func (cw *CompsWriter) Group(g *CompsGroup) error {
	if err := g.validate(); err != nil {
		return err
	}

	o := cw.o

	compsStart(o, "  ", "group", g.Arch)
	o.elem("    ", "id", g.ID)
	compsHeading(o, "    ", g.Name, g.NameLocalized, g.Description, g.DescriptionLocalized)
	o.elem("    ", "default", boolText(g.Default))
	o.elem("    ", "uservisible", boolText(g.UserVisible))

	if g.BiarchOnly {
		o.elem("    ", "biarchonly", "true")
	}

	compsDisplayOrder(o, g.DisplayOrder)
	o.optElem("    ", "langonly", g.LangOnly)

	if len(g.Packages) > 0 {
		o.raw("\n    <packagelist>")

		for j := range g.Packages {
			p := &g.Packages[j]

			typ := p.Type
			if typ == "" {
				typ = CompsDefault
			}

			o.open("      ", "packagereq")
			compsArchAttr(o, p.Arch)

			if p.BaseArchOnly {
				o.attr("basearchonly", "true")
			}

			o.optAttr("requires", p.Requires)
			o.attr("type", typ)
			o.raw(">")
			o.text(p.Name)
			o.closeTag("packagereq")
			o.flushIfFull()
		}

		o.raw("\n    </packagelist>")
	}

	o.raw("\n  </group>")

	return cw.flush()
}

// Category writes c. An invalid category fails with [ErrInvalidComps] and
// writes nothing.
func (cw *CompsWriter) Category(c *CompsCategory) error {
	if err := c.validate(); err != nil {
		return err
	}

	o := cw.o

	compsStart(o, "  ", "category", c.Arch)
	o.elem("    ", "id", c.ID)
	compsHeading(o, "    ", c.Name, c.NameLocalized, c.Description, c.DescriptionLocalized)
	compsDisplayOrder(o, c.DisplayOrder)
	compsRefs(o, "grouplist", c.Groups)
	o.raw("\n  </category>")

	return cw.flush()
}

// Environment writes e. An invalid environment fails with [ErrInvalidComps]
// and writes nothing.
func (cw *CompsWriter) Environment(e *CompsEnvironment) error {
	if err := e.validate(); err != nil {
		return err
	}

	o := cw.o

	compsStart(o, "  ", "environment", e.Arch)
	o.elem("    ", "id", e.ID)
	compsHeading(o, "    ", e.Name, e.NameLocalized, e.Description, e.DescriptionLocalized)
	compsDisplayOrder(o, e.DisplayOrder)
	compsRefs(o, "grouplist", e.Groups)
	compsRefs(o, "optionlist", e.Options)
	o.raw("\n  </environment>")

	return cw.flush()
}

// Langpacks writes one <langpacks> element with the entries; nothing for an
// empty list.
func (cw *CompsWriter) Langpacks(list []CompsLangpack) error {
	if err := validateRules(list, nil, nil); err != nil {
		return err
	}

	if len(list) == 0 {
		return nil
	}

	o := cw.o

	o.raw("\n  <langpacks>")

	for _, l := range list {
		o.open("    ", "match")
		o.attr("install", l.Install)
		o.attr("name", l.Name)
		o.selfClose()
		o.flushIfFull()
	}

	o.raw("\n  </langpacks>")

	return cw.flush()
}

// Blacklist writes one <blacklist> element with the entries; nothing for an
// empty list.
func (cw *CompsWriter) Blacklist(list []CompsBlacklisted) error {
	if err := validateRules(nil, list, nil); err != nil {
		return err
	}

	if len(list) == 0 {
		return nil
	}

	o := cw.o

	o.raw("\n  <blacklist>")

	for _, b := range list {
		o.open("    ", "package")
		o.optAttr("arch", b.Arch)
		o.attr("name", b.Name)
		o.selfClose()
		o.flushIfFull()
	}

	o.raw("\n  </blacklist>")

	return cw.flush()
}

// Whiteout writes one <whiteout> element with the entries; nothing for an
// empty list.
func (cw *CompsWriter) Whiteout(list []CompsIgnoredDep) error {
	if err := validateRules(nil, nil, list); err != nil {
		return err
	}

	if len(list) == 0 {
		return nil
	}

	o := cw.o

	o.raw("\n  <whiteout>")

	for _, w := range list {
		o.open("    ", "ignoredep")
		o.optAttr("package", w.Package)
		o.attr("requires", w.Requires)
		o.selfClose()
		o.flushIfFull()
	}

	o.raw("\n  </whiteout>")

	return cw.flush()
}

// Close writes the closing tag and reports the first write error.
func (cw *CompsWriter) Close() error {
	if !cw.closed {
		cw.closed = true

		cw.o.raw("\n</comps>\n")
	}

	return cw.o.finish()
}

func (cw *CompsWriter) flush() error {
	cw.o.flushIfFull()

	return cw.o.err
}

// WriteCompsXML writes c as comps.xml to w, the file the "group" data entry of
// repomd.xml points at. A model that breaks a rule of the format fails with
// [ErrInvalidComps] before anything is written.
func WriteCompsXML(w io.Writer, c *Comps) error {
	if c == nil {
		c = &Comps{}
	}

	if err := c.Validate(); err != nil {
		return err
	}

	cw := NewCompsWriter(w)

	for i := range c.Groups {
		if err := cw.Group(&c.Groups[i]); err != nil {
			return err
		}
	}

	for i := range c.Categories {
		if err := cw.Category(&c.Categories[i]); err != nil {
			return err
		}
	}

	for i := range c.Environments {
		if err := cw.Environment(&c.Environments[i]); err != nil {
			return err
		}
	}

	for _, err := range []error{cw.Langpacks(c.Langpacks), cw.Blacklist(c.Blacklist), cw.Whiteout(c.Whiteout)} {
		if err != nil {
			return err
		}
	}

	return cw.Close()
}

func boolText(b bool) string {
	if b {
		return "true"
	}

	return "false"
}

// compsArchAttr writes the arch attribute of an element that has a list of
// them.
func compsArchAttr(o *xmlOut, arch []string) {
	if len(arch) > 0 {
		o.attr("arch", strings.Join(arch, ","))
	}
}

// compsStart opens `<tag arch="...">`.
func compsStart(o *xmlOut, indent, tag string, arch []string) {
	o.open(indent, tag)
	compsArchAttr(o, arch)
	o.raw(">")
}

// compsHeading writes the name and the description with their translations.
func compsHeading(o *xmlOut, indent, name string, names map[string]string, desc string, descs map[string]string) {
	compsLocalized(o, indent, "name", name, names)
	compsLocalized(o, indent, "description", desc, descs)
}

func compsLocalized(o *xmlOut, indent, tag, text string, byLang map[string]string) {
	o.optElem(indent, tag, text)

	for _, lang := range slices.Sorted(maps.Keys(byLang)) {
		o.open(indent, tag)
		o.attr("xml:lang", lang)
		o.raw(">")
		o.text(byLang[lang])
		o.closeTag(tag)
	}
}

func compsDisplayOrder(o *xmlOut, n int) {
	if n != 0 {
		o.elem("    ", "display_order", strconv.Itoa(n))
	}
}

func compsRefs(o *xmlOut, tag string, refs []CompsGroupRef) {
	if len(refs) == 0 {
		return
	}

	o.raw("\n    <" + tag + ">")

	for i := range refs {
		o.open("      ", "groupid")
		compsArchAttr(o, refs[i].Arch)

		if refs[i].Default {
			o.attr("default", "true")
		}

		o.raw(">")
		o.text(refs[i].ID)
		o.closeTag("groupid")
	}

	o.raw("\n    </" + tag + ">")
}
