package repodata

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidUpdateinfo means an updateinfo.xml advisory cannot be read or
// written: a date or module version that is not a number or a date, an
// advisory without an id, or a checksum without its type.
var ErrInvalidUpdateinfo = errors.New("repodata: invalid updateinfo advisory")

// Default limits of [ReadUpdateinfo].
const (
	// DefaultMaxUpdates bounds the advisories of a document. The updateinfo
	// of the largest distributions holds a few tens of thousands.
	DefaultMaxUpdates = 1_000_000
	// DefaultMaxReferences bounds the references of one advisory.
	DefaultMaxReferences = 10_000
	// DefaultMaxCollections bounds the collections of one advisory.
	DefaultMaxCollections = 10_000
	// DefaultMaxAdvisoryPackages bounds the packages of one advisory,
	// summed over its collections. A Fedora advisory for a large rebuild
	// lists a few thousand.
	DefaultMaxAdvisoryPackages = 100_000
	// DefaultMaxAdvisoryFieldBytes bounds one text field of an advisory,
	// such as its description.
	DefaultMaxAdvisoryFieldBytes = 1 << 20
)

// maxUpdateinfoDepth bounds the nesting of the elements below an <update>; a
// valid one is four deep.
const maxUpdateinfoDepth = 16

// updateDateLayout is how createrepo_c and the distributions write an advisory
// date: <issued date="2024-03-01 09:30:00"/>.
const updateDateLayout = "2006-01-02 15:04:05"

// updateDateLayouts are the layouts [ReadUpdateinfo] accepts for a date, besides
// a Unix time in seconds: the ones distributions publish.
var updateDateLayouts = []string{
	updateDateLayout,
	"2006-01-02 15:04",
	"2006-01-02",
	time.RFC3339,
	"2006-01-02T15:04:05",
}

// Advisory is an <update> of updateinfo.xml: a security, bug fix or
// enhancement announcement and the packages that carry it.
type Advisory struct {
	// ID is the identifier of the advisory, such as "FEDORA-2024-1a2b3c4d5e"
	// or "RLSA-2024:1234"; it is required.
	ID string
	// Title is the one line name of the advisory.
	Title string
	// Type is "security", "bugfix", "enhancement" or "newpackage".
	Type string
	// Severity is "Critical", "Important", "Moderate", "Low" or "None".
	Severity string
	// Status is the state of the advisory, "stable" or "final".
	Status string
	// Version is the revision of the advisory text, usually a small number.
	Version string
	// From is the contact of the issuer, such as "updates@fedoraproject.org".
	From string
	// Issued and Updated are when the advisory was first published and last
	// changed, in UTC; the zero time leaves the date out.
	Issued  time.Time
	Updated time.Time
	// Release names the distribution release the advisory is for.
	Release string
	// Rights is the copyright notice.
	Rights string
	// Summary, Description and Solution are the texts of the advisory.
	Summary     string
	Description string
	Solution    string
	// PushCount is how many times the advisory was pushed.
	PushCount string
	// RebootSuggested says that installing any package of the advisory calls
	// for a reboot.
	RebootSuggested bool
	// References are the bug reports, CVEs and pages that concern it.
	References []AdvisoryReference
	// Collections are the package sets the advisory fixes.
	Collections []AdvisoryCollection
}

// AdvisoryReference is a <reference> of an advisory.
type AdvisoryReference struct {
	// Href is the address of the page.
	Href string
	// ID is the identifier in the referenced system, such as a CVE number.
	ID string
	// Title names the referenced item.
	Title string
	// Type is "self", "cve", "bugzilla", "vendor", and so on.
	Type string
}

// AdvisoryCollection is a <collection> of an advisory: the packages of one
// repository or module stream.
type AdvisoryCollection struct {
	// Short is the short name of the collection, such as "F40".
	Short string
	// Name is its descriptive name, such as "Fedora 40".
	Name string
	// Module is set when the collection belongs to a module stream.
	Module   *AdvisoryModule
	Packages []AdvisoryPackage
}

// AdvisoryModule is the module stream a collection is for.
type AdvisoryModule struct {
	Name    string
	Stream  string
	Version uint64
	Context string
	Arch    string
}

// AdvisoryPackage is a <package> of a collection: the package an advisory
// fixes.
type AdvisoryPackage struct {
	Name    string
	Version string
	Release string
	// Epoch is written as it is, "0" included.
	Epoch string
	Arch  string
	// Src is the source package, as a file name or an address.
	Src string
	// Filename is the name of the .rpm file.
	Filename string
	// Sum is the checksum of the .rpm file; empty when the advisory has none.
	Sum AdvisorySum
	// RebootSuggested, RestartSuggested and ReloginSuggested say what
	// installing this package calls for.
	RebootSuggested  bool
	RestartSuggested bool
	ReloginSuggested bool
}

// AdvisorySum is the checksum of a package of an advisory.
type AdvisorySum struct {
	// Type is the algorithm: "md5", "sha1", "sha256" or "sha512".
	Type string
	// Value is the hex digest.
	Value string
}

// UpdateinfoLimits bounds [ReadUpdateinfo]. A zero field selects its default.
type UpdateinfoLimits struct {
	// MaxUpdates bounds the advisories of the document.
	MaxUpdates int
	// MaxReferences bounds the references of one advisory.
	MaxReferences int
	// MaxCollections bounds the collections of one advisory.
	MaxCollections int
	// MaxPackages bounds the packages of one advisory, summed over its
	// collections.
	MaxPackages int
	// MaxFieldBytes bounds one text field of an advisory.
	MaxFieldBytes int
}

func (l UpdateinfoLimits) normalized() UpdateinfoLimits {
	if l.MaxUpdates <= 0 {
		l.MaxUpdates = DefaultMaxUpdates
	}

	if l.MaxReferences <= 0 {
		l.MaxReferences = DefaultMaxReferences
	}

	if l.MaxCollections <= 0 {
		l.MaxCollections = DefaultMaxCollections
	}

	if l.MaxPackages <= 0 {
		l.MaxPackages = DefaultMaxAdvisoryPackages
	}

	if l.MaxFieldBytes <= 0 {
		l.MaxFieldBytes = DefaultMaxAdvisoryFieldBytes
	}

	return l
}

// ReadUpdateinfo decodes updateinfo.xml from r and calls fn for every
// advisory. An element it does not know is ignored and an advisory without an
// id is skipped. Malformed XML, a date or module version that is invalid
// ([ErrInvalidUpdateinfo]), a limit exceeded ([ErrTooLarge]) or an error of fn
// stops the read and is returned. Bound the decompressed size of r with
// [OpenMetadata].
func ReadUpdateinfo(r io.Reader, lim UpdateinfoLimits, fn func(*Advisory) error) error {
	lim = lim.normalized()
	dec := xml.NewDecoder(r)
	count := 0

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("repodata: parsing updateinfo.xml: %w", err)
		}

		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "update" {
			continue
		}

		count++
		if count > lim.MaxUpdates {
			return fmt.Errorf("%w: more than %d advisories", ErrTooLarge, lim.MaxUpdates)
		}

		adv, err := readAdvisory(dec, start, lim)
		if err != nil {
			return err
		}

		if adv.ID == "" {
			continue
		}

		if err := fn(adv); err != nil {
			return err
		}
	}
}

// advisoryReader accumulates one <update> element.
type advisoryReader struct {
	lim      UpdateinfoLimits
	adv      Advisory
	packages int
}

func readAdvisory(dec *xml.Decoder, start xml.StartElement, lim UpdateinfoLimits) (*Advisory, error) {
	ar := &advisoryReader{lim: lim}
	ar.adv.From = attrOf(start.Attr, "from")
	ar.adv.Status = attrOf(start.Attr, "status")
	ar.adv.Type = attrOf(start.Attr, "type")
	ar.adv.Version = attrOf(start.Attr, "version")

	// path holds the names of the open elements below <update>.
	var (
		path []string
		text strings.Builder
	)

	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("repodata: parsing updateinfo.xml: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			text.Reset()

			if len(path) > maxUpdateinfoDepth {
				return nil, fmt.Errorf("%w: elements nested deeper than %d levels", ErrTooLarge, maxUpdateinfoDepth)
			}

			if err := ar.open(path, t.Attr); err != nil {
				return nil, err
			}
		case xml.CharData:
			if text.Len()+len(t) > lim.MaxFieldBytes {
				return nil, fmt.Errorf("%w: a text field of an advisory exceeds %d bytes", ErrTooLarge, lim.MaxFieldBytes)
			}

			text.Write(t)
		case xml.EndElement:
			if len(path) == 0 {
				return &ar.adv, nil
			}

			ar.close(path, text.String())

			path = path[:len(path)-1]
			text.Reset()
		}
	}
}

// open handles the start of the element at path.
func (ar *advisoryReader) open(path []string, attrs []xml.Attr) error {
	adv := &ar.adv

	switch len(path) {
	case 1:
		var err error

		switch path[0] {
		case "issued":
			adv.Issued, err = parseUpdateDate(attrOf(attrs, "date"))
		case "updated":
			adv.Updated, err = parseUpdateDate(attrOf(attrs, "date"))
		}

		if err != nil {
			return fmt.Errorf("repodata: advisory %q: %w", adv.ID, err)
		}
	case 2:
		switch {
		case path[0] == "references" && path[1] == "reference":
			if len(adv.References) >= ar.lim.MaxReferences {
				return fmt.Errorf("%w: more than %d references in an advisory", ErrTooLarge, ar.lim.MaxReferences)
			}

			adv.References = append(adv.References, AdvisoryReference{
				Href:  attrOf(attrs, "href"),
				ID:    attrOf(attrs, "id"),
				Title: attrOf(attrs, "title"),
				Type:  attrOf(attrs, "type"),
			})
		case path[0] == "pkglist" && path[1] == "collection":
			if len(adv.Collections) >= ar.lim.MaxCollections {
				return fmt.Errorf("%w: more than %d collections in an advisory", ErrTooLarge, ar.lim.MaxCollections)
			}

			adv.Collections = append(adv.Collections, AdvisoryCollection{Short: attrOf(attrs, "short")})
		}
	case 3:
		if path[0] != "pkglist" || path[1] != "collection" {
			break
		}

		col := &adv.Collections[len(adv.Collections)-1]

		switch path[2] {
		case "module":
			m, err := newAdvisoryModule(attrs)
			if err != nil {
				return fmt.Errorf("repodata: advisory %q: %w", adv.ID, err)
			}

			col.Module = m
		case "package":
			if ar.packages >= ar.lim.MaxPackages {
				return fmt.Errorf("%w: more than %d packages in an advisory", ErrTooLarge, ar.lim.MaxPackages)
			}

			ar.packages++

			col.Packages = append(col.Packages, AdvisoryPackage{
				Name:    attrOf(attrs, "name"),
				Version: attrOf(attrs, "version"),
				Release: attrOf(attrs, "release"),
				Epoch:   attrOf(attrs, "epoch"),
				Arch:    attrOf(attrs, "arch"),
				Src:     attrOf(attrs, "src"),
			})
		}
	case 4:
		if ar.inPackage(path) && path[3] == "sum" {
			col := &adv.Collections[len(adv.Collections)-1]
			col.Packages[len(col.Packages)-1].Sum.Type = attrOf(attrs, "type")
		}
	}

	return nil
}

// inPackage reports whether path names a child of a <package>.
func (*advisoryReader) inPackage(path []string) bool {
	return len(path) == 4 && path[0] == "pkglist" && path[1] == "collection" && path[2] == "package"
}

// close handles the end of the element at path, whose character data is text.
func (ar *advisoryReader) close(path []string, text string) {
	adv := &ar.adv

	switch len(path) {
	case 1:
		switch path[0] {
		case "id":
			adv.ID = strings.TrimSpace(text)
		case "title":
			adv.Title = text
		case "severity":
			adv.Severity = strings.TrimSpace(text)
		case "release":
			adv.Release = text
		case "rights":
			adv.Rights = text
		case "summary":
			adv.Summary = text
		case "description":
			adv.Description = text
		case "solution":
			adv.Solution = text
		case "pushcount":
			adv.PushCount = strings.TrimSpace(text)
		case "reboot_suggested":
			adv.RebootSuggested = parseSuggested(text)
		}
	case 3:
		if path[0] == "pkglist" && path[1] == "collection" && path[2] == "name" {
			adv.Collections[len(adv.Collections)-1].Name = text
		}
	case 4:
		if !ar.inPackage(path) {
			return
		}

		col := &adv.Collections[len(adv.Collections)-1]
		pkg := &col.Packages[len(col.Packages)-1]

		switch path[3] {
		case "filename":
			pkg.Filename = strings.TrimSpace(text)
		case "sum":
			// A checksum without a value is no checksum.
			if pkg.Sum.Value = strings.TrimSpace(text); pkg.Sum.Value == "" {
				pkg.Sum.Type = ""
			}
		case "reboot_suggested":
			pkg.RebootSuggested = parseSuggested(text)
		case "restart_suggested":
			pkg.RestartSuggested = parseSuggested(text)
		case "relogin_suggested":
			pkg.ReloginSuggested = parseSuggested(text)
		}
	}
}

func newAdvisoryModule(attrs []xml.Attr) (*AdvisoryModule, error) {
	m := &AdvisoryModule{
		Name:    attrOf(attrs, "name"),
		Stream:  attrOf(attrs, "stream"),
		Context: attrOf(attrs, "context"),
		Arch:    attrOf(attrs, "arch"),
	}

	if v := attrOf(attrs, "version"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: module version %q is not a number", ErrInvalidUpdateinfo, v)
		}

		m.Version = n
	}

	return m, nil
}

// parseSuggested reads the text of a reboot_suggested-like element:
// distributions write "True".
func parseSuggested(text string) bool {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "true", "1", "yes":
		return true
	}

	return false
}

// parseUpdateDate reads the date attribute of <issued> and <updated>: one of
// the layouts of [updateDateLayouts] or a Unix time in seconds. An empty date
// is the zero time.
func parseUpdateDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}

	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), nil
	}

	for _, layout := range updateDateLayouts {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("%w: unknown date %q", ErrInvalidUpdateinfo, s)
}

// UpdateinfoWriter streams updateinfo.xml advisory by advisory.
type UpdateinfoWriter struct {
	o *xmlOut
}

// NewUpdateinfoWriter writes the document header of an updateinfo.xml to w.
// Call [UpdateinfoWriter.Add] for each advisory, then
// [UpdateinfoWriter.Close].
func NewUpdateinfoWriter(w io.Writer) *UpdateinfoWriter {
	u := &UpdateinfoWriter{o: newXMLOut(w)}
	u.o.raw(xmlHeader)
	u.o.raw("<updates>")

	return u
}

// Add renders a into the document in the layout of createrepo_c: an element
// or attribute without a value is left out, except for <references> and
// <pkglist>. An advisory without an id, or a package with a checksum but no
// checksum type, fails with [ErrInvalidUpdateinfo] and writes nothing; a
// write error of an earlier advisory is returned too.
func (u *UpdateinfoWriter) Add(a *Advisory) error {
	if err := validateAdvisory(a); err != nil {
		return err
	}

	writeAdvisory(u.o, a)
	u.o.flushIfFull()

	return u.o.err
}

// Close writes the closing tag and reports the first write error.
func (u *UpdateinfoWriter) Close() error {
	u.o.raw("\n</updates>")

	return u.o.finish()
}

// WriteUpdateinfoXML writes advisories as updateinfo.xml to w, the file the
// "updateinfo" data entry of repomd.xml points at. The output equals what
// createrepo_c's library writes for the same advisories.
func WriteUpdateinfoXML(w io.Writer, advisories []Advisory) error {
	u := NewUpdateinfoWriter(w)

	for i := range advisories {
		if err := u.Add(&advisories[i]); err != nil {
			return err
		}
	}

	return u.Close()
}

func validateAdvisory(a *Advisory) error {
	if a.ID == "" {
		return fmt.Errorf("%w: no id", ErrInvalidUpdateinfo)
	}

	for i := range a.Collections {
		for j := range a.Collections[i].Packages {
			p := &a.Collections[i].Packages[j]
			if p.Sum.Value != "" && p.Sum.Type == "" {
				return fmt.Errorf("%w: advisory %q: the checksum of package %q has no type", ErrInvalidUpdateinfo, a.ID, p.Name)
			}
		}
	}

	return nil
}

func writeAdvisory(o *xmlOut, a *Advisory) {
	o.open("  ", "update")
	o.optAttr("from", a.From)
	o.optAttr("status", a.Status)
	o.optAttr("type", a.Type)
	o.optAttr("version", a.Version)
	o.raw(">")
	o.elem("    ", "id", a.ID)
	o.optElem("    ", "title", a.Title)
	writeUpdateDate(o, "issued", a.Issued)
	writeUpdateDate(o, "updated", a.Updated)
	o.optElem("    ", "rights", a.Rights)
	o.optElem("    ", "release", a.Release)
	o.optElem("    ", "pushcount", a.PushCount)
	o.optElem("    ", "severity", a.Severity)
	o.optElem("    ", "summary", a.Summary)
	o.optElem("    ", "description", a.Description)
	o.optElem("    ", "solution", a.Solution)

	if a.RebootSuggested {
		o.elem("    ", "reboot_suggested", "True")
	}

	if len(a.References) == 0 {
		o.raw("\n    <references/>")
	} else {
		o.raw("\n    <references>")

		for i := range a.References {
			r := &a.References[i]

			o.open("      ", "reference")
			o.optAttr("href", r.Href)
			o.optAttr("id", r.ID)
			o.optAttr("type", r.Type)
			o.optAttr("title", r.Title)
			o.selfClose()
		}

		o.raw("\n    </references>")
	}

	if len(a.Collections) == 0 {
		o.raw("\n    <pkglist/>")
	} else {
		o.raw("\n    <pkglist>")

		for i := range a.Collections {
			writeCollection(o, &a.Collections[i])
		}

		o.raw("\n    </pkglist>")
	}

	o.raw("\n  </update>")
}

func writeUpdateDate(o *xmlOut, tag string, t time.Time) {
	if t.IsZero() {
		return
	}

	o.open("    ", tag)
	o.attr("date", t.UTC().Format(updateDateLayout))
	o.selfClose()
}

func writeCollection(o *xmlOut, c *AdvisoryCollection) {
	o.open("      ", "collection")
	o.optAttr("short", c.Short)

	if c.Name == "" && c.Module == nil && len(c.Packages) == 0 {
		o.selfClose()

		return
	}

	o.raw(">")
	o.optElem("        ", "name", c.Name)

	if m := c.Module; m != nil {
		o.open("        ", "module")
		o.optAttr("name", m.Name)
		o.optAttr("stream", m.Stream)
		o.raw(` version="`)
		o.raw(strconv.FormatUint(m.Version, 10))
		o.raw(`"`)
		o.optAttr("context", m.Context)
		o.optAttr("arch", m.Arch)
		o.selfClose()
	}

	for i := range c.Packages {
		writeAdvisoryPackage(o, &c.Packages[i])
	}

	o.raw("\n      </collection>")
}

func writeAdvisoryPackage(o *xmlOut, p *AdvisoryPackage) {
	o.open("        ", "package")
	o.optAttr("name", p.Name)
	o.optAttr("version", p.Version)
	o.optAttr("release", p.Release)
	o.optAttr("epoch", p.Epoch)
	o.optAttr("arch", p.Arch)
	o.optAttr("src", p.Src)

	if p.Filename == "" && p.Sum.Value == "" && !p.RebootSuggested && !p.RestartSuggested && !p.ReloginSuggested {
		o.selfClose()

		return
	}

	o.raw(">")
	o.optElem("          ", "filename", p.Filename)

	if p.Sum.Value != "" {
		o.open("          ", "sum")
		o.attr("type", p.Sum.Type)
		o.raw(">")
		o.text(p.Sum.Value)
		o.closeTag("sum")
	}

	if p.RebootSuggested {
		o.elem("          ", "reboot_suggested", "True")
	}

	if p.RestartSuggested {
		o.elem("          ", "restart_suggested", "True")
	}

	if p.ReloginSuggested {
		o.elem("          ", "relogin_suggested", "True")
	}

	o.raw("\n        </package>")
}

// advisoryMerger keeps the newest advisory of every id, in the order the ids
// were first seen.
type advisoryMerger struct {
	index map[string]int
	out   []Advisory
}

func newAdvisoryMerger() *advisoryMerger {
	return &advisoryMerger{index: make(map[string]int)}
}

// add keeps a unless an advisory of the same id that is at least as new is
// already there. It reports whether a new id was added.
func (m *advisoryMerger) add(a Advisory) bool {
	if i, ok := m.index[a.ID]; ok {
		if a.modified().After(m.out[i].modified()) {
			m.out[i] = a
		}

		return false
	}

	m.index[a.ID] = len(m.out)
	m.out = append(m.out, a)

	return true
}

// modified is when the advisory last changed: its update time, or its
// issue time for one that was never updated.
func (a *Advisory) modified() time.Time {
	if a.Updated.IsZero() {
		return a.Issued
	}

	return a.Updated
}

// MergeAdvisories combines advisories of several sources into one list with
// every id once. Of the advisories that share an id the one updated last
// (issued last when none was updated) wins; on a tie the earlier source wins.
// The result lists the ids in the order they first appear.
func MergeAdvisories(sources ...[]Advisory) []Advisory {
	m := newAdvisoryMerger()

	for _, src := range sources {
		for i := range src {
			m.add(src[i])
		}
	}

	return m.out
}

// MergeUpdateinfo reads the updateinfo.xml documents of sources, merges their
// advisories like [MergeAdvisories], and writes the result to w as one
// updateinfo.xml. It returns the number of advisories written. The limits
// apply to each source; MaxUpdates also bounds the distinct advisories of the
// result, which are held in memory. A source that cannot be read fails the
// merge before anything is written.
func MergeUpdateinfo(w io.Writer, sources []io.Reader, lim UpdateinfoLimits) (int, error) {
	lim = lim.normalized()
	m := newAdvisoryMerger()

	for _, src := range sources {
		err := ReadUpdateinfo(src, lim, func(a *Advisory) error {
			if m.add(*a) && len(m.out) > lim.MaxUpdates {
				return fmt.Errorf("%w: more than %d distinct advisories", ErrTooLarge, lim.MaxUpdates)
			}

			return nil
		})
		if err != nil {
			return 0, err
		}
	}

	for i := range m.out {
		if err := validateAdvisory(&m.out[i]); err != nil {
			return 0, err
		}
	}

	if err := WriteUpdateinfoXML(w, m.out); err != nil {
		return 0, err
	}

	return len(m.out), nil
}
