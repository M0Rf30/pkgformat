package repodata

import (
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/M0Rf30/pkgformat/rpm"
)

// The primary/filelists/filelists-ext/other writers emit byte for byte what
// createrepo_c (libxml2 serialization) writes for the same packages:
// <package> elements at column 0, their children indented by two spaces,
// empty text elements as <a></a>, attribute-only elements self-closed, text
// and attribute values escaped like libxml2, no trailing newline. They append
// straight into a reusable buffer that is flushed to the destination every
// flushThreshold bytes, so memory stays flat regardless of repo size.

const (
	xmlHeader      = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"
	flushThreshold = 64 << 10

	nsRPM          = "http://linux.duke.edu/metadata/rpm"
	nsCommon       = "http://linux.duke.edu/metadata/common"
	nsFilelists    = "http://linux.duke.edu/metadata/filelists"
	nsFilelistsExt = "http://linux.duke.edu/metadata/filelists-ext"
	nsOther        = "http://linux.duke.edu/metadata/other"
)

// xmlOut accumulates XML text and writes it out in large chunks. The first
// write error sticks; later appends are cheap no-ops for the caller to ignore
// until finish reports it.
type xmlOut struct {
	w   io.Writer
	buf []byte
	err error
}

func newXMLOut(w io.Writer) *xmlOut {
	return &xmlOut{w: w, buf: make([]byte, 0, flushThreshold+flushThreshold/4)}
}

func (o *xmlOut) raw(s string) { o.buf = append(o.buf, s...) }

func (o *xmlOut) i64(v int64) { o.buf = strconv.AppendInt(o.buf, v, 10) }

func (o *xmlOut) u32(v uint32) { o.buf = strconv.AppendUint(o.buf, uint64(v), 10) }

// text appends s escaped as the character data of an element.
func (o *xmlOut) text(s string) {
	o.buf = appendText(o.buf, s)
}

// attr appends ` name="value"` with the value escaped as an attribute value.
func (o *xmlOut) attr(name, value string) {
	o.buf = append(o.buf, ' ')
	o.buf = append(o.buf, name...)
	o.buf = append(o.buf, '=', '"')
	o.buf = appendAttrValue(o.buf, value)
	o.buf = append(o.buf, '"')
}

// optAttr is attr that skips empty values.
func (o *xmlOut) optAttr(name, value string) {
	if value != "" {
		o.attr(name, value)
	}
}

// elem appends `\n<indent><tag>text</tag>`.
func (o *xmlOut) elem(indent, tag, value string) {
	o.open(indent, tag)
	o.buf = append(o.buf, '>')
	o.text(value)
	o.closeTag(tag)
}

// optElem is elem that skips empty values.
func (o *xmlOut) optElem(indent, tag, value string) {
	if value != "" {
		o.elem(indent, tag, value)
	}
}

// open starts a tag (`\n<indent><tag`) leaving it open for attributes.
func (o *xmlOut) open(indent, tag string) {
	o.buf = append(o.buf, '\n')
	o.buf = append(o.buf, indent...)
	o.buf = append(o.buf, '<')
	o.buf = append(o.buf, tag...)
}

func (o *xmlOut) closeTag(tag string) {
	o.buf = append(o.buf, '<', '/')
	o.buf = append(o.buf, tag...)
	o.buf = append(o.buf, '>')
}

// selfClose ends an attribute-only element: `/>`.
func (o *xmlOut) selfClose() {
	o.buf = append(o.buf, '/', '>')
}

// version writes `<version epoch=".." ver=".." rel=".."/>`; the epoch is
// always written, "0" included, as createrepo_c does.
func (o *xmlOut) version(indent string, p *rpm.Package) {
	o.open(indent, "version")
	o.raw(` epoch="`)
	o.u32(p.Epoch)
	o.raw(`"`)
	o.attr("ver", p.Version)
	o.attr("rel", p.Release)
	o.selfClose()
}

func (o *xmlOut) flush() {
	if o.err == nil && len(o.buf) > 0 {
		_, o.err = o.w.Write(o.buf)
	}

	o.buf = o.buf[:0]
}

func (o *xmlOut) flushIfFull() {
	if len(o.buf) >= flushThreshold {
		o.flush()
	}
}

func (o *xmlOut) finish() error {
	o.flush()

	return o.err
}

// appendText appends s escaped like libxml2 escapes the content of a text
// node: &, < and > and a carriage return become entities, a character that
// XML 1.0 does not allow (and invalid UTF-8) becomes U+FFFD, everything else,
// quotes and tabs included, is copied.
func appendText(dst []byte, s string) []byte {
	return appendEscaped(dst, s, false)
}

// appendAttrValue appends s escaped like libxml2 escapes an attribute value:
// the text escapes plus the double quote, the tab and the line feed.
func appendAttrValue(dst []byte, s string) []byte {
	return appendEscaped(dst, s, true)
}

func appendEscaped(dst []byte, s string, attr bool) []byte {
	last := 0

	for i := 0; i < len(s); {
		c := s[i]
		if c >= 0x20 && c < utf8.RuneSelf && c != '"' && c != '&' && c != '<' && c != '>' {
			i++
			continue
		}

		r, width := utf8.DecodeRuneInString(s[i:])

		esc, ok := xmlEscape(r, width, attr)
		if !ok {
			i += width
			continue
		}

		dst = append(dst, s[last:i]...)
		dst = append(dst, esc...)
		i += width
		last = i
	}

	return append(dst, s[last:]...)
}

// xmlEscape returns the replacement for r (decoded with the given width), or
// false when r is emitted unchanged.
func xmlEscape(r rune, width int, attr bool) (string, bool) {
	switch r {
	case '&':
		return "&amp;", true
	case '<':
		return "&lt;", true
	case '>':
		return "&gt;", true
	case '\r':
		return "&#13;", true
	case '"':
		if attr {
			return "&quot;", true
		}

		return "", false
	case '\n':
		if attr {
			return "&#10;", true
		}

		return "", false
	case '\t':
		if attr {
			return "&#9;", true
		}

		return "", false
	}

	if !isXMLChar(r) || (r == utf8.RuneError && width == 1) {
		return "\uFFFD", true
	}

	return "", false
}

// isXMLChar reports whether r is in the XML 1.0 Char production.
func isXMLChar(r rune) bool {
	return r == 0x09 || r == 0x0A || r == 0x0D ||
		r >= 0x20 && r <= 0xD7FF ||
		r >= 0xE000 && r <= 0xFFFD ||
		r >= 0x10000 && r <= 0x10FFFF
}

// DocKind selects which repodata document a DocWriter renders.
type DocKind int

const (
	// DocPrimary is primary.xml.
	DocPrimary DocKind = iota
	// DocFilelists is filelists.xml.
	DocFilelists
	// DocOther is other.xml.
	DocOther
	// DocFilelistsExt is filelists-ext.xml (createrepo_c --filelists-ext):
	// filelists.xml with the digest of every regular file.
	DocFilelistsExt
)

// Location is where a package is served from: Href relative to the
// repository, or to Base when set (createrepo_c --baseurl).
type Location struct {
	Href string
	Base string
}

// DocWriter streams one repodata document (primary, filelists, filelists-ext
// or other) package by package, for a caller that merges packages from several
// sources: rendered ones from the database (Package) and verbatim elements
// read from an another document (Raw). count is the number of packages the
// caller will write; it is the document's packages attribute.
type DocWriter struct {
	kind  DocKind
	o     *xmlOut
	rf    *requiresFilter
	limit int
}

// DefaultChangelogLimit is the number of changelog entries per package an
// other.xml document keeps, as createrepo_c does by default.
const DefaultChangelogLimit = 10

// SetChangelogLimit sets how many of the newest changelog entries of each
// package an other document keeps; zero or less keeps all of them.
func (d *DocWriter) SetChangelogLimit(n int) { d.limit = n }

// NewDocWriter writes the document header of kind to w.
func NewDocWriter(w io.Writer, kind DocKind, count int) *DocWriter {
	d := &DocWriter{kind: kind, o: newXMLOut(w), limit: DefaultChangelogLimit}

	d.o.raw(xmlHeader)

	switch kind {
	case DocPrimary:
		d.rf = newRequiresFilter()
		d.o.raw(`<metadata xmlns="` + nsCommon + `" xmlns:rpm="` + nsRPM + `" packages="`)
	case DocFilelists:
		d.o.raw(`<filelists xmlns="` + nsFilelists + `" packages="`)
	case DocFilelistsExt:
		d.o.raw(`<filelists-ext xmlns="` + nsFilelistsExt + `" packages="`)
	case DocOther:
		d.o.raw(`<otherdata xmlns="` + nsOther + `" packages="`)
	}

	d.o.i64(int64(count))
	d.o.raw(`">`)

	return d
}

// Package renders p into the document. A primary document lists it under
// [PackageLocation].
func (d *DocWriter) Package(p *rpm.Package) {
	d.PackageAt(p, Location{Href: PackageLocation(p)})
}

// PackageAt renders p into the document; loc is the location a primary
// document lists the package under and the other documents ignore.
func (d *DocWriter) PackageAt(p *rpm.Package, loc Location) {
	switch d.kind {
	case DocPrimary:
		writePrimaryPackage(d.o, d.rf, p, loc)
	case DocFilelists:
		writeFilelistsPackage(d.o, p, false)
	case DocFilelistsExt:
		writeFilelistsPackage(d.o, p, true)
	case DocOther:
		writeOtherPackage(d.o, p, d.limit)
	}

	d.o.flushIfFull()
}

// Raw appends an already serialized <package> element.
func (d *DocWriter) Raw(element []byte) {
	d.o.raw("\n")
	d.o.buf = append(d.o.buf, element...)
	d.o.flushIfFull()
}

// Close writes the closing tag and reports the first write error.
func (d *DocWriter) Close() error {
	d.o.raw("\n")

	switch d.kind {
	case DocPrimary:
		d.o.raw("</metadata>")
	case DocFilelists:
		d.o.raw("</filelists>")
	case DocFilelistsExt:
		d.o.raw("</filelists-ext>")
	case DocOther:
		d.o.raw("</otherdata>")
	}

	return d.o.finish()
}

// WritePrimaryXML streams primary.xml for packages to w.
func WritePrimaryXML(w io.Writer, packages []rpm.Package) error {
	return writeDocument(w, DocPrimary, packages)
}

func writeDocument(w io.Writer, kind DocKind, packages []rpm.Package) error {
	d := NewDocWriter(w, kind, len(packages))

	for i := range packages {
		d.Package(&packages[i])
	}

	return d.Close()
}

// PackageLocation is the href a package is listed under in primary.xml
// (and served from): Packages/<name>-<version>-<release>.<arch>.rpm.
func PackageLocation(p *rpm.Package) string {
	return "Packages/" + url.PathEscape(p.Name+"-"+p.Version+"-"+p.Release+"."+p.Arch+".rpm")
}

func writePrimaryPackage(o *xmlOut, rf *requiresFilter, p *rpm.Package, loc Location) {
	o.raw("\n<package type=\"rpm\">")
	o.elem("  ", "name", p.Name)
	o.elem("  ", "arch", p.Arch)
	o.version("  ", p)

	o.open("  ", "checksum")
	o.raw(` type="sha256" pkgid="YES">`)
	o.text(p.SHA256)
	o.closeTag("checksum")

	o.elem("  ", "summary", p.Summary)
	o.elem("  ", "description", p.Description)
	o.elem("  ", "packager", p.Packager)
	o.elem("  ", "url", p.URL)

	o.open("  ", "time")
	o.raw(` file="`)

	if p.FileTime > 0 {
		o.i64(p.FileTime)
	} else {
		o.i64(p.BuildTime)
	}

	o.raw(`" build="`)
	o.i64(p.BuildTime)
	o.raw(`"`)
	o.selfClose()

	o.open("  ", "size")
	o.raw(` package="`)
	o.i64(p.PackageSize)
	o.raw(`" installed="`)
	o.i64(p.InstalledSize)
	o.raw(`" archive="`)
	o.i64(p.ArchiveSize)
	o.raw(`"`)
	o.selfClose()

	// The element is lower-case: libdnf and createrepo_c only recognise
	// <location>, and cannot download a package listed under any other name.
	o.open("  ", "location")
	o.optAttr("xml:base", loc.Base)
	o.attr("href", loc.Href)
	o.selfClose()

	writePrimaryFormat(o, rf, p)

	o.raw("\n</package>")
}

func writePrimaryFormat(o *xmlOut, rf *requiresFilter, p *rpm.Package) {
	o.raw("\n  <format>")
	o.elem("    ", "rpm:license", p.License)
	o.elem("    ", "rpm:vendor", p.Vendor)
	o.elem("    ", "rpm:group", p.Group)
	o.elem("    ", "rpm:buildhost", p.BuildHost)
	o.elem("    ", "rpm:sourcerpm", p.SourceRPM)

	o.open("    ", "rpm:header-range")
	o.raw(` start="`)
	o.i64(p.HeaderStart)
	o.raw(`" end="`)
	o.i64(p.HeaderEnd)
	o.raw(`"`)
	o.selfClose()

	writeDepList(o, "rpm:provides", p.Provides, false)
	writeDepList(o, "rpm:requires", rf.filter(p), true)
	writeDepList(o, "rpm:conflicts", p.Conflicts, false)
	writeDepList(o, "rpm:obsoletes", p.Obsoletes, false)
	writeDepList(o, "rpm:suggests", p.Suggests, false)
	writeDepList(o, "rpm:enhances", p.Enhances, false)
	writeDepList(o, "rpm:recommends", p.Recommends, false)
	writeDepList(o, "rpm:supplements", p.Supplements, false)

	for j := range p.Files {
		if isPrimaryFile(p.Files[j].Path) {
			writeFile(o, "    ", &p.Files[j], false)
		}
	}

	o.raw("\n  </format>")
}

// writeDepList renders a dependency list the way createrepo_c does. When
// isRequires is set, rpmlib(...) features are skipped and script-time
// requirements carry pre="1". A list without an entry is not written.
func writeDepList(o *xmlOut, tag string, deps []rpm.Dependency, isRequires bool) {
	wrote := false

	for i := range deps {
		d := &deps[i]
		if isRequires && d.IsRPMLib() {
			continue
		}

		if !wrote {
			o.open("    ", tag)
			o.raw(">")

			wrote = true
		}

		o.open("      ", "rpm:entry")
		o.attr("name", d.Name)

		flags := rpm.SenseFlagsString(d.Flags)
		if flags != "" {
			ver, rel := rpm.SplitVersionRelease(d.Version)

			o.attr("flags", flags)
			o.raw(` epoch="`)
			o.u32(d.Epoch)
			o.raw(`"`)
			o.optAttr("ver", ver)
			o.optAttr("rel", rel)
		}

		if isRequires && isPre(*d) {
			o.raw(` pre="1"`)
		}

		o.selfClose()
	}

	if wrote {
		o.raw("\n    ")
		o.closeTag(tag)
	}
}

// WriteFilelistsXML streams filelists.xml for packages to w.
func WriteFilelistsXML(w io.Writer, packages []rpm.Package) error {
	return writeDocument(w, DocFilelists, packages)
}

// WriteFilelistsExtXML streams filelists-ext.xml, the filelists with the
// digest of each regular file, for packages to w.
func WriteFilelistsExtXML(w io.Writer, packages []rpm.Package) error {
	return writeDocument(w, DocFilelistsExt, packages)
}

func writeFilelistsPackage(o *xmlOut, p *rpm.Package, ext bool) {
	writePackageRef(o, p)

	if ext {
		o.open("  ", "checksum")
		o.attr("type", digestAlgorithm(p))
		o.selfClose()
	}

	for j := range p.Files {
		writeFile(o, "  ", &p.Files[j], ext)
	}

	o.raw("\n</package>")
}

// digestAlgorithm names the algorithm of the file digests of p, told by the
// length of the first one; sha256 when p has none, which is what createrepo_c
// writes.
func digestAlgorithm(p *rpm.Package) string {
	for i := range p.Files {
		switch len(p.Files[i].Digest) {
		case 0:
			continue
		case 32:
			return "md5"
		case 40:
			return "sha1"
		case 56:
			return "sha224"
		case 96:
			return "sha384"
		case 128:
			return "sha512"
		default:
			return "sha256"
		}
	}

	return "sha256"
}

// WriteOtherXML streams other.xml for packages to w.
func WriteOtherXML(w io.Writer, packages []rpm.Package) error {
	return writeDocument(w, DocOther, packages)
}

func writeOtherPackage(o *xmlOut, p *rpm.Package, limit int) {
	writePackageRef(o, p)

	// A header lists the changelog newest first; createrepo_c keeps the
	// newest limit entries and writes them oldest first.
	n := len(p.Changelogs)
	if limit > 0 && n > limit {
		n = limit
	}

	// Entries sharing a date are told apart by a second, as createrepo_c does.
	prev := int64(-1)

	for j := n - 1; j >= 0; j-- {
		cl := &p.Changelogs[j]

		date := cl.Time
		if date <= prev {
			date = prev + 1
		}

		prev = date

		o.open("  ", "changelog")
		o.attr("author", cl.Author)
		o.raw(` date="`)
		o.i64(date)
		o.raw(`">`)
		o.text(cl.Description)
		o.closeTag("changelog")
	}

	o.raw("\n</package>")
}

// writePackageRef opens a filelists/other <package> element and its <version>.
func writePackageRef(o *xmlOut, p *rpm.Package) {
	o.raw("\n<package")
	o.attr("pkgid", p.SHA256)
	o.attr("name", p.Name)
	o.attr("arch", p.Arch)
	o.raw(">")
	o.version("  ", p)
}

// writeFile writes a <file> element: the path, typed "dir" or "ghost" when it
// is one, and with its digest when withHash is set and the header has one.
func writeFile(o *xmlOut, indent string, f *rpm.FileEntry, withHash bool) {
	o.open(indent, "file")

	switch {
	case f.IsDir():
		o.raw(` type="dir"`)
	case f.IsGhost():
		o.raw(` type="ghost"`)
	case withHash:
		o.optAttr("hash", f.Digest)
	}

	o.raw(">")
	o.text(f.Path)
	o.closeTag("file")
}

// isPrimaryFile reports whether primary.xml lists the path: the files that
// are commonly depended upon (configuration, commands), the rest being in
// filelists.xml only.
func isPrimaryFile(p string) bool {
	return strings.HasPrefix(p, "/etc/") || p == "/usr/lib/sendmail" || strings.Contains(p, "bin/")
}
