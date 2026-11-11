package repodata

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrMalformedDeltaInfo means a prestodelta.xml document, or the value given
// to its writer, does not follow the format: the root element is not
// <prestodelta>, a required attribute or element is missing, or a number does
// not parse.
var ErrMalformedDeltaInfo = errors.New("repodata: malformed prestodelta.xml")

// Default limits of [ReadDeltaInfo].
const (
	// DefaultMaxDeltaPackages bounds the <newpackage> elements of a document.
	DefaultMaxDeltaPackages = 1 << 20
	// DefaultMaxDeltas bounds the <delta> elements of one <newpackage>.
	DefaultMaxDeltas = 10_000
	// DefaultMaxDeltaFieldBytes bounds one text value or attribute of a
	// document, such as a file name.
	DefaultMaxDeltaFieldBytes = 64 << 10
)

// DeltaChecksum is the digest of a delta rpm file and the name of its
// algorithm ("sha256" for the files createrepo_c writes by default).
type DeltaChecksum struct {
	Type  string
	Value string
}

// Delta is one <delta> element: a delta rpm that turns an older version of
// the package of its [DeltaPackage] into the new one.
type Delta struct {
	// Epoch, Version and Release identify the older version the delta is
	// applied to (the oldepoch, oldversion and oldrelease attributes).
	Epoch   uint32
	Version string
	Release string
	// Filename is the path of the .drpm file relative to the repository.
	Filename string
	// Sequence is the sequence text of the delta rpm as deltarpm records it:
	// the name-epoch:version-release of the old package, a dash and the hex
	// digest that applydeltarpm matches against the installed package, for
	// example "bash-0:5.2-1-1f8d0c...".
	Sequence string
	// Size is the size of the .drpm file and Checksum its digest.
	Size     int64
	Checksum DeltaChecksum
}

// DeltaPackage is a <newpackage> element: the package the deltas build, with
// the older versions they start from.
type DeltaPackage struct {
	Name    string
	Epoch   uint32
	Version string
	Release string
	Arch    string
	Deltas  []Delta
}

// DeltaInfo is a prestodelta.xml (deltainfo.xml) document: the delta rpms of
// a repository, grouped by the package they produce. Only the metadata is
// modelled; [DeltaInfo] neither reads nor creates the .drpm files. The
// Sequence of a delta, which deltarpm stores in the .drpm, is carried as the
// opaque text of the document, so a delta rpm made by makedeltarpm needs no
// further conversion to be listed.
type DeltaInfo struct {
	NewPackages []DeltaPackage
}

// DeltaInfoLimits bounds [ReadDeltaInfo] and [ParseDeltaInfo]. A zero field
// selects its default.
type DeltaInfoLimits struct {
	// MaxPackages bounds the <newpackage> elements of the document.
	MaxPackages int
	// MaxDeltas bounds the <delta> elements of one package.
	MaxDeltas int
	// MaxFieldBytes bounds one text value or attribute; a longer one fails
	// the read with [ErrTooLarge].
	MaxFieldBytes int
}

func (l DeltaInfoLimits) normalized() DeltaInfoLimits {
	if l.MaxPackages <= 0 {
		l.MaxPackages = DefaultMaxDeltaPackages
	}

	if l.MaxDeltas <= 0 {
		l.MaxDeltas = DefaultMaxDeltas
	}

	if l.MaxFieldBytes <= 0 {
		l.MaxFieldBytes = DefaultMaxDeltaFieldBytes
	}

	return l
}

func malformedDeltaInfo(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformedDeltaInfo, fmt.Sprintf(format, args...))
}

// ParseDeltaInfo reads a whole prestodelta.xml. It is [ReadDeltaInfo]
// collecting the packages; bound the decompressed size of r with
// [OpenMetadata].
func ParseDeltaInfo(r io.Reader, lim DeltaInfoLimits) (*DeltaInfo, error) {
	info := &DeltaInfo{}

	err := ReadDeltaInfo(r, lim, func(p *DeltaPackage) error {
		info.NewPackages = append(info.NewPackages, *p)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// ReadDeltaInfo decodes prestodelta.xml from r and calls fn for every
// <newpackage>, in document order. The package is only valid during the call.
//
// A document whose root is not <prestodelta>, a package without a name,
// version, release or architecture, a delta without an old version, file name,
// sequence or checksum, and a number that does not parse fail the read with
// [ErrMalformedDeltaInfo]; a limit exceeded fails it with [ErrTooLarge]; an
// error of fn stops the read and is returned as is. Elements and attributes
// that the format does not define are ignored. A missing epoch is 0.
func ReadDeltaInfo(r io.Reader, lim DeltaInfoLimits, fn func(*DeltaPackage) error) error {
	lim = lim.normalized()
	dec := xml.NewDecoder(r)

	var (
		sawRoot bool
		count   int
	)

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if !sawRoot {
				return malformedDeltaInfo("no <prestodelta> element")
			}

			return nil
		}

		if err != nil {
			return wrapDeltaXML(err)
		}

		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		if !sawRoot {
			if start.Name.Local != "prestodelta" {
				return malformedDeltaInfo("root element is <%s>, want <prestodelta>", start.Name.Local)
			}

			sawRoot = true

			continue
		}

		if start.Name.Local != "newpackage" {
			if err := dec.Skip(); err != nil {
				return wrapDeltaXML(err)
			}

			continue
		}

		if count++; count > lim.MaxPackages {
			return fmt.Errorf("%w: more than %d <newpackage> elements", ErrTooLarge, lim.MaxPackages)
		}

		pkg, err := readDeltaPackage(dec, start, lim)
		if err != nil {
			return err
		}

		if err := fn(pkg); err != nil {
			return err
		}
	}
}

func readDeltaPackage(dec *xml.Decoder, start xml.StartElement, lim DeltaInfoLimits) (*DeltaPackage, error) {
	pkg := &DeltaPackage{}

	for _, a := range start.Attr {
		if len(a.Value) > lim.MaxFieldBytes {
			return nil, fieldTooLarge("a <newpackage> attribute", lim.MaxFieldBytes)
		}

		switch a.Name.Local {
		case "name":
			pkg.Name = a.Value
		case "version":
			pkg.Version = a.Value
		case "release":
			pkg.Release = a.Value
		case "arch":
			pkg.Arch = a.Value
		case "epoch":
			e, err := parseDeltaEpoch(a.Value)
			if err != nil {
				return nil, err
			}

			pkg.Epoch = e
		}
	}

	if pkg.Name == "" || pkg.Version == "" || pkg.Release == "" || pkg.Arch == "" {
		return nil, malformedDeltaInfo("<newpackage> without name, version, release or arch")
	}

	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, wrapDeltaXML(err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local != "delta" {
				if err := dec.Skip(); err != nil {
					return nil, wrapDeltaXML(err)
				}

				continue
			}

			if len(pkg.Deltas) >= lim.MaxDeltas {
				return nil, fmt.Errorf("%w: more than %d <delta> elements in one <newpackage>", ErrTooLarge, lim.MaxDeltas)
			}

			d, err := readDelta(dec, t, lim)
			if err != nil {
				return nil, err
			}

			pkg.Deltas = append(pkg.Deltas, *d)
		case xml.EndElement:
			return pkg, nil
		}
	}
}

// wrapDeltaXML reports an error of the XML decoder or of readText as a
// malformed document; a limit exceeded keeps its [ErrTooLarge].
func wrapDeltaXML(err error) error {
	if errors.Is(err, ErrTooLarge) {
		return err
	}

	return fmt.Errorf("%w: %w", ErrMalformedDeltaInfo, err)
}

func fieldTooLarge(what string, limit int) error {
	return fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, what, limit)
}

func parseDeltaEpoch(s string) (uint32, error) {
	if s == "" {
		return 0, nil
	}

	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, malformedDeltaInfo("epoch %q is not a number", s)
	}

	return uint32(n), nil
}

func readDelta(dec *xml.Decoder, start xml.StartElement, lim DeltaInfoLimits) (*Delta, error) {
	d := &Delta{}

	for _, a := range start.Attr {
		if len(a.Value) > lim.MaxFieldBytes {
			return nil, fieldTooLarge("a <delta> attribute", lim.MaxFieldBytes)
		}

		switch a.Name.Local {
		case "oldversion":
			d.Version = a.Value
		case "oldrelease":
			d.Release = a.Value
		case "oldepoch":
			e, err := parseDeltaEpoch(a.Value)
			if err != nil {
				return nil, err
			}

			d.Epoch = e
		}
	}

	var (
		size    string
		sawSize bool
	)

	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, wrapDeltaXML(err)
		}

		t, ok := tok.(xml.StartElement)
		if !ok {
			if _, end := tok.(xml.EndElement); end {
				break
			}

			continue
		}

		var dst *string

		switch t.Name.Local {
		case "filename":
			dst = &d.Filename
		case "sequence":
			dst = &d.Sequence
		case "size":
			dst, sawSize = &size, true
		case "checksum":
			dst = &d.Checksum.Value
			d.Checksum.Type = attrOf(t.Attr, "type")
		}

		if dst == nil {
			if err := dec.Skip(); err != nil {
				return nil, wrapDeltaXML(err)
			}

			continue
		}

		text, err := readText(dec, lim.MaxFieldBytes, true)
		if err != nil {
			return nil, wrapDeltaXML(err)
		}

		*dst = text
	}

	if d.Version == "" || d.Release == "" {
		return nil, malformedDeltaInfo("<delta> without oldversion or oldrelease")
	}

	if d.Filename == "" || d.Sequence == "" || d.Checksum.Value == "" || d.Checksum.Type == "" {
		return nil, malformedDeltaInfo("<delta> %s-%s without filename, sequence or checksum", d.Version, d.Release)
	}

	if !sawSize {
		return nil, malformedDeltaInfo("<delta> %s without size", d.Filename)
	}

	n, err := strconv.ParseInt(size, 10, 64)
	if err != nil || n < 0 {
		return nil, malformedDeltaInfo("size %q of %s is not a number", size, d.Filename)
	}

	d.Size = n

	return d, nil
}

// readText reads the character data of the element the decoder just entered,
// up to its end tag, and returns it, trimmed of white space when trim is set;
// more than limit bytes fail with [ErrTooLarge]. Child elements are skipped and
// errors of the decoder are returned as they are.
func readText(dec *xml.Decoder, limit int, trim bool) (string, error) {
	var text strings.Builder

	depth := 0

	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}

		switch t := tok.(type) {
		case xml.CharData:
			if depth != 0 {
				continue
			}

			if text.Len()+len(t) > limit {
				return "", fieldTooLarge("a text value", limit)
			}

			text.Write(t)
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 {
				if trim {
					return strings.TrimSpace(text.String()), nil
				}

				return text.String(), nil
			}

			depth--
		}
	}
}

// DeltaInfoWriter streams a prestodelta.xml document package by package, with
// memory use independent of the number of packages. The layout is the one
// createrepo_c --deltas writes: a <newpackage> element at two spaces, its
// <delta> elements at four, their children at six, and no newline after the
// root's end tag.
type DeltaInfoWriter struct {
	o *xmlOut
}

// NewDeltaInfoWriter writes the document header to w.
func NewDeltaInfoWriter(w io.Writer) *DeltaInfoWriter {
	o := newXMLOut(w)
	o.raw(xmlHeader)
	o.raw("<prestodelta>")

	return &DeltaInfoWriter{o: o}
}

// Package writes p. A package without deltas is left out, as createrepo_c
// does; a package or delta missing a required field fails with
// [ErrMalformedDeltaInfo] and writes nothing.
func (w *DeltaInfoWriter) Package(p *DeltaPackage) error {
	if err := validateDeltaPackage(p); err != nil {
		return err
	}

	if len(p.Deltas) == 0 {
		return nil
	}

	o := w.o

	o.open("  ", "newpackage")
	o.attr("name", p.Name)
	o.raw(` epoch="`)
	o.u32(p.Epoch)
	o.raw(`"`)
	o.attr("version", p.Version)
	o.attr("release", p.Release)
	o.attr("arch", p.Arch)
	o.raw(">")

	for i := range p.Deltas {
		d := &p.Deltas[i]

		o.open("    ", "delta")
		o.raw(` oldepoch="`)
		o.u32(d.Epoch)
		o.raw(`"`)
		o.attr("oldversion", d.Version)
		o.attr("oldrelease", d.Release)
		o.raw(">")
		o.elem("      ", "filename", d.Filename)
		o.elem("      ", "sequence", d.Sequence)

		o.open("      ", "size")
		o.raw(">")
		o.i64(d.Size)
		o.closeTag("size")

		o.open("      ", "checksum")
		o.attr("type", d.Checksum.Type)
		o.raw(">")
		o.text(d.Checksum.Value)
		o.closeTag("checksum")

		o.raw("\n    ")
		o.closeTag("delta")
	}

	o.raw("\n  ")
	o.closeTag("newpackage")
	o.flushIfFull()

	return nil
}

// Close writes the end of the document and reports the first write error.
func (w *DeltaInfoWriter) Close() error {
	w.o.raw("\n")
	w.o.closeTag("prestodelta")

	return w.o.finish()
}

func validateDeltaPackage(p *DeltaPackage) error {
	if p.Name == "" || p.Version == "" || p.Release == "" || p.Arch == "" {
		return malformedDeltaInfo("package %q without name, version, release or arch", p.Name)
	}

	for i := range p.Deltas {
		d := &p.Deltas[i]

		switch {
		case d.Version == "" || d.Release == "":
			return malformedDeltaInfo("a delta of %s without old version or release", p.Name)
		case d.Filename == "" || d.Sequence == "":
			return malformedDeltaInfo("a delta of %s without file name or sequence", p.Name)
		case d.Checksum.Type == "" || d.Checksum.Value == "":
			return malformedDeltaInfo("delta %s without checksum", d.Filename)
		case d.Size < 0:
			return malformedDeltaInfo("delta %s with a negative size", d.Filename)
		}
	}

	return nil
}

// WriteDeltaInfoXML streams info as prestodelta.xml to w, byte for byte what
// createrepo_c --deltas writes for the same packages in the same order (it
// lists them in hash-table order, which no reader relies on).
func WriteDeltaInfoXML(w io.Writer, info *DeltaInfo) error {
	dw := NewDeltaInfoWriter(w)

	for i := range info.NewPackages {
		if err := dw.Package(&info.NewPackages[i]); err != nil {
			return err
		}
	}

	return dw.Close()
}
