package repodata

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/pathseg"
)

// PackageInfo identifies a <package> element of a primary, filelists
// or other document. Filelists and other documents carry no checksum element
// but the pkgid attribute; primary carries the location.
type PackageInfo struct {
	Name  string
	Arch  string
	Epoch string
	Ver   string
	Rel   string
	// PkgID is the package checksum (primary: the checksum element, filelists
	// and other: the pkgid attribute).
	PkgID string
	// Href is the package location of a primary element.
	Href string
}

// NEVRA is the identity two sources' packages collide on.
func (i PackageInfo) NEVRA() string {
	return PackageNEVRA(i.Name, i.Epoch, i.Ver, i.Rel, i.Arch)
}

// errTruncatedDocument reports an XML document that ends inside an element.
var errTruncatedDocument = errors.New("repodata: parsing metadata: document ends inside an element")

// ScanPackages reads the <package> elements of a primary, filelists or other
// document in order. When withElement is set fn also receives the element
// serialized (without the xml:base attribute of a location, which would send a
// client to another host); the slice is only valid during the call.
func ScanPackages(r io.Reader, withElement bool, fn func(info PackageInfo, element []byte) error) error {
	d := xml.NewDecoder(r)
	s := packageScanner{withElement: withElement}

	for {
		tok, err := d.RawToken()
		if errors.Is(err, io.EOF) {
			if s.depth != 0 {
				return errTruncatedDocument
			}

			return nil
		}

		if err != nil {
			return fmt.Errorf("repodata: parsing metadata: %w", err)
		}

		done, err := s.token(tok)
		if err != nil {
			return err
		}

		if done {
			s.info.Name, s.info.Arch = strings.TrimSpace(s.info.Name), strings.TrimSpace(s.info.Arch)
			s.info.PkgID = strings.TrimSpace(s.info.PkgID)

			if err := fn(s.info, s.out.Bytes()); err != nil {
				return err
			}

			s.reset()
		}
	}
}

// packageScanner walks the RawToken stream; depth 1 is the document root, so a
// <package> starts at depth 2.
type packageScanner struct {
	withElement bool

	depth   int
	inPkg   bool
	pkgBase int // depth at which the current package started
	info    PackageInfo
	out     bytes.Buffer
	scratch []byte
	capture *string // text sink of a leaf child being read
}

func (s *packageScanner) reset() {
	s.inPkg, s.capture = false, nil
	s.info = PackageInfo{}

	s.out.Reset()
}

func (s *packageScanner) token(tok xml.Token) (bool, error) {
	switch t := tok.(type) {
	case xml.StartElement:
		s.depth++

		if !s.inPkg {
			if s.depth == 2 && t.Name.Space == "" && t.Name.Local == "package" {
				s.inPkg, s.pkgBase = true, s.depth
				s.startPackage(t)
				s.writeStart(t)
			}

			return false, nil
		}

		if s.depth == s.pkgBase+1 && t.Name.Space == "" {
			s.child(t)
		}

		s.writeStart(t)
	case xml.EndElement:
		defer func() { s.depth-- }()

		if !s.inPkg {
			return false, nil
		}

		s.capture = nil

		s.writeEnd(t)

		return s.depth == s.pkgBase, nil
	case xml.CharData:
		if !s.inPkg {
			return false, nil
		}

		if s.capture != nil {
			*s.capture += string(t)
		}

		if s.withElement {
			s.scratch = appendText(s.scratch[:0], string(t))
			s.out.Write(s.scratch)
		}
	}

	return false, nil
}

func (s *packageScanner) startPackage(t xml.StartElement) {
	for _, a := range t.Attr {
		if a.Name.Space != "" {
			continue
		}

		switch a.Name.Local {
		case "pkgid":
			s.info.PkgID = a.Value
		case "name":
			s.info.Name = a.Value
		case "arch":
			s.info.Arch = a.Value
		}
	}
}

// child records the identifying direct children of a <package>.
func (s *packageScanner) child(t xml.StartElement) {
	switch strings.ToLower(t.Name.Local) {
	case "name":
		s.capture = &s.info.Name
	case "arch":
		s.capture = &s.info.Arch
	case "checksum":
		s.info.PkgID = ""
		s.capture = &s.info.PkgID
	case "version":
		for _, a := range t.Attr {
			switch a.Name.Local {
			case "epoch":
				s.info.Epoch = a.Value
			case "ver":
				s.info.Ver = a.Value
			case "rel":
				s.info.Rel = a.Value
			}
		}
	case "location":
		for _, a := range t.Attr {
			if a.Name.Space == "" && a.Name.Local == "href" {
				s.info.Href = a.Value
			}
		}
	}
}

func (s *packageScanner) writeStart(t xml.StartElement) {
	if !s.withElement {
		return
	}

	s.out.WriteByte('<')
	s.out.WriteString(qname(t.Name))

	for _, a := range t.Attr {
		if a.Name.Space == "xml" && a.Name.Local == "base" {
			continue
		}

		s.out.WriteByte(' ')
		s.out.WriteString(qname(a.Name))
		s.out.WriteString(`="`)
		s.scratch = appendAttrValue(s.scratch[:0], a.Value)
		s.out.Write(s.scratch)
		s.out.WriteByte('"')
	}

	s.out.WriteByte('>')
}

func (s *packageScanner) writeEnd(t xml.EndElement) {
	if !s.withElement {
		return
	}

	s.out.WriteString("</")
	s.out.WriteString(qname(t.Name))
	s.out.WriteByte('>')
}

func qname(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}

	return n.Space + ":" + n.Local
}

// SafeLocation cleans a package href and decodes its percent-escapes into the
// repository-relative path it is served from. ok is false for a location that
// is absolute or leaves the repository.
func SafeLocation(href string) (string, bool) {
	p, err := url.PathUnescape(href)
	if err != nil || p == "" {
		return "", false
	}

	// Clean folds the "." and ".." segments a href may carry; what is left must
	// be a relative path of plain segments (it is "." for an empty result, "..x"
	// or an absolute path when the href leaves the repository).
	p = path.Clean(p)
	if !pathseg.Path(p) {
		return "", false
	}

	return p, true
}
