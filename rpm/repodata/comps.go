package repodata

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// Package types of a comps group, as dnf reads them.
const (
	CompsMandatory   = "mandatory"
	CompsDefault     = "default"
	CompsOptional    = "optional"
	CompsConditional = "conditional"
)

// maxCompsSize bounds a comps document read by [ValidateCompsXML].
const maxCompsSize = 256 << 20

// CompsGroup is a package group of comps.xml.
type CompsGroup struct {
	ID          string
	Name        string
	Description string
	Default     bool
	UserVisible bool
	Packages    []CompsPackage
}

// CompsCategory is a category of comps.xml: a list of groups.
type CompsCategory struct {
	ID          string
	Name        string
	Description string
	GroupIDs    []string
}

// CompsPackage is a package of a group.
type CompsPackage struct {
	Name string
	// Type is one of the Comps* constants; empty means [CompsDefault].
	Type string
	// Condition is the package a conditional package requires.
	Condition string
}

// Comps is the content of a comps.xml: the groups and categories of a
// repository.
type Comps struct {
	Groups     []CompsGroup
	Categories []CompsCategory
}

// ValidateCompsXML reports whether data is well-formed XML.
func ValidateCompsXML(data []byte) error {
	decoder := xml.NewDecoder(limitio.Capped(bytes.NewReader(data), maxCompsSize+1, ErrTooLarge))

	for {
		_, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("repodata: invalid comps XML: %w", err)
		}
	}
}

// WriteCompsXML writes c as comps.xml to w, the file the "group" data entry of
// repomd.xml points at.
func WriteCompsXML(w io.Writer, c *Comps) error {
	o := newXMLOut(w)

	o.raw(xmlHeader)
	o.raw("<comps>")

	for i := range c.Groups {
		g := &c.Groups[i]

		o.raw("\n  <group>")
		o.elem("    ", "id", g.ID)
		o.elem("    ", "name", g.Name)
		o.optElem("    ", "description", g.Description)
		o.elem("    ", "default", boolText(g.Default))
		o.elem("    ", "uservisible", boolText(g.UserVisible))
		o.raw("\n    <packagelist>")

		for j := range g.Packages {
			p := &g.Packages[j]

			typ := p.Type
			if typ == "" {
				typ = CompsDefault
			}

			o.open("      ", "packagereq")
			o.attr("type", typ)
			o.optAttr("requires", p.Condition)
			o.raw(">")
			o.text(p.Name)
			o.closeTag("packagereq")
		}

		o.raw("\n    </packagelist>\n  </group>")
		o.flushIfFull()
	}

	for i := range c.Categories {
		cat := &c.Categories[i]

		o.raw("\n  <category>")
		o.elem("    ", "id", cat.ID)
		o.elem("    ", "name", cat.Name)
		o.optElem("    ", "description", cat.Description)
		o.raw("\n    <grouplist>")

		for _, id := range cat.GroupIDs {
			o.elem("      ", "groupid", id)
		}

		o.raw("\n    </grouplist>\n  </category>")
		o.flushIfFull()
	}

	o.raw("\n</comps>\n")

	return o.finish()
}

func boolText(b bool) string {
	if b {
		return "true"
	}

	return "false"
}
