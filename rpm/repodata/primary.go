package repodata

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// Default limits of [ReadPrimary].
const (
	// DefaultMaxDependencies bounds each dependency list of a package.
	DefaultMaxDependencies = 100_000
	// DefaultMaxFiles bounds the <file> entries of a package.
	DefaultMaxFiles = 100_000
	// DefaultMaxFieldBytes bounds one text field of a package, such as the
	// description.
	DefaultMaxFieldBytes = 1 << 20
	// DefaultMaxFileBytes bounds the total size of the <file> paths of a
	// package.
	DefaultMaxFileBytes = 16 << 20
)

// PrimaryPackage is a <package> element of primary.xml.
type PrimaryPackage struct {
	// Package holds the identity, sizes, dependencies and the <file> paths
	// that primary.xml lists. SHA256 is set when the checksum type is sha256.
	rpm.Package
	// Location is the href of the .rpm file relative to the repository (or
	// to Base) and Base the optional xml:base of the location.
	Location string
	Base     string
	// Checksum is the digest of the .rpm file and ChecksumType its
	// algorithm.
	Checksum     string
	ChecksumType string
}

// PrimaryLimits bounds [ReadPrimary]. A zero field selects its default.
type PrimaryLimits struct {
	// MaxDependencies bounds each dependency list; a longer one fails the
	// read with [ErrTooLarge].
	MaxDependencies int
	// MaxFiles bounds the <file> entries of a package; a package with more
	// fails the read with [ErrTooLarge].
	MaxFiles int
	// MaxFileBytes bounds the total size of the <file> paths of a package.
	MaxFileBytes int
	// MaxFieldBytes bounds one text field of a package.
	MaxFieldBytes int
}

func (l PrimaryLimits) normalized() PrimaryLimits {
	if l.MaxDependencies <= 0 {
		l.MaxDependencies = DefaultMaxDependencies
	}

	if l.MaxFiles <= 0 {
		l.MaxFiles = DefaultMaxFiles
	}

	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = DefaultMaxFileBytes
	}

	if l.MaxFieldBytes <= 0 {
		l.MaxFieldBytes = DefaultMaxFieldBytes
	}

	return l
}

// ReadPrimary decodes primary.xml from r and calls fn for every package. A
// package without a name or an architecture, or with a malformed number, is
// skipped; malformed XML, a limit exceeded ([ErrTooLarge]) or an error of fn
// stops the read and is returned. Bound the decompressed size of r with
// [OpenMetadata].
func ReadPrimary(r io.Reader, lim PrimaryLimits, fn func(*PrimaryPackage) error) error {
	lim = lim.normalized()
	dec := xml.NewDecoder(r)

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("repodata: parsing primary.xml: %w", err)
		}

		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "package" {
			continue
		}

		pkg, valid, err := readPrimaryPackage(dec, start, lim)
		if err != nil {
			return err
		}

		if !valid || pkg.Name == "" || pkg.Arch == "" {
			continue
		}

		if err := fn(pkg); err != nil {
			return err
		}
	}
}

// primaryReader accumulates one <package> element.
type primaryReader struct {
	lim   PrimaryLimits
	pkg   PrimaryPackage
	valid bool
	// fileBytes is the total size of the <file> paths read.
	fileBytes int
}

func readPrimaryPackage(dec *xml.Decoder, start xml.StartElement, lim PrimaryLimits) (*PrimaryPackage, bool, error) {
	pr := &primaryReader{lim: lim, valid: true}
	// path holds the names of the open elements below <package>.
	var (
		path []string
		text strings.Builder
	)

	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, false, fmt.Errorf("repodata: parsing primary.xml: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			text.Reset()

			if err := pr.open(path, t.Attr); err != nil {
				return nil, false, err
			}
		case xml.CharData:
			if text.Len()+len(t) > lim.MaxFieldBytes {
				return nil, false, fmt.Errorf("%w: a text field of a package exceeds %d bytes", ErrTooLarge, lim.MaxFieldBytes)
			}

			text.Write(t)
		case xml.EndElement:
			if len(path) == 0 {
				return &pr.pkg, pr.valid, nil
			}

			if err := pr.close(path, text.String()); err != nil {
				return nil, false, err
			}

			path = path[:len(path)-1]
			text.Reset()
		}
	}
}

// listTarget returns the dependency list a <format>/<rpm:xxx> element holds.
func (pr *primaryReader) listTarget(name string) *[]rpm.Dependency {
	switch name {
	case "provides":
		return &pr.pkg.Provides
	case "requires":
		return &pr.pkg.Requires
	case "conflicts":
		return &pr.pkg.Conflicts
	case "obsoletes":
		return &pr.pkg.Obsoletes
	case "recommends":
		return &pr.pkg.Recommends
	case "suggests":
		return &pr.pkg.Suggests
	case "supplements":
		return &pr.pkg.Supplements
	case "enhances":
		return &pr.pkg.Enhances
	}

	return nil
}

func attrOf(attrs []xml.Attr, local string) string {
	for _, a := range attrs {
		if a.Name.Local == local {
			return a.Value
		}
	}

	return ""
}

func (pr *primaryReader) number(s string) int64 {
	if s == "" {
		return 0
	}

	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		pr.valid = false

		return 0
	}

	return n
}

// open handles the attributes of an element that has just started.
func (pr *primaryReader) open(path []string, attrs []xml.Attr) error {
	switch {
	case len(path) == 1:
		pr.openChild(path[0], attrs)
	case len(path) == 2 && path[0] == "format":
		if path[1] == "header-range" {
			pr.pkg.HeaderStart = pr.number(attrOf(attrs, "start"))
			pr.pkg.HeaderEnd = pr.number(attrOf(attrs, "end"))
		}
	case len(path) == 3 && path[0] == "format" && path[2] == "entry":
		return pr.openEntry(path[1], attrs)
	}

	return nil
}

func (pr *primaryReader) openChild(name string, attrs []xml.Attr) {
	switch name {
	case "version":
		epoch := attrOf(attrs, "epoch")
		if epoch != "" {
			n, err := strconv.ParseUint(epoch, 10, 32)
			if err != nil {
				pr.valid = false
			}

			pr.pkg.Epoch = uint32(n)
		}

		pr.pkg.Version = attrOf(attrs, "ver")
		pr.pkg.Release = attrOf(attrs, "rel")
	case "checksum":
		pr.pkg.ChecksumType = attrOf(attrs, "type")
	case "time":
		pr.pkg.FileTime = pr.number(attrOf(attrs, "file"))
		pr.pkg.BuildTime = pr.number(attrOf(attrs, "build"))
	case "size":
		pr.pkg.PackageSize = pr.number(attrOf(attrs, "package"))
		pr.pkg.InstalledSize = pr.number(attrOf(attrs, "installed"))
		pr.pkg.ArchiveSize = pr.number(attrOf(attrs, "archive"))
	case "location":
		pr.pkg.Location = attrOf(attrs, "href")
		pr.pkg.Base = attrOf(attrs, "base")
	}
}

func (pr *primaryReader) openEntry(list string, attrs []xml.Attr) error {
	target := pr.listTarget(list)
	if target == nil {
		return nil
	}

	if len(*target) >= pr.lim.MaxDependencies {
		return fmt.Errorf("%w: a dependency list of a package exceeds %d entries", ErrTooLarge, pr.lim.MaxDependencies)
	}

	dep := rpm.Dependency{Name: attrOf(attrs, "name"), Version: attrOf(attrs, "ver")}

	if rel := attrOf(attrs, "rel"); rel != "" {
		dep.Version += "-" + rel
	}

	if epoch := attrOf(attrs, "epoch"); epoch != "" {
		n, err := strconv.ParseUint(epoch, 10, 32)
		if err != nil {
			pr.valid = false
		}

		dep.Epoch = uint32(n)
	}

	switch attrOf(attrs, "flags") {
	case "LT":
		dep.Flags = tag.RPMSENSE_LESS
	case "GT":
		dep.Flags = tag.RPMSENSE_GREATER
	case "EQ":
		dep.Flags = tag.RPMSENSE_EQUAL
	case "LE":
		dep.Flags = tag.RPMSENSE_LESS | tag.RPMSENSE_EQUAL
	case "GE":
		dep.Flags = tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL
	}

	if pre := attrOf(attrs, "pre"); pre == "1" || pre == "true" {
		dep.Flags |= tag.RPMSENSE_PREREQ
	}

	if strings.HasPrefix(dep.Name, "rpmlib(") {
		dep.Flags |= tag.RPMSENSE_RPMLIB
	}

	*target = append(*target, dep)

	return nil
}

// close handles the text of an element that has just ended.
func (pr *primaryReader) close(path []string, text string) error {
	switch {
	case len(path) == 1:
		switch path[0] {
		case "name":
			pr.pkg.Name = strings.TrimSpace(text)
		case "arch":
			pr.pkg.Arch = strings.TrimSpace(text)
		case "summary":
			pr.pkg.Summary = text
		case "description":
			pr.pkg.Description = text
		case "packager":
			pr.pkg.Packager = text
		case "url":
			pr.pkg.URL = strings.TrimSpace(text)
		case "checksum":
			pr.pkg.Checksum = strings.TrimSpace(text)

			if strings.EqualFold(pr.pkg.ChecksumType, "sha256") {
				pr.pkg.SHA256 = pr.pkg.Checksum
			}
		}
	case len(path) == 2 && path[0] == "format":
		switch path[1] {
		case "license":
			pr.pkg.License = text
		case "vendor":
			pr.pkg.Vendor = text
		case "group":
			pr.pkg.Group = text
		case "buildhost":
			pr.pkg.BuildHost = text
		case "sourcerpm":
			pr.pkg.SourceRPM = text
		case "file":
			return pr.addFile(text)
		}
	}

	return nil
}

func (pr *primaryReader) addFile(p string) error {
	if p == "" {
		return nil
	}

	pr.fileBytes += len(p)
	if len(pr.pkg.Files) >= pr.lim.MaxFiles || pr.fileBytes > pr.lim.MaxFileBytes {
		return fmt.Errorf("%w: the file list of a package exceeds %d entries or %d bytes",
			ErrTooLarge, pr.lim.MaxFiles, pr.lim.MaxFileBytes)
	}

	pr.pkg.Files = append(pr.pkg.Files, rpm.FileEntry{Path: p})

	return nil
}
