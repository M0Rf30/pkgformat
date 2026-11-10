package deb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// MaxLineBytes bounds one line of a deb822 document; a hostile index could
	// otherwise send one enormous line.
	MaxLineBytes = 4 << 20
	// MaxParagraphBytes bounds one paragraph (one package entry).
	MaxParagraphBytes = 16 << 20
)

// ControlFile is one deb822 paragraph: a binary package's control file, a
// Packages or dpkg status entry. Field names are matched case-insensitively
// (apt does), values are logical: the single space or tab that introduces a
// continuation line is removed and a " ." line is an empty line.
type ControlFile struct {
	// Fields maps a field name, as written in the document, to its value.
	Fields map[string]string
	// Order lists the field names in document order.
	Order []string
}

// NewControlFile returns an empty paragraph.
func NewControlFile() *ControlFile {
	return &ControlFile{Fields: make(map[string]string)}
}

// ParseControlFile parses the first paragraph of a deb822 document, such as
// the control file of a package. Unlike ScanControl it is strict: a line that
// is not a field, a continuation or a comment fails with ErrInvalidControlFormat.
func ParseControlFile(r io.Reader) (*ControlFile, error) {
	var cf *ControlFile

	err := scanParagraphs(r, func(text string) error {
		var perr error

		cf, perr = parseParagraph(text, true)
		if perr != nil {
			return perr
		}

		return errStopScan
	})
	if err != nil && !errors.Is(err, errStopScan) {
		return nil, err
	}

	if cf == nil {
		return NewControlFile(), nil
	}

	return cf, nil
}

// ScanControl calls fn for every paragraph of a deb822 document (an apt
// Packages index, a dpkg status file) in order. It is lenient: a line that is
// not a field is skipped, and a paragraph without fields is not reported. An
// error from fn stops the scan and is returned as is.
func ScanControl(r io.Reader, fn func(*ControlFile) error) error {
	return scanParagraphs(r, func(text string) error {
		cf, err := parseParagraph(text, false)
		if err != nil {
			return err
		}

		if len(cf.Order) == 0 {
			return nil
		}

		return fn(cf)
	})
}

// Get returns the value of a field, or "" when it is absent.
func (cf *ControlFile) Get(field string) string {
	v, _ := cf.Lookup(field)

	return v
}

// Lookup returns the value of a field and whether it is present. The exact
// spelling is tried first, then any case variant.
func (cf *ControlFile) Lookup(field string) (string, bool) {
	if v, ok := cf.Fields[field]; ok {
		return v, true
	}

	for _, name := range cf.Order {
		if strings.EqualFold(name, field) {
			return cf.Fields[name], true
		}
	}

	return "", false
}

// GetRequired returns the value of a field that must be present and not empty.
func (cf *ControlFile) GetRequired(field string) (string, error) {
	value, ok := cf.Lookup(field)
	if !ok || value == "" {
		return "", fmt.Errorf("%w: %q", ErrMissingRequiredField, field)
	}

	return value, nil
}

// Set sets a field, replacing the value of any case variant of the name in
// place, or appending the field.
func (cf *ControlFile) Set(field, value string) {
	if cf.Fields == nil {
		cf.Fields = make(map[string]string)
	}

	for _, name := range cf.Order {
		if strings.EqualFold(name, field) {
			cf.Fields[name] = value

			return
		}
	}

	cf.Fields[field] = value
	cf.Order = append(cf.Order, field)
}

// String renders the paragraph in document order, ending with a newline, and
// no blank line.
func (cf *ControlFile) String() string {
	var sb strings.Builder

	for _, name := range cf.Order {
		writeField(&sb, name, cf.Fields[name])
	}

	return sb.String()
}

// writeField writes "Name: value\n", encoding the continuation lines of a
// multi-line value.
func writeField(sb *strings.Builder, name, value string) {
	sb.WriteString(name)
	sb.WriteString(":")

	first, rest, multi := strings.Cut(value, "\n")
	if first != "" {
		sb.WriteString(" ")
		sb.WriteString(first)
	}

	sb.WriteString("\n")

	for multi {
		var line string

		line, rest, multi = strings.Cut(rest, "\n")

		if strings.TrimSpace(line) == "" {
			sb.WriteString(" .\n")

			continue
		}

		sb.WriteString(" ")
		sb.WriteString(line)
		sb.WriteString("\n")
	}
}

// errStopScan ends a scan early without being an error.
var errStopScan = errors.New("deb: stop scan")

// scanParagraphs splits r into paragraphs, separated by blank lines, and calls
// fn with the text of each (lines joined by "\n", comments dropped, one
// trailing newline). A scan that hits a size limit fails with ErrTooLarge.
func scanParagraphs(r io.Reader, fn func(text string) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineBytes)

	var sb strings.Builder

	flush := func() error {
		if sb.Len() == 0 {
			return nil
		}

		text := sb.String()

		sb.Reset()

		return fn(text)
	}

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")

		if strings.TrimSpace(line) == "" {
			if err := flush(); err != nil {
				return err
			}

			continue
		}

		if line[0] == '#' {
			continue
		}

		if sb.Len()+len(line)+1 > MaxParagraphBytes {
			return fmt.Errorf("%w: paragraph over %d bytes", ErrTooLarge, MaxParagraphBytes)
		}

		sb.WriteString(line)
		sb.WriteByte('\n')
	}

	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("%w: line over %d bytes", ErrTooLarge, MaxLineBytes)
		}

		return fmt.Errorf("deb: reading control data: %w", err)
	}

	return flush()
}

// trimValue strips the blanks around a field value. A newline in front of the
// first line is kept: "Conffiles:" followed by one entry per continuation line
// has an empty first line, and rendering the value must not fold the first
// entry up to the field name.
func trimValue(v string) string {
	return strings.TrimRight(strings.TrimLeft(v, " \t"), " \t\r\n")
}

// parseParagraph builds a ControlFile from the text of one paragraph.
func parseParagraph(text string, strict bool) (*ControlFile, error) {
	cf := NewControlFile()

	var (
		field string
		value strings.Builder
	)

	flush := func() {
		if field == "" {
			return
		}

		if _, dup := cf.Fields[field]; !dup {
			cf.Order = append(cf.Order, field)
		}

		cf.Fields[field] = trimValue(value.String())

		field = ""

		value.Reset()
	}

	for line := range strings.SplitSeq(text, "\n") {
		if line == "" {
			continue
		}

		if line[0] == ' ' || line[0] == '\t' {
			if field == "" {
				if strict {
					return nil, fmt.Errorf("%w: continuation line without a field: %q", ErrInvalidControlFormat, line)
				}

				continue
			}

			value.WriteByte('\n')

			if line != " ." {
				value.WriteString(line[1:])
			}

			continue
		}

		name, v, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)

		if !ok || name == "" {
			if strict {
				return nil, fmt.Errorf("%w: %q", ErrInvalidControlFormat, line)
			}

			continue
		}

		flush()

		field = name

		value.WriteString(strings.TrimSpace(v))
	}

	flush()

	return cf, nil
}

// Package holds the fields of a binary package that repositories and
// installers care about, read from a control file or a Packages entry.
type Package struct {
	Package       string
	Version       string
	Architecture  string
	Maintainer    string
	Description   string
	Depends       string
	PreDepends    string
	Recommends    string
	Suggests      string
	Enhances      string
	Conflicts     string
	Breaks        string
	Replaces      string
	Provides      string
	Section       string
	Priority      string
	Homepage      string
	Bugs          string
	Size          int64
	InstalledSize int64
	MD5sum        string
	SHA1          string
	SHA256        string
	SHA512        string
	Filename      string
	Source        string
	SourceVersion string
	Essential     bool
	MultiArch     string
	BuiltUsing    string
	// Custom holds every field not listed above, by its spelling in the document.
	Custom map[string]string
}

// ParsePackage extracts the package fields. Package, Version and Architecture
// are required.
func (cf *ControlFile) ParsePackage() (*Package, error) {
	for _, field := range [...]string{"Package", "Version", "Architecture"} {
		if _, err := cf.GetRequired(field); err != nil {
			return nil, err
		}
	}

	return cf.parsePackage(), nil
}

// parsePackage extracts the package fields without requiring any: the
// required ones are what the paragraph holds, possibly empty.
func (cf *ControlFile) parsePackage() *Package {
	pkg := &Package{
		Package:      cf.Get("Package"),
		Version:      cf.Get("Version"),
		Architecture: cf.Get("Architecture"),
		Custom:       make(map[string]string),
	}

	for _, name := range cf.Order {
		value := cf.Fields[name]

		if !pkg.setField(name, value) {
			pkg.Custom[name] = value
		}
	}

	return pkg
}

// setField stores a known field and reports whether name was one.
func (p *Package) setField(name, value string) bool {
	switch strings.ToLower(name) {
	case "package", "version", "architecture":
		// Required fields are set by ParsePackage.
	case "maintainer":
		p.Maintainer = value
	case "description":
		p.Description = value
	case "depends":
		p.Depends = value
	case "pre-depends":
		p.PreDepends = value
	case "recommends":
		p.Recommends = value
	case "suggests":
		p.Suggests = value
	case "enhances":
		p.Enhances = value
	case "conflicts":
		p.Conflicts = value
	case "breaks":
		p.Breaks = value
	case "replaces":
		p.Replaces = value
	case "provides":
		p.Provides = value
	case "section":
		p.Section = value
	case "priority":
		p.Priority = value
	case "homepage":
		p.Homepage = value
	case "bugs":
		p.Bugs = value
	case "size":
		p.Size = parseSize(value)
	case "installed-size":
		p.InstalledSize = parseSize(value)
	case "md5sum":
		p.MD5sum = value
	case "sha1":
		p.SHA1 = value
	case "sha256":
		p.SHA256 = value
	case "sha512":
		p.SHA512 = value
	case "filename":
		p.Filename = value
	case "source":
		p.Source = value
	case "source-version":
		p.SourceVersion = value
	case "essential":
		p.Essential = strings.EqualFold(value, "yes")
	case "multi-arch":
		p.MultiArch = value
	case "built-using":
		p.BuiltUsing = value
	default:
		return false
	}

	return true
}

// parseSize parses a size field; a value that is not a number, or does not fit
// in an int64, is 0.
func parseSize(value string) int64 {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}

	return n
}
