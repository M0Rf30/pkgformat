package source

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
)

// MaxDocumentBytes bounds a .dsc, .changes or .buildinfo file.
const MaxDocumentBytes = 16 << 20

const clearsignHeader = "-----BEGIN PGP SIGNED MESSAGE-----"

// Field is a deb822 field the typed structs do not model: it is kept so a
// document survives a parse and a write.
type Field struct {
	Name  string
	Value string
}

// FileRef is one file listed by a document, with the digests it carries. A
// digest that the document does not list is empty.
type FileRef struct {
	Name   string
	Size   int64
	MD5    string
	SHA1   string
	SHA256 string
	SHA512 string
	// Section and Priority are the extra columns of the Files field of a
	// .changes file; they are empty in a .dsc.
	Section  string
	Priority string
}

// isClearsigned reports whether data starts with a clear-signed wrapper.
func isClearsigned(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, "\r\n \t"), []byte(clearsignHeader))
}

// openDocument unwraps an optional clear-signed wrapper without verifying it
// and parses the first paragraph.
func openDocument(data []byte) (*deb.ControlFile, bool, error) {
	if len(data) > MaxDocumentBytes {
		return nil, false, fmt.Errorf("%w: document of %d bytes", ErrTooLarge, len(data))
	}

	signed := isClearsigned(data)
	if signed {
		data = deb.StripClearsign(bytes.TrimLeft(data, "\r\n \t"))
	}

	cf, err := deb.ParseControlFile(bytes.NewReader(data))
	if err != nil {
		return nil, signed, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	return cf, signed, nil
}

// openVerified verifies the clear-signed wrapper against kr and parses the
// body.
func openVerified(data []byte, kr *gpg.Keyring) (*deb.ControlFile, gpg.Verified, error) {
	if len(data) > MaxDocumentBytes {
		return nil, gpg.Verified{}, fmt.Errorf("%w: document of %d bytes", ErrTooLarge, len(data))
	}

	if !isClearsigned(data) {
		return nil, gpg.Verified{}, ErrNotSigned
	}

	body, who, err := gpg.VerifyClearsigned(kr, bytes.TrimLeft(data, "\r\n \t"))
	if err != nil {
		return nil, gpg.Verified{}, err
	}

	cf, err := deb.ParseControlFile(bytes.NewReader(body))
	if err != nil {
		return nil, gpg.Verified{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	return cf, who, nil
}

// splitList splits a comma separated field ("a, b") into its trimmed items;
// line breaks are separators too.
func splitList(v string) []string {
	var out []string

	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}

	return out
}

// splitWords splits a whitespace separated field.
func splitWords(v string) []string { return strings.Fields(v) }

// unknownFields returns the fields of cf that are not in known, in document
// order. known holds lower-case names.
func unknownFields(cf *deb.ControlFile, known map[string]bool) []Field {
	var out []Field

	for _, name := range cf.Order {
		if known[strings.ToLower(name)] {
			continue
		}

		out = append(out, Field{Name: name, Value: cf.Fields[name]})
	}

	return out
}

func nameSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[strings.ToLower(n)] = true
	}

	return m
}

// validFileName rejects names that are not a plain base name: they end up
// joined to a directory.
func validFileName(name string) error {
	if name == "" || name == "." || name == ".." ||
		strings.ContainsAny(name, "/\\\x00") || strings.ContainsAny(name, " \t\r\n") {
		return fmt.Errorf("%w: file name %q", ErrInvalid, name)
	}

	return nil
}

// hash kinds of the checksum fields.
const (
	hashMD5 = iota
	hashSHA1
	hashSHA256
	hashSHA512
)

var hashLen = [...]int{hashMD5: 32, hashSHA1: 40, hashSHA256: 64, hashSHA512: 128}

// checksumFields lists the field of every hash kind in a .dsc, a .changes
// file and a Sources index; a .buildinfo names the MD5 field "Checksums-Md5".
var checksumFields = [...]string{
	hashMD5:    "Files",
	hashSHA1:   "Checksums-Sha1",
	hashSHA256: "Checksums-Sha256",
	hashSHA512: "Checksums-Sha512",
}

// fieldName returns the name of the field that lists the hash kind.
func fieldName(kind int, md5Field string) string {
	if kind == hashMD5 {
		return md5Field
	}

	return checksumFields[kind]
}

func (f *FileRef) set(kind int, v string) {
	switch kind {
	case hashMD5:
		f.MD5 = v
	case hashSHA1:
		f.SHA1 = v
	case hashSHA256:
		f.SHA256 = v
	case hashSHA512:
		f.SHA512 = v
	}
}

func (f *FileRef) get(kind int) string {
	switch kind {
	case hashMD5:
		return f.MD5
	case hashSHA1:
		return f.SHA1
	case hashSHA256:
		return f.SHA256
	}

	return f.SHA512
}

// parseFileLists merges the Files and Checksums-* fields of cf into one list
// of files in order of appearance. extra is the number of columns after the
// size that precede the name (2 for the .changes Files field: section and
// priority) and applies to the Files field only.
func parseFileLists(cf *deb.ControlFile, filesExtra int, md5Field string) ([]FileRef, error) {
	var (
		files []FileRef
		index = map[string]int{}
	)

	for kind := hashMD5; kind <= hashSHA512; kind++ {
		field := fieldName(kind, md5Field)

		value, ok := cf.Lookup(field)
		if !ok {
			continue
		}

		extra := 0
		if kind == hashMD5 {
			extra = filesExtra
		}

		for _, line := range strings.Split(value, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			cols := strings.Fields(line)
			if len(cols) != 3+extra {
				return nil, fmt.Errorf("%w: %s line %q", ErrInvalid, field, line)
			}

			sum := strings.ToLower(cols[0])
			if _, err := hex.DecodeString(sum); err != nil || len(sum) != hashLen[kind] {
				return nil, fmt.Errorf("%w: %s digest %q", ErrInvalid, field, cols[0])
			}

			size, err := strconv.ParseInt(cols[1], 10, 64)
			if err != nil || size < 0 {
				return nil, fmt.Errorf("%w: %s size %q", ErrInvalid, field, cols[1])
			}

			name := cols[len(cols)-1]
			if err := validFileName(name); err != nil {
				return nil, err
			}

			i, seen := index[name]
			if !seen {
				i = len(files)
				index[name] = i
				files = append(files, FileRef{Name: name, Size: size})
			} else if files[i].Size != size {
				return nil, fmt.Errorf("%w: %s lists %s with size %d, another list has %d",
					ErrInvalid, field, name, size, files[i].Size)
			}

			files[i].set(kind, sum)

			if extra == 2 {
				files[i].Section, files[i].Priority = cols[2], cols[3]
			}
		}
	}

	return files, nil
}

// formatFileList renders one checksum field of files, "" when no file has
// that hash. withSectionPriority adds the .changes columns to the Files field.
func formatFileList(files []FileRef, kind int, withSectionPriority bool) string {
	var sb strings.Builder

	for _, f := range files {
		sum := f.get(kind)
		if sum == "" {
			continue
		}

		sb.WriteString("\n")
		sb.WriteString(sum)
		sb.WriteString(" ")
		sb.WriteString(strconv.FormatInt(f.Size, 10))

		if kind == hashMD5 && withSectionPriority {
			sb.WriteString(" ")
			sb.WriteString(orDash(f.Section))
			sb.WriteString(" ")
			sb.WriteString(orDash(f.Priority))
		}

		sb.WriteString(" ")
		sb.WriteString(f.Name)
	}

	return sb.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}

	return s
}

// paragraph builds a deb822 paragraph field by field.
type paragraph struct{ cf *deb.ControlFile }

func newParagraph() *paragraph { return &paragraph{cf: deb.NewControlFile()} }

// add appends name: value; an empty value is skipped.
func (p *paragraph) add(name, value string) {
	if value != "" {
		p.cf.Set(name, value)
	}
}

// fileListSpec says which checksum fields of a file list a document carries
// and how it names and orders them.
type fileListSpec struct {
	// kinds lists the hash kinds to write, in field order.
	kinds []int
	// md5Field names the field of the MD5 list: "Files" or "Checksums-Md5".
	md5Field string
	// sectionPriority adds the .changes columns to the Files field.
	sectionPriority bool
}

// addFiles writes the checksum fields of files that spec selects, skipping the
// hash kinds no file carries.
func (p *paragraph) addFiles(files []FileRef, spec fileListSpec) {
	for _, kind := range spec.kinds {
		if hasHash(files, kind) {
			p.add(fieldName(kind, spec.md5Field), formatFileList(files, kind, spec.sectionPriority))
		}
	}
}

func (p *paragraph) addExtra(extra []Field) {
	for _, f := range extra {
		p.cf.Set(f.Name, f.Value)
	}
}

// hasHash reports whether any file lists the hash kind.
func hasHash(files []FileRef, kind int) bool {
	for _, f := range files {
		if f.get(kind) != "" {
			return true
		}
	}

	return false
}
