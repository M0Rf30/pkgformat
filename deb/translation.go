package deb

import (
	"crypto/md5" //nolint:gosec // Description-md5 is a lookup key of the format, not a security control
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"sort"
	"strings"
)

// MaxTranslationEntries bounds the descriptions ParseTranslation reads.
const MaxTranslationEntries = 1 << 22

// ErrInvalidTranslation is returned for a language or entry that cannot be
// written to a Translation file.
var ErrInvalidTranslation = errors.New("deb: invalid translation")

// TranslationEntry is one package description of a Translation-<lang> file.
type TranslationEntry struct {
	// Package is the package name.
	Package string
	// DescriptionMD5 is the Description-md5 of the English description: the key
	// that ties the entry to the packages whose Packages stanza carries
	// Description-md5 instead of the description.
	DescriptionMD5 string
	// Description is the description in the language: the short description,
	// then the extended one on following lines, in the logical form the control
	// file reader returns (continuation lines without their leading blank).
	Description string
}

// DescriptionMD5 returns the Description-md5 of a description: the MD5 of the
// description as it is written in a Packages stanza, that is the short
// description, a newline, and every extended line with its leading blank and a
// newline ("short\n long\n .\n more\n"). description is the logical value, as
// ControlFile.Get returns it.
func DescriptionMD5(description string) string {
	var sb strings.Builder

	first, rest, multi := strings.Cut(description, "\n")
	sb.WriteString(first)
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

	sum := md5.Sum([]byte(sb.String())) //nolint:gosec // see above

	return hex.EncodeToString(sum[:])
}

// ShortDescription returns the first line of a description.
func ShortDescription(description string) string {
	first, _, _ := strings.Cut(description, "\n")

	return first
}

// TranslationEntry returns the Translation entry of the package: its
// description under its Description-md5. The language is that of the
// Translation file it is written to; an index carrying English descriptions
// writes Translation-en.
func (e IndexEntry) TranslationEntry() TranslationEntry {
	desc := canonicalFields(e.Control)["Description"]

	return TranslationEntry{Package: e.Name, DescriptionMD5: DescriptionMD5(desc), Description: desc}
}

// MarshalTranslation renders a Translation-<lang> file for the entries, in the
// order given: a paragraph per package with Package, Description-md5 and
// Description-<lang>. An entry without a DescriptionMD5 gets the md5 of its own
// description, which is the key only for English.
func MarshalTranslation(lang string, entries []TranslationEntry) []byte {
	var sb strings.Builder

	for _, e := range entries {
		appendTranslation(&sb, lang, e)
	}

	return []byte(sb.String())
}

func appendTranslation(sb *strings.Builder, lang string, e TranslationEntry) {
	writeField(sb, "Package", e.Package)

	md5sum := e.DescriptionMD5
	if md5sum == "" {
		md5sum = DescriptionMD5(e.Description)
	}

	writeField(sb, "Description-md5", md5sum)
	writeField(sb, "Description-"+lang, e.Description)
	sb.WriteString("\n")
}

// TranslationFileName is the name of a Translation file in the i18n directory
// of a component: "Translation-de.xz".
func TranslationFileName(lang, ext string) string { return "Translation-" + lang + ext }

// TranslationBuilder accumulates the descriptions of one language and renders
// them as a Translation-<lang> file the way a repository publishes it: one
// paragraph per distinct description (Description-md5), sorted by package name
// then md5, so the same input gives the same bytes. The zero value is not
// usable; create one with NewTranslationBuilder.
type TranslationBuilder struct {
	lang    string
	byMD5   map[string]TranslationEntry
	invalid error
}

// NewTranslationBuilder returns a builder for the language: "en", "de",
// "pt_BR". A language that is not a plain code makes every Add fail with
// ErrInvalidTranslation.
func NewTranslationBuilder(lang string) *TranslationBuilder {
	b := &TranslationBuilder{lang: lang, byMD5: make(map[string]TranslationEntry)}

	if !validLanguage(lang) {
		b.invalid = fmt.Errorf("%w: language %q", ErrInvalidTranslation, lang)
	}

	return b
}

// Language is the language of the builder.
func (b *TranslationBuilder) Language() string { return b.lang }

// Add records a description. An entry that has no DescriptionMD5 is keyed by
// the md5 of its own description (right for English); one without a package
// name or a description fails with ErrInvalidTranslation. A description that is
// already there (same md5) is kept as first added: packages that share a
// description share one paragraph.
func (b *TranslationBuilder) Add(e TranslationEntry) error {
	if b.invalid != nil {
		return b.invalid
	}

	if e.Package == "" || strings.TrimSpace(e.Description) == "" {
		return fmt.Errorf("%w: entry %q needs a package and a description", ErrInvalidTranslation, e.Package)
	}

	if e.DescriptionMD5 == "" {
		e.DescriptionMD5 = DescriptionMD5(e.Description)
	}

	e.DescriptionMD5 = strings.ToLower(e.DescriptionMD5)

	if _, dup := b.byMD5[e.DescriptionMD5]; dup {
		return nil
	}

	if len(b.byMD5) >= MaxTranslationEntries {
		return fmt.Errorf("%w: more than %d descriptions", ErrTooLarge, MaxTranslationEntries)
	}

	b.byMD5[e.DescriptionMD5] = e

	return nil
}

// AddIndexEntry records the description of a package of a Packages index (the
// English one, for a Translation-en builder). A package without a description
// is skipped.
func (b *TranslationBuilder) AddIndexEntry(e IndexEntry) error {
	te := e.TranslationEntry()
	if te.Description == "" {
		return nil
	}

	return b.Add(te)
}

// Len is the number of descriptions.
func (b *TranslationBuilder) Len() int { return len(b.byMD5) }

// Entries returns the descriptions in file order.
func (b *TranslationBuilder) Entries() []TranslationEntry {
	out := make([]TranslationEntry, 0, len(b.byMD5))
	for _, e := range b.byMD5 {
		out = append(out, e)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}

		return out[i].DescriptionMD5 < out[j].DescriptionMD5
	})

	return out
}

// Bytes renders the Translation file.
func (b *TranslationBuilder) Bytes() []byte { return MarshalTranslation(b.lang, b.Entries()) }

// Compressed renders the file compressed with c.
func (b *TranslationBuilder) Compressed(c Compression) ([]byte, error) {
	var buf sliceWriter

	if _, err := b.WriteTo(&buf, c); err != nil {
		return nil, err
	}

	return buf.b, nil
}

// WriteTo writes the file compressed with c to w and returns the number of
// bytes written to w.
func (b *TranslationBuilder) WriteTo(w io.Writer, c Compression) (int64, error) {
	cw := &countingWriter{w: w}

	zw, err := compressWriter(cw, c)
	if err != nil {
		return 0, err
	}

	if _, err := zw.Write(b.Bytes()); err != nil {
		_ = zw.Close()

		return cw.n, fmt.Errorf("deb: writing translation: %w", err)
	}

	if err := zw.Close(); err != nil {
		return cw.n, fmt.Errorf("deb: closing translation: %w", err)
	}

	return cw.n, nil
}

// ScanTranslation yields each entry of a Translation-<lang> file (read
// decompressed), in order. Entries without a Package or without a description
// in the language are skipped. The limits of ScanControl apply.
func ScanTranslation(r io.Reader, lang string) iter.Seq2[TranslationEntry, error] {
	field := "Description-" + lang

	return func(yield func(TranslationEntry, error) bool) {
		stopped := errors.New("stop")

		err := ScanControl(r, func(cf *ControlFile) error {
			pkg, desc := cf.Get("Package"), cf.Get(field)
			if pkg == "" || desc == "" {
				return nil
			}

			if !yield(TranslationEntry{Package: pkg, DescriptionMD5: strings.ToLower(cf.Get("Description-md5")), Description: desc}, nil) {
				return stopped
			}

			return nil
		})
		if err != nil && !errors.Is(err, stopped) {
			yield(TranslationEntry{}, err)
		}
	}
}

// ParseTranslation reads a whole Translation file into a map from
// Description-md5 to the description in the language, which is how apt looks
// translations up. An entry without a Description-md5 is keyed by the md5 of
// its description, which only matches when the file is in English. More than
// MaxTranslationEntries entries fail with ErrTooLarge.
func ParseTranslation(r io.Reader, lang string) (map[string]TranslationEntry, error) {
	out := make(map[string]TranslationEntry)

	for e, err := range ScanTranslation(r, lang) {
		if err != nil {
			return nil, err
		}

		key := e.DescriptionMD5
		if key == "" {
			key = DescriptionMD5(e.Description)
		}

		if _, known := out[key]; !known && len(out) >= MaxTranslationEntries {
			return nil, fmt.Errorf("%w: more than %d descriptions", ErrTooLarge, MaxTranslationEntries)
		}

		out[key] = e
	}

	return out, nil
}

// translationLanguage extracts "de" from "Translation-de.xz".
func translationLanguage(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, "Translation-")
	if !ok {
		return "", false
	}

	if ext := compressionOf(rest); ext != "" {
		rest = strings.TrimSuffix(rest, ext)
	}

	return rest, rest != ""
}
