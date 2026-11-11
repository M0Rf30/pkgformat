package deb

import (
	"crypto/md5" //nolint:gosec // Description-md5 is a lookup key of the format, not a security control
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
)

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
// Description-<lang>.
func MarshalTranslation(lang string, entries []TranslationEntry) []byte {
	var sb strings.Builder

	for _, e := range entries {
		writeField(&sb, "Package", e.Package)

		md5sum := e.DescriptionMD5
		if md5sum == "" {
			md5sum = DescriptionMD5(e.Description)
		}

		writeField(&sb, "Description-md5", md5sum)
		writeField(&sb, "Description-"+lang, e.Description)
		sb.WriteString("\n")
	}

	return []byte(sb.String())
}

// TranslationFileName is the name of a Translation file in the i18n directory
// of a component: "Translation-de.xz".
func TranslationFileName(lang, ext string) string { return "Translation-" + lang + ext }

// ScanTranslation calls fn for each entry of a Translation-<lang> file (read
// decompressed), in order. Entries without a Package or without a description
// in the language are skipped. fn returning an error stops the scan with it.
func ScanTranslation(r io.Reader, lang string, fn func(TranslationEntry) error) error {
	field := "Description-" + lang

	return ScanControl(r, func(cf *ControlFile) error {
		pkg, desc := cf.Get("Package"), cf.Get(field)
		if pkg == "" || desc == "" {
			return nil
		}

		return fn(TranslationEntry{Package: pkg, DescriptionMD5: strings.ToLower(cf.Get("Description-md5")), Description: desc})
	})
}

// ParseTranslation reads a whole Translation file into a map from
// Description-md5 to the description in the language, which is how apt looks
// translations up. An entry without a Description-md5 is keyed by the md5 of
// its description, which only matches when the file is in English.
func ParseTranslation(r io.Reader, lang string) (map[string]TranslationEntry, error) {
	out := make(map[string]TranslationEntry)

	err := ScanTranslation(r, lang, func(e TranslationEntry) error {
		key := e.DescriptionMD5
		if key == "" {
			key = DescriptionMD5(e.Description)
		}

		out[key] = e

		return nil
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// I18nIndex is the content of the i18n/Index file of a component: the
// checksums of the Translation files next to it, so that a client can tell a
// translation it has is current without fetching the Release again.
type I18nIndex struct {
	// Files lists the Translation files by name, relative to the i18n directory
	// ("Translation-en.xz").
	Files map[string]FileInfo
}

// AddFile records a Translation file in the index.
func (ix *I18nIndex) AddFile(fi FileInfo) {
	if ix.Files == nil {
		ix.Files = make(map[string]FileInfo)
	}

	ix.Files[fi.Path] = fi
}

// Marshal renders the index: the checksum sections of a Release, SHA1 and
// SHA256 here, with the digests the files have.
func (ix *I18nIndex) Marshal() []byte {
	var sb strings.Builder

	writeSections(&sb, ix.Files)

	return []byte(sb.String())
}

// Languages lists the languages the index has a Translation file for, sorted
// and without duplicates.
func (ix *I18nIndex) Languages() []string {
	seen := make(map[string]bool)

	for name := range ix.Files {
		if lang, ok := translationLanguage(name); ok {
			seen[lang] = true
		}
	}

	out := make([]string, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}

	sort.Strings(out)

	return out
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

// ParseI18nIndex parses an i18n/Index file.
func ParseI18nIndex(data []byte) (*I18nIndex, error) {
	if len(data) > MaxReleaseBytes {
		return nil, fmt.Errorf("%w: i18n index over %d bytes", ErrTooLarge, MaxReleaseBytes)
	}

	cf, err := firstParagraph(StripClearsign(data))
	if err != nil {
		return nil, err
	}

	ix := &I18nIndex{Files: make(map[string]FileInfo)}

	for _, sec := range sectionSpecs() {
		if err := addSection(ix.Files, cf.Get(sec.field), sec.length, sec.set); err != nil {
			return nil, fmt.Errorf("%s: %w", sec.field, err)
		}
	}

	return ix, nil
}
