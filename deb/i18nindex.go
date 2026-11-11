package deb

import (
	"fmt"
	"sort"
	"strings"
)

// i18nIndexSizeWidth is the width of the size column of a rendered i18n/Index,
// as the Ubuntu archive writes it.
const i18nIndexSizeWidth = 7

// I18nIndexName is the path of the index of the translations of a component,
// relative to dists/<dist>: "main/i18n/Index".
func I18nIndexName(comp string) string { return comp + "/i18n/Index" }

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

// Marshal renders the index: the checksum sections of a Release (MD5Sum, SHA1,
// SHA256, SHA512), each with the digests the files have. A file with only a
// SHA1 digest renders the SHA1 section alone, as the Ubuntu archive does.
func (ix *I18nIndex) Marshal() []byte {
	var sb strings.Builder

	writeSections(&sb, ix.Files, i18nIndexSizeWidth)

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

// Variants returns the files of one language the index lists, best
// compression first (.xz, .zst, .gz, .bz2, .lz4, plain).
func (ix *I18nIndex) Variants(lang string) []IndexVariant {
	base := TranslationFileName(lang, "")

	var out []IndexVariant

	for _, ext := range indexSuffixes() {
		if fi, ok := ix.Files[base+ext]; ok {
			out = append(out, IndexVariant{Path: base + ext, Extension: ext, Info: fi})
		}
	}

	return out
}

// ParseI18nIndex parses an i18n/Index file. A clear-signed one is accepted,
// its signature not verified.
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
