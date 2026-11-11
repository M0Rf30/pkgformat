package deb

import (
	"slices"
	"sort"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/pathseg"
)

// The kinds of index a Release lists, as IndexPath and Release.IndexPaths take
// them. Translation indexes are named by language: "Translation-de".
const (
	// IndexPackages is the Packages index of the binary packages of an
	// architecture: <comp>/binary-<arch>/Packages.
	IndexPackages = "Packages"
	// IndexPackagesUdeb is the Packages index of the udebs of an architecture:
	// <comp>/debian-installer/binary-<arch>/Packages.
	IndexPackagesUdeb = "Packages-udeb"
	// IndexSources is the Sources index of a component: <comp>/source/Sources.
	IndexSources = "Sources"
	// IndexContents is the Contents index of an architecture: <comp>/Contents-<arch>,
	// or Contents-<arch> for the whole distribution when comp is empty.
	IndexContents = "Contents"
	// IndexContentsUdeb is the Contents index of the udebs: Contents-udeb-<arch>.
	IndexContentsUdeb = "Contents-udeb"
	// IndexTranslationPrefix starts the kind of a Translation index:
	// IndexTranslationPrefix+"de" is <comp>/i18n/Translation-de.
	IndexTranslationPrefix = "Translation-"
)

// indexSuffixes lists the compressions an index is published in, best first:
// the order a client tries them.
func indexSuffixes() []string { return []string{".xz", ".zst", ".gz", ".bz2", ".lz4", ""} }

// IndexPath returns the path, relative to dists/<dist> and without a
// compression suffix, of the index of the given kind for a component and an
// architecture ("main/binary-amd64/Packages"). arch is ignored for the kinds
// that have none (Sources, Translation) and comp may be empty for Contents.
// It returns "" for an unknown kind, a missing component or architecture, or a
// language that is not a plain name.
func IndexPath(comp, arch, kind string) string {
	// A component may have a slash ("updates/main"); neither it nor the
	// architecture may climb out of the distribution directory.
	if (comp != "" && !pathseg.Path(comp)) || (arch != "" && !pathseg.Name(arch)) {
		return ""
	}

	switch {
	case kind == IndexPackages && comp != "" && arch != "":
		return comp + "/binary-" + arch + "/Packages"
	case kind == IndexPackagesUdeb && comp != "" && arch != "":
		return comp + "/debian-installer/binary-" + arch + "/Packages"
	case kind == IndexSources && comp != "":
		return comp + "/source/Sources"
	case kind == IndexContents && arch != "":
		return prefixed(comp, "Contents-"+arch)
	case kind == IndexContentsUdeb && arch != "":
		return prefixed(comp, "Contents-udeb-"+arch)
	}

	if lang, ok := strings.CutPrefix(kind, IndexTranslationPrefix); ok && comp != "" && validLanguage(lang) {
		return comp + "/i18n/" + kind
	}

	return ""
}

func prefixed(comp, name string) string {
	if comp == "" {
		return name
	}

	return comp + "/" + name
}

// validLanguage accepts the language codes of Translation files: "en", "de_DE",
// "pt_BR", "sr@latin", "zh-CN".
func validLanguage(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}

	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '@' {
			return false
		}
	}

	return true
}

// IndexVariant is one compression of an index the Release lists.
type IndexVariant struct {
	// Path is relative to dists/<dist>, with the suffix.
	Path string
	// Extension is the compression suffix: ".xz", ".zst", ".gz", ".bz2", ".lz4"
	// or "" for the plain file.
	Extension string
	// Info is the listing of the file.
	Info FileInfo
}

// IndexVariants returns the compressions of the index base (a path without
// suffix, see IndexPath) that the Release lists, best first: .xz, .zst, .gz,
// .bz2, .lz4, then the plain file.
func (r *Release) IndexVariants(base string) []IndexVariant {
	var out []IndexVariant

	for _, ext := range indexSuffixes() {
		if fi, ok := r.Files[base+ext]; ok {
			out = append(out, IndexVariant{Path: base + ext, Extension: ext, Info: fi})
		}
	}

	return out
}

// IndexPaths lists the paths of the index of the given kind (see IndexPath and
// the IndexPackages... constants) that the Release lists, best compression
// first. It is empty when the Release lists none.
func (r *Release) IndexPaths(comp, arch, kind string) []string {
	base := IndexPath(comp, arch, kind)
	if base == "" {
		return nil
	}

	var out []string

	for _, v := range r.IndexVariants(base) {
		out = append(out, v.Path)
	}

	return out
}

// PackagesVariants is IndexPaths for the Packages index of component comp and
// architecture arch.
func (r *Release) PackagesVariants(comp, arch string) []string {
	return r.IndexPaths(comp, arch, IndexPackages)
}

// HasIndex reports whether the Release lists a Packages index for comp and
// arch in any compression.
func (r *Release) HasIndex(comp, arch string) bool {
	return len(r.PackagesVariants(comp, arch)) > 0
}

// PackagesCandidates is PackagesVariants, except that a Release listing none
// of them (one that only carries by-hash entries) yields the usual
// .xz, .gz and plain paths to try.
func (r *Release) PackagesCandidates(comp, arch string) []string {
	if v := r.PackagesVariants(comp, arch); len(v) > 0 {
		return v
	}

	base := IndexPath(comp, arch, IndexPackages)
	if base == "" {
		return nil
	}

	return []string{base + ".xz", base + ".gz", base}
}

// TranslationLanguages lists the languages of the Translation files the
// Release lists for component comp, sorted.
func (r *Release) TranslationLanguages(comp string) []string {
	prefix := comp + "/i18n/"

	var langs []string

	for p := range r.Files {
		name, ok := strings.CutPrefix(p, prefix)
		if !ok || strings.Contains(name, "/") {
			continue
		}

		if lang, ok := translationLanguage(name); ok && !slices.Contains(langs, lang) {
			langs = append(langs, lang)
		}
	}

	sort.Strings(langs)

	return langs
}
