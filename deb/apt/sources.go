package apt

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Limits of the sources parsers, which bound what hostile input can allocate.
const (
	// MaxSourcesFileBytes caps one sources.list or deb822 .sources file read by
	// LoadSources, and the text given to ParseSourcesList and ParseSources822.
	MaxSourcesFileBytes = 1 << 20
	// MaxSourceListValues caps the words of one list value: the components of
	// a line, the Suites or URIs of a stanza, the entries of an option.
	MaxSourceListValues = 1024
	// MaxStanzaSources caps the sources one deb822 stanza expands to
	// (Types x URIs x Suites).
	MaxStanzaSources = 1024
	// MaxSourcesPerFile caps the sources one file yields.
	MaxSourcesPerFile = 16384
)

var (
	// ErrUnsupportedScheme reports a source whose URI scheme the client has no
	// transport for (everything but http and https as far as Update goes). The
	// parsers accept every scheme apt knows (file:, copy:, cdrom:, ftp:,
	// mirror+http:, ssh:, ...) and keep it in Source.URL; Scheme tells which.
	ErrUnsupportedScheme = errors.New("apt: unsupported URI scheme")
	// ErrMalformedSource reports a sources entry that is not well formed: an
	// unknown type, a missing URI, suite or component, a URI without a scheme,
	// an option that is not key=value.
	ErrMalformedSource = errors.New("apt: malformed source entry")
	// ErrInvalidOption reports the value of a known source option that apt
	// does not accept: a yes/no option that is neither, a duration that is not
	// a number of seconds, a By-Hash other than yes, no and force.
	ErrInvalidOption = errors.New("apt: invalid source option value")
	// ErrInvalidSignedBy reports a Signed-By value that is none of the forms
	// apt accepts: a list of fingerprints, a list of absolute keyring paths
	// (or both), or one inline armored key block alone.
	ErrInvalidSignedBy = errors.New("apt: invalid Signed-By value")
)

// SourceError reports an entry of a sources file that was skipped. Parsers
// return every such error joined (errors.Join) next to the sources that did
// parse. It matches ErrMalformedSource, ErrInvalidOption, ErrInvalidSignedBy or
// whatever else Err wraps, with errors.Is.
type SourceError struct {
	// Path is the file the entry is in, "" when parsing a string.
	Path string
	// Line is the 1-based line of the entry (of the first line of a deb822
	// stanza), 0 when unknown.
	Line int
	// Option is the option or field at fault, as written, or "".
	Option string
	// Err says what is wrong.
	Err error
}

// Error renders "apt: path:line: option "x": reason".
func (e *SourceError) Error() string {
	var sb strings.Builder

	sb.WriteString("apt: sources")

	if e.Path != "" {
		sb.WriteByte(' ')
		sb.WriteString(e.Path)
	}

	if e.Line > 0 {
		fmt.Fprintf(&sb, ":%d", e.Line)
	}

	sb.WriteString(": ")

	if e.Option != "" {
		fmt.Fprintf(&sb, "option %q: ", e.Option)
	}

	sb.WriteString(e.Err.Error())

	return sb.String()
}

// Unwrap exposes Err to errors.Is and errors.As.
func (e *SourceError) Unwrap() error { return e.Err }

// SourceType is the Types value of a source: what kind of archive it is.
type SourceType string

const (
	// TypeDeb is a binary package archive ("deb").
	TypeDeb SourceType = "deb"
	// TypeDebSrc is a source package archive ("deb-src").
	TypeDebSrc SourceType = "deb-src"
)

// Switch is a yes/no source option that may be left to the global
// configuration. The zero value means unset.
type Switch uint8

const (
	// SwitchDefault leaves the option to the default (UpdateOptions or apt's).
	SwitchDefault Switch = iota
	// SwitchYes is yes, true, with, on, enable or 1.
	SwitchYes
	// SwitchNo is no, false, without, off, disable or 0.
	SwitchNo
)

// Enabled resolves the switch, using def when it is unset.
func (s Switch) Enabled(def bool) bool {
	switch s {
	case SwitchYes:
		return true
	case SwitchNo:
		return false
	default:
		return def
	}
}

// ByHashMode is the By-Hash source option.
type ByHashMode uint8

const (
	// ByHashDefault is unset: by-hash is used when the Release file says
	// Acquire-By-Hash: yes, as with "yes".
	ByHashDefault ByHashMode = iota
	// ByHashYes uses by-hash when the Release file offers it.
	ByHashYes
	// ByHashNo never uses by-hash.
	ByHashNo
	// ByHashForce uses by-hash even if the Release file does not say so, and
	// does not fall back to the plain index path.
	ByHashForce
)

// Source is one apt repository: a base URL, a suite and its components, with
// the options of a sources.list line or deb822 stanza.
//
// A one-line entry and a deb822 stanza with one Types, URIs and Suites value
// each give one Source; a stanza with several of them gives one per type, URI
// and suite, all with the same Components and options.
type Source struct {
	// Type is TypeDeb or TypeDebSrc. The zero value means TypeDeb.
	Type SourceType
	// URL is the repository base URL with a trailing slash
	// ("https://archive.ubuntu.com/ubuntu/"). Besides http(s) it may carry
	// the schemes file:, copy:, cdrom:, mirror+http(s):// and mirror+file://
	// (and, accepted by the parser, anything else apt knows, which Update
	// refuses with ErrUnsupportedScheme). It is kept as written, apart from
	// the trailing slash; ListFileNameFor applies apt's normalisation.
	URL string
	// Suite is the distribution ("jammy", "bookworm-updates"). A suite that
	// ends in a slash ("./", "debian/$(ARCH)/") names an exact path: the
	// repository is flat, the Release lies in that directory and Components is
	// empty.
	Suite string
	// Components lists the archive areas ("main", "universe").
	Components []string
	// Architectures restricts the source to these architectures. Empty means
	// the default architecture.
	Architectures []string
	// ArchitecturesAdd and ArchitecturesRemove are the Architectures-Add and
	// Architectures-Remove options (arch+= and arch-=): architectures added
	// to, or taken off, the set the source is fetched for.
	ArchitecturesAdd, ArchitecturesRemove []string
	// Languages are the Languages option for the Translation indexes ("en",
	// "de", "none"); empty means the default (the translations apt would
	// fetch for the environment, here "none" unless UpdateOptions says
	// otherwise).
	Languages []string
	// LanguagesAdd and LanguagesRemove are the Languages-Add and
	// Languages-Remove options (lang+= and lang-=).
	LanguagesAdd, LanguagesRemove []string
	// Targets are the Targets option: the kinds of index to fetch, such as
	// "Packages", "Translations", "Contents", "Sources". Empty selects the
	// default of the Type: Packages for deb, Sources for deb-src.
	Targets []string
	// TargetsAdd and TargetsRemove are the Targets-Add and Targets-Remove
	// options (target+= and target-=).
	TargetsAdd, TargetsRemove []string
	// SignedBy is the Signed-By option verbatim: key fingerprints (separated
	// by comma or blank, each optionally ending in "!"), paths of keyring
	// files or directories, or an inline armored PGP public key block. "" means
	// the default keyrings. LoadKeyring interprets it.
	SignedBy string
	// Trusted, AllowInsecure, AllowWeak, AllowDowngradeToInsecure,
	// CheckValidUntil and CheckDate are the options of those names (trusted,
	// allow-insecure, allow-weak, allow-downgrade-to-insecure,
	// check-valid-until, check-date).
	Trusted, AllowInsecure, AllowWeak, AllowDowngradeToInsecure, CheckValidUntil, CheckDate Switch
	// ValidUntilMin and ValidUntilMax are the Valid-Until-Min and
	// Valid-Until-Max options, as durations. Zero is unset.
	ValidUntilMin, ValidUntilMax time.Duration
	// DateMaxFuture is the Date-Max-Future option: how far past the local clock
	// the Date of the Release may lie. Zero is unset.
	DateMaxFuture time.Duration
	// ByHash is the By-Hash option.
	ByHash ByHashMode
	// PDiffs is the PDiffs option.
	PDiffs Switch
	// Snapshot is the Snapshot option as written: a snapshot id for archives
	// that serve them, "enable" or "disable" (or another yes/no spelling), or
	// "" when unset.
	Snapshot string
	// Options holds the options the parser does not interpret (InRelease-Path,
	// target identifiers such as Contents-deb=no, anything unknown), with their
	// names as written, so that a writer can reproduce them.
	Options map[string]string
}

// IsSource reports whether the source is a source package archive.
func (s *Source) IsSource() bool { return s.Type == TypeDebSrc }

// Flat reports whether the suite is an exact path (it ends in a slash), so
// that the repository has no dists/ tree and no components.
func (s *Source) Flat() bool { return strings.HasSuffix(s.Suite, "/") }

// Scheme returns the lower-cased scheme of URL: "http", "https", "file",
// "copy", "cdrom", "mirror+http", "ssh", ... It is "" for a URL without one.
func (s *Source) Scheme() string {
	scheme, _, ok := strings.Cut(s.URL, ":")
	if !ok {
		return ""
	}

	return strings.ToLower(scheme)
}

// ExpandArch returns a copy of the source with the $(ARCH) variable of URL and
// Suite replaced by arch, as apt does with its native architecture.
func (s *Source) ExpandArch(arch string) Source {
	cp := *s
	cp.URL = strings.ReplaceAll(s.URL, "$(ARCH)", arch)
	cp.Suite = strings.ReplaceAll(s.Suite, "$(ARCH)", arch)

	return cp
}

// EffectiveArchitectures returns the architectures the source is fetched for:
// Architectures (defaultArch when that is empty), plus ArchitecturesAdd, minus
// ArchitecturesRemove, without duplicates, in that order. apt's implicit "all"
// is not added; it holds for every source whose Release lists it.
func (s *Source) EffectiveArchitectures(defaultArch string) []string {
	var base []string

	switch {
	case len(s.Architectures) > 0:
		base = s.Architectures
	case defaultArch != "":
		base = []string{defaultArch}
	}

	return applyPlusMinus(base, s.ArchitecturesAdd, s.ArchitecturesRemove)
}

// EffectiveLanguages returns the translation languages of the source:
// Languages (defaults when that is empty), plus LanguagesAdd, minus
// LanguagesRemove. "none" is kept as a language, as apt does.
func (s *Source) EffectiveLanguages(defaults []string) []string {
	base := s.Languages
	if len(base) == 0 {
		base = defaults
	}

	return applyPlusMinus(base, s.LanguagesAdd, s.LanguagesRemove)
}

// EffectiveTargets returns the kinds of index the source fetches. Without a
// Targets option the default is Packages for a deb source, with Translations
// after it when EffectiveLanguages(defaultLanguages) holds a language other
// than "none"; and Sources for a deb-src source. TargetsAdd and TargetsRemove
// are applied to the result.
func (s *Source) EffectiveTargets(defaultLanguages []string) []string {
	base := s.Targets

	if len(base) == 0 {
		switch {
		case s.IsSource():
			base = []string{"Sources"}
		case hasTranslationLanguage(s.EffectiveLanguages(defaultLanguages)):
			base = []string{"Packages", "Translations"}
		default:
			base = []string{"Packages"}
		}
	}

	return applyPlusMinus(base, s.TargetsAdd, s.TargetsRemove)
}

// hasTranslationLanguage reports whether langs names a real language.
func hasTranslationLanguage(langs []string) bool {
	return slices.ContainsFunc(langs, func(l string) bool { return l != "none" && l != "" })
}

// applyPlusMinus appends the values of add that base lacks, drops the
// duplicates, then drops the values of remove, in the order apt does.
func applyPlusMinus(base, add, remove []string) []string {
	var out []string

	for _, v := range base {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}

	for _, v := range add {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}

	out = slices.DeleteFunc(out, func(v string) bool { return slices.Contains(remove, v) })

	return out
}
