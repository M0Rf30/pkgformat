package repodata

import (
	"errors"
	"strconv"
	"time"
)

// ErrInvalidModulemd means a modulemd document is malformed: not YAML, a field
// of the wrong type, a missing mandatory field or a value libmodulemd would
// refuse. The error wraps it with the document and the field.
var ErrInvalidModulemd = errors.New("repodata: invalid modulemd document")

// ErrUnsupportedModulemd means a document is well-formed but of a kind or a
// format version this package does not model: the kinds are modulemd,
// modulemd-defaults, modulemd-obsoletes and modulemd-translations; modulemd
// is read at version 2 and the other three at version 1.
var ErrUnsupportedModulemd = errors.New("repodata: unsupported modulemd document")

// ModuleDocument is one document of a modules.yaml: a [ModuleStream], a
// [ModuleDefaults], a [ModuleObsoletes] or a [ModuleTranslations], always
// handled through a pointer.
type ModuleDocument interface {
	moduleDocument()
}

func (*ModuleStream) moduleDocument()       {}
func (*ModuleDefaults) moduleDocument()     {}
func (*ModuleObsoletes) moduleDocument()    {}
func (*ModuleTranslations) moduleDocument() {}

// The kinds a modules.yaml document declares in its "document" field.
const (
	moduleKindStream       = "modulemd"
	moduleKindDefaults     = "modulemd-defaults"
	moduleKindObsoletes    = "modulemd-obsoletes"
	moduleKindTranslations = "modulemd-translations"
)

// ModuleSet is the content of a modules.yaml: its documents by kind.
type ModuleSet struct {
	Streams      []*ModuleStream
	Defaults     []*ModuleDefaults
	Obsoletes    []*ModuleObsoletes
	Translations []*ModuleTranslations
}

// ModuleStream is a modulemd v2 document: one build of one stream of a
// module. Collections left nil are absent from the document; a non-nil empty
// XMD is written as "xmd: {}".
type ModuleStream struct {
	Name   string
	Stream string
	// Version is the build version, a timestamp by convention; zero is
	// absent.
	Version uint64
	Context string
	// StaticContext marks Context as chosen by the packager instead of a
	// hash of the build.
	StaticContext bool
	Arch          string
	Summary       string
	Description   string
	// ServiceLevels maps a service level name ("rawhide", "bug_fixes", ...)
	// to its end of life.
	ServiceLevels map[string]ModuleServiceLevel
	License       ModuleLicense
	// XMD is the opaque extensible metadata block. Values are strings,
	// booleans, []any and map[string]any: like libmodulemd, a number read from
	// the document is kept as a string.
	XMD          map[string]any
	Dependencies []ModuleDependency
	References   ModuleReferences
	// Profiles maps a profile name to its package lists.
	Profiles map[string]ModuleProfile
	// API lists the binary rpm names that are the stable interface of the
	// module and Filter those left out of it.
	API    []string
	Filter []string
	// Demodularized lists binary rpm names that stopped being part of the
	// module.
	Demodularized []string
	BuildOpts     *ModuleBuildOpts
	Components    ModuleComponents
	Artifacts     ModuleArtifacts
}

// NSVCA returns "name:stream:version:context:arch" with the empty trailing
// parts dropped, the key libmodulemd orders and identifies stream builds by.
func (s *ModuleStream) NSVCA() string {
	version := ""
	if s.Version != 0 {
		version = strconv.FormatUint(s.Version, 10)
	}

	nsvca := s.Name + ":" + s.Stream + ":" + version + ":" + s.Context + ":" + s.Arch

	for len(nsvca) > len(s.Name) && nsvca[len(nsvca)-1] == ':' {
		nsvca = nsvca[:len(nsvca)-1]
	}

	return nsvca
}

// ModuleServiceLevel is the support commitment of a stream.
type ModuleServiceLevel struct {
	// EOL is the end-of-life date as "YYYY-MM-DD"; empty when none.
	EOL string
}

// ModuleLicense lists the SPDX-style licenses of the module metadata and of
// the packages inside it.
type ModuleLicense struct {
	Module  []string
	Content []string
}

// ModuleDependency is one combination of dependencies of a stream: the module
// streams it builds against and the ones it needs at run time. The values are
// the stream lists that satisfy the dependency; an empty list accepts any
// stream and a name with a leading "-" excludes a stream.
type ModuleDependency struct {
	BuildRequires map[string][]string
	Requires      map[string][]string
}

// ModuleReferences points at the community, documentation and issue tracker of the module.
type ModuleReferences struct {
	Community     string
	Documentation string
	Tracker       string
}

// ModuleProfile is a set of packages a user installs together.
type ModuleProfile struct {
	Description string
	RPMs        []string
	// Default marks the profile dnf installs when none is named.
	Default bool
}

// ModuleBuildOpts holds the build options that apply to the whole module.
type ModuleBuildOpts struct {
	// Macros is text appended to the rpm macros of the buildroot.
	Macros string
	// Whitelist lists the package names the build may produce.
	Whitelist []string
	// Arches limits the architectures the module is built for.
	Arches []string
}

// ModuleComponents are the rpms and modules a stream is built from, by key.
type ModuleComponents struct {
	RPMs    map[string]ModuleRPMComponent
	Modules map[string]ModuleModuleComponent
}

// ModuleRPMComponent is a source package built into the module.
type ModuleRPMComponent struct {
	// Name is the package name when it differs from the key.
	Name       string
	Rationale  string
	Repository string
	Cache      string
	Ref        string
	// Buildroot and SRPMBuildroot install the buildroot profiles for the
	// later build batches.
	Buildroot     bool
	SRPMBuildroot bool
	// BuildOrder groups components into build batches; zero means none.
	// BuildAfter is the alternative that names the components to build
	// after; a component sets at most one of the two.
	BuildOrder int64
	BuildAfter []string
	BuildOnly  bool
	Arches     []string
	Multilib   []string
}

// ModuleModuleComponent is a module built inside another one.
type ModuleModuleComponent struct {
	Rationale  string
	Repository string
	Ref        string
	BuildOrder int64
	BuildAfter []string
	BuildOnly  bool
}

// ModuleArtifacts lists what the build produced.
type ModuleArtifacts struct {
	// RPMs holds the NEVRA of every binary and source package, as
	// [PackageNEVRA] builds them.
	RPMs []string
	// RPMMap links the checksum of a package in repomd to its NEVRA parts:
	// digest type, then checksum.
	RPMMap map[string]map[string]ModuleRPMMapEntry
}

// ModuleRPMMapEntry describes an artifact of RPMMap. The NEVRA is derived
// from the fields.
type ModuleRPMMapEntry struct {
	Name    string
	Epoch   uint64
	Version string
	Release string
	Arch    string
}

// NEVRA returns "name-epoch:version-release.arch".
func (e ModuleRPMMapEntry) NEVRA() string {
	return PackageNEVRA(e.Name, strconv.FormatUint(e.Epoch, 10), e.Version, e.Release, e.Arch)
}

// ModuleDefaults is a modulemd-defaults v1 document: the default stream of a
// module and the default profiles of its streams.
type ModuleDefaults struct {
	Module string
	// Modified is the revision of the document as YYYYMMDDHHMM; zero is
	// absent.
	Modified uint64
	// Stream is the default stream; empty means the module has none.
	Stream string
	// Profiles maps a stream to the profiles installed by default.
	Profiles map[string][]string
	// Intents overrides the defaults for a kind of system ("server",
	// "desktop"), by the name the system declares.
	Intents map[string]ModuleDefaultsIntent
}

// ModuleDefaultsIntent is the override of the defaults for one intent.
type ModuleDefaultsIntent struct {
	Stream   string
	Profiles map[string][]string
}

// ModuleObsoletes is a modulemd-obsoletes v1 document: a stream, or one
// context of it, that is no longer maintained.
type ModuleObsoletes struct {
	Module  string
	Stream  string
	Context string
	// Modified is when the record was written, in UTC to the minute.
	Modified time.Time
	// EOLDate is when the stream ends; the zero time is absent.
	EOLDate time.Time
	Message string
	// Reset cancels the earlier obsoletes records of the stream.
	Reset bool
	// ObsoletedBy names the stream that replaces this one.
	ObsoletedBy *ModuleObsoletedBy
}

// ModuleObsoletedBy names the module stream that replaces an obsolete one.
type ModuleObsoletedBy struct {
	Module string
	Stream string
}

// ModuleTranslations is a modulemd-translations v1 document: the texts of one
// stream in other languages.
type ModuleTranslations struct {
	Module   string
	Stream   string
	Modified uint64
	// Locales maps a locale ("es_ES", "ja") to its texts.
	Locales map[string]ModuleTranslation
}

// ModuleTranslation holds the translated summary, description and profile
// descriptions of a stream in one locale.
type ModuleTranslation struct {
	Summary     string
	Description string
	// Profiles maps a profile name to its translated description.
	Profiles map[string]string
}
