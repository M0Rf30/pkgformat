// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pack

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"slices"
	"strings"
	"time"

	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

const (
	// NoEpoch skips adding the epoch tag to the RPM.
	//
	// We decided to use this approach instead of making epoch a *uint32 to
	// avoid a breaking change.
	// For reference, this is the max uint32 value, which is 4294967295.
	NoEpoch = ^uint32(0)
)

// ChangelogEntry represents a single entry in the RPM changelog.
type ChangelogEntry struct {
	Time   time.Time
	Author string
	Text   string
}

// Translation holds the texts of a package in a language other than the default.
// Empty texts fall back to the default.
type Translation struct {
	Summary     string
	Description string
	Group       string
}

var (
	// ErrWriteAfterClose is returned when a user calls Write() on a closed rpm.
	ErrWriteAfterClose = errors.New("rpm write after close")
	// ErrWrongFileOrder is returned when files are not sorted by name.
	ErrWrongFileOrder = errors.New("wrong file addition order")
	// ErrInvalidFile is returned by Write when a file added with AddFile cannot be
	// represented in an rpm: a name that is not a clean absolute path, embedded NUL
	// bytes, mode bits outside the 16 bit rpm file mode, an inconsistent content
	// source or hard link, or (for the v4 format) a body larger than the 4 GiB limit
	// of the cpio payload.
	ErrInvalidFile = errors.New("invalid rpm file")
	// ErrInvalidMetadata is returned by Write when a package metadata value cannot
	// be represented in the rpm header: strings with embedded NUL bytes, nil
	// relations, or times outside the unsigned 32 bit range rpm stores.
	ErrInvalidMetadata = errors.New("invalid rpm metadata")
)

const (
	// maxMode is the largest value of the 16 bit rpm file mode.
	maxMode = math.MaxUint16
	// modeTypeMask selects the file type bits (S_IFMT) of a mode.
	modeTypeMask = 0170000
	// maxV4FileSize is the largest file the v4 cpio (newc) payload can hold: the size
	// is stored in 8 hex digits. v6 payloads have no such limit.
	maxV4FileSize = math.MaxUint32
)

// RPMMetaData contains meta info about the whole package.
type RPMMetaData struct {
	Name,
	Summary,
	Description,
	Version,
	Release,
	Arch,
	OS,
	Vendor,
	URL,
	Packager,
	Group,
	Licence,
	BuildHost,
	Compressor string
	Epoch     uint32
	BuildTime time.Time
	// Format selects the package format: FormatV4 (the default, also selected by
	// the zero value) or FormatV6 for the RPM v6 format written by rpm >= 6.0.
	// NewRPM fails for any other value.
	Format int
	// Prefixes is used for relocatable packages, usually with a one item
	// slice, e.g. `["/opt"]`.
	Prefixes []string
	// Distribution is the name of the distribution (e.g. "Fedora", "openSUSE").
	Distribution string
	// DistTag is the distribution tag of the release, e.g. ".fc43".
	DistTag string
	// DistURL is the URL of the distribution.
	DistURL string
	// BugURL is the URL for reporting bugs.
	BugURL string
	// VCS is the location of the source repository of the package.
	VCS string
	// SourceRPM is the file name of the source package. The default is
	// "name-version-release.src.rpm".
	SourceRPM string
	// BuildArchs lists the architectures the source package builds for.
	BuildArchs []string
	// Platform is the platform the package was built for, e.g. "x86_64-redhat-linux".
	Platform string
	// OptFlags are the compiler flags of the build.
	OptFlags string
	// Cookie identifies the build.
	Cookie string
	// ModularityLabel is the "name:stream:version:context" of the module the
	// package belongs to.
	ModularityLabel string
	// TranslationURL is the location of the translations of the package.
	TranslationURL string
	// Sysusers are the lines of the systemd-sysusers configuration the package
	// installs. The users and groups they create are provided as user(name) and
	// group(name).
	Sysusers []string
	// Translations holds the summary, description and group per language.
	Translations map[string]Translation
	// Changelog is the list of changelog entries, newest first.
	Changelog []ChangelogEntry
	// FileDigestAlgo selects the digest of the files: DigestSHA256 (the default,
	// also selected by zero), DigestSHA512, DigestSHA3256 or DigestSHA3512.
	FileDigestAlgo int
	// ClampTime, when set, is the latest time recorded in the package: file
	// modification times and the build time after it are set to it, which
	// makes packages reproducible, as SOURCE_DATE_EPOCH does for rpmbuild.
	ClampTime time.Time
	// ImplicitDirs adds the missing parent directories of all files as owned
	// directories (mode 0755, owned by root), so that the package owns the whole
	// tree it installs.
	ImplicitDirs bool
	// OwnerDeps adds a requirement for user(name) and group(name) of every file
	// owner other than root, as rpmbuild does.
	OwnerDeps bool
	// TempDir is where the compressed payload is held while the package is
	// written. The default is the directory for temporary files of the system.
	TempDir string
	Provides,
	Obsoletes,
	Suggests,
	Recommends,
	Requires,
	Conflicts,
	Enhances,
	Supplements,
	// OrderWithRequires adds ordering hints that do not require the packages.
	OrderWithRequires Relations
}

// Signer produces an OpenPGP signature of the data it reads.
type Signer func(data io.Reader) ([]byte, error)

// RPM holds the state of a particular rpm file. Please use NewRPM to instantiate it.
type RPM struct {
	RPMMetaData
	comp         *compressor
	closed       bool
	files        map[string]RPMFile
	scripts      [numScriptKinds]Scriptlet
	triggers     []Trigger
	fileTriggers []FileTrigger
	customTags   map[int]IndexEntry
	customSigs   map[int]IndexEntry
	pgpSigner    Signer
	fileSigning  *FileSigning
}

// NewRPM creates and returns a new RPM struct.
func NewRPM(m RPMMetaData) (*RPM, error) {
	switch m.Format {
	case 0:
		m.Format = FormatV4
	case FormatV4, FormatV6:
	default:
		return nil, fmt.Errorf("unsupported rpm format %d, want %d or %d", m.Format, FormatV4, FormatV6)
	}

	if m.OS == "" {
		m.OS = "linux"
	}

	if m.Arch == "" {
		m.Arch = "noarch"
	}

	if m.FileDigestAlgo == 0 {
		m.FileDigestAlgo = DigestSHA256
	}
	if _, err := newFileHash(m.FileDigestAlgo); err != nil {
		return nil, err
	}

	comp, err := parseCompressor(m.Compressor)
	if err != nil {
		return nil, err
	}
	// only use compressor name for the rpm tag, not the level
	m.Compressor = comp.name

	rpm := &RPM{
		RPMMetaData: m,
		comp:        comp,
		files:       make(map[string]RPMFile),
		customTags:  make(map[int]IndexEntry),
		customSigs:  make(map[int]IndexEntry),
	}

	// A package must provide itself...
	rpm.Provides.addIfMissing(&Relation{
		Name:    rpm.Name,
		Version: rpm.evr(),
		Sense:   SenseEqual,
	})

	return rpm, nil
}

// FullVersion properly combines version and release fields to a version string
func (r *RPM) FullVersion() string {
	if r.Release != "" {
		return fmt.Sprintf("%s-%s", r.Version, r.Release)
	}

	return r.Version
}

// evr is the version with its epoch, as dependencies on the package name it.
func (r *RPM) evr() string {
	if r.Epoch != NoEpoch {
		return fmt.Sprintf("%d:%s", r.Epoch, r.FullVersion())
	}
	return r.FullVersion()
}

// AllowListDirs removes all directories which are not explicitly allowlisted.
func (r *RPM) AllowListDirs(allowList map[string]bool) {
	for fn, ff := range r.files {
		if ff.Mode&040000 == 040000 {
			if !allowList[fn] {
				delete(r.files, fn)
			}
		}
	}
}

// AddFile adds an RPMFile to an existing rpm.
func (r *RPM) AddFile(f RPMFile) {
	if f.Name == "/" { // rpm does not allow the root dir to be included.
		return
	}
	r.files[f.Name] = f
}

// SetPGPSigner registers a function that will read the header, or the header
// and the payload, and return a signature as bytes. The function should simulate
// what gpg does, probably by using golang.org/x/crypto/openpgp or by running a gpg
// process. The data is streamed, so it can be larger than the memory.
func (r *RPM) SetPGPSigner(f Signer) {
	r.pgpSigner = f
}

// AddCustomTag adds or overwrites a tag value in the index.
func (r *RPM) AddCustomTag(tag int, e IndexEntry) {
	r.customTags[tag] = e
}

// AddCustomSig adds or overwrites a signature tag value.
func (r *RPM) AddCustomSig(tag int, e IndexEntry) {
	r.customSigs[tag] = e
}

// Write closes the rpm and writes the whole rpm to an io.Writer. The payload is
// compressed into a temporary file while the files are read, so that packages
// larger than the memory can be written; only the headers are held in memory.
func (r *RPM) Write(w io.Writer) error {
	if r.closed {
		return ErrWriteAfterClose
	}
	// Validate everything before any state is consumed, so that a failed
	// validation leaves the rpm usable.
	if err := r.validateMetadata(); err != nil {
		return err
	}
	if err := r.validateScripts(); err != nil {
		return err
	}
	if r.fileSigning != nil {
		if err := r.fileSigning.validate(r.FileDigestAlgo); err != nil {
			return err
		}
	}
	files, err := r.prepareFiles()
	if err != nil {
		return err
	}
	// The file sources are consumed by writing.
	r.closed = true

	pl, err := r.buildPayload(files)
	if err != nil {
		return err
	}
	defer pl.spool.close()

	h, err := r.buildHeader(files, pl)
	if err != nil {
		return err
	}
	hb, err := h.Bytes()
	if err != nil {
		return fmt.Errorf("failed to retrieve header: %w", err)
	}

	leadBytes := rpmhdr.Lead(r.Name, r.FullVersion())
	if r.Format == FormatV6 {
		leadBytes = rpmhdr.LeadV6(r.Name, r.FullVersion())
	}
	if _, err := w.Write(leadBytes); err != nil {
		return fmt.Errorf("failed to write lead: %w", err)
	}
	sb, err := r.signatureHeader(hb, files, pl)
	if err != nil {
		return fmt.Errorf("failed to create signatures: %w", err)
	}
	if _, err := w.Write(sb); err != nil {
		return fmt.Errorf("failed to write signature bytes: %w", err)
	}
	if _, err := w.Write(hb); err != nil {
		return fmt.Errorf("failed to write header body: %w", err)
	}
	if _, err := io.Copy(w, pl.spool.reader(pl.compressedSize)); err != nil {
		return fmt.Errorf("failed to write payload: %w", err)
	}
	return nil
}

// signatureHeader returns the signature header of the package, padded to 8 bytes.
func (r *RPM) signatureHeader(hb []byte, files []*fileEntry, pl *payloadResult) ([]byte, error) {
	if r.Format == FormatV6 {
		return r.signatureHeaderV6(hb, files, pl)
	}
	s := rpmhdr.NewIndex(tag.RPMTAG_HEADERSIGNATURES)
	if err := r.writeSignatures(s, hb, pl); err != nil {
		return nil, err
	}
	if err := r.addFileSignatures(s, files); err != nil {
		return nil, err
	}
	s.AddEntries(r.customSigs)
	sb, err := s.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve signatures header: %w", err)
	}
	// Signatures are padded to 8-byte boundaries
	return append(sb, make([]byte, rpmhdr.Pad8(len(sb)))...), nil
}

func (r *RPM) writeSignatures(sigHeader *rpmhdr.Index, regHeader []byte, pl *payloadResult) error {
	addSignatureSizes(sigHeader, uint64(pl.compressedSize)+uint64(len(regHeader)), uint64(pl.rawSize))
	sigHeader.Add(tag.SIG_SHA256, EntryString(fmt.Sprintf("%x", sha256.Sum256(regHeader))))
	if r.pgpSigner == nil {
		return nil
	}
	// For sha 256 you need to sign the header and payload separately
	headerSig, err := r.pgpSigner(bytes.NewReader(regHeader))
	if err != nil {
		return fmt.Errorf("call to signer failed: %w", err)
	}
	sigHeader.Add(tag.SIG_RSA, EntryBytes(headerSig))

	body := io.MultiReader(bytes.NewReader(regHeader), pl.spool.reader(pl.compressedSize))
	bodySig, err := r.pgpSigner(body)
	if err != nil {
		return fmt.Errorf("call to signer failed: %w", err)
	}
	sigHeader.Add((tag.SIG_PGP - tag.SIGHEADER_TAG_BASE), EntryBytes(bodySig))
	return nil
}

// addInstalledSize adds the total installed size of a v4 package: the 32 bit SIZE
// tag, or the 64 bit LONGSIZE tag when it does not fit, as rpmbuild does.
func addInstalledSize(h *rpmhdr.Index, size uint64) {
	if size > math.MaxUint32 {
		h.Add(tag.LONGSIZE, EntryUint64([]uint64{size}))
		return
	}
	h.Add(tag.SIZE, EntryUint32([]uint32{uint32(size)}))
}

// addSignatureSizes adds the sizes of the header plus payload and of the
// uncompressed payload to a v4 signature header, using the 64 bit LONGSIGSIZE and
// LONGARCHIVESIZE tags when they do not fit in 32 bits, as rpmbuild does.
func addSignatureSizes(s *rpmhdr.Index, headerAndPayload, archive uint64) {
	if headerAndPayload > math.MaxUint32 {
		s.Add(tag.SIG_LONGSIGSIZE, EntryUint64([]uint64{headerAndPayload}))
	} else {
		s.Add((tag.SIG_SIZE - tag.SIGHEADER_TAG_BASE), EntryUint32([]uint32{uint32(headerAndPayload)}))
	}
	if archive > math.MaxUint32 {
		s.Add(tag.SIG_LONGARCHIVESIZE, EntryUint64([]uint64{archive}))
	} else {
		s.Add((tag.SIG_PAYLOADSIZE - tag.SIGHEADER_TAG_BASE), EntryUint32([]uint32{uint32(archive)}))
	}
}

// validateMetadata checks that the package metadata can be represented in the header.
func (r *RPM) validateMetadata() error {
	strs := []string{
		r.Name, r.Summary, r.Description, r.Version, r.Release, r.Arch, r.OS, r.Vendor,
		r.URL, r.Packager, r.Group, r.Licence, r.BuildHost, r.Distribution, r.BugURL,
		r.DistTag, r.DistURL, r.VCS, r.SourceRPM, r.Platform, r.OptFlags, r.Cookie,
		r.ModularityLabel, r.TranslationURL,
	}
	for kind := range r.scripts {
		strs = append(strs, r.scripts[kind].Script)
	}
	strs = append(strs, r.Prefixes...)
	strs = append(strs, r.BuildArchs...)
	strs = append(strs, r.Sysusers...)
	for lang, t := range r.Translations {
		if lang == "" || lang == "C" {
			return fmt.Errorf("%w: translation language %q", ErrInvalidMetadata, lang)
		}
		strs = append(strs, lang, t.Summary, t.Description, t.Group)
	}
	for _, e := range r.Changelog {
		strs = append(strs, e.Author, e.Text)
	}
	for _, s := range strs {
		if hasNUL(s) {
			return fmt.Errorf("%w: value %q has an embedded NUL byte", ErrInvalidMetadata, s)
		}
	}
	for _, p := range r.Prefixes {
		if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
			return fmt.Errorf("%w: prefix %q is not a clean absolute path", ErrInvalidMetadata, p)
		}
	}
	for i, rels := range r.allRelations() {
		ctx := richAnd
		if i == conflictsIndex {
			ctx = richOr
		}
		for _, rel := range rels {
			if rel == nil {
				return fmt.Errorf("%w: nil relation", ErrInvalidMetadata)
			}
			if hasNUL(rel.Name) || hasNUL(rel.Version) {
				return fmt.Errorf("%w: relation %q has an embedded NUL byte", ErrInvalidMetadata, rel.Name)
			}
			if isRich(rel.Name) {
				if err := validateRich(rel.Name, ctx); err != nil {
					return err
				}
			}
		}
	}
	if !r.BuildTime.IsZero() {
		if err := checkTime32("build time", r.BuildTime); err != nil {
			return err
		}
	}
	if !r.ClampTime.IsZero() {
		if err := checkTime32("clamp time", r.ClampTime); err != nil {
			return err
		}
	}
	for _, e := range r.Changelog {
		if err := checkTime32("changelog time", e.Time); err != nil {
			return err
		}
	}
	return nil
}

// conflictsIndex is the position of Conflicts in allRelations: its boolean
// dependencies are evaluated with the opposite polarity.
const conflictsIndex = 5

func (r *RPM) allRelations() []Relations {
	return []Relations{
		r.Provides, r.Obsoletes, r.Suggests, r.Recommends, r.Requires, r.Conflicts, r.Enhances,
		r.Supplements, r.OrderWithRequires,
	}
}

func hasNUL(s string) bool { return strings.IndexByte(s, 0) >= 0 }

// checkTime32 checks that t fits the unsigned 32 bit time rpm stores in headers.
func checkTime32(what string, t time.Time) error {
	if u := t.Unix(); u < 0 || u > math.MaxUint32 {
		return fmt.Errorf("%w: %s %v is outside 1970..2106, the range of a 32 bit rpm time", ErrInvalidMetadata, what, t)
	}
	return nil
}

// sortedNames returns the keys of files in header order.
func sortedNames(files map[string]RPMFile) []string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}
