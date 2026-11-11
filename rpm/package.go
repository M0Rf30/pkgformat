package rpm

import (
	"fmt"
	"io"
	"math"
	"path"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/pathseg"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

const (
	// MaxPackageHeaderDataSize is the default bound on the data store of the
	// headers of [ReadPackage].
	MaxPackageHeaderDataSize = 1 << 24
	// MaxArrayEntries is the default bound on the entries kept of one array
	// of a package: a dependency list, the file list, the changelog.
	MaxArrayEntries = 100_000
	// MaxFileListBytes is the default bound on the total size of the strings
	// (path, digest, link target) kept for the file list of a package. Every
	// path is dirname+basename and all entries may reference the same
	// multi-megabyte dirname, so the entry count alone does not bound the
	// expanded size.
	MaxFileListBytes = 16 << 20
)

// FileEntry is one file of the file list of a package.
type FileEntry struct {
	// Path is the absolute path, directory name and base name joined.
	Path  string `json:"path"`
	MTime int64  `json:"mtime,omitempty"`
	// Mode is the file mode (type and permission bits) and Flags the
	// tag.RPMFILE_* bits; both are zero when the header omits them.
	Mode   uint32 `json:"mode,omitempty"`
	Flags  uint32 `json:"flags,omitempty"`
	Digest string `json:"digest,omitempty"`
	LinkTo string `json:"linkTo,omitempty"`
	// Size is the size of the file in bytes. User and Group name its owner.
	Size  int64  `json:"size,omitempty"`
	User  string `json:"user,omitempty"`
	Group string `json:"group,omitempty"`

	// Caps is the file capability set in the text form of cap_to_text(3),
	// for example "cap_net_raw=ep" (FILECAPS); empty for most files.
	Caps string `json:"caps,omitempty"`
	// Nlink is the number of hard links of the file within the package
	// (FILENLINKS). Older packages lack the tag: Nlink is then derived from
	// the device and inode numbers, and stays 0 when those are missing too.
	Nlink uint32 `json:"nlink,omitempty"`
	// Device and Inode are the numbers recorded when the package was built;
	// files with the same pair are hard links of each other. Rdev is the
	// device number of a device node.
	Device uint32 `json:"device,omitempty"`
	Inode  uint32 `json:"inode,omitempty"`
	Rdev   uint32 `json:"rdev,omitempty"`
	// Lang is the %lang of the file (FILELANGS), for example "de".
	Lang string `json:"lang,omitempty"`
	// Class is the description of the file type, as file(1) classifies it
	// (FILECLASS looked up in CLASSDICT), for example "directory".
	Class string `json:"class,omitempty"`
	// VerifyFlags are the checks "rpm -V" applies to the file: a mask of the
	// tag.RPMVERIFY_* bits (FILEVERIFYFLAGS), all bits set for the default.
	VerifyFlags uint32 `json:"verifyFlags,omitempty"`
	// Context is the SELinux context of the file (FILECONTEXTS).
	Context string `json:"context,omitempty"`
	// IMASignature is the IMA file signature (FILESIGNATURES), hex encoded;
	// see [Package.IMASignatureLength] and [VerifyIMASignature].
	IMASignature string `json:"imaSignature,omitempty"`
	// VeritySignature is the fs-verity signature of the file
	// (VERITYSIGNATURES of the signature header), hex encoded; see
	// [Package.VeritySignatureAlgorithm] and [VerifyVeritySignature].
	VeritySignature string `json:"veritySignature,omitempty"`
	// Depends lists the dependencies of the package that the file gave rise
	// to (FILEDEPENDSX, FILEDEPENDSN and DEPENDSDICT): the provides and
	// requires that the dependency generators found in it.
	Depends []FileDependency `json:"depends,omitempty"`
}

// FileDependency refers to a dependency of the package that was generated
// from a file.
type FileDependency struct {
	// Provide is true for an entry of Package.Provides, false for one of
	// Package.Requires.
	Provide bool `json:"provide,omitempty"`
	// Index is the position in that list.
	Index int `json:"index"`
}

// Dependency returns the dependency a file dependency refers to, and whether
// pkg has it.
func (d FileDependency) Dependency(pkg *Package) (Dependency, bool) {
	list := pkg.Requires
	if d.Provide {
		list = pkg.Provides
	}

	if d.Index < 0 || d.Index >= len(list) {
		return Dependency{}, false
	}

	return list[d.Index], true
}

// Verifies reports whether "rpm -V" applies every check of mask (the
// tag.RPMVERIFY_* bits) to the file.
func (f FileEntry) Verifies(mask uint32) bool { return f.VerifyFlags&mask == mask }

// IsSpec reports whether the entry is the spec file of a source package.
func (f FileEntry) IsSpec() bool { return f.Flags&tag.RPMFILE_SPECFILE != 0 }

// ChangelogEntry is one entry of the changelog of a package.
type ChangelogEntry struct {
	Time        int64  `json:"time"`
	Author      string `json:"author"`
	Description string `json:"description"`
}

// Package is the metadata of a binary or source package: what the headers
// carry, and what repository metadata (primary, filelists and other) lists.
// It is built from the headers by [ReadPackage] and [RpmHeader.Package], and
// is what the writers of repository metadata consume.
type Package struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Release     string `json:"release"`
	Epoch       uint32 `json:"epoch,omitempty"`
	Arch        string `json:"arch"`
	Summary     string `json:"summary,omitempty"`
	Description string `json:"description,omitempty"`
	License     string `json:"license,omitempty"`
	URL         string `json:"url,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	Group       string `json:"group,omitempty"`
	Packager    string `json:"packager,omitempty"`
	SourceRPM   string `json:"sourceRpm,omitempty"`
	BuildHost   string `json:"buildHost,omitempty"`
	BuildTime   int64  `json:"buildTime,omitempty"`
	// FileTime is when the file entered the repository (the <time file=>
	// value of primary.xml); zero falls back to BuildTime.
	FileTime int64 `json:"fileTime,omitempty"`
	// PackageSize is the size of the .rpm file. The headers do not carry it:
	// callers set it.
	PackageSize int64 `json:"packageSize,omitempty"`
	// InstalledSize is the size of the installed files.
	InstalledSize int64 `json:"installedSize,omitempty"`
	// InstallTime is when the package was installed, in seconds since the
	// epoch. Only the header of an installed package carries it: it is set by
	// [RpmHeader.InstalledPackage] and zero otherwise.
	InstallTime int64 `json:"installTime,omitempty"`
	// ArchiveSize is the size of the uncompressed payload.
	ArchiveSize int64 `json:"archiveSize,omitempty"`
	// SHA256 is the checksum of the .rpm file. The headers do not carry it:
	// callers set it.
	SHA256 string `json:"sha256,omitempty"`
	// HeaderStart and HeaderEnd are the byte offsets of the general header
	// within the .rpm file.
	HeaderStart int64        `json:"headerStart,omitempty"`
	HeaderEnd   int64        `json:"headerEnd,omitempty"`
	Provides    []Dependency `json:"provides,omitempty"`
	Requires    []Dependency `json:"requires,omitempty"`
	Conflicts   []Dependency `json:"conflicts,omitempty"`
	Obsoletes   []Dependency `json:"obsoletes,omitempty"`
	Recommends  []Dependency `json:"recommends,omitempty"`
	Suggests    []Dependency `json:"suggests,omitempty"`
	Supplements []Dependency `json:"supplements,omitempty"`
	Enhances    []Dependency `json:"enhances,omitempty"`

	Files      []FileEntry      `json:"files,omitempty"`
	Changelogs []ChangelogEntry `json:"changelogs,omitempty"`

	// Distribution, OS, BugURL and VCS are the tags of the same name.
	Distribution string `json:"distribution,omitempty"`
	OS           string `json:"os,omitempty"`
	BugURL       string `json:"bugUrl,omitempty"`
	VCS          string `json:"vcs,omitempty"`
	// RPMVersion is the version of rpm that built the package.
	RPMVersion string `json:"rpmVersion,omitempty"`
	// Format is the package format: 4, or 6 for the packages of rpm 6.
	Format int `json:"format,omitempty"`
	// Prefixes are the paths a relocatable package may be moved from.
	Prefixes []string `json:"prefixes,omitempty"`
	// ModularityLabel is the module stream the package belongs to,
	// "name:stream:version:context".
	ModularityLabel string `json:"modularityLabel,omitempty"`
	// DistTag is the %{dist} of the release (".fc41") and DistURL the
	// location the package was distributed from.
	DistTag string `json:"distTag,omitempty"`
	DistURL string `json:"distUrl,omitempty"`
	// BuildArchs are the architectures a source package is built for.
	BuildArchs []string `json:"buildArchs,omitempty"`
	// Cookie identifies the build ("host timestamp").
	Cookie string `json:"cookie,omitempty"`
	// Platform is the platform triplet the package was built for, for
	// example "x86_64-redhat-linux-gnu", and OptFlags the compiler flags.
	Platform string `json:"platform,omitempty"`
	OptFlags string `json:"optFlags,omitempty"`
	// Policies are the SELinux policy modules of the package.
	Policies []Policy `json:"policies,omitempty"`
	// SysUsers are the sysusers.d lines the package declares (%sysusers).
	SysUsers []string `json:"sysUsers,omitempty"`
	// Order lists the packages that must be installed in this transaction
	// before this one, as a dependency list (the ORDER* tags).
	Order []Dependency `json:"order,omitempty"`
	// IsSource is true for a source package.
	IsSource bool `json:"source,omitempty"`
	// ExcludeArch, ExclusiveArch, ExcludeOS and ExclusiveOS restrict where
	// the package is built (source packages).
	ExcludeArch   []string `json:"excludeArch,omitempty"`
	ExclusiveArch []string `json:"exclusiveArch,omitempty"`
	ExcludeOS     []string `json:"excludeOs,omitempty"`
	ExclusiveOS   []string `json:"exclusiveOs,omitempty"`
	// Sources and Patches list the sources and the patches of a source
	// package, including those it does not ship (%NoSource, %NoPatch).
	Sources []SourceFile `json:"sources,omitempty"`
	Patches []SourceFile `json:"patches,omitempty"`
	// Spec is the text of the spec file (a tag of rpm 6 source packages).
	Spec string `json:"spec,omitempty"`

	// Scripts are the scriptlets, Triggers the package triggers and
	// FileTriggers the file triggers and transaction file triggers.
	Scripts      Scripts       `json:"scripts,omitempty"`
	Triggers     []Trigger     `json:"triggers,omitempty"`
	FileTriggers []FileTrigger `json:"fileTriggers,omitempty"`

	// PayloadFormat, PayloadCompressor and PayloadFlags describe the
	// payload: "cpio", "zstd" and the compression level ("19").
	PayloadFormat     string `json:"payloadFormat,omitempty"`
	PayloadCompressor string `json:"payloadCompressor,omitempty"`
	PayloadFlags      string `json:"payloadFlags,omitempty"`
	// PayloadDigests are the digests of the payload, one per algorithm; see
	// [Rpm.SetVerifyPayloadDigest] for their use.
	PayloadDigests []PayloadDigest `json:"payloadDigests,omitempty"`
	// FileDigestAlgorithm is the number of the hash of Files[i].Digest
	// (FILEDIGESTALGO, 1 = MD5 for packages without the tag) and
	// FileDigestName its name, for example "sha256".
	FileDigestAlgorithm uint32 `json:"fileDigestAlgorithm,omitempty"`
	FileDigestName      string `json:"fileDigestName,omitempty"`
	// IMASignatureLength is the length in bytes of the IMA signatures of the
	// files (FILESIGNATURELENGTH); 0 when the package has none.
	IMASignatureLength uint32 `json:"imaSignatureLength,omitempty"`
	// VeritySignatureAlgorithm is the fs-verity digest algorithm of the
	// fs-verity signatures of the files: 1 for SHA-256, 2 for SHA-512; 0 when
	// the package has none.
	VeritySignatureAlgorithm uint32 `json:"veritySignatureAlgorithm,omitempty"`

	// FilesTruncated is true when the header declared more files than
	// PackageLimits.MaxArrayEntries or their strings exceeded
	// PackageLimits.MaxFileListBytes, so Files is only a prefix of the file
	// list of the package.
	FilesTruncated bool `json:"filesTruncated,omitempty"`
}

// PackageLimits bounds what [ReadPackage] keeps of a package read from
// untrusted input. A zero field selects its default.
type PackageLimits struct {
	// Header bounds the headers. The default data store is
	// [MaxPackageHeaderDataSize], smaller than that of [ReadHeader].
	Header HeaderLimits
	// MaxArrayEntries bounds every array: a dependency list over it rejects
	// the package, because dropping part of it would make the package
	// installable without its requirements; the file list and the changelog
	// are cut. Default [MaxArrayEntries].
	MaxArrayEntries int
	// MaxFileListBytes bounds the strings kept for the file list. Default
	// [MaxFileListBytes].
	MaxFileListBytes int
}

func (l PackageLimits) normalized() PackageLimits {
	if l.Header.MaxDataSize <= 0 {
		l.Header.MaxDataSize = MaxPackageHeaderDataSize
	}

	if l.MaxArrayEntries <= 0 {
		l.MaxArrayEntries = MaxArrayEntries
	}

	if l.MaxFileListBytes <= 0 {
		l.MaxFileListBytes = MaxFileListBytes
	}

	return l
}

// ReadPackage reads the lead and the headers of a package from r and returns
// its metadata, with the default [PackageLimits]. The payload is not read.
func ReadPackage(r io.Reader) (*Package, error) {
	return ReadPackageLimits(r, PackageLimits{})
}

// ReadPackageLimits is [ReadPackage] with explicit limits.
func ReadPackageLimits(r io.Reader, lim PackageLimits) (*Package, error) {
	lim = lim.normalized()

	hdr, err := ReadHeaderLimits(r, lim.Header)
	if err != nil {
		return nil, err
	}

	return hdr.Package(lim)
}

// Package returns the metadata of the package the headers describe.
// PackageSize and SHA256 are left for the caller to set. Limits that were not
// applied when the headers were read are applied to what is kept.
func (hdr *RpmHeader) Package(lim PackageLimits) (*Package, error) {
	return hdr.buildPackage(lim, true)
}

// buildPackage decodes the metadata of the header. A package file always
// carries an architecture; the header of an installed package may lack one
// (the gpg-pubkey pseudo packages do), which requireArch=false accepts.
func (hdr *RpmHeader) buildPackage(lim PackageLimits, requireArch bool) (*Package, error) {
	lim = lim.normalized()
	gen := hdr.genHeader

	pkg := &Package{
		Name:          gen.firstString(tag.NAME),
		Version:       gen.firstString(tag.VERSION),
		Release:       gen.firstString(tag.RELEASE),
		Epoch:         uint32(gen.firstNumber(tag.EPOCH)),
		Arch:          gen.firstString(tag.ARCH),
		Summary:       gen.firstString(tag.SUMMARY),
		Description:   gen.firstString(tag.DESCRIPTION),
		License:       gen.firstString(tag.LICENSE),
		URL:           gen.firstString(tag.URL),
		Vendor:        gen.firstString(tag.VENDOR),
		Group:         gen.firstString(tag.GROUP),
		Packager:      gen.firstString(tag.PACKAGER),
		SourceRPM:     gen.firstString(tag.SOURCERPM),
		BuildHost:     gen.firstString(tag.BUILDHOST),
		BuildTime:     int64(uint32(gen.firstNumber(tag.BUILDTIME))),
		HeaderStart:   int64(len(hdr.lead) + len(hdr.sigHeader.orig)),
		InstalledSize: size64(gen.firstNumber(tag.LONGSIZE, tag.SIZE)),
		ArchiveSize:   hdr.archiveSize(),
		InstallTime:   int64(uint32(gen.firstNumber(tag.INSTALLTIME))),
	}
	pkg.HeaderEnd = pkg.HeaderStart + int64(len(gen.orig))

	if err := pkg.validateIdentity(requireArch); err != nil {
		return nil, err
	}

	if err := pkg.readDependencies(gen, lim.MaxArrayEntries); err != nil {
		return nil, err
	}

	pkg.Files, pkg.FilesTruncated = gen.files(lim, hdr.sigHeader)
	pkg.Changelogs = gen.changelogs(lim.MaxArrayEntries)

	if err := pkg.readMetadata(hdr, lim); err != nil {
		return nil, err
	}

	return pkg, nil
}

// readMetadata fills the fields of the package beyond its identity,
// dependencies and files.
func (p *Package) readMetadata(hdr *RpmHeader, lim PackageLimits) error {
	gen := hdr.genHeader
	limit := lim.MaxArrayEntries

	p.Distribution = gen.firstString(tag.DISTRIBUTION)
	p.OS = gen.firstString(tag.OS)
	p.BugURL = gen.firstString(tag.BUGURL)
	p.VCS = gen.firstString(tag.VCS)
	p.RPMVersion = gen.firstString(tag.RPMVERSION)
	p.Format = hdr.Format()
	p.Prefixes, _ = gen.stringsPrefix(tag.PREFIXES, limit)
	p.ModularityLabel = gen.firstString(tag.MODULARITYLABEL)
	p.DistTag = gen.firstString(tag.DISTTAG)
	p.DistURL = gen.firstString(tag.DISTURL)
	p.BuildArchs, _ = gen.stringsPrefix(tag.BUILDARCHS, limit)
	p.Cookie = gen.firstString(tag.COOKIE)
	p.Platform = gen.firstString(tag.PLATFORM)
	p.OptFlags = gen.firstString(tag.OPTFLAGS)
	p.Policies = gen.policies(limit)
	p.SysUsers, _ = gen.stringsPrefix(tag.SYSUSERS, limit)
	p.Order, _ = gen.dependencies(tag.ORDERNAME, tag.ORDERFLAGS, tag.ORDERVERSION, limit)
	p.IsSource = hdr.isSource || gen.firstNumber(tag.SOURCEPACKAGE) != 0
	p.ExcludeArch, _ = gen.stringsPrefix(tag.EXCLUDEARCH, limit)
	p.ExclusiveArch, _ = gen.stringsPrefix(tag.EXCLUSIVEARCH, limit)
	p.ExcludeOS, _ = gen.stringsPrefix(tag.EXCLUDEOS, limit)
	p.ExclusiveOS, _ = gen.stringsPrefix(tag.EXCLUSIVEOS, limit)
	p.Spec = gen.firstString(tag.SPEC)
	p.PayloadFormat = gen.firstString(tag.PAYLOADFORMAT)
	p.PayloadCompressor = gen.firstString(tag.PAYLOADCOMPRESSOR)
	p.PayloadFlags = gen.firstString(tag.PAYLOADFLAGS)
	p.PayloadDigests = gen.payloadDigests()
	p.FileDigestAlgorithm = uint32(gen.firstNumber(tag.FILEDIGESTALGO))

	if p.FileDigestAlgorithm == 0 && len(p.Files) > 0 {
		p.FileDigestAlgorithm = tag.HASH_MD5
	}

	p.FileDigestName = DigestAlgorithmName(p.FileDigestAlgorithm)
	p.IMASignatureLength = uint32(gen.firstNumber(tag.FILESIGNATURELENGTH))
	if p.IMASignatureLength == 0 {
		p.IMASignatureLength = uint32(hdr.sigHeader.firstNumber(tag.SIG_FILESIGNATURELENGTH))
	}
	p.VeritySignatureAlgorithm = uint32(hdr.sigHeader.firstNumber(tag.SIG_VERITYSIGNATUREALGO))

	if p.IsSource {
		ghosts := map[string]bool{}

		for _, f := range p.Files {
			if f.IsGhost() {
				ghosts[path.Base(f.Path)] = true
			}
		}

		p.Sources = gen.readSources(tag.SOURCE, tag.NOSOURCE, limit, ghosts)
		p.Patches = gen.readSources(tag.PATCH, tag.NOPATCH, limit, ghosts)
	}

	p.Scripts = gen.scripts()

	var err error
	if p.Triggers, err = gen.triggers(limit); err != nil {
		return err
	}

	p.FileTriggers, err = gen.fileTriggers(limit)

	return err
}

// BuildRequires returns the build requirements of a source package: its
// Requires list, which for a source package holds the BuildRequires of the
// spec file, including the rpmlib(...) features needed to build it. It is nil
// for a binary package.
func (p *Package) BuildRequires() []Dependency {
	if !p.IsSource {
		return nil
	}

	return p.Requires
}

// BuildConflicts returns the build conflicts of a source package: its
// Conflicts list, which holds the BuildConflicts of the spec file. It is nil
// for a binary package.
func (p *Package) BuildConflicts() []Dependency {
	if !p.IsSource {
		return nil
	}

	return p.Conflicts
}

// archiveSize returns the uncompressed payload size: format 4 packages carry
// it in the signature header (LONGARCHIVESIZE, else PAYLOADSIZE); format 6
// packages moved it to the general header as PAYLOADSIZEALT, and their
// signature PAYLOADSIZE is the compressed size.
func (hdr *RpmHeader) archiveSize() int64 {
	const sigPayloadSize = tag.SIG_PAYLOADSIZE - tag.SIGHEADER_TAG_BASE

	if v := hdr.sigHeader.firstNumber(tag.SIG_LONGARCHIVESIZE, sigPayloadSize); v > 0 {
		return size64(v)
	}

	return size64(hdr.genHeader.firstNumber(tag.PAYLOADSIZEALT))
}

// size64 converts a size read from a header; a value that does not fit an
// int64 is bogus and reads as 0.
func size64(v uint64) int64 {
	if v > math.MaxInt64 {
		return 0
	}

	return int64(v)
}

// firstString returns the first string of a string tag, or "".
func (hdr *rpmHeader) firstString(id int) string {
	if strs, _ := hdr.stringsPrefix(id, 1); len(strs) > 0 {
		return strs[0]
	}

	return ""
}

// firstNumber returns the first value of the first of the integer tags that
// is present with a value, or 0.
func (hdr *rpmHeader) firstNumber(ids ...int) uint64 {
	for _, id := range ids {
		if vals, _ := hdr.numbersPrefix(id, 1); len(vals) > 0 {
			return vals[0]
		}
	}

	return 0
}

// validateIdentity rejects a package missing identity tags, or with
// characters that are unsafe in a file name.
func (p *Package) validateIdentity(requireArch bool) error {
	for _, f := range []struct{ name, value string }{
		{"NAME", p.Name}, {"VERSION", p.Version}, {"RELEASE", p.Release}, {"ARCH", p.Arch},
	} {
		if f.value == "" && f.name == "ARCH" && !requireArch {
			continue
		}

		if f.value == "" {
			return fmt.Errorf("%w: missing %s tag", ErrInvalidHeader, f.name)
		}

		if !pathseg.Name(f.value) || strings.ContainsAny(f.value, " \t\r\n") {
			return fmt.Errorf("%w: invalid characters in %s tag", ErrInvalidHeader, f.name)
		}
	}

	return nil
}

// readDependencies fills every dependency list of the package. A list over
// the cap rejects the package.
func (p *Package) readDependencies(h *rpmHeader, limit int) error {
	for _, d := range []struct {
		dst                   *[]Dependency
		name, flags, versions int
	}{
		{&p.Provides, tag.PROVIDENAME, tag.PROVIDEFLAGS, tag.PROVIDEVERSION},
		{&p.Requires, tag.REQUIRENAME, tag.REQUIREFLAGS, tag.REQUIREVERSION},
		{&p.Conflicts, tag.CONFLICTNAME, tag.CONFLICTFLAGS, tag.CONFLICTVERSION},
		{&p.Obsoletes, tag.OBSOLETENAME, tag.OBSOLETEFLAGS, tag.OBSOLETEVERSION},
		{&p.Recommends, tag.RECOMMENDNAME, tag.RECOMMENDFLAGS, tag.RECOMMENDVERSION},
		{&p.Suggests, tag.SUGGESTNAME, tag.SUGGESTFLAGS, tag.SUGGESTVERSION},
		{&p.Supplements, tag.SUPPLEMENTNAME, tag.SUPPLEMENTFLAGS, tag.SUPPLEMENTVERSION},
		{&p.Enhances, tag.ENHANCENAME, tag.ENHANCEFLAGS, tag.ENHANCEVERSION},
	} {
		if _, n := h.stringsPrefix(d.name, 0); n > limit {
			return fmt.Errorf("%w: tag %d declares %d entries, at most %d", ErrHeaderTooLarge, d.name, n, limit)
		}

		// A malformed list is skipped rather than failing the package.
		*d.dst, _ = h.dependencies(d.name, d.flags, d.versions, limit)
	}

	return nil
}

// files decodes the file list. It keeps at most lim.MaxArrayEntries files and
// lim.MaxFileListBytes of strings, and reports whether it stopped early.
func (hdr *rpmHeader) files(lim PackageLimits, sig *rpmHeader) (files []FileEntry, truncated bool) {
	bases, declared := hdr.stringsPrefix(tag.BASENAMES, lim.MaxArrayEntries)
	if len(bases) == 0 {
		return nil, false
	}

	truncated = declared > len(bases)

	dirNames, _ := hdr.stringsPrefix(tag.DIRNAMES, lim.MaxArrayEntries)
	dirIdx, _ := hdr.numbersPrefix(tag.DIRINDEXES, len(bases))
	mtimes, _ := hdr.numbersPrefix(tag.FILEMTIMES, len(bases))
	digests, _ := hdr.stringsPrefix(tag.FILEDIGESTS, len(bases))
	linktos, _ := hdr.stringsPrefix(tag.FILELINKTOS, len(bases))
	users, _ := hdr.stringsPrefix(tag.FILEUSERNAME, len(bases))
	groups, _ := hdr.stringsPrefix(tag.FILEGROUPNAME, len(bases))
	sizes, _ := hdr.numbersPrefix(tag.LONGFILESIZES, len(bases))

	if len(sizes) == 0 {
		sizes, _ = hdr.numbersPrefix(tag.FILESIZES, len(bases))
	}

	modes, _ := hdr.numbersPrefix(tag.FILEMODES, len(bases))
	flags, _ := hdr.numbersPrefix(tag.FILEFLAGS, len(bases))

	budget := lim.MaxFileListBytes
	files = make([]FileEntry, 0, len(bases))

	for i, base := range bases {
		dir := ""
		if i < len(dirIdx) && dirIdx[i] < uint64(len(dirNames)) {
			dir = dirNames[dirIdx[i]]
		}

		entry := FileEntry{}

		if i < len(digests) {
			entry.Digest = digests[i]
		}

		if i < len(linktos) {
			entry.LinkTo = linktos[i]
		}

		// Check before concatenating: dir may be megabytes long.
		if i < len(users) {
			entry.User = users[i]
		}

		if i < len(groups) {
			entry.Group = groups[i]
		}

		cost := len(dir) + len(base) + len(entry.Digest) + len(entry.LinkTo) + len(entry.User) + len(entry.Group)
		if cost > budget {
			truncated = true

			break
		}

		budget -= cost
		entry.Path = dir + base

		if i < len(mtimes) {
			entry.MTime = int64(uint32(mtimes[i]))
		}

		if i < len(sizes) {
			entry.Size = size64(sizes[i])
		}

		if i < len(modes) {
			entry.Mode = uint32(modes[i])
		}

		if i < len(flags) {
			entry.Flags = uint32(flags[i])
		}

		files = append(files, entry)
	}

	hdr.fileExtras(files, sig)

	return files, truncated
}

// fileExtras fills the per-file metadata beyond the basic attributes.
func (hdr *rpmHeader) fileExtras(files []FileEntry, sig *rpmHeader) {
	n := len(files)
	caps, _ := hdr.stringsPrefix(tag.FILECAPS, n)
	nlinks, _ := hdr.numbersPrefix(tag.FILENLINKS, n)
	devices, _ := hdr.numbersPrefix(tag.FILEDEVICES, n)
	inodes, _ := hdr.numbersPrefix(tag.FILEINODES, n)
	rdevs, _ := hdr.numbersPrefix(tag.FILERDEVS, n)
	langs, _ := hdr.stringsPrefix(tag.FILELANGS, n)
	classIdx, _ := hdr.numbersPrefix(tag.FILECLASS, n)
	classDict, _ := hdr.stringsPrefix(tag.CLASSDICT, n+1024)
	verify, _ := hdr.numbersPrefix(tag.FILEVERIFYFLAGS, n)
	contexts, _ := hdr.stringsPrefix(tag.FILECONTEXTS, n)
	imaSigs, _ := hdr.stringsPrefix(tag.FILESIGNATURES, n)
	depX, _ := hdr.numbersPrefix(tag.FILEDEPENDSX, n)
	depN, _ := hdr.numbersPrefix(tag.FILEDEPENDSN, n)
	depDict, _ := hdr.numbersPrefix(tag.DEPENDSDICT, 1<<20)

	var veritySigs []string
	if sig != nil {
		veritySigs, _ = sig.stringsPrefix(tag.SIG_VERITYSIGNATURES, n)
		// rpmsign --signfiles stores them in the signature header; rpm
		// moves them into the main header when it installs the package
		if len(imaSigs) == 0 {
			imaSigs, _ = sig.stringsPrefix(tag.SIG_FILESIGNATURES, n)
		}
	}

	at := func(s []string, i int) string {
		if i < len(s) {
			return s[i]
		}

		return ""
	}

	links := map[[2]uint64]uint32{}

	for i := range files {
		f := &files[i]
		f.Caps = at(caps, i)
		f.Lang = at(langs, i)
		f.Context = at(contexts, i)
		f.IMASignature = at(imaSigs, i)
		f.VeritySignature = at(veritySigs, i)

		if i < len(devices) {
			f.Device = uint32(devices[i])
		}

		if i < len(inodes) {
			f.Inode = uint32(inodes[i])
		}

		if i < len(rdevs) {
			f.Rdev = uint32(rdevs[i])
		}

		if i < len(verify) {
			f.VerifyFlags = uint32(verify[i])
		}

		if i < len(classIdx) && classIdx[i] < uint64(len(classDict)) {
			f.Class = classDict[classIdx[i]]
		}

		if i < len(depX) && i < len(depN) {
			start, count := depX[i], depN[i]
			for j := start; j < start+count && j < uint64(len(depDict)); j++ {
				v := uint32(depDict[j])
				f.Depends = append(f.Depends, FileDependency{
					Provide: v>>24 == 'P',
					Index:   int(v & 0x00ffffff),
				})
			}
		}

		if i < len(nlinks) {
			f.Nlink = uint32(nlinks[i])
		} else if i < len(devices) && i < len(inodes) {
			links[[2]uint64{devices[i], inodes[i]}]++
		}
	}

	if len(nlinks) == 0 && len(links) > 0 {
		for i := range files {
			f := &files[i]
			if f.Inode != 0 {
				f.Nlink = links[[2]uint64{uint64(f.Device), uint64(f.Inode)}]
			}
		}
	}
}

func (hdr *rpmHeader) changelogs(limit int) []ChangelogEntry {
	times, _ := hdr.numbersPrefix(tag.CHANGELOGTIME, limit)
	if times == nil {
		return nil
	}

	authors, _ := hdr.stringsPrefix(tag.CHANGELOGNAME, len(times))
	texts, _ := hdr.stringsPrefix(tag.CHANGELOGTEXT, len(times))

	entries := make([]ChangelogEntry, len(times))
	for i, t := range times {
		entries[i].Time = int64(uint32(t))

		if i < len(authors) {
			entries[i].Author = authors[i]
		}

		if i < len(texts) {
			entries[i].Description = texts[i]
		}
	}

	return entries
}

// IsDir reports whether the entry is a directory.
func (f FileEntry) IsDir() bool { return f.Mode&modeTypeMask == modeDir }

// IsGhost reports whether the entry is a %ghost file: owned by the package but
// not shipped in its payload.
func (f FileEntry) IsGhost() bool { return f.Flags&tag.RPMFILE_GHOST != 0 }

const (
	modeTypeMask = 0o170000
	modeDir      = 0o040000
)
