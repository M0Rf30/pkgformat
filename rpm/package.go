package rpm

import (
	"fmt"
	"io"
	"math"
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
}

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

	pkg.Files, pkg.FilesTruncated = gen.files(lim)
	pkg.Changelogs = gen.changelogs(lim.MaxArrayEntries)

	return pkg, nil
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
func (hdr *rpmHeader) files(lim PackageLimits) (files []FileEntry, truncated bool) {
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

	return files, truncated
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
