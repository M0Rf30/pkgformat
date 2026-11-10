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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/rpm/cpio"
	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
	"github.com/M0Rf30/pkgformat/rpm/tag"
	"github.com/klauspost/compress/zstd"
	gzip "github.com/klauspost/pgzip"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
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

var (
	// ErrWriteAfterClose is returned when a user calls Write() on a closed rpm.
	ErrWriteAfterClose = errors.New("rpm write after close")
	// ErrWrongFileOrder is returned when files are not sorted by name.
	ErrWrongFileOrder = errors.New("wrong file addition order")
	// ErrInvalidFile is returned by Write when a file added with AddFile cannot be
	// represented in an rpm: a name that is not a clean absolute path, embedded NUL
	// bytes, mode bits outside the 16 bit rpm file mode, or (for the v4 format) a
	// body larger than the 4 GiB limit of the cpio payload.
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
	// BugURL is the URL for reporting bugs.
	BugURL string
	// Changelog is the list of changelog entries, newest first.
	Changelog []ChangelogEntry
	Provides,
	Obsoletes,
	Suggests,
	Recommends,
	Requires,
	Conflicts,
	Enhances,
	Supplements Relations
}

// RPM holds the state of a particular rpm file. Please use NewRPM to instantiate it.
type RPM struct {
	RPMMetaData
	di                *dirIndex
	payload           *bytes.Buffer
	payloadSize       uint64
	cpio              *cpio.Writer
	basenames         []string
	dirindexes        []uint32
	filesizes         []uint32
	filemodes         []uint16
	fileowners        []string
	filegroups        []string
	filemtimes        []uint32
	filedigests       []string
	filelinktos       []string
	fileflags         []uint32
	closed            bool
	compressedPayload io.WriteCloser
	files             map[string]RPMFile
	prein             string
	postin            string
	preun             string
	postun            string
	pretrans          string
	posttrans         string
	verifyscript      string
	customTags        map[int]IndexEntry
	customSigs        map[int]IndexEntry
	pgpSigner         func([]byte) ([]byte, error)
	// v6 is only set when writing the RPM v6 format.
	v6 *v6State
}

// NewRPM creates and returns a new RPM struct.
func NewRPM(m RPMMetaData) (*RPM, error) {
	var err error

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

	p := &bytes.Buffer{}

	z, compressorName, err := setupCompressor(m.Compressor, p)
	if err != nil {
		return nil, err
	}

	// only use compressor name for the rpm tag, not the level
	m.Compressor = compressorName

	rpm := &RPM{
		RPMMetaData:       m,
		di:                newDirIndex(),
		payload:           p,
		compressedPayload: z,
		files:             make(map[string]RPMFile),
		customTags:        make(map[int]IndexEntry),
		customSigs:        make(map[int]IndexEntry),
	}

	if m.Format == FormatV6 {
		rpm.v6 = newV6State(z)
		rpm.cpio = cpio.NewStrippedWriter(rpm.v6.out)
	} else {
		rpm.cpio = cpio.NewWriter(z)
	}

	// A package must provide itself...
	rpm.Provides.addIfMissing(&Relation{
		Name:    rpm.Name,
		Version: rpm.FullVersion(),
		Sense:   SenseEqual,
	})

	return rpm, nil
}

func setupCompressor(
	compressorSetting string,
	w io.Writer,
) (wc io.WriteCloser, compressorType string, err error) {
	parts := strings.Split(compressorSetting, ":")
	if len(parts) > 2 {
		return nil, "", fmt.Errorf("malformed compressor setting: %s", compressorSetting)
	}

	compressorType = parts[0]
	compressorLevel := ""
	if len(parts) == 2 {
		compressorLevel = parts[1]
	}

	switch compressorType {
	case "":
		compressorType = "gzip"
		fallthrough
	case "gzip":
		level := 9

		if compressorLevel != "" {
			var err error

			level, err = strconv.Atoi(compressorLevel)
			if err != nil {
				return nil, "", fmt.Errorf("parse gzip compressor level: %w", err)
			}
		}

		wc, err = gzip.NewWriterLevel(w, level)
	case "lzma":
		if compressorLevel != "" {
			return nil, "", fmt.Errorf("no compressor level supported for lzma: %s", compressorLevel)
		}

		wc, err = lzma.NewWriter(w)
	case "xz":
		if compressorLevel != "" {
			return nil, "", fmt.Errorf("no compressor level supported for xz: %s", compressorLevel)
		}

		wc, err = xz.NewWriter(w)
	case "zstd":
		level := zstd.SpeedBetterCompression

		if compressorLevel != "" {
			var ok bool

			if intLevel, err := strconv.Atoi(compressorLevel); err == nil {
				level = zstd.EncoderLevelFromZstd(intLevel)
			} else {
				ok, level = zstd.EncoderLevelFromString(compressorLevel)
				if !ok {
					return nil, "", fmt.Errorf("invalid zstd compressor level: %s", compressorLevel)
				}
			}
		}

		wc, err = zstd.NewWriter(w, zstd.WithEncoderLevel(level))
	default:
		return nil, "", fmt.Errorf("unknown compressor type: %s", compressorType)
	}

	return wc, compressorType, err
}

// FullVersion properly combines version and release fields to a version string
func (r *RPM) FullVersion() string {
	if r.Release != "" {
		return fmt.Sprintf("%s-%s", r.Version, r.Release)
	}

	return r.Version
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

// Write closes the rpm and writes the whole rpm to an io.Writer
func (r *RPM) Write(w io.Writer) error {
	if r.closed {
		return ErrWriteAfterClose
	}
	// Validate everything before any state is consumed, so that a failed
	// validation leaves the rpm usable.
	if err := r.validateMetadata(); err != nil {
		return err
	}
	fnames := make([]string, 0, len(r.files))
	for fn := range r.files {
		fnames = append(fnames, fn)
	}
	sort.Strings(fnames)
	for _, fn := range fnames {
		if err := r.validateFile(r.files[fn]); err != nil {
			return err
		}
	}
	// The payload compressor and the file indexes are consumed by writing.
	r.closed = true
	// Add all of the files, sorted alphabetically.
	for _, fn := range fnames {
		if err := r.writeFile(r.files[fn]); err != nil {
			return fmt.Errorf("failed to write file %q: %w", fn, err)
		}
	}
	if err := r.cpio.Close(); err != nil {
		return fmt.Errorf("failed to close cpio payload: %w", err)
	}
	if err := r.compressedPayload.Close(); err != nil {
		return fmt.Errorf("failed to close %s payload: %w", r.Compressor, err)
	}

	leadBytes := rpmhdr.Lead(r.Name, r.FullVersion())
	if r.v6 != nil {
		leadBytes = rpmhdr.LeadV6(r.Name, r.FullVersion())
	}
	if _, err := w.Write(leadBytes); err != nil {
		return fmt.Errorf("failed to write lead: %w", err)
	}
	// Write the regular header.
	h := rpmhdr.NewIndex(tag.RPMTAG_HEADERIMMUTABLE)
	r.writeGenIndexes(h)

	// do not write file indexes if there are no files (meta package)
	// doing so will result in an invalid package
	if (len(r.files)) > 0 {
		r.writeFileIndexes(h)
	}

	if err := r.writeRelationIndexes(h); err != nil {
		return err
	}
	// CustomTags must be the last to be added, because they can overwrite values.
	h.AddEntries(r.customTags)
	hb, err := h.Bytes()
	if err != nil {
		return fmt.Errorf("failed to retrieve header: %w", err)
	}
	// Write the signatures
	if r.v6 != nil {
		sb, err := r.signatureHeaderV6(hb)
		if err != nil {
			return fmt.Errorf("failed to create signatures: %w", err)
		}
		if _, err := w.Write(sb); err != nil {
			return fmt.Errorf("failed to write signature bytes: %w", err)
		}
	} else {
		s := rpmhdr.NewIndex(tag.RPMTAG_HEADERSIGNATURES)
		if err := r.writeSignatures(s, hb); err != nil {
			return fmt.Errorf("failed to create signatures: %w", err)
		}

		s.AddEntries(r.customSigs)
		sb, err := s.Bytes()
		if err != nil {
			return fmt.Errorf("failed to retrieve signatures header: %w", err)
		}

		if _, err := w.Write(sb); err != nil {
			return fmt.Errorf("failed to write signature bytes: %w", err)
		}
		// Signatures are padded to 8-byte boundaries
		if _, err := w.Write(make([]byte, rpmhdr.Pad8(len(sb)))); err != nil {
			return fmt.Errorf("failed to write signature padding: %w", err)
		}
	}
	if _, err := w.Write(hb); err != nil {
		return fmt.Errorf("failed to write header body: %w", err)
	}
	if _, err := w.Write(r.payload.Bytes()); err != nil {
		return fmt.Errorf("failed to write payload: %w", err)
	}
	return nil
}

// SetPGPSigner registers a function that will accept the header and payload as bytes,
// and return a signature as bytes. The function should simulate what gpg does,
// probably by using golang.org/x/crypto/openpgp or by running a gpg process.
func (r *RPM) SetPGPSigner(f func([]byte) ([]byte, error)) {
	r.pgpSigner = f
}

// Only call this after the payload and header were written.
func (r *RPM) writeSignatures(sigHeader *rpmhdr.Index, regHeader []byte) error {
	addSignatureSizes(sigHeader, uint64(r.payload.Len())+uint64(len(regHeader)), r.payloadSize)
	sigHeader.Add(tag.SIG_SHA256, EntryString(fmt.Sprintf("%x", sha256.Sum256(regHeader))))
	if r.pgpSigner != nil {
		// For sha 256 you need to sign the header and payload separately
		header := append([]byte{}, regHeader...)
		headerSig, err := r.pgpSigner(header)
		if err != nil {
			return fmt.Errorf("call to signer failed: %w", err)
		}
		sigHeader.Add(tag.SIG_RSA, EntryBytes(headerSig))

		body := append(header, r.payload.Bytes()...)
		bodySig, err := r.pgpSigner(body)
		if err != nil {
			return fmt.Errorf("call to signer failed: %w", err)
		}
		sigHeader.Add((tag.SIG_PGP - tag.SIGHEADER_TAG_BASE), EntryBytes(bodySig))
	}
	return nil
}

func (r *RPM) writeRelationIndexes(h *rpmhdr.Index) error {
	// add all relation categories
	if err := r.Provides.AddToIndex(h, tag.PROVIDENAME, tag.PROVIDEVERSION, tag.PROVIDEFLAGS); err != nil {
		return fmt.Errorf("failed to add provides: %w", err)
	}
	if err := r.Obsoletes.AddToIndex(h, tag.OBSOLETENAME, tag.OBSOLETEVERSION, tag.OBSOLETEFLAGS); err != nil {
		return fmt.Errorf("failed to add obsoletes: %w", err)
	}
	if err := r.Suggests.AddToIndex(h, tag.SUGGESTNAME, tag.SUGGESTVERSION, tag.SUGGESTFLAGS); err != nil {
		return fmt.Errorf("failed to add suggests: %w", err)
	}
	if err := r.Recommends.AddToIndex(h, tag.RECOMMENDNAME, tag.RECOMMENDVERSION, tag.RECOMMENDFLAGS); err != nil {
		return fmt.Errorf("failed to add recommends: %w", err)
	}
	requires := r.Requires
	switch {
	case r.v6 != nil:
		requires = r.v6Requires()
	case r.payloadSize > math.MaxUint32:
		// The installed size is stored in the 64 bit LONGSIZE tag, which needs
		// rpm to support large files.
		requires = append(Relations{}, r.Requires...)
		requires.addIfMissing(largeFilesRequire())
	}
	if err := requires.AddToIndex(h, tag.REQUIRENAME, tag.REQUIREVERSION, tag.REQUIREFLAGS); err != nil {
		return fmt.Errorf("failed to add requires: %w", err)
	}
	if err := r.Conflicts.AddToIndex(h, tag.CONFLICTNAME, tag.CONFLICTVERSION, tag.CONFLICTFLAGS); err != nil {
		return fmt.Errorf("failed to add conflicts: %w", err)
	}
	if err := r.Enhances.AddToIndex(h, tag.ENHANCENAME, tag.ENHANCEVERSION, tag.ENHANCEFLAGS); err != nil {
		return fmt.Errorf("failed to add enhances: %w", err)
	}
	if err := r.Supplements.AddToIndex(h, tag.SUPPLEMENTNAME, tag.SUPPLEMENTVERSION, tag.SUPPLEMENTFLAGS); err != nil {
		return fmt.Errorf("failed to add supplements: %w", err)
	}

	return nil
}

// AddCustomTag adds or overwrites a tag value in the index.
func (r *RPM) AddCustomTag(tag int, e IndexEntry) {
	r.customTags[tag] = e
}

// AddCustomSig adds or overwrites a signature tag value.
func (r *RPM) AddCustomSig(tag int, e IndexEntry) {
	r.customSigs[tag] = e
}

func (r *RPM) writeGenIndexes(h *rpmhdr.Index) {
	h.Add(tag.HEADERI18NTABLE, EntryString("C"))
	if r.v6 == nil {
		addInstalledSize(h, r.payloadSize)
	}
	h.Add(tag.NAME, EntryString(r.Name))
	h.Add(tag.VERSION, EntryString(r.Version))
	if r.Epoch != NoEpoch {
		h.Add(tag.EPOCH, EntryUint32([]uint32{r.Epoch}))
	}
	h.Add(tag.SUMMARY, EntryString(r.Summary))
	h.Add(tag.DESCRIPTION, EntryString(r.Description))
	h.Add(tag.BUILDHOST, EntryString(r.BuildHost))
	if !r.BuildTime.IsZero() {
		// time.Time zero value is confusing, avoid if not supplied
		// a zero time would be written as a date in 1754 or 1970
		h.Add(tag.BUILDTIME, EntryUint32([]uint32{uint32(r.BuildTime.Unix())})) // range checked by validateMetadata
	}
	if len(r.Prefixes) != 0 {
		h.Add(tag.PREFIXES, EntryStringSlice(r.Prefixes))
	}
	h.Add(tag.RELEASE, EntryString(r.Release))
	h.Add(tag.PAYLOADFORMAT, EntryString("cpio"))
	h.Add(tag.PAYLOADCOMPRESSOR, EntryString(r.Compressor))
	h.Add(tag.PAYLOADFLAGS, EntryString("9"))
	h.Add(tag.ARCH, EntryString(r.Arch))
	h.Add(tag.OS, EntryString(r.OS))
	if r.Vendor != "" {
		h.Add(tag.VENDOR, EntryString(r.Vendor))
	}
	h.Add(tag.LICENSE, EntryString(r.Licence))
	if r.Packager != "" {
		h.Add(tag.PACKAGER, EntryString(r.Packager))
	}
	if r.Group != "" {
		h.Add(tag.GROUP, EntryString(r.Group))
	}
	if r.URL != "" {
		h.Add(tag.URL, EntryString(r.URL))
	}
	if r.Distribution != "" {
		h.Add(tag.DISTRIBUTION, EntryString(r.Distribution))
	}
	if r.BugURL != "" {
		h.Add(tag.BUGURL, EntryString(r.BugURL))
	}
	if len(r.Changelog) > 0 {
		times := make([]uint32, len(r.Changelog))
		names := make([]string, len(r.Changelog))
		texts := make([]string, len(r.Changelog))
		for i, e := range r.Changelog {
			times[i] = uint32(e.Time.Unix()) // range checked by validateMetadata
			names[i] = e.Author
			texts[i] = e.Text
		}
		h.Add(tag.CHANGELOGTIME, EntryUint32(times))
		h.Add(tag.CHANGELOGNAME, EntryStringSlice(names))
		h.Add(tag.CHANGELOGTEXT, EntryStringSlice(texts))
	}
	h.Add(tag.PAYLOADDIGEST, EntryStringSlice([]string{fmt.Sprintf("%x", sha256.Sum256(r.payload.Bytes()))}))
	if r.v6 == nil {
		h.Add(tag.PAYLOADDIGESTALGO, EntryInt32([]int32{tag.HASH_SHA256}))
	} else {
		r.writeV6Indexes(h)
	}

	// rpm utilities look for the sourcerpm tag to deduce if this is not a source rpm (if it has a sourcerpm,
	// it is NOT a source rpm).
	h.Add(tag.SOURCERPM, EntryString(fmt.Sprintf("%s-%s.src.rpm", r.Name, r.FullVersion())))
	if r.pretrans != "" {
		h.Add(tag.PRETRANS, EntryString(r.pretrans))
		h.Add(tag.PRETRANSPROG, EntryString("/bin/sh"))
	}
	if r.prein != "" {
		h.Add(tag.PREIN, EntryString(r.prein))
		h.Add(tag.PREINPROG, EntryString("/bin/sh"))
	}
	if r.postin != "" {
		h.Add(tag.POSTIN, EntryString(r.postin))
		h.Add(tag.POSTINPROG, EntryString("/bin/sh"))
	}
	if r.preun != "" {
		h.Add(tag.PREUN, EntryString(r.preun))
		h.Add(tag.PREUNPROG, EntryString("/bin/sh"))
	}
	if r.postun != "" {
		h.Add(tag.POSTUN, EntryString(r.postun))
		h.Add(tag.POSTUNPROG, EntryString("/bin/sh"))
	}
	if r.posttrans != "" {
		h.Add(tag.POSTTRANS, EntryString(r.posttrans))
		h.Add(tag.POSTTRANSPROG, EntryString("/bin/sh"))
	}
	if r.verifyscript != "" {
		h.Add(tag.VERIFYSCRIPT, EntryString(r.verifyscript))
		h.Add(tag.VERIFYSCRIPTPROG, EntryString("/bin/sh"))
	}
}

// WriteFileIndexes writes file related index headers to the header
func (r *RPM) writeFileIndexes(h *rpmhdr.Index) {
	h.Add(tag.BASENAMES, EntryStringSlice(r.basenames))
	h.Add(tag.DIRINDEXES, EntryUint32(r.dirindexes))
	h.Add(tag.DIRNAMES, EntryStringSlice(r.di.AllDirs()))
	if r.v6 == nil {
		h.Add(tag.FILESIZES, EntryUint32(r.filesizes))
	}
	h.Add(tag.FILEMODES, EntryUint16(r.filemodes))
	h.Add(tag.FILEUSERNAME, EntryStringSlice(r.fileowners))
	h.Add(tag.FILEGROUPNAME, EntryStringSlice(r.filegroups))
	h.Add(tag.FILEMTIMES, EntryUint32(r.filemtimes))
	h.Add(tag.FILEDIGESTS, EntryStringSlice(r.filedigests))
	h.Add(tag.FILELINKTOS, EntryStringSlice(r.filelinktos))
	h.Add(tag.FILEFLAGS, EntryUint32(r.fileflags))

	inodes := make([]int32, len(r.dirindexes))
	devices := make([]int32, len(r.dirindexes))
	digestAlgo := make([]int32, len(r.dirindexes))
	verifyFlags := make([]int32, len(r.dirindexes))
	fileRDevs := make([]int16, len(r.dirindexes))
	fileLangs := make([]string, len(r.dirindexes))

	for ii := range inodes {
		// is inodes just a range from 1..len(dirindexes)? maybe different with hard links
		inodes[ii] = int32(ii + 1)
		// is devices number from which the file was copied
		// from rpm original tools https://github.com/rpm-software-management/rpm/blob/c167ef8bdaecdd2e306ec896c919607ba9cceb6f/build/files.c#L1226
		devices[ii] = int32(1)
		digestAlgo[ii] = tag.HASH_SHA256
		// With regular files, it seems like we can always enable all of the verify flags
		verifyFlags[ii] = int32(-1)
		fileRDevs[ii] = int16(1)
	}
	h.Add(tag.FILEINODES, EntryInt32(inodes))
	h.Add(tag.FILEDEVICES, EntryInt32(devices))
	if r.v6 == nil {
		h.Add(tag.FILEDIGESTALGO, EntryInt32(digestAlgo))
	} else {
		// v6 has a single digest algorithm for all files.
		h.Add(tag.FILEDIGESTALGO, EntryInt32([]int32{tag.HASH_SHA256}))
	}
	h.Add(tag.FILEVERIFYFLAGS, EntryInt32(verifyFlags))
	h.Add(tag.FILERDEVS, EntryInt16(fileRDevs))
	h.Add(tag.FILELANGS, EntryStringSlice(fileLangs))
}

// AddPretrans adds a pretrans scriptlet
func (r *RPM) AddPretrans(s string) {
	r.pretrans = s
}

// AddPrein adds a prein scriptlet
func (r *RPM) AddPrein(s string) {
	r.prein = s
}

// AddPostin adds a postin scriptlet
func (r *RPM) AddPostin(s string) {
	r.postin = s
}

// AddPreun adds a preun scriptlet
func (r *RPM) AddPreun(s string) {
	r.preun = s
}

// AddPostun adds a postun scriptlet
func (r *RPM) AddPostun(s string) {
	r.postun = s
}

// AddPosttrans adds a posttrans scriptlet
func (r *RPM) AddPosttrans(s string) {
	r.posttrans = s
}

// AddVerifyScript adds a verifyscript scriptlet
func (r *RPM) AddVerifyScript(s string) {
	r.verifyscript = s
}

// AddFile adds an RPMFile to an existing rpm.
func (r *RPM) AddFile(f RPMFile) {
	if f.Name == "/" { // rpm does not allow the root dir to be included.
		return
	}
	r.files[f.Name] = f
}

// writeFile writes the file to the indexes and cpio.
func (r *RPM) writeFile(f RPMFile) error {
	dir, file := path.Split(f.Name)
	r.dirindexes = append(r.dirindexes, r.di.Get(dir))
	r.basenames = append(r.basenames, file)
	r.fileowners = append(r.fileowners, f.Owner)
	r.filegroups = append(r.filegroups, f.Group)
	r.filemtimes = append(r.filemtimes, f.MTime)
	r.fileflags = append(r.fileflags, uint32(f.Type))

	links := 1
	// v6 packages do not record a size for directories.
	var v6size uint64
	switch {
	case f.Mode&040000 != 0: // directory
		r.filesizes = append(r.filesizes, 4096)
		r.filedigests = append(r.filedigests, "")
		r.filelinktos = append(r.filelinktos, "")
		links = 2
	case f.Mode&0120000 == 0120000: //  symlink
		r.filesizes = append(r.filesizes, fileSize32(len(f.Body)))
		v6size = uint64(len(f.Body))
		r.filedigests = append(r.filedigests, "")
		r.filelinktos = append(r.filelinktos, string(f.Body))
	default: // regular file
		f.Mode = f.Mode | 0100000
		r.filesizes = append(r.filesizes, fileSize32(len(f.Body)))
		v6size = uint64(len(f.Body))
		r.filedigests = append(r.filedigests, fmt.Sprintf("%x", sha256.Sum256(f.Body)))
		r.filelinktos = append(r.filelinktos, "")
	}
	r.filemodes = append(r.filemodes, uint16(f.Mode)) // range checked by validateFile
	if r.v6 != nil {
		r.v6.addFile(v6size, mimeType(f))
	}

	// Ghost files have no payload
	if f.Type == GhostFile {
		return nil
	}
	return r.writePayload(f, links)
}

// writePayload writes the cpio entry of the file which was just added to the header
// indexes. The stripped cpio entries of v6 packages refer to the file by its position
// in the header, which is the same as the file order in the header.
func (r *RPM) writePayload(f RPMFile, links int) error {
	content := f.Body
	if f.Mode&040000 != 0 { // directories have no content, whatever Body holds
		content = nil
	}
	hdr := &cpio.Header{
		Name:  f.Name,
		Mode:  uint32(f.Mode), // range checked by validateFile
		Size:  int64(len(content)),
		Links: links,
		Index: len(r.basenames) - 1,
	}
	if err := r.cpio.WriteHeader(hdr); err != nil {
		return fmt.Errorf("failed to write payload file header: %w", err)
	}
	if _, err := r.cpio.Write(content); err != nil {
		return fmt.Errorf("failed to write payload file content: %w", err)
	}
	r.payloadSize += uint64(len(content))
	return nil
}

// fileSize32 converts a size to the 32 bit FILESIZES tag. The v4 format rejects
// larger files in validateFile; for v6, which has its own 64 bit tag, the value is
// unused.
func fileSize32(n int) uint32 {
	return uint32(min(uint64(n), math.MaxUint32))
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

func largeFilesRequire() *Relation {
	return &Relation{
		Name:    "rpmlib(LargeFiles)",
		Version: "4.12.0-1",
		Sense:   SenseRPMLIB | SenseLess | SenseEqual,
	}
}

// validateFile checks that f can be represented in the rpm file indexes.
func (r *RPM) validateFile(f RPMFile) error {
	switch {
	case !path.IsAbs(f.Name) || path.Clean(f.Name) != f.Name:
		return fmt.Errorf("%w: name %q is not a clean absolute path", ErrInvalidFile, f.Name)
	case hasNUL(f.Name), hasNUL(f.Owner), hasNUL(f.Group):
		return fmt.Errorf("%w: %q has an embedded NUL byte", ErrInvalidFile, f.Name)
	case f.Mode > maxMode:
		return fmt.Errorf("%w: %q has mode %#o which does not fit in 16 bits", ErrInvalidFile, f.Name, f.Mode)
	case !supportedFileType(f.Mode):
		return fmt.Errorf("%w: %q has file type bits %#o, only regular files, directories and symlinks are supported",
			ErrInvalidFile, f.Name, f.Mode&modeTypeMask)
	case f.Mode&0120000 == 0120000 && f.Mode&040000 == 0 && len(f.Body) == 0:
		return fmt.Errorf("%w: symlink %q has an empty target", ErrInvalidFile, f.Name)
	case f.Mode&0120000 == 0120000 && f.Mode&040000 == 0 && bytes.IndexByte(f.Body, 0) >= 0:
		return fmt.Errorf("%w: symlink %q has an embedded NUL byte in its target", ErrInvalidFile, f.Name)
	case r.v6 == nil && uint64(len(f.Body)) > maxV4FileSize:
		return fmt.Errorf("%w: %q is %d bytes, the v4 format supports files up to 4 GiB - 1 (use FormatV6)",
			ErrInvalidFile, f.Name, len(f.Body))
	}
	return nil
}

// validateMetadata checks that the package metadata can be represented in the header.
func (r *RPM) validateMetadata() error {
	strs := []string{
		r.Name, r.Summary, r.Description, r.Version, r.Release, r.Arch, r.OS, r.Vendor,
		r.URL, r.Packager, r.Group, r.Licence, r.BuildHost, r.Distribution, r.BugURL,
		r.prein, r.postin, r.preun, r.postun, r.pretrans, r.posttrans, r.verifyscript,
	}
	strs = append(strs, r.Prefixes...)
	for _, e := range r.Changelog {
		strs = append(strs, e.Author, e.Text)
	}
	for _, s := range strs {
		if hasNUL(s) {
			return fmt.Errorf("%w: value %q has an embedded NUL byte", ErrInvalidMetadata, s)
		}
	}
	for _, rels := range []Relations{
		r.Provides, r.Obsoletes, r.Suggests, r.Recommends, r.Requires, r.Conflicts, r.Enhances, r.Supplements,
	} {
		for _, rel := range rels {
			if rel == nil {
				return fmt.Errorf("%w: nil relation", ErrInvalidMetadata)
			}
			if hasNUL(rel.Name) || hasNUL(rel.Version) {
				return fmt.Errorf("%w: relation %q has an embedded NUL byte", ErrInvalidMetadata, rel.Name)
			}
		}
	}
	if !r.BuildTime.IsZero() {
		if err := checkTime32("build time", r.BuildTime); err != nil {
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

// supportedFileType reports whether the file type bits of mode are a regular file
// (also when unset), a directory or a symlink. Devices, fifos and sockets are not
// supported; their bits would otherwise be mangled into another type.
func supportedFileType(mode uint) bool {
	switch mode & modeTypeMask {
	case 0, 0100000, 040000, 0120000:
		return true
	}
	return false
}

func hasNUL(s string) bool { return strings.IndexByte(s, 0) >= 0 }

// checkTime32 checks that t fits the unsigned 32 bit time rpm stores in headers.
func checkTime32(what string, t time.Time) error {
	if u := t.Unix(); u < 0 || u > math.MaxUint32 {
		return fmt.Errorf("%w: %s %v is outside 1970..2106, the range of a 32 bit rpm time", ErrInvalidMetadata, what, t)
	}
	return nil
}
