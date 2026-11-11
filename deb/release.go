package deb

import (
	"bytes"
	"crypto/md5"  //nolint:gosec // MD5Sum is a field of the Release format, not a security control
	"crypto/sha1" //nolint:gosec // SHA1 is a field of the Release format, not a security control
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/internal/pathseg"
)

const (
	// MaxReleaseBytes bounds a Release or InRelease document.
	MaxReleaseBytes = 16 << 20
	// maxReleaseFiles bounds the files a Release lists.
	maxReleaseFiles = 1 << 20

	releaseDateFormat = "Mon, 02 Jan 2006 15:04:05 MST"
)

// ErrReleaseExpired is returned by Release.CheckValidity for a Release whose
// Valid-Until date is in the past.
var ErrReleaseExpired = errors.New("deb: release file has expired")

// FileInfo describes one file of a repository: its path, size and digests.
type FileInfo struct {
	// Path is relative to the directory the listing belongs to (the dists/<dist>
	// directory for a Release) or to the repository root for a package file.
	Path string
	Size int64
	// Hex digests; empty when unknown.
	MD5sum, SHA1, SHA256, SHA512 string
}

// Complete reports whether MD5sum, SHA1 and SHA256 are all set.
func (f FileInfo) Complete() bool { return f.MD5sum != "" && f.SHA1 != "" && f.SHA256 != "" }

// HashBytes returns the FileInfo of data stored under path, with every digest
// computed.
func HashBytes(path string, data []byte) FileInfo {
	fi, _ := HashReader(path, bytes.NewReader(data)) // a bytes.Reader does not fail

	return fi
}

// HashReader reads r to its end and returns its FileInfo with every digest
// computed.
func HashReader(path string, r io.Reader) (FileInfo, error) {
	h := []hash.Hash{md5.New(), sha1.New(), sha256.New(), sha512.New()} //nolint:gosec // see above

	w := make([]io.Writer, len(h))
	for i := range h {
		w[i] = h[i]
	}

	n, err := io.Copy(io.MultiWriter(w...), r)
	if err != nil {
		return FileInfo{}, fmt.Errorf("deb: hashing %s: %w", path, err)
	}

	return FileInfo{
		Path:   path,
		Size:   n,
		MD5sum: hex.EncodeToString(h[0].Sum(nil)),
		SHA1:   hex.EncodeToString(h[1].Sum(nil)),
		SHA256: hex.EncodeToString(h[2].Sum(nil)),
		SHA512: hex.EncodeToString(h[3].Sum(nil)),
	}, nil
}

// Release is the content of a Release file: the description of a
// distribution and the checksums of its index files.
type Release struct {
	Origin        string
	Label         string
	Suite         string
	Version       string
	Codename      string
	Date          time.Time
	ValidUntil    time.Time
	Architectures []string
	Components    []string
	Description   string
	// NotAutomatic ("NotAutomatic: yes") marks a repository whose packages must
	// not be installed or upgraded to without an explicit request (pin
	// priority 1); with ButAutomaticUpgrades the installed ones are upgraded
	// (pin priority 100).
	NotAutomatic, ButAutomaticUpgrades bool
	// AcquireByHash ("Acquire-By-Hash: yes") says the by-hash tree (see
	// ByHashPath) of the repository is complete: a client fetches the indexes
	// by their digest and is immune to a repository that is updated while it
	// downloads.
	AcquireByHash bool
	// SignedBy is the Signed-By field: the fingerprints of the keys that may
	// sign the repository, which a client may enforce. It may span lines.
	SignedBy string
	// NoSupportForArchitectureAll is the "No-Support-for-Architecture-all"
	// field: "Packages" says the architecture-specific Packages indexes do not
	// carry the architecture all packages and apt must fetch the
	// binary-all index.
	NoSupportForArchitectureAll string
	// Changelogs is the Changelogs field: the URL template of the changelog
	// server, or "no".
	Changelogs string
	// Snapshots is the Snapshots field: the URL template of the snapshot
	// service of the archive.
	Snapshots string
	// Extra holds the fields the type has no member for, by name as written,
	// so that a Release read and marshalled again loses none.
	Extra map[string]string
	// Files lists the index files by Path, relative to dists/<dist>/.
	Files map[string]FileInfo
}

// releaseKnownFields are the header fields of a Release the type models,
// together with the checksum sections.
var releaseKnownFields = []string{
	"Origin", "Label", "Suite", "Version", "Codename", "Date", "Valid-Until",
	"NotAutomatic", "ButAutomaticUpgrades", "Acquire-By-Hash", "Signed-By",
	"No-Support-for-Architecture-all", "Changelogs", "Snapshots",
	"Architectures", "Components", "Description",
	"MD5Sum", "SHA1", "SHA256", "SHA512",
}

// ParseBool reads the boolean spellings apt accepts in Release files and
// configuration: yes, true, with, on, enable and 1 are true; no, false,
// without, off, disable and 0 are false. ok is false for anything else.
func ParseBool(s string) (value, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "true", "with", "on", "enable", "1":
		return true, true
	case "no", "false", "without", "off", "disable", "0":
		return false, true
	}

	return false, false
}

func boolField(cf *ControlFile, names ...string) bool {
	for _, n := range names {
		if v, ok := cf.Lookup(n); ok {
			b, _ := ParseBool(v)

			return b
		}
	}

	return false
}

// AddFile records a file in the listing.
func (r *Release) AddFile(fi FileInfo) {
	if r.Files == nil {
		r.Files = make(map[string]FileInfo)
	}

	r.Files[fi.Path] = fi
}

// Marshal renders the Release. Files are listed by path, in the MD5Sum, SHA1,
// SHA256 and SHA512 sections, and only with the digests they have. Empty
// header fields and zero dates are omitted.
func (r *Release) Marshal() []byte {
	var sb strings.Builder

	field := func(name, value string) {
		if value != "" {
			writeField(&sb, name, value)
		}
	}

	field("Origin", r.Origin)
	field("Label", r.Label)
	field("Suite", r.Suite)
	field("Version", r.Version)
	field("Codename", r.Codename)

	if !r.Date.IsZero() {
		field("Date", r.Date.UTC().Format(releaseDateFormat))
	}

	if !r.ValidUntil.IsZero() {
		field("Valid-Until", r.ValidUntil.UTC().Format(releaseDateFormat))
	}

	yes := func(name string, v bool) {
		if v {
			writeField(&sb, name, "yes")
		}
	}

	yes("NotAutomatic", r.NotAutomatic)
	yes("ButAutomaticUpgrades", r.ButAutomaticUpgrades)
	yes("Acquire-By-Hash", r.AcquireByHash)
	field("Signed-By", r.SignedBy)
	field("No-Support-for-Architecture-all", r.NoSupportForArchitectureAll)
	field("Changelogs", r.Changelogs)
	field("Snapshots", r.Snapshots)
	field("Architectures", strings.Join(r.Architectures, " "))
	field("Components", strings.Join(r.Components, " "))
	field("Description", r.Description)

	extra := make([]string, 0, len(r.Extra))

	for k := range r.Extra {
		if !isReleaseKnownField(k) {
			extra = append(extra, k)
		}
	}

	sort.Strings(extra)

	for _, k := range extra {
		field(k, r.Extra[k])
	}

	writeSections(&sb, r.Files)

	return []byte(sb.String())
}

func isReleaseKnownField(name string) bool {
	return slices.ContainsFunc(releaseKnownFields, func(k string) bool { return strings.EqualFold(k, name) })
}

// sectionSpecs lists the checksum sections of a Release (and of the other
// indexes that list files: i18n/Index) with the digest each reads and writes.
func sectionSpecs() []struct {
	field  string
	length int
	get    func(FileInfo) string
	set    func(*FileInfo, string)
} {
	return []struct {
		field  string
		length int
		get    func(FileInfo) string
		set    func(*FileInfo, string)
	}{
		{"MD5Sum", md5.Size, func(f FileInfo) string { return f.MD5sum }, func(f *FileInfo, h string) { f.MD5sum = h }},
		{"SHA1", sha1.Size, func(f FileInfo) string { return f.SHA1 }, func(f *FileInfo, h string) { f.SHA1 = h }},
		{"SHA256", sha256.Size, func(f FileInfo) string { return f.SHA256 }, func(f *FileInfo, h string) { f.SHA256 = h }},
		{"SHA512", sha512.Size, func(f FileInfo) string { return f.SHA512 }, func(f *FileInfo, h string) { f.SHA512 = h }},
	}
}

// writeSections writes the MD5Sum, SHA1, SHA256 and SHA512 sections for files,
// by path, with only the digests each has.
func writeSections(sb *strings.Builder, files map[string]FileInfo) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}

	sort.Strings(paths)

	for _, spec := range sectionSpecs() {
		var any bool

		for _, p := range paths {
			fi := files[p]

			d := spec.get(fi)
			if d == "" {
				continue
			}

			if !any {
				sb.WriteString(spec.field + ":\n")

				any = true
			}

			fmt.Fprintf(sb, " %s %10d %s\n", d, fi.Size, p)
		}
	}
}

// ParseRelease parses a Release or InRelease document. A clear-signed
// document is unwrapped without verifying its signature; verify first (see
// VerifyInRelease) when the source is not trusted. Malformed checksum lines
// are skipped; a checksum that is not a hex digest of the right length, a
// listed path that is not a plain relative path, or two sections disagreeing
// on a file's size fail with ErrInvalidRelease.
func ParseRelease(data []byte) (*Release, error) {
	if len(data) > MaxReleaseBytes {
		return nil, fmt.Errorf("%w: release over %d bytes", ErrTooLarge, MaxReleaseBytes)
	}

	body := StripClearsign(data)

	cf, err := firstParagraph(body)
	if err != nil {
		return nil, err
	}

	rel := &Release{
		Origin:        cf.Get("Origin"),
		Label:         cf.Get("Label"),
		Suite:         cf.Get("Suite"),
		Version:       cf.Get("Version"),
		Codename:      cf.Get("Codename"),
		Architectures: strings.Fields(cf.Get("Architectures")),
		Components:    strings.Fields(cf.Get("Components")),
		Description:   cf.Get("Description"),
		Date:          parseReleaseTime(cf.Get("Date")),
		ValidUntil:    parseReleaseTime(cf.Get("Valid-Until")),
		Files:         make(map[string]FileInfo),

		NotAutomatic:                boolField(cf, "NotAutomatic", "Not-Automatic"),
		ButAutomaticUpgrades:        boolField(cf, "ButAutomaticUpgrades"),
		AcquireByHash:               boolField(cf, "Acquire-By-Hash"),
		SignedBy:                    cf.Get("Signed-By"),
		NoSupportForArchitectureAll: cf.Get("No-Support-for-Architecture-all"),
		Changelogs:                  cf.Get("Changelogs"),
		Snapshots:                   cf.Get("Snapshots"),
	}

	for _, name := range cf.Order {
		if isReleaseKnownField(name) || strings.EqualFold(name, "Not-Automatic") {
			continue
		}

		if rel.Extra == nil {
			rel.Extra = make(map[string]string)
		}

		rel.Extra[name] = cf.Fields[name]
	}

	for _, sec := range sectionSpecs() {
		if err := addSection(rel.Files, cf.Get(sec.field), sec.length, sec.set); err != nil {
			return nil, fmt.Errorf("%s: %w", sec.field, err)
		}
	}

	return rel, nil
}

// addSection merges the lines of one checksum section into files.
func addSection(files map[string]FileInfo, value string, hashLen int, set func(*FileInfo, string)) error {
	for line := range strings.SplitSeq(value, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}

		sum, sizeStr, path := fields[0], fields[1], fields[2]

		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil || size < 0 {
			continue
		}

		if raw, err := hex.DecodeString(sum); err != nil || len(raw) != hashLen {
			return fmt.Errorf("%w: bad digest for %q", ErrInvalidRelease, path)
		}

		if !pathseg.Path(path) {
			return fmt.Errorf("%w: unsafe path %q", ErrInvalidRelease, path)
		}

		fi, seen := files[path]
		if seen && fi.Size != size {
			return fmt.Errorf("%w: sections disagree on the size of %q", ErrInvalidRelease, path)
		}

		if !seen && len(files) >= maxReleaseFiles {
			return fmt.Errorf("%w: more than %d files", ErrTooLarge, maxReleaseFiles)
		}

		fi.Path, fi.Size = path, size
		set(&fi, strings.ToLower(sum))
		files[path] = fi
	}

	return nil
}

// firstParagraph parses the first paragraph of body leniently.
func firstParagraph(body []byte) (*ControlFile, error) {
	var cf *ControlFile

	err := scanParagraphs(bytes.NewReader(body), func(text string) error {
		var perr error

		cf, perr = parseParagraph(text, false)
		if perr != nil {
			return perr
		}

		return errStopScan
	})
	if err != nil && !errors.Is(err, errStopScan) {
		return nil, err
	}

	if cf == nil {
		return NewControlFile(), nil
	}

	return cf, nil
}

// parseReleaseTime parses the date of a Release field in the formats apt
// writes: RFC 1123 with a zone name or a numeric offset, with or without a
// zero-padded day. It returns the zero time for anything else.
func parseReleaseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}

	for _, layout := range []string{time.RFC1123, time.RFC1123Z, "Mon, 2 Jan 2006 15:04:05 MST", "Mon, 2 Jan 2006 15:04:05 -0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}

	return time.Time{}
}

// CheckValidity returns ErrReleaseExpired when the Release has a Valid-Until
// date that lies before now. A Release without one never expires.
func (r *Release) CheckValidity(now time.Time) error {
	if !r.ValidUntil.IsZero() && now.After(r.ValidUntil) {
		return fmt.Errorf("%w: valid until %s", ErrReleaseExpired, r.ValidUntil.UTC().Format(time.RFC3339))
	}

	return nil
}

// packagesSuffixes lists the compressions of a Packages index, best first.
func packagesSuffixes() []string { return []string{".xz", ".zst", ".gz", ".bz2", ".lz4", ""} }

// PackagesVariants lists the paths of the Packages index of component comp
// and architecture arch that the Release lists, best compression first.
func (r *Release) PackagesVariants(comp, arch string) []string {
	base := comp + "/binary-" + arch + "/Packages"

	var out []string

	for _, ext := range packagesSuffixes() {
		if _, ok := r.Files[base+ext]; ok {
			out = append(out, base+ext)
		}
	}

	return out
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

	base := comp + "/binary-" + arch + "/Packages"

	return []string{base + ".xz", base + ".gz", base}
}

// StripClearsign returns the signed text of a clear-signed document, with the
// dash-escaping removed, or data unchanged when it is not one. It does not
// verify the signature.
func StripClearsign(data []byte) []byte {
	const (
		begin = "-----BEGIN PGP SIGNED MESSAGE-----"
		sig   = "-----BEGIN PGP SIGNATURE-----"
	)

	if !bytes.HasPrefix(bytes.TrimLeft(data, "\r\n "), []byte(begin)) {
		return data
	}

	var out []string

	inBody, headers := false, true

	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimRight(line, "\r")

		switch {
		case strings.HasPrefix(line, sig):
			return []byte(strings.Join(out, "\n"))
		case !inBody && strings.HasPrefix(line, begin):
			inBody = true
		case inBody && headers:
			// Armor headers (Hash: ...) end at the first empty line.
			if line == "" {
				headers = false
			}
		case inBody:
			out = append(out, strings.TrimPrefix(line, "- "))
		}
	}

	return []byte(strings.Join(out, "\n"))
}
