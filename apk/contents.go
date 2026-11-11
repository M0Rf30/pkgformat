package apk

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha1" //nolint:gosec // apk records a SHA-1 per file in the PAX header
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/internal/pathseg"
)

// ErrChecksum is wrapped by the errors for a file whose content does not match
// the SHA-1 its package records for it. It is also an [ErrInvalidPackage].
var ErrChecksum = errors.New("file checksum mismatch")

// EntryType is the kind of a data segment entry.
type EntryType uint8

// The kinds of entry a data segment holds.
const (
	TypeRegular EntryType = iota + 1
	TypeDir
	TypeSymlink
	TypeHardlink
	TypeCharDevice
	TypeBlockDevice
	TypeFIFO
)

// String returns the lowercase name of the kind.
func (t EntryType) String() string {
	switch t {
	case TypeRegular:
		return "file"
	case TypeDir:
		return "dir"
	case TypeSymlink:
		return "symlink"
	case TypeHardlink:
		return "hardlink"
	case TypeCharDevice:
		return "chardev"
	case TypeBlockDevice:
		return "blockdev"
	case TypeFIFO:
		return "fifo"
	default:
		return "unknown"
	}
}

// Entry is one entry of the data segment of a package.
type Entry struct {
	// Name is the install path: relative, slash separated, without a trailing
	// slash, free of ".." elements.
	Name string
	Type EntryType
	// Mode holds the permission bits and fs.ModeSetuid, fs.ModeSetgid and
	// fs.ModeSticky; the kind is in Type.
	Mode fs.FileMode
	// Size is the content length of a regular file.
	Size    int64
	ModTime time.Time
	// UID, GID, Uname and Gname are the owner the package records.
	UID, GID     int
	Uname, Gname string
	// LinkTarget is the target of a symbolic link, or the earlier entry a
	// hard link is another name of.
	LinkTarget string
	// DevMajor and DevMinor are the numbers of a device node.
	DevMajor, DevMinor int64
	// Checksum is the lowercase hex SHA-1 the package records for a regular
	// file's content or a symbolic link's target (the PAX record
	// APK-TOOLS.checksum.SHA1); empty when the package records none.
	Checksum string
	// Xattrs are the extended attributes (SCHILY.xattr PAX records), such as
	// "security.capability".
	Xattrs map[string][]byte
}

// Limits of the entries a reader accepts.
const (
	maxEntryXattrs = 256
	// maxEntryXattrBytes bounds the attribute names and values of one entry.
	maxEntryXattrBytes = 1 << 20
	maxScriptSize      = 1 << 20
)

// Archive is a package opened for reading: its verified metadata, install
// scripts and data segment. It holds no file descriptor of its own; the
// ReaderAt must stay valid while it is used. An Archive is safe for
// concurrent use when its ReaderAt is.
type Archive struct {
	pkg       *Package
	scripts   Scripts
	sigs      *packageSignatures
	ra        io.ReaderAt
	size      int64
	dataStart int64
	lim       packageLimits
}

// OpenArchive opens an .apk of size bytes. It does everything [ParsePackage]
// does (so the datahash, the gzip framing and the entry names are verified
// before it returns) and also reads the install scripts of the control
// segment. Every error wraps [ErrInvalidPackage].
func OpenArchive(r io.ReaderAt, size int64) (*Archive, error) {
	return openArchive(r, size, defaultPackageLimits())
}

func openArchive(r io.ReaderAt, size int64, lim packageLimits) (*Archive, error) {
	pkg, sigs, err := inspectPackage(r, size, lim)
	if err != nil {
		return nil, err
	}

	control, err := readMember(r, sigs.controlStart, size, lim)
	if err != nil {
		return nil, err
	}

	scripts, err := readScripts(control.raw, lim)
	if err != nil {
		return nil, err
	}

	return &Archive{pkg: pkg, scripts: scripts, sigs: sigs, ra: r, size: size, dataStart: sigs.ctrlEnd, lim: lim}, nil
}

// Package returns the package metadata, as [ParsePackage] reports it.
func (a *Archive) Package() *Package { return a.pkg }

// Scripts returns the install scripts of the package: the control segment
// entries .pre-install, .post-install, .pre-upgrade, .post-upgrade,
// .pre-deinstall, .post-deinstall and .trigger, each as its complete text. The
// directories the .trigger script watches are in [Package.Triggers].
func (a *Archive) Scripts() Scripts { return a.scripts }

// Signatures returns the signature entries of the package, in file order.
// They are not verified here; see [VerifyPackage].
func (a *Archive) Signatures() []Signature {
	return append([]Signature(nil), a.sigs.sigs...)
}

// readScripts reads the install scripts of the control tar.
func readScripts(raw []byte, lim packageLimits) (Scripts, error) {
	var s Scripts

	tr := tar.NewReader(bytes.NewReader(raw))

	for n := 1; ; n++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return s, nil
		}

		if err != nil {
			return Scripts{}, bad("control segment: %v", err)
		}

		if n > lim.controlEntries {
			return Scripts{}, bad("control segment holds more than %d entries", lim.controlEntries)
		}

		dst := s.field(hdr.Name)
		if dst == nil {
			continue
		}

		if hdr.Typeflag != tar.TypeReg {
			return Scripts{}, bad("%s is not a regular file", short(hdr.Name))
		}

		if hdr.Size > maxScriptSize {
			return Scripts{}, bad("%s exceeds %d bytes", short(hdr.Name), maxScriptSize)
		}

		body, err := io.ReadAll(tr)
		if err != nil {
			return Scripts{}, bad("reading %s: %v", short(hdr.Name), err)
		}

		if *dst != "" {
			return Scripts{}, bad("control segment holds more than one %s", short(hdr.Name))
		}

		*dst = string(body)
	}
}

// field returns the script an entry name stands for, or nil.
func (s *Scripts) field(name string) *string {
	switch name {
	case ".pre-install":
		return &s.PreInstall
	case ".post-install":
		return &s.PostInstall
	case ".pre-upgrade":
		return &s.PreUpgrade
	case ".post-upgrade":
		return &s.PostUpgrade
	case ".pre-deinstall":
		return &s.PreDeinstall
	case ".post-deinstall":
		return &s.PostDeinstall
	case ".trigger":
		return &s.Trigger
	default:
		return nil
	}
}

// Walk calls fn for each entry of the data segment, in archive order, with a
// reader of the entry's content (empty for anything but a regular file). The
// reader is only valid during the call. When fn returns, the rest of the
// content is read and the file is checked against the checksum the package
// records for it: a mismatch fails Walk with an error wrapping [ErrChecksum].
// An error of fn stops the walk and is returned as is.
func (a *Archive) Walk(fn func(e *Entry, content io.Reader) error) error {
	rc, err := a.openData()
	if err != nil {
		return err
	}

	tr := tar.NewReader(rc)

	for n := 1; ; n++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return bad("data segment: %v", err)
		}

		if n > a.lim.dataEntries {
			return bad("data segment holds more than %d entries", a.lim.dataEntries)
		}

		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}

		e, err := entryOf(hdr)
		if err != nil {
			return err
		}

		if err := a.visit(e, tr, fn); err != nil {
			return err
		}
	}
}

// visit hands one entry to fn and checks the content afterwards.
func (a *Archive) visit(e *Entry, tr *tar.Reader, fn func(*Entry, io.Reader) error) error {
	var (
		sum  hash.Hash
		body io.Reader = eofReader{}
	)

	if e.Type == TypeRegular {
		sum = sha1.New() //nolint:gosec // see the import
		body = io.TeeReader(tr, sum)
	}

	if err := fn(e, body); err != nil {
		return err
	}

	if sum == nil {
		return nil
	}

	if _, err := io.Copy(io.Discard, body); err != nil {
		return bad("reading %q: %v", short(e.Name), err)
	}

	if e.Checksum != "" && hex.EncodeToString(sum.Sum(nil)) != e.Checksum {
		return fmt.Errorf("%w: %w: %q", ErrInvalidPackage, ErrChecksum, short(e.Name))
	}

	return nil
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

// Files lists the entries of the data segment, with their modes, owners and
// checksums. The content of every file is verified against its checksum on
// the way, as in [Archive.Walk].
func (a *Archive) Files() ([]Entry, error) {
	var out []Entry

	err := a.Walk(func(e *Entry, _ io.Reader) error {
		out = append(out, *e)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// openData opens the decompressed data segment.
func (a *Archive) openData() (io.Reader, error) {
	sr := io.NewSectionReader(a.ra, a.dataStart, a.size-a.dataStart)

	gz, err := newMemberReader(bufio.NewReaderSize(sr, 64<<10))
	if err != nil {
		return nil, bad("data segment is not gzip: %v", err)
	}

	return &capReader{r: gz, left: a.lim.dataDecompressed}, nil
}

// entryOf converts a tar header to an Entry.
func entryOf(hdr *tar.Header) (*Entry, error) {
	if !safeEntryName(hdr.Name) {
		return nil, bad("data segment entry %q escapes the install root", short(hdr.Name))
	}

	e := &Entry{
		Name:  strings.TrimRight(hdr.Name, "/"),
		Mode:  specialMode(hdr.Mode),
		Size:  0,
		UID:   hdr.Uid,
		GID:   hdr.Gid,
		Uname: hdr.Uname, Gname: hdr.Gname,
		ModTime: hdr.ModTime,
	}

	if e.Name == "" || pathseg.HasParent(e.Name) {
		return nil, bad("data segment entry %q is not a path", short(hdr.Name))
	}

	switch hdr.Typeflag {
	case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // old archives use the NUL type
		e.Type, e.Size = TypeRegular, hdr.Size
	case tar.TypeDir:
		e.Type = TypeDir
	case tar.TypeSymlink:
		e.Type, e.LinkTarget = TypeSymlink, hdr.Linkname
	case tar.TypeLink:
		e.Type, e.LinkTarget = TypeHardlink, strings.TrimLeft(hdr.Linkname, "/")
		if !safeEntryName(e.LinkTarget) {
			return nil, bad("hard link %q has the target %q outside the install root", short(hdr.Name), short(hdr.Linkname))
		}
	case tar.TypeChar:
		e.Type, e.DevMajor, e.DevMinor = TypeCharDevice, hdr.Devmajor, hdr.Devminor
	case tar.TypeBlock:
		e.Type, e.DevMajor, e.DevMinor = TypeBlockDevice, hdr.Devmajor, hdr.Devminor
	case tar.TypeFifo:
		e.Type = TypeFIFO
	default:
		return nil, bad("data segment entry %q has the unsupported type %q", short(hdr.Name), string(hdr.Typeflag))
	}

	if err := readRecords(e, hdr); err != nil {
		return nil, err
	}

	return e, nil
}

// readRecords takes the checksum and the extended attributes from the PAX
// records of hdr.
func readRecords(e *Entry, hdr *tar.Header) error {
	if sum, ok := hdr.PAXRecords[paxChecksum]; ok {
		if !validHex(strings.ToLower(sum), sha1HexLen) {
			return bad("%q has the malformed checksum %q", short(e.Name), short(sum))
		}

		e.Checksum = strings.ToLower(sum)
	}

	if e.Type == TypeSymlink && e.Checksum != "" {
		got := sha1.Sum([]byte(e.LinkTarget)) //nolint:gosec // see the import
		if hex.EncodeToString(got[:]) != e.Checksum {
			return fmt.Errorf("%w: %w: symbolic link %q", ErrInvalidPackage, ErrChecksum, short(e.Name))
		}
	}

	var total int

	for k, v := range hdr.PAXRecords {
		name, ok := strings.CutPrefix(k, paxXattr)
		if !ok {
			continue
		}

		if name == "" || len(e.Xattrs) >= maxEntryXattrs {
			return bad("%q has an invalid or too many extended attributes", short(e.Name))
		}

		total += len(name) + len(v)
		if total > maxEntryXattrBytes {
			return bad("%q has more than %d bytes of extended attributes", short(e.Name), maxEntryXattrBytes)
		}

		if e.Xattrs == nil {
			e.Xattrs = make(map[string][]byte)
		}

		e.Xattrs[name] = []byte(v)
	}

	return nil
}

const sha1HexLen = 40

// specialMode converts the permission and special bits of a tar mode.
func specialMode(m int64) fs.FileMode {
	mode := fs.FileMode(m & 0o777)

	if m&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}

	if m&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}

	if m&0o1000 != 0 {
		mode |= fs.ModeSticky
	}

	return mode
}
