package pacman

import (
	"archive/tar"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// Entry is one member of a package archive: its path, kind and the metadata a
// file system keeps.
type Entry struct {
	// Path is the slash-separated path below the root of the package, without
	// a leading "./" or a trailing "/". The metadata files are listed as
	// ".PKGINFO", ".MTREE" and so on.
	Path string
	// Mode holds the permission bits, setuid, setgid and sticky, and the type
	// bit: fs.ModeDir, fs.ModeSymlink, fs.ModeNamedPipe, fs.ModeDevice or
	// fs.ModeDevice|fs.ModeCharDevice. A regular file and a hard link have no
	// type bit.
	Mode fs.FileMode
	// UID and GID are the numeric owner; Uname and Gname the names, which may
	// be empty.
	UID, GID     int
	Uname, Gname string
	// Size is the length of the content in the archive: zero for everything but
	// a regular file that carries data (a hard link member has none).
	Size    int64
	ModTime time.Time
	// Linkname is the target of a symbolic link.
	Linkname string
	// Hardlink is the path of the member a hard link member links to; empty for
	// every other kind.
	Hardlink string
	// DevMajor and DevMinor are the device number of a device node.
	DevMajor, DevMinor int64
	// Xattrs are the extended attributes stored in the PAX records, such as
	// "security.capability".
	Xattrs map[string][]byte
}

// IsDir reports whether the entry is a directory.
func (e *Entry) IsDir() bool { return e.Mode&fs.ModeDir != 0 }

// IsRegular reports whether the entry is a regular file that carries content;
// a hard link member is not.
func (e *Entry) IsRegular() bool { return e.Mode.IsRegular() && e.Hardlink == "" }

// IsMetadata reports whether the entry is one of the dot files that describe
// the package and are not part of its payload.
func (e *Entry) IsMetadata() bool { return strings.HasPrefix(e.Path, ".") }

// Limits on the extended attributes of an entry read from an archive.
const (
	// MaxEntryXattrs bounds the extended attributes of one entry.
	MaxEntryXattrs = 256
	// MaxXattrValueBytes bounds the value of one extended attribute.
	MaxXattrValueBytes = 64 << 10
)

// WalkPackage reads a .pkg.tar.{zst,xz,gz} from r and calls fn for each member
// in archive order, the metadata files included. body yields the content of a
// regular file and is empty for any other kind; it is valid until fn returns.
// A non-nil error of fn stops the walk and is returned as it is.
//
// The archive is untrusted: its decompressed size, the number of its entries,
// the length of paths and the number of extended attributes are bounded, and a
// path that is absolute, climbs above the root or holds a control character is
// refused with ErrUnsafeEntry. Socket-like and unknown member types fail with
// ErrUnsupportedFile.
func WalkPackage(r io.Reader, fn func(e *Entry, body io.Reader) error) error {
	dec, _, closeDec, err := openCompressed(r)
	if err != nil {
		return err
	}

	defer closeDec()

	tr := tar.NewReader(limitio.Capped(dec, MaxUncompressedBytes, ErrPackageTooLarge))

	var (
		entries   int
		sawHeader bool
	)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			if errors.Is(err, ErrPackageTooLarge) {
				return err
			}

			if !sawHeader {
				return fmt.Errorf("%w: %w", ErrNotPackage, err)
			}

			return fmt.Errorf("pacman: reading package archive: %w", err)
		}

		sawHeader = true

		if entries++; entries > MaxFileEntries {
			return fmt.Errorf("%w: too many entries", ErrPackageTooLarge)
		}

		e, err := entryOf(hdr)
		if err != nil {
			return err
		}

		if e == nil {
			continue
		}

		if err := fn(e, tr); err != nil {
			return err
		}
	}
}

// entryOf converts a tar header; nil for the archive root.
func entryOf(hdr *tar.Header) (*Entry, error) {
	name, err := cleanEntryName(hdr.Name)
	if err != nil {
		return nil, err
	}

	if name == "" {
		return nil, nil //nolint:nilnil // the archive root is not an entry
	}

	e := &Entry{
		Path: name, Mode: hdr.FileInfo().Mode(), UID: hdr.Uid, GID: hdr.Gid, Uname: hdr.Uname, Gname: hdr.Gname,
		Size: hdr.Size, ModTime: hdr.ModTime,
	}

	switch hdr.Typeflag {
	case tar.TypeReg, tar.TypeRegA, tar.TypeDir: //nolint:staticcheck // old archives use the NUL type
	case tar.TypeSymlink:
		e.Linkname = hdr.Linkname
	case tar.TypeLink:
		if e.Hardlink, err = cleanEntryName(hdr.Linkname); err != nil {
			return nil, err
		}

		if e.Hardlink == "" {
			return nil, fmt.Errorf("%w: hard link %q to the archive root", ErrUnsafeEntry, name)
		}
	case tar.TypeFifo, tar.TypeChar, tar.TypeBlock:
		e.DevMajor, e.DevMinor = hdr.Devmajor, hdr.Devminor
	default:
		return nil, fmt.Errorf("%w: %q has type %q", ErrUnsupportedFile, name, string(hdr.Typeflag))
	}

	if e.Xattrs, err = headerXattrs(hdr); err != nil {
		return nil, fmt.Errorf("%w (%s)", err, name)
	}

	return e, nil
}

// headerXattrs reads the extended attributes of a header: the raw value of a
// SCHILY.xattr.<name> record, or else the base64 value of a
// LIBARCHIVE.xattr.<escaped name> record.
func headerXattrs(hdr *tar.Header) (map[string][]byte, error) {
	var out map[string][]byte

	put := func(name string, value []byte) error {
		if len(value) > MaxXattrValueBytes {
			return fmt.Errorf("%w: extended attribute %q is over %d bytes", ErrUnsafeEntry, name, MaxXattrValueBytes)
		}

		if out == nil {
			out = map[string][]byte{}
		}

		if _, ok := out[name]; ok {
			return nil
		}

		if len(out) >= MaxEntryXattrs {
			return fmt.Errorf("%w: more than %d extended attributes", ErrUnsafeEntry, MaxEntryXattrs)
		}

		out[name] = value

		return nil
	}

	for k, v := range hdr.PAXRecords {
		if name, ok := strings.CutPrefix(k, paxSchilyXattr); ok && name != "" {
			if err := put(name, []byte(v)); err != nil {
				return nil, err
			}
		}
	}

	for k, v := range hdr.PAXRecords {
		esc, ok := strings.CutPrefix(k, paxLibarchiveAttr)
		if !ok {
			continue
		}

		name, err := url.PathUnescape(esc)
		if err != nil || name == "" {
			return nil, fmt.Errorf("%w: bad extended attribute name %q", ErrUnsafeEntry, short(esc))
		}

		value, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("%w: extended attribute %q: %w", ErrUnsafeEntry, name, err)
		}

		if err := put(name, value); err != nil {
			return nil, err
		}
	}

	return out, nil
}
