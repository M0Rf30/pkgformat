package deb

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ARHeader is the header of one member of an ar archive.
type ARHeader struct {
	Name    string
	ModTime time.Time
	OwnerID int
	GroupID int
	Mode    int
	Size    int64
}

const (
	arMagic       = "!<arch>\n"
	arHeaderSize  = 60
	arMemberAlign = 2
	arNameLen     = 16

	// maxARMembers bounds how many members the reader walks. A .deb carries
	// debian-binary, control.tar.* and data.tar.* and, rarely, a signature
	// member or two.
	maxARMembers = 64
)

// parseARHeader parses a 60-byte ar member header.
func parseARHeader(buf []byte) (ARHeader, error) {
	if len(buf) != arHeaderSize {
		return ARHeader{}, fmt.Errorf("%w: %d", ErrInvalidHeaderSize, len(buf))
	}

	if buf[58] != '`' || buf[59] != '\n' {
		return ARHeader{}, ErrInvalidARHeaderEnd
	}

	header := ARHeader{}

	// The name may end in "/" (GNU ar); dpkg-deb writes it without.
	header.Name = strings.TrimSuffix(strings.TrimRight(string(buf[0:16]), " "), "/")

	modTimeStr := strings.TrimSpace(string(buf[16:28]))

	modTime, err := strconv.ParseInt(modTimeStr, 10, 64)
	if err != nil {
		return ARHeader{}, fmt.Errorf("%w: %q", ErrInvalidModTime, modTimeStr)
	}

	header.ModTime = time.Unix(modTime, 0)

	ownerStr := strings.TrimSpace(string(buf[28:34]))

	owner, err := strconv.Atoi(ownerStr)
	if err != nil {
		return ARHeader{}, fmt.Errorf("%w: %q", ErrInvalidOwnerID, ownerStr)
	}

	header.OwnerID = owner

	groupStr := strings.TrimSpace(string(buf[34:40]))

	group, err := strconv.Atoi(groupStr)
	if err != nil {
		return ARHeader{}, fmt.Errorf("%w: %q", ErrInvalidGroupID, groupStr)
	}

	header.GroupID = group

	modeStr := strings.TrimSpace(string(buf[40:48]))

	mode, err := strconv.ParseInt(modeStr, 8, 32)
	if err != nil {
		return ARHeader{}, fmt.Errorf("%w: %q", ErrInvalidMode, modeStr)
	}

	header.Mode = int(mode)

	sizeStr := strings.TrimSpace(string(buf[48:58]))

	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil || size < 0 {
		return ARHeader{}, fmt.Errorf("%w: %q", ErrInvalidSize, sizeStr)
	}

	header.Size = size

	return header, nil
}

// arMember is one member located inside an ar archive read through a ReaderAt.
type arMember struct {
	ARHeader
	// dataOff is the offset of the member's data in the archive.
	dataOff int64
}

// readARMembers walks the member headers of the ar archive in r (size bytes
// long) and returns them in order, without reading any member data. Every
// member is checked to lie within the archive.
func readARMembers(r io.ReaderAt, size int64) ([]arMember, error) {
	magic := make([]byte, len(arMagic))
	if _, err := r.ReadAt(magic, 0); err != nil {
		return nil, fmt.Errorf("reading ar magic: %w", err)
	}

	if string(magic) != arMagic {
		return nil, fmt.Errorf("%w: %q", ErrInvalidARMagic, magic)
	}

	var (
		members []arMember
		headBuf [arHeaderSize]byte
	)

	off := int64(len(arMagic))

	for off+arHeaderSize <= size {
		if len(members) >= maxARMembers {
			return nil, fmt.Errorf("%w: more than %d", ErrTooManyMembers, maxARMembers)
		}

		if _, err := r.ReadAt(headBuf[:], off); err != nil {
			return nil, fmt.Errorf("reading ar member header: %w", err)
		}

		header, err := parseARHeader(headBuf[:])
		if err != nil {
			return nil, fmt.Errorf("parsing ar member header: %w", err)
		}

		dataOff := off + arHeaderSize
		if header.Size > size-dataOff {
			return nil, fmt.Errorf("%w: member %q declares size %d beyond end of file",
				ErrARMemberTooLarge, header.Name, header.Size)
		}

		members = append(members, arMember{ARHeader: header, dataOff: dataOff})

		off = dataOff + header.Size
		if header.Size%arMemberAlign != 0 {
			off += arMemberAlign - (header.Size % arMemberAlign)
		}
	}

	return members, nil
}

// arWriter writes an ar archive.
type arWriter struct {
	w   io.Writer
	err error
}

func newARWriter(w io.Writer) (*arWriter, error) {
	if _, err := io.WriteString(w, arMagic); err != nil {
		return nil, fmt.Errorf("writing ar magic: %w", err)
	}

	return &arWriter{w: w}, nil
}

// member writes one member of exactly size bytes copied from r, with the
// owner 0:0 and mode 0644 dpkg-deb uses.
func (a *arWriter) member(name string, size int64, modTime time.Time, r io.Reader) error {
	if a.err != nil {
		return a.err
	}

	if len(name) > arNameLen || name == "" || strings.ContainsAny(name, " /\n") {
		a.err = fmt.Errorf("%w: ar member name %q", ErrInvalidSpec, name)

		return a.err
	}

	if size < 0 {
		a.err = fmt.Errorf("%w: ar member size %d", ErrInvalidSize, size)

		return a.err
	}

	mtime := max(modTime.Unix(), 0)

	hdr := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name, mtime, 0, 0, 0o100644, size)
	if len(hdr) != arHeaderSize {
		a.err = fmt.Errorf("%w: ar header does not fit (%d bytes)", ErrInvalidSize, len(hdr))

		return a.err
	}

	if _, err := io.WriteString(a.w, hdr); err != nil {
		a.err = fmt.Errorf("writing ar header: %w", err)

		return a.err
	}

	n, err := io.Copy(a.w, io.LimitReader(r, size))
	if err != nil {
		a.err = fmt.Errorf("writing ar member %q: %w", name, err)

		return a.err
	}

	if n != size {
		a.err = fmt.Errorf("writing ar member %q: %w: short body (%d of %d bytes)", name, io.ErrUnexpectedEOF, n, size)

		return a.err
	}

	if size%arMemberAlign != 0 {
		if _, err := io.WriteString(a.w, "\n"); err != nil {
			a.err = fmt.Errorf("writing ar padding: %w", err)

			return a.err
		}
	}

	return nil
}
