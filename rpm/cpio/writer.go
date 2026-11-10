package cpio

import (
	"errors"
	"fmt"
	"io"
	"math"
)

var (
	// ErrWriteTooLong indicates that an attempt was made to write more than
	// Header.Size bytes to the current file.
	ErrWriteTooLong = errors.New("cpio: write too long")

	// ErrWriteAfterClose indicates that an attempt was made to write to the
	// archive after it was closed.
	ErrWriteAfterClose = errors.New("cpio: write after close")

	// ErrFileTooLarge indicates a file that does not fit the 8 hexadecimal
	// digits of the size field of a newc header (4 GiB - 1).
	ErrFileTooLarge = errors.New("cpio: file too large for the newc format")
)

// Header describes a file written to an archive.
type Header struct {
	// Name is the path of the file. Stripped archives have no names.
	Name string
	// Mode holds the file type and permission bits. A mode without type bits
	// is a regular file.
	Mode uint32
	// Size is the number of bytes of content that follow the header.
	Size int64
	// Links is the number of links to the file. A regular file has at least one.
	Links int
	// Index is the position of the file in the file lists of the RPM header.
	// It is only used by stripped archives, where it replaces the metadata
	// that the RPM header already holds.
	Index int
}

// Writer writes a cpio archive of the "newc" (SVR4 without checksum) kind, or
// its RPM stripped variant. Call WriteHeader for each file and write the
// content of the file with Write.
//
// Hexadecimal digits of the headers are written in upper case by the newc
// writer and in lower case by the stripped one (and by the trailer that closes
// a stripped archive), which is what packages carry in either format.
type Writer struct {
	w        io.Writer
	stripped bool
	// remaining is the number of unwritten bytes of the current file.
	remaining int64
	// pad is the number of bytes to write after the current file.
	pad    int64
	inode  uint32
	err    error
	closed bool
}

// NewWriter returns a Writer of a newc archive.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// NewStrippedWriter returns a Writer of the stripped archive found in the
// payload of RPM v6 packages: instead of the metadata of a file it has the
// index of the file, see Header.Index.
func NewStrippedWriter(w io.Writer) *Writer {
	return &Writer{w: w, stripped: true}
}

// modePerm masks the permission bits of a mode.
const modePerm = 0o777

const (
	newcFormatUpper = "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X"
	newcFormatLower = "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x"
)

var zeroBlock [4]byte

// flush writes the padding that follows the current file.
func (w *Writer) flush() error {
	if w.remaining > 0 {
		return fmt.Errorf("cpio: missed writing %d bytes", w.remaining)
	}
	if w.pad > 0 {
		if _, err := w.w.Write(zeroBlock[:w.pad]); err != nil {
			return err
		}
		w.pad = 0
	}
	return nil
}

// WriteHeader writes the header of the next file, after the padding of the
// previous one. The previous file must be completely written.
func (w *Writer) WriteHeader(hdr *Header) error {
	if w.closed {
		return ErrWriteAfterClose
	}
	if w.err != nil {
		return w.err
	}
	w.err = w.writeHeader(hdr)
	return w.err
}

func (w *Writer) writeHeader(hdr *Header) error {
	if err := w.flush(); err != nil {
		return err
	}
	if hdr.Size < 0 || (!w.stripped && hdr.Size > math.MaxUint32) {
		return fmt.Errorf("%w: %d bytes", ErrFileTooLarge, hdr.Size)
	}
	if w.stripped {
		// "07070X", the index, and padding to 4 bytes before the content
		h := fmt.Appendf(nil, "%s%08x", strippedMagic, hdr.Index)
		h = append(h, zeroBlock[:(4-len(h)%4)%4]...)
		if _, err := w.w.Write(h); err != nil {
			return err
		}
	} else if err := w.writeNewc(hdr, newcFormatUpper); err != nil {
		return err
	}
	w.remaining = hdr.Size
	w.pad = (4 - hdr.Size%4) % 4
	return nil
}

// writeNewc writes a newc header and the name of the file.
func (w *Writer) writeNewc(hdr *Header, format string) error {
	mode, links := hdr.Mode, hdr.Links
	var inode uint32
	if hdr.Name != TRAILER {
		// ensure all inodes are unique
		w.inode++
		inode = w.inode
		// ensure the file type is set
		if mode&^modePerm == 0 {
			mode |= S_ISREG
		}
		// ensure plain regular files (those without setuid, setgid or sticky
		// bits) have at least 1 inbound link
		if links < 1 && mode&^modePerm == S_ISREG {
			links = 1
		}
	}
	// ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
	// rdevmajor, rdevminor, namesize, check
	h := fmt.Appendf(nil, format,
		inode, mode, 0, 0, links, 0, hdr.Size, 0, 0, 0, 0, len(hdr.Name)+1, 0)
	h = append(h, hdr.Name...)
	h = append(h, 0)
	// the name is padded so that header plus name is a multiple of 4
	h = append(h, zeroBlock[:(4-len(h)%4)%4]...)
	_, err := w.w.Write(h)
	return err
}

// Write writes to the current file. It returns ErrWriteTooLong if more than
// Header.Size bytes are written in total.
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, ErrWriteAfterClose
	}
	if w.err != nil {
		return 0, w.err
	}
	overwrite := int64(len(p)) > w.remaining
	if overwrite {
		p = p[:w.remaining]
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	if err != nil {
		w.err = err
		return n, err
	}
	if overwrite {
		return n, ErrWriteTooLong
	}
	return n, nil
}

// Close finishes the archive with its trailer. It does not close the
// underlying writer. The current file must be completely written.
func (w *Writer) Close() error {
	if w.closed || w.err != nil {
		return w.err
	}
	if w.err = w.flush(); w.err != nil {
		return w.err
	}
	format := newcFormatUpper
	if w.stripped {
		format = newcFormatLower
	}
	w.err = w.writeNewc(&Header{Name: TRAILER, Links: 1}, format)
	w.closed = true
	return w.err
}
