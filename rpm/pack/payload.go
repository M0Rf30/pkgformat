package pack

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	gzip "github.com/klauspost/pgzip"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// ErrInvalidCompressor is returned for a compressor setting that rpm packages cannot use.
var ErrInvalidCompressor = errors.New("invalid rpm payload compressor")

// compressor describes how the payload is compressed.
type compressor struct {
	// name is the value of PAYLOADCOMPRESSOR.
	name string
	// level is the value of PAYLOADFLAGS: the compression level actually used.
	level string
	open  func(io.Writer) (io.WriteCloser, error)
}

// parseCompressor parses a setting such as "gzip", "zstd:19" or "xz".
func parseCompressor(setting string) (*compressor, error) {
	typ, lvl, hasLevel := strings.Cut(setting, ":")
	if strings.Contains(lvl, ":") {
		return nil, fmt.Errorf("%w: malformed setting %q", ErrInvalidCompressor, setting)
	}
	switch typ {
	case "", "gzip":
		level := 9
		if hasLevel && lvl != "" {
			n, err := strconv.Atoi(lvl)
			if err != nil {
				return nil, fmt.Errorf("%w: parse gzip level: %w", ErrInvalidCompressor, err)
			}
			if n < 1 || n > 9 {
				return nil, fmt.Errorf("%w: gzip level %d is not in 1..9", ErrInvalidCompressor, n)
			}
			level = n
		}
		return &compressor{"gzip", strconv.Itoa(level), func(w io.Writer) (io.WriteCloser, error) {
			return gzip.NewWriterLevel(w, level)
		}}, nil
	case "lzma", "xz":
		if hasLevel && lvl != "" {
			return nil, fmt.Errorf("%w: no compressor level supported for %s: %s", ErrInvalidCompressor, typ, lvl)
		}
		open := func(w io.Writer) (io.WriteCloser, error) { return xz.NewWriter(w) }
		if typ == "lzma" {
			open = func(w io.Writer) (io.WriteCloser, error) { return lzma.NewWriter(w) }
		}
		// The writers have a single configuration, which is preset 6 of xz(1): an
		// 8 MiB dictionary.
		return &compressor{typ, "6", open}, nil
	case "zstd":
		level, flags := zstd.SpeedBetterCompression, "7"
		if hasLevel && lvl != "" {
			if n, err := strconv.Atoi(lvl); err == nil {
				if n < 0 || n > 22 {
					return nil, fmt.Errorf("%w: zstd level %d is not in 1..22", ErrInvalidCompressor, n)
				}
				level, flags = zstd.EncoderLevelFromZstd(n), lvl
			} else {
				ok, l := zstd.EncoderLevelFromString(lvl)
				if !ok {
					return nil, fmt.Errorf("%w: invalid zstd level %q", ErrInvalidCompressor, lvl)
				}
				level = l
				// the zstd levels the named speeds correspond to
				flags = map[zstd.EncoderLevel]string{
					zstd.SpeedFastest: "1", zstd.SpeedDefault: "3",
					zstd.SpeedBetterCompression: "7", zstd.SpeedBestCompression: "11",
				}[l]
			}
		}
		return &compressor{"zstd", flags, func(w io.Writer) (io.WriteCloser, error) {
			return zstd.NewWriter(w, zstd.WithEncoderLevel(level))
		}}, nil
	}
	return nil, fmt.Errorf("%w: unknown compressor type %q", ErrInvalidCompressor, typ)
}

// File digest algorithms of rpm (the values of FILEDIGESTALGO).
const (
	// DigestSHA256 is the default file digest algorithm.
	DigestSHA256 = 8
	// DigestSHA512 selects SHA-512.
	DigestSHA512 = 10
	// DigestSHA3256 selects SHA3-256.
	DigestSHA3256 = 12
	// DigestSHA3512 selects SHA3-512.
	DigestSHA3512 = 14
)

// ErrInvalidDigest is returned for a file digest algorithm rpm does not support.
var ErrInvalidDigest = errors.New("unsupported rpm file digest algorithm")

func newFileHash(algo int) (hash.Hash, error) {
	switch algo {
	case DigestSHA256:
		return sha256.New(), nil
	case DigestSHA512:
		return sha512.New(), nil
	case DigestSHA3256:
		return sha3.New256(), nil
	case DigestSHA3512:
		return sha3.New512(), nil
	}
	return nil, fmt.Errorf("%w: %d", ErrInvalidDigest, algo)
}

// countWriter counts and forwards the bytes written.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// archive writes the cpio archive of the payload: the "newc" format of rpm 4 and
// the stripped variant of rpm 6, which names files by their header index.
type archive struct {
	w        io.Writer
	stripped bool
	err      error
	// pad is the number of bytes owed after the current content.
	pad int
	// remaining is the number of content bytes the current file still needs.
	remaining int64
}

// entryHeader describes one payload entry.
type entryHeader struct {
	name       string // path in the package, absolute
	index      int    // header index, for the stripped format
	ino        uint32
	mode       uint32
	nlink      uint32
	mtime      uint32
	size       int64
	rmaj, rmin uint32
}

func (a *archive) write(p []byte) {
	if a.err == nil {
		_, a.err = a.w.Write(p)
	}
}

var zeroPad [4]byte

// begin writes the header of an entry. The caller writes exactly size bytes of
// content with a, then calls end.
func (a *archive) begin(h entryHeader) {
	if a.err != nil {
		return
	}
	if a.stripped {
		b := fmt.Appendf(nil, "07070X%08x", h.index)
		b = append(b, zeroPad[:(4-len(b)%4)%4]...)
		a.write(b)
	} else {
		a.write(newcHeader("."+h.name, h))
	}
	a.remaining = h.size
	a.pad = int((4 - h.size%4) % 4)
}

// newcHeader encodes a newc header with the name of the file.
func newcHeader(name string, h entryHeader) []byte {
	b := fmt.Appendf(nil, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		h.ino, h.mode, 0, 0, h.nlink, h.mtime, h.size, 0, 0, h.rmaj, h.rmin, len(name)+1, 0)
	b = append(b, name...)
	b = append(b, 0)
	return append(b, zeroPad[:(4-len(b)%4)%4]...)
}

// Write writes content of the current entry.
func (a *archive) Write(p []byte) (int, error) {
	if a.err != nil {
		return 0, a.err
	}
	if int64(len(p)) > a.remaining {
		a.err = errors.New("pack: file content longer than its size")
		return 0, a.err
	}
	n, err := a.w.Write(p)
	a.remaining -= int64(n)
	a.err = err
	return n, err
}

// end finishes the current entry with its padding.
func (a *archive) end() {
	if a.err == nil && a.remaining != 0 {
		a.err = fmt.Errorf("pack: file content is %d bytes short", a.remaining)
	}
	a.write(zeroPad[:a.pad])
	a.pad = 0
}

// close writes the trailer.
func (a *archive) close() error {
	a.write(newcHeader("TRAILER!!!", entryHeader{nlink: 1}))
	return a.err
}

// spool is a file holding the compressed payload until the header, which needs
// the payload digests, is complete.
type spool struct {
	f *os.File
}

func newSpool(dir string) (*spool, error) {
	f, err := os.CreateTemp(dir, "pkgformat-rpm-payload-*")
	if err != nil {
		return nil, fmt.Errorf("create payload spool file: %w", err)
	}
	return &spool{f: f}, nil
}

func (s *spool) close() {
	name := s.f.Name()
	_ = s.f.Close()
	_ = os.Remove(name)
}

// reader returns a reader of the whole spooled payload.
func (s *spool) reader(size int64) io.Reader { return io.NewSectionReader(s.f, 0, size) }
