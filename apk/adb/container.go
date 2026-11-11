package adb

import (
	"bufio"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// Default limits; see [Limits].
const (
	// DefaultMaxADB is the default bound on the ADB block. The format itself
	// cannot address more than 256 MiB.
	DefaultMaxADB int64 = 64 << 20
	// DefaultMaxStream is the default bound on the bytes of a file once
	// decompressed.
	DefaultMaxStream int64 = 16 << 30
	// DefaultMaxEntries is the default bound on the entries of one list: the
	// files of a package, the packages of an index.
	DefaultMaxEntries = 1 << 20

	maxADBFormat = valueMask
	// maxSignature is the largest signature block the format allows.
	maxSignature = 2048
)

// Limits bound the resources reading a file may use. The zero value applies
// the defaults.
type Limits struct {
	// MaxADB bounds the ADB block, the metadata of a package or an index.
	// Zero means [DefaultMaxADB].
	MaxADB int64
	// MaxStream bounds the bytes of the file once decompressed, which stops a
	// decompression bomb. Zero means [DefaultMaxStream].
	MaxStream int64
	// MaxEntries bounds the elements of any list read, and the files of a
	// package in all. Zero means [DefaultMaxEntries].
	MaxEntries int
	// MaxNodes bounds the values decoded from the ADB block. The values of
	// an ADB block form a graph in which one value can be shared by many,
	// so a small block can ask for a very large decode. Zero means 16Mi.
	MaxNodes int
	// MaxDecodedBytes bounds the memory those values take. Zero means 256 MiB.
	MaxDecodedBytes int64
}

func (l Limits) maxADB() int64 {
	if l.MaxADB <= 0 {
		return DefaultMaxADB
	}

	return min(l.MaxADB, maxADBFormat)
}

func (l Limits) maxStream() int64 {
	if l.MaxStream <= 0 {
		return DefaultMaxStream
	}

	return l.MaxStream
}

func (l Limits) maxEntries() int {
	if l.MaxEntries <= 0 {
		return DefaultMaxEntries
	}

	return l.MaxEntries
}

func (l Limits) maxNodes() int {
	if l.MaxNodes <= 0 {
		return defaultMaxNodes
	}

	return l.MaxNodes
}

func (l Limits) maxDecodedBytes() int64 {
	if l.MaxDecodedBytes <= 0 {
		return defaultMaxDecodedBytes
	}

	return l.MaxDecodedBytes
}

// CompAlg is a compression algorithm of the file.
type CompAlg uint8

// Compression algorithms.
const (
	// CompNone stores the file as it is.
	CompNone CompAlg = iota
	// CompDeflate wraps the file in a raw deflate stream.
	CompDeflate
	// CompZstd wraps the file in a Zstandard frame.
	CompZstd
)

// Compression selects how a file is compressed as a whole: ADB block and data
// blocks alike. The zero value is the default of apk: deflate at its default
// level.
type Compression struct {
	Alg CompAlg
	// Level is the level of the algorithm: 1 to 9 for deflate, 1 to 22 for
	// Zstandard. Zero means the default.
	Level int
}

// Compression choices.
var (
	// NoCompression stores the file uncompressed. It cannot be told apart
	// from the zero Compression by value alone, so it has a dedicated level.
	NoCompression = Compression{Alg: CompNone, Level: 1}
	// Deflate is deflate at the default level; the default of apk.
	Deflate = Compression{Alg: CompDeflate}
	// Zstd is Zstandard at its default level.
	Zstd = Compression{Alg: CompZstd}
)

// Magics of the file header.
const (
	magicADB  = "ADB."
	magicDefl = "ADBd"
	magicComp = "ADBc"

	fileHdrSize = 8
)

// openStream undoes the compression of the file and checks the file header.
// It returns the reader positioned at the first block, the schema, the
// compression and a function that releases the decompressor.
func openStream(r io.Reader, maxStream int64) (*bufio.Reader, uint32, Compression, func(), error) {
	br := bufio.NewReaderSize(r, 64<<10)
	noop := func() {}

	magic, err := br.Peek(4)
	if err != nil {
		return nil, 0, Compression{}, noop, headerErr(err)
	}

	var (
		comp    = NoCompression
		plain   io.Reader
		release = noop
	)

	switch string(magic) {
	case magicADB:
		plain = br
	case magicDefl:
		_, _ = br.Discard(4)
		plain, comp = flate.NewReader(br), Deflate
	case magicComp:
		_, _ = br.Discard(4)

		var spec [2]byte
		if _, err := io.ReadFull(br, spec[:]); err != nil {
			return nil, 0, Compression{}, noop, headerErr(err)
		}

		switch CompAlg(spec[0]) {
		case CompDeflate:
			plain = flate.NewReader(br)
		case CompZstd:
			zr, err := zstd.NewReader(br, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(1<<30))
			if err != nil {
				return nil, 0, Compression{}, noop, fmt.Errorf("%w: %w", ErrCompression, err)
			}

			plain, release = zr, zr.Close
		default:
			return nil, 0, Compression{}, noop, fmt.Errorf("%w: algorithm %d", ErrCompression, spec[0])
		}

		comp = Compression{Alg: CompAlg(spec[0]), Level: int(spec[1])}
	default:
		return nil, 0, Compression{}, noop, invalid("not an apk v3 file: magic %q", magic)
	}

	if comp.Alg != CompNone {
		br = bufio.NewReaderSize(limitio.Capped(plain, maxStream, ErrTooComplex), 64<<10)
	}

	var hdr [fileHdrSize]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		release()

		return nil, 0, Compression{}, noop, headerErr(err)
	}

	if string(hdr[:4]) != magicADB {
		release()

		return nil, 0, Compression{}, noop, invalid("not an apk v3 file: magic %q", hdr[:4])
	}

	return br, binary.LittleEndian.Uint32(hdr[4:]), comp, release, nil
}

func headerErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return invalid("file too short for an apk v3 header")
	}

	return fmt.Errorf("%w: %w", ErrInvalid, err)
}

// Block types.
const (
	blockADB  = 0
	blockSig  = 1
	blockData = 2
	blockExt  = 3

	blockAlign = 8
	// stdBlockMax is the largest payload a block with a short header holds.
	stdBlockMax = 0x3fffffff - 4
)

// blockHdr describes the block at the head of the stream.
type blockHdr struct {
	typ uint32
	// length is the bytes of the payload.
	length uint64
	// padding follows the payload.
	padding int
}

// readBlockHdr reads the header of the next block. At a clean end of the
// stream it returns io.EOF.
func readBlockHdr(br *bufio.Reader) (blockHdr, error) {
	p, err := br.Peek(4)
	if err != nil {
		if errors.Is(err, io.EOF) && len(p) == 0 {
			return blockHdr{}, io.EOF
		}

		return blockHdr{}, blockErr("truncated block header")
	}

	ts := binary.LittleEndian.Uint32(p)

	var h blockHdr

	var raw uint64

	hdrLen := 4

	if ts>>30 == blockExt {
		hdrLen = 16

		p, err = br.Peek(hdrLen)
		if err != nil {
			return blockHdr{}, blockErr("truncated extended block header")
		}

		h.typ = ts & 0x3fffffff
		raw = binary.LittleEndian.Uint64(p[8:])
	} else {
		h.typ = ts >> 30
		raw = uint64(ts & 0x3fffffff)
	}

	if raw < uint64(hdrLen) {
		return blockHdr{}, blockErr("block of %d bytes is shorter than its header", raw)
	}

	_, _ = br.Discard(hdrLen)

	h.length = raw - uint64(hdrLen)
	h.padding = int((blockAlign - raw%blockAlign) % blockAlign)

	return h, nil
}

// skipPadding discards the padding after a block.
func skipPadding(br *bufio.Reader, h blockHdr) error {
	if h.padding == 0 {
		return nil
	}

	if _, err := br.Discard(h.padding); err != nil {
		return blockErr("truncated block padding")
	}

	return nil
}

// blockTag encodes the header of a block of the given payload length.
func blockTag(typ uint32, length uint64) []byte {
	if length <= stdBlockMax {
		return binary.LittleEndian.AppendUint32(nil, typ<<30+4+uint32(length))
	}

	p := binary.LittleEndian.AppendUint32(nil, blockExt<<30+typ)
	p = binary.LittleEndian.AppendUint32(p, 0)

	return binary.LittleEndian.AppendUint64(p, 16+length)
}

// blockPad is the number of bytes that pad a block of the given payload.
func blockPad(typ uint32, length uint64) int {
	raw := length + uint64(len(blockTag(typ, length)))

	return int((blockAlign - raw%blockAlign) % blockAlign)
}
