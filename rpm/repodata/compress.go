package repodata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// ErrEmptyDocument is returned when a metadata generator wrote nothing.
var ErrEmptyDocument = errors.New("repodata: empty xml document")

// Compression selects how a repodata document is compressed.
type Compression int

const (
	// Gzip is the compression every dnf and createrepo_c understands. The
	// zero value.
	Gzip Compression = iota
	// Zstd is smaller and faster to decompress; dnf 4 and later read it.
	Zstd
	// XZ is the smallest; it is slow to compress.
	XZ
	// Zchunk is a zchunk file (see [ZchunkWriter]): zstd-compressed chunks,
	// one per package of a primary, filelists or other document, so a client
	// that has the previous version downloads only the packages that
	// changed. dnf and createrepo_c know it as the *_zck data types.
	Zchunk
)

// Extension returns the file name suffix of the compression: ".gz", ".zst",
// ".xz" or ".zck".
func (c Compression) Extension() string {
	switch c {
	case Zstd:
		return ".zst"
	case XZ:
		return ".xz"
	case Zchunk:
		return ".zck"
	default:
		return ".gz"
	}
}

// String returns the name of the compression.
func (c Compression) String() string {
	switch c {
	case Zstd:
		return "zstd"
	case XZ:
		return "xz"
	case Zchunk:
		return "zchunk"
	default:
		return "gzip"
	}
}

// CompressedMetadata is one repodata document compressed for repomd.xml.
type CompressedMetadata struct {
	// Data is the compressed document.
	Data []byte
	// SHA256 is the hex checksum of Data (the checksum of the repomd.xml
	// data entry).
	SHA256 string
	// Size is len(Data).
	Size int64
	// OpenSHA256 is the hex checksum of the uncompressed document (the
	// open-checksum of the data entry).
	OpenSHA256 string
	// OpenSize is the size of the uncompressed document.
	OpenSize int64
	// HeaderSHA256 and HeaderSize are the checksum and length of the header
	// of a zchunk file (the header-checksum and header-size of the data
	// entry); empty and zero for any other compression.
	HeaderSHA256 string
	HeaderSize   int64
}

// Entry returns the repomd.xml data entry of the document of the given type
// (see [RepomdData.Type]) stored as repodata/<name>; timestamp is the Unix
// time to record.
func (c *CompressedMetadata) Entry(typ, name string, timestamp int64) RepomdData {
	e := RepomdData{
		Type:             typ,
		Location:         "repodata/" + name,
		Checksum:         c.SHA256,
		ChecksumType:     "sha256",
		OpenChecksum:     c.OpenSHA256,
		OpenChecksumType: "sha256",
		Timestamp:        timestamp,
		Size:             c.Size,
		OpenSize:         c.OpenSize,
	}

	if c.HeaderSHA256 != "" {
		e.HeaderChecksum, e.HeaderChecksumType, e.HeaderSize = c.HeaderSHA256, "sha256", c.HeaderSize
	}

	return e
}

// gzipLevel trades a little size for a lot of CPU: on real primary, filelists
// and other documents level 6 compresses at 3-10x the speed of level 9 and
// produces output about 1-5 % larger.
const gzipLevel = 6

// hashedBuffer collects compressed output and hashes it on the way.
type hashedBuffer struct {
	buf bytes.Buffer
	h   hash.Hash
}

func newHashedBuffer() *hashedBuffer { return &hashedBuffer{h: sha256.New()} }

func (b *hashedBuffer) Write(p []byte) (int, error) {
	b.h.Write(p)

	return b.buf.Write(p)
}

// countingWriter counts and hashes the bytes that pass through it.
type countingWriter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	c.h.Write(p[:n])

	return n, err
}

// newEncoder returns the compressor of c writing into w.
func newEncoder(c Compression, w io.Writer) (io.WriteCloser, error) {
	switch c {
	case Gzip:
		return gzip.NewWriterLevel(w, gzipLevel)
	case Zstd:
		return zstd.NewWriter(w, zstd.WithEncoderConcurrency(1))
	case XZ:
		return xz.NewWriter(w)
	case Zchunk:
		return NewZchunkWriter(w, ZchunkOptions{Chunking: ZchunkXMLPackages})
	default:
		return nil, fmt.Errorf("repodata: unknown compression %d", int(c))
	}
}

// CompressMetadataStream runs write against a sink that feeds the encoder of
// c, so the uncompressed document never has to exist in memory.
func CompressMetadataStream(c Compression, write func(io.Writer) error) (*CompressedMetadata, error) {
	out := newHashedBuffer()

	enc, err := newEncoder(c, out)
	if err != nil {
		return nil, fmt.Errorf("repodata: %s compression: %w", c, err)
	}

	src := &countingWriter{w: enc, h: sha256.New()}

	if err := write(src); err != nil {
		_ = enc.Close()

		return nil, fmt.Errorf("repodata: writing xml: %w", err)
	}

	if src.n == 0 {
		_ = enc.Close()

		return nil, ErrEmptyDocument
	}

	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("repodata: %s compression: %w", c, err)
	}

	cm := &CompressedMetadata{
		Data:       out.buf.Bytes(),
		SHA256:     hex.EncodeToString(out.h.Sum(nil)),
		Size:       int64(out.buf.Len()),
		OpenSHA256: hex.EncodeToString(src.h.Sum(nil)),
		OpenSize:   src.n,
	}

	if zw, ok := enc.(*ZchunkWriter); ok {
		cm.HeaderSHA256, cm.HeaderSize = zw.Header().HexChecksum(), zw.Header().Size
	}

	return cm, nil
}
