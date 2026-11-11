package repodata

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // zchunk lists SHA-1 as a checksum type; it is only read, never written.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
)

// Zchunk file format errors. They are wrapped with the position of the
// problem; test for them with errors.Is.
var (
	// ErrZchunkFormat means the data is not a well-formed zchunk file.
	ErrZchunkFormat = errors.New("repodata: invalid zchunk file")
	// ErrZchunkChecksum means a checksum of a zchunk file (header, data or
	// one chunk) does not match its content.
	ErrZchunkChecksum = errors.New("repodata: zchunk checksum mismatch")
	// ErrZchunkUnsupported means the file uses a feature of the format that
	// is not implemented: data streams, an unknown compression, or an
	// unknown checksum type.
	ErrZchunkUnsupported = errors.New("repodata: unsupported zchunk feature")
	// ErrZchunkClosed is returned by a [ZchunkWriter] used after Close.
	ErrZchunkClosed = errors.New("repodata: zchunk writer is closed")
)

// ZchunkChecksum is a checksum algorithm of a zchunk file.
type ZchunkChecksum int

const (
	// ZchunkSHA512_128 is the first 128 bits of SHA-512: the checksum zck
	// uses for chunks, and the zero value of the options.
	ZchunkSHA512_128 ZchunkChecksum = iota
	// ZchunkSHA256 is SHA-256: the checksum of the header and of the data of
	// every file this package writes.
	ZchunkSHA256
	// ZchunkSHA512 is SHA-512.
	ZchunkSHA512
	// ZchunkSHA1 is SHA-1. It is read and verified but never written.
	ZchunkSHA1
)

// zchunk wire values of the checksum types.
const (
	wireSHA1      = 0
	wireSHA256    = 1
	wireSHA512    = 2
	wireSHA512128 = 3
)

func (c ZchunkChecksum) wire() uint64 {
	switch c {
	case ZchunkSHA1:
		return wireSHA1
	case ZchunkSHA256:
		return wireSHA256
	case ZchunkSHA512:
		return wireSHA512
	default:
		return wireSHA512128
	}
}

func checksumFromWire(v uint64) (ZchunkChecksum, bool) {
	switch v {
	case wireSHA1:
		return ZchunkSHA1, true
	case wireSHA256:
		return ZchunkSHA256, true
	case wireSHA512:
		return ZchunkSHA512, true
	case wireSHA512128:
		return ZchunkSHA512_128, true
	}

	return 0, false
}

// Size is the length in bytes of a digest of the algorithm.
func (c ZchunkChecksum) Size() int {
	switch c {
	case ZchunkSHA1:
		return sha1.Size
	case ZchunkSHA256:
		return sha256.Size
	case ZchunkSHA512:
		return sha512.Size
	default:
		return 16
	}
}

// String returns the name of the algorithm: "sha1", "sha256", "sha512" or
// "sha512-128".
func (c ZchunkChecksum) String() string {
	switch c {
	case ZchunkSHA1:
		return "sha1"
	case ZchunkSHA256:
		return "sha256"
	case ZchunkSHA512:
		return "sha512"
	default:
		return "sha512-128"
	}
}

// digester computes digests of one algorithm.
type digester struct {
	h hash.Hash
	n int
}

func (c ZchunkChecksum) digester() *digester {
	switch c {
	case ZchunkSHA1:
		return &digester{h: sha1.New(), n: sha1.Size} //nolint:gosec // see the import.
	case ZchunkSHA256:
		return &digester{h: sha256.New(), n: sha256.Size}
	case ZchunkSHA512:
		return &digester{h: sha512.New(), n: sha512.Size}
	default:
		return &digester{h: sha512.New(), n: 16}
	}
}

func (d *digester) Write(p []byte) (int, error) { return d.h.Write(p) }

func (d *digester) sum() []byte { return d.h.Sum(nil)[:d.n] }

func (c ZchunkChecksum) digest(parts ...[]byte) []byte {
	d := c.digester()
	for _, p := range parts {
		_, _ = d.Write(p)
	}

	return d.sum()
}

// ZchunkCompression is the compression of the chunks of a zchunk file.
type ZchunkCompression int

const (
	// ZchunkZstd compresses every chunk as a zstd frame. The zero value.
	ZchunkZstd ZchunkCompression = iota
	// ZchunkNone stores the chunks as they are.
	ZchunkNone
)

const (
	wireCompNone = 0
	wireCompZstd = 2
)

func (c ZchunkCompression) String() string {
	if c == ZchunkNone {
		return "none"
	}

	return "zstd"
}

// zchunk header flags.
const (
	flagStreams      = 1 << 0
	flagOptional     = 1 << 1
	flagUncompressed = 1 << 2
)

var (
	zchunkMagic         = []byte("\x00ZCK1")
	zchunkDetachedMagic = []byte("\x00ZHR1")
)

const (
	// zchunkMaxCompint is the longest compressed integer: ceil(64/7) bytes.
	zchunkMaxCompint = 10

	// DefaultZchunkMaxHeader is the header size [ReadZchunkHeader] and
	// [NewZchunkReader] allow by default. The index takes about 20 bytes per
	// chunk, and a file has a chunk per package or per 32 KiB of data.
	DefaultZchunkMaxHeader int64 = 64 << 20
	// DefaultZchunkMaxChunk is the uncompressed size of one chunk the readers
	// allow by default; the writers' own limit is 10 MiB.
	DefaultZchunkMaxChunk int64 = 64 << 20
)

// ZchunkChunk is one entry of the index of a zchunk file: a chunk of the
// compressed data, or the compression dictionary.
type ZchunkChunk struct {
	// Index is the position of the chunk in the index; the dictionary is 0
	// and the first data chunk 1.
	Index int
	// Offset is where the compressed chunk starts in the file and
	// CompressedSize its length; a range request for
	// [Offset, Offset+CompressedSize) fetches the chunk.
	Offset         int64
	CompressedSize int64
	// Size is the length of the chunk once decompressed.
	Size int64
	// Checksum is the digest of the compressed chunk, by the chunk checksum
	// type of the header. Two chunks with the same checksum hold the same
	// bytes.
	Checksum []byte
	// UncompressedChecksum is the digest of the decompressed chunk; only a
	// file made to be applied against an uncompressed source has it.
	UncompressedChecksum []byte
}

// End is the offset after the last byte of the compressed chunk.
func (c ZchunkChunk) End() int64 { return c.Offset + c.CompressedSize }

// ZchunkSignature is a signature of a zchunk header. The format defines no
// signature type; they are returned as found and not verified.
type ZchunkSignature struct {
	Type uint64
	Data []byte
}

// ZchunkHeader is the parsed header of a zchunk file: everything needed to
// know which chunks a download must fetch.
type ZchunkHeader struct {
	// Detached is set for a header stored apart from its file ("\0ZHR1").
	Detached bool
	// ChecksumType is the algorithm of Checksum and DataChecksum.
	ChecksumType ZchunkChecksum
	// Size is the length of the header, lead included: the offset of the
	// compressed data in the file (the header-size of repomd.xml).
	Size int64
	// Checksum is the digest of the header (the header-checksum of
	// repomd.xml).
	Checksum []byte
	// DataChecksum is the digest of everything after the header; all zeros
	// when UncompressedSource is set.
	DataChecksum []byte
	// Compression is how the chunks are compressed.
	Compression ZchunkCompression
	// UncompressedSource is set when the file can be applied against an
	// uncompressed source: its index has the digest of each decompressed
	// chunk.
	UncompressedSource bool
	// ChunkChecksumType is the algorithm of the chunk checksums.
	ChunkChecksumType ZchunkChecksum
	// Dict is the zstd dictionary the chunks are compressed with; its Size
	// is 0 when there is none.
	Dict ZchunkChunk
	// Chunks are the data chunks, in file order.
	Chunks []ZchunkChunk
	// Signatures are the signatures of the header, if any.
	Signatures []ZchunkSignature
}

// HasDict reports whether the chunks are compressed with a dictionary.
func (h *ZchunkHeader) HasDict() bool { return h.Dict.Size > 0 }

// DataSize is the length of the compressed data: the dictionary and the
// chunks.
func (h *ZchunkHeader) DataSize() int64 {
	n := h.Dict.CompressedSize
	for _, c := range h.Chunks {
		n += c.CompressedSize
	}

	return n
}

// FileSize is the length of the whole file.
func (h *ZchunkHeader) FileSize() int64 { return h.Size + h.DataSize() }

// UncompressedSize is the length of the decompressed content.
func (h *ZchunkHeader) UncompressedSize() int64 {
	var n int64

	for _, c := range h.Chunks {
		n += c.Size
	}

	return n
}

// HexChecksum is Checksum in hexadecimal, as repomd.xml records it.
func (h *ZchunkHeader) HexChecksum() string { return hex.EncodeToString(h.Checksum) }

// ZchunkReadOptions bounds what the zchunk readers accept. The zero value
// selects the defaults.
type ZchunkReadOptions struct {
	// MaxHeaderSize bounds the header, lead included;
	// [DefaultZchunkMaxHeader] when 0.
	MaxHeaderSize int64
	// MaxChunkSize bounds the decompressed size of a chunk;
	// [DefaultZchunkMaxChunk] when 0.
	MaxChunkSize int64
	// MaxSize bounds the decompressed size of the whole file;
	// [DefaultMaxDocument] when 0.
	MaxSize int64
}

func (o ZchunkReadOptions) withDefaults() ZchunkReadOptions {
	if o.MaxHeaderSize <= 0 {
		o.MaxHeaderSize = DefaultZchunkMaxHeader
	}

	if o.MaxChunkSize <= 0 {
		o.MaxChunkSize = DefaultZchunkMaxChunk
	}

	if o.MaxSize <= 0 {
		o.MaxSize = DefaultMaxDocument
	}

	return o
}

func appendCompint(b []byte, v uint64) []byte {
	for v >= 128 {
		b = append(b, byte(v&127))
		v >>= 7
	}

	return append(b, byte(v)|128)
}

// cursor reads the integers and digests of a header held in memory.
type cursor struct {
	b   []byte
	err error
}

func (c *cursor) fail(format string, args ...any) {
	if c.err == nil {
		c.err = fmt.Errorf("%w: %s", ErrZchunkFormat, fmt.Sprintf(format, args...))
	}
}

// compint reads one compressed integer that fits an int64.
func (c *cursor) compint(what string) uint64 {
	if c.err != nil {
		return 0
	}

	v, n, err := parseCompint(c.b)
	if err != nil {
		c.fail("%s: %v", what, err)

		return 0
	}

	c.b = c.b[n:]

	return v
}

func (c *cursor) take(n int, what string) []byte {
	if c.err != nil {
		return nil
	}

	if n < 0 || n > len(c.b) {
		c.fail("%s: read past the end of the header", what)

		return nil
	}

	p := c.b[:n:n]
	c.b = c.b[n:]

	return p
}

var errCompint = errors.New("bad compressed integer")

// parseCompint decodes the compressed integer at the start of b. The value
// must fit 63 bits.
func parseCompint(b []byte) (v uint64, n int, err error) {
	for i := range min(len(b), zchunkMaxCompint) {
		part := uint64(b[i] & 127)
		shift := 7 * i

		if part != 0 && (shift >= 63 || part > math.MaxInt64>>shift) {
			return 0, 0, fmt.Errorf("%w: too large", errCompint)
		}

		v |= part << shift

		if b[i] >= 128 {
			return v, i + 1, nil
		}
	}

	if len(b) >= zchunkMaxCompint {
		return 0, 0, fmt.Errorf("%w: too long", errCompint)
	}

	return 0, 0, fmt.Errorf("%w: read past the end of the header", errCompint)
}

// readLeadCompint reads one compressed integer from r a byte at a time, so
// that nothing after it is consumed, and appends its bytes to lead.
func readLeadCompint(r io.Reader, lead *[]byte, what string) (uint64, error) {
	var (
		buf [zchunkMaxCompint]byte
		one [1]byte
	)

	for i := range buf {
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return 0, fmt.Errorf("%w: %s: %w", ErrZchunkFormat, what, unexpectedEOF(err))
		}

		buf[i] = one[0]
		if one[0] < 128 {
			continue
		}

		v, _, err := parseCompint(buf[:i+1])
		if err != nil {
			return 0, fmt.Errorf("%w: %s: %w", ErrZchunkFormat, what, err)
		}

		*lead = append(*lead, buf[:i+1]...)

		return v, nil
	}

	return 0, fmt.Errorf("%w: %s: %w: too long", ErrZchunkFormat, what, errCompint)
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}

	return err
}

// ReadZchunkHeader reads and verifies the header of a zchunk file (or a
// detached header) from the start of r, and reads nothing after it. This is
// what a client downloads, by a range request for the header-size bytes
// repomd.xml gives, to decide which chunks it is missing.
func ReadZchunkHeader(r io.Reader, opts ZchunkReadOptions) (*ZchunkHeader, error) {
	h, _, err := readZchunkHeader(r, opts.withDefaults())

	return h, err
}

// readZchunkHeader returns the header and its raw bytes.
func readZchunkHeader(r io.Reader, opts ZchunkReadOptions) (*ZchunkHeader, []byte, error) {
	var magic [5]byte

	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, nil, fmt.Errorf("%w: lead: %w", ErrZchunkFormat, unexpectedEOF(err))
	}

	h := &ZchunkHeader{}

	switch {
	case bytes.Equal(magic[:], zchunkMagic):
	case bytes.Equal(magic[:], zchunkDetachedMagic):
		h.Detached = true
	default:
		return nil, nil, fmt.Errorf("%w: bad magic", ErrZchunkFormat)
	}

	lead := append([]byte(nil), magic[:]...)

	typeV, err := readLeadCompint(r, &lead, "checksum type")
	if err != nil {
		return nil, nil, err
	}

	sum, ok := checksumFromWire(typeV)
	if !ok || sum != ZchunkSHA1 && sum != ZchunkSHA256 {
		return nil, nil, fmt.Errorf("%w: header checksum type %d", ErrZchunkUnsupported, typeV)
	}

	length, err := readLeadCompint(r, &lead, "header size")
	if err != nil {
		return nil, nil, err
	}

	digestAt := len(lead)
	if length > uint64(opts.MaxHeaderSize) || int64(length)+int64(digestAt+sum.Size()) > opts.MaxHeaderSize {
		return nil, nil, fmt.Errorf("%w: zchunk header over %d bytes", ErrTooLarge, opts.MaxHeaderSize)
	}

	stored := make([]byte, sum.Size())
	if _, err := io.ReadFull(r, stored); err != nil {
		return nil, nil, fmt.Errorf("%w: header checksum: %w", ErrZchunkFormat, unexpectedEOF(err))
	}

	lead = append(lead, stored...)

	body, err := io.ReadAll(io.LimitReader(r, int64(length)))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: header: %w", ErrZchunkFormat, err)
	}

	if int64(len(body)) != int64(length) {
		return nil, nil, fmt.Errorf("%w: header: %w", ErrZchunkFormat, io.ErrUnexpectedEOF)
	}

	// A detached header is hashed as if it were the file, so the checksum is
	// the same for both.
	want := sum.digest(zchunkMagic, lead[5:digestAt], body)
	if !bytes.Equal(want, stored) {
		return nil, nil, fmt.Errorf("%w: header", ErrZchunkChecksum)
	}

	h.ChecksumType = sum
	h.Checksum = stored
	h.Size = int64(len(lead)) + int64(len(body))

	if err := parseZchunkBody(h, body, opts); err != nil {
		return nil, nil, err
	}

	return h, append(lead, body...), nil
}

// parseZchunkBody decodes the preface, index and signatures of a verified
// header whose lead is in h.
func parseZchunkBody(h *ZchunkHeader, body []byte, opts ZchunkReadOptions) error {
	c := &cursor{b: body}

	h.DataChecksum = c.take(h.ChecksumType.Size(), "data checksum")
	flags := c.compint("flags")

	if flags&flagStreams != 0 {
		return fmt.Errorf("%w: data streams", ErrZchunkUnsupported)
	}

	if flags&^(flagOptional|flagUncompressed) != 0 {
		return fmt.Errorf("%w: unknown flags %#x", ErrZchunkUnsupported, flags)
	}

	h.UncompressedSource = flags&flagUncompressed != 0

	switch comp := c.compint("compression type"); {
	case c.err != nil:
	case comp == wireCompZstd:
		h.Compression = ZchunkZstd
	case comp == wireCompNone:
		h.Compression = ZchunkNone
	default:
		return fmt.Errorf("%w: compression type %d", ErrZchunkUnsupported, comp)
	}

	if flags&flagOptional != 0 {
		skipOptionalElements(c)
	}

	indexSize := c.compint("index size")
	if c.err != nil {
		return c.err
	}

	if indexSize > uint64(len(c.b)) {
		return fmt.Errorf("%w: index exceeds the header", ErrZchunkFormat)
	}

	index := &cursor{b: c.take(int(indexSize), "index")}
	if err := parseZchunkIndex(h, index, opts); err != nil {
		return err
	}

	parseZchunkSignatures(h, c)

	if c.err != nil {
		return c.err
	}

	return nil
}

func skipOptionalElements(c *cursor) {
	n := c.compint("optional element count")

	for i := uint64(0); i < n && c.err == nil; i++ {
		_ = c.compint("optional element id")
		size := c.compint("optional element size")

		if size > uint64(len(c.b)) {
			c.fail("optional element exceeds the header")

			return
		}

		c.take(int(size), "optional element")
	}
}

func parseZchunkIndex(h *ZchunkHeader, c *cursor, opts ZchunkReadOptions) error {
	typeV := c.compint("chunk checksum type")
	if c.err != nil {
		return c.err
	}

	sum, ok := checksumFromWire(typeV)
	if !ok {
		return fmt.Errorf("%w: chunk checksum type %d", ErrZchunkUnsupported, typeV)
	}

	h.ChunkChecksumType = sum

	count := c.compint("chunk count")
	if c.err != nil {
		return c.err
	}

	digests := 1
	if h.UncompressedSource {
		digests = 2
	}

	// An entry is its digests and two integers of at least a byte each.
	entry := digests*sum.Size() + 2
	if count == 0 {
		return fmt.Errorf("%w: no dictionary entry in the index", ErrZchunkFormat)
	}

	if count > uint64(len(c.b)/entry) {
		return fmt.Errorf("%w: chunk count %d exceeds the index", ErrZchunkFormat, count)
	}

	h.Chunks = make([]ZchunkChunk, 0, count-1)
	offset := h.Size

	var total int64

	for i := range int(count) {
		ch := ZchunkChunk{Index: i, Offset: offset, Checksum: c.take(sum.Size(), "chunk checksum")}
		if h.UncompressedSource {
			ch.UncompressedChecksum = c.take(sum.Size(), "chunk checksum")
		}

		comp, size := c.compint("chunk size"), c.compint("chunk uncompressed size")
		if c.err != nil {
			return c.err
		}

		if size > uint64(opts.MaxChunkSize) {
			return fmt.Errorf("%w: zchunk chunk %d of %d bytes, max %d", ErrTooLarge, i, size, opts.MaxChunkSize)
		}

		if comp > uint64(opts.MaxChunkSize)+uint64(opts.MaxChunkSize)>>7+1<<10 {
			return fmt.Errorf("%w: zchunk chunk %d compressed to %d bytes", ErrTooLarge, i, comp)
		}

		ch.CompressedSize, ch.Size = int64(comp), int64(size)

		if i == 0 {
			h.Dict = ch
		} else {
			total += ch.Size
			if total > opts.MaxSize {
				return fmt.Errorf("%w: zchunk content over %d bytes", ErrTooLarge, opts.MaxSize)
			}

			h.Chunks = append(h.Chunks, ch)
		}

		offset += ch.CompressedSize
	}

	if len(c.b) != 0 {
		return fmt.Errorf("%w: %d unused bytes after the index entries", ErrZchunkFormat, len(c.b))
	}

	if (h.Dict.Size > 0) != (h.Dict.CompressedSize > 0) {
		return fmt.Errorf("%w: dictionary entry with a size and no data, or the reverse", ErrZchunkFormat)
	}

	if h.Dict.Size > 0 && h.Compression == ZchunkNone {
		return fmt.Errorf("%w: dictionary in an uncompressed file", ErrZchunkFormat)
	}

	return nil
}

func parseZchunkSignatures(h *ZchunkHeader, c *cursor) {
	n := c.compint("signature count")

	for i := uint64(0); i < n && c.err == nil; i++ {
		typ := c.compint("signature type")

		size := c.compint("signature size")
		if size > uint64(len(c.b)) {
			c.fail("signature exceeds the header")

			return
		}

		h.Signatures = append(h.Signatures, ZchunkSignature{Type: typ, Data: bytes.Clone(c.take(int(size), "signature"))})
	}
}

// marshalZchunkHeader builds the header of a file of the given chunks (the
// dictionary entry first); dataSum is the digest of the compressed data. It
// returns the header and its checksum.
func marshalZchunkHeader(chunkSum ZchunkChecksum, comp ZchunkCompression, dataSum []byte, entries []ZchunkChunk) (hdr, sum []byte) {
	var index []byte

	index = appendCompint(index, chunkSum.wire())
	index = appendCompint(index, uint64(len(entries)))

	for _, e := range entries {
		index = append(index, e.Checksum...)
		index = appendCompint(index, uint64(e.CompressedSize))
		index = appendCompint(index, uint64(e.Size))
	}

	wireComp := uint64(wireCompZstd)
	if comp == ZchunkNone {
		wireComp = wireCompNone
	}

	// Flags 0: no streams, no optional elements, no uncompressed source.
	body := append([]byte(nil), dataSum...)
	body = appendCompint(body, 0)
	body = appendCompint(body, wireComp)
	body = appendCompint(body, uint64(len(index)))
	body = append(body, index...)
	body = appendCompint(body, 0) // no signatures

	lead := append([]byte(nil), zchunkMagic...)
	lead = appendCompint(lead, wireSHA256)
	lead = appendCompint(lead, uint64(len(body)))

	sum = ZchunkSHA256.digest(lead, body)

	hdr = append(lead, sum...)
	hdr = append(hdr, body...)

	return hdr, sum
}

// readChunkBytes reads n bytes of chunk data from r into buf, grown when it
// is too small. n is bounded by the header checks.
func readChunkBytes(r io.Reader, n int64, buf []byte) ([]byte, error) {
	if int64(cap(buf)) < n {
		buf = make([]byte, n)
	}

	buf = buf[:n]
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("%w: chunk data: %w", ErrZchunkFormat, unexpectedEOF(err))
	}

	return buf, nil
}
