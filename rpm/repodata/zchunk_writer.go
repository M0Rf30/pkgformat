package repodata

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// ZchunkChunking selects where a [ZchunkWriter] ends a chunk.
type ZchunkChunking int

const (
	// ZchunkContentDefined ends a chunk where a rolling hash of the content
	// says so, as zck does by default, so equal content gives equal chunks
	// wherever it sits in the file. The chunks are about 32 KiB.
	ZchunkContentDefined ZchunkChunking = iota
	// ZchunkManual ends a chunk only at [ZchunkWriter.EndChunk], or when it
	// reaches the maximum chunk size.
	ZchunkManual
	// ZchunkXMLPackages ends a chunk before every <package> element that
	// starts a line, and when it reaches the maximum chunk size: one chunk
	// for the document header and one per package, which is how createrepo_c
	// chunks primary, filelists and other. A document without such elements
	// is a single chunk.
	ZchunkXMLPackages
)

const (
	// DefaultZchunkLevel is the zstd level zck compresses with.
	DefaultZchunkLevel = 9
	// DefaultZchunkMaxWriteChunk is the largest chunk a writer makes by
	// default.
	DefaultZchunkMaxWriteChunk = 10 << 20

	// xmlPackageMarker starts the line of a <package> element; it must be
	// followed by a space or '>'.
	xmlPackageMarker = "\n<package"
)

// ZchunkOptions configures a [ZchunkWriter]. The zero value is a file of
// content-defined chunks compressed with zstd at level 9, without a
// dictionary and with SHA-512/128 chunk checksums, as zck writes by default.
type ZchunkOptions struct {
	// Chunking selects where chunks end.
	Chunking ZchunkChunking
	// MinChunkSize and MaxChunkSize bound the chunks, by their decompressed
	// size; 1 and 10 MiB when 0. With content-defined chunking the chunk
	// size is also kept between 8 KiB and 128 KiB where these allow.
	MinChunkSize int
	MaxChunkSize int
	// Compression is how the chunks are compressed.
	Compression ZchunkCompression
	// Level is the zstd compression level, 1 to 22; 9 when 0.
	Level int
	// Dictionary is a zstd dictionary in the format zstd --train and
	// zck_gen_zdict write; every chunk is compressed with it and the
	// dictionary is stored in the file. Empty for none.
	Dictionary []byte
	// ChunkChecksum is the checksum of the chunks: [ZchunkSHA512_128]
	// (zck's default), [ZchunkSHA256] or [ZchunkSHA512].
	ChunkChecksum ZchunkChecksum
}

func (o ZchunkOptions) validate() (ZchunkOptions, error) {
	if o.MinChunkSize <= 0 {
		o.MinChunkSize = 1
	}

	if o.MaxChunkSize <= 0 {
		o.MaxChunkSize = DefaultZchunkMaxWriteChunk
	}

	if o.MinChunkSize > o.MaxChunkSize {
		return o, fmt.Errorf("repodata: zchunk minimum chunk size %d over the maximum %d", o.MinChunkSize, o.MaxChunkSize)
	}

	if o.Level == 0 {
		o.Level = DefaultZchunkLevel
	}

	if o.Level < 1 || o.Level > 22 {
		return o, fmt.Errorf("repodata: zchunk zstd level %d is not 1 to 22", o.Level)
	}

	if o.ChunkChecksum < 0 || o.ChunkChecksum >= ZchunkSHA1 {
		return o, fmt.Errorf("repodata: zchunk chunk checksum %v cannot be written", o.ChunkChecksum)
	}

	if o.Compression == ZchunkNone && len(o.Dictionary) > 0 {
		return o, errors.New("repodata: zchunk dictionary without compression")
	}

	if o.Chunking < ZchunkContentDefined || o.Chunking > ZchunkXMLPackages {
		return o, fmt.Errorf("repodata: unknown zchunk chunking %d", int(o.Chunking))
	}

	if o.Compression != ZchunkZstd && o.Compression != ZchunkNone {
		return o, fmt.Errorf("repodata: unknown zchunk compression %d", int(o.Compression))
	}

	return o, nil
}

// ZchunkWriter writes a zchunk file. The header carries the checksum and the
// size of every chunk, so it is only known once the last chunk is; the
// compressed chunks are held in memory until Close writes the file.
type ZchunkWriter struct {
	w    io.Writer
	o    ZchunkOptions
	enc  *zstd.Encoder
	data *digester // checksum of the compressed data, the dictionary first

	split   *contentSplitter
	pending []byte
	scanned int // bytes of pending already searched for a package marker

	entries []ZchunkChunk // entries[0] is the dictionary
	out     bytes.Buffer
	scratch []byte

	hdr    *ZchunkHeader
	err    error
	closed bool
}

// NewZchunkWriter returns a writer of a zchunk file to w. Nothing is written
// to w before Close.
func NewZchunkWriter(w io.Writer, opts ZchunkOptions) (*ZchunkWriter, error) {
	o, err := opts.validate()
	if err != nil {
		return nil, err
	}

	z := &ZchunkWriter{w: w, o: o, data: ZchunkSHA256.digester()}
	if o.Chunking == ZchunkContentDefined {
		z.split = newContentSplitter(o.MinChunkSize, o.MaxChunkSize)
	}

	// Without a dictionary its entry is all zeros.
	z.entries = []ZchunkChunk{{Checksum: make([]byte, o.ChunkChecksum.Size())}}

	if o.Compression == ZchunkZstd {
		if err := z.initZstd(); err != nil {
			return nil, err
		}
	}

	return z, nil
}

func (z *ZchunkWriter) initZstd() error {
	common := []zstd.EOption{
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(z.o.Level)),
		zstd.WithEncoderConcurrency(1),
		// The chunk checksums cover the data; the zstd one is a duplicate.
		zstd.WithEncoderCRC(false),
	}

	if len(z.o.Dictionary) == 0 {
		enc, err := zstd.NewWriter(nil, common...)
		if err != nil {
			return fmt.Errorf("repodata: zchunk zstd encoder: %w", err)
		}

		z.enc = enc

		return nil
	}

	// The dictionary is itself compressed without one.
	plain, err := zstd.NewWriter(nil, common...)
	if err != nil {
		return fmt.Errorf("repodata: zchunk zstd encoder: %w", err)
	}

	defer plain.Close()

	z.enc, err = zstd.NewWriter(nil, append(common, zstd.WithEncoderDict(z.o.Dictionary))...)
	if err != nil {
		return fmt.Errorf("repodata: zchunk dictionary: %w", err)
	}

	packed := plain.EncodeAll(z.o.Dictionary, nil)
	z.entries[0] = ZchunkChunk{
		Checksum:       z.o.ChunkChecksum.digest(packed),
		CompressedSize: int64(len(packed)),
		Size:           int64(len(z.o.Dictionary)),
	}
	z.out.Write(packed)
	_, _ = z.data.Write(packed)

	return nil
}

// Write adds p to the document.
func (z *ZchunkWriter) Write(p []byte) (int, error) {
	if z.closed {
		return 0, ErrZchunkClosed
	}

	if z.err != nil {
		return 0, z.err
	}

	switch z.o.Chunking {
	case ZchunkContentDefined:
		z.writeContent(p)
	case ZchunkManual:
		z.writeManual(p)
	case ZchunkXMLPackages:
		z.writePackages(p)
	}

	if z.err != nil {
		return 0, z.err
	}

	return len(p), nil
}

func (z *ZchunkWriter) writeContent(p []byte) {
	start := 0

	for i, c := range p {
		if z.split.feed(c) {
			z.pending = append(z.pending, p[start:i]...)
			start = i

			z.flush(z.pending)
			z.pending = z.pending[:0]
			z.split.feed(c)
		}
	}

	z.pending = append(z.pending, p[start:]...)
}

func (z *ZchunkWriter) writeManual(p []byte) {
	for len(z.pending)+len(p) > z.o.MaxChunkSize {
		take := z.o.MaxChunkSize - len(z.pending)
		z.pending = append(z.pending, p[:take]...)
		p = p[take:]

		z.flush(z.pending)
		z.pending = z.pending[:0]
	}

	z.pending = append(z.pending, p...)
}

func (z *ZchunkWriter) writePackages(p []byte) {
	buf := append(z.pending, p...)
	pos := 0

	for z.err == nil {
		end := -1

		if i := indexPackageStart(buf[pos:], max(z.scanned-pos, 0)); i >= 0 {
			end = pos + i + 1
		}

		switch {
		case end >= 0 && end-pos <= z.o.MaxChunkSize:
		case len(buf)-pos > z.o.MaxChunkSize:
			end = pos + z.o.MaxChunkSize
		default:
			z.pending = buf[:copy(buf, buf[pos:])]
			z.scanned = max(len(z.pending)-len(xmlPackageMarker), 0)

			return
		}

		z.flush(buf[pos:end])
		pos = end
		z.scanned = pos
	}
}

// indexPackageStart returns the index of the newline of the first "\n<package"
// at or after from in b that is followed by a space or '>', or -1.
func indexPackageStart(b []byte, from int) int {
	for from < len(b) {
		i := bytes.Index(b[from:], []byte(xmlPackageMarker))
		if i < 0 {
			return -1
		}

		i += from

		next := i + len(xmlPackageMarker)
		if next >= len(b) {
			return -1
		}

		if b[next] == ' ' || b[next] == '>' {
			return i
		}

		from = i + 1
	}

	return -1
}

// EndChunk ends the chunk being written, so that what follows starts a new
// one. A chunk shorter than the minimum chunk size is not ended, as in zck.
func (z *ZchunkWriter) EndChunk() error {
	if z.closed {
		return ErrZchunkClosed
	}

	if z.err != nil {
		return z.err
	}

	if len(z.pending) < z.o.MinChunkSize {
		return nil
	}

	z.endPending()

	return z.err
}

func (z *ZchunkWriter) endPending() {
	z.flush(z.pending)
	z.pending = z.pending[:0]
	z.scanned = 0

	if z.split != nil {
		z.split.hash.reset()
		z.split.pending = 0
	}
}

// flush compresses chunk and adds it to the data.
func (z *ZchunkWriter) flush(chunk []byte) {
	if len(chunk) == 0 || z.err != nil {
		return
	}

	packed := chunk
	if z.enc != nil {
		z.scratch = z.enc.EncodeAll(chunk, z.scratch[:0])
		packed = z.scratch
	}

	z.entries = append(z.entries, ZchunkChunk{
		Index:          len(z.entries),
		Checksum:       z.o.ChunkChecksum.digest(packed),
		CompressedSize: int64(len(packed)),
		Size:           int64(len(chunk)),
	})

	z.out.Write(packed)
	_, _ = z.data.Write(packed)
}

// Close ends the last chunk and writes the file to the destination. It does
// not close the destination. After Close, [ZchunkWriter.Header] describes the
// file.
func (z *ZchunkWriter) Close() error {
	if z.closed {
		return z.err
	}

	z.closed = true

	if z.enc != nil {
		defer z.enc.Close()
	}

	if z.err != nil {
		return z.err
	}

	z.endPending()

	hdr, _ := marshalZchunkHeader(z.o.ChunkChecksum, z.o.Compression, z.data.sum(), z.entries)

	// Reading the header back gives the caller the parsed form and checks it.
	const unbounded = 1 << 62

	var err error
	if z.hdr, _, err = readZchunkHeader(bytes.NewReader(hdr), ZchunkReadOptions{MaxHeaderSize: unbounded, MaxChunkSize: unbounded, MaxSize: unbounded}); err != nil {
		z.err = fmt.Errorf("repodata: zchunk header: %w", err)

		return z.err
	}

	if _, err := z.w.Write(hdr); err != nil {
		z.err = fmt.Errorf("repodata: writing zchunk: %w", err)

		return z.err
	}

	if _, err := z.out.WriteTo(z.w); err != nil {
		z.err = fmt.Errorf("repodata: writing zchunk: %w", err)

		return z.err
	}

	return nil
}

// Header returns the header of the file written, or nil before a successful
// Close. Its Checksum and Size are the header-checksum and header-size of the
// repomd.xml entry.
func (z *ZchunkWriter) Header() *ZchunkHeader { return z.hdr }
