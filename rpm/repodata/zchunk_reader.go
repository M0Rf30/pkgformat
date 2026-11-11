package repodata

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// ZchunkDecoder checks and decompresses the chunks of one zchunk file, for a
// client that fetches them itself: the ones it is missing by range requests
// and the others from an older copy.
type ZchunkDecoder struct {
	h   *ZchunkHeader
	dec *zstd.Decoder
	max int64
}

// NewZchunkDecoder prepares to decode the chunks of the file h describes.
// dict is the compressed dictionary chunk, as stored in the file at
// h.Dict.Offset; it is required when h.HasDict() and ignored otherwise.
func NewZchunkDecoder(h *ZchunkHeader, dict []byte, opts ZchunkReadOptions) (*ZchunkDecoder, error) {
	opts = opts.withDefaults()
	d := &ZchunkDecoder{h: h, max: opts.MaxChunkSize}

	if h.Compression == ZchunkNone {
		return d, nil
	}

	var dictionaries [][]byte

	if h.HasDict() {
		plain, err := newZstdDecoder(opts.MaxChunkSize)
		if err != nil {
			return nil, err
		}

		// The dictionary chunk is not compressed with the dictionary.
		pd := &ZchunkDecoder{h: h, dec: plain, max: opts.MaxChunkSize}
		raw, err := pd.Decode(h.Dict, dict)

		plain.Close()

		if err != nil {
			return nil, fmt.Errorf("zchunk dictionary: %w", err)
		}

		dictionaries = append(dictionaries, raw)
	}

	dec, err := newZstdDecoder(opts.MaxChunkSize, dictionaries...)
	if err != nil {
		return nil, err
	}

	d.dec = dec

	return d, nil
}

func newZstdDecoder(maxSize int64, dicts ...[]byte) (*zstd.Decoder, error) {
	o := []zstd.DOption{zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(maxSize))}
	if len(dicts) > 0 {
		o = append(o, zstd.WithDecoderDicts(dicts...))
	}

	dec, err := zstd.NewReader(nil, o...)
	if err != nil {
		return nil, fmt.Errorf("%w: zstd decoder: %w", ErrZchunkFormat, err)
	}

	return dec, nil
}

// Close releases the decoder.
func (d *ZchunkDecoder) Close() {
	if d.dec != nil {
		d.dec.Close()
	}
}

// Decode verifies the compressed chunk c against the checksum of its index
// entry and returns its decompressed content. For an uncompressed file the
// result is data itself.
func (d *ZchunkDecoder) Decode(c ZchunkChunk, data []byte) ([]byte, error) {
	if int64(len(data)) != c.CompressedSize {
		return nil, fmt.Errorf("%w: chunk %d is %d bytes, the index says %d", ErrZchunkFormat, c.Index, len(data), c.CompressedSize)
	}

	stored := d.h.UncompressedSource && c.Size > 0 && allZero(c.Checksum)

	if !stored && !bytes.Equal(d.h.ChunkChecksumType.digest(data), c.Checksum) {
		return nil, fmt.Errorf("%w: chunk %d", ErrZchunkChecksum, c.Index)
	}

	if stored || d.h.Compression == ZchunkNone {
		if int64(len(data)) != c.Size {
			return nil, fmt.Errorf("%w: chunk %d: %d bytes stored for %d", ErrZchunkFormat, c.Index, len(data), c.Size)
		}

		return data, nil
	}

	if c.Size == 0 {
		return nil, nil
	}

	out, err := d.dec.DecodeAll(data, make([]byte, 0, c.Size))
	if err != nil {
		if errors.Is(err, zstd.ErrDecoderSizeExceeded) {
			return nil, fmt.Errorf("%w: zchunk chunk %d decompresses over %d bytes", ErrTooLarge, c.Index, d.max)
		}

		return nil, fmt.Errorf("%w: chunk %d: %w", ErrZchunkFormat, c.Index, err)
	}

	if int64(len(out)) != c.Size {
		return nil, fmt.Errorf("%w: chunk %d decompresses to %d bytes, the index says %d", ErrZchunkFormat, c.Index, len(out), c.Size)
	}

	if d.h.UncompressedSource && c.UncompressedChecksum != nil &&
		!bytes.Equal(d.h.ChunkChecksumType.digest(out), c.UncompressedChecksum) {
		return nil, fmt.Errorf("%w: chunk %d, decompressed", ErrZchunkChecksum, c.Index)
	}

	return out, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}

	return true
}

// ZchunkReader decompresses a zchunk file as a stream, verifying the header,
// every chunk and the checksum of the data on the way. A chunk is held in
// memory while it is read, so the memory used is that of the largest chunk,
// never of the file.
type ZchunkReader struct {
	r    io.Reader
	h    *ZchunkHeader
	dec  *ZchunkDecoder
	data *digester

	next int
	buf  []byte
	cur  []byte
	err  error
}

// NewZchunkReader reads the header of the zchunk file r and its dictionary,
// and returns a reader of the decompressed content. An uncompressed size
// over opts.MaxSize is refused here with [ErrTooLarge], since the header
// states it. A damaged file fails the read with [ErrZchunkFormat] or
// [ErrZchunkChecksum], at the end of the content when it is the checksum of
// the data that does not match.
func NewZchunkReader(r io.Reader, opts ZchunkReadOptions) (*ZchunkReader, error) {
	opts = opts.withDefaults()

	h, _, err := readZchunkHeader(r, opts)
	if err != nil {
		return nil, err
	}

	if h.Detached {
		return nil, fmt.Errorf("%w: a detached header holds no data", ErrZchunkFormat)
	}

	z := &ZchunkReader{r: r, h: h, data: h.ChecksumType.digester()}

	var dict []byte

	if h.HasDict() {
		if dict, err = readChunkBytes(r, h.Dict.CompressedSize, nil); err != nil {
			return nil, err
		}

		_, _ = z.data.Write(dict)
	}

	if z.dec, err = NewZchunkDecoder(h, dict, opts); err != nil {
		return nil, err
	}

	return z, nil
}

// Header returns the header of the file: its index lists the chunks.
func (z *ZchunkReader) Header() *ZchunkHeader { return z.h }

// Read implements io.Reader.
func (z *ZchunkReader) Read(p []byte) (int, error) {
	for len(z.cur) == 0 {
		if z.err != nil {
			return 0, z.err
		}

		z.err = z.nextChunk()
	}

	n := copy(p, z.cur)
	z.cur = z.cur[n:]

	return n, nil
}

// nextChunk loads the next chunk into z.cur, or ends the file.
func (z *ZchunkReader) nextChunk() error {
	if z.next == len(z.h.Chunks) {
		return z.finish()
	}

	c := z.h.Chunks[z.next]
	z.next++

	buf, err := readChunkBytes(z.r, c.CompressedSize, z.buf)
	if err != nil {
		return err
	}

	z.buf = buf
	_, _ = z.data.Write(buf)

	out, err := z.dec.Decode(c, buf)
	if err != nil {
		return err
	}

	z.cur = out

	return nil
}

// finish checks the end of the file and the checksum of its data.
func (z *ZchunkReader) finish() error {
	var one [1]byte

	switch n, err := io.ReadFull(z.r, one[:]); {
	case n > 0:
		return fmt.Errorf("%w: data after the last chunk", ErrZchunkFormat)
	case !errors.Is(err, io.EOF):
		return err
	}

	if !z.h.UncompressedSource && !bytes.Equal(z.data.sum(), z.h.DataChecksum) {
		return fmt.Errorf("%w: data", ErrZchunkChecksum)
	}

	return io.EOF
}

// Close releases the decoder. It does not close the underlying reader.
func (z *ZchunkReader) Close() error {
	z.dec.Close()

	return nil
}
