package deb

import (
	"bufio"
	"compress/bzip2"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"

	"github.com/M0Rf30/pkgformat/internal/limitio"
	"github.com/M0Rf30/pkgformat/xzlimit"
)

// MaxIndexBytes bounds the decompressed size of one Packages (or Sources)
// index. The largest real ones are a few hundred MiB.
const MaxIndexBytes int64 = 4 << 30

const readBufSize = 64 << 10

// readCloser pairs a reader with the function that releases its decoder and
// the stream under it.
type readCloser struct {
	io.Reader

	closeFn func() error
}

func (c readCloser) Close() error { return c.closeFn() }

// closeAll returns a close function running every non-nil closer and
// reporting the first error.
func closeAll(closers ...io.Closer) func() error {
	return func() error {
		var first error

		for _, c := range closers {
			if c == nil {
				continue
			}

			if err := c.Close(); err != nil && first == nil {
				first = err
			}
		}

		return first
	}
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

// compressionOf returns the compression suffix of name (".gz", ".bz2", ".xz",
// ".lz4", ".zst") or "" when name carries none of them.
func compressionOf(name string) string {
	for _, ext := range []string{".gz", ".bz2", ".xz", ".lz4", ".zst"} {
		if strings.HasSuffix(name, ext) {
			return ext
		}
	}

	return ""
}

// newDecoder wraps r in the decoder for the compression suffix ext (as
// compressionOf returns it; "" is no compression). The decoders refuse a
// declared window or dictionary over xzlimit.MaxDictSize, but the output size
// is not limited; callers cap it. Closing the result closes the decoder and r
// when r is an io.Closer.
func newDecoder(r io.Reader, ext string) (io.ReadCloser, error) {
	rc, _ := r.(io.Closer)

	switch ext {
	case "":
		return readCloser{Reader: r, closeFn: closeAll(rc)}, nil
	case ".gz":
		gr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}

		return readCloser{Reader: gr, closeFn: closeAll(gr, rc)}, nil
	case ".bz2":
		return readCloser{Reader: bzip2.NewReader(bufio.NewReaderSize(r, readBufSize)), closeFn: closeAll(rc)}, nil
	case ".xz":
		// The xz decoder reads a byte at a time; buffered, that is not one
		// read call per byte.
		xr, err := xzlimit.NewReader(bufio.NewReaderSize(r, readBufSize))
		if err != nil {
			return nil, fmt.Errorf("xz: %w", err)
		}

		return readCloser{Reader: xr, closeFn: closeAll(rc)}, nil
	case ".lz4":
		return readCloser{Reader: lz4.NewReader(bufio.NewReaderSize(r, readBufSize)), closeFn: closeAll(rc)}, nil
	case ".zst":
		zr, err := zstd.NewReader(bufio.NewReaderSize(r, readBufSize),
			zstd.WithDecoderMaxWindow(xzlimit.MaxDictSize), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, fmt.Errorf("zstd: %w", err)
		}

		return readCloser{Reader: zr, closeFn: closeAll(closeFunc(func() error { zr.Close(); return nil }), rc)}, nil
	}

	return nil, fmt.Errorf("%w: %q", ErrUnsupportedArchiveFormat, ext)
}

// OpenIndex decompresses an apt index (Packages, Sources, Contents) read from
// r according to the extension of name: .gz, .bz2, .xz, .lz4, .zst or none.
// Reading more than MaxIndexBytes of decompressed data fails with ErrTooLarge.
// Closing the result closes r when it is an io.Closer.
func OpenIndex(r io.Reader, name string) (io.ReadCloser, error) {
	return openIndex(r, name, MaxIndexBytes)
}

// openIndex is OpenIndex with the decompressed size limit a parameter.
func openIndex(r io.Reader, name string, limit int64) (io.ReadCloser, error) {
	dec, err := newDecoder(r, compressionOf(name))
	if err != nil {
		if c, ok := r.(io.Closer); ok {
			_ = c.Close()
		}

		return nil, fmt.Errorf("deb: opening index %s: %w", name, err)
	}

	return readCloser{Reader: limitio.Capped(dec, limit, ErrTooLarge), closeFn: dec.Close}, nil
}
