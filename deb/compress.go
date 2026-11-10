package deb

import (
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// Compression selects how a tar member of a package or an index is compressed.
type Compression int

// The supported compressions. The zero value is CompressionNone.
const (
	CompressionNone Compression = iota
	CompressionGzip
	CompressionXZ
	CompressionZstd
)

// ParseCompression maps a name ("gzip", "gz", "xz", "zstd", "zst", "none") to a
// Compression. The empty name selects CompressionZstd, the default of the
// package writer.
func ParseCompression(name string) (Compression, error) {
	switch strings.ToLower(name) {
	case "", "zstd", "zst":
		return CompressionZstd, nil
	case "gzip", "gz":
		return CompressionGzip, nil
	case "xz":
		return CompressionXZ, nil
	case "none":
		return CompressionNone, nil
	}

	return CompressionNone, fmt.Errorf("%w: %q", ErrUnsupportedCompression, name)
}

// Extension is the file suffix of the compression: ".gz", ".xz", ".zst" or "".
func (c Compression) Extension() string {
	switch c {
	case CompressionGzip:
		return ".gz"
	case CompressionXZ:
		return ".xz"
	case CompressionZstd:
		return ".zst"
	default:
		return ""
	}
}

// compressWriter wraps w in the compressor for c. The returned writer must be
// closed to flush the stream; closing it does not close w.
func compressWriter(w io.Writer, c Compression) (io.WriteCloser, error) {
	switch c {
	case CompressionNone:
		return nopWriteCloser{w}, nil
	case CompressionGzip:
		return gzip.NewWriter(w), nil
	case CompressionXZ:
		xw, err := xz.NewWriter(w)
		if err != nil {
			return nil, fmt.Errorf("deb: xz writer: %w", err)
		}

		return xw, nil
	case CompressionZstd:
		zw, err := zstd.NewWriter(w)
		if err != nil {
			return nil, fmt.Errorf("deb: zstd writer: %w", err)
		}

		return zw, nil
	}

	return nil, fmt.Errorf("%w: %d", ErrUnsupportedCompression, int(c))
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
