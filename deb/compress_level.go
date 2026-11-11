package deb

import (
	"fmt"
	"io"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// Valid compression levels of each method. Level 0 always selects the
// default of the method.
const (
	// MaxGzipLevel is the best (slowest) gzip level; the lowest is 1.
	MaxGzipLevel = 9
	// MaxXZLevel is the best xz level; the lowest is 1.
	MaxXZLevel = 9
	// MaxZstdLevel is the highest zstd level; the lowest is 1. The encoder
	// groups the levels into four speed classes, like zstd's own presets.
	MaxZstdLevel = 22
)

// checkLevel reports whether level is valid for c. "none" takes only 0.
func checkLevel(c Compression, level int) error {
	maxLevel := 0

	switch c {
	case CompressionGzip:
		maxLevel = MaxGzipLevel
	case CompressionXZ:
		maxLevel = MaxXZLevel
	case CompressionZstd:
		maxLevel = MaxZstdLevel
	}

	if level < 0 || level > maxLevel {
		return invalidSpec("compression level %d is outside 0-%d for %s", level, maxLevel, compressionName(c))
	}

	return nil
}

func compressionName(c Compression) string {
	switch c {
	case CompressionGzip:
		return "gzip"
	case CompressionXZ:
		return "xz"
	case CompressionZstd:
		return "zstd"
	default:
		return "none"
	}
}

// xzDictCap maps an xz level to the dictionary size of the encoder; it is
// the dictionary of the xz preset of the same number.
var xzDictCap = [...]int{0, 1 << 20, 2 << 20, 4 << 20, 4 << 20, 8 << 20, 8 << 20, 16 << 20, 32 << 20, 64 << 20}

// compressWriterLevel is compressWriter with a level: 0 is the default of the
// method, 1 the fastest and the maximum (see MaxGzipLevel, MaxXZLevel,
// MaxZstdLevel) the smallest output.
func compressWriterLevel(w io.Writer, c Compression, level int) (io.WriteCloser, error) {
	if level == 0 {
		return compressWriter(w, c)
	}

	if err := checkLevel(c, level); err != nil {
		return nil, err
	}

	switch c {
	case CompressionGzip:
		gw, err := gzip.NewWriterLevel(w, level)
		if err != nil {
			return nil, fmt.Errorf("deb: gzip writer: %w", err)
		}

		return gw, nil
	case CompressionXZ:
		cfg := xz.WriterConfig{DictCap: xzDictCap[level], Matcher: lzma.HashTable4}
		if level >= 4 {
			cfg.Matcher = lzma.BinaryTree
		}

		xw, err := cfg.NewWriter(w)
		if err != nil {
			return nil, fmt.Errorf("deb: xz writer: %w", err)
		}

		return xw, nil
	case CompressionZstd:
		zw, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)))
		if err != nil {
			return nil, fmt.Errorf("deb: zstd writer: %w", err)
		}

		return zw, nil
	}

	return compressWriter(w, c)
}
