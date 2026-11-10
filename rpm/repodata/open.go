package repodata

import (
	"bufio"
	"compress/bzip2"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"

	"github.com/M0Rf30/pkgformat/internal/limitio"
	"github.com/M0Rf30/pkgformat/xzlimit"
)

// DefaultMaxDocument is the decompressed size [OpenMetadata] allows a
// document by default. The filelists of the largest repositories are a few
// gigabytes.
const DefaultMaxDocument int64 = 16 << 30

// OpenMetadata wraps r according to the extension of the file name it was
// fetched as (.gz, .xz, .zst, .bz2 or none), and decompresses at most maxSize
// bytes: a document over the limit fails the read with [ErrTooLarge] instead
// of ending as a silently shortened one. A maxSize of 0 selects
// [DefaultMaxDocument]. Closing the result closes r.
func OpenMetadata(r io.ReadCloser, name string, maxSize int64) (io.ReadCloser, error) {
	if maxSize <= 0 {
		maxSize = DefaultMaxDocument
	}

	var (
		dec  io.Reader
		stop func()
		err  error
	)

	switch {
	case strings.HasSuffix(name, ".gz"):
		var gr *gzip.Reader

		if gr, err = gzip.NewReader(r); err == nil {
			dec, stop = gr, func() { _ = gr.Close() }
		}
	case strings.HasSuffix(name, ".xz"):
		dec, err = xzlimit.NewReader(bufio.NewReaderSize(r, 64<<10))
	case strings.HasSuffix(name, ".zst"):
		var zr *zstd.Decoder

		if zr, err = zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(1<<30)); err == nil {
			dec, stop = zr, zr.Close
		}
	case strings.HasSuffix(name, ".bz2"):
		dec = bzip2.NewReader(r)
	default:
		return &decompressed{Reader: limitio.Capped(r, maxSize+1, ErrTooLarge), src: r}, nil
	}

	if err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("repodata: opening %s: %w", name, err)
	}

	return &decompressed{Reader: limitio.Capped(dec, maxSize+1, ErrTooLarge), src: r, stop: stop}, nil
}

type decompressed struct {
	io.Reader

	src  io.Closer
	stop func()
}

func (d *decompressed) Close() error {
	if d.stop != nil {
		d.stop()
	}

	return d.src.Close()
}
