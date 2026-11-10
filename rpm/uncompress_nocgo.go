//go:build !cgo
// +build !cgo

package rpm

import (
	"io"

	"github.com/klauspost/compress/zstd"
)

func newZstdReader(r io.Reader) (io.ReadCloser, error) {
	// 128 MiB is the default window limit of the reference zstd decoder; the
	// window size is taken from the untrusted frame header and allocated.
	decoder, err := zstd.NewReader(r, zstd.WithDecoderMaxWindow(128<<20))
	if err != nil {
		return nil, err
	}
	return zstdCloser{Decoder: decoder}, nil
}

// wrap Decoder so it implements io.Closer properly
type zstdCloser struct {
	*zstd.Decoder
}

func (d zstdCloser) Close() error {
	d.Decoder.Close()
	return nil
}
