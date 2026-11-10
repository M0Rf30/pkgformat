package deb

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
)

func gzBytes(tb testing.TB, data []byte) []byte {
	tb.Helper()

	var buf bytes.Buffer

	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(tb, err)
	require.NoError(tb, w.Close())

	return buf.Bytes()
}

func xzBytes(tb testing.TB, data []byte) []byte {
	tb.Helper()

	var buf bytes.Buffer

	w, err := xz.NewWriter(&buf)
	require.NoError(tb, err)
	_, err = w.Write(data)
	require.NoError(tb, err)
	require.NoError(tb, w.Close())

	return buf.Bytes()
}

func zstBytes(tb testing.TB, data []byte) []byte {
	tb.Helper()

	var buf bytes.Buffer

	w, err := zstd.NewWriter(&buf)
	require.NoError(tb, err)
	_, err = w.Write(data)
	require.NoError(tb, err)
	require.NoError(tb, w.Close())

	return buf.Bytes()
}

func TestOpenIndexLimit(t *testing.T) {
	text := []byte(strings.Repeat("Package: bomb\n", 5000))

	for name, raw := range map[string][]byte{
		"Packages":     text,
		"Packages.gz":  gzBytes(t, text),
		"Packages.xz":  xzBytes(t, text),
		"Packages.zst": zstBytes(t, text),
	} {
		t.Run(name, func(t *testing.T) {
			// A limit above the size is fine.
			rc, err := openIndex(bytes.NewReader(raw), name, int64(len(text))+1)
			require.NoError(t, err)

			got, err := io.ReadAll(rc)
			require.NoError(t, err)
			assert.Equal(t, text, got)
			require.NoError(t, rc.Close())

			// One byte over the limit fails. (Whether data that ends exactly at the
			// limit is accepted depends on the decoder, so that is not asserted.)
			rc, err = openIndex(bytes.NewReader(raw), name, int64(len(text))-1)
			require.NoError(t, err)

			got, err = io.ReadAll(rc)
			require.ErrorIs(t, err, ErrTooLarge)
			assert.Less(t, len(got), len(text))
			require.NoError(t, rc.Close())

			// A hundred-fold expansion is stopped early.
			rc, err = openIndex(bytes.NewReader(raw), name, 100)
			require.NoError(t, err)

			got, err = io.ReadAll(rc)
			require.ErrorIs(t, err, ErrTooLarge)
			assert.LessOrEqual(t, len(got), 100)
			require.NoError(t, rc.Close())
		})
	}
}

func TestNewDecoderUnknownSuffix(t *testing.T) {
	_, err := newDecoder(strings.NewReader("x"), ".7z")
	require.ErrorIs(t, err, ErrUnsupportedArchiveFormat)
}

func TestCompressionOf(t *testing.T) {
	for name, want := range map[string]string{
		"Packages": "", "Packages.gz": ".gz", "a.bz2": ".bz2", "a.xz": ".xz", "a.lz4": ".lz4", "a.zst": ".zst",
		"a.gz.bak": "", "gz": "", ".gz": ".gz", "a.tar.xz": ".xz",
	} {
		assert.Equal(t, want, compressionOf(name), name)
	}
}

func FuzzOpenIndex(f *testing.F) {
	text := []byte("Package: a\nVersion: 1\nArchitecture: all\n\n")

	f.Add("Packages", text)
	f.Add("Packages.gz", gzBytes(f, text))
	f.Add("Packages.xz", xzBytes(f, text))
	f.Add("Packages.zst", zstBytes(f, text))
	f.Add("Packages.bz2", []byte("BZh9\x17rE8P\x90\x00\x00\x00\x00"))
	f.Add("Packages.lz4", []byte("\x04\x22\x4d\x18\x64\x40\xa7\x00\x00\x00\x00\x05\x93\x69\x0c"))
	f.Add("Packages.gz", gzBytes(f, bytes.Repeat([]byte("x"), 1<<14)))

	const limit = 1 << 12

	f.Fuzz(func(t *testing.T, name string, data []byte) {
		rc, err := openIndex(bytes.NewReader(data), name, limit)
		if err != nil {
			return
		}

		n, err := io.Copy(io.Discard, rc)
		_ = rc.Close()

		assert.LessOrEqual(t, n, int64(limit), "output beyond the limit")

		if err != nil && n >= limit {
			assert.True(t, errors.Is(err, ErrTooLarge) || !errors.Is(err, io.EOF), err)
		}

	})
}
