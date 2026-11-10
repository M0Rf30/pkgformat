package deb_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/pierrec/lz4/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/xzlimit"
)

func lz4Of(t testing.TB, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer

	w := lz4.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.Bytes()
}

func bz2Fixture(t testing.TB) []byte {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(bz2Text)
	require.NoError(t, err)

	return raw
}

func readIndex(t *testing.T, raw []byte, name string) (string, error) {
	t.Helper()

	rc, err := deb.OpenIndex(bytes.NewReader(raw), name)
	if err != nil {
		return "", err
	}

	defer rc.Close()

	out, err := io.ReadAll(rc)

	return string(out), err
}

func TestOpenIndexFormats(t *testing.T) {
	text := []byte(strings.Repeat("Package: p\nVersion: 1\nArchitecture: all\n\n", 200))

	tests := map[string][]byte{
		"Packages":     text,
		"Packages.gz":  compressWith(t, ".gz", text),
		"Packages.xz":  compressWith(t, ".xz", text),
		"Packages.zst": compressWith(t, ".zst", text),
		"Packages.lz4": lz4Of(t, text),
		// An unknown suffix is read as it is.
		"Packages.unknown": text,
		"Sources.gz":       compressWith(t, ".gz", text),
	}

	for name, raw := range tests {
		got, err := readIndex(t, raw, name)
		require.NoError(t, err, name)
		assert.Equal(t, string(text), got, name)
	}

	got, err := readIndex(t, bz2Fixture(t), "Packages.bz2")
	require.NoError(t, err)
	assert.Equal(t, bz2Plain, got)
}

func TestOpenIndexEmptyInput(t *testing.T) {
	got, err := readIndex(t, nil, "Packages")
	require.NoError(t, err)
	assert.Empty(t, got)

	for _, name := range []string{"Packages.gz", "Packages.xz"} {
		_, err = readIndex(t, nil, name)
		require.Error(t, err, name)
	}
}

func TestOpenIndexCorrupt(t *testing.T) {
	text := []byte(strings.Repeat("Package: p\n", 1000))

	for _, ext := range []string{".gz", ".xz", ".zst"} {
		raw := compressWith(t, ext, text)

		// A truncated stream fails while reading.
		_, err := readIndex(t, raw[:len(raw)/2], "Packages"+ext)
		require.Error(t, err, ext)

		// So does random content.
		_, err = readIndex(t, []byte("definitely not compressed data, at all"), "Packages"+ext)
		require.Error(t, err, ext)
	}

	_, err := readIndex(t, []byte("not bzip2"), "Packages.bz2")
	require.Error(t, err)

	_, err = readIndex(t, []byte("not lz4 either"), "Packages.lz4")
	require.Error(t, err)
}

type closeTracker struct {
	io.Reader

	closed int
}

func (c *closeTracker) Close() error { c.closed++; return nil }

func TestOpenIndexClosesSource(t *testing.T) {
	text := []byte("Package: p\n")

	for name, raw := range map[string][]byte{
		"Packages": text, "Packages.gz": compressWith(t, ".gz", text), "Packages.xz": compressWith(t, ".xz", text),
		"Packages.zst": compressWith(t, ".zst", text), "Packages.bz2": bz2Fixture(t), "Packages.lz4": lz4Of(t, text),
	} {
		src := &closeTracker{Reader: bytes.NewReader(raw)}

		rc, err := deb.OpenIndex(src, name)
		require.NoError(t, err, name)

		_, err = io.ReadAll(rc)
		require.NoError(t, err, name)
		require.NoError(t, rc.Close(), name)
		assert.Equal(t, 1, src.closed, name)
	}

	// A decoder that fails to start still releases the source.
	src := &closeTracker{Reader: strings.NewReader("junk junk junk junk")}
	_, err := deb.OpenIndex(src, "Packages.gz")
	require.Error(t, err)
	assert.Equal(t, 1, src.closed)
}

func TestOpenIndexRejectsHugeXZDictionary(t *testing.T) {
	raw := compressWith(t, ".xz", []byte("Package: p\n"))

	// The stream header (12 bytes) is followed by the block header; the LZMA2
	// dictionary-size byte sits at offset 16 and 0x28 asks for 4 GiB.
	raw[16] = 0x28

	_, err := readIndex(t, raw, "Packages.xz")
	require.ErrorIs(t, err, xzlimit.ErrDictTooLarge)
}

func TestOpenIndexRejectsHugeZstdWindow(t *testing.T) {
	// Frame header with a 2^40-byte window and no content size.
	raw := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0xf8, 0x01, 0x00, 0x00}

	_, err := readIndex(t, raw, "Packages.zst")
	require.Error(t, err)
}

// countingReader counts Read calls.
type countingReader struct {
	r     io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) { c.reads++; return c.r.Read(p) }

// The xz decoder asks for one byte at a time; OpenIndex must buffer that.
func TestOpenIndexReadsXZInLargeChunks(t *testing.T) {
	raw := compressWith(t, ".xz", bytes.Repeat([]byte("Package: p\nVersion: 1\n\n"), 20000))

	src := &countingReader{r: bytes.NewReader(raw)}

	rc, err := deb.OpenIndex(src, "Packages.xz")
	require.NoError(t, err)

	_, err = io.Copy(io.Discard, rc)
	require.NoError(t, err)
	assert.Less(t, src.reads, len(raw)/1024+8, "%d reads for %d bytes", src.reads, len(raw))
}

func TestOpenIndexWithRealCompressors(t *testing.T) {
	text := []byte(strings.Repeat("Package: real\nVersion: 1\nArchitecture: all\n\n", 500))

	for _, tc := range []struct{ tool, ext string }{
		{"gzip", ".gz"}, {"xz", ".xz"}, {"bzip2", ".bz2"}, {"zstd", ".zst"}, {"lz4", ".lz4"},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			path, err := exec.LookPath(tc.tool)
			if err != nil {
				t.Skipf("%s not installed", tc.tool)
			}

			cmd := exec.Command(path, "-c")
			cmd.Stdin = bytes.NewReader(text)

			raw, err := cmd.Output()
			require.NoError(t, err)

			got, err := readIndex(t, raw, "Packages"+tc.ext)
			require.NoError(t, err)
			assert.Equal(t, string(text), got)
		})
	}
}

var errReadFailed = errors.New("read failed")

func TestOpenIndexPropagatesReadError(t *testing.T) {
	rc, err := deb.OpenIndex(io.MultiReader(strings.NewReader("Package: a\n"), errReader{}), "Packages")
	require.NoError(t, err)

	_, err = io.ReadAll(rc)
	require.ErrorIs(t, err, errReadFailed)
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errReadFailed }
