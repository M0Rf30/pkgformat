package cpio

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriterNewcLayout(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	require.NoError(t, w.WriteHeader(&Header{Name: "/a", Mode: 0o644, Size: 5}))
	_, err := w.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, w.WriteHeader(&Header{Name: "/d", Mode: S_ISDIR | 0o755, Links: 2}))
	require.NoError(t, w.Close())

	// regular type bits, one link and inode 1 are filled in; hex is upper case
	want := cat(
		[]byte("070701"+"00000001"+"000081A4"+"00000000"+"00000000"+"00000001"+"00000000"+"00000005"+"00000000"+"00000000"+"00000000"+"00000000"+"00000003"+"00000000"),
		[]byte("/a\x00\x00\x00\x00"), // name padded: 110 + 3 = 113 -> 116
		[]byte("hello\x00\x00\x00"),
		[]byte("070701"+"00000002"+"000041ED"+"00000000"+"00000000"+"00000002"+"00000000"+"00000000"+"00000000"+"00000000"+"00000000"+"00000000"+"00000003"+"00000000"),
		[]byte("/d\x00\x00\x00\x00"),
		[]byte("070701"+"00000000"+"00000000"+"00000000"+"00000000"+"00000001"+"00000000"+"00000000"+"00000000"+"00000000"+"00000000"+"00000000"+"0000000B"+"00000000"),
		[]byte("TRAILER!!!\x00\x00\x00\x00"),
	)
	require.Equal(t, want, buf.Bytes())
}

func TestWriterRoundTrip(t *testing.T) {
	files := map[string]string{"/a": "x", "/b": "hello", "/c": ""}
	order := []string{"/a", "/b", "/c"}
	var buf bytes.Buffer
	w := NewWriter(&buf)
	for _, n := range order {
		require.NoError(t, w.WriteHeader(&Header{Name: n, Mode: 0o600, Size: int64(len(files[n]))}))
		_, err := w.Write([]byte(files[n]))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	require.NoError(t, w.Close(), "closing twice is a no-op")

	r := NewReader(&buf)
	for _, n := range order {
		h, err := r.Next()
		require.NoError(t, err)
		require.Equal(t, n, h.Filename())
		b, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, files[n], string(b))
	}
	_, err := r.Next()
	require.ErrorIs(t, err, io.EOF)
}

func TestStrippedWriterRoundTrip(t *testing.T) {
	contents := [][]byte{[]byte("abc"), nil, bytes.Repeat([]byte{7}, 4097)}
	var buf bytes.Buffer
	w := NewStrippedWriter(&buf)
	var sizes []int64
	for i, c := range contents {
		require.NoError(t, w.WriteHeader(&Header{Index: i, Size: int64(len(c))}))
		_, err := w.Write(c)
		require.NoError(t, err)
		sizes = append(sizes, int64(len(c)))
	}
	require.NoError(t, w.Close())
	// entries and the trailer are 4 byte aligned, and the trailer is lower case
	require.Zero(t, buf.Len()%4)
	require.True(t, bytes.HasSuffix(buf.Bytes(), []byte("0000000b"+"00000000"+"TRAILER!!!\x00\x00\x00\x00")))

	r := NewReaderWithSizes(&buf, sizes)
	for i, c := range contents {
		h, err := r.Next()
		require.NoError(t, err)
		require.True(t, h.IsStripped())
		require.Equal(t, i, h.Index())
		b, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, string(c), string(b))
	}
	_, err := r.Next()
	require.ErrorIs(t, err, io.EOF)
}

func TestWriterErrors(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	require.NoError(t, w.WriteHeader(&Header{Name: "/a", Size: 2}))
	_, err := w.Write([]byte("abc"))
	require.ErrorIs(t, err, ErrWriteTooLong)

	w = NewWriter(&buf)
	require.NoError(t, w.WriteHeader(&Header{Name: "/a", Size: 2}))
	require.Error(t, w.WriteHeader(&Header{Name: "/b"}), "previous file is incomplete")

	w = NewWriter(&buf)
	require.ErrorIs(t, w.WriteHeader(&Header{Name: "/big", Size: 1 << 32}), ErrFileTooLarge)
	require.ErrorIs(t, NewWriter(&buf).WriteHeader(&Header{Name: "/neg", Size: -1}), ErrFileTooLarge)
	// the stripped format has no such limit
	require.NoError(t, NewStrippedWriter(io.Discard).WriteHeader(&Header{Size: 1 << 32}))

	w = NewWriter(&buf)
	require.NoError(t, w.Close())
	require.ErrorIs(t, w.WriteHeader(&Header{Name: "/a"}), ErrWriteAfterClose)
	_, err = w.Write([]byte("x"))
	require.ErrorIs(t, err, ErrWriteAfterClose)
}

type failWriter struct{ n int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.n--; f.n < 0 {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

func TestWriterWriteError(t *testing.T) {
	w := NewWriter(&failWriter{n: 1}) // the header is written, the content is not
	require.NoError(t, w.WriteHeader(&Header{Name: "/a", Size: 3}))
	_, err := w.Write([]byte("abc"))
	require.Error(t, err)
	require.Error(t, w.Close(), "the error sticks")
}
