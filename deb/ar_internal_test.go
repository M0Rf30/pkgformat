package deb

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validARHeader returns a well-formed 60-byte member header.
func validARHeader() []byte {
	buf := make([]byte, arHeaderSize)
	copy(buf[0:16], "test.txt        ")
	copy(buf[16:28], "1234567890  ")
	copy(buf[28:34], "0     ")
	copy(buf[34:40], "0     ")
	copy(buf[40:48], "100644  ")
	copy(buf[48:58], "1024      ")
	buf[58] = '`'
	buf[59] = '\n'

	return buf
}

// arMemberBytes renders one member (header, data, padding) by hand.
func arMemberBytes(name string, data []byte) []byte {
	var out bytes.Buffer

	fmt.Fprintf(&out, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", len(data))
	out.Write(data)

	if len(data)%2 != 0 {
		out.WriteByte('\n')
	}

	return out.Bytes()
}

func arArchive(members ...[]byte) []byte {
	out := []byte(arMagic)
	for _, m := range members {
		out = append(out, m...)
	}

	return out
}

func TestParseARHeader(t *testing.T) {
	header, err := parseARHeader(validARHeader())
	require.NoError(t, err)

	assert.Equal(t, "test.txt", header.Name)
	assert.Equal(t, int64(1024), header.Size)
	assert.Equal(t, int64(1234567890), header.ModTime.Unix())
	assert.Equal(t, 0, header.OwnerID)
	assert.Equal(t, 0, header.GroupID)
	assert.Equal(t, 0o100644, header.Mode)
}

func TestParseARHeaderGNUSlashName(t *testing.T) {
	buf := validARHeader()
	copy(buf[0:16], "data.tar.xz/    ")

	header, err := parseARHeader(buf)
	require.NoError(t, err)
	assert.Equal(t, "data.tar.xz", header.Name)
}

func TestParseARHeaderInvalid(t *testing.T) {
	tests := []struct {
		name  string
		setup func([]byte) []byte
		want  error
	}{
		{"short", func(b []byte) []byte { return b[:59] }, ErrInvalidHeaderSize},
		{"long", func(b []byte) []byte { return append(b, 'x') }, ErrInvalidHeaderSize},
		{"empty", func([]byte) []byte { return nil }, ErrInvalidHeaderSize},
		{"ending marker", func(b []byte) []byte { b[58], b[59] = 'X', 'Y'; return b }, ErrInvalidARHeaderEnd},
		{"ending newline", func(b []byte) []byte { b[59] = ' '; return b }, ErrInvalidARHeaderEnd},
		{"mtime", func(b []byte) []byte { copy(b[16:28], "yesterday   "); return b }, ErrInvalidModTime},
		{"owner", func(b []byte) []byte { copy(b[28:34], "root  "); return b }, ErrInvalidOwnerID},
		{"group", func(b []byte) []byte { copy(b[34:40], "wheel "); return b }, ErrInvalidGroupID},
		{"mode not octal", func(b []byte) []byte { copy(b[40:48], "100999  "); return b }, ErrInvalidMode},
		{"size", func(b []byte) []byte { copy(b[48:58], "invalid   "); return b }, ErrInvalidSize},
		{"negative size", func(b []byte) []byte { copy(b[48:58], "-1        "); return b }, ErrInvalidSize},
		{"empty size", func(b []byte) []byte { copy(b[48:58], "          "); return b }, ErrInvalidSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseARHeader(tt.setup(validARHeader()))
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestARWriterLayout(t *testing.T) {
	var buf bytes.Buffer

	aw, err := newARWriter(&buf)
	require.NoError(t, err)

	mod := time.Unix(1700000000, 0)

	require.NoError(t, aw.member("odd", 3, mod, strings.NewReader("abc")))
	require.NoError(t, aw.member("even", 4, mod, strings.NewReader("abcd")))
	require.NoError(t, aw.member("empty", 0, mod, strings.NewReader("")))
	require.NoError(t, aw.member("exactly16chars!!", 1, mod, strings.NewReader("z")))

	raw := buf.Bytes()
	assert.True(t, bytes.HasPrefix(raw, []byte(arMagic)))
	// 8 magic + (60+3+1) + (60+4) + 60 + (60+1+1)
	assert.Len(t, raw, 8+64+64+60+62)
	assert.Equal(t, byte('\n'), raw[8+60+3], "odd member is padded with a newline")

	members, err := readARMembers(bytes.NewReader(raw), int64(len(raw)))
	require.NoError(t, err)
	require.Len(t, members, 4)

	assert.Equal(t, "odd", members[0].Name)
	assert.Equal(t, int64(3), members[0].Size)
	assert.Equal(t, 0o100644, members[0].Mode)
	assert.Equal(t, 0, members[0].OwnerID)
	assert.Equal(t, 0, members[0].GroupID)
	assert.Equal(t, int64(1700000000), members[0].ModTime.Unix())
	assert.Equal(t, "even", members[1].Name)
	assert.Equal(t, "empty", members[2].Name)
	assert.Equal(t, int64(0), members[2].Size)
	assert.Equal(t, "exactly16chars!!", members[3].Name)

	assert.Equal(t, "abc", string(raw[members[0].dataOff:members[0].dataOff+3]))
	assert.Equal(t, "abcd", string(raw[members[1].dataOff:members[1].dataOff+4]))
}

func TestARWriterNegativeModTimeClamped(t *testing.T) {
	var buf bytes.Buffer

	aw, err := newARWriter(&buf)
	require.NoError(t, err)
	require.NoError(t, aw.member("x", 0, time.Unix(-5, 0), strings.NewReader("")))

	members, err := readARMembers(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, int64(0), members[0].ModTime.Unix())
}

func TestARWriterBadNames(t *testing.T) {
	for name, member := range map[string]string{
		"empty":    "",
		"too long": strings.Repeat("a", arNameLen+1),
		"space":    "a b",
		"slash":    "a/b",
		"newline":  "a\nb",
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer

			aw, err := newARWriter(&buf)
			require.NoError(t, err)

			err = aw.member(member, 1, time.Time{}, strings.NewReader("x"))
			require.ErrorIs(t, err, ErrInvalidSpec)
			assert.Equal(t, len(arMagic), buf.Len(), "nothing but the magic may be written")

			// The error is sticky.
			require.ErrorIs(t, aw.member("ok", 0, time.Time{}, strings.NewReader("")), ErrInvalidSpec)
		})
	}
}

func TestARWriterBadSizes(t *testing.T) {
	aw, err := newARWriter(io.Discard)
	require.NoError(t, err)
	require.ErrorIs(t, aw.member("neg", -1, time.Time{}, strings.NewReader("")), ErrInvalidSize)

	aw, err = newARWriter(io.Discard)
	require.NoError(t, err)
	// 13 digits do not fit the 10-character size field.
	require.ErrorIs(t, aw.member("huge", 1<<40, time.Time{}, strings.NewReader("")), ErrInvalidSize)
}

func TestARWriterShortBody(t *testing.T) {
	aw, err := newARWriter(io.Discard)
	require.NoError(t, err)

	err = aw.member("short", 10, time.Time{}, strings.NewReader("abc"))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)

	// Sticky: later members fail with the same error.
	require.ErrorIs(t, aw.member("later", 0, time.Time{}, strings.NewReader("")), io.ErrUnexpectedEOF)
}

// failAfter fails every write once n bytes have been accepted.
type failAfter struct{ n int }

var errDisk = errors.New("disk full")

func (f *failAfter) Write(p []byte) (int, error) {
	if len(p) > f.n {
		return 0, errDisk
	}

	f.n -= len(p)

	return len(p), nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errDisk }

func TestARWriterIOErrors(t *testing.T) {
	_, err := newARWriter(&failAfter{n: 0})
	require.ErrorIs(t, err, errDisk)

	// Header fails.
	aw, err := newARWriter(&failAfter{n: len(arMagic)})
	require.NoError(t, err)
	require.ErrorIs(t, aw.member("a", 1, time.Time{}, strings.NewReader("x")), errDisk)

	// Body fails.
	aw, err = newARWriter(&failAfter{n: len(arMagic) + arHeaderSize})
	require.NoError(t, err)
	require.ErrorIs(t, aw.member("a", 1, time.Time{}, strings.NewReader("x")), errDisk)

	// Padding fails.
	aw, err = newARWriter(&failAfter{n: len(arMagic) + arHeaderSize + 1})
	require.NoError(t, err)
	require.ErrorIs(t, aw.member("a", 1, time.Time{}, strings.NewReader("x")), errDisk)

	// The source fails.
	aw, err = newARWriter(io.Discard)
	require.NoError(t, err)
	require.ErrorIs(t, aw.member("a", 1, time.Time{}, errReader{}), errDisk)
}

func TestReadARMembers(t *testing.T) {
	t.Run("magic only", func(t *testing.T) {
		raw := []byte(arMagic)
		members, err := readARMembers(bytes.NewReader(raw), int64(len(raw)))
		require.NoError(t, err)
		assert.Empty(t, members)
	})

	t.Run("bad magic", func(t *testing.T) {
		raw := []byte("!<arch>X" + strings.Repeat(" ", 100))
		_, err := readARMembers(bytes.NewReader(raw), int64(len(raw)))
		require.ErrorIs(t, err, ErrInvalidARMagic)
	})

	t.Run("truncated magic", func(t *testing.T) {
		_, err := readARMembers(bytes.NewReader([]byte("!<ar")), 4)
		require.ErrorIs(t, err, io.EOF)
	})

	t.Run("empty", func(t *testing.T) {
		_, err := readARMembers(bytes.NewReader(nil), 0)
		require.Error(t, err)
	})

	t.Run("member beyond file", func(t *testing.T) {
		raw := arArchive(arMemberBytes("data.tar", bytes.Repeat([]byte("x"), 100)))
		raw = raw[:len(raw)-10]
		_, err := readARMembers(bytes.NewReader(raw), int64(len(raw)))
		require.ErrorIs(t, err, ErrARMemberTooLarge)
	})

	t.Run("declared size far beyond file", func(t *testing.T) {
		raw := arArchive(arMemberBytes("data.tar", []byte("abcd")))
		copy(raw[8+48:8+58], "9999999999")
		_, err := readARMembers(bytes.NewReader(raw), int64(len(raw)))
		require.ErrorIs(t, err, ErrARMemberTooLarge)
	})

	t.Run("bad member header", func(t *testing.T) {
		raw := arArchive(arMemberBytes("a", []byte("xy")))
		raw[8+58] = 'Z'
		_, err := readARMembers(bytes.NewReader(raw), int64(len(raw)))
		require.ErrorIs(t, err, ErrInvalidARHeaderEnd)
	})

	t.Run("trailing garbage shorter than a header", func(t *testing.T) {
		raw := append(arArchive(arMemberBytes("a", []byte("xy"))), "junk"...)
		members, err := readARMembers(bytes.NewReader(raw), int64(len(raw)))
		require.NoError(t, err)
		assert.Len(t, members, 1)
	})

	t.Run("missing final padding", func(t *testing.T) {
		raw := arArchive(arMemberBytes("a", []byte("xyz")))
		raw = raw[:len(raw)-1]
		members, err := readARMembers(bytes.NewReader(raw), int64(len(raw)))
		require.NoError(t, err)
		assert.Len(t, members, 1)
	})

	t.Run("member limit", func(t *testing.T) {
		var parts [][]byte
		for range maxARMembers {
			parts = append(parts, arMemberBytes("m", nil))
		}

		raw := arArchive(parts...)
		members, err := readARMembers(bytes.NewReader(raw), int64(len(raw)))
		require.NoError(t, err)
		assert.Len(t, members, maxARMembers)

		raw = arArchive(append(parts, arMemberBytes("m", nil))...)
		_, err = readARMembers(bytes.NewReader(raw), int64(len(raw)))
		require.ErrorIs(t, err, ErrTooManyMembers)
	})

	t.Run("read error on header", func(t *testing.T) {
		raw := arArchive(arMemberBytes("a", nil))
		_, err := readARMembers(errAt{data: raw, failFrom: 8}, int64(len(raw)))
		require.ErrorIs(t, err, errDisk)
	})
}

// errAt serves data and fails reads that reach failFrom.
type errAt struct {
	data     []byte
	failFrom int64
}

func (e errAt) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > e.failFrom && off >= e.failFrom {
		return 0, errDisk
	}

	return bytes.NewReader(e.data).ReadAt(p, off)
}

// FuzzParseARHeader feeds arbitrary header bytes to the header parser.
func FuzzParseARHeader(f *testing.F) {
	f.Add(validARHeader())
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{' '}, arHeaderSize))
	f.Add(append(bytes.Repeat([]byte{'9'}, arHeaderSize-2), '`', '\n'))

	f.Fuzz(func(t *testing.T, in []byte) {
		h, err := parseARHeader(in)
		if err != nil {
			return
		}

		assert.Len(t, in, arHeaderSize)
		assert.GreaterOrEqual(t, h.Size, int64(0))
	})
}

// FuzzReadARMembers feeds arbitrary archives to the member walker; every
// member it returns must lie inside the input.
func FuzzReadARMembers(f *testing.F) {
	f.Add([]byte(arMagic))
	f.Add(arArchive(arMemberBytes("debian-binary", []byte("2.0\n"))))
	f.Add(arArchive(arMemberBytes("a", []byte("xyz")), arMemberBytes("b", nil)))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, in []byte) {
		members, err := readARMembers(bytes.NewReader(in), int64(len(in)))
		if err != nil {
			return
		}

		assert.LessOrEqual(t, len(members), maxARMembers)

		for _, m := range members {
			assert.GreaterOrEqual(t, m.dataOff, int64(len(arMagic)+arHeaderSize))
			assert.LessOrEqual(t, m.dataOff+m.Size, int64(len(in)))
		}
	})
}
