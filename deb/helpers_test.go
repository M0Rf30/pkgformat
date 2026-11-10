package deb_test

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"

	"github.com/M0Rf30/pkgformat/deb"
)

// validControl is the control file of the packages the tests assemble by hand.
const validControl = "Package: crafted\nVersion: 1.0-1\nArchitecture: all\nMaintainer: A <a@example.org>\nDescription: crafted\n"

// bz2Control is a bzip2 control.tar holding validControl-like fields
// ("Package: bz", "Version: 1", "Architecture: all") and bz2Text the same
// fields as a plain index; the standard library cannot write bzip2.
const (
	bz2ControlTar = "QlpoOTFBWSZTWW/O5z8AAFxfgMqQQAHnkCAAQYB67Z4QBEggAHQiCYmmmgYgDRpp6QZUHpMRoAAADTVkjyCAtAQCJZliFq0IBEADI/W9KrL6EYScFEAzckGBz3KVLoH0KgNvbRK6PFh5JimQzMMUGBYoqnRjVHZXBahpAhCAH4u5IpwoSDfnc5+A"
	bz2Text       = "QlpoOTFBWSZTWR2JodMAAAZfgAAQQAAgECAAQQA67Z4QIAAxQAYjTTRoUaPUTDQ1MyaiTB4Q3B9UDuHMtroIvCSSr1jOX2G8LuSKcKEgOxNDpg=="
	bz2Plain      = "Package: bz\nVersion: 1\nArchitecture: all\n\n"
)

type arMem struct {
	name string
	data []byte
}

// buildAR assembles an ar archive by hand, the way dpkg-deb lays it out.
func buildAR(members ...arMem) []byte {
	var out bytes.Buffer

	out.WriteString("!<arch>\n")

	for _, m := range members {
		fmt.Fprintf(&out, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", m.name, 0, 0, 0, "100644", len(m.data))
		out.Write(m.data)

		if len(m.data)%2 != 0 {
			out.WriteByte('\n')
		}
	}

	return out.Bytes()
}

type tarEntry struct {
	hdr  tar.Header
	body string
}

// buildTar writes a tar archive; unlike deb.Write it accepts any entry,
// including the hostile ones.
func buildTar(tb testing.TB, entries ...tarEntry) []byte {
	tb.Helper()

	var buf bytes.Buffer

	tw := tar.NewWriter(&buf)

	for _, e := range entries {
		h := e.hdr
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}

		if h.Typeflag == tar.TypeReg && h.Size == 0 {
			h.Size = int64(len(e.body))
		}

		if h.Mode == 0 {
			h.Mode = 0o644
		}

		require.NoError(tb, tw.WriteHeader(&h))

		if h.Typeflag == tar.TypeReg {
			_, err := io.WriteString(tw, e.body)
			require.NoError(tb, err)
		}
	}

	require.NoError(tb, tw.Close())

	return buf.Bytes()
}

func reg(name, body string) tarEntry { return tarEntry{hdr: tar.Header{Name: name}, body: body} }

func dirEntry(name string, mode int64) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: mode}}
}

func symlinkEntry(name, target string) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777}}
}

func hardlinkEntry(name, target string) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeLink, Linkname: target}}
}

// compressWith compresses data; ext is ".gz", ".xz", ".zst" or "".
func compressWith(tb testing.TB, ext string, data []byte) []byte {
	tb.Helper()

	var buf bytes.Buffer

	switch ext {
	case "":
		return data
	case ".gz":
		w := gzip.NewWriter(&buf)
		_, err := w.Write(data)
		require.NoError(tb, err)
		require.NoError(tb, w.Close())
	case ".xz":
		w, err := xz.NewWriter(&buf)
		require.NoError(tb, err)
		_, err = w.Write(data)
		require.NoError(tb, err)
		require.NoError(tb, w.Close())
	case ".zst":
		w, err := zstd.NewWriter(&buf)
		require.NoError(tb, err)
		_, err = w.Write(data)
		require.NoError(tb, err)
		require.NoError(tb, w.Close())
	default:
		tb.Fatalf("unknown extension %q", ext)
	}

	return buf.Bytes()
}

// controlTar returns a control archive holding the control file.
func controlTar(tb testing.TB, control string, extra ...tarEntry) []byte {
	tb.Helper()

	return buildTar(tb, append([]tarEntry{reg("./control", control)}, extra...)...)
}

// debOf assembles a .deb from raw members.
func debOf(controlName string, control []byte, dataName string, data []byte) []byte {
	members := []arMem{{"debian-binary", []byte("2.0\n")}}

	if controlName != "" {
		members = append(members, arMem{controlName, control})
	}

	if dataName != "" {
		members = append(members, arMem{dataName, data})
	}

	return buildAR(members...)
}

// debWithData returns a package whose data archive is the tar bytes.
func debWithData(tb testing.TB, dataTar []byte) []byte {
	tb.Helper()

	return debOf("control.tar.gz", compressWith(tb, ".gz", controlTar(tb, validControl)), "data.tar", dataTar)
}

func parseDeb(raw []byte) (*deb.DebFile, error) {
	return deb.ParseDebFileAt(bytes.NewReader(raw), int64(len(raw)))
}
