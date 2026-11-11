package repodata

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func fuzzSeedFiles(f *testing.F) {
	f.Helper()

	for _, name := range []string{"createrepo-other.xml.zck", "zck-other-sha256.zck", "zck-other-none.zck", "zck-other-uncompressed-source.zck", "zck-primary-dict.zhr"} {
		b, err := os.ReadFile(filepath.Join("testdata", "zchunk", name))
		if err != nil {
			f.Fatal(err)
		}

		// The seeds are cut to what the fuzzer can mutate usefully: the
		// header and the first chunks.
		f.Add(b[:min(len(b), 4096)])
	}

	f.Add(rawHeader{comp: 2, entries: [][]byte{entry(32, 0, 0), entry(32, 10, 20)}}.bytes())
	f.Add(zchunkMagic)
}

func FuzzReadZchunkHeader(f *testing.F) {
	fuzzSeedFiles(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ReadZchunkHeader(bytes.NewReader(data), ZchunkReadOptions{MaxHeaderSize: 1 << 20, MaxChunkSize: 1 << 20, MaxSize: 1 << 30})
		if err != nil {
			return
		}

		// What parses is consistent: the chunks follow the header and the
		// sizes add up.
		at := h.Size
		for _, c := range h.Chunks {
			if c.Offset < at || c.Size < 0 || c.CompressedSize < 0 {
				t.Fatalf("chunk %+v at %d", c, at)
			}
		}

		if h.Size > int64(len(data)) || len(h.Checksum) != h.ChecksumType.Size() || len(h.DataChecksum) != h.ChecksumType.Size() {
			t.Fatalf("header %+v of %d bytes", h, len(data))
		}

		_ = h.MissingChunks(nil)
		_ = ByteRanges(h.Chunks)
	})
}

func FuzzZchunkReader(f *testing.F) {
	for _, name := range []string{"createrepo-other.xml.zck", "zck-other-sha256.zck", "zck-other-none.zck", "zck-other-uncompressed-source.zck"} {
		b, err := os.ReadFile(filepath.Join("testdata", "zchunk", name))
		if err != nil {
			f.Fatal(err)
		}

		f.Add(b)
	}

	small, _ := writeZchunk(f, []byte("<a>\n<package>1</package>\n<package>2</package>\n</a>"), ZchunkOptions{Chunking: ZchunkXMLPackages})
	f.Add(small)

	f.Fuzz(func(_ *testing.T, data []byte) {
		zr, err := NewZchunkReader(bytes.NewReader(data), ZchunkReadOptions{MaxHeaderSize: 1 << 20, MaxChunkSize: 1 << 20, MaxSize: 1 << 22})
		if err != nil {
			return
		}

		_, _ = io.Copy(io.Discard, zr)
		_ = zr.Close()
	})
}

// Whatever is written reads back, in any chunking.
func FuzzZchunkRoundTrip(f *testing.F) {
	f.Add([]byte("<m>\n<package a>x</package>\n<package>y</package>\n</m>"), uint8(0), uint8(0), uint16(100))
	f.Add(bytes.Repeat([]byte("ab"), 40000), uint8(1), uint8(1), uint16(7))
	f.Add([]byte(""), uint8(2), uint8(2), uint16(1))

	f.Fuzz(func(t *testing.T, doc []byte, chunking, sum uint8, piece uint16) {
		opts := ZchunkOptions{
			Chunking:      ZchunkChunking(chunking % 3),
			ChunkChecksum: ZchunkChecksum(sum % 3),
			MaxChunkSize:  1 + int(piece)*3,
			Level:         1,
		}

		var buf bytes.Buffer

		zw, err := NewZchunkWriter(&buf, opts)
		if err != nil {
			t.Fatal(err)
		}

		step := int(piece) + 1
		for rest := doc; len(rest) > 0; rest = rest[min(step, len(rest)):] {
			if _, err := zw.Write(rest[:min(step, len(rest))]); err != nil {
				t.Fatal(err)
			}
		}

		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}

		zr, err := NewZchunkReader(bytes.NewReader(buf.Bytes()), ZchunkReadOptions{})
		if err != nil {
			t.Fatal(err)
		}

		got, err := io.ReadAll(zr)
		if err != nil || !bytes.Equal(got, doc) {
			t.Fatalf("round trip: %v, %d bytes of %d", err, len(got), len(doc))
		}

		for _, c := range zw.Header().Chunks {
			if c.Size > int64(opts.MaxChunkSize) {
				t.Fatalf("chunk of %d bytes over the maximum %d", c.Size, opts.MaxChunkSize)
			}
		}
	})
}
