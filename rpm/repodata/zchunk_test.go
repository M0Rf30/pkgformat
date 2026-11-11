package repodata

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
)

func zfixture(t testing.TB, name string) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join("testdata", "zchunk", name))
	if err != nil {
		t.Fatal(err)
	}

	return b
}

// goldenXML is the document createrepo_c wrote for the corpus: primary,
// filelists or other.
func goldenXML(t testing.TB, name string) []byte {
	t.Helper()

	f, err := os.Open(filepath.Join("testdata", "createrepo", "golden", name+".xml.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}

	return doc
}

func writeZchunk(t testing.TB, doc []byte, opts ZchunkOptions) ([]byte, *ZchunkHeader) {
	t.Helper()

	var buf bytes.Buffer

	zw, err := NewZchunkWriter(&buf, opts)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := zw.Write(doc); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes(), zw.Header()
}

func readZchunk(t testing.TB, file []byte, opts ZchunkReadOptions) ([]byte, *ZchunkHeader) {
	t.Helper()

	zr, err := NewZchunkReader(bytes.NewReader(file), opts)
	if err != nil {
		t.Fatal(err)
	}

	defer zr.Close()

	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}

	return got, zr.Header()
}

func chunkSizes(h *ZchunkHeader) []int64 {
	sizes := make([]int64, len(h.Chunks))
	for i, c := range h.Chunks {
		sizes[i] = c.Size
	}

	return sizes
}

func TestZchunkCompint(t *testing.T) {
	for _, v := range []uint64{0, 1, 127, 128, 129, 16383, 16384, 1 << 31, 1<<32 + 5, math.MaxInt64} {
		b := appendCompint(nil, v)

		got, n, err := parseCompint(b)
		if err != nil || got != v || n != len(b) {
			t.Errorf("%d: got %d, %d bytes of %d, %v", v, got, n, len(b), err)
		}

		if b[len(b)-1] < 128 || (len(b) > 1 && b[0] >= 128) {
			t.Errorf("%d: bad terminator bits in % x", v, b)
		}
	}

	// The documented little-endian layout: 300 = 0b10_0101100.
	if got := appendCompint(nil, 300); !bytes.Equal(got, []byte{0x2c, 0x82}) {
		t.Errorf("300 = % x, want 2c 82", got)
	}

	for name, b := range map[string][]byte{
		"empty":      {},
		"unfinished": {0x01, 0x02},
		"too long":   bytes.Repeat([]byte{0}, 11),
		"overflow":   append(bytes.Repeat([]byte{0xff & 0x7f}, 9), 0x80|0x7f),
		"63 bits":    append(bytes.Repeat([]byte{0}, 9), 0x81),
	} {
		if _, _, err := parseCompint(b); err == nil {
			t.Errorf("%s: no error", name)
		}
	}

	// Padding that keeps the value is accepted: a writer need not be minimal.
	if v, n, err := parseCompint([]byte{0x01, 0x00, 0x80}); err != nil || v != 1 || n != 3 {
		t.Errorf("padded: %d, %d, %v", v, n, err)
	}
}

func TestZchunkChecksumTypes(t *testing.T) {
	want := map[ZchunkChecksum]struct {
		size int
		name string
		wire uint64
	}{
		ZchunkSHA1:       {20, "sha1", 0},
		ZchunkSHA256:     {32, "sha256", 1},
		ZchunkSHA512:     {64, "sha512", 2},
		ZchunkSHA512_128: {16, "sha512-128", 3},
	}

	for c, w := range want {
		if c.Size() != w.size || c.String() != w.name || c.wire() != w.wire || len(c.digest([]byte("x"))) != w.size {
			t.Errorf("%v: size %d name %s wire %d", c, c.Size(), c, c.wire())
		}

		if back, ok := checksumFromWire(w.wire); !ok || back != c {
			t.Errorf("wire %d -> %v", w.wire, back)
		}
	}

	// SHA-512/128 is the head of SHA-512, not the SHA-512/256 variant.
	if got, full := ZchunkSHA512_128.digest([]byte("abc")), ZchunkSHA512.digest([]byte("abc")); !bytes.Equal(got, full[:16]) {
		t.Errorf("sha512-128 %x is not the head of sha512 %x", got, full)
	}

	if _, ok := checksumFromWire(4); ok {
		t.Error("wire 4 accepted")
	}

	if ZchunkZstd.String() != "zstd" || ZchunkNone.String() != "none" {
		t.Errorf("compressions %s, %s", ZchunkZstd, ZchunkNone)
	}
}

// The reference tools' own files decode, and to the document they were made
// from: createrepo_c --zck against the gzip createrepo_c wrote next to them,
// zck against its input.
func TestZchunkReadsReferenceFiles(t *testing.T) {
	cases := []struct {
		file, doc string
		check     func(*testing.T, *ZchunkHeader)
	}{
		{"createrepo-primary.xml.zck", "primary", func(t *testing.T, h *ZchunkHeader) {
			if len(h.Chunks) != 32 || h.HasDict() || h.ChunkChecksumType != ZchunkSHA512_128 || h.Compression != ZchunkZstd {
				t.Errorf("%d chunks, dict %v, %v, %v", len(h.Chunks), h.HasDict(), h.ChunkChecksumType, h.Compression)
			}
		}},
		{"createrepo-filelists.xml.zck", "filelists", nil},
		{"createrepo-other.xml.zck", "other", nil},
		{"zck-filelists.zck", "filelists", nil},
		{"zck-other-sha256.zck", "other", func(t *testing.T, h *ZchunkHeader) {
			if h.ChunkChecksumType != ZchunkSHA256 {
				t.Errorf("chunk checksum %v", h.ChunkChecksumType)
			}
		}},
		{"zck-other-sha512.zck", "other", func(t *testing.T, h *ZchunkHeader) {
			if h.ChunkChecksumType != ZchunkSHA512 {
				t.Errorf("chunk checksum %v", h.ChunkChecksumType)
			}
		}},
		{"zck-other-none.zck", "other", func(t *testing.T, h *ZchunkHeader) {
			if h.Compression != ZchunkNone {
				t.Errorf("compression %v", h.Compression)
			}
		}},
		{"zck-other-uncompressed-source.zck", "other", func(t *testing.T, h *ZchunkHeader) {
			if !h.UncompressedSource || len(h.Chunks[0].UncompressedChecksum) != 32 {
				t.Errorf("uncompressed source %v", h.UncompressedSource)
			}
		}},
		{"zck-other-split.zck", "other", nil},
		{"zck-primary-dict.zck", "primary", func(t *testing.T, h *ZchunkHeader) {
			if !h.HasDict() || h.Dict.Size != int64(len(zfixture(t, "primary.zdict"))) {
				t.Errorf("dictionary %+v", h.Dict)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			file := zfixture(t, tc.file)

			got, h := readZchunk(t, file, ZchunkReadOptions{})
			if !bytes.Equal(got, goldenXML(t, tc.doc)) {
				t.Fatal("decoded document differs from the one it was made from")
			}

			if h.FileSize() != int64(len(file)) || h.UncompressedSize() != int64(len(got)) || h.ChecksumType != ZchunkSHA256 {
				t.Errorf("sizes: file %d/%d content %d/%d", h.FileSize(), len(file), h.UncompressedSize(), len(got))
			}

			if tc.check != nil {
				tc.check(t, h)
			}
		})
	}
}

// What the file says about itself equals what zck_read_header reports.
func TestZchunkHeaderMatchesReferenceTool(t *testing.T) {
	tool := needTool(t, "zck_read_header")

	for _, name := range []string{"createrepo-primary.xml.zck", "zck-primary-dict.zck", "zck-other-sha256.zck"} {
		h, err := ReadZchunkHeader(bytes.NewReader(zfixture(t, name)), ZchunkReadOptions{})
		if err != nil {
			t.Fatal(err)
		}

		out := run(t, tool, "-c", filepath.Join("testdata", "zchunk", name))
		if !strings.Contains(out, "Header size: "+strconv.FormatInt(h.Size, 10)+"\n") ||
			!strings.Contains(out, "Header checksum: "+h.HexChecksum()+"\n") ||
			!strings.Contains(out, "Data size: "+strconv.FormatInt(h.DataSize(), 10)+"\n") ||
			!strings.Contains(out, "Chunk count: "+strconv.Itoa(len(h.Chunks)+1)+"\n") {
			t.Errorf("%s: header %d %s %d differs from\n%s", name, h.Size, h.HexChecksum(), h.DataSize(), out)
		}

		// Every row of the listing is a chunk: number, checksum, start, sizes.
		rows := regexp.MustCompile(`(?m)^\s+(\d+) ([0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)$`).FindAllStringSubmatch(out, -1)
		if len(rows) != len(h.Chunks)+1 {
			t.Fatalf("%s: %d rows for %d chunks", name, len(rows), len(h.Chunks)+1)
		}

		for i, c := range append([]ZchunkChunk{h.Dict}, h.Chunks...) {
			r := rows[i]
			if r[2] != fmt.Sprintf("%x", c.Checksum) || r[3] != strconv.FormatInt(c.Offset, 10) ||
				r[4] != strconv.FormatInt(c.CompressedSize, 10) || r[5] != strconv.FormatInt(c.Size, 10) {
				t.Errorf("%s chunk %d: %v differs from %+v", name, i, r[1:], c)
			}
		}
	}
}

// ReadZchunkHeader takes the header and not a byte more, and a detached
// header is the header of its file.
func TestZchunkReadHeaderConsumesOnlyTheHeader(t *testing.T) {
	file := zfixture(t, "zck-primary-dict.zck")

	r := bytes.NewReader(file)

	h, err := ReadZchunkHeader(r, ZchunkReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if consumed := int64(len(file)) - int64(r.Len()); consumed != h.Size {
		t.Errorf("consumed %d bytes, header is %d", consumed, h.Size)
	}

	if h.Detached {
		t.Error("a file is not detached")
	}

	detached, err := ReadZchunkHeader(bytes.NewReader(zfixture(t, "zck-primary-dict.zhr")), ZchunkReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !detached.Detached || detached.Size != h.Size || !bytes.Equal(detached.Checksum, h.Checksum) ||
		!slices.EqualFunc(detached.Chunks, h.Chunks, func(a, b ZchunkChunk) bool {
			return a.Offset == b.Offset && a.Size == b.Size && bytes.Equal(a.Checksum, b.Checksum)
		}) {
		t.Errorf("detached header %+v is not that of the file %+v", detached, h)
	}

	if _, err := NewZchunkReader(bytes.NewReader(zfixture(t, "zck-primary-dict.zhr")), ZchunkReadOptions{}); !errors.Is(err, ErrZchunkFormat) {
		t.Errorf("reading data from a detached header: %v", err)
	}
}

// Content-defined chunking cuts where zck does: the chunk sizes of the files
// zck wrote are those of this writer for the same document, whatever the sizes
// of the writes that carry the data.
func TestZchunkContentChunksMatchReferenceTool(t *testing.T) {
	for _, tc := range []struct{ file, doc string }{
		{"zck-filelists.zck", "filelists"},
		{"zck-other-sha256.zck", "other"},
		{"zck-other-sha512.zck", "other"},
	} {
		want, err := ReadZchunkHeader(bytes.NewReader(zfixture(t, tc.file)), ZchunkReadOptions{})
		if err != nil {
			t.Fatal(err)
		}

		doc := goldenXML(t, tc.doc)

		for _, piece := range []int{len(doc), 4096, 1000, 7, 1} {
			if piece < 1000 && len(doc) > 1<<20 {
				continue
			}

			var buf bytes.Buffer

			zw, err := NewZchunkWriter(&buf, ZchunkOptions{})
			if err != nil {
				t.Fatal(err)
			}

			for rest := doc; len(rest) > 0; rest = rest[min(piece, len(rest)):] {
				if _, err := zw.Write(rest[:min(piece, len(rest))]); err != nil {
					t.Fatal(err)
				}
			}

			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}

			if got := chunkSizes(zw.Header()); !slices.Equal(got, chunkSizes(want)) {
				t.Errorf("%s, writes of %d: chunks %v, zck cuts %v", tc.file, piece, got, chunkSizes(want))
			}
		}
	}
}

// The chunks of the package-per-chunk mode are createrepo_c's, except that
// createrepo_c keeps the packages of one source package in one chunk: its
// boundaries are among ours, and the documents are the same.
func TestZchunkPackageChunksAgreeWithCreaterepo(t *testing.T) {
	for _, name := range []string{"primary", "filelists", "other"} {
		doc := goldenXML(t, name)
		file, h := writeZchunk(t, doc, ZchunkOptions{Chunking: ZchunkXMLPackages})

		ref, err := ReadZchunkHeader(bytes.NewReader(zfixture(t, "createrepo-"+name+".xml.zck")), ZchunkReadOptions{})
		if err != nil {
			t.Fatal(err)
		}

		if want := bytes.Count(doc, []byte("\n<package ")) + 1; len(h.Chunks) != want {
			t.Errorf("%s: %d chunks, want a header and %d packages", name, len(h.Chunks), want-1)
		}

		ends := map[int64]bool{}

		var at int64
		for _, s := range chunkSizes(h) {
			at += s
			ends[at] = true
		}

		at = 0

		for _, s := range chunkSizes(ref) {
			if at += s; !ends[at] {
				t.Errorf("%s: createrepo_c cuts at %d, we do not", name, at)
			}
		}

		if got, _ := readZchunk(t, file, ZchunkReadOptions{}); !bytes.Equal(got, doc) {
			t.Errorf("%s: round trip differs", name)
		}

		// The first chunk is the document header, as in createrepo_c.
		if h.Chunks[0].Size != ref.Chunks[0].Size {
			t.Errorf("%s: header chunk %d bytes, createrepo_c %d", name, h.Chunks[0].Size, ref.Chunks[0].Size)
		}
	}
}

func TestZchunkWriterRoundTrip(t *testing.T) {
	doc := goldenXML(t, "other")
	dict := zfixture(t, "primary.zdict")

	for name, opts := range map[string]ZchunkOptions{
		"default":          {},
		"manual":           {Chunking: ZchunkManual, MaxChunkSize: 10000},
		"packages":         {Chunking: ZchunkXMLPackages},
		"sha256":           {ChunkChecksum: ZchunkSHA256},
		"sha512":           {ChunkChecksum: ZchunkSHA512},
		"level 1":          {Level: 1},
		"level 19":         {Level: 19, Chunking: ZchunkXMLPackages},
		"uncompressed":     {Compression: ZchunkNone},
		"dictionary":       {Dictionary: dict, Chunking: ZchunkXMLPackages},
		"dictionary sha":   {Dictionary: dict, ChunkChecksum: ZchunkSHA256},
		"small chunks":     {MaxChunkSize: 9000, MinChunkSize: 100},
		"packages small":   {Chunking: ZchunkXMLPackages, MaxChunkSize: 1500},
		"tiny max":         {Chunking: ZchunkContentDefined, MaxChunkSize: 100},
		"packages one max": {Chunking: ZchunkXMLPackages, MaxChunkSize: 1},
	} {
		t.Run(name, func(t *testing.T) {
			file, h := writeZchunk(t, doc, opts)

			got, rh := readZchunk(t, file, ZchunkReadOptions{})
			if !bytes.Equal(got, doc) {
				t.Fatal("round trip differs")
			}

			if h.FileSize() != int64(len(file)) || h.UncompressedSize() != int64(len(doc)) {
				t.Errorf("header says %d bytes of file and %d of content, have %d and %d", h.FileSize(), h.UncompressedSize(), len(file), len(doc))
			}

			if h.HasDict() != (len(opts.Dictionary) > 0) || h.Dict.Size != int64(len(opts.Dictionary)) {
				t.Errorf("dictionary: %+v", h.Dict)
			}

			if !bytes.Equal(h.Checksum, rh.Checksum) || h.Size != rh.Size || len(h.Chunks) != len(rh.Chunks) {
				t.Errorf("the header of the writer is not the header of the reader")
			}

			// Chunks are contiguous, in order, after the header and dictionary.
			at := h.Size + h.Dict.CompressedSize
			for i, c := range h.Chunks {
				if c.Index != i+1 || c.Offset != at || c.Size <= 0 {
					t.Fatalf("chunk %d: %+v at %d", i, c, at)
				}

				if opts.MaxChunkSize > 0 && c.Size > int64(opts.MaxChunkSize) {
					t.Errorf("chunk %d of %d bytes, max %d", i, c.Size, opts.MaxChunkSize)
				}

				at = c.End()
			}

			if at != int64(len(file)) {
				t.Errorf("chunks end at %d of %d", at, len(file))
			}

			wantType := opts.ChunkChecksum
			if h.ChunkChecksumType != wantType || (opts.Compression == ZchunkNone) != (h.Compression == ZchunkNone) {
				t.Errorf("checksum %v compression %v", h.ChunkChecksumType, h.Compression)
			}
		})
	}
}

func TestZchunkWriterEmptyDocument(t *testing.T) {
	file, h := writeZchunk(t, nil, ZchunkOptions{})
	if len(h.Chunks) != 0 {
		t.Errorf("%d chunks", len(h.Chunks))
	}

	if got, _ := readZchunk(t, file, ZchunkReadOptions{}); len(got) != 0 {
		t.Errorf("read %d bytes", len(got))
	}
}

func TestZchunkWriterEndChunk(t *testing.T) {
	var buf bytes.Buffer

	zw, err := NewZchunkWriter(&buf, ZchunkOptions{Chunking: ZchunkManual, MinChunkSize: 3, MaxChunkSize: 10})
	if err != nil {
		t.Fatal(err)
	}

	write := func(s string) {
		t.Helper()

		if _, err := zw.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	end := func() {
		t.Helper()

		if err := zw.EndChunk(); err != nil {
			t.Fatal(err)
		}
	}

	write("ab")
	end() // under the minimum: refused, "ab" stays in the chunk
	write("cdef")
	end()                       // "abcdef"
	write("0123456789ABCDEFGH") // 10 + 8 pending
	end()                       // "ABCDEFGH"
	end()                       // nothing pending
	write("xyz")

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	got, h := readZchunk(t, buf.Bytes(), ZchunkReadOptions{})
	if string(got) != "abcdef0123456789ABCDEFGHxyz" {
		t.Errorf("content %q", got)
	}

	if sizes := chunkSizes(h); !slices.Equal(sizes, []int64{6, 10, 8, 3}) {
		t.Errorf("chunk sizes %v", sizes)
	}
}

func TestZchunkWriterPackageChunking(t *testing.T) {
	doc := "<?xml?>\n<metadata packages=\"3\">\n" +
		"<package type=\"rpm\">a</package>\n" +
		"<packages>not a package</packages>\n" + // a longer name is not a package
		"<package>b</package>\n" +
		"  <package>indented is not at line start</package>\n" +
		"<package type=\"rpm\">c</package>\n</metadata>"

	for _, piece := range []int{len(doc), 1, 2, 3, 9, 10, 11, 20} {
		var buf bytes.Buffer

		zw, err := NewZchunkWriter(&buf, ZchunkOptions{Chunking: ZchunkXMLPackages})
		if err != nil {
			t.Fatal(err)
		}

		for rest := []byte(doc); len(rest) > 0; rest = rest[min(piece, len(rest)):] {
			if _, err := zw.Write(rest[:min(piece, len(rest))]); err != nil {
				t.Fatal(err)
			}
		}

		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}

		got, h := readZchunk(t, buf.Bytes(), ZchunkReadOptions{})
		if string(got) != doc {
			t.Fatalf("writes of %d: content %q", piece, got)
		}

		var starts []string

		var at int64

		for _, c := range h.Chunks {
			starts = append(starts, doc[at:min(at+10, int64(len(doc)))])
			at += c.Size
		}

		// The <packages> and indented lines stay in the chunk before them.
		want := []string{"<?xml?>\n<m", "<package t", "<package>b", "<package t"}
		if !slices.Equal(starts, want) {
			t.Errorf("writes of %d: chunks start with %q, want %q", piece, starts, want)
		}
	}
}

func TestZchunkWriterOptions(t *testing.T) {
	for name, o := range map[string]ZchunkOptions{
		"min over max":       {MinChunkSize: 10, MaxChunkSize: 5},
		"level too low":      {Level: -1},
		"level too high":     {Level: 23},
		"sha1 chunks":        {ChunkChecksum: ZchunkSHA1},
		"unknown checksum":   {ChunkChecksum: 9},
		"negative checksum":  {ChunkChecksum: -1},
		"dictionary none":    {Compression: ZchunkNone, Dictionary: []byte("x")},
		"unknown chunking":   {Chunking: 9},
		"unknown compress":   {Compression: 9},
		"dictionary garbage": {Dictionary: []byte("not a zstd dictionary at all")},
	} {
		if _, err := NewZchunkWriter(io.Discard, o); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

type failWriter struct{ left int }

func (f *failWriter) Write(p []byte) (int, error) {
	if len(p) > f.left {
		return 0, errors.New("disk full")
	}

	f.left -= len(p)

	return len(p), nil
}

func TestZchunkWriterLifecycle(t *testing.T) {
	zw, err := NewZchunkWriter(io.Discard, ZchunkOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if zw.Header() != nil {
		t.Error("header before Close")
	}

	if _, err := zw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}

	if _, err := zw.Write([]byte("y")); !errors.Is(err, ErrZchunkClosed) {
		t.Errorf("Write after Close: %v", err)
	}

	if err := zw.EndChunk(); !errors.Is(err, ErrZchunkClosed) {
		t.Errorf("EndChunk after Close: %v", err)
	}

	for _, left := range []int{0, 100} {
		zw, err := NewZchunkWriter(&failWriter{left: left}, ZchunkOptions{})
		if err != nil {
			t.Fatal(err)
		}

		_, _ = zw.Write([]byte("hello"))

		if err := zw.Close(); err == nil || !strings.Contains(err.Error(), "disk full") {
			t.Errorf("failing destination (%d): %v", left, err)
		}
	}
}

func TestZchunkContentSplitterBounds(t *testing.T) {
	doc := goldenXML(t, "filelists")
	file, h := writeZchunk(t, doc, ZchunkOptions{})

	if got, _ := readZchunk(t, file, ZchunkReadOptions{}); !bytes.Equal(got, doc) {
		t.Fatal("round trip differs")
	}

	for i, c := range h.Chunks {
		if c.Size > zchunkAutoMax || (c.Size < zchunkAutoMin && i < len(h.Chunks)-1) {
			t.Errorf("chunk %d is %d bytes, outside %d..%d", i, c.Size, zchunkAutoMin, zchunkAutoMax)
		}
	}

	// Constant data never matches the hash: chunks end at the maximum.
	_, h = writeZchunk(t, bytes.Repeat([]byte{'a'}, 3*zchunkAutoMax+5), ZchunkOptions{})
	if got := chunkSizes(h); !slices.Equal(got, []int64{zchunkAutoMax, zchunkAutoMax, zchunkAutoMax, 5}) && len(got) < 4 {
		t.Errorf("constant data chunked as %v", got)
	}
}

// A chunk checksum or size changed after the fact is caught, wherever it is.
func TestZchunkReaderDetectsDamage(t *testing.T) {
	file := zfixture(t, "createrepo-other.xml.zck")

	h, err := ReadZchunkHeader(bytes.NewReader(file), ZchunkReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	flip := func(at int64) []byte {
		b := bytes.Clone(file)
		b[at] ^= 0x40

		return b
	}

	cases := map[string]struct {
		data []byte
		want error
	}{
		"magic":           {flip(1), ErrZchunkFormat},
		"header checksum": {flip(9), ErrZchunkChecksum},
		"header body":     {flip(h.Size - 3), ErrZchunkChecksum},
		"chunk data":      {flip(h.Chunks[2].Offset + 3), ErrZchunkChecksum},
		"last chunk":      {flip(int64(len(file)) - 1), ErrZchunkChecksum},
		"trailing data":   {append(bytes.Clone(file), 0), ErrZchunkFormat},
		"truncated":       {file[:len(file)-1], ErrZchunkFormat},
		"no chunks":       {file[:h.Size], ErrZchunkFormat},
		"empty":           {nil, ErrZchunkFormat},
		"short lead":      {file[:6], ErrZchunkFormat},
	}

	for name, tc := range cases {
		zr, err := NewZchunkReader(bytes.NewReader(tc.data), ZchunkReadOptions{})
		if err == nil {
			_, err = io.Copy(io.Discard, zr)
		}

		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

// No prefix of a file panics or reads as a whole file.
func TestZchunkReaderTruncations(t *testing.T) {
	file, _ := writeZchunk(t, goldenXML(t, "other")[:6000], ZchunkOptions{Chunking: ZchunkXMLPackages, Dictionary: zfixture(t, "primary.zdict")})

	for n := range len(file) {
		zr, err := NewZchunkReader(bytes.NewReader(file[:n]), ZchunkReadOptions{})
		if err != nil {
			continue
		}

		if _, err := io.Copy(io.Discard, zr); err == nil {
			t.Fatalf("prefix of %d bytes of %d reads without error", n, len(file))
		}
	}
}

func TestZchunkReaderLimits(t *testing.T) {
	file := zfixture(t, "createrepo-primary.xml.zck")
	_, h := readZchunk(t, file, ZchunkReadOptions{})

	for name, o := range map[string]ZchunkReadOptions{
		"header": {MaxHeaderSize: h.Size - 1},
		"chunk":  {MaxChunkSize: 50000},
		"total":  {MaxSize: h.UncompressedSize() - 1},
	} {
		if _, err := NewZchunkReader(bytes.NewReader(file), o); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", name, err)
		}

		if _, err := ReadZchunkHeader(bytes.NewReader(file), o); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s header: %v", name, err)
		}
	}

	// A bound the file is within.
	if _, err := NewZchunkReader(bytes.NewReader(file), ZchunkReadOptions{MaxSize: h.UncompressedSize()}); err != nil {
		t.Errorf("exact bound: %v", err)
	}

	// A chunk that decompresses beyond what the index declared cannot bypass
	// the chunk bound: the decoder stops at the limit.
	big := bytes.Repeat([]byte("a"), 200000)

	zfile, zh := writeZchunk(t, big, ZchunkOptions{Chunking: ZchunkManual})
	if len(zh.Chunks) != 1 {
		t.Fatalf("%d chunks", len(zh.Chunks))
	}

	dec, err := NewZchunkDecoder(zh, nil, ZchunkReadOptions{MaxChunkSize: 1000})
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	c := zh.Chunks[0]
	c.Size = 10 // a lying index

	if _, err := dec.Decode(c, zfile[c.Offset:c.End()]); !errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrZchunkFormat) {
		t.Errorf("bomb: %v", err)
	}
}

// rawHeader assembles a header by hand, checksum included, so that the
// readers can be shown files no writer here produces.
type rawHeader struct {
	leadType  uint64 // header checksum type, SHA-256 (1) by default
	sha1      bool   // header checksum type SHA-1 (0) with 20-byte digests
	flags     uint64
	comp      uint64
	optional  []byte // encoded optional elements, after the flags
	chunkType uint64
	count     uint64   // chunk count; len(entries) when 0
	entries   [][]byte // encoded index entries
	trailing  []byte   // after the entries, still in the index
	sigs      []byte   // encoded signatures; one zero byte when nil
	detached  bool
	digests   int // digest size of the header checksum type, 32 by default
}

func (r rawHeader) bytes() []byte {
	if r.digests == 0 {
		r.digests = 32
	}

	if r.sha1 {
		r.leadType, r.digests = 0, 20
	}

	if r.chunkType == 0 {
		r.chunkType = 1
	}

	if r.leadType == 0 && !r.sha1 {
		r.leadType = 1
	}

	if r.count == 0 {
		r.count = uint64(len(r.entries))
	}

	index := appendCompint(nil, r.chunkType)
	index = appendCompint(index, r.count)

	for _, e := range r.entries {
		index = append(index, e...)
	}

	index = append(index, r.trailing...)

	body := make([]byte, r.digests) // data checksum
	body = appendCompint(body, r.flags)
	body = appendCompint(body, r.comp)
	body = append(body, r.optional...)
	body = appendCompint(body, uint64(len(index)))
	body = append(body, index...)

	if r.sigs == nil {
		r.sigs = appendCompint(nil, 0)
	}

	body = append(body, r.sigs...)

	lead := append([]byte(nil), zchunkMagic...)
	lead = appendCompint(lead, r.leadType)
	lead = appendCompint(lead, uint64(len(body)))

	var sum []byte

	switch r.digests {
	case 20:
		sum = ZchunkSHA1.digest(lead, body)
	default:
		sum = ZchunkSHA256.digest(lead, body)
	}

	out := append(lead, sum...)
	out = append(out, body...)

	if r.detached {
		copy(out, zchunkDetachedMagic)
	}

	return out
}

// entry is an index entry of the given digest size.
func entry(digest int, comp, size uint64) []byte {
	e := bytes.Repeat([]byte{7}, digest)
	e = appendCompint(e, comp)

	return appendCompint(e, size)
}

func TestZchunkHeaderParsing(t *testing.T) {
	dictEntry := entry(32, 0, 0)

	// The shape of a valid header that every case below spoils in one place.
	valid := rawHeader{comp: 2, chunkType: 1, entries: [][]byte{dictEntry, entry(32, 10, 20)}}

	if h, err := ReadZchunkHeader(bytes.NewReader(valid.bytes()), ZchunkReadOptions{}); err != nil || len(h.Chunks) != 1 || h.Chunks[0].Size != 20 {
		t.Fatalf("valid header: %v %+v", err, h)
	}

	with := func(f func(*rawHeader)) rawHeader {
		r := valid
		r.entries = slices.Clone(valid.entries)
		f(&r)

		return r
	}

	good := map[string]rawHeader{
		"optional elements": with(func(r *rawHeader) {
			r.flags = flagOptional
			// Two elements: id 9 with "abc", and id 1 with nothing.
			r.optional = appendCompint(nil, 2)
			r.optional = appendCompint(appendCompint(r.optional, 9), 3)
			r.optional = append(r.optional, 'a', 'b', 'c')
			r.optional = appendCompint(appendCompint(r.optional, 1), 0)
		}),
		"detached": with(func(r *rawHeader) { r.detached = true }),
		"no compression": with(func(r *rawHeader) {
			r.comp = 0
			r.entries = [][]byte{dictEntry, entry(32, 20, 20)}
		}),
		"sha1 header": with(func(r *rawHeader) {
			r.sha1 = true
		}),
		"sha512 chunks": with(func(r *rawHeader) {
			r.chunkType = 2
			r.entries = [][]byte{entry(64, 0, 0), entry(64, 10, 20)}
		}),
		"uncompressed source": with(func(r *rawHeader) {
			r.flags = flagUncompressed
			r.entries = [][]byte{append(dictEntry[:32:32], entry(32, 0, 0)...), append(entry(32, 10, 20)[:32:32], entry(32, 10, 20)...)}
		}),
		"padded integers": with(func(r *rawHeader) {
			r.entries = [][]byte{dictEntry, append(bytes.Repeat([]byte{7}, 32), 0x0a, 0x80, 0x14, 0x80)}
		}),
	}

	for name, r := range good {
		h, err := ReadZchunkHeader(bytes.NewReader(r.bytes()), ZchunkReadOptions{})
		if err != nil {
			t.Errorf("%s: %v", name, err)

			continue
		}

		if name == "optional elements" && len(h.Chunks) != 1 {
			t.Errorf("%s: %+v", name, h)
		}
	}

	bad := map[string]struct {
		r    rawHeader
		want error
	}{
		"streams":                 {with(func(r *rawHeader) { r.flags = flagStreams }), ErrZchunkUnsupported},
		"unknown flag":            {with(func(r *rawHeader) { r.flags = 8 }), ErrZchunkUnsupported},
		"unknown compression":     {with(func(r *rawHeader) { r.comp = 1 }), ErrZchunkUnsupported},
		"unknown chunk checksum":  {with(func(r *rawHeader) { r.chunkType = 4 }), ErrZchunkUnsupported},
		"header checksum sha512":  {with(func(r *rawHeader) { r.leadType = 2 }), ErrZchunkUnsupported},
		"header checksum unknown": {with(func(r *rawHeader) { r.leadType = 77 }), ErrZchunkUnsupported},
		"no dictionary entry":     {with(func(r *rawHeader) { r.entries = nil; r.count = 0 }), ErrZchunkFormat},
		"count over entries":      {with(func(r *rawHeader) { r.count = 3 }), ErrZchunkFormat},
		"count over index":        {with(func(r *rawHeader) { r.count = 1 << 40 }), ErrZchunkFormat},
		"count under entries":     {with(func(r *rawHeader) { r.count = 1 }), ErrZchunkFormat},
		"entry cut":               {with(func(r *rawHeader) { r.entries = [][]byte{dictEntry, entry(32, 10, 20)[:33]} }), ErrZchunkFormat},
		"unused bytes":            {with(func(r *rawHeader) { r.trailing = []byte{1, 2} }), ErrZchunkFormat},
		"dictionary size only":    {with(func(r *rawHeader) { r.entries[0] = entry(32, 0, 5) }), ErrZchunkFormat},
		"dictionary data only":    {with(func(r *rawHeader) { r.entries[0] = entry(32, 5, 0) }), ErrZchunkFormat},
		"dictionary uncompressed": {with(func(r *rawHeader) {
			r.comp = 0
			r.entries[0] = entry(32, 5, 5)
		}), ErrZchunkFormat},
		"huge chunk":            {with(func(r *rawHeader) { r.entries[1] = entry(32, 10, 1<<40) }), ErrTooLarge},
		"huge compressed chunk": {with(func(r *rawHeader) { r.entries[1] = entry(32, 1<<40, 20) }), ErrTooLarge},
		"signature past end": {with(func(r *rawHeader) {
			r.sigs = appendCompint(appendCompint(appendCompint(nil, 1), 1), 50)
		}), ErrZchunkFormat},
		"optional past end": {with(func(r *rawHeader) {
			r.flags = flagOptional
			r.optional = appendCompint(appendCompint(appendCompint(nil, 1), 1), 500)
		}), ErrZchunkFormat},
		"optional count lies": {with(func(r *rawHeader) {
			r.flags = flagOptional
			r.optional = appendCompint(nil, 5)
		}), ErrZchunkFormat},
	}

	for name, tc := range bad {
		_, err := ReadZchunkHeader(bytes.NewReader(tc.r.bytes()), ZchunkReadOptions{})
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	// Signatures are returned, not verified.
	signed := with(func(r *rawHeader) {
		r.sigs = append(appendCompint(appendCompint(appendCompint(nil, 1), 42), 3), 's', 'i', 'g')
	})

	h, err := ReadZchunkHeader(bytes.NewReader(signed.bytes()), ZchunkReadOptions{})
	if err != nil || len(h.Signatures) != 1 || h.Signatures[0].Type != 42 || string(h.Signatures[0].Data) != "sig" {
		t.Errorf("signatures: %v %+v", err, h)
	}

	// A header of the right shape whose size is lied about.
	b := valid.bytes()
	b = append(b[:len(b):len(b)], 0)

	if _, err := ReadZchunkHeader(bytes.NewReader(b), ZchunkReadOptions{}); err != nil {
		t.Errorf("bytes after the header are not part of it: %v", err)
	}
}

// A file made to be applied against an uncompressed source stores the chunks
// it has no checksum for as they are, and has no data checksum.
func TestZchunkUncompressedSourceStoredChunk(t *testing.T) {
	content := []byte("stored chunk")
	hdr := rawHeader{
		flags:     flagUncompressed,
		comp:      2,
		chunkType: 1,
		entries: [][]byte{
			append(bytes.Repeat([]byte{0}, 32), entry(32, 0, 0)...),
			// A zero checksum marks the chunk as stored uncompressed.
			append(bytes.Repeat([]byte{0}, 32), append(ZchunkSHA256.digest(content), appendCompint(appendCompint(nil, uint64(len(content))), uint64(len(content)))...)...),
		},
	}

	file := append(hdr.bytes(), content...)

	got, h := readZchunk(t, file, ZchunkReadOptions{})
	if !bytes.Equal(got, content) || !h.UncompressedSource {
		t.Errorf("got %q, header %+v", got, h)
	}
}

func TestZchunkDecoderErrors(t *testing.T) {
	file := zfixture(t, "zck-primary-dict.zck")

	h, err := ReadZchunkHeader(bytes.NewReader(file), ZchunkReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewZchunkDecoder(h, nil, ZchunkReadOptions{}); err == nil {
		t.Error("a dictionary file without its dictionary")
	}

	if _, err := NewZchunkDecoder(h, file[h.Dict.Offset:h.Dict.End()-1], ZchunkReadOptions{}); err == nil {
		t.Error("a truncated dictionary")
	}

	dict := bytes.Clone(file[h.Dict.Offset:h.Dict.End()])
	dict[len(dict)/2] ^= 1

	if _, err := NewZchunkDecoder(h, dict, ZchunkReadOptions{}); !errors.Is(err, ErrZchunkChecksum) {
		t.Errorf("a damaged dictionary: %v", err)
	}

	dec, err := NewZchunkDecoder(h, file[h.Dict.Offset:h.Dict.End()], ZchunkReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	c := h.Chunks[0]
	data := file[c.Offset:c.End()]

	if _, err := dec.Decode(c, data[:len(data)-1]); !errors.Is(err, ErrZchunkFormat) {
		t.Errorf("short chunk: %v", err)
	}

	lie := c
	lie.Size++

	if _, err := dec.Decode(lie, data); !errors.Is(err, ErrZchunkFormat) {
		t.Errorf("wrong size: %v", err)
	}

	out, err := dec.Decode(c, data)
	if err != nil || int64(len(out)) != c.Size || !bytes.HasPrefix(out, []byte("<?xml")) {
		t.Errorf("chunk 1: %d bytes, %v", len(out), err)
	}
}

// A client holding the previous primary needs only the chunks that changed:
// the same ones and the same bytes zck_delta_size reports, and the new document
// is rebuilt from the old file and the missing ranges alone.
func TestZchunkDelta(t *testing.T) {
	oldFile := zfixture(t, "createrepo-primary-old.xml.zck")
	newFile := zfixture(t, "createrepo-primary.xml.zck")

	oldH, err := ReadZchunkHeader(bytes.NewReader(oldFile), ZchunkReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	newH, err := ReadZchunkHeader(bytes.NewReader(newFile), ZchunkReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	missing := newH.MissingChunks(oldH)
	if len(missing) != 10 {
		t.Fatalf("%d chunks missing, want 10", len(missing))
	}

	if all := newH.MissingChunks(nil); len(all) != len(newH.Chunks) {
		t.Errorf("nothing held, %d of %d chunks missing", len(all), len(newH.Chunks))
	}

	if none := newH.MissingChunks(newH); len(none) != 0 {
		t.Errorf("everything held, %d chunks missing", len(none))
	}

	var download int64

	for _, r := range ByteRanges(missing) {
		download += r.Length
	}

	if tool, err := exec.LookPath("zck_delta_size"); err == nil {
		out := run(t, tool, filepath.Join("testdata", "zchunk", "createrepo-primary-old.xml.zck"), filepath.Join("testdata", "zchunk", "createrepo-primary.xml.zck"))
		want := fmt.Sprintf("Would download in total %d of %d bytes", download+newH.Size, len(newFile))

		if !strings.Contains(out, want) || !strings.Contains(out, fmt.Sprintf("the rest in %d chunks", len(missing))) {
			t.Errorf("zck_delta_size says %q, we need %s in %d chunks", out, want, len(missing))
		}
	}

	// Rebuild the new document from the old file and the missing ranges.
	have := map[string][]byte{}
	for _, c := range oldH.Chunks {
		have[string(c.Checksum)] = oldFile[c.Offset:c.End()]
	}

	for _, c := range missing {
		have[string(c.Checksum)] = newFile[c.Offset:c.End()]
	}

	dec, err := NewZchunkDecoder(newH, nil, ZchunkReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	var rebuilt []byte

	for _, c := range newH.Chunks {
		out, err := dec.Decode(c, have[string(c.Checksum)])
		if err != nil {
			t.Fatal(err)
		}

		rebuilt = append(rebuilt, out...)
	}

	if want, _ := readZchunk(t, newFile, ZchunkReadOptions{}); !bytes.Equal(rebuilt, want) {
		t.Error("the rebuilt document differs from the new one")
	}

	// Different compression or dictionary: nothing carries over.
	dictH, _ := ReadZchunkHeader(bytes.NewReader(zfixture(t, "zck-primary-dict.zck")), ZchunkReadOptions{})
	if got := dictH.MissingChunks(newH); len(got) != len(dictH.Chunks) {
		t.Errorf("across dictionaries %d of %d chunks missing", len(got), len(dictH.Chunks))
	}
}

func TestZchunkByteRanges(t *testing.T) {
	chunks := []ZchunkChunk{
		{Offset: 100, CompressedSize: 10},
		{Offset: 110, CompressedSize: 5},
		{Offset: 200, CompressedSize: 7},
		{Offset: 207, CompressedSize: 0},
		{Offset: 207, CompressedSize: 3},
		{Offset: 50, CompressedSize: 1},
	}

	got := ByteRanges(chunks)
	want := []ZchunkRange{{100, 15}, {200, 10}, {50, 1}}

	if !slices.Equal(got, want) {
		t.Errorf("ranges %v, want %v", got, want)
	}

	if s := got[0].String(); s != "bytes=100-114" {
		t.Errorf("range header %q", s)
	}

	if len(ByteRanges(nil)) != 0 {
		t.Error("ranges of nothing")
	}
}

func TestCompressMetadataStreamZchunk(t *testing.T) {
	doc := goldenXML(t, "primary")

	cm, err := CompressMetadataStream(Zchunk, func(w io.Writer) error {
		_, err := w.Write(doc)

		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	if Zchunk.Extension() != ".zck" || Zchunk.String() != "zchunk" {
		t.Errorf("%q %q", Zchunk.Extension(), Zchunk)
	}

	h, err := ReadZchunkHeader(bytes.NewReader(cm.Data), ZchunkReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if cm.HeaderSHA256 != h.HexChecksum() || cm.HeaderSize != h.Size || h.ChecksumType != ZchunkSHA256 {
		t.Errorf("header %s/%d, file says %s/%d", cm.HeaderSHA256, cm.HeaderSize, h.HexChecksum(), h.Size)
	}

	if cm.Size != int64(len(cm.Data)) || cm.SHA256 != sha256Hex(cm.Data) || cm.OpenSize != int64(len(doc)) || cm.OpenSHA256 != sha256Hex(doc) {
		t.Errorf("sizes and checksums: %+v", cm)
	}

	// The same chunks createrepo_c makes (one per package, header apart).
	if want := bytes.Count(doc, []byte("\n<package ")) + 1; len(h.Chunks) != want {
		t.Errorf("%d chunks, want %d", len(h.Chunks), want)
	}

	for _, size := range []int64{0, int64(len(doc))} {
		rc, err := OpenMetadata(io.NopCloser(bytes.NewReader(cm.Data)), "primary.xml.zck", size)
		if err != nil {
			t.Fatal(err)
		}

		got, err := io.ReadAll(rc)
		if err != nil || !bytes.Equal(got, doc) {
			t.Errorf("OpenMetadata(%d): %d bytes, %v", size, len(got), err)
		}

		if err := rc.Close(); err != nil {
			t.Error(err)
		}
	}

	if _, err := OpenMetadata(io.NopCloser(bytes.NewReader(cm.Data)), "primary.xml.zck", int64(len(doc))-1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("OpenMetadata over the bound: %v", err)
	}

	if _, err := OpenMetadata(io.NopCloser(strings.NewReader("not a zchunk")), "primary.xml.zck", 0); !errors.Is(err, ErrZchunkFormat) {
		t.Errorf("OpenMetadata of garbage: %v", err)
	}

	// repomd.xml carries the header-checksum and header-size, and they
	// survive a write and a parse.
	entry := cm.Entry("primary_zck", "primary.xml.zck", 1700000000)
	if entry.HeaderChecksum != h.HexChecksum() || entry.HeaderChecksumType != "sha256" || entry.HeaderSize != h.Size {
		t.Fatalf("entry %+v", entry)
	}

	xml, err := GenerateRepomdXML("1", []RepomdData{entry})
	if err != nil {
		t.Fatal(err)
	}

	index, err := ParseRepomd(bytes.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}

	if got, ok := index.Find("primary_zck"); !ok || got.HeaderChecksum != entry.HeaderChecksum || got.HeaderSize != entry.HeaderSize {
		t.Errorf("parsed entry %+v", got)
	}
}

func TestCompressMetadataStreamZchunkDocWriter(t *testing.T) {
	pkgs := []rpm.Package{
		{Name: "a", Version: "1", Release: "1", Arch: "noarch", SHA256: "aa"},
		{Name: "b", Version: "2", Release: "1", Arch: "noarch", SHA256: "bb"},
		{Name: "c", Version: "3", Release: "1", Arch: "x86_64", SHA256: "cc"},
	}

	cm, err := CompressMetadataStream(Zchunk, func(w io.Writer) error { return WritePrimaryXML(w, pkgs) })
	if err != nil {
		t.Fatal(err)
	}

	got, h := readZchunk(t, cm.Data, ZchunkReadOptions{})

	want, err := renderXML(WritePrimaryXML, pkgs)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) || len(h.Chunks) != 4 {
		t.Errorf("%d chunks, content equal %v", len(h.Chunks), bytes.Equal(got, want))
	}

	if _, err := CompressMetadataStream(Zchunk, func(io.Writer) error { return nil }); !errors.Is(err, ErrEmptyDocument) {
		t.Errorf("empty document: %v", err)
	}

	if _, err := CompressMetadataStream(Zchunk, func(io.Writer) error { return errors.New("boom") }); err == nil {
		t.Error("a failing generator succeeded")
	}
}

func needTool(t testing.TB, name string) string {
	t.Helper()

	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed", name)
	}

	return path
}

func run(t testing.TB, tool string, args ...string) string {
	t.Helper()

	var stdout, stderr bytes.Buffer

	cmd := exec.Command(tool, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v: %v\n%s", filepath.Base(tool), args, err, stderr.String())
	}

	return stdout.String()
}

// The files this package writes are accepted by the reference tools, which
// verify every checksum (zck_read_header -f) and decode to the same document
// (unzck).
func TestZchunkWriterAcceptedByReferenceTools(t *testing.T) {
	verify := needTool(t, "zck_read_header")
	unzck := needTool(t, "unzck")

	dir := t.TempDir()
	dict := zfixture(t, "primary.zdict")

	for name, tc := range map[string]struct {
		doc  string
		opts ZchunkOptions
	}{
		"auto":         {"filelists", ZchunkOptions{}},
		"packages":     {"primary", ZchunkOptions{Chunking: ZchunkXMLPackages}},
		"manual":       {"other", ZchunkOptions{Chunking: ZchunkManual, MaxChunkSize: 20000}},
		"sha256":       {"other", ZchunkOptions{ChunkChecksum: ZchunkSHA256}},
		"sha512":       {"other", ZchunkOptions{ChunkChecksum: ZchunkSHA512}},
		"uncompressed": {"other", ZchunkOptions{Compression: ZchunkNone}},
		"dictionary":   {"primary", ZchunkOptions{Dictionary: dict, Chunking: ZchunkXMLPackages}},
		"level 3":      {"primary", ZchunkOptions{Level: 3}},
	} {
		t.Run(name, func(t *testing.T) {
			doc := goldenXML(t, tc.doc)
			file, h := writeZchunk(t, doc, tc.opts)
			path := filepath.Join(dir, name+".zck")

			if err := os.WriteFile(path, file, 0o600); err != nil {
				t.Fatal(err)
			}

			run(t, verify, "-f", "-q", path)

			if got := run(t, unzck, "-c", path); got != string(doc) {
				t.Error("unzck decodes a different document")
			}

			out := run(t, verify, path)
			if !strings.Contains(out, "Header checksum: "+h.HexChecksum()+"\n") ||
				!strings.Contains(out, "Header size: "+strconv.FormatInt(h.Size, 10)+"\n") ||
				!strings.Contains(out, "Chunk count: "+strconv.Itoa(len(h.Chunks)+1)+"\n") {
				t.Errorf("zck_read_header:\n%s\nheader %s %d, %d chunks", out, h.HexChecksum(), h.Size, len(h.Chunks))
			}
		})
	}
}

// What the tool decodes of a damaged file is refused here too: the two agree
// on which files are valid.
func TestZchunkReaderAgreesWithReferenceToolOnDamage(t *testing.T) {
	verify := needTool(t, "zck_read_header")

	file, h := writeZchunk(t, goldenXML(t, "other")[:20000], ZchunkOptions{Chunking: ZchunkXMLPackages})
	dir := t.TempDir()

	for i, at := range []int64{3, 9, h.Size - 2, h.Size + 5, h.Chunks[1].Offset + 4, int64(len(file)) - 1} {
		b := bytes.Clone(file)
		b[at] ^= 0x20

		path := filepath.Join(dir, "damaged"+strconv.Itoa(i)+".zck")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}

		toolOK := exec.Command(verify, "-f", "-q", path).Run() == nil

		zr, err := NewZchunkReader(bytes.NewReader(b), ZchunkReadOptions{})
		if err == nil {
			_, err = io.Copy(io.Discard, zr)
		}

		if toolOK || err == nil {
			t.Errorf("byte %d flipped: tool accepts %v, reader error %v", at, toolOK, err)
		}
	}
}

// A file from a real repository: the comps of the Fedora 43 Server tree as
// createrepo_c wrote it, with the repomd.xml that lists it. The header size,
// header checksum and file checksum of the entry are those of the file, and the
// document is the one the same repository serves zstd-compressed as "group".
func TestZchunkReadsFedoraFile(t *testing.T) {
	file := zfixture(t, "fedora43-server-comps.xml.zck")

	rm, err := os.Open(filepath.Join("testdata", "zchunk", "fedora43-server-repomd.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer rm.Close()

	repomd, err := ParseRepomd(rm)
	if err != nil {
		t.Fatal(err)
	}

	entry, ok := repomd.Find("group_zck")
	if !ok {
		t.Fatal("no group_zck entry")
	}

	got, h := readZchunk(t, file, ZchunkReadOptions{})

	if h.Size != entry.HeaderSize || h.HexChecksum() != entry.HeaderChecksum || int64(len(file)) != entry.Size || sha256Hex(file) != entry.Checksum {
		t.Errorf("header %d %s, file %d %s; repomd says %d %s, %d %s", h.Size, h.HexChecksum(), len(file), sha256Hex(file),
			entry.HeaderSize, entry.HeaderChecksum, entry.Size, entry.Checksum)
	}

	// The checksum of the "group" entry's zstd file, which holds the same XML
	// (the repomd open-checksum of group_zck repeats the one of that file, not
	// of the XML).
	if sum := sha256Hex(got); sum != "17c6cb2f3701ff305ed0194985f07a2a664d2b0cf2478f161e6dffffb0d994b8" || !bytes.HasPrefix(got, []byte("<?xml")) {
		t.Errorf("document %s", sum)
	}

	if len(h.Chunks) != 3 || h.ChunkChecksumType != ZchunkSHA512_128 || h.HasDict() {
		t.Errorf("%d chunks, %v", len(h.Chunks), h.ChunkChecksumType)
	}

	// The chunker cuts the document where createrepo_c did.
	_, mine := writeZchunk(t, got, ZchunkOptions{})
	if !slices.Equal(chunkSizes(mine), chunkSizes(h)) {
		t.Errorf("chunks %v, Fedora's %v", chunkSizes(mine), chunkSizes(h))
	}
}
