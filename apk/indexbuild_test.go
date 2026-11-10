package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

// gzMember is one gzip member of an archive, taken apart without using any
// code of this package.
type gzMember struct {
	compressed []byte
	raw        []byte
	header     gzip.Header
}

func splitMembers(t *testing.T, data []byte) []gzMember {
	t.Helper()

	rd := bytes.NewReader(data) // a ByteReader: the gzip reader stops at the member's end

	zr, err := gzip.NewReader(rd)
	if err != nil {
		t.Fatal(err)
	}

	var members []gzMember

	for start := 0; ; {
		zr.Multistream(false)

		raw, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}

		end := len(data) - rd.Len()
		members = append(members, gzMember{compressed: data[start:end], raw: raw, header: zr.Header})

		if rd.Len() == 0 {
			return members
		}

		start = end

		if err := zr.Reset(rd); err != nil {
			t.Fatal(err)
		}
	}
}

type tarFile struct {
	hdr  tar.Header
	body []byte
}

func readTar(t *testing.T, raw []byte) []tarFile {
	t.Helper()

	var files []tarFile

	tr := tar.NewReader(bytes.NewReader(raw))

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files
		}

		if err != nil {
			t.Fatal(err)
		}

		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}

		files = append(files, tarFile{hdr: *hdr, body: body})
	}
}

func TestBuildIndex_layout(t *testing.T) {
	pkgs := samplePackages()

	data, err := BuildIndex(pkgs, "v3.20.0-test", testSigner(t))
	if err != nil {
		t.Fatal(err)
	}

	members := splitMembers(t, data)
	if len(members) != 2 {
		t.Fatalf("%d gzip members, want a signature and an index", len(members))
	}

	for i, m := range members {
		checkGzipHeader(t, i, m)
	}

	checkSignatureMember(t, members[0], members[1])
	checkIndexMember(t, members[1], pkgs)
}

func checkGzipHeader(t *testing.T, i int, m gzMember) {
	t.Helper()

	if !m.header.ModTime.IsZero() || m.header.Name != "" || m.header.Comment != "" || m.header.OS != 3 {
		t.Errorf("member %d: gzip header %+v, want mtime 0, no name, OS 3", i, m.header)
	}

	if !bytes.Equal(m.compressed[:4], []byte{0x1f, 0x8b, 8, 0}) || !bytes.Equal(m.compressed[4:8], make([]byte, 4)) {
		t.Errorf("member %d: gzip header bytes % x", i, m.compressed[:10])
	}
}

func checkSignatureMember(t *testing.T, sigMember, indexMember gzMember) {
	t.Helper()

	files := readTar(t, sigMember.raw)
	if len(files) != 1 || files[0].hdr.Name != ".SIGN.RSA256.pkgformat-test.rsa.pub" {
		t.Fatalf("signature entries %+v", files)
	}

	// As in the index apk itself publishes, the signature's tar has no
	// end-of-archive blocks: header and the padded signature, nothing else.
	if want := 512 + (len(files[0].body)+511)/512*512; len(sigMember.raw) != want {
		t.Fatalf("signature tar is %d bytes, want %d with no end blocks", len(sigMember.raw), want)
	}

	sum := sha256.Sum256(indexMember.compressed)
	if err := rsa.VerifyPKCS1v15(&testKey(t).PublicKey, crypto.SHA256, sum[:], files[0].body); err != nil {
		t.Fatalf("signature does not cover the bytes of the index member: %v", err)
	}

	checkHeader(t, &files[0].hdr)
}

func checkIndexMember(t *testing.T, indexMember gzMember, pkgs []Package) {
	t.Helper()

	files := readTar(t, indexMember.raw)
	if len(files) != 2 || files[0].hdr.Name != "DESCRIPTION" || files[1].hdr.Name != "APKINDEX" {
		t.Fatalf("index entries %+v", files)
	}

	if string(files[0].body) != "v3.20.0-test" {
		t.Fatalf("DESCRIPTION %q", files[0].body)
	}

	if !bytes.Equal(files[1].body, RenderIndex(pkgs)) {
		t.Fatalf("APKINDEX differs from RenderIndex")
	}

	// The index tar is terminated, again as in the official index.
	if !bytes.HasSuffix(indexMember.raw, make([]byte, 1024)) {
		t.Fatal("index tar has no end-of-archive blocks")
	}

	for i := range files {
		checkHeader(t, &files[i].hdr)
	}
}

func checkHeader(t *testing.T, h *tar.Header) {
	t.Helper()

	if h.Typeflag != tar.TypeReg || h.Mode != 0o644 || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" ||
		h.ModTime.Unix() != 0 || h.Format != tar.FormatUSTAR || len(h.PAXRecords) != 0 {
		t.Errorf("%s: header %+v, want a plain ustar regular file, mode 0644, owner 0, mtime 0", h.Name, *h)
	}
}

func TestBuildIndex_deterministic(t *testing.T) {
	a, err := BuildIndex(samplePackages(), "d", testSigner(t))
	if err != nil {
		t.Fatal(err)
	}

	b, err := BuildIndex(samplePackages(), "d", testSigner(t))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(a, b) {
		t.Fatal("two builds of the same index differ")
	}

	c, err := BuildIndex(samplePackages()[:1], "d", testSigner(t))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(a, c) {
		t.Fatal("different packages gave the same index")
	}
}

func TestBuildIndex_unsigned(t *testing.T) {
	signed, err := BuildIndex(samplePackages(), "d", testSigner(t))
	if err != nil {
		t.Fatal(err)
	}

	unsigned, err := BuildIndex(samplePackages(), "d", nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.HasSuffix(signed, unsigned) || len(signed) == len(unsigned) {
		t.Fatal("the signed index is not the signature member followed by the unsigned index")
	}

	if n := len(splitMembers(t, unsigned)); n != 1 {
		t.Fatalf("%d members", n)
	}
}

func TestBuildIndex_parses(t *testing.T) {
	want := samplePackages()

	for name, signer := range map[string]*Signer{"signed": testSigner(t), "unsigned": nil} {
		t.Run(name, func(t *testing.T) {
			data, err := BuildIndex(want, "d", signer)
			if err != nil {
				t.Fatal(err)
			}

			got, err := ParseIndex(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got  %+v\nwant %+v", got, want)
			}
		})
	}

	t.Run("no packages", func(t *testing.T) {
		data, err := BuildIndex(nil, "", testSigner(t))
		if err != nil {
			t.Fatal(err)
		}

		got, err := ParseIndex(bytes.NewReader(data))
		if err != nil || len(got) != 0 {
			t.Fatalf("got %v, %v", got, err)
		}
	})
}

func TestBuildIndex_invalid(t *testing.T) {
	edit := func(f func(*Package)) []Package {
		pkgs := samplePackages()
		f(&pkgs[0])

		return pkgs
	}

	tests := []struct {
		name string
		pkgs []Package
		desc string
	}{
		{"description with a newline", samplePackages(), "a\nb"},
		{"long description", samplePackages(), strings.Repeat("d", 1025)},
		{"description with invalid UTF-8", samplePackages(), "a\xff"},
		{"bad name", edit(func(p *Package) { p.Name = "../x" }), "d"},
		{"bad version", edit(func(p *Package) { p.Version = "x" }), "d"},
		{"bad arch", edit(func(p *Package) { p.Arch = "x/y" }), "d"},
		{"no checksum", edit(func(p *Package) { p.Checksum = "" }), "d"},
		{"bad checksum", edit(func(p *Package) { p.Checksum = "Q1x" }), "d"},
		{"control character in a field", edit(func(p *Package) { p.Description = "a\nC:x" }), "d"},
		{"control character in a dependency", edit(func(p *Package) { p.Depends = []string{"a\x01"} }), "d"},
		{"dependency with a space", edit(func(p *Package) { p.Depends = []string{"a b"} }), "d"},
		{"empty dependency", edit(func(p *Package) { p.Provides = []string{""} }), "d"},
		{"negative size", edit(func(p *Package) { p.Size = -1 }), "d"},
		{"negative priority", edit(func(p *Package) { p.ProviderPriority = -1 }), "d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildIndex(tt.pkgs, tt.desc, testSigner(t))
			if !errors.Is(err, ErrInvalidIndex) || got != nil {
				t.Fatalf("got %d bytes, %v, want ErrInvalidIndex", len(got), err)
			}
		})
	}
}

// recompress returns the member data compressed again the way a segment of the
// given kind is, one Write like the member was made from.
func recompress(t *testing.T, member []byte, std bool) []byte {
	t.Helper()

	zr, err := gzip.NewReader(bytes.NewReader(member))
	if err != nil {
		t.Fatal(err)
	}

	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer

	compress := packageGzip
	if std {
		compress = indexGzip
	}

	gw, err := compress(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := gw.Write(plain); err != nil {
		t.Fatal(err)
	}

	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

// TestBuildIndex_stdlibGzip pins the encoding of an index, signed or not, to
// the standard library's compress/gzip at its default level with OS=3: a served
// APKINDEX.tar.gz must not change bytes (ETag, signature) with the compressor.
func TestBuildIndex_stdlibGzip(t *testing.T) {
	for _, signer := range []*Signer{nil, testSigner(t)} {
		pkgs := samplePackages()
		for range 200 {
			pkgs = append(pkgs, pkgs[0])
		}

		data, err := BuildIndex(pkgs, "pinned", signer)
		if err != nil {
			t.Fatal(err)
		}

		offs := append(memberOffsets(t, data), len(data))
		if want := 1 + btoi(signer != nil); len(offs)-1 != want {
			t.Fatalf("%d members, want %d", len(offs)-1, want)
		}

		for i := 0; i+1 < len(offs); i++ {
			member := data[offs[i]:offs[i+1]]

			if !bytes.Equal(member, recompress(t, member, true)) {
				t.Fatalf("member %d is not what the standard library's gzip writes", i)
			}

			// mtime 0, no name or extra field, OS = unix.
			if !bytes.Equal(member[:4], []byte{0x1f, 0x8b, 8, 0}) || !bytes.Equal(member[4:8], make([]byte, 4)) || member[9] != 3 {
				t.Fatalf("member %d header % x", i, member[:10])
			}
		}
	}
}

// TestWritePackage_segmentsStayOnPackageGzip pins the segments of a package to
// the encoder that has always written them, so that they keep their bytes.
func TestWritePackage_segmentsStayOnPackageGzip(t *testing.T) {
	raw, _ := mustWrite(t, sampleSpec(), WriteOptions{Signer: testSigner(t), TempDir: t.TempDir()})
	offs := append(memberOffsets(t, raw), len(raw))

	if len(offs) != 4 {
		t.Fatalf("%d members", len(offs)-1)
	}

	for i := 0; i < 2; i++ { // signature and control
		member := raw[offs[i]:offs[i+1]]
		if !bytes.Equal(member, recompress(t, member, false)) {
			t.Fatalf("segment %d is not written by the package encoder", i)
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}

	return 0
}
