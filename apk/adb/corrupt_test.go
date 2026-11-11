package adb

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

// rawBlock is one block of a file without compression.
type rawBlock struct {
	typ     uint32
	payload []byte
	// ext writes the block with the extended header.
	ext bool
}

// joinFile assembles a file from blocks, with the header the schema asks for.
func joinFile(schema uint32, blocks ...rawBlock) []byte {
	out := append([]byte(magicADB), binary.LittleEndian.AppendUint32(nil, schema)...)

	for _, b := range blocks {
		var hdr []byte

		if b.ext {
			hdr = binary.LittleEndian.AppendUint32(nil, blockExt<<30|b.typ)
			hdr = binary.LittleEndian.AppendUint32(hdr, 0)
			hdr = binary.LittleEndian.AppendUint64(hdr, 16+uint64(len(b.payload)))
		} else {
			hdr = binary.LittleEndian.AppendUint32(nil, b.typ<<30|uint32(4+len(b.payload)))
		}

		out = append(out, hdr...)
		out = append(out, b.payload...)
		out = append(out, make([]byte, (8-(len(hdr)+len(b.payload))%8)%8)...)
	}

	return out
}

// splitFile is the inverse of joinFile, for files that are not compressed.
func splitFile(t testing.TB, file []byte) (uint32, []rawBlock) {
	t.Helper()

	if string(file[:4]) != magicADB {
		t.Fatalf("file is compressed")
	}

	schema := binary.LittleEndian.Uint32(file[4:8])

	var blocks []rawBlock

	for rest := file[8:]; len(rest) > 0; {
		ts := binary.LittleEndian.Uint32(rest)

		var b rawBlock

		hdr, size := 4, uint64(ts&0x3fffffff)
		if ts>>30 == blockExt {
			b.ext, b.typ, hdr, size = true, ts&0x3fffffff, 16, binary.LittleEndian.Uint64(rest[8:])
		} else {
			b.typ = ts >> 30
		}

		b.payload = rest[hdr:size]
		blocks = append(blocks, b)
		rest = rest[min(uint64(len(rest)), (size+7)&^7):]
	}

	return schema, blocks
}

// signedBase is a package of three files signed by an RSA key, not compressed.
func signedBase(t testing.TB) []byte {
	t.Helper()

	spec := &Spec{
		Info: Info{Name: "base", Version: "1-r0", Arch: "noarch"},
		Files: []File{
			MemFile("a/one", 0o644, []byte("first file")),
			MemFile("a/two", 0o644, []byte("second file, a little longer")),
			MemFile("b/three", 0o755, []byte("third")),
		},
	}

	var out bytes.Buffer
	if _, err := WritePackage(&out, spec, WriteOptions{Compression: NoCompression, Signers: []*Signer{keysOf(t)[0].signer}}); err != nil {
		t.Fatal(err)
	}

	return out.Bytes()
}

// rawPackage encodes a package as it is, whatever it holds, without
// compression or data blocks.
func rawPackage(t testing.TB, p *Package) []byte {
	t.Helper()

	b := newBuilder()

	is, err := b.info(&p.Info, true)
	if err != nil {
		t.Fatal(err)
	}

	slots := make([]value, pkgReplacesPriority+1)
	slots[pkgInfo] = b.object(typeObject, is)

	paths := make([]value, 1)

	for _, d := range p.Paths {
		files := make([]value, 1)
		for i := range d.Files {
			files = append(files, b.file(&d.Files[i], nil))
		}

		ds := make([]value, diFiles+1)
		ds[diName] = b.str(d.Name)
		ds[diACL] = b.acl(&d.ACL)
		ds[diFiles] = b.object(typeObject, files)
		paths = append(paths, b.object(typeObject, ds))
	}

	slots[pkgPaths] = b.object(typeObject, paths)

	raw, err := b.finish(b.object(typeObject, slots))
	if err != nil {
		t.Fatal(err)
	}

	return joinFile(SchemaPackage, rawBlock{typ: blockADB, payload: raw})
}

var okACL = ACL{Mode: 0o644, User: "root", Group: "root"}

func rawBase() *Package {
	sum := sha256.Sum256([]byte("x"))

	return &Package{
		Info: Info{Name: "raw", Version: "1", Arch: "noarch", Hashes: make([]byte, 20)},
		Paths: []Dir{{
			Name: "d", ACL: ACL{Mode: 0o755, User: "root", Group: "root"},
			Files: []FileEntry{{Name: "f", ACL: okACL, Size: 1, Hash: sum[:]}},
		}},
	}
}

func TestHostileMetadata(t *testing.T) {
	apkTemp := ".apk." + strings.Repeat("a", 48)

	for _, c := range []struct {
		name string
		mod  func(*Package)
		want error
	}{
		{"slash in a name", func(p *Package) { p.Paths[0].Files[0].Name = "a/b" }, ErrUnsafePath},
		{"dotdot name", func(p *Package) { p.Paths[0].Files[0].Name = ".." }, ErrUnsafePath},
		{"dot name", func(p *Package) { p.Paths[0].Files[0].Name = "." }, ErrUnsafePath},
		{"empty name", func(p *Package) { p.Paths[0].Files[0].Name = "" }, ErrUnsafePath},
		{"control character", func(p *Package) { p.Paths[0].Files[0].Name = "a\x01" }, ErrUnsafePath},
		{"del", func(p *Package) { p.Paths[0].Files[0].Name = "a\x7f" }, ErrUnsafePath},
		{"temporary name", func(p *Package) { p.Paths[0].Files[0].Name = apkTemp }, ErrUnsafePath},
		{"dotdot directory", func(p *Package) { p.Paths[0].Name = "../x" }, ErrUnsafePath},
		{"absolute directory", func(p *Package) { p.Paths[0].Name = "/abs" }, ErrUnsafePath},
		{"doubled slash", func(p *Package) { p.Paths[0].Name = "a//b" }, ErrUnsafePath},
		{"trailing slash", func(p *Package) { p.Paths[0].Name = "a/" }, ErrUnsafePath},
		{"dotdot inside", func(p *Package) { p.Paths[0].Name = "a/../b" }, ErrUnsafePath},
		{"huge mode", func(p *Package) { p.Paths[0].ACL.Mode = 1 << 20 }, ErrSchema},
		{"huge file mode", func(p *Package) { p.Paths[0].Files[0].ACL.Mode = 1 << 20 }, ErrSchema},
		{"short target", func(p *Package) { p.Paths[0].Files[0].Target = []byte{0x00} }, ErrSchema},
		{"unknown type", func(p *Package) { p.Paths[0].Files[0].Target = []byte{0xff, 0xff, 'x'} }, ErrSchema},
		{"fifo number", func(p *Package) { p.Paths[0].Files[0].Target = []byte{0x00, 0x10, 1, 2, 3} }, ErrSchema},
		{"long link", func(p *Package) {
			p.Paths[0].Files[0].Target = append([]byte{0x00, 0xa0}, bytes.Repeat([]byte("a"), 5000)...)
		}, ErrSchema},
		{"link out of the tree", func(p *Package) {
			p.Paths[0].Files[0].Target = append([]byte{0x00, 0x80}, "../../x"...)
		}, ErrUnsafePath},
		{"no digest", func(p *Package) { p.Paths[0].Files[0].Hash = nil }, ErrSchema},
		{"odd digest", func(p *Package) { p.Paths[0].Files[0].Hash = []byte{1, 2, 3} }, ErrSchema},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := rawBase()
			c.mod(p)

			file := rawPackage(t, p)

			// What the decoder refuses, it refuses while parsing; what the
			// walk refuses, it refuses at the entry.
			_, err := ParsePackage(bytes.NewReader(file), ReadOptions{})
			if err == nil {
				_, _, err = readAll(t, file, ReadOptions{})
			}

			if !errors.Is(err, c.want) {
				t.Errorf("got %v, want %v", err, c.want)
			}

			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%v does not wrap ErrInvalid", err)
			}
		})
	}
}

func TestHostileContainer(t *testing.T) {
	base := signedBase(t)
	schema, blocks := splitFile(t, base)

	if len(blocks) != 5 || blocks[0].typ != blockADB || blocks[1].typ != blockSig {
		t.Fatalf("unexpected base layout: %d blocks", len(blocks))
	}

	adb, sig, d1, d2, d3 := blocks[0], blocks[1], blocks[2], blocks[3], blocks[4]

	with := func(bs ...rawBlock) []byte { return joinFile(schema, bs...) }
	edit := func(b rawBlock, f func([]byte) []byte) rawBlock {
		b.payload = f(append([]byte(nil), b.payload...))

		return b
	}

	for _, c := range []struct {
		name string
		file []byte
		want error
	}{
		{"empty", nil, ErrInvalid},
		{"short", []byte("ADB"), ErrInvalid},
		{"bad magic", append([]byte("ADB!"), base[4:]...), ErrInvalid},
		{"unknown algorithm", append([]byte("ADBc\x07\x01"), base[4:]...), ErrCompression},
		{"truncated compression header", []byte("ADBc\x01"), ErrInvalid},
		{"truncated file header", []byte("ADB.ab"), ErrInvalid},
		{"no blocks", with(), ErrBlock},
		{"data first", with(d1), ErrBlock},
		{"signature first", with(sig, adb), ErrBlock},
		{"tiny ADB block", with(rawBlock{typ: blockADB, payload: make([]byte, 8)}), ErrBlock},
		{"garbage ADB block", with(rawBlock{typ: blockADB, payload: bytes.Repeat([]byte{0xff}, 64)}), ErrInvalid},
		{"unknown compat version", with(edit(adb, func(p []byte) []byte { p[0] = 9; return p })), ErrInvalid},
		{"second ADB block", with(adb, adb, sig, d1, d2, d3), ErrBlock},
		{"unknown block type", with(adb, rawBlock{typ: 9, ext: true, payload: []byte("zz")}, d1, d2, d3), ErrBlock},
		{"huge signature", with(adb, rawBlock{typ: blockSig, payload: make([]byte, 100<<10)}, d1, d2, d3), ErrBlock},
		{"short signature", with(adb, rawBlock{typ: blockSig, payload: []byte{0}}, d1, d2, d3), ErrBlock},
		{"short signature header", with(adb, rawBlock{typ: blockSig, payload: make([]byte, 10)}, d1, d2, d3), ErrBlock},
		{"missing last data block", with(adb, sig, d1, d2), ErrBlock},
		{"missing all data", with(adb, sig), ErrBlock},
		{"swapped data blocks", with(adb, sig, d2, d1, d3), ErrBlock},
		{"extra data block", with(adb, sig, d1, d2, d3, d3), ErrBlock},
		{"extra signature after data", with(adb, sig, d1, d2, d3, sig), ErrBlock},
		{"altered content", with(adb, sig, edit(d1, func(p []byte) []byte { p[9] ^= 1; return p }), d2, d3), ErrDigest},
		{"wrong path index", with(adb, sig, edit(d1, func(p []byte) []byte { p[0] = 7; return p }), d2, d3), ErrBlock},
		{"wrong file index", with(adb, sig, edit(d1, func(p []byte) []byte { p[4] = 9; return p }), d2, d3), ErrBlock},
		{"longer content", with(adb, sig, edit(d1, func(p []byte) []byte { return append(p, 'x') }), d2, d3), ErrBlock},
		{"shorter content", with(adb, sig, edit(d1, func(p []byte) []byte { return p[:len(p)-1] }), d2, d3), ErrBlock},
		{"data without index", with(adb, sig, rawBlock{typ: blockData, payload: []byte{1, 2}}, d2, d3), ErrBlock},
		{"empty data block", with(adb, sig, rawBlock{typ: blockData}, d2, d3), ErrBlock},
		{"signature in place of data", with(adb, sig, sig, d2, d3), ErrBlock},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := VerifyPackage(bytes.NewReader(c.file), keyringOf(t, keysOf(t)[0]), ReadOptions{})
			if !errors.Is(err, c.want) {
				t.Errorf("VerifyPackage: %v, want %v", err, c.want)
			}

			// Without the signature check the content is still checked.
			if _, err := Extract(bytes.NewReader(c.file), t.TempDir(), ExtractOptions{AllowUntrusted: true}); err == nil {
				t.Error("Extract accepted it")
			}
		})
	}
}

// TestExtendedBlocks reads the same package with every block in the extended
// form.
func TestExtendedBlocks(t *testing.T) {
	base := signedBase(t)
	schema, blocks := splitFile(t, base)

	for i := range blocks {
		blocks[i].ext = true
	}

	ext := joinFile(schema, blocks...)

	want, _, err := readAll(t, base, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	got, _, err := readAll(t, ext, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, want) || len(got) == 0 {
		t.Errorf("extended blocks read differently")
	}

	if _, _, err := VerifyPackage(bytes.NewReader(ext), keyringOf(t, keysOf(t)[0]), ReadOptions{}); err != nil {
		t.Errorf("signature over extended blocks: %v", err)
	}

	// An extended header can say what a short one cannot.
	for _, n := range []uint64{0, 1, stdBlockMax, stdBlockMax + 1, 1 << 33} {
		if tag := blockTag(blockData, n); (n > stdBlockMax) != (len(tag) == 16) {
			t.Errorf("length %d: tag of %d bytes", n, len(tag))
		}
	}

	// Header too short for its own length.
	short := binary.LittleEndian.AppendUint32(nil, blockExt<<30|blockData)
	short = binary.LittleEndian.AppendUint32(short, 0)
	short = binary.LittleEndian.AppendUint64(short, 8)

	if _, err := ParsePackage(bytes.NewReader(append([]byte("ADB.pckg"), short...)), ReadOptions{}); !errors.Is(err, ErrBlock) {
		t.Errorf("ext header of 8 bytes: %v", err)
	}

	trunc := append([]byte("ADB.pckg"), short[:6]...)
	if _, err := ParsePackage(bytes.NewReader(trunc), ReadOptions{}); !errors.Is(err, ErrBlock) {
		t.Errorf("truncated ext header: %v", err)
	}

	if _, err := ParsePackage(bytes.NewReader(append([]byte("ADB.pckg"), 0, 0)), ReadOptions{}); !errors.Is(err, ErrBlock) {
		t.Errorf("truncated header: %v", err)
	}

	if _, err := ParsePackage(bytes.NewReader(append([]byte("ADB.pckg"), 2, 0, 0, 0)), ReadOptions{}); !errors.Is(err, ErrBlock) {
		t.Errorf("block shorter than its header: %v", err)
	}
}

// TestTruncation cuts the file at every length, uncompressed and not.
func TestTruncation(t *testing.T) {
	kr := keyringOf(t, keysOf(t)[0])

	var deflated, zstded bytes.Buffer

	spec := &Spec{
		Info:  Info{Name: "base", Version: "1-r0", Arch: "noarch"},
		Files: []File{MemFile("a/one", 0o644, []byte("first file")), MemFile("b", 0o755, []byte("second"))},
	}

	signer := keysOf(t)[0].signer
	if _, err := WritePackage(&deflated, spec, WriteOptions{Signers: []*Signer{signer}}); err != nil {
		t.Fatal(err)
	}

	if _, err := WritePackage(&zstded, spec, WriteOptions{Compression: Zstd, Signers: []*Signer{signer}}); err != nil {
		t.Fatal(err)
	}

	for name, file := range map[string][]byte{"plain": signedBase(t), "deflate": deflated.Bytes(), "zstd": zstded.Bytes()} {
		if _, _, err := VerifyPackage(bytes.NewReader(file), kr, ReadOptions{}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		for n := range len(file) {
			if _, _, err := VerifyPackage(bytes.NewReader(file[:n]), kr, ReadOptions{}); err == nil {
				t.Fatalf("%s: a file cut to %d of %d bytes verified", name, n, len(file))
			}
		}
	}
}

// TestBitFlips changes every byte of a package; none may panic, and a change
// to the signed metadata must not verify.
func TestBitFlips(t *testing.T) {
	kr := keyringOf(t, keysOf(t)[0])
	base := signedBase(t)

	_, blocks := splitFile(t, base)
	// The signed bytes: after the file header and the block header.
	from, to := 8+4, 8+4+len(blocks[0].payload)

	for i := range base {
		file := bytes.Clone(base)
		file[i] ^= 0x55

		_, _, err := VerifyPackage(bytes.NewReader(file), kr, ReadOptions{})
		if err == nil && i >= from && i < to {
			t.Fatalf("a change at byte %d of the signed block verified", i)
		}

		_, _ = Extract(bytes.NewReader(file), t.TempDir(), ExtractOptions{AllowUntrusted: true})
		_, _ = ParsePackage(bytes.NewReader(file), ReadOptions{})
		_, _ = ParseIndex(bytes.NewReader(file), ReadOptions{})
	}
}

func TestLimits(t *testing.T) {
	var kinds bytes.Buffer
	if _, err := WritePackage(&kinds, kindsSpec(), WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	zeros := &Spec{
		Info:  Info{Name: "z", Version: "1", Arch: "noarch"},
		Files: []File{MemFile("big", 0o644, make([]byte, 4<<20))},
	}

	var zbuf bytes.Buffer
	if _, err := WritePackage(&zbuf, zeros, WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		file []byte
		lim  Limits
		want error
	}{
		{"ADB block", kinds.Bytes(), Limits{MaxADB: 100}, ErrBlock},
		{"stream", zbuf.Bytes(), Limits{MaxStream: 1 << 20}, ErrTooComplex},
		{"entries", kinds.Bytes(), Limits{MaxEntries: 2}, ErrTooComplex},
		{"nodes", kinds.Bytes(), Limits{MaxNodes: 5}, ErrTooComplex},
		{"decoded bytes", kinds.Bytes(), Limits{MaxDecodedBytes: 200}, ErrTooComplex},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := IndexEntry(bytes.NewReader(c.file), ReadOptions{Limits: c.lim})
			if !errors.Is(err, c.want) {
				t.Errorf("IndexEntry: %v, want %v", err, c.want)
			}

			if _, err := Extract(bytes.NewReader(c.file), t.TempDir(), ExtractOptions{AllowUntrusted: true, Read: ReadOptions{Limits: c.lim}}); !errors.Is(err, c.want) {
				t.Errorf("Extract: %v, want %v", err, c.want)
			}
		})
	}

	// The bounds the format itself has.
	if (Limits{MaxADB: 1 << 40}).maxADB() != maxADBFormat {
		t.Error("MaxADB is not capped to what the format can address")
	}

	if (Limits{}).maxADB() != DefaultMaxADB || (Limits{}).maxStream() != DefaultMaxStream || (Limits{}).maxEntries() != DefaultMaxEntries {
		t.Error("zero limits are not the defaults")
	}
}

// TestSharedValueBlowup: one value referenced from many slots must not
// multiply into an unbounded decode.
func TestSharedValueBlowup(t *testing.T) {
	b := newBuilder()

	one := make([]value, fiTarget+1)
	one[fiName] = b.str("name")

	entry := b.object(typeObject, one)

	file := make([]value, 1)
	for range 4000 {
		file = append(file, entry)
	}

	fileArr := b.object(typeObject, file)

	ds := make([]value, diFiles+1)
	ds[diName] = b.str("d")
	ds[diFiles] = fileArr
	dir := b.object(typeObject, ds)

	paths := make([]value, 1)
	for range 4000 {
		paths = append(paths, dir)
	}

	info := make([]value, piMax)
	info[piName] = b.str("x")
	info[piVersion] = b.str("1")

	slots := make([]value, pkgReplacesPriority+1)
	slots[pkgInfo] = b.object(typeObject, info)
	slots[pkgPaths] = b.object(typeObject, paths)

	raw, err := b.finish(b.object(typeObject, slots))
	if err != nil {
		t.Fatal(err)
	}

	f := joinFile(SchemaPackage, rawBlock{typ: blockADB, payload: raw})
	if len(f) > 1<<20 {
		t.Fatalf("test file is %d bytes", len(f))
	}

	if _, err := ParsePackage(bytes.NewReader(f), ReadOptions{}); !errors.Is(err, ErrTooComplex) {
		t.Errorf("16M entries out of %d bytes: %v", len(f), err)
	}
}

// TestSignatureBlocks signs by hand with the other digests the format names,
// and with versions this package does not know.
func TestSignatureBlocks(t *testing.T) {
	for _, k := range keysOf(t) {
		base := signedBase(t)
		schema, blocks := splitFile(t, base)
		adb := blocks[0].payload

		sigOf := func(version, alg uint8, id KeyID) []byte {
			md := adbDigest(alg, adb)
			if md == nil {
				md = []byte("unknown")
			}

			sig, err := k.signer.key.Sign(rand.Reader, signedDigest(schema, version, alg, id, md), crypto.SHA512)
			if err != nil {
				t.Fatal(err)
			}

			return append(append([]byte{version, alg}, id[:]...), sig...)
		}

		id := k.signer.KeyID()

		for _, c := range []struct {
			name string
			sig  []byte
			want error
		}{
			{"sha256", sigOf(0, DigestSHA256, id), nil},
			{"sha256/160", sigOf(0, DigestSHA256_160, id), nil},
			{"sha512", sigOf(0, DigestSHA512, id), nil},
			{"unknown digest", sigOf(0, 9, id), ErrBadSignature},
			{"unknown version", append([]byte{1, 4}, make([]byte, 40)...), ErrUntrusted},
			{"other key", sigOf(0, DigestSHA512, KeyID{1}), ErrUntrusted},
			{"signed for another key", append(append([]byte{0, 4}, id[:]...), sigOf(0, DigestSHA512, KeyID{1})[18:]...), ErrBadSignature},
		} {
			t.Run(k.name+"/"+c.name, func(t *testing.T) {
				file := joinFile(schema, blocks[0], rawBlock{typ: blockSig, payload: c.sig}, blocks[2], blocks[3], blocks[4])

				_, got, err := VerifyPackage(bytes.NewReader(file), keyringOf(t, k), ReadOptions{})
				if !errors.Is(err, c.want) {
					t.Fatalf("%v, want %v", err, c.want)
				}

				if c.want == nil && got != id {
					t.Errorf("key id %x, want %x", got, id)
				}
			})
		}
	}

	if _, err := parseSignature([]byte{0}); !errors.Is(err, ErrBlock) {
		t.Errorf("one byte signature: %v", err)
	}
}

func TestBlockHeaders(t *testing.T) {
	for _, n := range []uint64{0, 1, 3, 4, 5, 7, 8, 9, 1000, stdBlockMax, stdBlockMax + 1} {
		tag := blockTag(blockData, n)
		pad := blockPad(blockData, n)

		if (uint64(len(tag))+n+uint64(pad))%blockAlign != 0 {
			t.Errorf("length %d: block not aligned", n)
		}

		if n > 1<<20 {
			continue
		}

		raw := append(append([]byte(nil), tag...), make([]byte, int(n)+pad)...)

		h, err := readBlockHdr(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil || h.typ != blockData || h.length != n || h.padding != pad {
			t.Errorf("length %d: %+v %v", n, h, err)
		}
	}
}

func TestReaderWithShortReads(t *testing.T) {
	base := signedBase(t)

	for name, r := range map[string]io.Reader{
		"one byte": iotest.OneByteReader(bytes.NewReader(base)),
		"half":     iotest.HalfReader(bytes.NewReader(base)),
		"data err": iotest.DataErrReader(bytes.NewReader(base)),
	} {
		pkg, _, err := VerifyPackage(r, keyringOf(t, keysOf(t)[0]), ReadOptions{})
		if err != nil || pkg.Info.Name != "base" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReadErrorPropagates(t *testing.T) {
	base := signedBase(t)
	boom := errors.New("boom")

	for _, at := range []int{0, 5, 20, 100, len(base) - 20} {
		r := io.MultiReader(bytes.NewReader(base[:at]), errReader{boom})

		_, err := IndexEntry(r, ReadOptions{})
		if err == nil {
			t.Errorf("failure after %d bytes went unnoticed", at)
		}
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
