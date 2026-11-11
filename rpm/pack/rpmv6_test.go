package pack

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
	"github.com/M0Rf30/pkgformat/rpm/tag"
	"github.com/klauspost/compress/zstd"
	gzip "github.com/klauspost/pgzip"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

type parsedEntry struct {
	typ, count int
	data       []byte
}

type parsedHeader struct {
	raw     []byte // the whole header blob, as signed
	entries map[int]parsedEntry
}

func (h parsedHeader) str(t *testing.T, id int) string {
	t.Helper()
	e, ok := h.entries[id]
	if !ok || e.typ != tag.RPM_STRING_TYPE {
		t.Fatalf("tag %d missing or not a string: %+v", id, e)
	}
	return string(bytes.TrimSuffix(e.data, []byte{0}))
}

func (h parsedHeader) strs(t *testing.T, id int) []string {
	t.Helper()
	e, ok := h.entries[id]
	if !ok || e.typ != tag.RPM_STRING_ARRAY_TYPE {
		t.Fatalf("tag %d missing or not a string array: %+v", id, e)
	}
	s := strings.Split(string(e.data), "\x00")
	return s[:len(s)-1]
}

func (h parsedHeader) ints(t *testing.T, id, typ int) []uint64 {
	t.Helper()
	e, ok := h.entries[id]
	if !ok || e.typ != typ {
		t.Fatalf("tag %d missing or wrong type (want %d): %+v", id, typ, e)
	}
	size := map[int]int{tag.RPM_INT16_TYPE: 2, tag.RPM_INT32_TYPE: 4, tag.RPM_INT64_TYPE: 8}[typ]
	var out []uint64
	for i := 0; i < e.count; i++ {
		b := e.data[i*size : (i+1)*size]
		switch size {
		case 2:
			out = append(out, uint64(binary.BigEndian.Uint16(b)))
		case 4:
			out = append(out, uint64(binary.BigEndian.Uint32(b)))
		case 8:
			out = append(out, binary.BigEndian.Uint64(b))
		}
	}
	return out
}

func (h parsedHeader) tags() []int {
	var t []int
	for k := range h.entries {
		t = append(t, k)
	}
	sort.Ints(t)
	return t
}

type parsedRPM struct {
	lead    []byte
	sig     parsedHeader
	sigLen  int // padded length of the signature header
	main    parsedHeader
	payload []byte // as stored (compressed)
}

func readHeader(t *testing.T, b []byte) (parsedHeader, int) {
	t.Helper()
	if !bytes.HasPrefix(b, []byte{0x8e, 0xad, 0xe8, 0x01}) {
		t.Fatalf("bad header magic % x", b[:4])
	}
	n := int(binary.BigEndian.Uint32(b[8:]))
	dsize := int(binary.BigEndian.Uint32(b[12:]))
	total := 16 + 16*n + dsize
	data := b[16+16*n : total]
	h := parsedHeader{raw: b[:total], entries: map[int]parsedEntry{}}
	prev := -1
	for i := 0; i < n; i++ {
		e := b[16+16*i:]
		id := int(binary.BigEndian.Uint32(e))
		typ := int(binary.BigEndian.Uint32(e[4:]))
		off := int(int32(binary.BigEndian.Uint32(e[8:])))
		cnt := int(binary.BigEndian.Uint32(e[12:]))
		// the region tag comes first and is not part of the ordering
		if i > 1 && id <= prev {
			t.Fatalf("tags not strictly sorted: %d after %d", id, prev)
		}
		prev = id
		if i == 0 { // region tag: its data is the 16 byte trailer of the data region
			if off != dsize-16 {
				t.Fatalf("region trailer at offset %d, want %d", off, dsize-16)
			}
			cnt = 16
		}
		// the end of an entry is the start of the next one in data order,
		// so find it by type.
		var l int
		switch typ {
		case tag.RPM_INT16_TYPE:
			l = 2 * cnt
		case tag.RPM_INT32_TYPE:
			l = 4 * cnt
		case tag.RPM_INT64_TYPE:
			l = 8 * cnt
		case tag.RPM_BIN_TYPE:
			l = cnt
		case tag.RPM_STRING_TYPE:
			l = bytes.IndexByte(data[off:], 0) + 1
		case tag.RPM_STRING_ARRAY_TYPE, tag.RPM_I18NSTRING_TYPE:
			p := off
			for j := 0; j < cnt; j++ {
				p += bytes.IndexByte(data[p:], 0) + 1
			}
			l = p - off
		default:
			t.Fatalf("tag %d has unknown type %d", id, typ)
		}
		if b := map[int]int{tag.RPM_INT16_TYPE: 2, tag.RPM_INT32_TYPE: 4, tag.RPM_INT64_TYPE: 8}[typ]; b != 0 && off%b != 0 {
			t.Errorf("tag %d of type %d is not aligned: offset %d", id, typ, off)
		}
		h.entries[id] = parsedEntry{typ, cnt, data[off : off+l]}
	}
	return h, total
}

func parseRPM(t *testing.T, b []byte) parsedRPM {
	t.Helper()
	var p parsedRPM
	p.lead = b[:96]
	var n int
	p.sig, n = readHeader(t, b[96:])
	// signature header is padded to 8 bytes
	p.sigLen = n + (8-n%8)%8
	var mainLen int
	p.main, mainLen = readHeader(t, b[96+p.sigLen:])
	p.payload = b[96+p.sigLen+mainLen:]
	return p
}

func decompress(t *testing.T, comp string, b []byte) []byte {
	t.Helper()
	var r io.Reader
	var err error
	switch comp {
	case "gzip":
		r, err = gzip.NewReader(bytes.NewReader(b))
	case "zstd":
		r, err = zstd.NewReader(bytes.NewReader(b))
	case "xz":
		r, err = xz.NewReader(bytes.NewReader(b))
	case "lzma":
		r, err = lzma.NewReader(bytes.NewReader(b))
	}
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func hexSum(sum []byte) string { return fmt.Sprintf("%x", sum) }

func newV6Test(t *testing.T, comp string) *RPM {
	t.Helper()
	r, err := NewRPM(RPMMetaData{
		Name: "v6test", Version: "1.2", Release: "3", Epoch: NoEpoch,
		Summary: "s", Description: "d", Licence: "MIT",
		Compressor: comp, Format: FormatV6, BuildTime: time.Unix(1700000000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Names are deliberately added unsorted. The ghost sits in the middle so that
	// the payload indexes can only be right if they follow the header order.
	r.AddFile(RPMFile{Name: "/opt/v6", Mode: 040755, Owner: "root", Group: "root"})
	r.AddFile(RPMFile{Name: "/opt/v6/b.txt", Body: []byte("hello world\n"), Mode: 0644, Owner: "root", Group: "root"})
	r.AddFile(RPMFile{Name: "/opt/v6/bin", Body: bytes.Repeat([]byte{0x7f, 'E', 'L', 'F', 0, 1}, 100), Mode: 0755, Owner: "root", Group: "root"})
	r.AddFile(RPMFile{Name: "/opt/v6/c.log", Mode: 0644, Owner: "root", Group: "root", Type: GhostFile})
	r.AddFile(RPMFile{Name: "/opt/v6/d-link", Body: []byte("b.txt"), Mode: 0120777, Owner: "root", Group: "root"})
	r.AddFile(RPMFile{Name: "/opt/v6/e", Body: []byte("odd"), Mode: 0644, Owner: "root", Group: "root"})
	return r
}

func TestFormatValidation(t *testing.T) {
	for _, f := range []int{0, FormatV4, FormatV6} {
		if _, err := NewRPM(RPMMetaData{Format: f}); err != nil {
			t.Errorf("format %d: unexpected error %v", f, err)
		}
	}
	for _, f := range []int{1, 3, 5, 7, -6} {
		if _, err := NewRPM(RPMMetaData{Format: f}); err == nil {
			t.Errorf("format %d: want error", f)
		}
	}
}

func TestV4DefaultUnchanged(t *testing.T) {
	build := func(format int) []byte {
		r, err := NewRPM(RPMMetaData{Name: "x", Version: "1", Epoch: NoEpoch, Format: format, BuildTime: time.Unix(1, 0)})
		if err != nil {
			t.Fatal(err)
		}
		r.AddFile(RPMFile{Name: "/a", Body: []byte("a"), Mode: 0644})
		var b bytes.Buffer
		if err := r.Write(&b); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	def, v4 := build(0), build(FormatV4)
	if !bytes.Equal(def, v4) {
		t.Error("Format 0 and FormatV4 must produce identical output")
	}
	p := parseRPM(t, def)
	if p.lead[4] != 3 {
		t.Errorf("v4 lead major = %d, want 3", p.lead[4])
	}
	for _, id := range []int{tag.RPMFORMAT, tag.LONGSIZE, tag.LONGFILESIZES, tag.PAYLOADSHA3_256, tag.SIG_SHA3_256} {
		if _, ok := p.main.entries[id]; ok {
			t.Errorf("v4 main header has v6 tag %d", id)
		}
		if _, ok := p.sig.entries[id]; ok {
			t.Errorf("v4 signature header has v6 tag %d", id)
		}
	}
	for _, id := range []int{tag.SIZE, tag.FILESIZES, tag.PAYLOADDIGESTALGO} {
		if _, ok := p.main.entries[id]; !ok {
			t.Errorf("v4 main header lacks tag %d", id)
		}
	}
}

func TestV6Structure(t *testing.T) {
	r := newV6Test(t, "zstd")
	var out bytes.Buffer
	if err := r.Write(&out); err != nil {
		t.Fatal(err)
	}
	p := parseRPM(t, out.Bytes())

	wantLead := rpmhdr.LeadV6("v6test", "1.2-3")
	if !bytes.Equal(p.lead, wantLead) {
		t.Errorf("lead = % x", p.lead)
	}
	if p.lead[4] != 4 || p.lead[8] != 0 || p.lead[9] != 0 || p.lead[76] != 0 || p.lead[77] != 0 || p.lead[79] != 5 {
		t.Errorf("lead is not a v6 lead: % x", p.lead)
	}

	// Signature header: exactly these tags, none above 999, region tag first.
	if got, want := p.sig.tags(), []int{62, tag.SIG_SHA256, tag.SIG_SHA3_256, tag.SIG_RESERVED}; !reflect.DeepEqual(got, want) {
		t.Errorf("unsigned signature tags = %v, want %v", got, want)
	}
	if got := p.sig.str(t, tag.SIG_SHA256); got != hexSum(sha256Sum(p.main.raw)) {
		t.Errorf("sig sha256 = %s", got)
	}
	if got := p.sig.str(t, tag.SIG_SHA3_256); got != hexSum(sha3Sum(p.main.raw)) {
		t.Errorf("sig sha3-256 = %s", got)
	}
	res := p.sig.entries[tag.SIG_RESERVED]
	if res.typ != tag.RPM_BIN_TYPE || res.count != v6SigReserved || !bytes.Equal(res.data, make([]byte, v6SigReserved)) {
		t.Errorf("reserved: type %d, count %d", res.typ, res.count)
	}

	h := p.main
	if got := h.ints(t, tag.RPMFORMAT, tag.RPM_INT32_TYPE); !reflect.DeepEqual(got, []uint64{6}) {
		t.Errorf("RPMFORMAT = %v", got)
	}
	if got := h.str(t, tag.ENCODING); got != "utf-8" {
		t.Errorf("ENCODING = %q", got)
	}
	if got := h.str(t, tag.SOURCENEVR); got != "v6test-1.2-3" {
		t.Errorf("SOURCENEVR = %q", got)
	}
	if got := h.ints(t, tag.FILEDIGESTALGO, tag.RPM_INT32_TYPE); !reflect.DeepEqual(got, []uint64{8}) {
		t.Errorf("FILEDIGESTALGO = %v, want a single [8]", got)
	}
	for _, id := range []int{tag.SIZE, tag.FILESIZES, tag.PAYLOADDIGESTALGO} {
		if _, ok := h.entries[id]; ok {
			t.Errorf("main header must not have tag %d in v6", id)
		}
	}
	// FILESIZES / LONGFILESIZES: directories have no size, the symlink has its target length.
	// Files are in order: /opt/v6, b.txt, bin, c.log, d-link, e
	if got, want := h.ints(t, tag.LONGFILESIZES, tag.RPM_INT64_TYPE), []uint64{0, 12, 600, 0, 5, 3}; !reflect.DeepEqual(got, want) {
		t.Errorf("LONGFILESIZES = %v, want %v", got, want)
	}
	// ghost files are not in the payload, so they do not count.
	if got := h.ints(t, tag.LONGSIZE, tag.RPM_INT64_TYPE); !reflect.DeepEqual(got, []uint64{12 + 600 + 5 + 3}) {
		t.Errorf("LONGSIZE = %v", got)
	}
	wantDict := []string{"inode/directory", "text/plain", "application/octet-stream", "", "inode/symlink"}
	if got := h.strs(t, tag.MIMEDICT); !reflect.DeepEqual(got, wantDict) {
		t.Errorf("MIMEDICT = %v, want %v", got, wantDict)
	}
	if got, want := h.ints(t, tag.FILEMIMEINDEX, tag.RPM_INT32_TYPE), []uint64{0, 1, 2, 3, 4, 1}; !reflect.DeepEqual(got, want) {
		t.Errorf("FILEMIMEINDEX = %v, want %v", got, want)
	}

	// requires
	names := h.strs(t, tag.REQUIRENAME)
	vers := h.strs(t, tag.REQUIREVERSION)
	flags := h.ints(t, tag.REQUIREFLAGS, tag.RPM_INT32_TYPE)
	if !reflect.DeepEqual(names, []string{"rpmlib(LargeFiles)", "rpmlib(PayloadIsZstd)"}) ||
		!reflect.DeepEqual(vers, []string{"4.12.0-1", "5.4.18-1"}) ||
		!reflect.DeepEqual(flags, []uint64{16777226, 16777226}) {
		t.Errorf("requires = %v %v %v", names, vers, flags)
	}
}

func TestV6PayloadAndDigests(t *testing.T) {
	for _, comp := range []string{"gzip", "zstd", "xz", "lzma"} {
		t.Run(comp, func(t *testing.T) {
			r := newV6Test(t, comp)
			var out bytes.Buffer
			if err := r.Write(&out); err != nil {
				t.Fatal(err)
			}
			p := parseRPM(t, out.Bytes())
			h := p.main
			raw := decompress(t, comp, p.payload)

			// compressed digests + size, uncompressed (ALT) digests + size
			checks := []struct {
				name string
				got  string
				want string
			}{
				{"PAYLOADSHA256", h.strs(t, tag.PAYLOADDIGEST)[0], hexSum(sha256Sum(p.payload))},
				{"PAYLOADSHA256ALT", h.strs(t, tag.PAYLOADSHA256ALT)[0], hexSum(sha256Sum(raw))},
				{"PAYLOADSHA512", h.str(t, tag.PAYLOADSHA512), fmt.Sprintf("%x", sha512.Sum512(p.payload))},
				{"PAYLOADSHA512ALT", h.str(t, tag.PAYLOADSHA512ALT), fmt.Sprintf("%x", sha512.Sum512(raw))},
				{"PAYLOADSHA3_256", h.str(t, tag.PAYLOADSHA3_256), hexSum(sha3Sum(p.payload))},
				{"PAYLOADSHA3_256ALT", h.str(t, tag.PAYLOADSHA3_256ALT), hexSum(sha3Sum(raw))},
			}
			for _, c := range checks {
				if c.got != c.want {
					t.Errorf("%s = %s, want %s", c.name, c.got, c.want)
				}
			}
			if got := h.ints(t, tag.PAYLOADSIZE, tag.RPM_INT64_TYPE); !reflect.DeepEqual(got, []uint64{uint64(len(p.payload))}) {
				t.Errorf("PAYLOADSIZE = %v, want %d", got, len(p.payload))
			}
			if got := h.ints(t, tag.PAYLOADSIZEALT, tag.RPM_INT64_TYPE); !reflect.DeepEqual(got, []uint64{uint64(len(raw))}) {
				t.Errorf("PAYLOADSIZEALT = %v, want %d", got, len(raw))
			}
			if _, ok := h.entries[tag.PAYLOADDIGESTALGO]; ok {
				t.Error("PAYLOADSHA256ALGO must be absent")
			}

			// The stripped cpio: entries refer to the file index in header order.
			type entry struct {
				idx     int
				content string
			}
			var got []entry
			pos := 0
			for {
				magic := string(raw[pos : pos+6])
				if magic == "070701" {
					break
				}
				if magic != "07070X" {
					t.Fatalf("unexpected magic %q at %d", magic, pos)
				}
				var idx int
				if _, err := fmt.Sscanf(string(raw[pos+6:pos+14]), "%08x", &idx); err != nil {
					t.Fatal(err)
				}
				pos += 14
				pos += (4 - pos%4) % 4
				size := int(h.ints(t, tag.LONGFILESIZES, tag.RPM_INT64_TYPE)[idx])
				mode := h.ints(t, tag.FILEMODES, tag.RPM_INT16_TYPE)[idx]
				if mode&040000 != 0 {
					size = 0
				}
				got = append(got, entry{idx, string(raw[pos : pos+size])})
				pos += size
				pos += (4 - pos%4) % 4
			}
			// the trailer is a regular newc entry
			trailer := raw[pos:]
			wantTrailer := "070701" + strings.Repeat("00000000", 4) + "00000001" + strings.Repeat("00000000", 6) + "0000000b" + "00000000" + "TRAILER!!!\x00\x00\x00\x00"
			if string(trailer) != wantTrailer {
				t.Errorf("trailer = %q", trailer)
			}

			// files: 0 /opt/v6 dir, 1 b.txt, 2 bin, 3 c.log (ghost), 4 d-link, 5 e
			want := []entry{
				{0, ""},
				{1, "hello world\n"},
				{2, string(bytes.Repeat([]byte{0x7f, 'E', 'L', 'F', 0, 1}, 100))},
				{4, "b.txt"},
				{5, "odd"},
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("payload entries = %+v, want %+v", got, want)
			}

			// requires carry the compressor
			wantReq := map[string]string{
				"zstd": "rpmlib(PayloadIsZstd)", "xz": "rpmlib(PayloadIsXz)", "lzma": "rpmlib(PayloadIsLzma)",
			}[comp]
			names := h.strs(t, tag.REQUIRENAME)
			if wantReq == "" {
				if !reflect.DeepEqual(names, []string{"rpmlib(LargeFiles)"}) {
					t.Errorf("requires = %v", names)
				}
			} else if !reflect.DeepEqual(names, []string{"rpmlib(LargeFiles)", wantReq}) {
				t.Errorf("requires = %v", names)
			}
		})
	}
}

func TestV6Signed(t *testing.T) {
	unsigned := newV6Test(t, "zstd")
	var ub bytes.Buffer
	if err := unsigned.Write(&ub); err != nil {
		t.Fatal(err)
	}
	u := parseRPM(t, ub.Bytes())

	signed := newV6Test(t, "zstd")
	var calls [][]byte
	sigBytes := bytes.Repeat([]byte{0xab, 0xcd, 0xef}, 100)
	signed.SetPGPSigner(func(rd io.Reader) ([]byte, error) {
		b, err := io.ReadAll(rd)
		if err != nil {
			return nil, err
		}
		calls = append(calls, b)
		return sigBytes, nil
	})
	var sb bytes.Buffer
	if err := signed.Write(&sb); err != nil {
		t.Fatal(err)
	}
	s := parseRPM(t, sb.Bytes())

	if len(calls) != 1 {
		t.Fatalf("signer called %d times, want once", len(calls))
	}
	if !bytes.Equal(calls[0], s.main.raw) {
		t.Error("signer was not called with exactly the main header blob")
	}
	if got, want := s.sig.tags(), []int{62, tag.SIG_SHA256, tag.SIG_OPENPGP, tag.SIG_SHA3_256, tag.SIG_RESERVED}; !reflect.DeepEqual(got, want) {
		t.Errorf("signed signature tags = %v, want %v", got, want)
	}
	for _, id := range s.sig.tags() {
		if id > 999 {
			t.Errorf("signature header has illegal tag %d", id)
		}
	}
	got := s.sig.strs(t, tag.SIG_OPENPGP)
	if len(got) != 1 {
		t.Fatalf("OPENPGP has %d elements", len(got))
	}
	dec, err := base64.StdEncoding.DecodeString(got[0])
	if err != nil || !bytes.Equal(dec, sigBytes) {
		t.Errorf("OPENPGP is not the base64 of the signature: %v", err)
	}
	// the total signature header length stays the same as unsigned, like rpm does
	if s.sigLen != u.sigLen {
		t.Errorf("signed signature header is %d bytes, unsigned %d", s.sigLen, u.sigLen)
	}
	// the signer sees the same header the digests cover
	if s.sig.str(t, tag.SIG_SHA256) != hexSum(sha256Sum(s.main.raw)) {
		t.Error("sha256 does not cover the main header")
	}
}

func TestV6SignerError(t *testing.T) {
	r := newV6Test(t, "gzip")
	r.SetPGPSigner(func(io.Reader) ([]byte, error) { return nil, fmt.Errorf("boom") })
	if err := r.Write(io.Discard); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("Write error = %v", err)
	}
}

func TestV6BigSignatureDropsReserved(t *testing.T) {
	r := newV6Test(t, "gzip")
	r.SetPGPSigner(func(io.Reader) ([]byte, error) { return make([]byte, 10000), nil })
	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	p := parseRPM(t, b.Bytes())
	if _, ok := p.sig.entries[tag.SIG_RESERVED]; ok {
		t.Error("reserved space must be dropped when the signature does not fit")
	}
}

func TestV6MetaPackage(t *testing.T) {
	r, err := NewRPM(RPMMetaData{Name: "meta", Version: "1", Release: "1", Format: FormatV6, Compressor: "zstd"})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	p := parseRPM(t, b.Bytes())
	for _, id := range []int{tag.BASENAMES, tag.LONGFILESIZES, tag.FILEMIMEINDEX, tag.MIMEDICT, tag.FILEDIGESTALGO} {
		if _, ok := p.main.entries[id]; ok {
			t.Errorf("meta package has file tag %d", id)
		}
	}
	raw := decompress(t, "zstd", p.payload)
	if len(raw) != 124 || !strings.HasPrefix(string(raw), "070701") {
		t.Errorf("meta payload should only be the trailer, got %d bytes", len(raw))
	}
	if got := p.main.ints(t, tag.PAYLOADSIZEALT, tag.RPM_INT64_TYPE); got[0] != 124 {
		t.Errorf("PAYLOADSIZEALT = %v", got)
	}
	if got := p.main.ints(t, tag.LONGSIZE, tag.RPM_INT64_TYPE); got[0] != 0 {
		t.Errorf("LONGSIZE = %v", got)
	}
}

func TestV6Epoch(t *testing.T) {
	r, err := NewRPM(RPMMetaData{Name: "e", Version: "1", Release: "2", Epoch: 3, Format: FormatV6})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	if got := parseRPM(t, b.Bytes()).main.str(t, tag.SOURCENEVR); got != "e-3:1-2" {
		t.Errorf("SOURCENEVR = %q", got)
	}
}

func TestEntryInt64(t *testing.T) {
	e := EntryInt64([]int64{1, -2})
	if e.Type != 5 || e.Count != 2 ||
		!bytes.Equal(e.Data, []byte{0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}) {
		t.Errorf("EntryInt64 = %+v", e)
	}
	if u := EntryUint64([]uint64{1 << 40}); u.Type != 5 || u.Count != 1 ||
		!bytes.Equal(u.Data, []byte{0, 0, 1, 0, 0, 0, 0, 0}) {
		t.Errorf("EntryUint64 = %+v", u)
	}

	// INT64 values are 8-byte aligned in the header data.
	i := rpmhdr.NewIndex(tag.RPMTAG_HEADERIMMUTABLE)
	i.Add(1, EntryString("abc")) // 4 bytes
	i.Add(2, EntryInt64([]int64{7}))
	b, err := i.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	h, _ := readHeader(t, b)
	if got := h.ints(t, 2, tag.RPM_INT64_TYPE); !reflect.DeepEqual(got, []uint64{7}) {
		t.Errorf("round trip = %v", got)
	}
}

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
func sha3Sum(b []byte) []byte   { s := sha3.Sum256(b); return s[:] }
