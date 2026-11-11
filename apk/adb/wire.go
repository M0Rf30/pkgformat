package adb

import (
	"encoding/binary"
	"math"
)

// value is one 32-bit tagged ADB value: the high 4 bits are the type, the low
// 28 bits an immediate (small integers) or the offset of the value in the ADB
// block.
type value uint32

// Value types.
const (
	typeSpecial uint32 = 0x0
	typeInt     uint32 = 0x1
	typeInt32   uint32 = 0x2
	typeInt64   uint32 = 0x3
	typeBlob8   uint32 = 0x8
	typeBlob16  uint32 = 0x9
	typeBlob32  uint32 = 0xa
	typeArray   uint32 = 0xd
	typeObject  uint32 = 0xe

	valueMask  = 0x0fffffff
	valueShift = 28

	// null is the absent value.
	null value = 0

	// hdrSize is the size of the header at the start of the ADB block: the
	// compatibility and format versions, two reserved bytes and the root value.
	hdrSize = 8

	// maxSlots bounds the slots of one object or array; the format reserves
	// 24 bits for the count.
	maxSlots = 0x1000000
)

func (v value) typ() uint32 { return uint32(v) >> valueShift }
func (v value) off() int    { return int(uint32(v) & valueMask) }
func mkValue(t uint32, off int) value {
	return value(t<<valueShift | uint32(off)&valueMask)
}

// block is the payload of an ADB block under decoding. All reads are bounds
// checked: a value that points outside the block is ErrInvalid, never a panic.
type block struct {
	data []byte
	// budget bounds the work and the memory a decode may cost. It is shared by
	// every decoder reading the block, because the values form a DAG: one
	// shared object can be referenced from every slot of a large array.
	nodes int64
	bytes int64
}

// Default decode budget; see Limits.
const (
	defaultMaxNodes        = 1 << 24
	defaultMaxDecodedBytes = 1 << 28
)

func newBlock(data []byte, lim Limits) (*block, error) {
	if len(data) < hdrSize+4 {
		return nil, blockErr("ADB block of %d bytes is shorter than its header", len(data))
	}

	if data[0] != 0 {
		return nil, invalid("unsupported ADB compatibility version %d", data[0])
	}

	return &block{data: data, nodes: int64(lim.maxNodes()), bytes: lim.maxDecodedBytes()}, nil
}

func (b *block) root() value { return value(binary.LittleEndian.Uint32(b.data[4:8])) }

// charge accounts for one decoded node holding n bytes.
func (b *block) charge(n int) error {
	b.nodes--
	b.bytes -= int64(n) + 16

	if b.nodes < 0 || b.bytes < 0 {
		return ErrTooComplex
	}

	return nil
}

// at returns size bytes at the value's offset plus extra.
func (b *block) at(v value, extra, size int) ([]byte, error) {
	off := v.off() + extra
	if size < 0 || off < 0 || off > len(b.data) || size > len(b.data)-off {
		return nil, invalid("value at offset %d (%d bytes) lies outside the ADB block", off, size)
	}

	return b.data[off : off+size], nil
}

// uint decodes an integer value; null is zero.
func (b *block) uint(v value) (uint64, error) {
	switch v.typ() {
	case typeSpecial:
		if v != null {
			return 0, schemaErr("special value %#x where an integer is expected", uint32(v))
		}

		return 0, nil
	case typeInt:
		return uint64(v.off()), nil
	case typeInt32:
		p, err := b.at(v, 0, 4)
		if err != nil {
			return 0, err
		}

		return uint64(binary.LittleEndian.Uint32(p)), nil
	case typeInt64:
		p, err := b.at(v, 0, 8)
		if err != nil {
			return 0, err
		}

		return binary.LittleEndian.Uint64(p), nil
	default:
		return 0, schemaErr("value of type %#x where an integer is expected", v.typ())
	}
}

// blob decodes a byte string value; null is nil. The result aliases the block.
func (b *block) blob(v value) ([]byte, error) {
	var n, prefix int

	switch v.typ() {
	case typeSpecial:
		if v != null {
			return nil, schemaErr("special value %#x where a string is expected", uint32(v))
		}

		return nil, nil
	case typeBlob8:
		p, err := b.at(v, 0, 1)
		if err != nil {
			return nil, err
		}

		n, prefix = int(p[0]), 1
	case typeBlob16:
		p, err := b.at(v, 0, 2)
		if err != nil {
			return nil, err
		}

		n, prefix = int(binary.LittleEndian.Uint16(p)), 2
	case typeBlob32:
		p, err := b.at(v, 0, 4)
		if err != nil {
			return nil, err
		}

		u := binary.LittleEndian.Uint32(p)
		if u > math.MaxInt32 {
			return nil, invalid("blob of %d bytes", u)
		}

		n, prefix = int(u), 4
	default:
		return nil, schemaErr("value of type %#x where a string is expected", v.typ())
	}

	p, err := b.at(v, prefix, n)
	if err != nil {
		return nil, err
	}

	if err := b.charge(n); err != nil {
		return nil, err
	}

	return p, nil
}

// obj is the view of an object or array: slot 0 holds the number of slots
// (itself included), slots 1.. the values.
type obj struct {
	b *block
	// slots is the raw little-endian slot array, count word included.
	slots []byte
	num   int
}

// object opens an object or array value; null is an empty object.
func (b *block) object(v value) (obj, error) {
	if v == null {
		return obj{b: b, num: 1}, nil
	}

	if t := v.typ(); t != typeObject && t != typeArray {
		return obj{}, schemaErr("value of type %#x where an object is expected", t)
	}

	p, err := b.at(v, 0, 4)
	if err != nil {
		return obj{}, err
	}

	n := binary.LittleEndian.Uint32(p)
	if n == 0 || n > maxSlots {
		return obj{}, invalid("object with %d slots", n)
	}

	slots, err := b.at(v, 0, int(n)*4)
	if err != nil {
		return obj{}, err
	}

	if err := b.charge(int(n) * 4); err != nil {
		return obj{}, err
	}

	return obj{b: b, slots: slots, num: int(n)}, nil
}

// val returns slot i; slots past the end are null.
func (o obj) val(i int) value {
	if i <= 0 || i >= o.num {
		return null
	}

	return value(binary.LittleEndian.Uint32(o.slots[i*4:]))
}

// items is the number of items of an array.
func (o obj) items() int { return o.num - 1 }

func (o obj) uint(i int) (uint64, error) { return o.b.uint(o.val(i)) }
func (o obj) blob(i int) ([]byte, error) { return o.b.blob(o.val(i)) }
func (o obj) obj(i int) (obj, error)     { return o.b.object(o.val(i)) }
func (o obj) str(i int) (string, error) {
	p, err := o.blob(i)

	return string(p), err
}

// builder assembles an ADB block. Values are appended and de-duplicated the
// way apk-tools does: a datum identical to one already written, and aligned
// as required, is not written twice. The bytes of a block therefore match what
// apk mkpkg and apk mkndx produce for the same content.
type builder struct {
	buf   []byte
	cache map[string]int
	err   error
}

func newBuilder() *builder {
	return &builder{buf: make([]byte, hdrSize, 4096), cache: make(map[string]int)}
}

// raw appends the parts, padded to align, and returns the offset.
func (b *builder) raw(align int, parts ...[]byte) int {
	for len(b.buf)%align != 0 {
		b.buf = append(b.buf, 0)
	}

	off := len(b.buf)
	for _, p := range parts {
		b.buf = append(b.buf, p...)
	}

	if len(b.buf) > valueMask+1 && b.err == nil {
		b.err = ErrTooLarge
	}

	return off
}

// data is raw with de-duplication.
func (b *builder) data(align int, parts ...[]byte) int {
	n := 0
	for _, p := range parts {
		n += len(p)
	}

	key := make([]byte, 0, n)
	for _, p := range parts {
		key = append(key, p...)
	}

	if off, ok := b.cache[string(key)]; ok && off&(align-1) == 0 {
		return off
	}

	off := b.raw(align, key)
	b.cache[string(key)] = off

	return off
}

// blobOf appends a string. The empty string is the null value: the format has
// no empty blob.
func (b *builder) blobOf(cache bool, parts ...[]byte) value {
	n := 0
	for _, p := range parts {
		n += len(p)
	}

	var (
		prefix []byte
		typ    uint32
	)

	switch {
	case n > 0xffff:
		prefix, typ = binary.LittleEndian.AppendUint32(nil, uint32(n)), typeBlob32
	case n > 0xff:
		prefix, typ = binary.LittleEndian.AppendUint16(nil, uint16(n)), typeBlob16
	case n > 0:
		prefix, typ = []byte{byte(n)}, typeBlob8
	default:
		return null
	}

	all := append([][]byte{prefix}, parts...)
	if cache {
		return mkValue(typ, b.data(len(prefix), all...))
	}

	return mkValue(typ, b.raw(len(prefix), all...))
}

func (b *builder) blob(p []byte) value    { return b.blobOf(true, p) }
func (b *builder) str(s string) value     { return b.blobOf(true, []byte(s)) }
func (b *builder) blobRaw(p []byte) value { return b.blobOf(false, p) }

// uint appends an integer: values below 2^28 are immediate.
func (b *builder) uint(n uint64) value {
	switch {
	case n >= 1<<32:
		return mkValue(typeInt64, b.data(4, binary.LittleEndian.AppendUint64(nil, n)))
	case n >= 1<<28:
		return mkValue(typeInt32, b.data(4, binary.LittleEndian.AppendUint32(nil, uint32(n))))
	default:
		return mkValue(typeInt, int(n))
	}
}

// object appends an object or array whose slots start at index 1 (slots[0] is
// ignored). Trailing nulls are dropped; an object with no value is null.
func (b *builder) object(typ uint32, slots []value) value {
	n := len(slots)
	for n > 1 && slots[n-1] == null {
		n--
	}

	if n <= 1 {
		return null
	}

	p := make([]byte, 4*n)
	binary.LittleEndian.PutUint32(p, uint32(n))

	for i := 1; i < n; i++ {
		binary.LittleEndian.PutUint32(p[4*i:], uint32(slots[i]))
	}

	return mkValue(typ, b.data(4, p))
}

// finish sets the root value and returns the block.
func (b *builder) finish(root value) ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}

	binary.LittleEndian.PutUint32(b.buf[4:8], uint32(root))

	return b.buf, nil
}
