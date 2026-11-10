package header

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/rpm/tag"
)

func TestEntries(t *testing.T) {
	require.Equal(t, Entry{Type: tag.RPM_STRING_TYPE, Count: 1, Data: []byte("a\x00")}, String("a"))
	require.Equal(t, Entry{Type: tag.RPM_BIN_TYPE, Count: 2, Data: []byte{1, 2}}, Bytes([]byte{1, 2}))
	require.Equal(t, Entry{Type: tag.RPM_STRING_ARRAY_TYPE, Count: 2, Data: []byte("a\x00bc\x00")}, Strings([]string{"a", "bc"}))
	require.Equal(t, Entry{Type: tag.RPM_INT16_TYPE, Count: 2, Data: []byte{0, 1, 0xff, 0xfe}}, Integers([]uint16{1, 0xfffe}))
	require.Equal(t, Entry{Type: tag.RPM_INT32_TYPE, Count: 1, Data: []byte{0, 0, 1, 0}}, Integers([]int32{256}))
	require.Equal(t, Entry{Type: tag.RPM_INT64_TYPE, Count: 1, Data: []byte{0, 0, 0, 0, 0, 0, 1, 0}}, Integers([]uint64{256}))
}

func TestIndexBytes(t *testing.T) {
	b := String("x").IndexBytes(1000, 7)
	require.Len(t, b, IndexEntrySize)
	require.Equal(t, []uint32{1000, tag.RPM_STRING_TYPE, 7, 1}, []uint32{
		binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:]), binary.BigEndian.Uint32(b[8:]), binary.BigEndian.Uint32(b[12:]),
	})
}

func TestBytesLayout(t *testing.T) {
	h := NewIndex(tag.RPMTAG_HEADERIMMUTABLE)
	h.Add(tag.NAME, String("n"))
	h.Add(tag.EPOCH, Integers([]uint32{3}))
	b, err := h.Bytes()
	require.NoError(t, err)

	require.EqualValues(t, IntroMagic, binary.BigEndian.Uint32(b))
	require.EqualValues(t, 3, binary.BigEndian.Uint32(b[8:]), "two entries and the region")
	dataLen := int(binary.BigEndian.Uint32(b[12:]))
	require.Len(t, b, IntroSize+3*IndexEntrySize+dataLen)

	// the region sorts first, then the tags in order
	ids := []uint32{}
	for i := range 3 {
		ids = append(ids, binary.BigEndian.Uint32(b[IntroSize+i*IndexEntrySize:]))
	}
	require.Equal(t, []uint32{tag.RPMTAG_HEADERIMMUTABLE, tag.NAME, tag.EPOCH}, ids)

	// "n\0" is followed by padding that aligns the INT32, then the region data
	data := b[IntroSize+3*IndexEntrySize:]
	require.Equal(t, []byte{'n', 0, 0, 0, 0, 0, 0, 3}, data[:8])
	require.EqualValues(t, 4, binary.BigEndian.Uint32(b[IntroSize+2*IndexEntrySize+8:]), "EPOCH is aligned")
	// the region data is a negative offset: minus the size of the index
	trailer := data[len(data)-IndexEntrySize:]
	require.EqualValues(t, tag.RPMTAG_HEADERIMMUTABLE, binary.BigEndian.Uint32(trailer))
	require.EqualValues(t, -3*IndexEntrySize, int32(binary.BigEndian.Uint32(trailer[8:])))
	require.EqualValues(t, dataLen-IndexEntrySize, binary.BigEndian.Uint32(b[IntroSize+8:]))
}

func TestReserve(t *testing.T) {
	for _, size := range []int{200, 208, 4096} {
		h := NewIndex(tag.RPMTAG_HEADERSIGNATURES)
		h.Add(tag.SIG_SIZE-tag.SIGHEADER_TAG_BASE, Integers([]uint32{1}))
		require.NoError(t, h.Reserve(tag.SIG_RESERVED, size))
		b, err := h.Bytes()
		require.NoError(t, err)
		require.Len(t, b, size)
	}

	// nothing is reserved when the header is already larger
	h := NewIndex(tag.RPMTAG_HEADERSIGNATURES)
	h.Add(tag.NAME, String("a long enough value"))
	require.NoError(t, h.Reserve(tag.SIG_RESERVED, 10))
	require.NotContains(t, h.Entries, tag.SIG_RESERVED)
}

func TestPad8(t *testing.T) {
	for n, want := range map[int]int{0: 0, 1: 7, 7: 1, 8: 0, 9: 7, 16: 0} {
		require.Equal(t, want, Pad8(n), n)
	}
}

func TestTooLarge(t *testing.T) {
	h := NewIndex(tag.RPMTAG_HEADERIMMUTABLE)
	h.Add(tag.NAME, Entry{Type: tag.RPM_STRING_TYPE, Count: 1 << 31, Data: []byte{0}})
	_, err := h.Bytes()
	require.ErrorIs(t, err, ErrHeaderTooLarge)
}

func TestLead(t *testing.T) {
	require.Len(t, Lead("n", "1-1"), LeadSize)
	require.Len(t, LeadV6("n", "1-1"), LeadSize)
}
