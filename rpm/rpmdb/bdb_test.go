package rpmdb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// bdbBuilder writes small BerkeleyDB hash files with the layout the reader
// expects, so that each rule of the walker can be broken on its own.
type bdbBuilder struct {
	order    binary.ByteOrder
	pageSize int
	pages    [][]byte
}

func newBDBBuilder(order binary.ByteOrder, pageSize int) *bdbBuilder {
	b := &bdbBuilder{order: order, pageSize: pageSize}
	meta := make([]byte, pageSize)
	order.PutUint32(meta[bdbMagicOffset:], bdbHashMagic)
	order.PutUint32(meta[16:], 9)
	order.PutUint32(meta[bdbOffPageSize:], uint32(pageSize))
	meta[bdbOffType] = pageHashMeta
	b.pages = append(b.pages, meta)

	return b
}

func (b *bdbBuilder) addPage(t byte) []byte {
	p := make([]byte, b.pageSize)
	p[bdbOffType] = t
	b.pages = append(b.pages, p)
	b.order.PutUint32(p[8:], uint32(len(b.pages)-1))

	return p
}

// bucket adds a hash page whose items are the given (already encoded) items,
// the way BerkeleyDB places them: from the end of the page, in order.
func (b *bdbBuilder) bucket(t byte, items ...[]byte) []byte {
	p := b.addPage(t)
	b.order.PutUint16(p[bdbOffEntries:], uint16(len(items)))

	end := b.pageSize
	for i, it := range items {
		end -= len(it)
		copy(p[end:], it)
		b.order.PutUint16(p[bdbPageHeader+2*i:], uint16(end))
	}

	b.order.PutUint16(p[bdbOffLength:], uint16(end))

	return p
}

// overflow adds a chain of overflow pages that holds data, and returns the
// number of its first page.
func (b *bdbBuilder) overflow(data []byte) uint32 {
	first := uint32(len(b.pages))
	room := b.pageSize - bdbPageHeader

	for len(data) > 0 {
		n := min(room, len(data))
		p := b.addPage(pageOverflow)
		copy(p[bdbPageHeader:], data[:n])
		b.order.PutUint16(p[bdbOffLength:], uint16(n))

		data = data[n:]
		if len(data) > 0 {
			b.order.PutUint32(p[bdbOffNext:], uint32(len(b.pages)))
		}
	}

	return first
}

func (b *bdbBuilder) keyData(v []byte) []byte { return append([]byte{itemKeyData}, v...) }

func (b *bdbBuilder) offPage(pgno, length uint32) []byte {
	it := make([]byte, offPageSize)
	it[0] = itemOffPage
	b.order.PutUint32(it[4:], pgno)
	b.order.PutUint32(it[8:], length)

	return it
}

func (b *bdbBuilder) bytes() []byte {
	b.order.PutUint32(b.pages[0][bdbOffLastPage:], uint32(len(b.pages)-1))

	return bytes.Join(b.pages, nil)
}

var testKey = []byte{1, 0, 0, 0}

func openBDBBytes(t *testing.T, data []byte, opts Options) (*bdbStore, error) {
	t.Helper()

	return newBDB(bytes.NewReader(data), int64(len(data)), opts.normalized())
}

func collect(t *testing.T, s store) (blobs [][]byte, err error) {
	t.Helper()

	for blob, e := range s.blobs(t.Context()) {
		if e != nil {
			return blobs, e
		}

		blobs = append(blobs, bytes.Clone(blob))
	}

	return blobs, nil
}

func TestBDBBuilderRoundTrip(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789"), 300)

	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, bucketType := range []byte{pageHash, pageHashUnsorted} {
			b := newBDBBuilder(order, 512)
			first := b.overflow(big)
			b.bucket(bucketType,
				b.keyData(testKey), b.keyData([]byte("small")),
				b.keyData(testKey), b.offPage(first, uint32(len(big))),
				// Duplicate and off-page duplicate values are left alone.
				b.keyData(testKey), []byte{itemDuplicate, 0, 0, 0},
				b.keyData(testKey), []byte{itemOffDup, 0, 0, 0},
			)
			// Pages of other types are ignored.
			b.addPage(0)

			s, err := openBDBBytes(t, b.bytes(), Options{})
			require.NoError(t, err)

			got, err := collect(t, s)
			require.NoError(t, err)
			assert.Equal(t, [][]byte{[]byte("small"), big}, got)
			require.NoError(t, s.close())
		}
	}
}

func TestBDBRejectsDamagedContainers(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 2000)

	build := func(mutate func(b *bdbBuilder, first uint32)) []byte {
		b := newBDBBuilder(binary.LittleEndian, 512)
		first := b.overflow(big)
		b.bucket(pageHash, b.keyData(testKey), b.offPage(first, uint32(len(big))))

		if mutate != nil {
			mutate(b, first)
		}

		return b.bytes()
	}

	cases := map[string]func(b *bdbBuilder, first uint32){
		"overflow chain loops": func(b *bdbBuilder, first uint32) {
			// One byte per visit, forever: the budget ends it.
			b.order.PutUint16(b.pages[first][bdbOffLength:], 1)
			b.order.PutUint32(b.pages[first][bdbOffNext:], first)
		},
		"overflow page is not one": func(b *bdbBuilder, first uint32) { b.pages[first][bdbOffType] = pageHash },
		"overflow page holds nothing": func(b *bdbBuilder, first uint32) {
			b.order.PutUint16(b.pages[first][bdbOffLength:], 0)
		},
		"overflow page holds too much": func(b *bdbBuilder, first uint32) {
			b.order.PutUint16(b.pages[first][bdbOffLength:], 511)
		},
		"overflow chain leaves the file": func(b *bdbBuilder, first uint32) {
			b.order.PutUint32(b.pages[first][bdbOffNext:], 9999)
		},
		"chain ends early": func(b *bdbBuilder, first uint32) {
			b.order.PutUint32(b.pages[first+3][bdbOffNext:], 0)
		},
		"item count exceeds the page": func(b *bdbBuilder, first uint32) {
			b.order.PutUint16(b.pages[len(b.pages)-1][bdbOffEntries:], 600)
		},
		"item starts inside the offset table": func(b *bdbBuilder, first uint32) {
			b.order.PutUint16(b.pages[len(b.pages)-1][bdbPageHeader+2:], 4)
		},
		"item ends beyond the page": func(b *bdbBuilder, first uint32) {
			b.order.PutUint16(b.pages[len(b.pages)-1][bdbPageHeader:], 60000)
		},
		"item is empty": func(b *bdbBuilder, first uint32) {
			p := b.pages[len(b.pages)-1]
			b.order.PutUint16(p[bdbPageHeader+2:], b.order.Uint16(p[bdbPageHeader:]))
		},
		"item type unknown": func(b *bdbBuilder, first uint32) {
			p := b.pages[len(b.pages)-1]
			p[b.order.Uint16(p[bdbPageHeader+2:])] = 77
		},
		"off page item is cut": func(b *bdbBuilder, first uint32) {
			p := b.pages[len(b.pages)-1]
			// Make the value start 4 bytes before the key: shorter than an off
			// page item.
			b.order.PutUint16(p[bdbPageHeader:], b.order.Uint16(p[bdbPageHeader+2:])+4)
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := openBDBBytes(t, build(mutate), Options{})
			require.NoError(t, err)

			_, err = collect(t, s)
			require.ErrorIs(t, err, ErrCorrupt)
		})
	}

	// The unmodified file is fine.
	s, err := openBDBBytes(t, build(nil), Options{})
	require.NoError(t, err)

	got, err := collect(t, s)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{big}, got)
}

func TestBDBHostileOverflowHasABudget(t *testing.T) {
	// Many values that all point at the same chain: each is valid on its own,
	// together they would make the reader read far more than the file holds.
	b := newBDBBuilder(binary.LittleEndian, 512)
	first := b.overflow(bytes.Repeat([]byte("y"), 4000))

	var items [][]byte

	for range 20 {
		items = append(items, b.keyData(testKey), b.offPage(first, 4000))
	}

	b.bucket(pageHash, items...)

	s, err := openBDBBytes(t, b.bytes(), Options{})
	require.NoError(t, err)

	got, err := collect(t, s)
	require.ErrorIs(t, err, ErrCorrupt)
	assert.Less(t, len(got), 20)
}

func TestBDBOversizedValuesAreSkipped(t *testing.T) {
	b := newBDBBuilder(binary.LittleEndian, 512)
	first := b.overflow(bytes.Repeat([]byte("z"), 3000))
	b.bucket(pageHash,
		b.keyData(testKey), b.offPage(first, 3000),
		b.keyData(testKey), b.keyData([]byte("ok")),
		// A length field that lies: far larger than any file.
		b.keyData(testKey), b.offPage(first, 0xffffffff),
	)

	var log bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))

	s, err := openBDBBytes(t, b.bytes(), Options{MaxBlobBytes: 1000, Logger: logger})
	require.NoError(t, err)

	got, err := collect(t, s)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("ok")}, got)
	assert.Contains(t, log.String(), "oversized")
}

func TestBDBLengthLongerThanChain(t *testing.T) {
	// The value claims fewer bytes than its pages hold: only that many are
	// returned.
	b := newBDBBuilder(binary.LittleEndian, 512)
	first := b.overflow(bytes.Repeat([]byte("q"), 1000))
	b.bucket(pageHash, b.keyData(testKey), b.offPage(first, 700))

	s, err := openBDBBytes(t, b.bytes(), Options{})
	require.NoError(t, err)

	got, err := collect(t, s)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Len(t, got[0], 700)
}

func TestBDBMetadataChecks(t *testing.T) {
	good := newBDBBuilder(binary.LittleEndian, 512).bytes()

	_, err := openBDBBytes(t, good, Options{})
	require.NoError(t, err)

	mutate := func(f func(b []byte)) []byte {
		b := bytes.Clone(good)
		f(b)

		return b
	}

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"too short", good[:100], ErrCorrupt},
		{"bad magic", mutate(func(b []byte) { b[bdbMagicOffset] ^= 0xff }), ErrFormat},
		{"not a meta page", mutate(func(b []byte) { b[bdbOffType] = pageHash }), ErrCorrupt},
		{"encrypted", mutate(func(b []byte) { b[bdbOffEncrypt] = 1 }), ErrUnsupported},
		{"checksummed", mutate(func(b []byte) { b[bdbOffMetaFlags] = bdbMetaFlagSum }), ErrUnsupported},
		{"page size 256", mutate(func(b []byte) { binary.LittleEndian.PutUint32(b[bdbOffPageSize:], 256) }), ErrCorrupt},
		{"page size 1000", mutate(func(b []byte) { binary.LittleEndian.PutUint32(b[bdbOffPageSize:], 1000) }), ErrCorrupt},
		{"page size 1M", mutate(func(b []byte) { binary.LittleEndian.PutUint32(b[bdbOffPageSize:], 1<<20) }), ErrCorrupt},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := openBDBBytes(t, c.data, Options{})
			require.ErrorIs(t, err, c.want)
		})
	}
}

func TestBDBTruncatedFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "Packages.bdb"))
	require.NoError(t, err)

	// Cut anywhere past the metadata: the walk reaches the cut and fails, or
	// the cut happens to fall on the last bucket and costs nothing.
	for _, cut := range []int{4096, 4096 + 100, len(data) / 2, len(data) - 4096, len(data) - 1} {
		s, err := openBDBBytes(t, data[:cut], Options{})
		require.NoError(t, err)

		_, err = collect(t, s)
		if err != nil {
			require.ErrorIs(t, err, ErrCorrupt, "cut at %d", cut)
		}
	}
}

// failingReader serves the first n bytes, then fails.
type failingReader struct {
	data []byte
	n    int64
}

var errDisk = errors.New("disk on fire")

func (f failingReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= f.n {
		return 0, errDisk
	}

	return copy(p, f.data[off:]), nil
}

func TestBDBReadError(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "Packages.bdb"))
	require.NoError(t, err)

	s, err := newBDB(failingReader{data, 8192}, int64(len(data)), Options{}.normalized())
	require.NoError(t, err)

	_, err = collect(t, s)
	require.ErrorIs(t, err, errDisk)
	require.NoError(t, s.close())

	// ... and while reading the metadata.
	_, err = newBDB(failingReader{data, 0}, int64(len(data)), Options{}.normalized())
	require.ErrorIs(t, err, ErrCorrupt)
}

func TestBDBContextCancelled(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "Packages.bdb"))
	require.NoError(t, err)

	s, err := openBDBBytes(t, data, Options{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	for _, err := range s.blobs(ctx) {
		require.ErrorIs(t, err, context.Canceled)
	}
}

func TestBDBFixtureBlobs(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "Packages.bdb"))
	require.NoError(t, err)

	s, err := openBDBBytes(t, data, Options{})
	require.NoError(t, err)

	got, err := collect(t, s)
	require.NoError(t, err)
	// Four packages and the counter rpm keeps under key 0.
	assert.Len(t, got, 5)
}

func FuzzBDB(f *testing.F) {
	if data, err := os.ReadFile(filepath.Join("testdata", "Packages.bdb")); err == nil {
		f.Add(data)
	}

	b := newBDBBuilder(binary.LittleEndian, 512)
	first := b.overflow(bytes.Repeat([]byte("f"), 900))
	b.bucket(pageHash, b.keyData(testKey), b.keyData([]byte("v")), b.keyData(testKey), b.offPage(first, 900))
	f.Add(b.bytes())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := newBDB(bytes.NewReader(data), int64(len(data)), Options{MaxBlobBytes: 1 << 20}.normalized())
		if err != nil {
			return
		}

		for blob, err := range s.blobs(context.Background()) {
			if err != nil {
				break
			}

			decodeBlob(blob)
		}
	})
}

// decodeBlob runs the decoders over a record the way the reader does.
func decodeBlob(blob []byte) {
	if hdr, err := rpm.ReadHeaderBlob(blob, rpm.HeaderLimits{MaxDataSize: 1 << 20}); err == nil {
		_, _ = hdr.InstalledPackage(rpm.PackageLimits{})
		_, _ = hdr.GetStrings(tag.PROVIDENAME)
	}
}
