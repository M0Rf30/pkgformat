package rpmdb

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/adler32"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/rpm"
)

// ndbBlob encodes a blob the way rpm writes it.
func ndbBlob(pkgidx uint32, data []byte) []byte {
	le := binary.LittleEndian
	total := (ndbHeadSize + len(data) + ndbTailSize + ndbBlockSize - 1) / ndbBlockSize * ndbBlockSize
	blob := make([]byte, total)
	le.PutUint32(blob, ndbHeadMagic)
	le.PutUint32(blob[4:], pkgidx)
	le.PutUint32(blob[8:], 1)
	le.PutUint32(blob[12:], uint32(len(data)))
	copy(blob[ndbHeadSize:], data)

	tail := blob[total-ndbTailSize:]
	le.PutUint32(tail, adler32.Checksum(blob[:total-ndbTailSize]))
	le.PutUint32(tail[4:], uint32(len(data)))
	le.PutUint32(tail[8:], ndbTailMagic)

	return blob
}

// ndbFile lays out a file with one page of slots and the blobs after it.
func ndbFile(blobs ...[]byte) []byte {
	le := binary.LittleEndian
	file := make([]byte, ndbPageSize)
	le.PutUint32(file, ndbMagic)
	le.PutUint32(file[12:], 1)
	le.PutUint32(file[16:], uint32(len(blobs)+1))

	for o := ndbHeaderSize; o < ndbPageSize; o += ndbSlotSize {
		le.PutUint32(file[o:], ndbSlotMagic)
	}

	for i, blob := range blobs {
		slot := file[ndbHeaderSize+i*ndbSlotSize:]
		le.PutUint32(slot[4:], uint32(i+1))
		le.PutUint32(slot[8:], uint32(len(file)/ndbBlockSize))
		le.PutUint32(slot[12:], uint32(len(blob)/ndbBlockSize))
		file = append(file, blob...)
	}

	return file
}

func openNDBBytes(t *testing.T, data []byte, opts Options) (*ndbStore, error) {
	t.Helper()

	return newNDB(bytes.NewReader(data), int64(len(data)), opts.normalized())
}

func TestNDBBuilderRoundTrip(t *testing.T) {
	data := ndbFile(ndbBlob(1, []byte("first")), ndbBlob(2, bytes.Repeat([]byte("b"), 5000)), ndbBlob(3, nil))

	s, err := openNDBBytes(t, data, Options{})
	require.NoError(t, err)

	got, err := collect(t, s)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, []byte("first"), got[0])
	assert.Len(t, got[1], 5000)
	assert.Empty(t, got[2])
	require.NoError(t, s.close())
}

func TestNDBHeaderChecks(t *testing.T) {
	good := ndbFile(ndbBlob(1, []byte("x")))

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
		{"short", good[:100], ErrCorrupt},
		{"magic", mutate(func(b []byte) { b[0] = 'X' }), ErrFormat},
		{"version", mutate(func(b []byte) { b[4] = 1 }), ErrUnsupported},
		{"no slot pages", mutate(func(b []byte) { b[12] = 0 }), ErrCorrupt},
		{"slot pages beyond the file", mutate(func(b []byte) { b[12] = 200 }), ErrCorrupt},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := openNDBBytes(t, c.data, Options{})
			require.ErrorIs(t, err, c.want)
		})
	}

	_, err := newNDB(failingReader{good, 0}, int64(len(good)), Options{}.normalized())
	require.ErrorIs(t, err, ErrCorrupt)
}

func TestNDBDamagedSlotsAreErrors(t *testing.T) {
	le := binary.LittleEndian
	good := ndbFile(ndbBlob(1, []byte("x")))
	slot := ndbHeaderSize

	cases := map[string]func(b []byte){
		"slot magic":        func(b []byte) { b[ndbHeaderSize+3*ndbSlotSize] = 0 },
		"slot of no record": func(b []byte) { le.PutUint32(b[slot+4:], 0) },
		"empty blob":        func(b []byte) { le.PutUint32(b[slot+12:], 0) },
		"blob in the slots": func(b []byte) { le.PutUint32(b[slot+8:], 10) },
		"blob past the end": func(b []byte) { le.PutUint32(b[slot+12:], 1<<20) },
		"offset overflow":   func(b []byte) { le.PutUint32(b[slot+8:], 0xffffffff) },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			data := bytes.Clone(good)
			mutate(data)

			s, err := openNDBBytes(t, data, Options{})
			require.NoError(t, err)

			_, err = collect(t, s)
			require.ErrorIs(t, err, ErrCorrupt)
		})
	}
}

func TestNDBSharedBlobsHaveABudget(t *testing.T) {
	le := binary.LittleEndian
	// One large blob that 199 more slots claim as theirs: each is valid on its
	// own, together they would make the reader read far more than the file
	// holds.
	data := ndbFile(ndbBlob(1, bytes.Repeat([]byte("s"), 3000)))

	for i := 1; i < 200; i++ {
		slot := data[ndbHeaderSize+i*ndbSlotSize:]
		copy(slot, data[ndbHeaderSize:ndbHeaderSize+ndbSlotSize])
		le.PutUint32(slot[4:], 1)
	}

	s, err := openNDBBytes(t, data, Options{})
	require.NoError(t, err)

	got, err := collect(t, s)
	require.ErrorIs(t, err, ErrCorrupt)
	assert.Less(t, len(got), 199)
}

func TestNDBDamagedBlobsAreSkipped(t *testing.T) {
	le := binary.LittleEndian

	cases := map[string]func(blob []byte){
		"head magic":    func(b []byte) { b[0] = 0 },
		"record number": func(b []byte) { le.PutUint32(b[4:], 99) },
		"length":        func(b []byte) { le.PutUint32(b[12:], 100000) },
		"tail length":   func(b []byte) { le.PutUint32(b[len(b)-8:], 3) },
		"tail magic":    func(b []byte) { b[len(b)-1] = 0 },
		"checksum":      func(b []byte) { b[ndbHeadSize] ^= 1 },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad := ndbBlob(1, []byte("damaged"))
			mutate(bad)

			var log bytes.Buffer

			logger := slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))

			s, err := openNDBBytes(t, ndbFile(bad, ndbBlob(2, []byte("fine"))), Options{Logger: logger})
			require.NoError(t, err)

			got, err := collect(t, s)
			require.NoError(t, err)
			assert.Equal(t, [][]byte{[]byte("fine")}, got)
			assert.Contains(t, log.String(), "damaged ndb blob")
		})
	}

	// An oversized blob is skipped without reading it into a buffer.
	s, err := openNDBBytes(t, ndbFile(ndbBlob(1, bytes.Repeat([]byte("o"), 5000)), ndbBlob(2, []byte("fine"))), Options{MaxBlobBytes: 100})
	require.NoError(t, err)

	got, err := collect(t, s)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("fine")}, got)

	// A file the reader cannot read past the slots.
	data := ndbFile(ndbBlob(1, []byte("x")))
	s, err = newNDB(failingReader{data, ndbPageSize}, int64(len(data)), Options{}.normalized())
	require.NoError(t, err)

	got, err = collect(t, s)
	require.NoError(t, err)
	assert.Empty(t, got)

	// ... and the slot pages themselves.
	s, err = newNDB(failingReader{data[:ndbHeaderSize+1], ndbHeaderSize}, int64(len(data)), Options{}.normalized())
	require.NoError(t, err)

	_, err = collect(t, s)
	require.ErrorIs(t, err, ErrCorrupt)
}

func TestNDBContextCancelled(t *testing.T) {
	s, err := openNDBBytes(t, ndbFile(ndbBlob(1, []byte("x"))), Options{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var last error

	for _, err := range s.blobs(ctx) {
		last = err
	}

	require.ErrorIs(t, last, context.Canceled)
}

func TestNDBFixtureBlobs(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "Packages.ndb"))
	require.NoError(t, err)

	s, err := openNDBBytes(t, data, Options{})
	require.NoError(t, err)

	got, err := collect(t, s)
	require.NoError(t, err)
	assert.Len(t, got, 3)

	for _, blob := range got {
		hdr, err := rpm.ReadHeaderBlob(blob, rpm.HeaderLimits{})
		require.NoError(t, err)

		pkg, err := hdr.InstalledPackage(rpm.PackageLimits{})
		require.NoError(t, err)
		assert.NotEmpty(t, pkg.Name)
	}
}

func FuzzNDB(f *testing.F) {
	if data, err := os.ReadFile(filepath.Join("testdata", "Packages.ndb")); err == nil {
		f.Add(data)
	}

	f.Add(ndbFile(ndbBlob(1, []byte("seed")), ndbBlob(2, bytes.Repeat([]byte("n"), 300))))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := newNDB(bytes.NewReader(data), int64(len(data)), Options{MaxBlobBytes: 1 << 20}.normalized())
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
