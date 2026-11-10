package rpmdb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
)

// The BerkeleyDB hash database of rpm 4.15 and earlier is a file of fixed size
// pages. Page 0 is the metadata page. The other pages are hash buckets (type
// P_HASH, or P_HASH_UNSORTED in older files), which hold key and data items
// side by side, or overflow pages (P_OVERFLOW), which hold the value of an item
// that does not fit in a bucket as a chain. rpm keys each record by its number
// and stores the header image of the package as the value; key 0 holds a
// counter.
//
// Every page starts with a 26 byte header:
//
//	 0  lsn          8 bytes
//	 8  pgno         page number
//	12  prev_pgno
//	16  next_pgno    next page of an overflow chain
//	20  entries      number of items of a bucket page
//	22  hf_offset    offset of the lowest item of a bucket page; the number of
//	                 data bytes of an overflow page
//	24  level
//	25  type
//
// followed, on a bucket page, by entries 16 bit item offsets. Items grow from
// the end of the page; item i ends where item i-1 starts. An item is a type
// byte and its payload: H_KEYDATA holds the bytes themselves, H_OFFPAGE holds
// the number of the first overflow page (offset 4) and the total length
// (offset 8) of a value stored elsewhere.
//
// The metadata page holds, after the common header, the magic number at offset
// 12, the version at 16, the page size at 20, the encryption algorithm at 24,
// the page type at 25, the metadata flags at 26 and the number of the last page
// at 32. All integers use the byte order of the machine that created the file.
const (
	bdbPageHeader = 26
	bdbMinPage    = 512
	bdbMaxPage    = 65536

	bdbOffNext    = 16
	bdbOffEntries = 20
	bdbOffLength  = 22
	bdbOffType    = 25

	bdbOffPageSize  = 20
	bdbOffEncrypt   = 24
	bdbOffMetaFlags = 26
	bdbOffLastPage  = 32
	bdbMetaFlagSum  = 0x01

	pageHashUnsorted = 2
	pageOverflow     = 7
	pageHashMeta     = 8
	pageHash         = 13

	itemKeyData   = 1
	itemDuplicate = 2
	itemOffPage   = 3
	itemOffDup    = 4
	offPageSize   = 12
)

type bdbStore struct {
	r        io.ReaderAt
	closer   io.Closer
	size     int64
	order    binary.ByteOrder
	pageSize int
	pages    uint32
	maxBlob  int
	log      *slog.Logger
}

// newBDB checks the metadata page of a BerkeleyDB hash database. It takes
// ownership of r, which must be an io.Closer too when it is to be closed.
func newBDB(r io.ReaderAt, size int64, opts Options) (*bdbStore, error) {
	if size < bdbMinPage {
		return nil, fmt.Errorf("%w: a BerkeleyDB file of %d bytes", ErrCorrupt, size)
	}

	meta := make([]byte, bdbMinPage)
	if _, err := r.ReadAt(meta, 0); err != nil {
		return nil, fmt.Errorf("%w: reading the metadata page: %w", ErrCorrupt, err)
	}

	var order binary.ByteOrder = binary.LittleEndian
	if order.Uint32(meta[bdbMagicOffset:]) != bdbHashMagic {
		order = binary.BigEndian
	}

	if order.Uint32(meta[bdbMagicOffset:]) != bdbHashMagic {
		return nil, fmt.Errorf("%w: BerkeleyDB magic number", ErrFormat)
	}

	if meta[bdbOffType] != pageHashMeta {
		return nil, fmt.Errorf("%w: page 0 is not a hash metadata page", ErrCorrupt)
	}

	if meta[bdbOffEncrypt] != 0 {
		return nil, fmt.Errorf("%w: encrypted BerkeleyDB file", ErrUnsupported)
	}

	if meta[bdbOffMetaFlags]&bdbMetaFlagSum != 0 {
		return nil, fmt.Errorf("%w: BerkeleyDB pages with checksums", ErrUnsupported)
	}

	pageSize := int(order.Uint32(meta[bdbOffPageSize:]))
	if pageSize < bdbMinPage || pageSize > bdbMaxPage || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("%w: BerkeleyDB page size %d", ErrCorrupt, pageSize)
	}

	// The file may be shorter than the metadata claims (an interrupted
	// write): read what is there, and let the items that point beyond it
	// fail.
	pages := min(int64(order.Uint32(meta[bdbOffLastPage:]))+1, size/int64(pageSize))

	s := &bdbStore{
		r: r, size: size, order: order, pageSize: pageSize,
		pages: uint32(pages), maxBlob: opts.MaxBlobBytes, log: opts.Logger,
	}

	if c, ok := r.(io.Closer); ok {
		s.closer = c
	}

	return s, nil
}

func (s *bdbStore) close() error {
	if s.closer == nil {
		return nil
	}

	return s.closer.Close()
}

// readPage reads page pgno into buf, which is one page long.
func (s *bdbStore) readPage(buf []byte, pgno uint32) error {
	if pgno >= s.pages {
		return fmt.Errorf("%w: page %d is outside the file (%d pages)", ErrCorrupt, pgno, s.pages)
	}

	if _, err := s.r.ReadAt(buf, int64(pgno)*int64(s.pageSize)); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: page %d is truncated", ErrCorrupt, pgno)
		}

		return fmt.Errorf("rpmdb: reading page %d: %w", pgno, err)
	}

	return nil
}

func (s *bdbStore) blobs(ctx context.Context) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		w := &bdbWalk{s: s, page: make([]byte, s.pageSize), ovf: make([]byte, s.pageSize), budget: s.size}

		for pgno := uint32(1); pgno < s.pages; pgno++ {
			if err := ctx.Err(); err != nil {
				yield(nil, err)

				return
			}

			if !w.bucket(pgno, yield) {
				return
			}
		}
	}
}

// bdbWalk is the state of one pass over a file.
type bdbWalk struct {
	s    *bdbStore
	page []byte
	ovf  []byte
	blob []byte
	// budget is how many more bytes of overflow pages may be read: what the
	// file holds. A well formed file references each page once, so a file
	// that makes the reader read more is hostile.
	budget int64
}

// bucket yields the values of the hash page pgno. It returns false when the
// iteration is over: the consumer stopped, or an error was yielded.
func (w *bdbWalk) bucket(pgno uint32, yield func([]byte, error) bool) bool {
	s := w.s
	if err := s.readPage(w.page, pgno); err != nil {
		return fail(yield, err)
	}

	if t := w.page[bdbOffType]; t != pageHash && t != pageHashUnsorted {
		return true
	}

	order, page := s.order, w.page
	entries := int(order.Uint16(page[bdbOffEntries:]))
	table := bdbPageHeader + 2*entries

	if table > len(page) {
		return fail(yield, fmt.Errorf("%w: page %d claims %d items", ErrCorrupt, pgno, entries))
	}

	// Items come in pairs, a key then its value: the odd ones are values.
	for i := 1; i < entries; i += 2 {
		off := int(order.Uint16(page[bdbPageHeader+2*i:]))
		end := int(order.Uint16(page[bdbPageHeader+2*(i-1):]))

		if end > len(page) || off < table || off >= end {
			return fail(yield, fmt.Errorf("%w: page %d item %d is outside the page", ErrCorrupt, pgno, i))
		}

		var value []byte

		switch page[off] {
		case itemKeyData:
			value = page[off+1 : end]
		case itemOffPage:
			if end-off < offPageSize {
				return fail(yield, fmt.Errorf("%w: page %d item %d is truncated", ErrCorrupt, pgno, i))
			}

			first, length := order.Uint32(page[off+4:]), order.Uint32(page[off+8:])
			if int64(length) > int64(s.maxBlob) {
				s.log.Debug("rpmdb: skipping an oversized record", "page", pgno, "bytes", length)

				continue
			}

			var err error
			if value, err = w.overflow(first, length); err != nil {
				return fail(yield, err)
			}
		case itemDuplicate, itemOffDup:
			continue
		default:
			return fail(yield, fmt.Errorf("%w: page %d item %d has type %d", ErrCorrupt, pgno, i, page[off]))
		}

		if !yield(value, nil) {
			return false
		}
	}

	return true
}

// overflow assembles the value of length bytes that starts on overflow page
// first.
func (w *bdbWalk) overflow(first, length uint32) ([]byte, error) {
	s := w.s
	w.blob = w.blob[:0]

	for pgno, left := first, int(length); left > 0; {
		if w.budget -= int64(s.pageSize); w.budget < 0 {
			return nil, fmt.Errorf("%w: overflow chains hold more than the file", ErrCorrupt)
		}

		if err := s.readPage(w.ovf, pgno); err != nil {
			return nil, err
		}

		if w.ovf[bdbOffType] != pageOverflow {
			return nil, fmt.Errorf("%w: page %d is not an overflow page", ErrCorrupt, pgno)
		}

		n := int(s.order.Uint16(w.ovf[bdbOffLength:]))
		if n == 0 || n > s.pageSize-bdbPageHeader {
			return nil, fmt.Errorf("%w: overflow page %d holds %d bytes", ErrCorrupt, pgno, n)
		}

		n = min(n, left)
		w.blob = append(w.blob, w.ovf[bdbPageHeader:bdbPageHeader+n]...)
		left -= n
		pgno = s.order.Uint32(w.ovf[bdbOffNext:])
	}

	return w.blob, nil
}

// fail yields err and reports the iteration as over.
func fail(yield func([]byte, error) bool, err error) bool {
	yield(nil, err)

	return false
}
