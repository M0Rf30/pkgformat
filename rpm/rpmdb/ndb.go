package rpmdb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"iter"
	"log/slog"
)

// The "ndb" database (Packages.db) of openSUSE and SUSE Linux Enterprise is a
// file of 4096 byte pages made of 16 byte blocks, all integers little endian.
// The first slotnpages pages are an index of 16 byte slots; the blobs follow.
//
// The file starts with a 32 byte header that takes the place of the first two
// slots:
//
//	 0  magic        "RpmP"
//	 4  version      0
//	 8  generation
//	12  slotnpages   number of pages of slots
//	16  nextpkgidx
//
// Each slot is
//
//	 0  magic        "Slot"
//	 4  pkgidx       record number, 0 in no used slot
//	 8  blkoff       offset of the blob in blocks, 0 for a free slot
//	12  blkcnt       size of the blob in blocks
//
// A blob is a header image of the package between a head and a tail, padded
// with zeros to whole blocks:
//
//	 0  magic        "BlbS"
//	 4  pkgidx
//	 8  generation
//	12  bloblen      size of the image
//	16  the image, then the padding
//	..  adler32      of everything before it
//	..  bloblen
//	..  magic        "BlbE"
const (
	ndbPageSize   = 4096
	ndbBlockSize  = 16
	ndbSlotSize   = 16
	ndbHeaderSize = 32

	ndbVersion   = 0
	ndbSlotMagic = 'S' | 'l'<<8 | 'o'<<16 | 't'<<24
	ndbHeadMagic = 'B' | 'l'<<8 | 'b'<<16 | 'S'<<24
	ndbTailMagic = 'B' | 'l'<<8 | 'b'<<16 | 'E'<<24
	ndbHeadSize  = 16
	ndbTailSize  = 12
)

type ndbStore struct {
	r         io.ReaderAt
	closer    io.Closer
	size      int64
	slotPages uint32
	maxBlob   int
	log       *slog.Logger
}

// newNDB checks the header of an ndb database. It closes r on close when r is
// an io.Closer.
func newNDB(r io.ReaderAt, size int64, opts Options) (*ndbStore, error) {
	if size < ndbPageSize {
		return nil, fmt.Errorf("%w: an ndb file of %d bytes", ErrCorrupt, size)
	}

	head := make([]byte, ndbHeaderSize)
	if _, err := r.ReadAt(head, 0); err != nil {
		return nil, fmt.Errorf("%w: reading the header: %w", ErrCorrupt, err)
	}

	le := binary.LittleEndian

	if le.Uint32(head) != ndbMagic {
		return nil, fmt.Errorf("%w: ndb magic number", ErrFormat)
	}

	if v := le.Uint32(head[4:]); v != ndbVersion {
		return nil, fmt.Errorf("%w: ndb version %d", ErrUnsupported, v)
	}

	slotPages := le.Uint32(head[12:])
	if slotPages == 0 || int64(slotPages)*ndbPageSize > size {
		return nil, fmt.Errorf("%w: %d pages of slots in a file of %d bytes", ErrCorrupt, slotPages, size)
	}

	s := &ndbStore{r: r, size: size, slotPages: slotPages, maxBlob: opts.MaxBlobBytes, log: opts.Logger}
	if c, ok := r.(io.Closer); ok {
		s.closer = c
	}

	return s, nil
}

func (s *ndbStore) close() error {
	if s.closer == nil {
		return nil
	}

	return s.closer.Close()
}

func (s *ndbStore) blobs(ctx context.Context) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		var (
			page = make([]byte, ndbPageSize)
			buf  []byte
			// budget is how many more bytes of blobs may be read: what the
			// file holds. A well formed file has each blob once; slots that
			// share one are hostile.
			budget  = s.size
			minBlob = uint64(s.slotPages) * (ndbPageSize / ndbBlockSize)
			le      = binary.LittleEndian
		)

		for p := range s.slotPages {
			if _, err := s.r.ReadAt(page, int64(p)*ndbPageSize); err != nil {
				yield(nil, fmt.Errorf("%w: reading slot page %d: %w", ErrCorrupt, p, err))

				return
			}

			start := 0
			if p == 0 {
				start = ndbHeaderSize
			}

			for o := start; o < ndbPageSize; o += ndbSlotSize {
				if err := ctx.Err(); err != nil {
					yield(nil, err)

					return
				}

				slot := page[o : o+ndbSlotSize]
				if le.Uint32(slot) != ndbSlotMagic {
					yield(nil, fmt.Errorf("%w: bad slot magic in page %d", ErrCorrupt, p))

					return
				}

				pkgidx, blkoff, blkcnt := le.Uint32(slot[4:]), uint64(le.Uint32(slot[8:])), uint64(le.Uint32(slot[12:]))
				if blkoff == 0 {
					continue // free
				}

				if pkgidx == 0 || blkcnt == 0 || blkoff < minBlob || (blkoff+blkcnt)*ndbBlockSize > uint64(s.size) {
					yield(nil, fmt.Errorf("%w: slot %d of page %d points outside the file", ErrCorrupt, o/ndbSlotSize, p))

					return
				}

				if budget -= int64(blkcnt) * ndbBlockSize; budget < 0 {
					yield(nil, fmt.Errorf("%w: blobs hold more than the file", ErrCorrupt))

					return
				}

				var (
					blob []byte
					err  error
				)

				if blob, buf, err = s.readBlob(buf, pkgidx, int64(blkoff)*ndbBlockSize, int(blkcnt)); err != nil {
					s.log.Debug("rpmdb: skipping a damaged ndb blob", "pkgidx", pkgidx, "error", err)

					continue
				}

				if !yield(blob, nil) {
					return
				}
			}
		}
	}
}

// errBlob marks a blob that is damaged on its own, which skips the record.
var errBlob = errors.New("bad blob")

// readBlob reads and checks the blob of blkcnt blocks at off, using buf as
// the buffer, and returns the image it holds with the possibly grown buffer.
func (s *ndbStore) readBlob(buf []byte, pkgidx uint32, off int64, blkcnt int) (blob, grown []byte, err error) {
	le := binary.LittleEndian
	total := blkcnt * ndbBlockSize

	if cap(buf) < total {
		// total is at most the size of the file; the image is at most
		// maxBlob, so only blobs worth reading get a buffer.
		if total > s.maxBlob+ndbHeadSize+ndbTailSize+ndbBlockSize {
			return nil, buf, fmt.Errorf("%w: %d bytes exceed the limit", errBlob, total)
		}

		buf = make([]byte, total)
	}

	buf = buf[:total]
	if _, err := s.r.ReadAt(buf, off); err != nil {
		return nil, buf, fmt.Errorf("%w: %w", errBlob, err)
	}

	if le.Uint32(buf) != ndbHeadMagic || le.Uint32(buf[4:]) != pkgidx {
		return nil, buf, fmt.Errorf("%w: head", errBlob)
	}

	length := uint64(le.Uint32(buf[12:]))
	if (ndbHeadSize+length+ndbTailSize+ndbBlockSize-1)/ndbBlockSize != uint64(blkcnt) {
		return nil, buf, fmt.Errorf("%w: size does not match the block count", errBlob)
	}

	tail := buf[total-ndbTailSize:]
	if le.Uint32(tail[4:]) != uint32(length) || le.Uint32(tail[8:]) != ndbTailMagic {
		return nil, buf, fmt.Errorf("%w: tail", errBlob)
	}

	if le.Uint32(tail) != adler32.Checksum(buf[:total-ndbTailSize]) {
		return nil, buf, fmt.Errorf("%w: checksum", errBlob)
	}

	return buf[ndbHeadSize : ndbHeadSize+int(length)], buf, nil
}
