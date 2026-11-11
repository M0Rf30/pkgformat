package repodata

import (
	"bytes"
	"strconv"
)

// MissingChunks returns the chunks of the file h describes that a client
// holding the file old does not have, in file order, each distinct chunk once:
// the ones to fetch with range requests. Chunks are matched by checksum, which
// is only meaningful when both files use the same chunk checksum type,
// compression and dictionary; when they do not, or old is nil, every chunk is
// missing.
func (h *ZchunkHeader) MissingChunks(old *ZchunkHeader) []ZchunkChunk {
	have := map[string]struct{}{}

	if old != nil && h.comparable(old) {
		for _, c := range old.Chunks {
			have[string(c.Checksum)] = struct{}{}
		}
	}

	var missing []ZchunkChunk

	for _, c := range h.Chunks {
		if _, ok := have[string(c.Checksum)]; ok {
			continue
		}

		have[string(c.Checksum)] = struct{}{}

		missing = append(missing, c)
	}

	return missing
}

// comparable reports whether the chunks of h and o can be exchanged.
func (h *ZchunkHeader) comparable(o *ZchunkHeader) bool {
	return h.ChunkChecksumType == o.ChunkChecksumType &&
		h.Compression == o.Compression &&
		h.UncompressedSource == o.UncompressedSource &&
		h.Dict.Size == o.Dict.Size &&
		bytes.Equal(h.Dict.Checksum, o.Dict.Checksum)
}

// ZchunkRange is a run of bytes of a zchunk file.
type ZchunkRange struct {
	Offset int64
	Length int64
}

// End is the offset after the last byte of the range.
func (r ZchunkRange) End() int64 { return r.Offset + r.Length }

// String is the range as an HTTP Range header value spells it:
// "bytes=first-last".
func (r ZchunkRange) String() string {
	return "bytes=" + strconv.FormatInt(r.Offset, 10) + "-" + strconv.FormatInt(r.End()-1, 10)
}

// ByteRanges returns the ranges of the file that hold chunks, in the order
// given, with chunks that are adjacent in the file merged into one range so
// that a download makes as few requests as it can.
func ByteRanges(chunks []ZchunkChunk) []ZchunkRange {
	var ranges []ZchunkRange

	for _, c := range chunks {
		if c.CompressedSize == 0 {
			continue
		}

		if n := len(ranges); n > 0 && ranges[n-1].End() == c.Offset {
			ranges[n-1].Length += c.CompressedSize

			continue
		}

		ranges = append(ranges, ZchunkRange{Offset: c.Offset, Length: c.CompressedSize})
	}

	return ranges
}
