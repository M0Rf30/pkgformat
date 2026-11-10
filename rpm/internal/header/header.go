// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package header encodes RPM headers: the signature header and the main header
// of a package share one binary layout, which is written here for both the
// package writer and the signature rewriting of the reader.
//
// A header is an intro (magic, entry count, data size), the index of entries
// sorted by tag, the data of the entries, and a trailing "region" entry that
// covers the whole index. The index entry of the region is sorted first, its
// 16 bytes of data come last.
package header

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"

	"github.com/M0Rf30/pkgformat/rpm/tag"
)

const (
	// IntroMagic is the magic number at the start of a header.
	IntroMagic = 0x8eade801
	// IntroSize is the size of the intro: magic, reserved, entry count and data size.
	IntroSize = 16
	// IndexEntrySize is the size of one entry of the index: tag, type, offset and count.
	IndexEntrySize = 16
)

// ErrHeaderTooLarge is returned when a header does not fit the 31 bit offsets and
// counts of the rpm header format.
var ErrHeaderTooLarge = errors.New("rpm header too large")

// Entry is the value of a tag: its type, the number of items and the raw
// big endian data.
type Entry struct {
	// Type is one of the tag.RPM_*_TYPE constants.
	Type int
	// Count is the number of items in Data.
	Count int
	// Data is the encoded value.
	Data []byte
}

// align returns the boundary data of a type must start at. Only integer types
// are aligned. This is not just an optimization - some versions of rpm fail when
// integers are not aligned. Other versions fail when non-integers are aligned.
func align(typ int) int {
	switch typ {
	case tag.RPM_INT16_TYPE:
		return 2
	case tag.RPM_INT32_TYPE:
		return 4
	case tag.RPM_INT64_TYPE:
		return 8
	}
	return 1
}

// IndexBytes returns the 16 bytes of the index entry for this entry with the
// given tag and offset into the data.
func (e Entry) IndexBytes(tag, offset int) []byte {
	b := make([]byte, 0, IndexEntrySize)
	b = binary.BigEndian.AppendUint32(b, uint32(tag))
	b = binary.BigEndian.AppendUint32(b, uint32(e.Type))
	b = binary.BigEndian.AppendUint32(b, uint32(offset))
	return binary.BigEndian.AppendUint32(b, uint32(e.Count))
}

// Integer is the set of slices of integers an entry can be made of.
type Integer interface {
	int16 | uint16 | int32 | uint32 | int64 | uint64
}

// Integers creates an entry from integers. The rpm type is selected by the size
// of the integers: INT16, INT32 or INT64.
func Integers[T Integer](values []T) Entry {
	var typ int
	switch any(*new(T)).(type) {
	case int16, uint16:
		typ = tag.RPM_INT16_TYPE
	case int32, uint32:
		typ = tag.RPM_INT32_TYPE
	default:
		typ = tag.RPM_INT64_TYPE
	}
	// binary.Append cannot fail for slices of fixed size integers.
	data, _ := binary.Append(nil, binary.BigEndian, values)
	return Entry{Type: typ, Count: len(values), Data: data}
}

// String creates an entry from a string value.
func String(value string) Entry {
	return Entry{Type: tag.RPM_STRING_TYPE, Count: 1, Data: append([]byte(value), 0)}
}

// Bytes creates an entry from a byte slice.
func Bytes(value []byte) Entry {
	return Entry{Type: tag.RPM_BIN_TYPE, Count: len(value), Data: value}
}

// Strings creates an entry from a slice of strings.
func Strings(value []string) Entry {
	b := [][]byte{}
	for _, v := range value {
		b = append(b, []byte(v))
	}
	bb := append(bytes.Join(b, []byte{0}), 0)
	return Entry{Type: tag.RPM_STRING_ARRAY_TYPE, Count: len(value), Data: bb}
}

// Index is a header under construction: the entries by tag and the tag of the
// region entry that encloses them, tag.RPMTAG_HEADERSIGNATURES for a signature
// header and tag.RPMTAG_HEADERIMMUTABLE for the main header.
type Index struct {
	Region  int
	Entries map[int]Entry
}

// NewIndex returns an empty index with the given region tag.
func NewIndex(region int) *Index {
	return &Index{Region: region, Entries: make(map[int]Entry)}
}

// Add sets the entry of a tag, replacing the previous one.
func (i *Index) Add(tag int, e Entry) {
	i.Entries[tag] = e
}

// AddEntries sets all the entries of m, replacing the previous ones.
func (i *Index) AddEntries(m map[int]Entry) {
	maps.Copy(i.Entries, m)
}

// Bytes encodes the header: intro, index and data. It does not add the padding
// that signature headers need to reach a multiple of 8 bytes, see Pad8.
func (i *Index) Bytes() ([]byte, error) {
	// The index entries hold offsets into the data, which are only known after
	// the entries were aligned and written.
	data := &bytes.Buffer{}
	tags := slices.Sorted(maps.Keys(i.Entries))
	offsets := make([]int, len(tags))
	for ii, t := range tags {
		e := i.Entries[t]
		if e.Count > math.MaxInt32 {
			return nil, fmt.Errorf("%w: tag %d has %d items", ErrHeaderTooLarge, t, e.Count)
		}
		if a := align(e.Type); data.Len()%a != 0 {
			data.Write(make([]byte, a-data.Len()%a))
		}
		offsets[ii] = data.Len()
		data.Write(e.Data)
		// keep room for the region entry appended below
		if data.Len() > math.MaxInt32-IndexEntrySize {
			return nil, fmt.Errorf("%w: data region is over %d bytes at tag %d", ErrHeaderTooLarge, math.MaxInt32-IndexEntrySize, t)
		}
	}
	region := i.regionEntry()
	data.Write(region.Data)

	out := make([]byte, 0, IntroSize+IndexEntrySize*(len(tags)+1)+data.Len())
	out = binary.BigEndian.AppendUint32(out, IntroMagic)
	out = binary.BigEndian.AppendUint32(out, 0) // reserved
	// The region is a pseudo entry, which counts too.
	out = binary.BigEndian.AppendUint32(out, uint32(len(tags)+1))
	out = binary.BigEndian.AppendUint32(out, uint32(data.Len()))
	out = append(out, region.IndexBytes(i.Region, data.Len()-IndexEntrySize)...)
	for ii, t := range tags {
		out = append(out, i.Entries[t].IndexBytes(t, offsets[ii])...)
	}
	return append(out, data.Bytes()...), nil
}

// regionEntry is a weird entry. Its index entry is sorted first, but its content
// is last. The content is a 16 byte index entry, which is almost the same as the index
// entry except for the offset. The offset here is minus the length of the index entry
// region, which is always 16 * the number of entries. I kid you not.
func (i *Index) regionEntry() Entry {
	e := Entry{Type: tag.RPM_BIN_TYPE, Count: IndexEntrySize}
	return Bytes(e.IndexBytes(i.Region, -IndexEntrySize*(len(i.Entries)+1)))
}

// Reserve adds a zero filled RPM_BIN_TYPE entry under tag, which makes the
// encoded header (see Bytes) size bytes, as long as the data of the entries
// that follow the reserved one needs no alignment padding of its own (the
// reserved entry sorts before them). Packages reserve such space in the
// signature header so that signatures can be added without moving the rest of
// the file. Nothing is added when the header already needs more than size bytes.
func (i *Index) Reserve(tag, size int) error {
	b, err := i.Bytes()
	if err != nil {
		return err
	}
	if n := size - len(b) - IndexEntrySize; n >= 0 {
		i.Add(tag, Bytes(make([]byte, n)))
	}
	return nil
}

// Pad8 returns the number of zero bytes that bring a signature header of n bytes
// to a multiple of 8. The main header that follows it must start at such an offset.
func Pad8(n int) int {
	return (8 - n%8) % 8
}
