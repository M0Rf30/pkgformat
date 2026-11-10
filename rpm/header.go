/*
 * Copyright (c) SAS Institute, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rpm

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
	"github.com/M0Rf30/pkgformat/rpm/tag"
	"io"
	"path"
	"strconv"
)

type rpmHeader struct {
	entries  map[int]rpmhdr.Entry
	isSource bool
	orig     []byte
}

type headerIntro struct {
	Magic, Reserved, Entries, Size uint32
}

type headerTag struct {
	Tag, DataType, Offset, Count int32
}

var typeSizes = map[int32]int{
	tag.RPM_NULL_TYPE:  0,
	tag.RPM_CHAR_TYPE:  1,
	tag.RPM_INT8_TYPE:  1,
	tag.RPM_INT16_TYPE: 2,
	tag.RPM_INT32_TYPE: 4,
	tag.RPM_INT64_TYPE: 8,
	tag.RPM_BIN_TYPE:   1,
}

// Limits applied while parsing a header from untrusted input. They match (or
// are tighter than) the sanity limits that rpm itself enforces.
const (
	// MaxHeaderEntries is the maximum number of index entries in a header.
	MaxHeaderEntries = 0xffff
	// MaxHeaderDataSize is the maximum size of the data store of a header,
	// the default of [ReadHeader] and [ReadRpm].
	MaxHeaderDataSize = 0x0fffffff
	// stringScanFactor bounds how many bytes of the data store string tags
	// may scan in total, as a multiple of the data store size. Well-formed
	// headers never overlap string data; the factor leaves some slack while
	// preventing quadratic work from entries that all point at the same data.
	stringScanFactor = 4
	// maxSplicedPathBytes bounds the total size of the file names built from
	// DIRNAMES, DIRINDEXES and BASENAMES.
	maxSplicedPathBytes = 1 << 27
)

// HeaderLimits bounds the header of a package read from untrusted input. A
// zero field selects its default; the limits cannot be raised above
// [MaxHeaderEntries] and [MaxHeaderDataSize].
type HeaderLimits struct {
	// MaxEntries is the largest number of index entries accepted.
	MaxEntries int
	// MaxDataSize is the largest data store, in bytes, accepted for a header.
	MaxDataSize int
}

func (l HeaderLimits) normalized() HeaderLimits {
	if l.MaxEntries <= 0 || l.MaxEntries > MaxHeaderEntries {
		l.MaxEntries = MaxHeaderEntries
	}
	if l.MaxDataSize <= 0 || l.MaxDataSize > MaxHeaderDataSize {
		l.MaxDataSize = MaxHeaderDataSize
	}
	return l
}

// readExact reads exactly n bytes. The buffer grows as data arrives, so that a
// lying length field cannot make the caller allocate more than the input
// actually holds.
func readExact(f io.Reader, n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("invalid read length %d", n)
	}
	const eager = 64 << 10
	if n <= eager {
		buf := make([]byte, n)
		_, err := io.ReadFull(f, buf)
		return buf, err
	}
	buf, err := io.ReadAll(io.LimitReader(f, int64(n)))
	if err != nil {
		return buf, err
	}
	if len(buf) < n {
		return buf, io.ErrUnexpectedEOF
	}
	return buf, nil
}

func readHeader(f io.Reader, hash string, hashType crypto.Hash, isSource bool, sigBlock bool, lim HeaderLimits) (*rpmHeader, error) {
	lim = lim.normalized()
	// read and verify intro
	introBuf, err := readExact(f, rpmhdr.IntroSize)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the header intro: %w", ErrInvalidHeader, err)
	}
	intro := headerIntro{
		Magic:    binary.BigEndian.Uint32(introBuf[0:4]),
		Reserved: binary.BigEndian.Uint32(introBuf[4:8]),
		Entries:  binary.BigEndian.Uint32(introBuf[8:12]),
		Size:     binary.BigEndian.Uint32(introBuf[12:16]),
	}
	if intro.Magic != rpmhdr.IntroMagic {
		return nil, fmt.Errorf("%w: bad magic", ErrInvalidHeader)
	}
	if int64(intro.Entries) > int64(lim.MaxEntries) {
		return nil, fmt.Errorf("%w: %d index entries, at most %d", ErrHeaderTooLarge, intro.Entries, lim.MaxEntries)
	}
	if int64(intro.Size) > int64(lim.MaxDataSize) {
		return nil, fmt.Errorf("%w: %d bytes of data, at most %d", ErrHeaderTooLarge, intro.Size, lim.MaxDataSize)
	}
	// read entries
	entryTable, err := readExact(f, int(intro.Entries)*rpmhdr.IndexEntrySize)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the index: %w", ErrInvalidHeader, err)
	}
	// read data
	size := int(intro.Size)
	if sigBlock {
		// signature block is padded to 8 byte alignment
		size = (size + 7) / 8 * 8
	}
	data, err := readExact(f, size)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the data: %w", ErrInvalidHeader, err)
	}
	// keep the original bytes: the header digests and signatures cover them
	orig := make([]byte, 0, len(introBuf)+len(entryTable)+len(data))
	orig = append(orig, introBuf...)
	orig = append(orig, entryTable...)
	orig = append(orig, data...)
	// Check hash if it was specified
	if len(hash) > 1 {
		h := hashType.New()
		h.Write(orig)
		calculated := hex.EncodeToString(h.Sum(nil))
		if calculated != hash {
			return nil, fmt.Errorf("%s mismatch in signature header", hashType)
		}
	}
	// parse entries
	ents := make(map[int]rpmhdr.Entry, intro.Entries)
	scanBudget := int64(len(data)) * stringScanFactor
	for i := 0; i < int(intro.Entries); i++ {
		raw := entryTable[i*rpmhdr.IndexEntrySize:]
		ie := headerTag{
			Tag:      int32(binary.BigEndian.Uint32(raw[0:4])),
			DataType: int32(binary.BigEndian.Uint32(raw[4:8])),
			Offset:   int32(binary.BigEndian.Uint32(raw[8:12])),
			Count:    int32(binary.BigEndian.Uint32(raw[12:16])),
		}
		if ie.Offset < 0 || ie.Count < 0 {
			return nil, fmt.Errorf("%w: tag %d has an invalid offset or count", ErrInvalidHeader, ie.Tag)
		}
		if int64(ie.Offset) > int64(len(data)) {
			return nil, fmt.Errorf("%w: tag %d points outside of the header data", ErrInvalidHeader, ie.Tag)
		}
		var end int64
		if typeSize, ok := typeSizes[ie.DataType]; ok {
			end = int64(ie.Offset) + int64(typeSize)*int64(ie.Count)
		} else {
			// String types are null-terminated
			if int64(ie.Count) > int64(len(data)) {
				return nil, fmt.Errorf("%w: tag %d is truncated", ErrInvalidHeader, ie.Tag)
			}
			pos := int(ie.Offset)
			for j := int32(0); j < ie.Count; j++ {
				next := bytes.IndexByte(data[pos:], 0)
				if next < 0 {
					return nil, fmt.Errorf("%w: tag %d is truncated", ErrInvalidHeader, ie.Tag)
				}
				pos += next + 1
				scanBudget -= int64(next) + 1
				if scanBudget < 0 {
					return nil, fmt.Errorf("%w: tag %d: string data is inconsistent", ErrInvalidHeader, ie.Tag)
				}
			}
			end = int64(pos)
		}
		if end > int64(len(data)) {
			return nil, fmt.Errorf("%w: tag %d is truncated", ErrInvalidHeader, ie.Tag)
		}
		ents[int(ie.Tag)] = rpmhdr.Entry{
			Type:  int(ie.DataType),
			Count: int(ie.Count),
			Data:  data[ie.Offset:end:end],
		}
	}

	return &rpmHeader{
		entries:  ents,
		isSource: isSource,
		orig:     orig,
	}, nil
}

// HasTag returns true if the given tag exists in the header
func (hdr *rpmHeader) HasTag(id int) bool {
	_, ok := hdr.entries[id]
	return ok
}

// Get the value of a tag. Returns whichever type most closely represents how
// the tag was stored, or NoSuchTagError if the tag was not found. If tag is
// OLDFILENAMES, special handling is provided to splice together DIRNAMES and
// BASENAMES if it is not present.
func (hdr *rpmHeader) Get(id int) (interface{}, error) {
	ent, ok := hdr.entries[id]
	if !ok && id == tag.OLDFILENAMES {
		return hdr.GetStrings(id)
	}
	if !ok {
		return nil, NewNoSuchTagError(id)
	}
	switch ent.Type {
	case tag.RPM_STRING_TYPE, tag.RPM_STRING_ARRAY_TYPE, tag.RPM_I18NSTRING_TYPE:
		return hdr.GetStrings(id)
	case tag.RPM_INT8_TYPE, tag.RPM_INT16_TYPE, tag.RPM_INT32_TYPE, tag.RPM_INT64_TYPE, tag.RPM_CHAR_TYPE:
		out, _, err := hdr.getInts(id)
		return out, err
	case tag.RPM_BIN_TYPE:
		return hdr.GetBytes(id)
	default:
		return nil, fmt.Errorf("unsupported data type")
	}
}

// GetStrings fetches the given tag holding a string or array of strings. If tag
// is OLDFILENAMES, special handling is provided to splice together DIRNAMES and
// BASENAMES if it is not present.
func (hdr *rpmHeader) GetStrings(id int) ([]string, error) {
	ent, ok := hdr.entries[id]
	if id == tag.OLDFILENAMES && !ok {
		dirs, err := hdr.GetStrings(tag.DIRNAMES)
		if err != nil {
			return nil, err
		}
		dirIdxs, err := hdr.GetUint32s(tag.DIRINDEXES)
		if err != nil {
			return nil, err
		}
		baseNames, err := hdr.GetStrings(tag.BASENAMES)
		if err != nil {
			return nil, err
		}
		if len(dirIdxs) < len(baseNames) {
			return nil, errors.New("DIRINDEXES is shorter than BASENAMES")
		}
		paths := make([]string, 0, len(baseNames))
		budget := maxSplicedPathBytes
		for i, base := range baseNames {
			idx := dirIdxs[i]
			if uint64(idx) >= uint64(len(dirs)) {
				return nil, fmt.Errorf("directory index %d out of range", idx)
			}
			// Every path may repeat the same directory name, so the entry
			// count alone does not bound the size of the list.
			if budget -= len(dirs[idx]) + len(base); budget < 0 {
				return nil, fmt.Errorf("%w: the file names exceed %d bytes", ErrHeaderTooLarge, maxSplicedPathBytes)
			}
			paths = append(paths, path.Join(dirs[idx], base))
		}
		return paths, nil
	}

	if !ok {
		return nil, NewNoSuchTagError(id)
	}
	if ent.Type != tag.RPM_STRING_TYPE && ent.Type != tag.RPM_STRING_ARRAY_TYPE && ent.Type != tag.RPM_I18NSTRING_TYPE {
		return nil, fmt.Errorf("unsupported datatype for string: %d, tag: %d", ent.Type, id)
	}
	strs, ok := splitStrings(ent.Data, ent.Count, ent.Count)
	if !ok {
		return nil, fmt.Errorf("tag %d holds fewer strings than declared", id)
	}
	return strs, nil
}

// splitStrings returns the first min(count, limit) NUL terminated strings of
// data. ok is false when data holds fewer than that many strings.
func splitStrings(data []byte, count, limit int) (strs []string, ok bool) {
	n := min(count, limit)
	strs = make([]string, 0, n)
	for len(strs) < n {
		i := bytes.IndexByte(data, 0)
		if i < 0 {
			return nil, false
		}
		strs = append(strs, string(data[:i]))
		data = data[i+1:]
	}
	return strs, true
}

// stringsPrefix returns at most limit strings of a string tag, and the number
// of strings the tag declares. A missing tag, one of another type, or one
// that holds fewer strings than it declares yields nil and 0.
func (hdr *rpmHeader) stringsPrefix(id, limit int) ([]string, int) {
	ent, ok := hdr.entries[id]
	if !ok || (ent.Type != tag.RPM_STRING_TYPE && ent.Type != tag.RPM_STRING_ARRAY_TYPE && ent.Type != tag.RPM_I18NSTRING_TYPE) {
		return nil, 0
	}
	strs, ok := splitStrings(ent.Data, ent.Count, limit)
	if !ok {
		return nil, 0
	}
	return strs, ent.Count
}

// numbersPrefix returns at most limit values of an integer tag of any width,
// and the number of values the tag declares. A missing tag or one of another
// type yields nil and 0.
func (hdr *rpmHeader) numbersPrefix(id, limit int) ([]uint64, int) {
	ent, ok := hdr.entries[id]
	if !ok {
		return nil, 0
	}
	var width int
	switch ent.Type {
	case tag.RPM_INT8_TYPE, tag.RPM_CHAR_TYPE:
		width = 1
	case tag.RPM_INT16_TYPE:
		width = 2
	case tag.RPM_INT32_TYPE:
		width = 4
	case tag.RPM_INT64_TYPE:
		width = 8
	default:
		return nil, 0
	}
	n := min(len(ent.Data)/width, limit)
	out := make([]uint64, n)
	for i := range out {
		b := ent.Data[i*width:]
		switch width {
		case 1:
			out[i] = uint64(b[0])
		case 2:
			out[i] = uint64(binary.BigEndian.Uint16(b))
		case 4:
			out[i] = uint64(binary.BigEndian.Uint32(b))
		default:
			out[i] = binary.BigEndian.Uint64(b)
		}
	}
	return out, len(ent.Data) / width
}

// get an int array using whatever the appropriate sized type is
func (hdr *rpmHeader) getInts(id int) (buf interface{}, n int, err error) {
	ent, ok := hdr.entries[id]
	if !ok {
		return nil, 0, NewNoSuchTagError(id)
	}
	n = len(ent.Data)
	switch ent.Type {
	case tag.RPM_INT8_TYPE, tag.RPM_CHAR_TYPE:
		buf = make([]uint8, n)
	case tag.RPM_INT16_TYPE:
		n >>= 1
		buf = make([]uint16, n)
	case tag.RPM_INT32_TYPE:
		n >>= 2
		buf = make([]uint32, n)
	case tag.RPM_INT64_TYPE:
		n >>= 3
		buf = make([]uint64, n)
	default:
		return nil, 0, fmt.Errorf("tag %d isn't an int type", id)
	}
	if err := binary.Read(bytes.NewReader(ent.Data), binary.BigEndian, buf); err != nil {
		return nil, 0, err
	}
	return
}

// GetInts gets an integer array using the default 'int' type.
//
// DEPRECATED: large int32s and int64s can overflow. Use GetUint32s or GetUint64s instead.
func (hdr *rpmHeader) GetInts(id int) ([]int, error) {
	buf, n, err := hdr.getInts(id)
	if err != nil {
		return nil, err
	}
	out := make([]int, n)
	switch bvals := buf.(type) {
	case []uint8:
		for i, v := range bvals {
			out[i] = int(v)
		}
	case []uint16:
		for i, v := range bvals {
			out[i] = int(v)
		}
	case []uint32:
		for i, v := range bvals {
			if v > (1<<31)-1 {
				return nil, fmt.Errorf("value %d out of range for int32 array in tag %d", i, id)
			}
			out[i] = int(v)
		}
	default:
		return nil, fmt.Errorf("tag %d is too big for int type", id)
	}
	return out, nil
}

// GetUint32s gets an int array as a uint32 slice. This can accommodate any int
// type other than INT64. Returns an error in case of overflow.
func (hdr *rpmHeader) GetUint32s(id int) ([]uint32, error) {
	buf, n, err := hdr.getInts(id)
	if err != nil {
		return nil, err
	}
	if out, ok := buf.([]uint32); ok {
		return out, nil
	}
	out := make([]uint32, n)
	switch bvals := buf.(type) {
	case []uint8:
		for i, v := range bvals {
			out[i] = uint32(v)
		}
	case []uint16:
		for i, v := range bvals {
			out[i] = uint32(v)
		}
	default:
		return nil, fmt.Errorf("tag %d is too big for int type", id)
	}
	return out, nil
}

// GetUint64s gets an int array as a uint64 slice. This can accommodate all int
// types.
func (hdr *rpmHeader) GetUint64s(id int) ([]uint64, error) {
	buf, n, err := hdr.getInts(id)
	if err != nil {
		return nil, err
	}
	if out, ok := buf.([]uint64); ok {
		return out, nil
	}
	out := make([]uint64, n)
	switch bvals := buf.(type) {
	case []uint8:
		for i, v := range bvals {
			out[i] = uint64(v)
		}
	case []uint16:
		for i, v := range bvals {
			out[i] = uint64(v)
		}
	case []uint32:
		for i, v := range bvals {
			out[i] = uint64(v)
		}
	}
	return out, nil
}

// GetUint64Fallback gets longTag if it exists, otherwise intTag, and returns
// the value as an array of uint64s. This can accommodate all int types and is
// normally used when a int32 tag was later replaced with a int64 tag.
func (hdr *rpmHeader) GetUint64Fallback(intTag, longTag int) ([]uint64, error) {
	if _, ok := hdr.entries[longTag]; ok {
		return hdr.GetUint64s(longTag)
	}
	return hdr.GetUint64s(intTag)
}

// GetBytes gets a tag as a byte array.
func (hdr *rpmHeader) GetBytes(id int) ([]byte, error) {
	ent, ok := hdr.entries[id]
	if !ok {
		return nil, NewNoSuchTagError(id)
	}
	if ent.Type != tag.RPM_BIN_TYPE {
		return nil, fmt.Errorf("unsupported datatype for bytes: %d, tag: %d", ent.Type, id)
	}
	return ent.Data, nil
}

// GetNEVRA gets the name, epoch, version, release and arch of the RPM.
func (hdr *rpmHeader) GetNEVRA() (*NEVRA, error) {
	name, err := hdr.GetStrings(tag.NAME)
	if err != nil {
		return nil, err
	}
	epoch, err := hdr.GetUint64s(tag.EPOCH)
	if absent := errors.As(err, &NoSuchTagError{}); !absent && err != nil {
		return nil, err
	} else if len(epoch) == 0 {
		// no epoch is treated as 0
		epoch = []uint64{0}
	}
	version, err := hdr.GetStrings(tag.VERSION)
	if err != nil {
		return nil, err
	}
	release, err := hdr.GetStrings(tag.RELEASE)
	if err != nil {
		return nil, err
	}
	arch, err := hdr.GetStrings(tag.ARCH)
	if err != nil {
		return nil, err
	}
	if len(name) == 0 || len(version) == 0 || len(release) == 0 || len(arch) == 0 {
		return nil, errors.New("NEVRA tag holds no value")
	}
	return &NEVRA{
		Name:    name[0],
		Epoch:   strconv.FormatUint(epoch[0], 10),
		Version: version[0],
		Release: release[0],
		Arch:    arch[0],
	}, nil
}

// GetFiles returns an array of FileInfo objects holding file-related attributes
// held in parallel arrays of tags
//
// If the RPM has no files, GetFiles returns an empty list.
func (hdr *rpmHeader) GetFiles() ([]FileInfo, error) {
	paths, err := hdr.GetStrings(tag.OLDFILENAMES)
	if err != nil {
		if !errors.As(err, &NoSuchTagError{}) {
			return nil, err
		}
		// RPM has no files
		return nil, nil
	}
	fileSizes, err := hdr.GetUint64Fallback(tag.FILESIZES, tag.LONGFILESIZES)
	if err != nil {
		return nil, err
	}
	fileUserName, err := hdr.GetStrings(tag.FILEUSERNAME)
	if err != nil {
		return nil, err
	}
	fileGroupName, err := hdr.GetStrings(tag.FILEGROUPNAME)
	if err != nil {
		return nil, err
	}
	fileFlags, err := hdr.GetUint32s(tag.FILEFLAGS)
	if err != nil {
		return nil, err
	}
	fileMtimes, err := hdr.GetUint32s(tag.FILEMTIMES)
	if err != nil {
		return nil, err
	}
	fileDigests, err := hdr.GetStrings(tag.FILEDIGESTS)
	if err != nil {
		return nil, err
	}
	fileModes, err := hdr.GetUint32s(tag.FILEMODES)
	if err != nil {
		return nil, err
	}
	linkTos, err := hdr.GetStrings(tag.FILELINKTOS)
	if err != nil {
		return nil, err
	}
	devices, err := hdr.GetUint32s(tag.FILEDEVICES)
	if err != nil {
		devices = make([]uint32, len(paths))
	}
	inodes, err := hdr.GetUint32s(tag.FILEINODES)
	if err != nil {
		inodes = make([]uint32, len(paths))
	}
	// optional: only present when the package holds device nodes
	rdevs, err := hdr.GetUint32s(tag.FILERDEVS)
	if err != nil {
		rdevs = make([]uint32, len(paths))
	}

	n := len(paths)
	for _, l := range []int{
		len(fileSizes), len(fileUserName), len(fileGroupName), len(fileFlags),
		len(fileMtimes), len(fileDigests), len(fileModes), len(linkTos),
		len(devices), len(inodes), len(rdevs),
	} {
		if l < n {
			return nil, errors.New("file attribute tags are shorter than the file list")
		}
	}

	files := make([]FileInfo, n)
	for i := 0; i < n; i++ {
		files[i] = &fileInfo{
			name:      paths[i],
			size:      fileSizes[i],
			userName:  fileUserName[i],
			groupName: fileGroupName[i],
			flags:     fileFlags[i],
			mtime:     fileMtimes[i],
			digest:    fileDigests[i],
			mode:      fileModes[i],
			linkName:  linkTos[i],
			device:    devices[i],
			inode:     inodes[i],
			rdev:      rdevs[i],
		}
	}

	return files, nil
}
