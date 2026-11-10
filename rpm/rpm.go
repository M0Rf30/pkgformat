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
	"errors"
	"fmt"
	"io"

	"github.com/M0Rf30/pkgformat/rpm/cpio"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// Rpm is an open RPM header and payload
type Rpm struct {
	Header *RpmHeader
	f      io.Reader

	maxPayload int64
}

// ErrPayloadTooLarge is returned when the decompressed payload is larger than
// the limit set with [Rpm.SetMaxPayloadSize].
var ErrPayloadTooLarge = errors.New("rpm payload exceeds the configured size limit")

// SetMaxPayloadSize bounds the number of bytes the decompressed payload may
// produce through ExpandPayload, PayloadReader and PayloadReaderExtended. Once
// the payload yields more than limit bytes, reads fail with
// [ErrPayloadTooLarge]. A limit of zero or less removes the limit, which is the
// default.
//
// RPM payloads are compressed and come from untrusted sources: a few KiB of
// compressed data can expand to many GiB. Callers handling untrusted packages
// should set a limit derived from their own policy (the PAYLOADSIZE declared
// in the header, see [RpmHeader.PayloadSize], is attacker-controlled too).
func (rpm *Rpm) SetMaxPayloadSize(limit int64) {
	rpm.maxPayload = limit
}

// uncompressedPayload returns the decompressed payload stream with the configured
// size limit applied.
func (rpm *Rpm) uncompressedPayload() (io.Reader, error) {
	pld, err := uncompressRpmPayloadReader(rpm.f, rpm.Header)
	if err != nil {
		return nil, err
	}
	if rpm.maxPayload > 0 {
		pld = newLimitedReader(pld, rpm.maxPayload)
	}
	return pld, nil
}

// RpmHeader holds the signature header and general header of a RPM
//
// Tags are drawn from both header areas, with IDs between tag.GENERAL_TAG_BASE and
// tag.SIGHEADER_TAG_BASE coming from the general header and all others coming from
// the signature header.
type RpmHeader struct {
	lead      []byte
	sigHeader *rpmHeader
	genHeader *rpmHeader
	isSource  bool
}

// ReadRpm reads the header from a RPM file and prepares to read payload contents
func ReadRpm(f io.Reader) (*Rpm, error) {
	hdr, err := ReadHeader(f)
	if err != nil {
		return nil, err
	}
	return &Rpm{
		Header: hdr,
		f:      f,
	}, nil
}

// ExpandPayload extracts the payload of a RPM to the specified directory
func (rpm *Rpm) ExpandPayload(dest string) error {
	pld, err := rpm.uncompressedPayload()
	if err != nil {
		return err
	}
	if c, ok := pld.(io.Closer); ok {
		defer c.Close()
	}
	return cpio.Extract(pld, dest)
}

// PayloadReader accesses the payload cpio archive within the RPM.
//
// DEPRECATED: Use PayloadReaderExtended instead in order to handle files larger than 4GiB.
func (rpm *Rpm) PayloadReader() (*cpio.Reader, error) {
	pld, err := rpm.uncompressedPayload()
	if err != nil {
		return nil, err
	}
	return cpio.NewReader(pld), nil
}

// PayloadReaderExtended accesses payload file contents sequentially
func (rpm *Rpm) PayloadReaderExtended() (PayloadReader, error) {
	pld, err := rpm.uncompressedPayload()
	if err != nil {
		return nil, err
	}
	files, err := rpm.Header.GetFiles()
	if err != nil {
		return nil, err
	}
	return newPayloadReader(pld, files), nil
}

// ReadHeader reads the signature and general headers from a RPM.
//
// The stream is positioned for reading the compressed payload following the headers.
// The headers are bounded by [MaxHeaderEntries] and [MaxHeaderDataSize]; use
// [ReadHeaderLimits] for tighter bounds.
func ReadHeader(f io.Reader) (*RpmHeader, error) {
	return ReadHeaderLimits(f, HeaderLimits{})
}

// ReadHeaderLimits is [ReadHeader] with the headers bounded by lim.
func ReadHeaderLimits(f io.Reader, lim HeaderLimits) (*RpmHeader, error) {
	lead, sigHeader, err := readSignatureHeader(f, lim)
	if err != nil {
		return nil, err
	}

	genHeader, err := readGeneralHeader(f, sigHeader, lim)
	if err != nil {
		return nil, err
	}

	return &RpmHeader{
		lead:      lead,
		sigHeader: sigHeader,
		genHeader: genHeader,
		isSource:  sigHeader.isSource,
	}, nil
}

func readSignatureHeader(f io.Reader, lim HeaderLimits) ([]byte, *rpmHeader, error) {
	// Read signature header
	lead, err := readExact(f, LeadSize)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: reading the lead: %w", ErrNotRPM, err)
	}

	l, err := parseLead(lead)
	if err != nil {
		return nil, nil, err
	}

	// Return signature header
	hdr, err := readHeader(f, "", 0, l.Type == 1, true, lim)
	return lead, hdr, err
}

// HeaderRange indicates the byte offsets that the RPM header spans
type HeaderRange struct {
	// Start is the byte offset of the signature header
	Start int
	// End is the byte offset of the end of the general header and start of the payload
	End int
}

// GetRange returns the byte offsets that the RPM header spans within the original RPM file
func (hdr *RpmHeader) GetRange() HeaderRange {
	start := 96 + len(hdr.sigHeader.orig)
	end := start + len(hdr.genHeader.orig)
	return HeaderRange{
		Start: start,
		End:   end,
	}
}

// HasTag returns true if the given tag exists in the header
func (hdr *RpmHeader) HasTag(id int) bool {
	h, t := hdr.getHeader(id)
	return h.HasTag(t)
}

// Get the value of a tag. Returns whichever type most closely represents how
// the tag was stored, or NoSuchTagError if the tag was not found. If tag is
// OLDFILENAMES, special handling is provided to splice together DIRNAMES and
// BASENAMES if it is not present.
func (hdr *RpmHeader) Get(id int) (interface{}, error) {
	h, t := hdr.getHeader(id)
	return h.Get(t)
}

// GetString returns the value of a tag holding a single string
func (hdr *RpmHeader) GetString(id int) (string, error) {
	vals, err := hdr.GetStrings(id)
	if err != nil {
		return "", err
	}
	if len(vals) != 1 {
		return "", fmt.Errorf("incorrect number of values")
	}
	return vals[0], nil
}

// GetStrings fetches the given tag holding a string or array of strings. If tag
// is OLDFILENAMES, special handling is provided to splice together DIRNAMES and
// BASENAMES if it is not present.
func (hdr *RpmHeader) GetStrings(id int) ([]string, error) {
	h, t := hdr.getHeader(id)
	return h.GetStrings(t)
}

// GetInt gets an integer using the default 'int' type.
//
// DEPRECATED: large int32s and int64s can overflow. Use GetUint32s or GetUint64s instead.
func (hdr *RpmHeader) GetInt(id int) (int, error) {
	vals, err := hdr.GetInts(id)
	if err != nil {
		return -1, err
	}
	if len(vals) != 1 {
		return -1, fmt.Errorf("incorrect number of values")
	}
	return vals[0], nil
}

// GetInts gets an integer array using the default 'int' type.
//
// DEPRECATED: large int32s and int64s can overflow. Use GetUint32s or GetUint64s instead.
func (hdr *RpmHeader) GetInts(id int) ([]int, error) {
	h, t := hdr.getHeader(id)
	return h.GetInts(t)
}

// GetUint32 gets an uint32 type other than INT64. Note that it returns 0 when fails instead of -1.
// Returns an error in case of overflow.
func (hdr *RpmHeader) GetUint32(id int) (uint32, error) {
	vals, err := hdr.GetUint32s(id)
	if err != nil {
		return 0, err
	}
	if len(vals) != 1 {
		return 0, fmt.Errorf("incorrect number of values")
	}
	return vals[0], nil
}

// GetUint32s gets an int array as a uint32 slice. This can accommodate any int
// type other than INT64. Returns an error in case of overflow.
func (hdr *RpmHeader) GetUint32s(id int) ([]uint32, error) {
	h, t := hdr.getHeader(id)
	return h.GetUint32s(t)
}

// GetUint64 gets an uint64 type. Note that it returns 0 when fails instead of -1.
func (hdr *RpmHeader) GetUint64(id int) (uint64, error) {
	vals, err := hdr.GetUint64s(id)
	if err != nil {
		return 0, err
	}
	if len(vals) != 1 {
		return 0, fmt.Errorf("incorrect number of values")
	}
	return vals[0], nil
}

// GetUint64s gets an int array as a uint64 slice. This can accommodate all int
// types
func (hdr *RpmHeader) GetUint64s(id int) ([]uint64, error) {
	h, t := hdr.getHeader(id)
	return h.GetUint64s(t)
}

// GetUint64Fallback gets longTag if it exists, otherwise intTag, and returns
// the value as an array of uint64s. This can accommodate all int types and is
// normally used when a int32 tag was later replaced with a int64 tag.
func (hdr *RpmHeader) GetUint64Fallback(intTag, longTag int) (uint64, error) {
	h, t := hdr.getHeader(longTag)
	vals, err := h.GetUint64s(t)
	if err == nil && len(vals) == 1 {
		return vals[0], nil
	}
	h, t = hdr.getHeader(intTag)
	vals, err = h.GetUint64s(t)
	if err != nil {
		return 0, err
	} else if len(vals) != 1 {
		return 0, errors.New("incorrect number of values")
	}
	return vals[0], nil
}

// GetBytes gets a tag as a byte array.
func (hdr *RpmHeader) GetBytes(id int) ([]byte, error) {
	h, t := hdr.getHeader(id)
	return h.GetBytes(t)
}

// getHeader decides whether the conventional tag ID is within the signature
// header range and returns the appropriate sub-header struct and raw tag
// identifier
func (hdr *RpmHeader) getHeader(id int) (*rpmHeader, int) {
	if id > tag.SIGHEADER_TAG_BASE {
		return hdr.sigHeader, id - tag.SIGHEADER_TAG_BASE
	}
	if id < tag.GENERAL_TAG_BASE {
		return hdr.sigHeader, id
	}
	return hdr.genHeader, id
}

// GetNEVRA gets the name, epoch, version, release and arch of the RPM.
func (hdr *RpmHeader) GetNEVRA() (*NEVRA, error) {
	return hdr.genHeader.GetNEVRA()
}

// GetFiles returns an array of FileInfo objects holding file-related attributes
// held in parallel arrays of tags
func (hdr *RpmHeader) GetFiles() ([]FileInfo, error) {
	return hdr.genHeader.GetFiles()
}

// InstalledSize returns the approximate disk space needed to install the package
func (hdr *RpmHeader) InstalledSize() (int64, error) {
	u, err := hdr.GetUint64Fallback(tag.SIZE, tag.LONGSIZE)
	if err != nil {
		return -1, err
	}
	return int64(u), nil
}

// PayloadSize returns the size of the uncompressed payload in bytes
func (hdr *RpmHeader) PayloadSize() (int64, error) {
	if hdr.genHeader.HasTag(tag.PAYLOADSIZEALT) {
		// RPM v6 keeps payload sizes in the general header
		u, err := hdr.genHeader.GetUint64s(tag.PAYLOADSIZEALT)
		if err != nil {
			return -1, err
		} else if len(u) != 1 {
			return -1, errors.New("incorrect number of values")
		}
		return int64(u[0]), nil
	}
	u, err := hdr.sigHeader.GetUint64Fallback(tag.SIG_PAYLOADSIZE-tag.SIGHEADER_TAG_BASE, tag.SIG_LONGARCHIVESIZE)
	if err != nil {
		return -1, err
	} else if len(u) != 1 {
		return -1, errors.New("incorrect number of values")
	}
	return int64(u[0]), err
}

// Format returns the RPM package format version: the value of the RPMFORMAT
// tag, or 4 if absent (RPM v4 packages).
func (hdr *RpmHeader) Format() int {
	if vals, err := hdr.genHeader.GetUint32s(tag.RPMFORMAT); err == nil && len(vals) == 1 {
		return int(vals[0])
	}
	return 4
}

// IsSource return isSource
func (hdr *RpmHeader) IsSource() bool {
	return hdr.isSource
}
