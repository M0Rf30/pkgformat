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
	"errors"
	"io"

	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// index returns the entries of the header as they are written back, under a
// region tag that encloses them all. Any existing regions are discarded.
func (hdr *rpmHeader) index(regionTag int) *rpmhdr.Index {
	ix := rpmhdr.NewIndex(regionTag)
	for k, e := range hdr.entries {
		if k >= tag.RPMTAG_HEADERREGIONS {
			ix.Add(k, e)
		}
	}
	return ix
}

func checkRegionTag(regionTag int) error {
	if regionTag != 0 && regionTag >= tag.RPMTAG_HEADERREGIONS {
		return errors.New("invalid region tag")
	}
	return nil
}

// WriteTo writes the header out, adding a region tag encompassing all the existing tags
func (hdr *rpmHeader) WriteTo(outfile io.Writer, regionTag int) error {
	if err := checkRegionTag(regionTag); err != nil {
		return err
	}
	return writeIndex(outfile, hdr.index(regionTag))
}

// writeIndex writes an encoded header, padded to 8 bytes when it is a signature header.
func writeIndex(outfile io.Writer, ix *rpmhdr.Index) error {
	b, err := ix.Bytes()
	if err != nil {
		return err
	}
	if ix.Region == tag.RPMTAG_HEADERSIGNATURES {
		b = append(b, make([]byte, rpmhdr.Pad8(len(b)))...)
	}
	_, err = outfile.Write(b)
	return err
}

// OriginalSignatureHeaderSize returns the size of the lead and signature header
// area as originally read from the file.
func (hdr *RpmHeader) OriginalSignatureHeaderSize() int {
	return len(hdr.sigHeader.orig) + rpmhdr.LeadSize
}

// DumpSignatureHeader dumps the lead and signature header, optionally adding or
// changing padding to make it the same size as when it was originally read.
// Otherwise padding is removed to make it as small as possible.
//
// A RPM can be signed by removing the first OriginalSignatureHeaderSize() bytes
// of the file and replacing it with the result of DumpSignatureHeader().
func (hdr *RpmHeader) DumpSignatureHeader(sameSize bool) ([]byte, error) {
	if len(hdr.lead) != rpmhdr.LeadSize {
		return nil, errors.New("invalid or missing RPM lead")
	}
	sigh := hdr.sigHeader
	regionTag := tag.RPMTAG_HEADERSIGNATURES
	reservedTag := tag.SIG_RESERVEDSPACE - tag.SIGHEADER_TAG_BASE
	if hdr.genHeader != nil && isFormatV6(hdr.genHeader) {
		// v6 reserves space with its own tag (999), which must be the last
		// one in the signature header, and every v6 package carries it:
		// keep the original size even when sameSize is not requested.
		reservedTag = tag.SIG_RESERVED
		sameSize = true
	}
	delete(sigh.entries, tag.SIG_RESERVEDSPACE-tag.SIGHEADER_TAG_BASE)
	delete(sigh.entries, tag.SIG_RESERVED)
	ix := sigh.index(regionTag)
	if sameSize {
		// Fill unused space with a RESERVEDSPACE tag. The signature header
		// is padded to 8 bytes, which is part of its original size.
		b, err := ix.Bytes()
		if err != nil {
			return nil, err
		}
		if err := ix.Reserve(reservedTag, len(sigh.orig)-rpmhdr.Pad8(len(b))); err != nil {
			return nil, err
		}
	}
	buf := new(bytes.Buffer)
	buf.Write(hdr.lead)
	if err := writeIndex(buf, ix); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
