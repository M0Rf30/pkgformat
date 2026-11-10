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
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/M0Rf30/pkgformat/rpm/tag"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// maxDictSize caps the LZMA dictionary size an xz/lzma stream may request. The
// size comes from the (untrusted) stream header and is allocated up front.
// 256 MiB is far above anything rpm produces (xz -9 uses 64 MiB).
const maxDictSize = 256 << 20

// Wrap RPM payload with uncompress reader, assumes that header has
// already been read.
func uncompressRpmPayloadReader(r io.Reader, hdr *RpmHeader) (io.Reader, error) {
	// Check to make sure payload format is a cpio archive. If the tag does
	// not exist, assume archive is cpio.
	if hdr.HasTag(tag.PAYLOADFORMAT) {
		val, err := hdr.GetString(tag.PAYLOADFORMAT)
		if err != nil {
			return nil, err
		}
		if val != "cpio" {
			return nil, fmt.Errorf("unknown payload format %s", val)
		}
	}

	// Check to see how the payload was compressed. If the tag does not
	// exist, check if it is gzip, if not it is uncompressed.
	var compression string
	if hdr.HasTag(tag.PAYLOADCOMPRESSOR) {
		val, err := hdr.GetString(tag.PAYLOADCOMPRESSOR)
		if err != nil {
			return nil, err
		}
		compression = val
	} else {
		// peek at the start of the payload to see if it's compressed
		b := make([]byte, 2)
		_, err := io.ReadFull(r, b)
		if err != nil {
			return nil, err
		}
		if b[0] == 0x1f && b[1] == 0x8b {
			compression = "gzip"
		} else {
			compression = "uncompressed"
		}
		// splice the peeked bytes back in
		r = io.MultiReader(bytes.NewReader(b), r)
	}

	switch compression {
	case "zstd":
		return newZstdReader(r)
	case "gzip":
		return gzip.NewReader(r)
	case "bzip2":
		return bzip2.NewReader(r), nil
	case "lzma":
		cfg := lzma.ReaderConfig{DictCap: maxDictSize}
		return cfg.NewReader(r)
	case "xz":
		return xz.ReaderConfig{DictCap: maxDictSize}.NewReader(r)
	case "uncompressed":
		// prevent ExpandPayload from closing the underlying file
		return noCloseWrapper{r}, nil
	default:
		return nil, fmt.Errorf("unknown compression type %s", compression)
	}
}

type noCloseWrapper struct {
	r io.Reader
}

func (w noCloseWrapper) Read(d []byte) (int, error) {
	return w.r.Read(d)
}

// limitedReader fails with ErrPayloadTooLarge when more than limit bytes can
// be read from the underlying reader. Unlike io.LimitReader it distinguishes
// "exactly limit bytes" from "more than limit bytes" instead of silently
// truncating. It forwards Close to the underlying reader.
type limitedReader struct {
	r     io.Reader
	limit int64
	read  int64
}

func newLimitedReader(r io.Reader, limit int64) io.Reader {
	return &limitedReader{r: r, limit: limit}
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.read > l.limit {
		return 0, ErrPayloadTooLarge
	}
	// allow one byte more than the limit so that excess data is noticed
	if rem := l.limit - l.read + 1; int64(len(p)) > rem {
		p = p[:rem]
	}
	n, err := l.r.Read(p)
	l.read += int64(n)
	if l.read > l.limit {
		return n - int(l.read-l.limit), ErrPayloadTooLarge
	}
	return n, err
}

func (l *limitedReader) Close() error {
	if c, ok := l.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
