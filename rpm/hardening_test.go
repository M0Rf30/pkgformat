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
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
	"github.com/M0Rf30/pkgformat/rpm/tag"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/stretchr/testify/require"
)

// buildHeader serialises a header with the given index entries and data store.
func buildHeader(t *testing.T, tags []headerTag, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	intro := headerIntro{Magic: rpmhdr.IntroMagic, Entries: uint32(len(tags)), Size: uint32(len(data))}
	require.NoError(t, binary.Write(&b, binary.BigEndian, &intro))
	for i := range tags {
		require.NoError(t, binary.Write(&b, binary.BigEndian, &tags[i]))
	}
	b.Write(data)
	return b.Bytes()
}

func strEntry(vals ...string) rpmhdr.Entry {
	if len(vals) == 0 {
		return rpmhdr.Entry{Type: tag.RPM_STRING_ARRAY_TYPE}
	}
	return rpmhdr.Entry{
		Type:  tag.RPM_STRING_ARRAY_TYPE,
		Count: len(vals),
		Data:  []byte(strings.Join(vals, "\x00") + "\x00"),
	}
}

func u32Entry(vals ...uint32) rpmhdr.Entry {
	var b bytes.Buffer
	for _, v := range vals {
		_ = binary.Write(&b, binary.BigEndian, v)
	}
	return rpmhdr.Entry{Type: tag.RPM_INT32_TYPE, Count: len(vals), Data: b.Bytes()}
}

func introOnly(entries, size uint32) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, headerIntro{Magic: rpmhdr.IntroMagic, Entries: entries, Size: size})
	return b.Bytes()
}

func TestReadHeaderRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{"entry count overflows uint32 when multiplied by 16", introOnly(0xffffffff, 0)},
		{"too many entries", introOnly(0x10000, 0)},
		{"data size far larger than the input", introOnly(0, 0xffffffff)},
		{"data size within limits but larger than the input", introOnly(0, 0x0fffffff)},
		{
			"negative offset",
			buildHeader(t, []headerTag{{Tag: 1, DataType: tag.RPM_BIN_TYPE, Offset: -1, Count: 1}}, []byte("abcd")),
		},
		{
			"negative count",
			buildHeader(t, []headerTag{{Tag: 1, DataType: tag.RPM_BIN_TYPE, Offset: 0, Count: -1}}, []byte("abcd")),
		},
		{
			"offset beyond data",
			buildHeader(t, []headerTag{{Tag: 1, DataType: tag.RPM_BIN_TYPE, Offset: 5, Count: 0}}, []byte("abcd")),
		},
		{
			"count beyond data",
			buildHeader(t, []headerTag{{Tag: 1, DataType: tag.RPM_BIN_TYPE, Offset: 0, Count: 5}}, []byte("abcd")),
		},
		{
			"int count overflowing the data size computation",
			buildHeader(t, []headerTag{{Tag: 1, DataType: tag.RPM_INT64_TYPE, Offset: 0, Count: 0x7fffffff}}, []byte("abcd")),
		},
		{
			"string offset beyond data",
			buildHeader(t, []headerTag{{Tag: 1, DataType: tag.RPM_STRING_TYPE, Offset: 100, Count: 1}}, []byte("abcd\x00")),
		},
		{
			"string count larger than the data",
			buildHeader(t, []headerTag{{Tag: 1, DataType: tag.RPM_STRING_ARRAY_TYPE, Offset: 0, Count: 0x7fffffff}}, []byte("a\x00b\x00")),
		},
		{
			"unterminated string",
			buildHeader(t, []headerTag{{Tag: 1, DataType: tag.RPM_STRING_TYPE, Offset: 0, Count: 1}}, []byte("abcd")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := readHeader(bytes.NewReader(tt.raw), "", 0, false, false, HeaderLimits{})
				require.Error(t, err)
			})
		})
	}
}

func TestReadHeaderStringScanIsBounded(t *testing.T) {
	// Many entries that all point at the same long string would make the
	// parser rescan it once per entry.
	data := append(bytes.Repeat([]byte{'a'}, 1<<16), 0)
	tags := make([]headerTag, 1000)
	for i := range tags {
		tags[i] = headerTag{Tag: int32(i + 1), DataType: tag.RPM_STRING_TYPE, Count: 1}
	}
	_, err := readHeader(bytes.NewReader(buildHeader(t, tags, data)), "", 0, false, false, HeaderLimits{})
	require.Error(t, err)
}

func TestReadHeaderValid(t *testing.T) {
	raw := buildHeader(t, []headerTag{
		{Tag: 1000, DataType: tag.RPM_STRING_TYPE, Offset: 0, Count: 1},
		{Tag: 1001, DataType: tag.RPM_INT32_TYPE, Offset: 4, Count: 1},
	}, []byte("abc\x00\x00\x00\x00\x07"))
	hdr, err := readHeader(bytes.NewReader(raw), "", 0, false, false, HeaderLimits{})
	require.NoError(t, err)
	s, err := hdr.GetStrings(1000)
	require.NoError(t, err)
	require.Equal(t, []string{"abc"}, s)
	n, err := hdr.GetUint32s(1001)
	require.NoError(t, err)
	require.Equal(t, []uint32{7}, n)
	require.Equal(t, raw, hdr.orig)
}

func TestGetStringsOldFilenamesInconsistent(t *testing.T) {
	tests := []struct {
		name string
		hdr  map[int]rpmhdr.Entry
	}{
		{"dir index out of range", map[int]rpmhdr.Entry{
			tag.DIRNAMES: strEntry("/etc/"), tag.DIRINDEXES: u32Entry(5), tag.BASENAMES: strEntry("a"),
		}},
		{"fewer dir indexes than base names", map[int]rpmhdr.Entry{
			tag.DIRNAMES: strEntry("/etc/"), tag.DIRINDEXES: u32Entry(0), tag.BASENAMES: strEntry("a", "b"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr := &rpmHeader{entries: tt.hdr}
			require.NotPanics(t, func() {
				_, err := hdr.GetStrings(tag.OLDFILENAMES)
				require.Error(t, err)
			})
		})
	}
}

func TestGetNEVRAEmptyValues(t *testing.T) {
	hdr := &rpmHeader{entries: map[int]rpmhdr.Entry{
		tag.NAME: strEntry(), tag.VERSION: strEntry("1"), tag.RELEASE: strEntry("1"), tag.ARCH: strEntry("noarch"),
	}}
	require.NotPanics(t, func() {
		_, err := hdr.GetNEVRA()
		require.Error(t, err)
	})
}

func TestGetFilesShortAttributeArrays(t *testing.T) {
	hdr := &rpmHeader{entries: map[int]rpmhdr.Entry{
		tag.DIRNAMES:      strEntry("/etc/"),
		tag.DIRINDEXES:    u32Entry(0, 0),
		tag.BASENAMES:     strEntry("a", "b"),
		tag.FILESIZES:     u32Entry(1), // one value for two files
		tag.FILEUSERNAME:  strEntry("root", "root"),
		tag.FILEGROUPNAME: strEntry("root", "root"),
		tag.FILEFLAGS:     u32Entry(0, 0),
		tag.FILEMTIMES:    u32Entry(0, 0),
		tag.FILEDIGESTS:   strEntry("", ""),
		tag.FILEMODES:     u32Entry(0o100644, 0o100644),
		tag.FILELINKTOS:   strEntry("", ""),
	}}
	require.NotPanics(t, func() {
		_, err := hdr.GetFiles()
		require.Error(t, err)
	})
}

func TestGetStringsCountExceedsContents(t *testing.T) {
	hdr := &rpmHeader{entries: map[int]rpmhdr.Entry{
		1: {Type: tag.RPM_STRING_ARRAY_TYPE, Count: 5, Data: []byte("a\x00")},
	}}
	require.NotPanics(t, func() {
		_, err := hdr.GetStrings(1)
		require.Error(t, err)
	})
}

func TestEmptySignatureDigestTags(t *testing.T) {
	// A zero-length string array used to panic in the digest accessors.
	sigHeader := &rpmHeader{entries: map[int]rpmhdr.Entry{
		tag.SIG_SHA1:     strEntry(),
		tag.SIG_SHA256:   strEntry(),
		tag.SIG_SHA3_256: strEntry(),
	}}
	require.NotPanics(t, func() {
		require.Empty(t, getSha1(sigHeader))
		require.Empty(t, getSha256(sigHeader))
		require.Empty(t, getSha3_256(sigHeader))
	})
}

func TestSignDefaultOptions(t *testing.T) {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(testkey)))
	require.NoError(t, err)
	entity := keyring[0]

	f, err := os.Open("testdata/simple-1.0.1-1.i386.rpm")
	require.NoError(t, err)
	defer f.Close()

	// documented: an unset Hash defaults to SHA-256, an unset CreationTime to now.
	// A non-nil but empty SignatureOptions used to panic on the zero hash.
	h, err := SignRpmStream(f, entity.PrivateKey, &SignatureOptions{})
	require.NoError(t, err)
	sigblob, err := h.DumpSignatureHeader(false)
	require.NoError(t, err)
	_, err = f.Seek(int64(h.OriginalSignatureHeaderSize()), io.SeekStart)
	require.NoError(t, err)
	_, sigs, err := Verify(io.MultiReader(bytes.NewReader(sigblob), f), keyring)
	require.NoError(t, err)
	require.NotEmpty(t, sigs)
	for _, sig := range sigs {
		require.False(t, sig.CreationTime.IsZero())
	}
}

func TestRewriteRpmFailureKeepsOutput(t *testing.T) {
	f, err := os.Open("testdata/simple-1.0.1-1.i386.rpm")
	require.NoError(t, err)
	defer f.Close()
	hdr, err := ReadHeader(f)
	require.NoError(t, err)

	outpath := filepath.Join(t.TempDir(), "out.rpm")
	require.NoError(t, os.WriteFile(outpath, []byte("precious"), 0o644))

	// A directory can be stat'ed but not read, so writing the RPM fails midway.
	dir, err := os.Open(t.TempDir())
	require.NoError(t, err)
	defer dir.Close()

	require.Error(t, rewriteRpm(dir, outpath, hdr))

	got, err := os.ReadFile(outpath)
	require.NoError(t, err)
	require.Equal(t, "precious", string(got), "failed rewrite must not replace the output")
	entries, err := os.ReadDir(filepath.Dir(outpath))
	require.NoError(t, err)
	require.Len(t, entries, 1, "temporary file must be cleaned up")
}

func TestUncompressHugeLZMADictionary(t *testing.T) {
	// .lzma header: properties, 4 byte dictionary size, 8 byte unknown size.
	stream := append([]byte{0x5d, 0xff, 0xff, 0xff, 0x7f}, bytes.Repeat([]byte{0xff}, 8)...)
	stream = append(stream, 0, 0, 0, 0, 0)
	hdr := &RpmHeader{
		sigHeader: &rpmHeader{entries: map[int]rpmhdr.Entry{}},
		genHeader: &rpmHeader{entries: map[int]rpmhdr.Entry{
			tag.PAYLOADCOMPRESSOR: strEntry("lzma"),
		}},
	}
	_, err := uncompressRpmPayloadReader(bytes.NewReader(stream), hdr)
	require.Error(t, err)
}

func TestSetMaxPayloadSize(t *testing.T) {
	open := func() *Rpm {
		f, err := os.Open("testdata/payload-test-0.1-w9.gzdio.x86_64.rpm")
		require.NoError(t, err)
		t.Cleanup(func() { f.Close() })
		rpm, err := ReadRpm(f)
		require.NoError(t, err)
		return rpm
	}
	size, err := open().Header.PayloadSize()
	require.NoError(t, err)
	require.Positive(t, size)

	// exactly the declared size is fine
	rpm := open()
	rpm.SetMaxPayloadSize(size)
	require.NoError(t, rpm.ExpandPayload(t.TempDir()))

	// one byte less is rejected
	rpm = open()
	rpm.SetMaxPayloadSize(size - 1)
	err = rpm.ExpandPayload(t.TempDir())
	require.ErrorIs(t, err, ErrPayloadTooLarge)

	// the reader API is limited too
	rpm = open()
	rpm.SetMaxPayloadSize(16)
	pr, err := rpm.PayloadReaderExtended()
	require.NoError(t, err)
	var gotErr error
	for gotErr == nil {
		_, gotErr = pr.Next()
	}
	require.True(t, errors.Is(gotErr, ErrPayloadTooLarge) || errors.Is(gotErr, io.ErrUnexpectedEOF), gotErr)
}
