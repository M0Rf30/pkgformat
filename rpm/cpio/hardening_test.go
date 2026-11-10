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

package cpio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// newcEntry serialises one newc entry. size is written to the header as is,
// independently of len(data), so tests can lie about it.
func newcEntry(name string, mode, nlink, ino int, size uint32, data []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		ino, mode, 0, 0, nlink, 0, size, 0, 0, 0, 0, len(name)+1, 0)
	b.WriteString(name)
	b.WriteByte(0)
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	b.Write(data)
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func newcTrailer() []byte {
	return newcEntry(TRAILER, 0, 1, 0, 0, nil)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

const (
	modeReg  = S_ISREG | 0o644
	modeDir  = S_ISDIR | 0o755
	modeLink = S_ISLNK | 0o777
	modeFifo = S_ISFIFO | 0o644
)

func TestReadHeaderRejectsMalformed(t *testing.T) {
	goodTail := "00000000" // filler
	_ = goodTail
	tests := []struct {
		name string
		raw  []byte
	}{
		{"zero name size", func() []byte {
			b := newcEntry("x", modeReg, 1, 1, 0, nil)
			copy(b[6+11*8:], "00000000") // namesize
			return b
		}()},
		{"huge name size", func() []byte {
			b := newcEntry("x", modeReg, 1, 1, 0, nil)
			copy(b[6+11*8:], "ffffffff")
			return b
		}()},
		{"signed file size", func() []byte {
			b := newcEntry("x", modeReg, 1, 1, 0, nil)
			copy(b[6+6*8:], "-0000010")
			return b
		}()},
		{"plus signed field", func() []byte {
			b := newcEntry("x", modeReg, 1, 1, 0, nil)
			copy(b[6+1*8:], "+00081a4")
			return b
		}()},
		{"non-hex field", func() []byte {
			b := newcEntry("x", modeReg, 1, 1, 0, nil)
			copy(b[6:], "0xzzzzzz")
			return b
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := NewCpioStream(bytes.NewReader(cat(tt.raw, newcTrailer()))).ReadNextEntry()
				require.Error(t, err)
			})
		})
	}
}

func TestReadTruncatedHugeEntryDoesNotAllocate(t *testing.T) {
	// The header claims ~2 GiB of content that is not there. Skipping to the
	// next entry used to allocate a buffer of that size; it must now just fail.
	raw := newcEntry("big", modeReg, 1, 1, 0x7fffffff, []byte("tiny"))
	r := NewReader(bytes.NewReader(raw))
	_, err := r.Next()
	require.NoError(t, err)
	_, err = r.Next()
	require.Error(t, err)
}

func TestReadBeforeNext(t *testing.T) {
	r := NewReader(bytes.NewReader(newcTrailer()))
	require.NotPanics(t, func() {
		_, err := r.Read(make([]byte, 4))
		require.Error(t, err)
	})
}

func TestStrippedNegativeSizeAndFilesize64(t *testing.T) {
	raw, err := os.ReadFile("../testdata/stripped.cpio")
	require.NoError(t, err)

	r := NewReaderWithSizes(bytes.NewReader(raw), []int64{-1, 6})
	_, err = r.Next()
	require.Error(t, err)

	r = NewReaderWithSizes(bytes.NewReader(raw), []int64{3, 6})
	h, err := r.Next()
	require.NoError(t, err)
	require.Equal(t, int64(3), h.Filesize64())
}

func TestNameTerminatedAtNUL(t *testing.T) {
	// "a\0b" with a namesize covering all of it: the name is "a"
	b := newcEntry("a\x00b", modeReg, 1, 1, 0, nil)
	h, err := NewReader(bytes.NewReader(cat(b, newcTrailer()))).Next()
	require.NoError(t, err)
	require.Equal(t, "a", h.Filename())
}

func TestExtractDoesNotFollowSymlinkOutOfDest(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "dest")
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.Mkdir(outside, 0o755))

	archive := cat(
		newcEntry("link", modeLink, 1, 1, uint32(len(outside)), []byte(outside)),
		newcEntry("link/pwned", modeReg, 1, 2, 3, []byte("bad")),
		newcTrailer(),
	)
	err := Extract(bytes.NewReader(archive), dest)
	require.Error(t, err)
	_, statErr := os.Stat(filepath.Join(outside, "pwned"))
	require.True(t, errors.Is(statErr, os.ErrNotExist), "file was written outside of dest")
}

func TestExtractDoesNotCreateDirsThroughSymlink(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "dest")
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.Mkdir(outside, 0o755))

	archive := cat(
		newcEntry("link", modeLink, 1, 1, uint32(len(outside)), []byte(outside)),
		newcEntry("link/sub/file", modeReg, 1, 2, 3, []byte("bad")),
		newcTrailer(),
	)
	require.Error(t, Extract(bytes.NewReader(archive), dest))
	_, statErr := os.Stat(filepath.Join(outside, "sub"))
	require.True(t, errors.Is(statErr, os.ErrNotExist), "directory was created outside of dest")
}

func TestExtractFifoThroughSymlinkRejected(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "dest")
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.Mkdir(outside, 0o755))

	archive := cat(
		newcEntry("link", modeLink, 1, 1, uint32(len(outside)), []byte(outside)),
		newcEntry("link/fifo", modeFifo, 1, 2, 0, nil),
		newcTrailer(),
	)
	require.Error(t, Extract(bytes.NewReader(archive), dest))
	_, statErr := os.Lstat(filepath.Join(outside, "fifo"))
	require.True(t, errors.Is(statErr, os.ErrNotExist), "fifo was created outside of dest")
}

func TestExtractAbsoluteAndTraversalNames(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "dest")
	archive := cat(
		newcEntry("/abs/file", modeReg, 1, 1, 1, []byte("a")),
		newcEntry("../../up", modeReg, 1, 2, 1, []byte("b")),
		newcEntry("sub/../../../up2", modeReg, 1, 3, 1, []byte("c")),
		newcTrailer(),
	)
	require.NoError(t, Extract(bytes.NewReader(archive), dest))
	for _, p := range []string{"abs/file", "up", "up2"} {
		_, err := os.Stat(filepath.Join(dest, p))
		require.NoError(t, err, p)
	}
	entries, err := os.ReadDir(base)
	require.NoError(t, err)
	require.Len(t, entries, 1, "nothing may be created next to dest")
}

func TestExtractSymlinksAndHardlinks(t *testing.T) {
	dest := t.TempDir()
	archive := cat(
		newcEntry("d", modeDir, 1, 1, 0, nil),
		newcEntry("d/link", modeLink, 1, 2, 9, []byte("/abs/path")),
		newcEntry("d/h1", modeReg, 2, 3, 0, nil),
		newcEntry("d/h2", modeReg, 2, 3, 4, []byte("data")),
		newcTrailer(),
	)
	require.NoError(t, Extract(bytes.NewReader(archive), dest))
	target, err := os.Readlink(filepath.Join(dest, "d", "link"))
	require.NoError(t, err)
	require.Equal(t, "/abs/path", target)
	for _, n := range []string{"h1", "h2"} {
		got, err := os.ReadFile(filepath.Join(dest, "d", n))
		require.NoError(t, err)
		require.Equal(t, "data", string(got))
	}
}

func TestExtractOversizedSymlinkTarget(t *testing.T) {
	archive := cat(
		newcEntry("link", modeLink, 1, 1, 1<<20, bytes.Repeat([]byte{'a'}, 16)),
		newcTrailer(),
	)
	require.Error(t, Extract(bytes.NewReader(archive), t.TempDir()))
}

func TestExtractTruncatedSymlinkTarget(t *testing.T) {
	// the stream ends in the middle of the target: a short Read used to be
	// accepted as a complete target
	raw := newcEntry("link", modeLink, 1, 1, 100, []byte("short"))
	require.Error(t, Extract(io.LimitReader(bytes.NewReader(raw), int64(len(raw)-3)), t.TempDir()))
}
