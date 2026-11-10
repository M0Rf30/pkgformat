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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func addSeedCpios(f *testing.F) {
	f.Helper()
	paths, err := filepath.Glob("../testdata/*.cpio")
	if err != nil {
		f.Fatal(err)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
}

// FuzzReader reads newc and stripped archives (the latter with a few
// supplemental sizes, including hostile ones).
func FuzzReader(f *testing.F) {
	addSeedCpios(f)
	f.Fuzz(func(_ *testing.T, data []byte) {
		for _, sizes := range [][]int64{nil, {3, 6}, {-1, 1 << 62, 0}} {
			r := NewReaderWithSizes(bytes.NewReader(data), sizes)
			for i := 0; i < 1000; i++ {
				h, err := r.Next()
				if err != nil {
					break
				}
				_ = h.Filename()
				if _, err := io.Copy(io.Discard, r); err != nil {
					break
				}
			}
		}
	})
}

// FuzzExtract extracts arbitrary archives and checks that nothing is ever
// created outside of the destination directory.
func FuzzExtract(f *testing.F) {
	addSeedCpios(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		base := t.TempDir()
		t.Cleanup(func() {
			// the archive may give directories modes that prevent removing them
			_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
				if err == nil && d.IsDir() {
					_ = os.Chmod(p, 0o755)
				}
				return nil
			})
		})
		_ = Extract(bytes.NewReader(data), filepath.Join(base, "dest"))
		entries, err := os.ReadDir(base)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) > 1 {
			t.Fatalf("extraction escaped the destination: %v", entries)
		}
	})
}

// FuzzWriterRoundTrip writes one file and reads it back with the Reader, in
// both archive flavours.
func FuzzWriterRoundTrip(f *testing.F) {
	f.Add("/usr/bin/x", []byte("content"), uint32(0o755), false)
	f.Add("", []byte(nil), uint32(S_ISDIR|0o755), true)
	f.Add("a", bytes.Repeat([]byte{1}, 5), uint32(S_ISREG|S_ISUID|0o755), true)
	f.Fuzz(func(t *testing.T, name string, content []byte, mode uint32, stripped bool) {
		if strings.ContainsRune(name, 0) || name == TRAILER {
			return
		}
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if stripped {
			w = NewStrippedWriter(&buf)
		}
		if err := w.WriteHeader(&Header{Name: name, Mode: mode, Size: int64(len(content)), Index: 3}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if buf.Len()%4 != 0 {
			t.Fatalf("archive of %d bytes is not 4 byte aligned", buf.Len())
		}

		r := NewReaderWithSizes(&buf, []int64{0, 0, 0, int64(len(content))})
		h, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		if stripped && h.Index() != 3 || !stripped && h.Filename() != name {
			t.Fatalf("read back %q index %d", h.Filename(), h.Index())
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		// the reader moves the target of symlinks out of the content
		if !bytes.Equal(got, content) && h.Filesize64() != 0 {
			t.Fatalf("content %q, want %q", got, content)
		}
		if _, err := r.Next(); !errors.Is(err, io.EOF) {
			t.Fatalf("want the trailer, got %v", err)
		}
	})
}
