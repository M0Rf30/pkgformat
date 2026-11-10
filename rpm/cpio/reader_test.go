/*
 * Copyright (c) SAS Institute Inc.
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
	"errors"
	"io"
	"os"
	"testing"
	"testing/iotest"
)

func TestReadStripped(t *testing.T) {
	f, err := os.Open("../testdata/stripped.cpio")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := NewReaderWithSizes(iotest.HalfReader(f), []int64{3, 6})
	for i, want := range []string{"foo", "foobar"} {
		h, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !h.IsStripped() || h.Index() != i {
			t.Fatalf("wrong header: %#v", h)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("entry %d: got %q want %q", i, got, want)
		}
	}
	_, err = r.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("wrong error: %v", err)
	}
}
