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

// TODO version 2:
// - Make PayloadReader and FileInfo regular structs
// - Promote IsLink to a method of FileInfo
// - Add Close() that must be called to clean up decompressors

// PayloadReader is used to sequentially access the file contents of a RPM payload
type PayloadReader interface {
	Next() (FileInfo, error)
	Read([]byte) (int, error)
	IsLink() bool
}

type payloadReader struct {
	stream  io.Reader
	cr      *cpio.Reader
	files   []*fileInfo
	fileMap map[string]int
	isLink  []bool
	index   int
}

func newPayloadReader(r io.Reader, files []FileInfo) *payloadReader {
	sizes, _, isLink := payloadLayout(files)
	pr := &payloadReader{
		stream:  r,
		files:   make([]*fileInfo, len(files)),
		fileMap: make(map[string]int, len(files)),
		isLink:  isLink,
	}
	for i, info := range files {
		fileSt := info.(*fileInfo)
		pr.files[i] = fileSt
		pr.fileMap[fileSt.name] = i
	}
	pr.cr = cpio.NewReaderWithSizes(r, sizes)
	return pr
}

// payloadLayout works out how the payload stores each file of the header
// file list, as needed to read a stripped cpio archive (RPM v6), where the
// entries carry no size of their own.
//
// sizes[i] is the number of content bytes stored for file i: its size for a
// regular file, the length of the target for a symlink, 0 for everything
// else. A regular file in a hard link group (same device and inode) has
// content only in the last member of the group, so the others get 0 and are
// flagged in isLink. nlinks[i] is the size of the group of a regular file.
// Ghost files are not part of the payload and are ignored.
func payloadLayout(files []FileInfo) (sizes []int64, nlinks []int, isLink []bool) {
	sizes = make([]int64, len(files))
	nlinks = make([]int, len(files))
	isLink = make([]bool, len(files))
	lastInodes := make(map[uint64]int)
	groupSize := make(map[uint64]int)
	for i, info := range files {
		fileSt := info.(*fileInfo)
		if fileSt.flags&tag.RPMFILE_GHOST != 0 {
			continue
		}
		switch fileSt.fileType() {
		case cpio.S_ISREG:
			sizes[i] = fileSt.Size()

			// all but the last file in a link group will have no contents. flag
			// them so we don't try to read the nonexistent payload.
			ino := fileSt.inode64()
			if ino != 0 {
				groupSize[ino]++
				if last, ok := lastInodes[ino]; ok {
					isLink[last] = true
					sizes[last] = 0
				}
				lastInodes[ino] = i
			}
		case cpio.S_ISLNK:
			sizes[i] = int64(len(fileSt.linkName))
		}
	}
	for i, info := range files {
		fileSt := info.(*fileInfo)
		if ino := fileSt.inode64(); ino != 0 && fileSt.fileType() == cpio.S_ISREG && fileSt.flags&tag.RPMFILE_GHOST == 0 {
			if n := groupSize[ino]; n > 1 {
				nlinks[i] = n
			}
		}
	}
	return sizes, nlinks, isLink
}

// Next returns the info of the next file in the payload. After calling Next(),
// Read() can be used to read the contents of the file. Returns io.EOF when all
// files have been consumed.
func (pr *payloadReader) Next() (FileInfo, error) {
	hdr, err := pr.cr.Next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			if verr := verifyPayloadEnd(pr.stream); verr != nil {
				err = verr
			}
		}
		// close decompressor on EOF or error, zstd in particular leaks
		// goroutines otherwise
		if c, ok := pr.stream.(io.Closer); ok {
			_ = c.Close()
		}
		return nil, err
	}
	var index int
	if hdr.IsStripped() {
		index = hdr.Index()
	} else {
		var ok bool
		name := hdr.Filename()
		if len(name) > 1 && name[0] == '.' && name[1] == '/' {
			name = name[1:]
		}
		index, ok = pr.fileMap[name]
		if !ok {
			return nil, fmt.Errorf("invalid file \"%s\" in payload", name)
		}
	}
	if index >= len(pr.files) {
		return nil, errors.New("invalid file index")
	}
	pr.index = index
	return pr.files[index], nil
}

// Read bytes from the file returned by the preceding call to Next()
func (pr *payloadReader) Read(d []byte) (int, error) {
	return pr.cr.Read(d)
}

// IsLink returns true if the current file is a hard-link with no contents. A
// subsequent file with the same FileInfo.Inode and for which IsLink() returns
// false will have the contents.
func (pr *payloadReader) IsLink() bool {
	return pr.index < len(pr.isLink) && pr.isLink[pr.index]
}
