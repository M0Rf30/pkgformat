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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm/internal/fileutil"
)

// Standard set of permission bit masks.
const (
	S_ISUID  = 04000   // Set uid
	S_ISGID  = 02000   // Set gid
	S_ISVTX  = 01000   // Save text (sticky bit)
	S_ISDIR  = 040000  // Directory
	S_ISFIFO = 010000  // FIFO
	S_ISREG  = 0100000 // Regular file
	S_ISLNK  = 0120000 // Symbolic link
	S_ISBLK  = 060000  // Block special file
	S_ISCHR  = 020000  // Character special file
	S_ISSOCK = 0140000 // Socket
)

// maxSymlinkTarget bounds the size of a symlink target read from an archive.
const maxSymlinkTarget = 4096

// Extract the contents of a cpio stream from r to the destination directory dest.
//
// The archive is untrusted. All file system operations are confined to dest
// with [os.Root]: absolute paths and ".." elements in entry names are
// neutralised, and an entry can never be written through a symbolic link
// (created earlier by the same archive or already present in dest) that
// points outside of dest. Symbolic links themselves may point anywhere, as
// they do in the packages that contain them. Files are created without
// set-uid/set-gid bits.
//
// Extract does not limit the total amount of data written; an attacker
// controlling a compressed stream can make it expand a lot. Bound the stream
// (see rpm.Rpm.SetMaxPayloadSize) when that matters.
func Extract(rs io.Reader, dest string) error {
	dest = filepath.Clean(filepath.FromSlash(dest))
	//nolint:gosec // G301: extracted package directories are meant to be world readable
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return err
	}
	defer root.Close()

	linkMap := make(map[int][]string)

	stream := NewCpioStream(rs)

	for {
		entry, err := stream.ReadNextEntry()
		if err != nil {
			return err
		}

		if entry.Header.filename == TRAILER {
			break
		}

		// Sanitize the path: cleaning it as a rooted path removes every ".."
		// element that would climb above the root, and makes it relative.
		rel := filepath.FromSlash(strings.TrimPrefix(path.Clean("/"+entry.Header.filename), "/"))
		if rel == "" {
			rel = "."
		}
		// Create the parent directory if it doesn't exist.
		if parent := filepath.Dir(rel); parent != "." {
			if err := root.MkdirAll(parent, 0o755); err != nil {
				return err
			}
		}
		// FIXME: Need a makedev implementation in go.

		switch entry.Header.Mode() &^ 07777 {
		case S_ISCHR:
			// FIXME: skipping due to lack of makedev.
			continue
		case S_ISBLK:
			// FIXME: skipping due to lack of makedev.
			continue
		case S_ISDIR:
			m := os.FileMode(entry.Header.Mode()).Perm()
			if err := root.Mkdir(rel, m); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
		case S_ISFIFO:
			if err := mkfifoInRoot(dest, rel, uint32(entry.Header.Mode())); err != nil {
				return err
			}
		case S_ISLNK:
			if entry.Header.filesize > maxSymlinkTarget {
				return fmt.Errorf("symlink target of %q is too long", entry.Header.filename)
			}
			buf := make([]byte, entry.Header.filesize)
			if _, err := io.ReadFull(entry.payload, buf); err != nil {
				return err
			}
			if err := root.Symlink(string(buf), rel); err != nil {
				return err
			}
		case S_ISREG:
			// save hardlinks until after the taget is written
			if entry.Header.nlink > 1 && entry.Header.filesize == 0 {
				linkMap[entry.Header.ino] = append(linkMap[entry.Header.ino], rel)
				continue
			}

			if err := extractFile(root, rel, entry); err != nil {
				return err
			}

			// Create hardlinks after the file content is written.
			if entry.Header.nlink > 1 && entry.Header.filesize > 0 {
				l, ok := linkMap[entry.Header.ino]
				if !ok {
					return fmt.Errorf("hardlinks missing")
				}
				delete(linkMap, entry.Header.ino)

				for _, t := range l {
					if err := root.Link(rel, t); err != nil {
						return err
					}
				}
			}
		default:
			return fmt.Errorf("unknown file mode 0%o for %s",
				entry.Header.mode, entry.Header.filename)
		}
	}

	return nil
}

// extractFile writes the contents of a regular file entry to rel within root.
func extractFile(root *os.Root, rel string, entry *CpioEntry) error {
	// FIXME: Set permissions on files when creating.
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return err
	}
	written, err := io.Copy(f, entry.payload)
	if err != nil {
		_ = f.Close()
		return err
	}
	if written != int64(entry.Header.filesize) {
		_ = f.Close()
		return fmt.Errorf("short write")
	}
	return f.Close()
}

// mkfifoInRoot creates a named pipe at rel below dest. [os.Root] has no
// mkfifo, so verify that the (already created) parent directory really
// resolves to a location inside dest before creating the node; mkfifo itself
// does not follow a symlink in the final path element.
func mkfifoInRoot(dest, rel string, mode uint32) error {
	full := filepath.Join(dest, rel)
	realDest, err := filepath.EvalSymlinks(dest)
	if err != nil {
		return err
	}
	realParent, err := filepath.EvalSymlinks(filepath.Dir(full))
	if err != nil {
		return err
	}
	if realParent != realDest && !strings.HasPrefix(realParent, realDest+string(filepath.Separator)) {
		return fmt.Errorf("invalid cpio path %q", rel)
	}
	return fileutil.Mkfifo(full, mode)
}
