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
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

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

// ErrDigestMismatch is matched (errors.Is) by the [DigestMismatchError]
// returned when the contents of an extracted file do not hash to the digest
// recorded for it.
var ErrDigestMismatch = errors.New("cpio: file digest mismatch")

// DigestMismatchError reports a regular file whose contents do not match the
// expected digest. The file is removed from the destination.
type DigestMismatchError struct {
	// Path is the name of the entry in the archive.
	Path string
	// Want is the expected digest, as recorded in the package header.
	Want string
	// Got is the digest of the extracted contents.
	Got string
}

// Error implements error.
func (e *DigestMismatchError) Error() string {
	return fmt.Sprintf("cpio: digest mismatch for %s: header has %s, contents hash to %s", e.Path, e.Want, e.Got)
}

// Is reports whether target is [ErrDigestMismatch].
func (e *DigestMismatchError) Is(target error) bool { return target == ErrDigestMismatch }

// FileMeta describes one file of an RPM header. A stripped (RPM v6) payload
// carries only an index into the header's file list, so everything else
// about an entry has to come from here; for ordinary newc archives it
// supplies the per-file digest and owner that the archive does not record.
type FileMeta struct {
	// Name is the path of the file as recorded in the package.
	Name string
	// Mode holds the file type and permission bits (st_mode).
	Mode uint32
	// Size is the number of content bytes the payload stores for this entry:
	// the file size, the length of a symlink target, or 0 for directories and
	// for every member of a hard link group except the one carrying the data.
	Size int64
	// UID and GID are the numeric owner, or a negative value if unknown.
	UID, GID int
	// Mtime is the modification time in seconds since the epoch.
	Mtime int64
	// Rdev is the device number of a device node (st_rdev).
	Rdev uint64
	// Inode identifies the hard link group of a regular file; zero when the
	// file is not part of a group.
	Inode uint64
	// Nlink is the number of members of the hard link group.
	Nlink int
	// Digest is the hex digest of the file contents, or empty if none is
	// recorded (directories, symlinks, ghost files).
	Digest string
}

// ExtractOptions tunes [ExtractWithOptions]. The zero value applies the
// modes and modification times recorded in the archive exactly, creates
// regular files, directories, symlinks and hard links, and skips special
// files.
type ExtractOptions struct {
	// Files supplies the file metadata of an RPM header, in header order. It
	// is required to read a stripped payload, whose entries are indexes into
	// this list. Files that are not part of the payload (%ghost) are not
	// referenced by the archive and are never created.
	Files []FileMeta

	// Umask clears the given bits of every mode before it is applied. It is
	// a unix-style mask over the permission bits (0777) and also over the
	// special bits: 07000 removes set-uid, set-gid and sticky.
	Umask uint32

	// Chown applies the owner of each entry (FileMeta.UID/GID, or the header
	// of a newc archive when Files does not cover the entry). It only takes
	// effect when the process runs as root; otherwise it is ignored with a
	// logged warning.
	Chown bool

	// SpecialFiles allows creating device nodes, FIFOs and sockets. They are
	// skipped, with a logged warning, unless it is set. Creating a device
	// node needs privileges: the call fails when mknod does.
	SpecialFiles bool

	// NewDigest returns the hash used to verify the contents of regular files
	// against FileMeta.Digest. Files whose digest is empty are not verified,
	// and nothing is verified when NewDigest is nil.
	NewDigest func() hash.Hash

	// Logger receives a warning for everything that is skipped. Nil discards.
	Logger *slog.Logger
}

// Extract the contents of a cpio stream from r to the destination directory dest.
// It is [ExtractWithOptions] with default options, so it cannot read stripped
// archives (RPM v6 payloads).
//
// The archive is untrusted. All file system operations are confined to dest
// with [os.Root]: absolute paths and ".." elements in entry names are
// neutralised, and an entry can never be written through a symbolic link
// (created earlier by the same archive or already present in dest) that
// points outside of dest. Symbolic links themselves may point anywhere, as
// they do in the packages that contain them.
//
// Permissions (including set-uid, set-gid and sticky bits) and modification
// times are applied as recorded; use [ExtractOptions.Umask] to mask them.
//
// Extract does not limit the total amount of data written; an attacker
// controlling a compressed stream can make it expand a lot. Bound the stream
// (see rpm.Rpm.SetMaxPayloadSize) when that matters.
func Extract(rs io.Reader, dest string) error {
	return ExtractWithOptions(rs, dest, nil)
}

// ExtractWithOptions extracts a cpio stream like [Extract], with the
// behaviour selected by opts (nil means defaults).
//
// Existing files that an entry replaces are removed first, so extracting over
// a previous tree works even when it holds read-only files and never writes
// through a link. Directory permissions and modification times are applied
// once all their content has been written.
func ExtractWithOptions(rs io.Reader, dest string, opts *ExtractOptions) error {
	var o ExtractOptions
	if opts != nil {
		o = *opts
	}
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

	x := &extractor{
		root:    root,
		dest:    dest,
		opts:    &o,
		log:     o.Logger,
		pending: make(map[linkKey][]string),
		created: make(map[linkKey]string),
	}
	if x.log == nil {
		x.log = slog.New(slog.DiscardHandler)
	}
	x.chown = o.Chown
	if o.Chown && os.Geteuid() != 0 {
		x.chown = false
		x.log.Warn("not running as root: file owners are not applied")
	}

	stream := NewCpioStream(rs)
	if o.Files != nil {
		sizes := make([]int64, len(o.Files))
		x.byName = make(map[string]int, len(o.Files))
		for i := range o.Files {
			sizes[i] = o.Files[i].Size
			x.byName[sanitize(o.Files[i].Name)] = i
		}
		stream.SetFileSizes(sizes)
	}

	for {
		entry, err := stream.ReadNextEntry()
		if err != nil {
			return err
		}
		if !entry.Header.stripped && entry.Header.filename == TRAILER {
			break
		}
		if err := x.extractEntry(entry); err != nil {
			return err
		}
	}
	var orphan error
	for _, names := range x.pending {
		orphan = fmt.Errorf("cpio: hard link %q has no file carrying its contents", names[0])
	}
	if orphan != nil {
		return orphan
	}
	return x.finishDirs()
}

// linkKey identifies a hard link group.
type linkKey struct{ dev, ino uint64 }

// entryMeta is what the extractor needs to know about one entry, whether it
// came from the cpio header or from the RPM header.
type entryMeta struct {
	name     string
	mode     uint32
	uid, gid int
	mtime    int64
	size     int64
	rdev     uint64
	key      linkKey
	nlink    int
	digest   string
}

type dirFix struct {
	rel string
	m   entryMeta
}

type extractor struct {
	root   *os.Root
	dest   string
	opts   *ExtractOptions
	log    *slog.Logger
	chown  bool
	byName map[string]int

	// pending holds the members of hard link groups seen before the member
	// carrying the data; created maps groups to the path that carries it.
	pending map[linkKey][]string
	created map[linkKey]string
	dirs    []dirFix
}

// sanitize cleans an archive name as a rooted path and makes it relative:
// every ".." element that would climb above the root is removed.
func sanitize(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

func (x *extractor) meta(entry *CpioEntry) (entryMeta, error) {
	h := entry.Header
	if h.stripped {
		f := &x.opts.Files[h.index]
		return entryMeta{
			name: f.Name, mode: f.Mode, uid: f.UID, gid: f.GID, mtime: f.Mtime,
			size: h.size64, rdev: f.Rdev, key: linkKey{ino: f.Inode}, nlink: f.Nlink,
			digest: f.Digest,
		}, nil
	}
	m := entryMeta{
		name: h.filename, mode: uint32(h.mode), uid: h.uid, gid: h.gid, mtime: int64(h.mtime),
		size: h.size64, rdev: fileutil.Mkdev(uint32(h.rdevmajor), uint32(h.rdevminor)),
		key: linkKey{dev: uint64(h.devmajor)<<32 | uint64(h.devminor), ino: uint64(h.ino)}, nlink: h.nlink,
	}
	if i, ok := x.byName[sanitize(h.filename)]; ok {
		// like rpm itself, trust the package header over the archive header
		// for everything but the structure of the archive
		f := &x.opts.Files[i]
		if f.Mode&^07777 != m.mode&^07777 {
			return m, fmt.Errorf("cpio: %s is of type 0%o in the payload but 0%o in the package header",
				f.Name, m.mode&^07777, f.Mode&^07777)
		}
		m.name, m.mode, m.mtime = f.Name, f.Mode, f.Mtime
		m.uid, m.gid = f.UID, f.GID
		m.digest = f.Digest
		if m.mode&^07777 == S_ISCHR || m.mode&^07777 == S_ISBLK {
			m.rdev = f.Rdev
		}
	}
	return m, nil
}

func (x *extractor) extractEntry(entry *CpioEntry) error {
	m, err := x.meta(entry)
	if err != nil {
		return err
	}
	rel := filepath.FromSlash(sanitize(m.name))
	if rel == "" {
		rel = "."
	}
	// Create the parent directory if it doesn't exist.
	if parent := filepath.Dir(rel); parent != "." {
		if err := x.root.MkdirAll(parent, 0o755); err != nil {
			return err
		}
	}

	switch m.mode &^ 07777 {
	case S_ISDIR:
		return x.extractDir(rel, m)
	case S_ISCHR, S_ISBLK, S_ISFIFO, S_ISSOCK:
		return x.extractSpecial(rel, m)
	case S_ISLNK:
		return x.extractSymlink(rel, m, entry)
	case S_ISREG:
		return x.extractRegular(rel, m, entry)
	default:
		return fmt.Errorf("unknown file mode 0%o for %s", m.mode, m.name)
	}
}

// perm converts the permission and special bits of a unix mode, masked with
// the umask, into an [os.FileMode].
func (x *extractor) perm(mode uint32) os.FileMode {
	mode &^= x.opts.Umask
	p := os.FileMode(mode & 0o777)
	if mode&S_ISUID != 0 {
		p |= os.ModeSetuid
	}
	if mode&S_ISGID != 0 {
		p |= os.ModeSetgid
	}
	if mode&S_ISVTX != 0 {
		p |= os.ModeSticky
	}
	return p
}

func (x *extractor) extractDir(rel string, m entryMeta) error {
	// writable while the content is extracted; the final mode is set by
	// finishDirs
	if err := x.root.Mkdir(rel, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	fi, err := x.root.Stat(rel)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("cpio: %q exists and is not a directory", m.name)
	}
	if err := x.root.Chmod(rel, fi.Mode().Perm()|0o700); err != nil {
		return err
	}
	x.dirs = append(x.dirs, dirFix{rel: rel, m: m})
	return nil
}

func (x *extractor) finishDirs() error {
	for i := len(x.dirs) - 1; i >= 0; i-- {
		d := x.dirs[i]
		if err := x.applyOwner(d.rel, d.m, false); err != nil {
			return err
		}
		if err := x.root.Chmod(d.rel, x.perm(d.m.mode)); err != nil {
			return err
		}
		if err := x.applyTimes(d.rel, d.m); err != nil {
			return err
		}
	}
	return nil
}

func (x *extractor) applyOwner(rel string, m entryMeta, link bool) error {
	if !x.chown || m.uid < 0 || m.gid < 0 {
		return nil
	}
	if link {
		return x.root.Lchown(rel, m.uid, m.gid)
	}
	return x.root.Chown(rel, m.uid, m.gid)
}

func (x *extractor) applyTimes(rel string, m entryMeta) error {
	t := time.Unix(m.mtime, 0)
	return x.root.Chtimes(rel, t, t)
}

// remove deletes whatever a non-directory entry replaces, so that extraction
// never writes through an existing file, hard link or symlink.
func (x *extractor) remove(rel string) error {
	fi, err := x.root.Lstat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("cpio: %q exists and is a directory", rel)
	}
	return x.root.Remove(rel)
}

func (x *extractor) extractSpecial(rel string, m entryMeta) error {
	if !x.opts.SpecialFiles {
		x.log.Warn("skipping special file: not enabled in the extract options",
			"path", m.name, "type", fileTypeName(m.mode))
		return nil
	}
	if err := x.remove(rel); err != nil {
		return err
	}
	if err := x.mknodInRoot(rel, m); err != nil {
		return err
	}
	if err := x.applyOwner(rel, m, true); err != nil {
		return err
	}
	if err := x.root.Chmod(rel, x.perm(m.mode)); err != nil {
		return err
	}
	return x.applyTimes(rel, m)
}

func fileTypeName(mode uint32) string {
	switch mode &^ 07777 {
	case S_ISCHR:
		return "character device"
	case S_ISBLK:
		return "block device"
	case S_ISFIFO:
		return "fifo"
	case S_ISSOCK:
		return "socket"
	}
	return "unknown"
}

func (x *extractor) extractSymlink(rel string, m entryMeta, entry *CpioEntry) error {
	if m.size > maxSymlinkTarget {
		return fmt.Errorf("symlink target of %q is too long", m.name)
	}
	buf := make([]byte, m.size)
	if _, err := io.ReadFull(entry.payload, buf); err != nil {
		return err
	}
	if err := x.remove(rel); err != nil {
		return err
	}
	if err := x.root.Symlink(string(buf), rel); err != nil {
		return err
	}
	return x.applyOwner(rel, m, true)
}

func (x *extractor) extractRegular(rel string, m entryMeta, entry *CpioEntry) error {
	if m.nlink > 1 {
		carrier := m.size > 0 || len(x.pending[m.key])+1 >= m.nlink
		if !carrier {
			if target, ok := x.created[m.key]; ok {
				return x.link(target, rel)
			}
			x.pending[m.key] = append(x.pending[m.key], rel)
			return nil
		}
	}
	if err := x.extractFile(rel, m, entry); err != nil {
		return err
	}
	if m.nlink > 1 {
		x.created[m.key] = rel
		for _, l := range x.pending[m.key] {
			if err := x.link(rel, l); err != nil {
				return err
			}
		}
		delete(x.pending, m.key)
	}
	return nil
}

func (x *extractor) link(target, rel string) error {
	if err := x.remove(rel); err != nil {
		return err
	}
	return x.root.Link(target, rel)
}

// extractFile writes the contents of a regular file entry to rel within root
// and applies its metadata.
func (x *extractor) extractFile(rel string, m entryMeta, entry *CpioEntry) error {
	if err := x.remove(rel); err != nil {
		return err
	}
	f, err := x.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	var w io.Writer = f
	var h hash.Hash
	if x.opts.NewDigest != nil && m.digest != "" {
		h = x.opts.NewDigest()
		w = io.MultiWriter(f, h)
	}
	written, err := io.Copy(w, entry.payload)
	if err != nil {
		_ = f.Close()
		return err
	}
	if written != m.size {
		_ = f.Close()
		return errors.New("short write")
	}
	if h != nil {
		if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, m.digest) {
			_ = f.Close()
			_ = x.root.Remove(rel)
			return &DigestMismatchError{Path: m.name, Want: m.digest, Got: got}
		}
	}
	// chown first: it clears the set-uid and set-gid bits
	if x.chown && m.uid >= 0 && m.gid >= 0 {
		if err := f.Chown(m.uid, m.gid); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Chmod(x.perm(m.mode)); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return x.applyTimes(rel, m)
}

// mknodInRoot creates a device node, FIFO or socket at rel below dest.
// [os.Root] has no mknod, so verify that the (already created) parent
// directory really resolves to a location inside dest before creating the
// node; mknod itself does not follow a symlink in the final path element.
func (x *extractor) mknodInRoot(rel string, m entryMeta) error {
	full := filepath.Join(x.dest, rel)
	realDest, err := filepath.EvalSymlinks(x.dest)
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
	mode := m.mode &^ 07000 & 0o777
	if m.mode&^07777 == S_ISFIFO {
		return fileutil.Mkfifo(full, mode)
	}
	return fileutil.Mknod(full, m.mode&^07777|mode, m.rdev)
}
