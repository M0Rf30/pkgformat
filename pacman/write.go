package pacman

import (
	"archive/tar"
	"compress/gzip"
	"crypto/md5" //nolint:gosec // the .MTREE of older makepkg versions lists MD5
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// Names of the metadata files a package carries at the top of its archive.
const (
	FilePkgInfo   = ".PKGINFO"
	FileBuildInfo = ".BUILDINFO"
	FileMtree     = ".MTREE"
	FileInstall   = ".INSTALL"
	FileChangelog = ".CHANGELOG"
)

// Errors writing a package.
var (
	// ErrInvalidFile reports a File that cannot be stored: a bad path, a
	// duplicate, a path below a regular file, or a body that does not match.
	ErrInvalidFile = errors.New("pacman: invalid package file")
	// ErrUnsupportedFile reports a file type a package cannot hold (a socket).
	ErrUnsupportedFile = errors.New("pacman: unsupported file type")
	// ErrReservedName reports a payload path whose first element starts with a
	// dot: pacman treats those as package metadata.
	ErrReservedName = errors.New("pacman: reserved package path")
	// ErrUnsupportedCompression reports a compression other than zst, xz, gz.
	ErrUnsupportedCompression = errors.New("pacman: unsupported compression")
)

// File is one entry of the payload of a package: a regular file, a directory,
// a symbolic link, a hard link, a named pipe or a device node.
type File struct {
	// Path is the slash-separated path below the root of the package, such as
	// "usr/bin/tool". A leading "./" and a trailing "/" are accepted. The first
	// element must not start with a dot (see ErrReservedName).
	Path string
	// Mode holds the permission bits, setuid, setgid and sticky, plus the type
	// bit: fs.ModeDir, fs.ModeSymlink, fs.ModeNamedPipe, fs.ModeDevice (block
	// device) or fs.ModeDevice|fs.ModeCharDevice (character device). A regular
	// file and a hard link have no type bit.
	Mode fs.FileMode
	// UID and GID are the numeric owner of the entry. Uname and Gname are the
	// owner names; when empty and the number is 0 they are "root".
	UID, GID     int
	Uname, Gname string
	// DevMajor and DevMinor are the device number of a device node.
	DevMajor, DevMinor int64
	// Hardlink, when not empty, makes the entry a hard link to the regular file
	// of the package with that path. The entry takes the type, content, mode,
	// owner, time and extended attributes of that file, so Mode, Data, Open,
	// Size, UID, GID, ModTime and Xattrs are ignored. The link target must be
	// a regular file entry of its own, not another hard link.
	Hardlink string
	// Xattrs are extended attributes, such as "security.capability" for file
	// capabilities, stored as PAX records the way bsdtar (and so makepkg)
	// writes them. They need the PAX tar format.
	Xattrs map[string][]byte
	// ModTime is the modification time, kept to the second. The zero time means
	// the build date of the package.
	ModTime time.Time
	// Linkname is the target of a symbolic link.
	Linkname string
	// Data is the content of a regular file. When Open is set, Data is ignored.
	Data []byte
	// Open returns the content of a regular file, for content too large to hold
	// in memory. It is called twice (once to checksum for the .MTREE, once to
	// write) and must return the same Size bytes both times.
	Open func() (io.ReadCloser, error)
	// Size is the length of the content Open returns.
	Size int64
}

func (f *File) kind() fs.FileMode { return f.Mode & fs.ModeType }

func (f *File) size() int64 {
	if f.Open != nil {
		return f.Size
	}

	return int64(len(f.Data))
}

// Spec describes a package to write: everything the archive holds.
type Spec struct {
	// Info is the .PKGINFO. Name, Version and Arch are required. A zero
	// InstalledSz is replaced by the total size of the regular files, and an
	// empty Base by the name.
	Info PkgInfo
	// BuildInfo is the .BUILDINFO; nil leaves the file out. Its empty PkgName,
	// PkgBase, PkgVer, PkgArch, Packager and BuildDate are taken from Info.
	BuildInfo *BuildInfo
	// Scriptlets are the install hooks written to .INSTALL; nil or no hook
	// leaves the file out.
	Scriptlets *Scriptlets
	// Changelog is the content of .CHANGELOG; empty leaves the file out.
	Changelog []byte
	// Files is the payload. Parent directories that are not listed are added
	// with mode 0755.
	Files []File
}

// WriteOptions tunes how a package is written. The zero value writes a
// zstd-compressed PAX tar.
type WriteOptions struct {
	// Compression is the extension of the package: CompressionZstd (the
	// default), CompressionXZ or CompressionGzip.
	Compression string
	// Level is the compression level: a zstd level (1-22), or a gzip level
	// (1-9). Zero selects the default; xz has a single setting.
	Level int
	// ClampMTime limits every file time to the build date (Info.BuildDate), as
	// makepkg does under SOURCE_DATE_EPOCH, so the archive does not depend on
	// when the files were touched.
	ClampMTime bool
	// TarFormat is the tar flavour; the zero value selects tar.FormatPAX.
	TarFormat tar.Format
	// Generator, when not empty, names the tool in the "# Generated by" comment
	// of .PKGINFO.
	Generator string
	// MtreeMD5 adds an md5digest next to the sha256digest of every regular file
	// of the .MTREE, as older makepkg versions wrote it (they asked bsdtar for
	// "md5,sha256"). makepkg 7.1, the version checked against, writes the
	// sha256digest only, which is the default here. libarchive prints the
	// md5digest before the sha256digest.
	MtreeMD5 bool
}

func (o WriteOptions) tarFormat() tar.Format {
	if o.TarFormat == tar.FormatUnknown {
		return tar.FormatPAX
	}

	return o.TarFormat
}

// FileName returns the file name the package is published under:
// name-version-arch.pkg.tar.ext.
func (s *Spec) FileName(compression string) string {
	if compression == "" {
		compression = CompressionZstd
	}

	return PackageFileName(s.Info.Name, s.Info.Version, s.Info.Arch, compression)
}

// ScanDir lists the files below root as payload Files, in directory order.
// The top-level entries named like the generated metadata files (.PKGINFO,
// .BUILDINFO, .MTREE, .INSTALL, .CHANGELOG) are skipped, so a staging
// directory that was used before can be scanned again. Contents are opened
// lazily and never followed outside root.
//
// Files that share an inode become hard links, named pipes and device nodes
// are listed as such, and every file is owned by root:root; ScanDirWith keeps
// the owners and the extended attributes of the tree instead.
func ScanDir(root string) ([]File, error) {
	return ScanDirWith(root, ScanOptions{})
}

// ScanOptions tunes ScanDirWith.
type ScanOptions struct {
	// Owners keeps the numeric owner of each file, and its name when the user
	// and group databases know it, where ScanDir makes everything root:root.
	// A packager that is not root usually builds under fakeroot, which reports
	// root as the owner, and leaves this off.
	Owners bool
	// Xattrs keeps the extended attributes of each file, such as
	// security.capability. Only Linux reads them.
	Xattrs bool
}

// ScanDirWith is ScanDir with options.
func ScanDirWith(root string, opts ScanOptions) ([]File, error) {
	root = filepath.Clean(root)

	var files []File

	type inode struct{ dev, ino uint64 }

	firstLink := map[inode]string{}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if p == root {
			return nil
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}

		if isGeneratedName(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}

			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		f := File{Path: filepath.ToSlash(rel), Mode: info.Mode(), ModTime: info.ModTime()}
		st, haveStat := sysStat(info)

		if opts.Owners && haveStat {
			f.UID, f.GID = st.uid, st.gid
			f.Uname, f.Gname = lookupOwnerNames(st.uid, st.gid)
		}

		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			if f.Linkname, err = os.Readlink(p); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			f.Size = info.Size()
			f.Open = func() (io.ReadCloser, error) { return os.OpenInRoot(root, rel) }

			if haveStat && st.nlink > 1 {
				key := inode{st.dev, st.ino}
				if first, ok := firstLink[key]; ok {
					f.Hardlink, f.Open, f.Size = first, nil, 0
				} else {
					firstLink[key] = f.Path
				}
			}
		case info.Mode()&(fs.ModeDevice|fs.ModeNamedPipe) != 0 && haveStat:
			f.DevMajor, f.DevMinor = int64(st.rdevMajor), int64(st.rdevMinor)
		}

		if opts.Xattrs && info.Mode()&fs.ModeDevice == 0 {
			if f.Xattrs, err = listXattrs(p); err != nil {
				return err
			}
		}

		files = append(files, f)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("pacman: scanning %s: %w", root, err)
	}

	return files, nil
}

// lookupOwnerNames returns the user and group names of the numeric owner, empty
// where the databases do not know them.
func lookupOwnerNames(uid, gid int) (string, string) {
	var uname, gname string

	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		uname = u.Username
	}

	if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		gname = g.Name
	}

	return uname, gname
}

func isGeneratedName(rel string) bool {
	switch rel {
	case FilePkgInfo, FileBuildInfo, FileMtree, FileInstall, FileChangelog:
		return true
	}

	return false
}

// tarEntry is one member of the archive as it will be written.
type tarEntry struct {
	hdr  tar.Header
	data []byte
	// file supplies the content of a regular file. A hard link member points at
	// the File of the entry it links to, so the .MTREE can list its content.
	file *File
	hash [32]byte
	md5  [16]byte
}

// Write writes the package to w.
func (s *Spec) Write(w io.Writer, opts WriteOptions) error {
	compression := opts.Compression
	if compression == "" {
		compression = CompressionZstd
	}

	if compression != CompressionZstd && compression != CompressionXZ && compression != CompressionGzip {
		return fmt.Errorf("%w: %q", ErrUnsupportedCompression, compression)
	}

	entries, err := s.layout(opts)
	if err != nil {
		return err
	}

	cw, closeCompressor, err := newCompressor(w, compression, opts.Level)
	if err != nil {
		return err
	}

	tw := tar.NewWriter(cw)

	for _, e := range entries {
		if err := writeEntry(tw, e); err != nil {
			_ = tw.Close()
			_ = closeCompressor()

			return err
		}
	}

	if err := tw.Close(); err != nil {
		_ = closeCompressor()

		return fmt.Errorf("pacman: writing package: %w", err)
	}

	if err := closeCompressor(); err != nil {
		return fmt.Errorf("pacman: writing package: %w", err)
	}

	return nil
}

// WriteFile writes the package to path through a temporary file in the same
// directory, so a failed write leaves nothing behind.
func (s *Spec) WriteFile(path string, opts WriteOptions) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("pacman: creating package file: %w", err)
	}

	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())

		return err
	}

	if err := s.Write(tmp, opts); err != nil {
		return fail(err)
	}

	if err := tmp.Chmod(0o644); err != nil {
		return fail(fmt.Errorf("pacman: creating package file: %w", err))
	}

	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())

		return fmt.Errorf("pacman: creating package file: %w", err)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())

		return fmt.Errorf("pacman: creating package file: %w", err)
	}

	return nil
}

// layout validates the spec and returns the members of the archive in the
// order they are written: .PKGINFO, .BUILDINFO, .MTREE, .INSTALL, .CHANGELOG,
// then the payload sorted by path.
func (s *Spec) layout(opts WriteOptions) ([]*tarEntry, error) {
	payload, err := s.payload(opts)
	if err != nil {
		return nil, err
	}

	var size int64

	for _, e := range payload {
		if e.hdr.Typeflag == tar.TypeReg {
			size += e.hdr.Size
		}
	}

	info := s.Info
	if info.InstalledSz == 0 {
		info.InstalledSz = size
	}

	built := time.Unix(info.BuildDate, 0).UTC()

	meta := func(name string, data []byte) *tarEntry {
		return &tarEntry{
			hdr: tar.Header{
				Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: built,
				Uname: "root", Gname: "root", Format: opts.tarFormat(),
			},
			data: data,
		}
	}

	pkginfo, err := info.Render(opts.Generator)
	if err != nil {
		return nil, err
	}

	head := []*tarEntry{meta(FilePkgInfo, pkginfo)}

	if s.BuildInfo != nil {
		bi := *s.BuildInfo
		fillBuildInfo(&bi, &info)

		text, err := bi.Render()
		if err != nil {
			return nil, err
		}

		head = append(head, meta(FileBuildInfo, text))
	}

	var tail []*tarEntry

	if script := s.Scriptlets.Render(); script != nil {
		if len(script) > MaxInstallBytes {
			return nil, fmt.Errorf("%w: .INSTALL too large", ErrInvalidField)
		}

		tail = append(tail, meta(FileInstall, script))
	}

	if len(s.Changelog) > 0 {
		tail = append(tail, meta(FileChangelog, s.Changelog))
	}

	// The .MTREE lists every member but itself.
	listed := slices.Concat(head, tail, payload)

	mtree, err := buildMtree(listed, opts.MtreeMD5)
	if err != nil {
		return nil, err
	}

	return slices.Concat(head, []*tarEntry{meta(FileMtree, mtree)}, tail, payload), nil
}

func fillBuildInfo(bi *BuildInfo, info *PkgInfo) {
	if bi.PkgName == "" {
		bi.PkgName = info.Name
	}

	if bi.PkgBase == "" {
		bi.PkgBase = info.Base
	}

	if bi.PkgVer == "" {
		bi.PkgVer = info.Version
	}

	if bi.PkgArch == "" {
		bi.PkgArch = info.Arch
	}

	if bi.Packager == "" {
		bi.Packager = info.Packager
	}

	if bi.BuildDate == 0 {
		bi.BuildDate = info.BuildDate
	}
}

// buildMtree checksums the listed members and renders the gzip-compressed
// .MTREE. The hashes of payload members are stored in their entries, to be
// checked again when the member is written.
func buildMtree(listed []*tarEntry, withMD5 bool) ([]byte, error) {
	sorted := slices.Clone(listed)

	slices.SortFunc(sorted, func(a, b *tarEntry) int {
		return strings.Compare(strings.TrimSuffix(a.hdr.Name, "/"), strings.TrimSuffix(b.hdr.Name, "/"))
	})

	lines := make([]mtreeEntry, 0, len(sorted))

	for _, e := range sorted {
		line := mtreeEntry{
			path:  strings.TrimSuffix(e.hdr.Name, "/"),
			mtime: e.hdr.ModTime.Unix(),
			mode:  modeOf(&e.hdr),
			uid:   e.hdr.Uid,
			gid:   e.hdr.Gid,
		}

		switch e.hdr.Typeflag {
		case tar.TypeDir:
			line.kind = fs.ModeDir
		case tar.TypeSymlink:
			line.kind = fs.ModeSymlink
			line.link = e.hdr.Linkname
		case tar.TypeFifo:
			line.kind = fs.ModeNamedPipe
		case tar.TypeChar:
			line.kind = fs.ModeDevice | fs.ModeCharDevice
		case tar.TypeBlock:
			line.kind = fs.ModeDevice
		default:
			// A regular file, or a hard link, which the .MTREE lists as the
			// file it is: bsdtar reads the tree, not the archive.
			// A link member has no data of its own: read it as the file.
			whole := *e
			if e.hdr.Typeflag == tar.TypeLink {
				whole.hdr.Size = e.file.size()
			}

			sum, md5sum, err := whole.checksum(withMD5)
			if err != nil {
				return nil, err
			}

			e.hash, e.md5 = sum, md5sum
			line.size = whole.hdr.Size

			line.sha256 = sum
			line.md5 = md5sum
			line.withMD5 = withMD5
			line.noMode = line.path == FilePkgInfo || line.path == FileBuildInfo
		}

		lines = append(lines, line)
	}

	return gzipBytes(renderMtree(lines))
}

func modeOf(h *tar.Header) fs.FileMode {
	m := fs.FileMode(h.Mode & 0o777)

	if h.Mode&0o4000 != 0 {
		m |= fs.ModeSetuid
	}

	if h.Mode&0o2000 != 0 {
		m |= fs.ModeSetgid
	}

	if h.Mode&0o1000 != 0 {
		m |= fs.ModeSticky
	}

	return m
}

// checksum returns the SHA-256 of the member's content, and its MD5 when
// withMD5 is set.
func (e *tarEntry) checksum(withMD5 bool) ([32]byte, [16]byte, error) {
	var (
		sum    [32]byte
		md5sum [16]byte
	)

	if e.file == nil || e.file.Open == nil {
		data := e.contents()
		if withMD5 {
			md5sum = md5.Sum(data) //nolint:gosec // the .MTREE of older makepkg versions lists it
		}

		return sha256.Sum256(data), md5sum, nil
	}

	h := sha256.New()
	hm := md5.New() //nolint:gosec // see above

	var w io.Writer = h
	if withMD5 {
		w = io.MultiWriter(h, hm)
	}

	if err := e.copyBody(w); err != nil {
		return sum, md5sum, err
	}

	copy(sum[:], h.Sum(nil))

	if withMD5 {
		copy(md5sum[:], hm.Sum(nil))
	}

	return sum, md5sum, nil
}

func (e *tarEntry) contents() []byte {
	if e.file != nil {
		return e.file.Data
	}

	return e.data
}

// copyBody streams exactly hdr.Size bytes of the member's content to dst.
func (e *tarEntry) copyBody(dst io.Writer) error {
	if e.file == nil || e.file.Open == nil {
		_, err := dst.Write(e.contents())

		return err
	}

	rc, err := e.file.Open()
	if err != nil {
		return fmt.Errorf("pacman: opening %s: %w", e.hdr.Name, err)
	}

	defer func() { _ = rc.Close() }()

	n, err := io.Copy(dst, io.LimitReader(rc, e.hdr.Size))
	if err != nil {
		return fmt.Errorf("pacman: reading %s: %w", e.hdr.Name, err)
	}

	if n != e.hdr.Size {
		return fmt.Errorf("%w: %s is shorter than its declared size", ErrInvalidFile, e.hdr.Name)
	}

	var extra [1]byte
	if m, _ := rc.Read(extra[:]); m > 0 {
		return fmt.Errorf("%w: %s is longer than its declared size", ErrInvalidFile, e.hdr.Name)
	}

	return nil
}

func writeEntry(tw *tar.Writer, e *tarEntry) error {
	hdr := e.hdr

	if err := tw.WriteHeader(&hdr); err != nil {
		return fmt.Errorf("pacman: writing %s: %w", hdr.Name, err)
	}

	if hdr.Typeflag != tar.TypeReg {
		return nil
	}

	if e.file == nil || e.file.Open == nil {
		if _, err := tw.Write(e.contents()); err != nil {
			return fmt.Errorf("pacman: writing %s: %w", hdr.Name, err)
		}

		return nil
	}

	h := sha256.New()

	if err := e.copyBody(io.MultiWriter(tw, h)); err != nil {
		return err
	}

	if !equalSum(h.Sum(nil), e.hash) {
		return fmt.Errorf("%w: %s changed while the package was written", ErrInvalidFile, hdr.Name)
	}

	return nil
}

func equalSum(got []byte, want [32]byte) bool {
	return len(got) == len(want) && string(got) == string(want[:])
}

// payload validates the files and returns them as sorted tar members, with the
// missing parent directories added.
func (s *Spec) payload(opts WriteOptions) ([]*tarEntry, error) {
	built := time.Unix(s.Info.BuildDate, 0).UTC()

	stamp := func(t time.Time) time.Time {
		if t.IsZero() {
			return built
		}

		if opts.ClampMTime && t.After(built) {
			return built
		}

		return time.Unix(t.Unix(), 0).UTC()
	}

	format := opts.tarFormat()

	byPath := make(map[string]*tarEntry, len(s.Files))

	for i := range s.Files {
		f := &s.Files[i]

		name, err := cleanPayloadPath(f.Path)
		if err != nil {
			return nil, err
		}

		if _, dup := byPath[name]; dup {
			return nil, fmt.Errorf("%w: duplicate path %q", ErrInvalidFile, name)
		}

		hdr := tar.Header{
			Name: name, Mode: int64(posixMode(f.Mode)), ModTime: stamp(f.ModTime),
			Uid: f.UID, Gid: f.GID, Uname: f.Uname, Gname: f.Gname, Format: format,
		}

		if err := checkOwner(name, f); err != nil {
			return nil, err
		}

		if hdr.Uname == "" && hdr.Uid == 0 {
			hdr.Uname = "root"
		}

		if hdr.Gname == "" && hdr.Gid == 0 {
			hdr.Gname = "root"
		}

		if err := setXattrs(&hdr, name, f.Xattrs, format); err != nil {
			return nil, err
		}

		switch {
		case f.Hardlink != "":
			// Resolved below, once every path is known.
			hdr.Typeflag = tar.TypeLink
		case f.kind() == 0:
			hdr.Typeflag = tar.TypeReg
			hdr.Size = f.size()

			if hdr.Size < 0 {
				return nil, fmt.Errorf("%w: %q has a negative size", ErrInvalidFile, name)
			}
		case f.kind() == fs.ModeDir:
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
		case f.kind() == fs.ModeSymlink:
			if err := checkLinkname(name, f.Linkname); err != nil {
				return nil, err
			}

			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = f.Linkname
		case f.kind() == fs.ModeNamedPipe:
			hdr.Typeflag = tar.TypeFifo
		case f.kind() == fs.ModeDevice, f.kind() == fs.ModeDevice|fs.ModeCharDevice:
			if f.DevMajor < 0 || f.DevMinor < 0 {
				return nil, fmt.Errorf("%w: %q has a negative device number", ErrInvalidFile, name)
			}

			hdr.Typeflag = tar.TypeBlock
			if f.kind()&fs.ModeCharDevice != 0 {
				hdr.Typeflag = tar.TypeChar
			}

			hdr.Devmajor, hdr.Devminor = f.DevMajor, f.DevMinor
		default:
			return nil, fmt.Errorf("%w: %q (%v)", ErrUnsupportedFile, name, f.Mode.Type())
		}

		byPath[name] = &tarEntry{hdr: hdr, file: f}
	}

	if err := resolveHardlinks(byPath); err != nil {
		return nil, err
	}

	// Parents: add the missing directories, and refuse a path below a
	// non-directory.
	names := make([]string, 0, len(byPath))
	for name := range byPath {
		names = append(names, name)
	}

	for _, name := range names {
		for parent := parentOf(name); parent != ""; parent = parentOf(parent) {
			if cur, ok := byPath[parent]; ok {
				if cur.hdr.Typeflag != tar.TypeDir {
					return nil, fmt.Errorf("%w: %q lies below %q, which is not a directory", ErrInvalidFile, name, parent)
				}

				break
			}

			byPath[parent] = &tarEntry{hdr: tar.Header{
				Typeflag: tar.TypeDir, Name: parent + "/", Mode: 0o755, ModTime: built,
				Uname: "root", Gname: "root", Format: format,
			}}
		}
	}

	out := make([]*tarEntry, 0, len(byPath))
	for _, e := range byPath {
		out = append(out, e)
	}

	slices.SortFunc(out, func(a, b *tarEntry) int {
		return strings.Compare(strings.TrimSuffix(a.hdr.Name, "/"), strings.TrimSuffix(b.hdr.Name, "/"))
	})

	return out, nil
}

// maxOwnerName bounds an owner name.
const maxOwnerName = 256

func checkOwner(name string, f *File) error {
	if f.UID < 0 || f.GID < 0 {
		return fmt.Errorf("%w: %q has a negative owner", ErrInvalidFile, name)
	}

	for _, n := range [...]string{f.Uname, f.Gname} {
		if len(n) > maxOwnerName {
			return fmt.Errorf("%w: owner name of %q is too long", ErrInvalidFile, name)
		}

		for i := range len(n) {
			if n[i] < ' ' || n[i] == 0x7f {
				return fmt.Errorf("%w: control character in an owner name of %q", ErrInvalidFile, name)
			}
		}
	}

	return nil
}

// Prefixes of the PAX records that carry extended attributes: bsdtar writes
// both, and libarchive reads either.
const (
	paxSchilyXattr    = "SCHILY.xattr."
	paxLibarchiveAttr = "LIBARCHIVE.xattr."
)

// maxXattrs bounds the extended attributes of one entry.
const maxXattrs = 64

// setXattrs stores the extended attributes of an entry as PAX records, the
// raw value under SCHILY.xattr.<name> and the base64 value under
// LIBARCHIVE.xattr.<escaped name>, as bsdtar does.
func setXattrs(hdr *tar.Header, path string, xattrs map[string][]byte, format tar.Format) error {
	if len(xattrs) == 0 {
		return nil
	}

	if format != tar.FormatPAX {
		return fmt.Errorf("%w: %q has extended attributes, which need the PAX tar format", ErrInvalidFile, path)
	}

	if len(xattrs) > maxXattrs {
		return fmt.Errorf("%w: %q has too many extended attributes", ErrInvalidFile, path)
	}

	hdr.PAXRecords = make(map[string]string, 2*len(xattrs))

	for name, value := range xattrs {
		if name == "" || len(name) > 255 || strings.ContainsAny(name, "=\x00") {
			return fmt.Errorf("%w: bad extended attribute name %q on %q", ErrInvalidFile, name, path)
		}

		hdr.PAXRecords[paxSchilyXattr+name] = string(value)
		hdr.PAXRecords[paxLibarchiveAttr+url.PathEscape(name)] = base64.StdEncoding.EncodeToString(value)
	}

	return nil
}

// resolveHardlinks turns the entries that name a Hardlink into tar hard link
// members. tar wants the data on the first member of an inode, so the member
// that sorts first among a file and its links carries the content and the
// others link to it. Every member shares the metadata of the linked file, as
// the inodes of a tree do.
func resolveHardlinks(byPath map[string]*tarEntry) error {
	groups := map[string][]string{}

	for name, e := range byPath {
		if e.file == nil || e.file.Hardlink == "" {
			continue
		}

		target, err := cleanPayloadPath(e.file.Hardlink)
		if err != nil {
			return err
		}

		te, ok := byPath[target]

		switch {
		case !ok:
			return fmt.Errorf("%w: %q is a hard link to %q, which is not in the package", ErrInvalidFile, name, target)
		case target == name:
			return fmt.Errorf("%w: %q is a hard link to itself", ErrInvalidFile, name)
		case te.hdr.Typeflag != tar.TypeReg:
			return fmt.Errorf("%w: %q is a hard link to %q, which is not a regular file", ErrInvalidFile, name, target)
		}

		groups[target] = append(groups[target], name)
	}

	for target, links := range groups {
		base, content := byPath[target].hdr, byPath[target].file
		members := append([]string{target}, links...)
		carrier := slices.Min(members)

		for _, m := range members {
			e := byPath[m]
			hdr := base
			hdr.Name = m
			hdr.PAXRecords = maps.Clone(base.PAXRecords)

			if m != carrier {
				hdr.Typeflag = tar.TypeLink
				hdr.Linkname = carrier
				hdr.Size = 0
			}

			e.hdr = hdr
			e.file = content
		}
	}

	return nil
}

// parentOf returns the parent of a slash path, or "" at the top.
func parentOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return ""
	}

	return p[:i]
}

// cleanPayloadPath validates a payload path and returns it without a leading
// "./" or a trailing "/".
func cleanPayloadPath(raw string) (string, error) {
	name := strings.TrimPrefix(raw, "./")
	name = strings.TrimSuffix(name, "/")

	if name == "" || len(name) > MaxEntryNameLen {
		return "", fmt.Errorf("%w: %q", ErrInvalidFile, raw)
	}

	for i := range len(name) {
		if name[i] < ' ' || name[i] == 0x7f {
			return "", fmt.Errorf("%w: control character in %q", ErrInvalidFile, raw)
		}
	}

	for seg := range strings.SplitSeq(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("%w: %q", ErrInvalidFile, raw)
		}
	}

	if name[0] == '.' {
		return "", fmt.Errorf("%w: %q", ErrReservedName, raw)
	}

	return name, nil
}

func checkLinkname(name, target string) error {
	if target == "" || len(target) > MaxEntryNameLen || strings.ContainsAny(target, "\x00\n\r") {
		return fmt.Errorf("%w: bad link target for %q", ErrInvalidFile, name)
	}

	return nil
}

// newCompressor returns a writer that compresses into dst and the function
// that finishes the stream.
func newCompressor(dst io.Writer, compression string, level int) (io.Writer, func() error, error) {
	switch compression {
	case CompressionZstd:
		var zopts []zstd.EOption
		if level > 0 {
			zopts = append(zopts, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)))
		}

		zw, err := zstd.NewWriter(dst, zopts...)
		if err != nil {
			return nil, nil, fmt.Errorf("pacman: starting zstd: %w", err)
		}

		return zw, zw.Close, nil
	case CompressionGzip:
		if level == 0 {
			level = gzip.DefaultCompression
		}

		gw, err := gzip.NewWriterLevel(dst, level)
		if err != nil {
			return nil, nil, fmt.Errorf("pacman: starting gzip: %w", err)
		}

		return gw, gw.Close, nil
	default:
		xw, err := xz.NewWriter(dst)
		if err != nil {
			return nil, nil, fmt.Errorf("pacman: starting xz: %w", err)
		}

		return xw, xw.Close, nil
	}
}
