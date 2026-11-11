package adb

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// File is one entry of a package: a directory, a regular file, a symbolic
// link, a hard link, a device or a named pipe.
type File struct {
	// Name is the install path: slash separated, relative, without "." or
	// ".." elements and without a trailing slash. Directories above a file
	// need not be listed; unlisted ones get the mode 0755 and the owner root.
	Name string
	// Mode holds the type and the permission bits, setuid, setgid and sticky
	// included. The types are: directory, symbolic link, named pipe, block and
	// character device and regular file. Sockets are refused.
	Mode fs.FileMode
	// Size is the length of the content of a regular file.
	Size int64
	// ModTime is the modification time, truncated to the second. The zero
	// time is the epoch.
	ModTime time.Time
	// Uname and Gname name the owner and the group. Empty means root. The
	// format records names, not numeric ids.
	Uname, Gname string
	// Xattrs are the extended attributes.
	Xattrs []Xattr
	// LinkTarget is the target of a symbolic link.
	LinkTarget string
	// HardLink, if not empty, makes a regular file a hard link to the
	// regular file of that name, which must come first in the order of the
	// package: directories by name, with the root first, files by name. The
	// content and its size are the target's and are stored once.
	HardLink string
	// Rdev is the device number of a device.
	Rdev uint64
	// Open returns the content of a regular file. It is called twice (once to
	// compute the digest, once to write) and must return Size bytes both
	// times. Nil is an empty file.
	Open func() (io.ReadCloser, error)
}

// MemFile returns a regular file with the given content, owned by root and
// stamped with the epoch. mode holds the permission bits and may add setuid,
// setgid or sticky.
func MemFile(name string, mode fs.FileMode, data []byte) File {
	return File{
		Name: name, Mode: mode &^ fs.ModeType, Size: int64(len(data)),
		Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil },
	}
}

// FilesFromDir lists the tree under dir for [Spec.Files]: every entry below
// dir in lexical order, with names relative to dir, links not followed, the
// owner root:root and the modification time the epoch, so the package does not
// depend on who built it or when. The permission bits are kept. Hard links
// are not detected: each name becomes a file of its own.
func FilesFromDir(dir string) ([]File, error) {
	dir = filepath.Clean(dir)

	var files []File

	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if p == dir {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}

		f := File{Name: filepath.ToSlash(rel), Mode: info.Mode()}

		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			if f.LinkTarget, err = os.Readlink(p); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			f.Size = info.Size()
			f.Open = func() (io.ReadCloser, error) { return os.Open(p) }
		case info.Mode()&fs.ModeNamedPipe != 0:
		case !info.IsDir():
			return specErr("%s: unsupported file type %s", f.Name, info.Mode().Type())
		}

		files = append(files, f)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("adb: %w", err)
	}

	return files, nil
}

// Spec is everything a package consists of.
type Spec struct {
	Info Info
	// Scripts are the maintainer scripts.
	Scripts Scripts
	// Triggers are the directories whose changes run the trigger script.
	Triggers []string
	// ReplacesPriority breaks ties between packages that replace each
	// other's files.
	ReplacesPriority uint64
	Files            []File
}

// WriteOptions configures the writers.
type WriteOptions struct {
	// Signers sign the ADB block, each adding a signature block.
	Signers []*Signer
	// Compression of the file; the zero value is deflate, as apk does.
	Compression Compression
	// Compat is the apk-tools version a package is to stay readable by, which
	// decides how much of the directory tree is written out: before
	// "3.0.0_pre3" the root directory is written as well; before "3.0.0_rc9"
	// every directory is; from then on directories that have the default
	// owner and mode 0755 and hold only directories are left out. The default
	// is "3.0.0_pre1", which is what apk mkpkg writes.
	Compat string
}

// defaultCompat is what apk mkpkg uses without --compat.
const defaultCompat = "3.0.0_pre1"

// compatNodes tells which directory nodes a compat version asks for.
func compatNodes(v string) (rootNode, dirNode bool, err error) {
	if v == "" {
		v = defaultCompat
	}

	if !ValidVersion(v) {
		return false, false, specErr("invalid compat version %q", v)
	}

	switch {
	case CompareVersions(v, "3.0.0_pre3") < 0:
		return true, true, nil
	case CompareVersions(v, "3.0.0_rc9") < 0:
		return false, true, nil
	default:
		return false, false, nil
	}
}

// dirNode is a directory of the package under construction.
type dirNode struct {
	name   string
	acl    ACL
	files  []*File
	nchild int
}

var defaultDirACL = ACL{Mode: 0o755, User: "root", Group: "root"}

func ownerName(s string) string {
	if s == "" {
		return "root"
	}

	return s
}

// layout arranges the files of a spec into directories.
func layout(files []File) ([]*dirNode, map[string]*File, error) {
	byName := make(map[string]*File, len(files))
	nodes := map[string]*dirNode{"": {acl: defaultDirACL}}

	var node func(name string) *dirNode

	node = func(name string) *dirNode {
		if n, ok := nodes[name]; ok {
			return n
		}

		n := &dirNode{name: name, acl: defaultDirACL}
		nodes[name] = n
		node(parentOf(name)).nchild++

		return n
	}

	for i := range files {
		f := &files[i]

		if f.Name == "" || isMaliciousPathname(f.Name) {
			return nil, nil, fmt.Errorf("%w: %w", ErrInvalidSpec, unsafeName("file name", f.Name))
		}

		if byName[f.Name] != nil {
			return nil, nil, specErr("duplicate file %q", f.Name)
		}

		byName[f.Name] = f
	}

	for i := range files {
		f := &files[i]

		for p := parentOf(f.Name); p != ""; p = parentOf(p) {
			if o := byName[p]; o != nil && o.Mode&fs.ModeDir == 0 {
				return nil, nil, specErr("%q is below %q, which is not a directory", f.Name, p)
			}
		}

		if f.Mode&fs.ModeDir != 0 {
			n := node(f.Name)
			n.acl = ACL{Mode: modeACL(f.Mode), User: ownerName(f.Uname), Group: ownerName(f.Gname), Xattrs: f.Xattrs}

			continue
		}

		n := node(parentOf(f.Name))
		n.files = append(n.files, f)
		n.nchild++
	}

	out := make([]*dirNode, 0, len(nodes))
	for _, n := range nodes {
		slices.SortFunc(n.files, func(a, b *File) int { return strings.Compare(path.Base(a.Name), path.Base(b.Name)) })
		out = append(out, n)
	}

	slices.SortFunc(out, func(a, b *dirNode) int { return strings.Compare(a.name, b.name) })

	return out, byName, nil
}

func parentOf(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[:i]
	}

	return ""
}

// fileEntry validates a file and builds the record of it, apart from the
// digest.
func fileEntry(f *File) (FileEntry, error) {
	e := FileEntry{
		Name:  path.Base(f.Name),
		ACL:   ACL{Mode: modeACL(f.Mode), User: ownerName(f.Uname), Group: ownerName(f.Gname), Xattrs: f.Xattrs},
		MTime: uint64(max(f.ModTime.Unix(), 0)),
	}

	for _, x := range f.Xattrs {
		if x.Name == "" || strings.IndexByte(x.Name, 0) >= 0 {
			return e, specErr("%q: invalid extended attribute name", f.Name)
		}
	}

	switch typ := f.Mode.Type(); typ {
	case 0:
		if f.Size < 0 {
			return e, specErr("%q: negative size", f.Name)
		}

		if f.Open == nil && f.Size > 0 && f.HardLink == "" {
			return e, specErr("%q: has a size but no content", f.Name)
		}

		e.Size = uint64(f.Size)
	case fs.ModeSymlink:
		if f.LinkTarget == "" || len(f.LinkTarget) >= 4095 {
			return e, specErr("%q: symbolic link target of %d bytes", f.Name, len(f.LinkTarget))
		}

		e.Target = append(binary.LittleEndian.AppendUint16(nil, typeLnk), f.LinkTarget...)
		e.Size = uint64(len(f.LinkTarget))
	case fs.ModeNamedPipe:
		e.Target = binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint16(nil, typeFifo), f.Rdev)
	case fs.ModeDevice:
		e.Target = binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint16(nil, typeBlk), f.Rdev)
	case fs.ModeDevice | fs.ModeCharDevice:
		e.Target = binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint16(nil, typeChr), f.Rdev)
	default:
		return e, specErr("%q: unsupported file type %s", f.Name, typ)
	}

	if f.HardLink != "" && f.Mode.Type() != 0 {
		return e, specErr("%q: only a regular file can be a hard link", f.Name)
	}

	return e, nil
}

// digestFile returns the SHA-256 of the content of a regular file, which must
// be exactly Size bytes.
func digestFile(f *File) ([]byte, error) {
	h := sha256.New()

	if f.Open == nil {
		return h.Sum(nil), nil
	}

	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("adb: opening %q: %w", f.Name, err)
	}

	defer func() { _ = rc.Close() }()

	if err := copyExactly(h, rc, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// copyExactly copies the content of a regular file, which must be Size bytes.
func copyExactly(w io.Writer, r io.Reader, f *File) error {
	n, err := io.Copy(w, io.LimitReader(r, f.Size))
	if err != nil {
		return fmt.Errorf("adb: reading %q: %w", f.Name, err)
	}

	if n != f.Size {
		return specErr("%q: content is %d bytes, Size says %d", f.Name, n, f.Size)
	}

	var extra [1]byte
	if m, _ := r.Read(extra[:]); m > 0 {
		return specErr("%q: content is longer than Size (%d)", f.Name, f.Size)
	}

	return nil
}

// pkgPlan is a package ready to be written.
type pkgPlan struct {
	adb []byte
	// data lists, in order of the blocks, the files whose content follows.
	data []dataBlock
}

type dataBlock struct {
	pathIdx, fileIdx int
	f                *File
}

// buildPackage assembles the ADB block of a package.
func buildPackage(spec *Spec, opts WriteOptions) (*pkgPlan, error) {
	rootNode, dirNodes, err := compatNodes(opts.Compat)
	if err != nil {
		return nil, err
	}

	in := spec.Info
	if in.Arch == "" {
		return nil, specErr("arch is required")
	}

	dirs, byName, err := layout(spec.Files)
	if err != nil {
		return nil, err
	}

	if err := checkHardLinks(dirs, byName); err != nil {
		return nil, err
	}

	b := newBuilder()

	infoSlots, err := b.info(&in, false)
	if err != nil {
		return nil, err
	}

	pkgSlots := make([]value, pkgReplacesPriority+1)
	if spec.ReplacesPriority != 0 {
		pkgSlots[pkgReplacesPriority] = b.uint(spec.ReplacesPriority)
	}

	linkSources := make(map[string]bool)

	for _, f := range spec.Files {
		if f.HardLink != "" {
			linkSources[f.HardLink] = true
		}
	}

	var (
		pathVals  = make([]value, 1, len(dirs)+1)
		plan      pkgPlan
		installed uint64
		digests   = make(map[string][]byte)
	)

	if len(spec.Files) == 0 {
		dirs = nil
	}

	for _, d := range dirs {
		var (
			fileVals = make([]value, 1, len(d.files)+1)
			pending  []dataBlock
		)

		for k, f := range d.files {
			e, err := fileEntry(f)
			if err != nil {
				return nil, err
			}

			var pre []byte

			switch {
			case f.Mode.Type() != 0:
			case f.HardLink != "":
				src := byName[f.HardLink]
				e.Size = uint64(src.Size)
				e.Hash = digests[f.HardLink]
				e.Target = append(binary.LittleEndian.AppendUint16(nil, typeReg), f.HardLink...)
			default:
				sum, err := digestFile(f)
				if err != nil {
					return nil, err
				}

				e.Hash = sum
				digests[f.Name] = sum
				installed += e.Size

				if linkSources[f.Name] {
					pre = append(binary.LittleEndian.AppendUint16(nil, typeReg), f.Name...)
				}

				if e.Size > 0 {
					pending = append(pending, dataBlock{fileIdx: k + 1, f: f})
				}
			}

			fileVals = append(fileVals, b.file(&e, pre))
		}

		if isDefaultDir(d) {
			if d.name == "" && !rootNode || d.name != "" && d.nchild > 0 && !dirNodes {
				continue
			}
		}

		slots := make([]value, diFiles+1)
		slots[diName] = b.str(d.name)
		slots[diACL] = b.acl(&d.acl)
		slots[diFiles] = b.object(typeObject, fileVals)
		pathVals = append(pathVals, b.object(typeObject, slots))

		for _, p := range pending {
			p.pathIdx = len(pathVals) - 1
			plan.data = append(plan.data, p)
		}
	}

	if in.InstalledSize != 0 {
		installed = in.InstalledSize
	}

	if installed == 0 && (len(spec.Files) > 0 || spec.Scripts.any()) {
		installed = 1
	}

	infoSlots[piInstalledSize] = b.uint(installed)
	infoSlots[piHashes] = b.blobRaw(make([]byte, 20))
	uidOff := infoSlots[piHashes].off() + 1

	pkgSlots[pkgInfo] = b.object(typeObject, infoSlots)
	pkgSlots[pkgPaths] = b.object(typeObject, pathVals)

	if spec.Scripts.any() {
		s := &spec.Scripts
		slots := make([]value, scPostUpgrade+1)
		slots[scTrigger] = b.str(s.Trigger)
		slots[scPreInstall] = b.str(s.PreInstall)
		slots[scPostInstall] = b.str(s.PostInstall)
		slots[scPreDeinstall] = b.str(s.PreDeinstall)
		slots[scPostDeinstall] = b.str(s.PostDeinstall)
		slots[scPreUpgrade] = b.str(s.PreUpgrade)
		slots[scPostUpgrade] = b.str(s.PostUpgrade)
		pkgSlots[pkgScripts] = b.object(typeObject, slots)
	}

	pkgSlots[pkgTriggers] = b.strs(spec.Triggers)

	raw, err := b.finish(b.object(typeObject, pkgSlots))
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(raw)
	copy(raw[uidOff:uidOff+20], sum[:20])

	plan.adb = raw

	return &plan, nil
}

// isDefaultDir reports whether a directory is what is assumed for a directory
// the package does not list.
func isDefaultDir(d *dirNode) bool {
	return len(d.files) == 0 && d.acl.Mode == defaultDirACL.Mode && d.acl.User == "root" &&
		d.acl.Group == "root" && len(d.acl.Xattrs) == 0
}

// checkHardLinks verifies that every hard link names a regular file that is
// not itself a link and that comes earlier in the package.
func checkHardLinks(dirs []*dirNode, byName map[string]*File) error {
	seq := make(map[string]int, len(byName))

	for _, d := range dirs {
		for _, f := range d.files {
			seq[f.Name] = len(seq)
		}
	}

	for _, d := range dirs {
		for _, f := range d.files {
			if f.HardLink == "" {
				continue
			}

			src := byName[f.HardLink]

			switch {
			case src == nil || src.Mode.Type() != 0:
				return specErr("%q is a hard link to %q, which is not a regular file of the package", f.Name, f.HardLink)
			case src.HardLink != "":
				return specErr("%q is a hard link to %q, which is a link itself", f.Name, f.HardLink)
			case seq[f.HardLink] >= seq[f.Name]:
				return specErr("%q is a hard link to %q, which does not come first", f.Name, f.HardLink)
			}
		}
	}

	return nil
}

// WritePackage writes the package described by spec to w, signed by the
// signers in opts. The ADB block comes out byte for byte as apk mkpkg writes
// it for the same content. It returns the package as written.
//
// Errors for a spec it refuses wrap [ErrInvalidSpec].
func WritePackage(w io.Writer, spec *Spec, opts WriteOptions) (*Package, error) {
	pp, err := buildPackage(spec, opts)
	if err != nil {
		return nil, err
	}

	blk, err := newBlock(pp.adb, Limits{})
	if err != nil {
		return nil, err
	}

	pkg, err := decodePackage(blk, Limits{MaxEntries: 1 << 30})
	if err != nil {
		return nil, err
	}

	err = writeFile(w, SchemaPackage, pp.adb, opts, func(bw *blockWriter) error {
		for _, d := range pp.data {
			if err := bw.fileData(d); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return pkg, nil
}

// blockWriter writes the blocks of a file.
type blockWriter struct{ w io.Writer }

func (bw *blockWriter) block(typ uint32, parts ...[]byte) error {
	n := uint64(0)
	for _, p := range parts {
		n += uint64(len(p))
	}

	if _, err := bw.w.Write(blockTag(typ, n)); err != nil {
		return err
	}

	for _, p := range parts {
		if _, err := bw.w.Write(p); err != nil {
			return err
		}
	}

	return bw.pad(typ, n)
}

var zeroPad [blockAlign]byte

func (bw *blockWriter) pad(typ uint32, n uint64) error {
	_, err := bw.w.Write(zeroPad[:blockPad(typ, n)])

	return err
}

// fileData writes the data block of one file.
func (bw *blockWriter) fileData(d dataBlock) error {
	f := d.f

	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("adb: opening %q: %w", f.Name, err)
	}

	defer func() { _ = rc.Close() }()

	var idx [8]byte
	binary.LittleEndian.PutUint32(idx[:4], uint32(d.pathIdx))
	binary.LittleEndian.PutUint32(idx[4:], uint32(d.fileIdx))

	n := uint64(len(idx)) + uint64(f.Size)

	if _, err := bw.w.Write(blockTag(blockData, n)); err != nil {
		return err
	}

	if _, err := bw.w.Write(idx[:]); err != nil {
		return err
	}

	if err := copyExactly(bw.w, rc, f); err != nil {
		return err
	}

	return bw.pad(blockData, n)
}

// resolve fixes the zero Compression to deflate and checks the levels.
func (c Compression) resolve() (Compression, error) {
	switch c.Alg {
	case CompNone:
		if c.Level == 0 {
			return Deflate, nil
		}

		return NoCompression, nil
	case CompDeflate:
		if c.Level < 0 || c.Level > 9 {
			return c, fmt.Errorf("%w: deflate level %d", ErrCompression, c.Level)
		}
	case CompZstd:
		if c.Level < 0 || c.Level > 22 {
			return c, fmt.Errorf("%w: zstd level %d", ErrCompression, c.Level)
		}
	default:
		return c, fmt.Errorf("%w: algorithm %d", ErrCompression, c.Alg)
	}

	return c, nil
}

// writeFile writes a whole file: the compression header, the file header, the
// ADB block, the signatures and what body adds.
func writeFile(w io.Writer, schema uint32, adbBlock []byte, opts WriteOptions, body func(*blockWriter) error) (err error) {
	comp, err := opts.Compression.resolve()
	if err != nil {
		return err
	}

	sigs := make([][]byte, 0, len(opts.Signers))

	for _, s := range opts.Signers {
		p, err := s.sign(schema, adbBlock)
		if err != nil {
			return err
		}

		sigs = append(sigs, p)
	}

	out := w
	closeOut := func() error { return nil }

	switch comp.Alg {
	case CompNone:
	case CompDeflate:
		hdr := []byte(magicDefl)
		if comp.Level != 0 {
			hdr = append([]byte(magicComp), byte(CompDeflate), byte(comp.Level))
		}

		if _, err := w.Write(hdr); err != nil {
			return err
		}

		lvl := flate.DefaultCompression
		if comp.Level != 0 {
			lvl = comp.Level
		}

		fw, err := flate.NewWriter(w, lvl)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrCompression, err)
		}

		out, closeOut = fw, fw.Close
	case CompZstd:
		hdr := append([]byte(magicComp), byte(CompZstd), byte(comp.Level))
		if _, err := w.Write(hdr); err != nil {
			return err
		}

		zw, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstdLevel(comp.Level)), zstd.WithEncoderConcurrency(1))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrCompression, err)
		}

		out, closeOut = zw, zw.Close
	}

	defer func() {
		if cerr := closeOut(); err == nil {
			err = cerr
		}
	}()

	head := binary.LittleEndian.AppendUint32([]byte(magicADB), schema)
	if _, err := out.Write(head); err != nil {
		return err
	}

	bw := &blockWriter{w: out}

	if err := bw.block(blockADB, adbBlock); err != nil {
		return err
	}

	for _, s := range sigs {
		if err := bw.block(blockSig, s); err != nil {
			return err
		}
	}

	if body == nil {
		return nil
	}

	return body(bw)
}

// zstdLevel maps a zstd level of 1 to 22 onto the encoder's four speeds.
func zstdLevel(l int) zstd.EncoderLevel {
	switch {
	case l == 0:
		return zstd.SpeedDefault
	case l <= 2:
		return zstd.SpeedFastest
	case l <= 5:
		return zstd.SpeedDefault
	case l <= 8:
		return zstd.SpeedBetterCompression
	default:
		return zstd.SpeedBestCompression
	}
}
