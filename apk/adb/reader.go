package adb

import (
	"bufio"
	"bytes"
	"crypto/sha1" //nolint:gosec // the format records SHA-1 digests of files
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"strings"
	"time"
)

// maxSigRead bounds a signature block on reading. The format allows 2048
// bytes; this leaves room for larger signatures written by others.
const maxSigRead = 64 << 10

// ReadOptions tunes the readers. The zero value applies the defaults.
type ReadOptions struct {
	Limits Limits
}

// Reader reads an APKv3 file: a package or an index.
//
// NewReader reads the ADB block, the metadata, and the signatures that
// follow it. [Reader.Package] and [Reader.Index] decode the metadata;
// [Reader.Verify] checks the signatures. For a package, [Reader.Next] and
// [Reader.Read] then walk the files and stream their content out of the data
// blocks, checking each against the digest in the metadata.
//
// A Reader does not require the file to be signed, or trusted, to hand out
// the data; check [Reader.Verify] first when the source is not trusted. A
// Reader is not safe for concurrent use.
type Reader struct {
	br      *bufio.Reader
	release func()
	lim     Limits

	schema uint32
	comp   Compression
	adb    []byte
	sigs   []Signature

	pkg *Package
	idx *Index

	// pending is the header of the first block after the signatures, which
	// NewReader has consumed.
	pending *blockHdr

	// cursor over the entries: directory pi, file fi (-1 before the
	// directory entry itself).
	pi, fi int
	done   bool
	err    error

	body *body
}

// body is the content of the current entry under reading.
type body struct {
	remain  uint64
	h       hash.Hash
	want    []byte
	padding int
	name    string
}

// NewReader reads the head of an APKv3 file from r: the file header, the ADB
// block and the signatures. Call [Reader.Close] when done with it.
func NewReader(r io.Reader, opts ReadOptions) (*Reader, error) {
	lim := opts.Limits

	br, schema, comp, release, err := openStream(r, lim.maxStream())
	if err != nil {
		return nil, err
	}

	rd := &Reader{br: br, release: release, lim: lim, schema: schema, comp: comp, fi: -1}

	if err := rd.readHead(); err != nil {
		release()

		return nil, err
	}

	return rd, nil
}

// readErr maps an error of the stream onto the package's errors.
func readErr(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return blockErr("file is truncated")
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrTooComplex):
		return err
	default:
		return fmt.Errorf("adb: reading: %w", err)
	}
}

func (r *Reader) readHead() error {
	h, err := readBlockHdr(r.br)
	if errors.Is(err, io.EOF) {
		return blockErr("no ADB block")
	}

	if err != nil {
		return err
	}

	if h.typ != blockADB {
		return blockErr("first block is of type %d, not the ADB block", h.typ)
	}

	if h.length < 16 || h.length > uint64(r.lim.maxADB()) {
		return blockErr("ADB block of %d bytes", h.length)
	}

	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r.br, int64(h.length)); err != nil {
		return readErr(err)
	}

	if err := skipPadding(r.br, h); err != nil {
		return err
	}

	r.adb = buf.Bytes()

	if _, err := newBlock(r.adb, r.lim); err != nil {
		return err
	}

	for {
		h, err := readBlockHdr(r.br)
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return err
		}

		switch h.typ {
		case blockSig:
			if h.length > maxSigRead {
				return blockErr("signature block of %d bytes", h.length)
			}

			p := make([]byte, h.length)
			if _, err := io.ReadFull(r.br, p); err != nil {
				return readErr(err)
			}

			if err := skipPadding(r.br, h); err != nil {
				return err
			}

			s, err := parseSignature(p)
			if err != nil {
				return err
			}

			r.sigs = append(r.sigs, s)
		case blockData:
			r.pending = &h

			return nil
		default:
			return blockErr("block of type %d after the ADB block", h.typ)
		}
	}
}

// Close releases the decompressor. It does not close the underlying reader.
func (r *Reader) Close() error {
	r.release()

	return nil
}

// Schema returns the schema of the file: [SchemaPackage] or [SchemaIndex].
func (r *Reader) Schema() uint32 { return r.schema }

// Compression returns how the file is compressed.
func (r *Reader) Compression() Compression { return r.comp }

// Signatures returns the signature blocks of the file, in order.
func (r *Reader) Signatures() []Signature { return r.sigs }

// ADB returns the ADB block, which the signatures cover.
func (r *Reader) ADB() []byte { return r.adb }

// Verify checks the signatures of the file against kr, and returns the id of
// the key that verified one. It fails with [ErrUnsigned] when there is no
// signature, [ErrNoKeyring] when the keyring is empty, [ErrBadSignature] when
// a signature of a trusted key does not verify and [ErrUntrusted] when no
// signature is by a trusted key.
func (r *Reader) Verify(kr *Keyring) (KeyID, error) {
	return kr.trustedBy(r.sigs, r.schema, r.adb)
}

// Package decodes the metadata of a package.
func (r *Reader) Package() (*Package, error) {
	if r.schema != SchemaPackage {
		return nil, schemaErr("schema %#08x is not a package", r.schema)
	}

	if r.pkg != nil {
		return r.pkg, nil
	}

	b, err := newBlock(r.adb, r.lim)
	if err != nil {
		return nil, err
	}

	p, err := decodePackage(b, r.lim)
	if err != nil {
		return nil, err
	}

	r.pkg = p

	return p, nil
}

// Index decodes a repository index.
func (r *Reader) Index() (*Index, error) {
	if r.schema != SchemaIndex {
		return nil, schemaErr("schema %#08x is not an index", r.schema)
	}

	if r.idx != nil {
		return r.idx, nil
	}

	b, err := newBlock(r.adb, r.lim)
	if err != nil {
		return nil, err
	}

	ix, err := decodeIndex(b, r.lim)
	if err != nil {
		return nil, err
	}

	r.idx = ix

	return ix, nil
}

// IndexInfo returns the entry that an index lists for this package: its
// metadata with the identity hash (the SHA-256 of the ADB block) and, if
// fileSize is not negative, the size of the package file.
func (r *Reader) IndexInfo(fileSize int64) (Info, error) {
	p, err := r.Package()
	if err != nil {
		return Info{}, err
	}

	in := p.Info
	sum := sha256.Sum256(r.adb)
	in.Hashes = sum[:]

	if fileSize >= 0 {
		in.FileSize = uint64(fileSize)
	}

	return in, nil
}

// Entry is one entry of a package, as [Reader.Next] returns it.
type Entry struct {
	// Name is the path of the entry, "/"-separated and relative to the root
	// of the installation.
	Name string
	Kind Kind
	// Mode holds the type and the permission bits.
	Mode fs.FileMode
	// Size is the size of the content of a regular file. A hard link records
	// the size of its target but has no content of its own.
	Size    int64
	ModTime time.Time
	User    string
	Group   string
	Xattrs  []Xattr
	// Hash is the digest of the content of a regular file.
	Hash []byte
	// LinkTarget is the target of a symbolic link, and the path of the file a
	// hard link is a link to.
	LinkTarget string
	// Rdev is the device number of a device or FIFO.
	Rdev uint64
}

func newEntry(name string, k Kind, acl *ACL) *Entry {
	e := &Entry{Name: name, Kind: k, User: acl.User, Group: acl.Group, Xattrs: acl.Xattrs}
	e.Mode = aclFileMode(acl.Mode)

	switch k {
	case KindDir:
		e.Mode |= fs.ModeDir
	case KindSymlink:
		e.Mode |= fs.ModeSymlink
	case KindBlock:
		e.Mode |= fs.ModeDevice
	case KindChar:
		e.Mode |= fs.ModeDevice | fs.ModeCharDevice
	case KindFIFO:
		e.Mode |= fs.ModeNamedPipe
	}

	return e
}

func digestFor(n int) hash.Hash {
	switch n {
	case sha1.Size:
		return sha1.New() //nolint:gosec // the format records SHA-1 digests of files
	case sha256.Size:
		return sha256.New()
	case sha512.Size:
		return sha512.New()
	default:
		return nil
	}
}

// Next returns the next entry of a package: for each directory but the root,
// the directory, then its files. The content of a regular file is read with
// [Reader.Read] until io.EOF; what is left unread is skipped, and verified, by
// the next call. At the end it returns io.EOF.
func (r *Reader) Next() (*Entry, error) {
	if r.err != nil {
		return nil, r.err
	}

	e, err := r.next()
	if err != nil && !errors.Is(err, io.EOF) {
		r.err = err
	}

	return e, err
}

func (r *Reader) next() (*Entry, error) {
	pkg, err := r.Package()
	if err != nil {
		return nil, err
	}

	if r.body != nil {
		if _, err := io.Copy(io.Discard, r); err != nil {
			return nil, err
		}
	}

	if r.done {
		return nil, io.EOF
	}

	for r.pi < len(pkg.Paths) {
		dir := &pkg.Paths[r.pi]

		if r.fi == -1 {
			r.fi = 0

			if dir.Name != "" {
				return newEntry(dir.Name, KindDir, &dir.ACL), nil
			}
		}

		if r.fi < len(dir.Files) {
			f := &dir.Files[r.fi]
			r.fi++

			return r.fileEntry(dir, f, r.pi+1, r.fi)
		}

		r.pi++
		r.fi = -1
	}

	r.done = true

	return nil, r.finish()
}

// finish checks that no data block is left after the last entry.
func (r *Reader) finish() error {
	if r.pending != nil {
		return blockErr("data block for no entry")
	}

	_, err := readBlockHdr(r.br)
	switch {
	case errors.Is(err, io.EOF):
		return io.EOF
	case err != nil:
		return err
	default:
		return blockErr("data block for no entry")
	}
}

func (r *Reader) fileEntry(dir *Dir, f *FileEntry, pathIdx, fileIdx int) (*Entry, error) {
	name := f.Name
	if dir.Name != "" {
		name = dir.Name + "/" + f.Name
	}

	kind, link, dev, err := f.kind()
	if err != nil {
		return nil, err
	}

	if kind == KindHardlink {
		// apk mkpkg writes the target of a link to a file in the root as
		// "./name".
		link = strings.TrimPrefix(link, "./")
		if isMaliciousPathname(link) {
			return nil, unsafeName("hard link target", link)
		}
	}

	e := newEntry(name, kind, &f.ACL)
	e.Size = int64(min(f.Size, 1<<62))
	e.ModTime = time.Unix(int64(min(f.MTime, 1<<62)), 0).UTC()
	e.Rdev = dev
	e.LinkTarget = link

	if kind != KindFile {
		e.Hash = f.Hash

		return e, nil
	}

	h := digestFor(len(f.Hash))
	if h == nil {
		return nil, schemaErr("file %q: digest of %d bytes", name, len(f.Hash))
	}

	e.Hash = f.Hash

	if f.Size == 0 {
		return e, nil
	}

	if err := r.openBody(name, f, h, pathIdx, fileIdx); err != nil {
		return nil, err
	}

	return e, nil
}

// openBody reads the header of the data block of a file.
func (r *Reader) openBody(name string, f *FileEntry, h hash.Hash, pathIdx, fileIdx int) error {
	var (
		bh  blockHdr
		err error
	)

	if r.pending != nil {
		bh, r.pending = *r.pending, nil
	} else if bh, err = readBlockHdr(r.br); err != nil {
		if errors.Is(err, io.EOF) {
			return blockErr("data block of %q is missing", name)
		}

		return err
	}

	if bh.typ != blockData {
		return blockErr("block of type %d where the data of %q is expected", bh.typ, name)
	}

	if bh.length < 8 {
		return blockErr("data block of %d bytes", bh.length)
	}

	var idx [8]byte
	if _, err := io.ReadFull(r.br, idx[:]); err != nil {
		return readErr(err)
	}

	gotPath, gotFile := binary.LittleEndian.Uint32(idx[:4]), binary.LittleEndian.Uint32(idx[4:])
	if int64(gotPath) != int64(pathIdx) || int64(gotFile) != int64(fileIdx) {
		return blockErr("data block for entry %d/%d where %q (%d/%d) is expected", gotPath, gotFile, name, pathIdx, fileIdx)
	}

	if bh.length-8 != f.Size {
		return blockErr("data block of %q holds %d bytes, the metadata says %d", name, bh.length-8, f.Size)
	}

	r.body = &body{remain: f.Size, h: h, want: f.Hash, padding: bh.padding, name: name}

	return nil
}

// Read reads the content of the current regular file. It returns io.EOF at
// its end, after checking the digest; an entry that is not a regular file with
// content is empty.
//
// The bytes returned before io.EOF have not yet been checked against the
// digest.
func (r *Reader) Read(p []byte) (int, error) {
	b := r.body
	if b == nil {
		if r.err != nil {
			return 0, r.err
		}

		return 0, io.EOF
	}

	if b.remain == 0 {
		return 0, r.endBody()
	}

	if uint64(len(p)) > b.remain {
		p = p[:b.remain]
	}

	n, err := r.br.Read(p)
	b.h.Write(p[:n])
	b.remain -= uint64(n)

	if err != nil && n == 0 {
		r.err = readErr(err)

		return 0, r.err
	}

	return n, nil
}

func (r *Reader) endBody() error {
	b := r.body
	r.body = nil

	if !bytes.Equal(b.h.Sum(nil), b.want) {
		r.err = fmt.Errorf("%w: %q", ErrDigest, b.name)

		return r.err
	}

	if b.padding > 0 {
		if _, err := r.br.Discard(b.padding); err != nil {
			r.err = readErr(err)

			return r.err
		}
	}

	return io.EOF
}
