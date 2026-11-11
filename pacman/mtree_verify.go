package pacman

import (
	"crypto/md5"  //nolint:gosec // the .MTREE of older makepkg versions lists MD5
	"crypto/sha1" //nolint:gosec // an mtree may list SHA-1
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"strconv"
	"strings"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck,gosec // an mtree may list RIPEMD-160
)

// Errors of the verification against an .MTREE.
var (
	// ErrMtreeMismatch is matched (errors.Is) by the *MtreeError that reports
	// files that differ from their .MTREE.
	ErrMtreeMismatch = errors.New("pacman: contents differ from the .MTREE")
	// ErrNoMtree reports a package without an .MTREE to verify against.
	ErrNoMtree = errors.New("pacman: package has no .MTREE")
)

// MaxMtreeDiffs bounds the differences an MtreeError lists.
const MaxMtreeDiffs = 10000

// DiffKind says how a path differs from the .MTREE.
type DiffKind int

// The kinds of difference.
const (
	// DiffMismatch means the path exists and one keyword differs.
	DiffMismatch DiffKind = iota
	// DiffMissing means the .MTREE lists a path that is not there.
	DiffMissing
	// DiffExtra means the archive holds a path the .MTREE does not list.
	DiffExtra
)

func (k DiffKind) String() string {
	switch k {
	case DiffMissing:
		return "missing"
	case DiffExtra:
		return "extra"
	default:
		return "mismatch"
	}
}

// MtreeDiff is one difference between a file and its .MTREE entry.
type MtreeDiff struct {
	Path string
	Kind DiffKind
	// Keyword is the mtree keyword that differs ("size", "sha256digest",
	// "mode", ...); empty for DiffMissing and DiffExtra.
	Keyword string
	// Want is the value of the .MTREE and Got the one found.
	Want, Got string
}

func (d MtreeDiff) String() string {
	switch d.Kind {
	case DiffMissing, DiffExtra:
		return d.Path + ": " + d.Kind.String()
	default:
		return fmt.Sprintf("%s: %s is %s, the .MTREE has %s", d.Path, d.Keyword, d.Got, d.Want)
	}
}

// MtreeError reports files that differ from the .MTREE. It matches
// ErrMtreeMismatch.
type MtreeError struct {
	Diffs []MtreeDiff
	// Truncated is set when more than MaxMtreeDiffs differences were found and
	// the rest is not listed.
	Truncated bool
}

func (e *MtreeError) Error() string {
	more := ""
	if len(e.Diffs) > 1 || e.Truncated {
		more = fmt.Sprintf(" (%d differences", len(e.Diffs))

		if e.Truncated {
			more += " or more"
		}

		more += ")"
	}

	return fmt.Sprintf("%v: %s%s", ErrMtreeMismatch, e.Diffs[0], more)
}

// Unwrap returns ErrMtreeMismatch.
func (e *MtreeError) Unwrap() error { return ErrMtreeMismatch }

// VerifyOptions tunes the verification against an .MTREE. The zero value
// checks every keyword the .MTREE gives.
type VerifyOptions struct {
	// IgnoreTime leaves the modification time unchecked.
	IgnoreTime bool
	// IgnoreOwner leaves uid, gid, uname and gname unchecked. A package
	// extracted by a user that is not root has the owner of that user.
	IgnoreOwner bool
	// IgnoreMode leaves the permission bits unchecked.
	IgnoreMode bool
	// SkipContent, when not nil, reports paths whose size, time and digests
	// are not checked, such as the backup files a user may have edited.
	SkipContent func(path string) bool

	// installed is set by VerifyInstalled: the times of directories are then
	// left alone, since putting files into one changes it.
	installed bool
}

// observed is what was found for one path.
type observed struct {
	typ       MtreeType
	mode      uint32
	uid, gid  int64
	haveOwner bool
	uname     string
	gname     string
	size      int64
	mtime     int64
	link      string
	sums      digestSums
}

// digestSums are the hex digests of a content, for the keys that were asked.
type digestSums struct {
	have                                   MtreeKeys
	md5, sha1, sha256, sha384, sha512, rmd string
	cksum                                  string
}

// digestKeys are the keywords of an mtree that depend on the content.
const digestKeys = KeyDigests | KeyCksum

// digester hashes a content for a set of keywords.
type digester struct {
	keys   MtreeKeys
	hashes []keyedHash
	cksum  *posixCksum
	w      io.Writer
}

type keyedHash struct {
	key MtreeKeys
	h   hash.Hash
}

func newDigester(keys MtreeKeys) *digester {
	d := &digester{keys: keys & digestKeys}

	for _, c := range []struct {
		key MtreeKeys
		new func() hash.Hash
	}{
		{KeyMD5, md5.New}, {KeySHA1, sha1.New}, {KeySHA256, sha256.New},
		{KeySHA384, sha512.New384}, {KeySHA512, sha512.New}, {KeyRMD160, ripemd160.New},
	} {
		if d.keys&c.key != 0 {
			d.hashes = append(d.hashes, keyedHash{c.key, c.new()})
		}
	}

	writers := make([]io.Writer, 0, len(d.hashes)+1)

	for _, h := range d.hashes {
		writers = append(writers, h.h)
	}

	if d.keys&KeyCksum != 0 {
		d.cksum = newPosixCksum()
		writers = append(writers, d.cksum)
	}

	d.w = io.MultiWriter(writers...)

	return d
}

func (d *digester) sums() digestSums {
	s := digestSums{have: d.keys}

	for _, h := range d.hashes {
		x := hex.EncodeToString(h.h.Sum(nil))

		switch h.key {
		case KeyMD5:
			s.md5 = x
		case KeySHA1:
			s.sha1 = x
		case KeySHA256:
			s.sha256 = x
		case KeySHA384:
			s.sha384 = x
		case KeySHA512:
			s.sha512 = x
		case KeyRMD160:
			s.rmd = x
		}
	}

	if d.cksum != nil {
		s.cksum = strconv.FormatUint(uint64(d.cksum.sum()), 10)
	}

	return s
}

// posixCksum computes the checksum of cksum(1), which mtree lists as "cksum".
type posixCksum struct {
	crc uint32
	n   uint64
}

var cksumTable = func() *[256]uint32 {
	var t [256]uint32

	for i := range t {
		c := uint32(i) << 24

		for range 8 {
			if c&0x80000000 != 0 {
				c = c<<1 ^ 0x04c11db7
			} else {
				c <<= 1
			}
		}

		t[i] = c
	}

	return &t
}()

func newPosixCksum() *posixCksum { return &posixCksum{} }

func (c *posixCksum) Write(p []byte) (int, error) {
	crc := c.crc
	for _, b := range p {
		crc = crc<<8 ^ cksumTable[byte(crc>>24)^b]
	}

	c.crc = crc
	c.n += uint64(len(p))

	return len(p), nil
}

func (c *posixCksum) sum() uint32 {
	crc := c.crc

	for n := c.n; n != 0; n >>= 8 {
		crc = crc<<8 ^ cksumTable[byte(crc>>24)^byte(n)]
	}

	return ^crc
}

// typeOfMode returns the mtree type of a file mode.
func typeOfMode(m fs.FileMode) MtreeType {
	switch {
	case m&fs.ModeDir != 0:
		return MtreeDir
	case m&fs.ModeSymlink != 0:
		return MtreeLink
	case m&fs.ModeNamedPipe != 0:
		return MtreeFifo
	case m&fs.ModeDevice != 0 && m&fs.ModeCharDevice != 0:
		return MtreeChar
	case m&fs.ModeDevice != 0:
		return MtreeBlock
	case m&fs.ModeSocket != 0:
		return MtreeSocket
	default:
		return MtreeFile
	}
}

func (s digestSums) value(key MtreeKeys) string {
	switch key {
	case KeyMD5:
		return s.md5
	case KeySHA1:
		return s.sha1
	case KeySHA256:
		return s.sha256
	case KeySHA384:
		return s.sha384
	case KeySHA512:
		return s.sha512
	case KeyRMD160:
		return s.rmd
	case KeyCksum:
		return s.cksum
	}

	return ""
}

// diffSink collects differences up to MaxMtreeDiffs.
type diffSink struct {
	diffs     []MtreeDiff
	truncated bool
}

func (s *diffSink) add(d MtreeDiff) {
	if len(s.diffs) >= MaxMtreeDiffs {
		s.truncated = true

		return
	}

	s.diffs = append(s.diffs, d)
}

func (s *diffSink) err() error {
	if len(s.diffs) == 0 {
		return nil
	}

	return &MtreeError{Diffs: s.diffs, Truncated: s.truncated}
}

var digestNames = []struct {
	key  MtreeKeys
	name string
}{
	{KeyMD5, "md5digest"}, {KeySHA1, "sha1digest"}, {KeySHA256, "sha256digest"},
	{KeySHA384, "sha384digest"}, {KeySHA512, "sha512digest"}, {KeyRMD160, "rmd160digest"}, {KeyCksum, "cksum"},
}

func wantDigest(e *MtreeEntry, key MtreeKeys) string {
	switch key {
	case KeyMD5:
		return e.MD5
	case KeySHA1:
		return e.SHA1
	case KeySHA256:
		return e.SHA256
	case KeySHA384:
		return e.SHA384
	case KeySHA512:
		return e.SHA512
	case KeyRMD160:
		return e.RMD160
	default:
		return e.Cksum
	}
}

// compare appends the differences between an .MTREE entry and what was found.
func compare(sink *diffSink, want *MtreeEntry, got *observed, o *VerifyOptions) {
	mismatch := func(keyword, w, g string) {
		sink.add(MtreeDiff{Path: want.Path, Kind: DiffMismatch, Keyword: keyword, Want: w, Got: g})
	}

	if want.Has(KeyType) && string(want.Type) != string(got.typ) {
		mismatch("type", string(want.Type), string(got.typ))

		return
	}

	if want.Has(KeyMode) && !o.IgnoreMode && want.Mode != got.mode {
		mismatch("mode", strconv.FormatUint(uint64(want.Mode), 8), strconv.FormatUint(uint64(got.mode), 8))
	}

	if !o.IgnoreOwner {
		if want.Has(KeyUID) && got.haveOwner && want.UID != got.uid {
			mismatch("uid", strconv.FormatInt(want.UID, 10), strconv.FormatInt(got.uid, 10))
		}

		if want.Has(KeyGID) && got.haveOwner && want.GID != got.gid {
			mismatch("gid", strconv.FormatInt(want.GID, 10), strconv.FormatInt(got.gid, 10))
		}

		if want.Has(KeyUname) && got.uname != "" && want.Uname != got.uname {
			mismatch("uname", want.Uname, got.uname)
		}

		if want.Has(KeyGname) && got.gname != "" && want.Gname != got.gname {
			mismatch("gname", want.Gname, got.gname)
		}
	}

	if want.Has(KeyLink) && got.typ == MtreeLink && want.Link != got.link {
		mismatch("link", want.Link, got.link)
	}

	skipContent := o.SkipContent != nil && o.SkipContent(want.Path)

	skipTime := o.IgnoreTime || skipContent || o.installed && want.Type == MtreeDir

	if want.Has(KeyTime) && !skipTime && want.Time.Unix() != got.mtime {
		mismatch("time", strconv.FormatInt(want.Time.Unix(), 10), strconv.FormatInt(got.mtime, 10))
	}

	if got.typ != MtreeFile || skipContent {
		return
	}

	if want.Has(KeySize) && want.Size != got.size {
		mismatch("size", strconv.FormatInt(want.Size, 10), strconv.FormatInt(got.size, 10))
	}

	for _, d := range digestNames {
		if want.Has(d.key) && got.sums.have&d.key != 0 && wantDigest(want, d.key) != got.sums.value(d.key) {
			mismatch(d.name, wantDigest(want, d.key), got.sums.value(d.key))
		}
	}
}

// compareAll compares every entry of the .MTREE with what was found, in the
// order of the .MTREE, and then lists the found paths it does not list.
func compareAll(sink *diffSink, mt *Mtree, found map[string]*observed, order []string, o *VerifyOptions) {
	for i := range mt.Entries {
		want := &mt.Entries[i]
		if want.Path == "." {
			continue
		}

		got, ok := found[want.Path]
		if !ok {
			if !want.Optional {
				sink.add(MtreeDiff{Path: want.Path, Kind: DiffMissing})
			}

			continue
		}

		compare(sink, want, got, o)
	}

	for _, p := range order {
		if _, ok := mt.Lookup(p); !ok && p != FileMtree {
			sink.add(MtreeDiff{Path: p, Kind: DiffExtra})
		}
	}
}

// packageVerifier checks the members of a package archive against an .MTREE
// while they stream by.
type packageVerifier struct {
	mt    *Mtree
	opts  VerifyOptions
	found map[string]*observed
	order []string
}

func newPackageVerifier(mt *Mtree, opts VerifyOptions) *packageVerifier {
	return &packageVerifier{mt: mt, opts: opts, found: map[string]*observed{}}
}

// keys returns the content keywords worth computing.
func (v *packageVerifier) keys() MtreeKeys {
	if v.mt == nil {
		return digestKeys
	}

	return v.mt.keys & digestKeys
}

// observe records the member and consumes its body. The .MTREE member is not
// recorded: the caller parses it.
func (v *packageVerifier) observe(e *Entry, body io.Reader) error {
	if !e.IsRegular() {
		v.record(e, 0, digestSums{})

		return nil
	}

	d := newDigester(v.keys())

	n, err := io.Copy(d.w, body)
	if err != nil {
		return fmt.Errorf("pacman: reading %q: %w", e.Path, err)
	}

	v.record(e, n, d.sums())

	return nil
}

// record stores what is known of the member: the size and digests of its
// content, which a member without any has none of.
func (v *packageVerifier) record(e *Entry, size int64, sums digestSums) {
	o := &observed{
		typ: typeOfMode(e.Mode), mode: posixMode(e.Mode), uid: int64(e.UID), gid: int64(e.GID), haveOwner: true,
		uname: e.Uname, gname: e.Gname, size: size, mtime: e.ModTime.Unix(), link: e.Linkname, sums: sums,
	}

	if e.Hardlink != "" {
		// bsdtar lists a hard link as the file it is.
		o.typ = MtreeFile

		if t, ok := v.found[e.Hardlink]; ok {
			o.size, o.sums = t.size, t.sums
		}
	}

	if _, dup := v.found[e.Path]; !dup {
		v.order = append(v.order, e.Path)
	}

	v.found[e.Path] = o
}

func (v *packageVerifier) result() error {
	if v.mt == nil {
		return ErrNoMtree
	}

	var sink diffSink

	compareAll(&sink, v.mt, v.found, v.order, &v.opts)

	return sink.err()
}

// VerifyPackage checks the files of a package against its own .MTREE: type,
// mode, owner, size, modification time, link target and every digest the
// .MTREE lists (md5digest, sha1digest, sha256digest, sha384digest,
// sha512digest, rmd160digest and cksum). Keywords it does not know how to
// check (flags, device, inode, nlink, contents) are ignored.
//
// It returns nil when everything matches, ErrNoMtree when the package has no
// .MTREE, and otherwise a *MtreeError that lists the differences.
func VerifyPackage(r io.Reader, opts VerifyOptions) error {
	v := newPackageVerifier(nil, opts)

	err := WalkPackage(r, func(e *Entry, body io.Reader) error {
		if e.Path == FileMtree && e.IsRegular() {
			mt, err := ParseMtree(io.LimitReader(body, maxMtreeMemberBytes))
			if err != nil {
				return err
			}

			v.mt = mt

			return nil
		}

		return v.observe(e, body)
	})
	if err != nil {
		return err
	}

	return v.result()
}

// VerifyPackageWith is VerifyPackage against an .MTREE that is given, such as
// the one of the local database, instead of the one inside the package.
func VerifyPackageWith(r io.Reader, mt *Mtree, opts VerifyOptions) error {
	v := newPackageVerifier(mt, opts)

	err := WalkPackage(r, func(e *Entry, body io.Reader) error {
		if e.Path == FileMtree {
			return nil
		}

		return v.observe(e, body)
	})
	if err != nil {
		return err
	}

	return v.result()
}

// VerifyInstalled checks installed files against an .MTREE, the way
// pacman -Qkk does. fsys is the root of the system; give it an fs.FS that
// implements fs.ReadLinkFS and does not follow links out of the root, such as
// the one of an os.Root (os.OpenRoot(dir).FS()). A path the .MTREE lists that
// is not there is DiffMissing, whatever is not listed is not looked at.
//
// Owners are compared when the file system reports them; the owner names of
// the .MTREE are not. Like pacman, it leaves the modification time of
// directories alone: installing or removing a file changes it.
func VerifyInstalled(fsys fs.FS, mt *Mtree, opts VerifyOptions) error {
	var sink diffSink

	opts.installed = true

	for i := range mt.Entries {
		want := &mt.Entries[i]

		// The dot files describe the package and are not installed.
		if strings.HasPrefix(want.Path, ".") {
			continue
		}

		got, err := observeInstalled(fsys, want, &opts, mt.keys&digestKeys)
		if errors.Is(err, fs.ErrNotExist) {
			if !want.Optional {
				sink.add(MtreeDiff{Path: want.Path, Kind: DiffMissing})
			}

			continue
		}

		if err != nil {
			return err
		}

		compare(&sink, want, got, &opts)
	}

	return sink.err()
}

func observeInstalled(fsys fs.FS, want *MtreeEntry, opts *VerifyOptions, keys MtreeKeys) (*observed, error) {
	fi, err := fs.Lstat(fsys, want.Path)
	if err != nil {
		return nil, err
	}

	o := &observed{
		typ: typeOfMode(fi.Mode()), mode: posixMode(fi.Mode()), size: fi.Size(), mtime: fi.ModTime().Unix(),
	}

	if st, ok := sysStat(fi); ok {
		o.uid, o.gid, o.haveOwner = int64(st.uid), int64(st.gid), true
	}

	switch o.typ {
	case MtreeLink:
		if o.link, err = fs.ReadLink(fsys, want.Path); err != nil {
			return nil, err
		}
	case MtreeFile:
		if keys == 0 || opts.SkipContent != nil && opts.SkipContent(want.Path) {
			break
		}

		if o.sums, err = hashFile(fsys, want.Path, keys); err != nil {
			return nil, err
		}

	}

	return o, nil
}

func hashFile(fsys fs.FS, name string, keys MtreeKeys) (digestSums, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return digestSums{}, err
	}

	defer func() { _ = f.Close() }()

	d := newDigester(keys)

	if _, err := io.Copy(d.w, f); err != nil {
		return digestSums{}, fmt.Errorf("pacman: reading %q: %w", name, err)
	}

	return d.sums(), nil
}

// String joins the differences, one per line.
func (e *MtreeError) String() string {
	var b strings.Builder

	for _, d := range e.Diffs {
		b.WriteString(d.String())
		b.WriteByte('\n')
	}

	return b.String()
}
