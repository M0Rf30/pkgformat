package adb

import (
	"encoding/hex"
	"io/fs"
	"strings"
)

// Schema magics: the four bytes after "ADB." that tell what the root object
// of the file is.
const (
	// SchemaPackage is the schema of a package: "pckg".
	SchemaPackage uint32 = 0x676b6370
	// SchemaIndex is the schema of a repository index: "indx".
	SchemaIndex uint32 = 0x78646e69
	// SchemaInstalledDB is the schema of the installed-packages database.
	// This package reads and writes only the other two.
	SchemaInstalledDB uint32 = 0x00626469
)

// Info is the metadata of a package: the "info" object of a package and an
// element of the "packages" array of an index.
type Info struct {
	Name    string
	Version string
	// Hashes identifies the package: 20 bytes in a package (a digest of its
	// own ADB block, with this field zeroed), 32 bytes in an index entry (the
	// SHA-256 of the package's ADB block).
	Hashes      []byte
	Description string
	Arch        string
	License     string
	Origin      string
	Maintainer  string
	URL         string
	// RepoCommit is the commit the package was built from, as hexadecimal.
	RepoCommit string
	// BuildTime is a Unix time.
	BuildTime     uint64
	InstalledSize uint64
	// FileSize is the size of the package file; set in index entries.
	FileSize         uint64
	ProviderPriority uint64
	// Dependency lists, one string per entry in apk syntax ("name>=1.2",
	// "!name"); see [ParseDependency].
	Depends    []string
	Provides   []string
	Replaces   []string
	InstallIf  []string
	Recommends []string
	Layer      uint64
	Tags       []string
}

// Xattr is an extended attribute of a file.
type Xattr struct {
	Name  string
	Value []byte
}

// ACL is the ownership and permissions of a file or directory. The format
// records the names of the owner and the group, not numeric ids.
type ACL struct {
	// Mode holds the permission bits, with setuid, setgid and sticky as the
	// octal 04000, 02000 and 01000.
	Mode   uint32
	User   string
	Group  string
	Xattrs []Xattr
}

// FileEntry is one file of a directory of a package.
type FileEntry struct {
	// Name is the file name, without the directory.
	Name string
	ACL  ACL
	// Size is the size of the content of a regular file.
	Size  uint64
	MTime uint64
	// Hash is the digest of the content of a regular file: SHA-1, SHA-256 or
	// SHA-512 by its length of 20, 32 or 64 bytes.
	Hash []byte
	// Target is the raw "target" field: the file type as a little-endian
	// 16-bit mode, then the link target (symbolic and hard links) or the
	// 64-bit device number (devices and FIFOs). Empty for a regular file.
	Target []byte
}

// Dir is one directory of a package with the files it holds. The root has an
// empty name.
type Dir struct {
	// Name is the path of the directory, "/"-separated, without a leading or
	// trailing slash.
	Name  string
	ACL   ACL
	Files []FileEntry
}

// Scripts are the maintainer scripts of a package.
type Scripts struct {
	Trigger       string
	PreInstall    string
	PostInstall   string
	PreDeinstall  string
	PostDeinstall string
	PreUpgrade    string
	PostUpgrade   string
}

func (s *Scripts) any() bool {
	return s.Trigger != "" || s.PreInstall != "" || s.PostInstall != "" || s.PreDeinstall != "" ||
		s.PostDeinstall != "" || s.PreUpgrade != "" || s.PostUpgrade != ""
}

// Package is the root object of a package: its metadata, the file tree and
// the scripts.
type Package struct {
	Info             Info
	Paths            []Dir
	Scripts          Scripts
	Triggers         []string
	ReplacesPriority uint64
}

// Index is the root object of a repository index.
type Index struct {
	Description string
	// PkgnameSpec is the template of the file names of the packages.
	PkgnameSpec string
	Packages    []Info
}

// Field numbers of the schemas.
const (
	piName = iota + 1
	piVersion
	piHashes
	piDescription
	piArch
	piLicense
	piOrigin
	piMaintainer
	piURL
	piRepoCommit
	piBuildTime
	piInstalledSize
	piFileSize
	piProviderPriority
	piDepends
	piProvides
	piReplaces
	piInstallIf
	piRecommends
	piLayer
	piTags
	piMax
)

const (
	depName = iota + 1
	depVersion
	depMatch
)

const (
	aclMode = iota + 1
	aclUser
	aclGroup
	aclXattrs
)

const (
	fiName = iota + 1
	fiACL
	fiSize
	fiMTime
	fiHash
	fiTarget
)

const (
	diName = iota + 1
	diACL
	diFiles
)

const (
	scTrigger = iota + 1
	scPreInstall
	scPostInstall
	scPreDeinstall
	scPostDeinstall
	scPreUpgrade
	scPostUpgrade
)

const (
	pkgInfo = iota + 1
	pkgPaths
	pkgScripts
	pkgTriggers
	pkgReplacesPriority
)

const (
	ndxDescription = iota + 1
	ndxPackages
	ndxPkgnameSpec
)

// decoder reads typed values out of a block, remembering the first error.
type decoder struct {
	b   *block
	err error
	// maxEntries bounds the elements of one array.
	maxEntries int
}

func (d *decoder) fail(err error) {
	if d.err == nil {
		d.err = err
	}
}

func (d *decoder) obj(o obj, i int) obj {
	if d.err != nil {
		return obj{b: d.b, num: 1}
	}

	s, err := o.obj(i)
	d.fail(err)

	if err != nil {
		return obj{b: d.b, num: 1}
	}

	return s
}

func (d *decoder) str(o obj, i int) string {
	if d.err != nil {
		return ""
	}

	s, err := o.str(i)
	d.fail(err)

	return s
}

func (d *decoder) bytes(o obj, i int) []byte {
	if d.err != nil {
		return nil
	}

	p, err := o.blob(i)
	d.fail(err)

	if len(p) == 0 {
		return nil
	}

	return append([]byte(nil), p...)
}

func (d *decoder) uint(o obj, i int) uint64 {
	if d.err != nil {
		return 0
	}

	n, err := o.uint(i)
	d.fail(err)

	return n
}

// items checks the array bound and returns the number of items.
func (d *decoder) items(o obj) int {
	if o.items() > d.maxEntries {
		d.fail(ErrTooComplex)

		return 0
	}

	return o.items()
}

func (d *decoder) strings(o obj, i int) []string {
	arr := d.obj(o, i)

	n := d.items(arr)
	if n == 0 {
		return nil
	}

	out := make([]string, 0, n)
	for k := 1; k <= n && d.err == nil; k++ {
		out = append(out, d.str(arr, k))
	}

	return out
}

func (d *decoder) deps(o obj, i int) []string {
	arr := d.obj(o, i)

	n := d.items(arr)
	if n == 0 {
		return nil
	}

	out := make([]string, 0, n)

	for k := 1; k <= n && d.err == nil; k++ {
		dep := d.obj(arr, k)

		m := d.uint(dep, depMatch)
		if m > 0xff {
			d.fail(schemaErr("dependency match %#x", m))
		}

		out = append(out, Dependency{
			Name:    d.str(dep, depName),
			Version: d.str(dep, depVersion),
			Match:   Match(m),
		}.String())
	}

	return out
}

func (d *decoder) info(o obj) Info {
	in := Info{
		Name:             d.str(o, piName),
		Version:          d.str(o, piVersion),
		Hashes:           d.bytes(o, piHashes),
		Description:      d.str(o, piDescription),
		Arch:             d.str(o, piArch),
		License:          d.str(o, piLicense),
		Origin:           d.str(o, piOrigin),
		Maintainer:       d.str(o, piMaintainer),
		URL:              d.str(o, piURL),
		BuildTime:        d.uint(o, piBuildTime),
		InstalledSize:    d.uint(o, piInstalledSize),
		FileSize:         d.uint(o, piFileSize),
		ProviderPriority: d.uint(o, piProviderPriority),
		Layer:            d.uint(o, piLayer),
		Depends:          d.deps(o, piDepends),
		Provides:         d.deps(o, piProvides),
		Replaces:         d.deps(o, piReplaces),
		InstallIf:        d.deps(o, piInstallIf),
		Recommends:       d.deps(o, piRecommends),
		Tags:             d.strings(o, piTags),
	}

	if c := d.bytes(o, piRepoCommit); c != nil {
		in.RepoCommit = hex.EncodeToString(c)
	}

	return in
}

func (d *decoder) acl(o obj, i int) ACL {
	a := d.obj(o, i)

	acl := ACL{
		User:  d.str(a, aclUser),
		Group: d.str(a, aclGroup),
	}

	mode := d.uint(a, aclMode)
	if mode > 0xffff {
		d.fail(schemaErr("file mode %#o", mode))
	}

	acl.Mode = uint32(mode)

	x := d.obj(a, aclXattrs)
	for k := 1; k <= d.items(x) && d.err == nil; k++ {
		p, err := x.blob(k)
		d.fail(err)

		name, val, ok := strings.Cut(string(p), "\x00")
		if !ok {
			d.fail(schemaErr("malformed extended attribute"))

			break
		}

		acl.Xattrs = append(acl.Xattrs, Xattr{Name: name, Value: []byte(val)})
	}

	return acl
}

func (d *decoder) file(o obj) FileEntry {
	f := FileEntry{
		Name:   d.str(o, fiName),
		ACL:    d.acl(o, fiACL),
		Size:   d.uint(o, fiSize),
		MTime:  d.uint(o, fiMTime),
		Hash:   d.bytes(o, fiHash),
		Target: d.bytes(o, fiTarget),
	}

	if d.err == nil && isMaliciousFilename(f.Name) {
		d.fail(unsafeName("file name", f.Name))
	}

	return f
}

func (d *decoder) pkg(o obj) Package {
	p := Package{
		Info:             d.info(d.obj(o, pkgInfo)),
		Triggers:         d.strings(o, pkgTriggers),
		ReplacesPriority: d.uint(o, pkgReplacesPriority),
	}

	sc := d.obj(o, pkgScripts)
	p.Scripts = Scripts{
		Trigger:       d.str(sc, scTrigger),
		PreInstall:    d.str(sc, scPreInstall),
		PostInstall:   d.str(sc, scPostInstall),
		PreDeinstall:  d.str(sc, scPreDeinstall),
		PostDeinstall: d.str(sc, scPostDeinstall),
		PreUpgrade:    d.str(sc, scPreUpgrade),
		PostUpgrade:   d.str(sc, scPostUpgrade),
	}

	paths := d.obj(o, pkgPaths)
	total := 0

	for i := 1; i <= d.items(paths) && d.err == nil; i++ {
		dir := d.obj(paths, i)
		dd := Dir{Name: d.str(dir, diName), ACL: d.acl(dir, diACL)}

		if d.err == nil && dd.Name != "" && isMaliciousPathname(dd.Name) {
			d.fail(unsafeName("directory name", dd.Name))
		}

		files := d.obj(dir, diFiles)

		n := d.items(files)

		total += n
		if total > d.maxEntries {
			d.fail(ErrTooComplex)
		}

		for k := 1; k <= n && d.err == nil; k++ {
			dd.Files = append(dd.Files, d.file(d.obj(files, k)))
		}

		p.Paths = append(p.Paths, dd)
	}

	return p
}

func (d *decoder) index(o obj) Index {
	ix := Index{
		Description: d.str(o, ndxDescription),
		PkgnameSpec: d.str(o, ndxPkgnameSpec),
	}

	pk := d.obj(o, ndxPackages)
	for i := 1; i <= d.items(pk) && d.err == nil; i++ {
		ix.Packages = append(ix.Packages, d.info(d.obj(pk, i)))
	}

	return ix
}

func newDecoder(b *block, lim Limits) *decoder {
	return &decoder{b: b, maxEntries: lim.maxEntries()}
}

func decodePackage(b *block, lim Limits) (*Package, error) {
	d := newDecoder(b, lim)

	o, err := b.object(b.root())
	if err != nil {
		return nil, err
	}

	p := d.pkg(o)
	if d.err != nil {
		return nil, d.err
	}

	return &p, nil
}

func decodeIndex(b *block, lim Limits) (*Index, error) {
	d := newDecoder(b, lim)

	o, err := b.object(b.root())
	if err != nil {
		return nil, err
	}

	ix := d.index(o)
	if d.err != nil {
		return nil, d.err
	}

	return &ix, nil
}

// File kinds, as the type bits of the mode in a "target" field.
const (
	typeReg  = 0x8000
	typeLnk  = 0xa000
	typeBlk  = 0x6000
	typeChr  = 0x2000
	typeFifo = 0x1000
)

// Kind is the type of an entry of a package.
type Kind uint8

// Entry kinds.
const (
	KindFile Kind = iota
	KindDir
	KindSymlink
	KindHardlink
	KindBlock
	KindChar
	KindFIFO
)

func (k Kind) String() string {
	switch k {
	case KindFile:
		return "file"
	case KindDir:
		return "dir"
	case KindSymlink:
		return "symlink"
	case KindHardlink:
		return "hardlink"
	case KindBlock:
		return "block"
	case KindChar:
		return "char"
	case KindFIFO:
		return "fifo"
	default:
		return "unknown"
	}
}

// kind decodes the target field: the type of the file, the target path of
// a link and the device number of a device or FIFO.
func (f *FileEntry) kind() (k Kind, link string, dev uint64, err error) {
	if len(f.Target) == 0 {
		return KindFile, "", 0, nil
	}

	if len(f.Target) < 2 {
		return 0, "", 0, schemaErr("file %q: target of %d bytes", f.Name, len(f.Target))
	}

	typ := uint16(f.Target[0]) | uint16(f.Target[1])<<8
	rest := f.Target[2:]

	switch typ {
	case typeBlk, typeChr, typeFifo:
		if len(rest) != 8 {
			return 0, "", 0, schemaErr("file %q: device number of %d bytes", f.Name, len(rest))
		}

		for i := range 8 {
			dev |= uint64(rest[i]) << (8 * i)
		}

		switch typ {
		case typeBlk:
			k = KindBlock
		case typeChr:
			k = KindChar
		default:
			k = KindFIFO
		}

		return k, "", dev, nil
	case typeLnk, typeReg:
		if len(rest) >= 4095 {
			return 0, "", 0, schemaErr("file %q: link target of %d bytes", f.Name, len(rest))
		}

		if typ == typeReg {
			return KindHardlink, string(rest), 0, nil
		}

		return KindSymlink, string(rest), 0, nil
	default:
		return 0, "", 0, schemaErr("file %q: unknown file type %#x", f.Name, typ)
	}
}

// aclMode turns the permission bits of an ACL into a file mode.
func aclFileMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	if m&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}

	if m&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}

	if m&0o1000 != 0 {
		mode |= fs.ModeSticky
	}

	return mode
}

// modeACL is the inverse of aclFileMode.
func modeACL(m fs.FileMode) uint32 {
	a := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		a |= 0o4000
	}

	if m&fs.ModeSetgid != 0 {
		a |= 0o2000
	}

	if m&fs.ModeSticky != 0 {
		a |= 0o1000
	}

	return a
}

// isMaliciousFilename reports whether name cannot be a single path element:
// it is empty, "." or "..", holds a control character or "/" or is an
// apk-internal temporary name.
func isMaliciousFilename(name string) bool {
	for i := range len(name) {
		if c := name[i]; c < 0x20 || c == '/' || c == 0x7f {
			return true
		}
	}

	switch len(name) {
	case 0:
		return true
	case 1:
		return name == "."
	case 2:
		return name == ".."
	case 5 + 48:
		return strings.HasPrefix(name, ".apk.")
	}

	return false
}

// isMaliciousPathname reports whether any element of a "/"-separated path is
// malicious. A leading, trailing or doubled "/" counts: a package must name
// its directories in canonical form.
func isMaliciousPathname(path string) bool {
	for el := range strings.SplitSeq(path, "/") {
		if isMaliciousFilename(el) {
			return true
		}
	}

	return false
}

func unsafeName(what, name string) error {
	return &unsafePathError{what: what, name: name}
}

type unsafePathError struct{ what, name string }

func (e *unsafePathError) Error() string {
	return ErrUnsafePath.Error() + ": " + e.what + " " + quote(e.name)
}

func (e *unsafePathError) Unwrap() error { return ErrUnsafePath }

func quote(s string) string {
	var sb strings.Builder

	sb.WriteByte('"')

	for i := range len(s) {
		c := s[i]

		switch {
		case c == '"' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c < 0x20 || c >= 0x7f:
			sb.WriteString(`\x`)
			sb.WriteString(hex.EncodeToString([]byte{c}))
		default:
			sb.WriteByte(c)
		}
	}

	sb.WriteByte('"')

	return sb.String()
}
