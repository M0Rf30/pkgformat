package pacman

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// Limits on reading a .MTREE.
const (
	// MaxMtreeBytes bounds the decompressed text of an .MTREE.
	MaxMtreeBytes int64 = 1 << 30
	// MaxMtreeEntries bounds its entries.
	MaxMtreeEntries = MaxFileEntries
	// MaxMtreeLineBytes bounds one logical line, continuations included.
	MaxMtreeLineBytes = 64 << 10
)

// ErrInvalidMtree reports an .MTREE that cannot be parsed or exceeds a limit.
var ErrInvalidMtree = errors.New("pacman: invalid .MTREE")

// MtreeType is the "type" keyword of an mtree entry.
type MtreeType string

// The types of an mtree entry.
const (
	MtreeFile   MtreeType = "file"
	MtreeDir    MtreeType = "dir"
	MtreeLink   MtreeType = "link"
	MtreeFifo   MtreeType = "fifo"
	MtreeChar   MtreeType = "char"
	MtreeBlock  MtreeType = "block"
	MtreeSocket MtreeType = "socket"
)

func (t MtreeType) valid() bool {
	switch t {
	case MtreeFile, MtreeDir, MtreeLink, MtreeFifo, MtreeChar, MtreeBlock, MtreeSocket:
		return true
	}

	return false
}

// MtreeKeys is the set of keywords an entry carries, after the defaults of the
// "/set" lines have been applied. It tells a keyword that is absent from one
// that is zero.
type MtreeKeys uint32

// The keywords an MtreeEntry holds as fields. Any other keyword is in
// MtreeEntry.Extra.
const (
	KeyType MtreeKeys = 1 << iota
	KeyMode
	KeyUID
	KeyGID
	KeyUname
	KeyGname
	KeySize
	KeyTime
	KeyLink
	KeyNlink
	KeyMD5
	KeySHA1
	KeySHA256
	KeySHA384
	KeySHA512
	KeyRMD160
	KeyCksum
	KeyFlags
	KeyDevice
	KeyInode
	KeyContents
	KeyOptional
)

// KeyDigests are the digest keywords.
const KeyDigests = KeyMD5 | KeySHA1 | KeySHA256 | KeySHA384 | KeySHA512 | KeyRMD160

// MtreeEntry is one line of an .MTREE, with the keywords of the "/set" lines
// in force applied.
type MtreeEntry struct {
	// Path is relative to the root of the package, without "./".
	Path string
	Type MtreeType
	// Keys says which of the fields below were given.
	Keys MtreeKeys
	// Mode is the permission bits with setuid (04000), setgid (02000) and
	// sticky (01000).
	Mode  uint32
	UID   int64
	GID   int64
	Uname string
	Gname string
	Size  int64
	// Time is the modification time; the "time" keyword has fractions.
	Time  time.Time
	Link  string
	Nlink int64
	// MD5, SHA1, SHA256, SHA384, SHA512 and RMD160 are the lowercase hex
	// digests of the content (keywords md5digest or md5, sha256digest or
	// sha256, and so on).
	MD5, SHA1, SHA256, SHA384, SHA512, RMD160 string
	Cksum                                     string
	Flags                                     string
	Device                                    string
	Inode                                     int64
	Contents                                  string
	// Optional is set by the "optional" keyword: the entry need not exist.
	Optional bool
	// Extra holds the keywords this type does not know, by name.
	Extra map[string]string
}

// Has reports whether every keyword of k is present.
func (e *MtreeEntry) Has(k MtreeKeys) bool { return e.Keys&k == k }

// Mtree is a parsed .MTREE.
type Mtree struct {
	Entries []MtreeEntry
	byPath  map[string]int
	// keys is the union of the keywords of all entries.
	keys MtreeKeys
}

// Lookup returns the entry of a path (relative, without "./"); a path listed
// twice yields its last line.
func (m *Mtree) Lookup(p string) (*MtreeEntry, bool) {
	i, ok := m.byPath[p]
	if !ok {
		return nil, false
	}

	return &m.Entries[i], true
}

// ParseMtree parses an .MTREE, gzip-compressed as in a package and in the local
// database, or plain text. Both the flat layout libarchive writes (a full path on every
// line) and the nested one of mtree(8) (directories entered by name and left
// with "..") are read, with "/set" and "/unset" and continuation lines.
func ParseMtree(r io.Reader) (*Mtree, error) {
	m := &Mtree{byPath: map[string]int{}}

	err := ReadMtree(r, func(e *MtreeEntry) error {
		if len(m.Entries) >= MaxMtreeEntries {
			return fmt.Errorf("%w: more than %d entries", ErrInvalidMtree, MaxMtreeEntries)
		}

		m.byPath[e.Path] = len(m.Entries)
		m.keys |= e.Keys
		m.Entries = append(m.Entries, *e)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return m, nil
}

// ReadMtree parses an .MTREE like ParseMtree but hands each entry to fn as it
// is read, so that a huge file never sits in memory. The entry is reused
// between calls; fn must copy what it keeps. An error of fn stops the reading
// and is returned as it is.
func ReadMtree(r io.Reader, fn func(*MtreeEntry) error) error {
	return readMtree(r, fn, MaxMtreeBytes)
}

func readMtree(r io.Reader, fn func(*MtreeEntry) error, limit int64) error {
	br := bufio.NewReaderSize(r, 64<<10)

	head, _ := br.Peek(2)
	if bytes.HasPrefix(head, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidMtree, err)
		}

		defer func() { _ = zr.Close() }()

		br = bufio.NewReaderSize(limitio.Capped(zr, limit+1, ErrInvalidMtree), 64<<10)
	}

	p := &mtreeParser{defaults: mtreeDefaults{}, fn: fn}
	lr := &lineReader{br: br, limit: limit}

	for {
		line, err := lr.next()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return err
		}

		if err := p.line(line); err != nil {
			return err
		}
	}
}

// lineReader yields logical lines: a backslash at the end of a line joins it to
// the next. It bounds the bytes it reads and the length of a line.
type lineReader struct {
	br    *bufio.Reader
	limit int64
	read  int64
}

func (l *lineReader) next() (string, error) {
	var b strings.Builder

	for {
		chunk, err := l.br.ReadSlice('\n')
		l.read += int64(len(chunk))

		if l.read > l.limit {
			return "", fmt.Errorf("%w: text over %d bytes", ErrInvalidMtree, l.limit)
		}

		if b.Len()+len(chunk) > MaxMtreeLineBytes {
			return "", fmt.Errorf("%w: line over %d bytes", ErrInvalidMtree, MaxMtreeLineBytes)
		}

		b.Write(chunk)

		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}

		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("%w: %w", ErrInvalidMtree, err)
		}

		text := strings.TrimRight(b.String(), "\r\n")

		if strings.HasSuffix(text, "\\") && !strings.HasSuffix(text, "\\\\") && err == nil {
			b.Reset()
			b.WriteString(strings.TrimSuffix(text, "\\") + " ")

			continue
		}

		if err != nil && b.Len() == 0 {
			return "", io.EOF
		}

		return text, nil
	}
}

type mtreeDefaults map[string]string

type mtreeParser struct {
	defaults mtreeDefaults
	fn       func(*MtreeEntry) error
	// dir is the current directory of a nested file.
	dir   []string
	entry MtreeEntry
}

func (p *mtreeParser) line(line string) error {
	// Fields are separated by blanks only; other white space is part of a name.
	fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
	if len(fields) == 0 || fields[0][0] == '#' {
		return nil
	}

	switch fields[0] {
	case "/set":
		return p.set(fields[1:])
	case "/unset":
		return p.unset(fields[1:])
	case "..":
		if len(p.dir) > 0 {
			p.dir = p.dir[:len(p.dir)-1]
		}

		return nil
	}

	if fields[0][0] == '/' {
		return fmt.Errorf("%w: unknown command %q", ErrInvalidMtree, short(fields[0]))
	}

	return p.entryLine(fields)
}

func (p *mtreeParser) set(args []string) error {
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			return fmt.Errorf("%w: /set keyword %q has no value", ErrInvalidMtree, short(a))
		}

		if len(p.defaults) >= 64 {
			return fmt.Errorf("%w: too many /set keywords", ErrInvalidMtree)
		}

		p.defaults[k] = v
	}

	return nil
}

func (p *mtreeParser) unset(args []string) error {
	for _, a := range args {
		if a == "all" {
			clear(p.defaults)

			continue
		}

		delete(p.defaults, a)
	}

	return nil
}

func (p *mtreeParser) entryLine(fields []string) error {
	name, err := mtreeUnescape(fields[0])
	if err != nil {
		return err
	}

	p.entry = MtreeEntry{}
	e := &p.entry

	// Defaults first, so that the keywords of the line override them.
	for k, v := range p.defaults {
		if err := e.setKeyword(k, v); err != nil {
			return err
		}
	}

	for _, kw := range fields[1:] {
		k, v, ok := strings.Cut(kw, "=")
		if !ok {
			if k == "optional" || k == "ignore" || k == "nochange" {
				e.Keys |= KeyOptional

				e.Optional = e.Optional || k == "optional"

				continue
			}

			return fmt.Errorf("%w: keyword %q has no value", ErrInvalidMtree, short(kw))
		}

		if err := e.setKeyword(k, v); err != nil {
			return err
		}
	}

	// A name with a slash is a path from the root; one without is a member of
	// the current directory, which a directory entry enters.
	full := name
	if !strings.Contains(name, "/") {
		full = path.Join(append(slicesClone(p.dir), name)...)
	}

	full, err = cleanMtreePath(full)
	if err != nil {
		return err
	}

	e.Path = full

	if !e.Type.valid() {
		if e.Type != "" {
			return fmt.Errorf("%w: type %q of %s", ErrInvalidMtree, short(string(e.Type)), short(full))
		}

		return fmt.Errorf("%w: %s has no type", ErrInvalidMtree, short(full))
	}

	if e.Type == MtreeDir && !strings.Contains(name, "/") {
		if len(p.dir) >= 1024 {
			return fmt.Errorf("%w: directories nested too deep", ErrInvalidMtree)
		}

		p.dir = append(p.dir, name)
	}

	return p.fn(e)
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

// cleanMtreePath turns "./usr/bin" into "usr/bin" and refuses a path that
// leaves the root.
func cleanMtreePath(p string) (string, error) {
	for seg := range strings.SplitSeq(p, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: parent directory in %s", ErrInvalidMtree, short(p))
		}
	}

	p = path.Clean(p)

	switch {
	case p == ".":
		return ".", nil
	case strings.HasPrefix(p, "/"):
		return "", fmt.Errorf("%w: absolute path %s", ErrInvalidMtree, short(p))
	case len(p) > MaxEntryNameLen:
		return "", fmt.Errorf("%w: path too long", ErrInvalidMtree)
	}

	return p, nil
}

func (e *MtreeEntry) setKeyword(k, v string) error {
	var err error

	switch k {
	case "type":
		e.Type, e.Keys = MtreeType(v), e.Keys|KeyType
	case "mode":
		var n uint64

		n, err = strconv.ParseUint(v, 8, 32)
		e.Mode, e.Keys = uint32(n&0o7777), e.Keys|KeyMode
	case "uid":
		e.UID, err = parseMtreeInt(v)
		e.Keys |= KeyUID
	case "gid":
		e.GID, err = parseMtreeInt(v)
		e.Keys |= KeyGID
	case "uname":
		e.Uname, err = mtreeUnescape(v)
		e.Keys |= KeyUname
	case "gname":
		e.Gname, err = mtreeUnescape(v)
		e.Keys |= KeyGname
	case "size":
		e.Size, err = parseMtreeInt(v)
		e.Keys |= KeySize
	case "time":
		e.Time, err = parseMtreeTime(v)
		e.Keys |= KeyTime
	case "link":
		e.Link, err = mtreeUnescape(v)
		e.Keys |= KeyLink
	case "nlink":
		e.Nlink, err = parseMtreeInt(v)
		e.Keys |= KeyNlink
	case "md5digest", "md5":
		e.MD5, err = parseDigest(v, 16)
		e.Keys |= KeyMD5
	case "sha1digest", "sha1":
		e.SHA1, err = parseDigest(v, 20)
		e.Keys |= KeySHA1
	case "sha256digest", "sha256":
		e.SHA256, err = parseDigest(v, 32)
		e.Keys |= KeySHA256
	case "sha384digest", "sha384":
		e.SHA384, err = parseDigest(v, 48)
		e.Keys |= KeySHA384
	case "sha512digest", "sha512":
		e.SHA512, err = parseDigest(v, 64)
		e.Keys |= KeySHA512
	case "rmd160digest", "rmd160", "ripemd160digest":
		e.RMD160, err = parseDigest(v, 20)
		e.Keys |= KeyRMD160
	case "cksum":
		e.Cksum, e.Keys = v, e.Keys|KeyCksum
	case "flags":
		e.Flags, e.Keys = v, e.Keys|KeyFlags
	case "device":
		e.Device, e.Keys = v, e.Keys|KeyDevice
	case "inode":
		e.Inode, err = parseMtreeInt(v)
		e.Keys |= KeyInode
	case "contents", "content":
		e.Contents, err = mtreeUnescape(v)
		e.Keys |= KeyContents
	case "optional":
		e.Optional, e.Keys = v != "0", e.Keys|KeyOptional
	default:
		if e.Extra == nil {
			e.Extra = map[string]string{}
		}

		if len(e.Extra) >= 32 {
			return fmt.Errorf("%w: too many keywords", ErrInvalidMtree)
		}

		e.Extra[k] = v
	}

	if err != nil {
		return fmt.Errorf("%w: keyword %s=%s: %w", ErrInvalidMtree, k, short(v), err)
	}

	return nil
}

func parseMtreeInt(v string) (int64, error) {
	n, err := strconv.ParseInt(v, 0, 64)
	if err != nil {
		// Decimal with a leading zero is not octal here.
		n, err = strconv.ParseInt(v, 10, 64)
	}

	if err != nil {
		return 0, err
	}

	if n < 0 {
		return 0, errors.New("negative")
	}

	return n, nil
}

func parseMtreeTime(v string) (time.Time, error) {
	secs, frac, _ := strings.Cut(v, ".")

	s, err := strconv.ParseInt(secs, 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	var ns int64

	if frac != "" {
		if len(frac) > 9 {
			frac = frac[:9]
		}

		n, err := strconv.ParseInt(frac, 10, 64)
		if err != nil || n < 0 {
			return time.Time{}, errors.New("bad fraction")
		}

		for range 9 - len(frac) {
			n *= 10
		}

		ns = n
	}

	return time.Unix(s, ns).UTC(), nil
}

func parseDigest(v string, size int) (string, error) {
	v = strings.ToLower(v)
	if len(v) != 2*size {
		return "", fmt.Errorf("digest has %d hex digits, want %d", len(v), 2*size)
	}

	for i := range len(v) {
		if c := v[i]; c < '0' || c > '9' && c < 'a' || c > 'f' {
			return "", errors.New("not hex")
		}
	}

	return v, nil
}

// mtreeUnescape decodes the vis(3) encoding of a name: "\ooo" with one to three
// octal digits, the C escapes, and "\\".
func mtreeUnescape(s string) (string, error) {
	if !strings.Contains(s, "\\") {
		return s, nil
	}

	var b strings.Builder

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			b.WriteByte(c)

			continue
		}

		i++

		if i >= len(s) {
			return "", fmt.Errorf("%w: trailing backslash in %s", ErrInvalidMtree, short(s))
		}

		switch c = s[i]; {
		case c >= '0' && c <= '7':
			n, j := 0, i
			for ; j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7'; j++ {
				n = n*8 + int(s[j]-'0')
			}

			if n > 255 {
				return "", fmt.Errorf("%w: octal escape over 255 in %s", ErrInvalidMtree, short(s))
			}

			b.WriteByte(byte(n))

			i = j - 1
		default:
			if r, ok := map[byte]byte{'a': 7, 'b': 8, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11, 's': ' '}[c]; ok {
				b.WriteByte(r)
			} else {
				b.WriteByte(c)
			}
		}
	}

	return b.String(), nil
}

// FileMode returns the entry as a Go file mode: the type bit, the permissions
// and the setuid, setgid and sticky bits. An entry without a mode has the
// permission bits 0.
func (e *MtreeEntry) FileMode() fs.FileMode {
	m := fs.FileMode(e.Mode & 0o777)

	if e.Mode&0o4000 != 0 {
		m |= fs.ModeSetuid
	}

	if e.Mode&0o2000 != 0 {
		m |= fs.ModeSetgid
	}

	if e.Mode&0o1000 != 0 {
		m |= fs.ModeSticky
	}

	switch e.Type {
	case MtreeDir:
		m |= fs.ModeDir
	case MtreeLink:
		m |= fs.ModeSymlink
	case MtreeFifo:
		m |= fs.ModeNamedPipe
	case MtreeChar:
		m |= fs.ModeDevice | fs.ModeCharDevice
	case MtreeBlock:
		m |= fs.ModeDevice
	case MtreeSocket:
		m |= fs.ModeSocket
	}

	return m
}
