package pacman

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

// mtreeEntry is one line of the .MTREE of a package.
type mtreeEntry struct {
	path   string // relative, no leading "./"
	kind   fs.FileMode
	mode   fs.FileMode
	mtime  int64
	size   int64
	sha256 [32]byte
	// md5 is listed before the sha256 when withMD5 is set.
	md5     [16]byte
	withMD5 bool
	link    string
	noMode  bool // regular file whose mode the /set line already gives
	// uid and gid are written only when they differ from the 0 of the /set line.
	uid, gid int
}

// posixMode is the permission string of a mode as the mtree format spells it:
// permission bits plus setuid (4000), setgid (2000) and sticky (1000). Go's
// type bits (ModeDir, ModeSymlink, ...) are dropped.
func posixMode(mode fs.FileMode) uint32 {
	posix := uint32(mode.Perm())

	if mode&fs.ModeSetuid != 0 {
		posix |= 0o4000
	}

	if mode&fs.ModeSetgid != 0 {
		posix |= 0o2000
	}

	if mode&fs.ModeSticky != 0 {
		posix |= 0o1000
	}

	return posix
}

func mtreeMode(mode fs.FileMode) string {
	return strconv.FormatUint(uint64(posixMode(mode)), 8)
}

// mtreeEscape encodes the bytes the mtree reader treats specially (space and
// control characters, backslash, and the pattern and comment characters) as
// backslash-octal, the way libarchive writes them.
func mtreeEscape(s string) string {
	clean := true

	for i := range len(s) {
		if mtreeSpecial(s[i]) {
			clean = false

			break
		}
	}

	if clean {
		return s
	}

	var b strings.Builder

	for i := range len(s) {
		c := s[i]
		if mtreeSpecial(c) {
			fmt.Fprintf(&b, "\\%03o", c)
		} else {
			b.WriteByte(c)
		}
	}

	return b.String()
}

func mtreeSpecial(c byte) bool {
	return c <= ' ' || c >= 0x7f || strings.IndexByte("\\#*?[=", c) >= 0
}

// renderMtree renders the .MTREE text for entries, in the order given.
func renderMtree(entries []mtreeEntry) []byte {
	var b bytes.Buffer

	b.WriteString("#mtree\n/set type=file uid=0 gid=0 mode=644\n")

	for i := range entries {
		e := &entries[i]

		b.WriteString("./" + mtreeEscape(e.path))

		fmt.Fprintf(&b, " time=%d.0", e.mtime)

		if !e.noMode {
			fmt.Fprintf(&b, " mode=%s", mtreeMode(e.mode))
		}

		if e.gid != 0 {
			fmt.Fprintf(&b, " gid=%d", e.gid)
		}

		if e.uid != 0 {
			fmt.Fprintf(&b, " uid=%d", e.uid)
		}

		switch e.kind {
		case fs.ModeDir:
			b.WriteString(" type=dir")
		case fs.ModeSymlink:
			fmt.Fprintf(&b, " type=link link=%s", mtreeEscape(e.link))
		case fs.ModeNamedPipe:
			b.WriteString(" type=fifo")
		case fs.ModeDevice | fs.ModeCharDevice:
			b.WriteString(" type=char")
		case fs.ModeDevice:
			b.WriteString(" type=block")
		default:
			fmt.Fprintf(&b, " size=%d", e.size)

			if e.withMD5 {
				fmt.Fprintf(&b, " md5digest=%x", e.md5)
			}

			fmt.Fprintf(&b, " sha256digest=%x", e.sha256)
		}

		b.WriteByte('\n')
	}

	return b.Bytes()
}

// gzipBytes compresses data with gzip. The header carries no timestamp, so the
// output depends on data only.
func gzipBytes(data []byte) ([]byte, error) {
	var out bytes.Buffer

	zw := gzip.NewWriter(&out)

	if _, err := zw.Write(data); err != nil {
		return nil, fmt.Errorf("pacman: compressing .MTREE: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("pacman: compressing .MTREE: %w", err)
	}

	return out.Bytes(), nil
}
