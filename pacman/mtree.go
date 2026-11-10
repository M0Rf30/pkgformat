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
	link   string
	noMode bool // regular file whose mode the /set line already gives
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
		name := "./" + mtreeEscape(e.path)

		switch e.kind {
		case fs.ModeDir:
			fmt.Fprintf(&b, "%s time=%d.0 mode=%s type=dir\n", name, e.mtime, mtreeMode(e.mode))
		case fs.ModeSymlink:
			fmt.Fprintf(&b, "%s time=%d.0 mode=%s type=link link=%s\n", name, e.mtime, mtreeMode(e.mode), mtreeEscape(e.link))
		default:
			if e.noMode {
				fmt.Fprintf(&b, "%s time=%d.0 size=%d sha256digest=%x\n", name, e.mtime, e.size, e.sha256)
			} else {
				fmt.Fprintf(&b, "%s time=%d.0 mode=%s size=%d sha256digest=%x\n", name, e.mtime, mtreeMode(e.mode), e.size, e.sha256)
			}
		}
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
