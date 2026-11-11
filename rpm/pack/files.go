package pack

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
)

// content is what the payload holds for a regular file: it is shared by the members
// of a hard link set, whose content is stored once.
type content struct {
	size   int64
	digest string
	verity [32]byte
	mime   string
	// source of the bytes: exactly one is used
	body   []byte
	reader io.Reader
	open   func() (io.ReadCloser, error)
	path   string
}

// fileEntry is a file of the package, validated and normalized for writing.
type fileEntry struct {
	RPMFile
	dir, base string
	// index is the position in the header.
	index int
	// ino and nlink describe the inode of the cpio entry; they are shared by hard links.
	ino   uint32
	nlink uint32
	// size is the size recorded in the header: the length of the content or of the
	// symlink target.
	size int64
	// c is the content of a regular file that is part of the payload, nil otherwise.
	c *content
	// carrier is set on the one file of a hard link set (or the only file) whose
	// payload entry holds the content.
	carrier bool
	// inPayload is false for ghost files.
	inPayload bool
}

func (e *fileEntry) isReg() bool  { return modeIs(e.Mode, modeRegBit) }
func (e *fileEntry) isDir() bool  { return modeIs(e.Mode, modeDirBit) }
func (e *fileEntry) isLink() bool { return modeIs(e.Mode, modeSymlinkBit) }
func (e *fileEntry) ghost() bool  { return e.Type&GhostFile != 0 }

func supportedFileType(mode uint) bool {
	switch mode & modeTypeMask {
	case 0, modeRegBit, modeDirBit, modeSymlinkBit, ModeFifo, ModeSocket, ModeChar, ModeBlock:
		return true
	}
	return false
}

func invalidFile(f RPMFile, format string, args ...any) error {
	return fmt.Errorf("%w: %q: %s", ErrInvalidFile, f.Name, fmt.Sprintf(format, args...))
}

// validateFile checks that f can be represented in the rpm file indexes.
func (r *RPM) validateFile(f RPMFile) error {
	mode := f.Mode
	if mode&modeTypeMask == 0 {
		mode |= modeRegBit
	}
	switch {
	case hasNUL(f.Name):
		return invalidFile(f, "embedded NUL byte")
	case !pathIsClean(f.Name):
		return fmt.Errorf("%w: name %q is not a clean absolute path", ErrInvalidFile, f.Name)
	case hasNUL(f.Owner), hasNUL(f.Group), hasNUL(f.Lang), hasNUL(f.Class), hasNUL(f.Caps), hasNUL(f.Path), hasNUL(f.Hardlink):
		return invalidFile(f, "embedded NUL byte")
	case f.Mode > maxMode:
		return invalidFile(f, "mode %#o does not fit in 16 bits", f.Mode)
	case !supportedFileType(f.Mode):
		return invalidFile(f, "file type bits %#o are not a file type", f.Mode&modeTypeMask)
	case r.Format == FormatV4 && (uint64(len(f.Body)) > maxV4FileSize || f.Size > maxV4FileSize) && !modeIs(mode, modeSymlinkBit):
		return invalidFile(f, "the file is over 4 GiB, which the v4 format cannot hold (use FormatV6)")
	case f.Size < 0:
		return invalidFile(f, "negative size")
	case (f.Major != 0 || f.Minor != 0) && !modeIs(f.Mode, ModeChar) && !modeIs(f.Mode, ModeBlock):
		return invalidFile(f, "device numbers on a file that is not a device")
	case f.Major > 255 || f.Minor > 255:
		return invalidFile(f, "device numbers above 255 do not fit the rpm header")
	}
	for _, rels := range []Relations{f.Provides, f.Requires} {
		for _, rel := range rels {
			if rel == nil || hasNUL(rel.Name) || hasNUL(rel.Version) {
				return invalidFile(f, "a nil dependency or one with a NUL byte")
			}
		}
	}
	if f.VerifyExclude&^VerifyAll != 0 {
		return invalidFile(f, "unknown verify flags %#x", uint32(f.VerifyExclude))
	}
	srcs := 0
	for _, set := range []bool{f.Body != nil && !modeIs(mode, modeSymlinkBit), f.Reader != nil, f.Open != nil, f.Path != ""} {
		if set {
			srcs++
		}
	}
	switch {
	case modeIs(mode, modeSymlinkBit):
		if len(f.Body) == 0 || f.Reader != nil || f.Open != nil || f.Path != "" {
			return invalidFile(f, "a symlink needs its target in Body and nothing else")
		}
		if hasNULBytes(f.Body) {
			return invalidFile(f, "embedded NUL byte in the symlink target")
		}
	case srcs > 1:
		return invalidFile(f, "more than one content source")
	case f.Hardlink != "" && (srcs > 0 || !modeIs(mode, modeRegBit)):
		return invalidFile(f, "a hard link is a regular file without content of its own")
	case f.Hardlink != "" && f.Type&GhostFile != 0:
		return invalidFile(f, "a ghost file cannot be a hard link")
	}
	return nil
}

// VerifyAll is the union of all the verify flags.
const VerifyAll = VerifyDigest | VerifySize | VerifyLinkTo | VerifyUser | VerifyGroup | VerifyMTime |
	VerifyMode | VerifyRdev | VerifyCaps | VerifyContexts

func pathIsClean(p string) bool { return path.IsAbs(p) && path.Clean(p) == p }

func hasNULBytes(b []byte) bool { return strings.IndexByte(string(b), 0) >= 0 }

// prepareFiles validates and orders the files, assigns inodes and finds the
// carrier of the content of every hard link set.
func (r *RPM) prepareFiles() ([]*fileEntry, error) {
	files := r.files
	if r.ImplicitDirs {
		files = make(map[string]RPMFile, len(r.files))
		for n, f := range r.files {
			files[n] = f
		}
		for _, n := range sortedNames(r.files) {
			for d := path.Dir(n); d != "/" && d != "."; d = path.Dir(d) {
				if _, ok := files[d]; ok {
					continue
				}
				files[d] = RPMFile{Name: d, Mode: modeDirBit | 0o755, MTime: uint32(r.BuildTime.Unix())}
			}
		}
	}
	names := sortedNames(files)
	entries := make([]*fileEntry, len(names))
	byName := make(map[string]*fileEntry, len(names))
	for i, n := range names {
		f := files[n]
		if err := r.validateFile(f); err != nil {
			return nil, err
		}
		if f.Owner == "" {
			f.Owner = "root"
		}
		if f.Group == "" {
			f.Group = "root"
		}
		if !r.ClampTime.IsZero() && int64(f.MTime) > r.ClampTime.Unix() {
			f.MTime = uint32(r.ClampTime.Unix())
		}
		if f.Mode&modeTypeMask == 0 {
			f.Mode |= modeRegBit
		}
		if !modeIs(f.Mode, modeRegBit) && !modeIs(f.Mode, modeSymlinkBit) {
			f.Body, f.Reader, f.Open, f.Path = nil, nil, nil, ""
		}
		dir, base := path.Split(f.Name)
		e := &fileEntry{RPMFile: f, dir: dir, base: base, index: i, inPayload: f.Type&GhostFile == 0, nlink: 1}
		entries[i], byName[n] = e, e
	}
	// content and hard links
	roots := map[string][]*fileEntry{}
	for _, e := range entries {
		switch {
		case e.Hardlink != "":
			t, ok := byName[e.Hardlink]
			switch {
			case !ok:
				return nil, invalidFile(e.RPMFile, "hard link target %q is not in the package", e.Hardlink)
			case !t.isReg() || t.ghost() || t.Hardlink != "":
				return nil, invalidFile(e.RPMFile, "hard link target %q is not a regular file with content", e.Hardlink)
			case t.Owner != e.Owner || t.Group != e.Group || t.Mode != e.Mode || t.MTime != e.MTime:
				return nil, invalidFile(e.RPMFile, "hard link and %q must have the same owner, group, mode and time", e.Hardlink)
			}
			roots[t.Name] = append(roots[t.Name], e)
		case e.isLink():
			e.size = int64(len(e.Body))
		case e.isReg():
			c, err := r.sourceContent(e)
			if err != nil {
				return nil, err
			}
			e.c, e.size = c, c.size
		}
	}
	for _, e := range entries {
		e.ino = uint32(e.index + 1)
		if e.isDir() {
			e.nlink = 2
		}
	}
	for root, members := range roots {
		set := append([]*fileEntry{byName[root]}, members...)
		slices.SortFunc(set, func(a, b *fileEntry) int { return a.index - b.index })
		for _, m := range set {
			m.ino, m.nlink = set[0].ino, uint32(len(set))
			m.c, m.size = byName[root].c, byName[root].size
			m.carrier = false
		}
		set[len(set)-1].carrier = true
	}
	for _, e := range entries {
		if e.Hardlink == "" && roots[e.Name] == nil && e.inPayload {
			e.carrier = true
		}
	}
	return entries, nil
}

// sourceContent determines the size of a regular file's content and records where
// it comes from.
func (r *RPM) sourceContent(e *fileEntry) (*content, error) {
	c := &content{body: e.Body, reader: e.Reader, open: e.Open, path: e.Path}
	switch {
	case e.Path != "":
		st, err := os.Stat(e.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidFile, e.Name, err)
		}
		if !st.Mode().IsRegular() {
			return nil, invalidFile(e.RPMFile, "%q is not a regular file", e.Path)
		}
		c.size = st.Size()
		if r.Format == FormatV4 && c.size > maxV4FileSize {
			return nil, invalidFile(e.RPMFile, "the file is over 4 GiB, which the v4 format cannot hold (use FormatV6)")
		}
	case e.Reader != nil || e.Open != nil:
		c.size = e.Size
	default:
		c.size = int64(len(e.Body))
	}
	return c, nil
}

// payloadOrder returns the entries in the order of the payload: the files that
// are not hard linked in header order, then the hard link sets.
func payloadOrder(entries []*fileEntry) []*fileEntry {
	var singles, sets []*fileEntry
	for _, e := range entries {
		if !e.inPayload {
			continue
		}
		if e.nlink > 1 && e.isReg() {
			sets = append(sets, e)
		} else {
			singles = append(singles, e)
		}
	}
	// the members of a set stay together, sets ordered by their first member
	first := map[uint32]int{}
	for _, e := range sets {
		if _, ok := first[e.ino]; !ok {
			first[e.ino] = e.index
		}
	}
	slices.SortStableFunc(sets, func(a, b *fileEntry) int {
		if a.ino != b.ino {
			return first[a.ino] - first[b.ino]
		}
		return a.index - b.index
	})
	return append(singles, sets...)
}

// installedSize is the sum of the sizes of the files once installed: the content
// of a hard link set counts once.
func installedSize(entries []*fileEntry) uint64 {
	var total uint64
	for _, e := range entries {
		if e.ghost() || e.isDir() || (!e.isReg() && !e.isLink()) {
			continue
		}
		if e.isReg() && e.nlink > 1 && !e.carrier {
			continue
		}
		total += uint64(e.size)
	}
	return total
}

// AddFS adds the files below opts.Dir of fsys. The content of regular files is
// streamed from fsys when the package is written, so large trees do not need to fit
// in memory. Only regular files, directories and symlinks are supported by io/fs
// file systems; a symlink is added when fsys implements fs.ReadLinkFS.
func (r *RPM) AddFS(fsys fs.FS, opts AddFSOptions) error {
	dir := opts.Dir
	if dir == "" {
		dir = "."
	}
	prefix := opts.Prefix
	if prefix == "" {
		prefix = "/"
	}
	owner, group := opts.Owner, opts.Group
	if owner == "" {
		owner = "root"
	}
	if group == "" {
		group = "root"
	}
	return fs.WalkDir(fsys, dir, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(name, dir), "/")
		if rel == "" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode, ok := fsFileMode(info.Mode())
		if !ok {
			return fmt.Errorf("%w: %q has a file type io/fs cannot describe", ErrInvalidFile, name)
		}
		f := RPMFile{
			Name:  path.Join(prefix, rel),
			Mode:  mode,
			Owner: owner,
			Group: group,
			MTime: uint32(max(info.ModTime().Unix(), 0)),
		}
		switch mode & modeTypeMask {
		case modeDirBit:
			if opts.SkipDirs {
				return nil
			}
		case modeSymlinkBit:
			link, ok := fsys.(fs.ReadLinkFS)
			if !ok {
				return fmt.Errorf("%w: %q is a symlink and the file system cannot read links", ErrInvalidFile, name)
			}
			target, err := link.ReadLink(name)
			if err != nil {
				return err
			}
			f.Body = []byte(target)
		default:
			f.Type = opts.Type
			f.Size = info.Size()
			f.Open = func() (io.ReadCloser, error) { return fsys.Open(name) }
		}
		r.AddFile(f)
		return nil
	})
}
