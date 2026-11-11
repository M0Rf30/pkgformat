package deb

import (
	"archive/tar"
	"bytes"
	"crypto/md5" //nolint:gosec // Debian policy mandates MD5 for the md5sums file
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/gzip"
)

const (
	debianBinary   = "2.0\n"
	controlTarName = "control.tar"
	dataTarName    = "data.tar"
)

// WriteOptions tunes Write. The zero value is valid.
type WriteOptions struct {
	// TempDir is where the compressed data archive is staged, because its size
	// must be known before it is copied into the package. Empty means the
	// system temporary directory.
	TempDir string
}

// Write writes the package described by spec, with payload as the files it
// installs, to w as a .deb: the ar archive made of debian-binary, the control
// archive and the data archive. Entries are written in the given order; the
// missing parent directories of an entry are added before it, and so is the
// root "./". Owners are root:root unless an entry names others, which is what
// "dpkg-deb --root-owner-group" produces for a tree of root-owned files. The
// md5sums file and, when Spec.InstalledSize
// is zero, the Installed-Size are computed from the payload.
func Write(w io.Writer, spec *Spec, payload []Entry, opts WriteOptions) error {
	if err := spec.Validate(); err != nil {
		return err
	}

	entries, err := withChangelog(spec, payload)
	if err != nil {
		return err
	}

	staging, err := os.CreateTemp(opts.TempDir, "deb-data-*")
	if err != nil {
		return fmt.Errorf("deb: staging data archive: %w", err)
	}

	defer func() {
		_ = staging.Close()
		_ = os.Remove(staging.Name())
	}()

	stats, err := writeDataArchive(staging, spec, entries)
	if err != nil {
		return err
	}

	dataSize, err := staging.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("deb: staging data archive: %w", err)
	}

	if _, err := staging.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("deb: staging data archive: %w", err)
	}

	control, err := buildControlArchive(spec, stats)
	if err != nil {
		return err
	}

	aw, err := newARWriter(w)
	if err != nil {
		return err
	}

	dataComp, _ := spec.dataCompression()
	ctrlComp, _ := spec.controlCompression()

	if err := aw.member("debian-binary", int64(len(debianBinary)), spec.ModTime, strings.NewReader(debianBinary)); err != nil {
		return err
	}

	if err := aw.member(controlTarName+ctrlComp.Extension(), int64(len(control)), spec.ModTime, bytes.NewReader(control)); err != nil {
		return err
	}

	return aw.member(dataTarName+dataComp.Extension(), dataSize, spec.ModTime, staging)
}

// WriteFile writes the package to path through a temporary file in the same
// directory, renamed into place when complete.
func WriteFile(filePath string, spec *Spec, payload []Entry, opts WriteOptions) error {
	dir := filepath.Dir(filePath)

	tmp, err := os.CreateTemp(dir, ".deb-*")
	if err != nil {
		return fmt.Errorf("deb: creating package file: %w", err)
	}

	defer func() { _ = os.Remove(tmp.Name()) }()

	if err := Write(tmp, spec, payload, opts); err != nil {
		_ = tmp.Close()

		return err
	}

	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("deb: creating package file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("deb: closing package file: %w", err)
	}

	if err := os.Rename(tmp.Name(), filePath); err != nil {
		return fmt.Errorf("deb: creating package file: %w", err)
	}

	return nil
}

// withChangelog returns the payload with the compressed changelog added.
func withChangelog(spec *Spec, payload []Entry) ([]Entry, error) {
	if len(spec.Changelog) == 0 {
		return payload, nil
	}

	var buf bytes.Buffer

	gz := gzip.NewWriter(&buf)
	gz.ModTime = spec.ModTime

	if _, err := gz.Write(spec.Changelog); err != nil {
		return nil, fmt.Errorf("deb: compressing changelog: %w", err)
	}

	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("deb: compressing changelog: %w", err)
	}

	out := make([]Entry, 0, len(payload)+1)
	out = append(out, payload...)

	return append(out, Entry{
		Path: "usr/share/doc/" + spec.Name + "/changelog.Debian.gz",
		Mode: 0o644,
		Data: buf.Bytes(),
	}), nil
}

// dataStats is what the data archive reveals about the payload.
type dataStats struct {
	// md5s holds "<digest>  <path>" lines of the regular files, unsorted.
	md5s []md5Line
	// size is the sum of the sizes of the files and symlinks, in bytes.
	size int64
}

type md5Line struct{ path, sum string }

// cleanEntryPath normalises an entry path to a relative slash path without
// "." or ".." elements; the root is "".
func cleanEntryPath(p string) (string, error) {
	c := path.Clean("/" + strings.TrimPrefix(p, "./"))
	c = strings.TrimPrefix(c, "/")

	if strings.Contains("/"+p+"/", "/../") || strings.ContainsRune(p, 0) || strings.ContainsAny(p, "\n") {
		return "", invalidSpec("unsafe entry path %q", p)
	}

	return c, nil
}

// dataWriter writes the entries of the data archive.
type dataWriter struct {
	tw    *tar.Writer
	spec  *Spec
	stats *dataStats
	// regular maps the path of every regular file written, hard links
	// included, to the md5 sum of its content.
	regular map[string]string
}

// writeDataArchive writes the tar of the payload, compressed, to w.
func writeDataArchive(w io.Writer, spec *Spec, entries []Entry) (*dataStats, error) {
	comp, level := spec.dataCompression()

	zw, err := compressWriterLevel(w, comp, level)
	if err != nil {
		return nil, err
	}

	dw := &dataWriter{tw: tar.NewWriter(zw), spec: spec, stats: &dataStats{}, regular: make(map[string]string)}
	seen := map[string]bool{"": true}

	if err := writeDir(dw.tw, "", 0o755, spec.ModTime); err != nil {
		return nil, err
	}

	// explicit lists the directories the payload names itself, so that a
	// parent that comes later in the list is not added twice.
	explicit := make(map[string]bool)

	for _, e := range entries {
		if e.Mode.IsDir() {
			if p, err := cleanEntryPath(e.Path); err == nil {
				explicit[p] = true
			}
		}
	}

	for i := range entries {
		e := &entries[i]

		p, err := cleanEntryPath(e.Path)
		if err != nil {
			return nil, err
		}

		if p == "" {
			if !e.Mode.IsDir() {
				return nil, invalidSpec("entry path %q is the root", e.Path)
			}

			continue
		}

		if seen[p] {
			return nil, invalidSpec("duplicate entry %q", p)
		}

		seen[p] = true

		for _, dir := range missingParents(p, seen, explicit) {
			seen[dir] = true

			if err := writeDir(dw.tw, dir, 0o755, spec.ModTime); err != nil {
				return nil, err
			}
		}

		if err := dw.entry(p, e); err != nil {
			return nil, err
		}
	}

	if err := dw.tw.Close(); err != nil {
		return nil, fmt.Errorf("deb: closing data archive: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("deb: closing data archive: %w", err)
	}

	return dw.stats, nil
}

// missingParents lists the ancestors of p that have not been written and are
// not written explicitly later, outermost first.
func missingParents(p string, seen, explicit map[string]bool) []string {
	var out []string

	for dir := path.Dir(p); dir != "." && dir != "/"; dir = path.Dir(dir) {
		if seen[dir] || explicit[dir] {
			continue
		}

		out = append(out, dir)
	}

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}

	return out
}

func tarMode(m fs.FileMode) int64 {
	mode := int64(m.Perm())

	if m&fs.ModeSetuid != 0 {
		mode |= 0o4000
	}

	if m&fs.ModeSetgid != 0 {
		mode |= 0o2000
	}

	if m&fs.ModeSticky != 0 {
		mode |= 0o1000
	}

	return mode
}

// writeDir writes a directory entry owned by root:root.
func writeDir(tw *tar.Writer, p string, mode int64, mtime time.Time) error {
	name := "./"
	if p != "" {
		name = "./" + p + "/"
	}

	return writeHeader(tw, asRoot(&tar.Header{
		Typeflag: tar.TypeDir, Name: name, Mode: mode, ModTime: mtime,
	}))
}

func asRoot(hdr *tar.Header) *tar.Header {
	hdr.Uid, hdr.Gid = 0, 0
	hdr.Uname, hdr.Gname = "root", "root"

	return hdr
}

func writeHeader(tw *tar.Writer, hdr *tar.Header) error {
	hdr.Format = tar.FormatGNU

	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("deb: writing tar header %q: %w", hdr.Name, err)
	}

	return nil
}

// modTime is the time of an entry: its own, else the spec's, never later than
// the spec's when ClampMTime is set.
func (dw *dataWriter) modTime(e *Entry) time.Time {
	mtime := e.ModTime
	if mtime.IsZero() {
		mtime = dw.spec.ModTime
	}

	if dw.spec.ClampMTime && mtime.After(dw.spec.ModTime) {
		mtime = dw.spec.ModTime
	}

	return mtime
}

// header starts the tar header of an entry with its mode, time and owner.
func (dw *dataWriter) header(typ byte, name string, e *Entry) (*tar.Header, error) {
	if e.UID < 0 || e.GID < 0 {
		return nil, invalidSpec("entry %q has a negative owner id", name)
	}

	if strings.ContainsAny(e.User+e.Group, "\x00\n") {
		return nil, invalidSpec("entry %q has an invalid owner name", name)
	}

	hdr := &tar.Header{
		Typeflag: typ, Name: "./" + name, Mode: tarMode(e.Mode), ModTime: dw.modTime(e),
		Uid: e.UID, Gid: e.GID, Uname: e.User, Gname: e.Group,
	}

	if e.UID == 0 && e.User == "" {
		hdr.Uname = "root"
	}

	if e.GID == 0 && e.Group == "" {
		hdr.Gname = "root"
	}

	return hdr, nil
}

func (dw *dataWriter) entry(p string, e *Entry) error {
	if e.Hardlink != "" {
		return dw.hardlink(p, e)
	}

	switch e.Mode.Type() {
	case fs.ModeDir:
		hdr, err := dw.header(tar.TypeDir, p+"/", e)
		if err != nil {
			return err
		}

		return writeHeader(dw.tw, hdr)
	case fs.ModeSymlink:
		if e.Linkname == "" {
			return invalidSpec("symlink %q has no target", p)
		}

		hdr, err := dw.header(tar.TypeSymlink, p, e)
		if err != nil {
			return err
		}

		hdr.Mode, hdr.Linkname = 0o777, e.Linkname
		dw.stats.size += int64(len(e.Linkname))

		return writeHeader(dw.tw, hdr)
	case 0:
		return dw.file(p, e)
	case fs.ModeNamedPipe:
		hdr, err := dw.header(tar.TypeFifo, p, e)
		if err != nil {
			return err
		}

		return writeHeader(dw.tw, hdr)
	case fs.ModeDevice, fs.ModeDevice | fs.ModeCharDevice:
		return dw.device(p, e)
	}

	return fmt.Errorf("%w: %w: entry %q has type %s", ErrInvalidSpec, ErrUnsupportedEntryType, p, e.Mode.Type())
}

func (dw *dataWriter) device(p string, e *Entry) error {
	typ := byte(tar.TypeBlock)
	if e.Mode&fs.ModeCharDevice != 0 {
		typ = tar.TypeChar
	}

	if e.DevMajor < 0 || e.DevMinor < 0 {
		return invalidSpec("device %q has a negative number", p)
	}

	hdr, err := dw.header(typ, p, e)
	if err != nil {
		return err
	}

	hdr.Devmajor, hdr.Devminor = e.DevMajor, e.DevMinor

	return writeHeader(dw.tw, hdr)
}

// hardlink writes a hard link to the regular file that an earlier entry wrote.
func (dw *dataWriter) hardlink(p string, e *Entry) error {
	if e.Mode.Type() != 0 || e.Data != nil || e.Open != nil || e.Size != 0 {
		return invalidSpec("hard link %q must be a regular entry without content", p)
	}

	target, err := cleanEntryPath(e.Hardlink)
	if err != nil {
		return err
	}

	sum, ok := dw.regular[target]
	if !ok {
		return invalidSpec("hard link %q points to %q, which is not an earlier regular file", p, e.Hardlink)
	}

	hdr, err := dw.header(tar.TypeLink, p, e)
	if err != nil {
		return err
	}

	hdr.Linkname = "./" + target
	dw.regular[p] = sum
	dw.stats.md5s = append(dw.stats.md5s, md5Line{path: p, sum: sum})

	return writeHeader(dw.tw, hdr)
}

func (dw *dataWriter) file(p string, e *Entry) error {
	var (
		body io.Reader
		size = e.Size
	)

	switch {
	case e.Data != nil:
		body, size = bytes.NewReader(e.Data), int64(len(e.Data))
	case e.Open != nil:
		rc, err := e.Open()
		if err != nil {
			return fmt.Errorf("deb: opening %q: %w", p, err)
		}

		defer func() { _ = rc.Close() }()

		body = rc
	default:
		body, size = bytes.NewReader(nil), 0
	}

	hdr, err := dw.header(tar.TypeReg, p, e)
	if err != nil {
		return err
	}

	hdr.Size = size

	if err := writeHeader(dw.tw, hdr); err != nil {
		return err
	}

	h := md5.New() //nolint:gosec // see import

	n, err := io.Copy(io.MultiWriter(dw.tw, h), io.LimitReader(body, size))
	if err != nil {
		return fmt.Errorf("deb: writing %q: %w", p, err)
	}

	if n != size {
		return fmt.Errorf("deb: writing %q: %w: %d of %d bytes", p, io.ErrUnexpectedEOF, n, size)
	}

	sum := hex.EncodeToString(h.Sum(nil))
	dw.stats.size += size
	dw.regular[p] = sum
	dw.stats.md5s = append(dw.stats.md5s, md5Line{path: p, sum: sum})

	return nil
}

// controlMember is one file of the control archive as it is written.
type controlMember struct {
	name string
	mode int64
	body string
}

// controlMembers lists the files of the control archive in the order they are
// written.
func controlMembers(spec *Spec, stats *dataStats) []controlMember {
	members := []controlMember{{"control", 0o644, controlFile(spec, stats)}}

	add := func(name string, mode fs.FileMode, def int64, body string) {
		if body == "" {
			return
		}

		m := def
		if mode != 0 {
			m = int64(mode)
		}

		members = append(members, controlMember{name, m, body})
	}

	add("conffiles", 0, 0o644, conffilesContent(spec.Conffiles))
	add("md5sums", 0, 0o644, md5sumsContent(stats.md5s))

	if len(spec.Licenses) > 0 {
		add("copyright", 0, 0o644, copyrightContent(spec))
	}

	add("triggers", 0, 0o644, FormatTriggers(spec.Triggers))
	add("shlibs", 0, 0o644, FormatShlibs(spec.Shlibs))
	add("symbols", 0, 0o644, FormatSymbols(spec.Symbols))

	sc, modes := spec.Scripts, spec.Scripts.Modes
	add("preinst", modes.Preinst, 0o755, sc.Preinst)
	add("postinst", modes.Postinst, 0o755, sc.Postinst)
	add("prerm", modes.Prerm, 0o755, withHeader(sc.Prerm))
	add("postrm", modes.Postrm, 0o755, withHeader(sc.Postrm))
	add("config", modes.Config, 0o755, sc.Config)
	add("templates", modes.Templates, 0o644, sc.Templates)

	for _, m := range spec.ExtraControl {
		mode := m.Mode
		if mode == 0 {
			mode = 0o644
		}

		// An empty file is still a member, unlike the generated ones.
		members = append(members, controlMember{m.Name, int64(mode), string(m.Data)})
	}

	return members
}

// buildControlArchive returns the compressed control archive.
func buildControlArchive(spec *Spec, stats *dataStats) ([]byte, error) {
	var buf bytes.Buffer

	comp, level := spec.controlCompression()

	zw, err := compressWriterLevel(&buf, comp, level)
	if err != nil {
		return nil, err
	}

	tw := tar.NewWriter(zw)

	if err := writeDir(tw, "", 0o755, spec.ModTime); err != nil {
		return nil, err
	}

	for _, m := range controlMembers(spec, stats) {
		if err := writeHeader(tw, asRoot(&tar.Header{
			Typeflag: tar.TypeReg, Name: "./" + m.name, Mode: m.mode, Size: int64(len(m.body)), ModTime: spec.ModTime,
		})); err != nil {
			return nil, err
		}

		if _, err := io.WriteString(tw, m.body); err != nil {
			return nil, fmt.Errorf("deb: writing control member %q: %w", m.name, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("deb: closing control archive: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("deb: closing control archive: %w", err)
	}

	return buf.Bytes(), nil
}

func withHeader(script string) string {
	if script == "" {
		return ""
	}

	return RemoveScriptHeader + script
}

// controlFile renders the control file of the package.
func controlFile(spec *Spec, stats *dataStats) string {
	var sb strings.Builder

	field := func(name, value string) {
		if value != "" {
			writeField(&sb, name, value)
		}
	}

	list := func(name string, rels []Alternatives) {
		if len(rels) > 0 {
			field(name, FormatRelations(rels))
		}
	}

	field("Package", spec.Name)
	field("Version", spec.FullVersion())
	field("Section", spec.Section)
	field("Priority", spec.Priority)

	if spec.Essential {
		field("Essential", "yes")
	}

	if spec.Protected {
		field("Protected", "yes")
	}

	field("Architecture", spec.Architecture)

	multiArch := spec.MultiArch
	if multiArch == "" && spec.Architecture == "all" {
		multiArch = "foreign"
	}

	field("Multi-Arch", multiArch)
	field("Maintainer", spec.Maintainer)
	field("Source", spec.SourcePkg)

	installed := spec.InstalledSize
	if installed == 0 {
		installed = stats.size / 1024
	}

	field("Installed-Size", strconv.FormatInt(installed, 10))

	list("Provides", spec.Provides)
	list("Pre-Depends", spec.PreDepends)
	list("Depends", spec.Depends)
	list("Conflicts", spec.Conflicts)
	list("Breaks", spec.Breaks)
	list("Replaces", spec.Replaces)
	list("Recommends", spec.Recommends)
	list("Suggests", spec.Suggests)
	list("Enhances", spec.Enhances)
	list("Built-Using", spec.BuiltUsing)
	list("Static-Built-Using", spec.StaticBuiltUsing)
	field("Homepage", spec.URL)
	field("Bugs", spec.Bugs)

	for _, f := range spec.Fields {
		writeField(&sb, f.Name, f.Value)
	}

	field("Description", strings.TrimSpace(spec.Description))

	return sb.String()
}

func conffilesContent(files []string) string {
	var sb strings.Builder

	for _, f := range files {
		if f == "" {
			continue
		}

		if !strings.HasPrefix(f, "/") {
			f = "/" + f
		}

		sb.WriteString(f + "\n")
	}

	return sb.String()
}

// md5sumsContent renders the md5sums file: regular files sorted by path.
func md5sumsContent(lines []md5Line) string {
	sort.Slice(lines, func(i, j int) bool { return lines[i].path < lines[j].path })

	var sb strings.Builder

	for _, l := range lines {
		sb.WriteString(l.sum + "  " + l.path + "\n")
	}

	return sb.String()
}

func copyrightContent(spec *Spec) string {
	var sb strings.Builder

	sb.WriteString("Format: http://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n")
	writeField(&sb, "Upstream-Name", spec.Name)

	if spec.Maintainer != "" {
		writeField(&sb, "Upstream-Contact", spec.Maintainer)
	}

	if spec.URL != "" {
		writeField(&sb, "Source", spec.URL)
	}

	sb.WriteString("Files: *\n")

	if len(spec.Copyrights) > 0 {
		writeField(&sb, "Copyright", strings.Join(spec.Copyrights, "\n"))
	}

	writeField(&sb, "License", strings.Join(spec.Licenses, " and "))

	return sb.String()
}
