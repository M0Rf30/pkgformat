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
// root "./". Owners are root:root. The md5sums file and, when Spec.InstalledSize
// is zero, the Installed-Size are computed from the payload.
func Write(w io.Writer, spec *Spec, payload []Entry, opts WriteOptions) error {
	if err := spec.Validate(); err != nil {
		return err
	}

	comp, _ := ParseCompression(spec.Compression) // validated above

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

	stats, err := writeDataArchive(staging, comp, spec, entries)
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

	control, err := buildControlArchive(spec, comp, stats)
	if err != nil {
		return err
	}

	aw, err := newARWriter(w)
	if err != nil {
		return err
	}

	ext := comp.Extension()

	if err := aw.member("debian-binary", int64(len(debianBinary)), spec.ModTime, strings.NewReader(debianBinary)); err != nil {
		return err
	}

	if err := aw.member(controlTarName+ext, int64(len(control)), spec.ModTime, bytes.NewReader(control)); err != nil {
		return err
	}

	return aw.member(dataTarName+ext, dataSize, spec.ModTime, staging)
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

// writeDataArchive writes the tar of the payload, compressed, to w.
func writeDataArchive(w io.Writer, comp Compression, spec *Spec, entries []Entry) (*dataStats, error) {
	zw, err := compressWriter(w, comp)
	if err != nil {
		return nil, err
	}

	tw := tar.NewWriter(zw)
	stats := &dataStats{}
	seen := map[string]bool{"": true}

	if err := writeDir(tw, "", 0o755, spec.ModTime); err != nil {
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

			if err := writeDir(tw, dir, 0o755, spec.ModTime); err != nil {
				return nil, err
			}
		}

		mtime := e.ModTime
		if mtime.IsZero() {
			mtime = spec.ModTime
		}

		if err := writeEntry(tw, p, e, mtime, stats); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("deb: closing data archive: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("deb: closing data archive: %w", err)
	}

	return stats, nil
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

func writeDir(tw *tar.Writer, p string, mode int64, mtime time.Time) error {
	name := "./"
	if p != "" {
		name = "./" + p + "/"
	}

	return writeHeader(tw, &tar.Header{
		Typeflag: tar.TypeDir, Name: name, Mode: mode, ModTime: mtime,
	})
}

func writeHeader(tw *tar.Writer, hdr *tar.Header) error {
	hdr.Uid, hdr.Gid = 0, 0
	hdr.Uname, hdr.Gname = "root", "root"
	hdr.Format = tar.FormatGNU

	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("deb: writing tar header %q: %w", hdr.Name, err)
	}

	return nil
}

func writeEntry(tw *tar.Writer, p string, e *Entry, mtime time.Time, stats *dataStats) error {
	switch {
	case e.Mode.IsDir():
		return writeHeader(tw, &tar.Header{
			Typeflag: tar.TypeDir, Name: "./" + p + "/", Mode: tarMode(e.Mode), ModTime: mtime,
		})
	case e.Mode&fs.ModeSymlink != 0:
		if e.Linkname == "" {
			return invalidSpec("symlink %q has no target", p)
		}

		stats.size += int64(len(e.Linkname))

		return writeHeader(tw, &tar.Header{
			Typeflag: tar.TypeSymlink, Name: "./" + p, Linkname: e.Linkname, Mode: 0o777, ModTime: mtime,
		})
	case e.Mode.IsRegular():
		return writeFile(tw, p, e, mtime, stats)
	}

	return invalidSpec("entry %q has unsupported type %s", p, e.Mode.Type())
}

func writeFile(tw *tar.Writer, p string, e *Entry, mtime time.Time, stats *dataStats) error {
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

	if err := writeHeader(tw, &tar.Header{
		Typeflag: tar.TypeReg, Name: "./" + p, Mode: tarMode(e.Mode), Size: size, ModTime: mtime,
	}); err != nil {
		return err
	}

	h := md5.New() //nolint:gosec // see import

	n, err := io.Copy(io.MultiWriter(tw, h), io.LimitReader(body, size))
	if err != nil {
		return fmt.Errorf("deb: writing %q: %w", p, err)
	}

	if n != size {
		return fmt.Errorf("deb: writing %q: %w: %d of %d bytes", p, io.ErrUnexpectedEOF, n, size)
	}

	stats.size += size
	stats.md5s = append(stats.md5s, md5Line{path: p, sum: hex.EncodeToString(h.Sum(nil))})

	return nil
}

// buildControlArchive returns the compressed control archive.
func buildControlArchive(spec *Spec, comp Compression, stats *dataStats) ([]byte, error) {
	type member struct {
		name string
		mode int64
		body string
	}

	members := []member{{"control", 0o644, controlFile(spec, stats)}}

	if conf := conffilesContent(spec.Conffiles); conf != "" {
		members = append(members, member{"conffiles", 0o644, conf})
	}

	if sums := md5sumsContent(stats.md5s); sums != "" {
		members = append(members, member{"md5sums", 0o644, sums})
	}

	if len(spec.Licenses) > 0 {
		members = append(members, member{"copyright", 0o644, copyrightContent(spec)})
	}

	sc := spec.Scripts

	for _, s := range []struct {
		name, body string
		mode       int64
	}{
		{"preinst", sc.Preinst, 0o755},
		{"postinst", sc.Postinst, 0o755},
		{"prerm", withHeader(sc.Prerm), 0o755},
		{"postrm", withHeader(sc.Postrm), 0o755},
		{"config", sc.Config, 0o755},
		{"templates", sc.Templates, 0o644},
	} {
		if s.body != "" {
			members = append(members, member{s.name, s.mode, s.body})
		}
	}

	var buf bytes.Buffer

	zw, err := compressWriter(&buf, comp)
	if err != nil {
		return nil, err
	}

	tw := tar.NewWriter(zw)

	if err := writeDir(tw, "", 0o755, spec.ModTime); err != nil {
		return nil, err
	}

	for _, m := range members {
		if err := writeHeader(tw, &tar.Header{
			Typeflag: tar.TypeReg, Name: "./" + m.name, Mode: m.mode, Size: int64(len(m.body)), ModTime: spec.ModTime,
		}); err != nil {
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

	list := func(name string, values []string) {
		var kept []string

		for _, v := range values {
			if v = strings.TrimSpace(v); v != "" {
				kept = append(kept, v)
			}
		}

		field(name, strings.Join(kept, ", "))
	}

	field("Package", spec.Name)
	field("Version", spec.FullVersion())
	field("Section", spec.Section)
	field("Priority", spec.Priority)
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
	field("Homepage", spec.URL)
	field("Bugs", spec.Bugs)
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
