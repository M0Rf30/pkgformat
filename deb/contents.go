package deb

import (
	"archive/tar"
	"bufio"
	"errors"
	"fmt"
	"io"
	"iter"
	"sort"
	"strings"
)

const (
	// MaxContentsFiles bounds the files ParseContents and
	// ContentsBuilder.AddReader accept. The Contents index of a large Debian
	// architecture lists some ten million.
	MaxContentsFiles = 1 << 25
	// MaxContentsLocations bounds the packages that one file of a Contents
	// index lists.
	MaxContentsLocations = 1 << 16
	// maxContentsDebFiles bounds the files ContentsBuilder.AddDeb reads from one
	// package.
	maxContentsDebFiles = 1 << 22
	// maxContentsPath bounds a path of a package.
	maxContentsPath = 1 << 16
)

// ErrInvalidContents is returned for a file or package name that cannot be
// written to a Contents index, such as a package name that holds a blank or a
// comma.
var ErrInvalidContents = errors.New("deb: invalid contents entry")

// ContentsFileName is the file name of a Contents index: "Contents-amd64" for
// the packages of an architecture, "Contents-udeb-amd64" for its udebs, with
// ext (".gz", ".xz", "") appended. In a repository it lives in dists/<dist>
// and in each component directory (main/Contents-amd64.gz).
func ContentsFileName(arch string, udeb bool, ext string) string {
	if udeb {
		return "Contents-udeb-" + arch + ext
	}

	return "Contents-" + arch + ext
}

// ContentsLocation is the name a package goes by in a Contents file:
// "section/name", or just the name for a package without a Section, as
// apt-ftparchive generate and dak write it.
func ContentsLocation(cf *ControlFile) string {
	name := cf.Get("Package")
	if section := cf.Get("Section"); section != "" {
		return section + "/" + name
	}

	return name
}

// ContentsEntry is one line of a Contents index: a file and the packages that
// contain it.
type ContentsEntry struct {
	// Path is the file, without a leading "./" or "/".
	Path string
	// Locations lists the packages as "section/name" (see ContentsLocation).
	Locations []string
}

// normalizeContentsPath strips the "./" or "/" a tar member name starts with.
func normalizeContentsPath(p string) string {
	for strings.HasPrefix(p, "./") || strings.HasPrefix(p, "/") {
		p = strings.TrimPrefix(strings.TrimPrefix(p, "./"), "/")
	}

	return p
}

// ContentsBuilder accumulates the files of packages and renders them as a
// Contents index, the way apt-ftparchive does: one line per file, sorted by
// path, the path padded with tabs and spaces to the package column, the
// packages after it, sorted and comma separated. The zero value is empty and
// ready to use.
type ContentsBuilder struct {
	files map[string]map[string]struct{}
}

// validContentsLocation reports whether a package name can be a location
// column: not empty and without blanks, commas or line breaks.
func validContentsLocation(s string) bool {
	return s != "" && !strings.ContainsAny(s, " \t,\r\n\x00")
}

// Add records that the package at location (see ContentsLocation) contains
// paths. Paths are stored without leading "./" or "/"; empty ones, directory
// names (a trailing "/") and names with a line break or NUL, which a Contents
// file cannot hold, are ignored. A location that is empty or holds a blank, a
// comma or a line break fails with ErrInvalidContents.
func (b *ContentsBuilder) Add(location string, paths ...string) error {
	if !validContentsLocation(location) {
		return fmt.Errorf("%w: package %q", ErrInvalidContents, location)
	}

	if b.files == nil {
		b.files = make(map[string]map[string]struct{})
	}

	for _, p := range paths {
		p = normalizeContentsPath(p)
		if p == "" || strings.HasSuffix(p, "/") || strings.ContainsAny(p, "\r\n\x00") {
			continue
		}

		locs := b.files[p]
		if locs == nil {
			locs = make(map[string]struct{}, 1)
			b.files[p] = locs
		}

		locs[location] = struct{}{}
	}

	return nil
}

// AddEntry records a ContentsEntry, such as ScanContents yields.
func (b *ContentsBuilder) AddEntry(e ContentsEntry) error {
	for _, loc := range e.Locations {
		if err := b.Add(loc, e.Path); err != nil {
			return err
		}
	}

	return nil
}

// AddReader merges a Contents index read from r (decompressed; wrap a
// compressed one with OpenIndex) into the builder. It fails with ErrTooLarge
// when the builder would hold more than MaxContentsFiles files.
func (b *ContentsBuilder) AddReader(r io.Reader) error {
	for e, err := range ScanContents(r) {
		if err != nil {
			return err
		}

		if _, known := b.files[e.Path]; !known && len(b.files) >= MaxContentsFiles {
			return fmt.Errorf("%w: more than %d files in a contents index", ErrTooLarge, MaxContentsFiles)
		}

		if err := b.AddEntry(e); err != nil {
			return err
		}
	}

	return nil
}

// DebContentsFiles lists the files a package contains: the regular files,
// symbolic and hard links and special files of its data archive, not the
// directories, without the leading "./". It fails with ErrTooLarge for a
// package with an absurd number of members.
func DebContentsFiles(d *DebFile) ([]string, error) {
	rc, err := d.OpenData()
	if err != nil {
		return nil, err
	}

	defer func() { _ = rc.Close() }()

	tr := tar.NewReader(rc)

	var out []string

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}

		if err != nil {
			return nil, fmt.Errorf("%w: reading data archive: %w", ErrInvalidPackage, err)
		}

		switch hdr.Typeflag {
		case tar.TypeDir, tar.TypeXGlobalHeader, tar.TypeXHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			continue
		}

		if len(out) >= maxContentsDebFiles {
			return nil, fmt.Errorf("%w: package lists more than %d files", ErrTooLarge, maxContentsDebFiles)
		}

		if len(hdr.Name) > maxContentsPath {
			return nil, fmt.Errorf("%w: path over %d bytes", ErrTooLarge, maxContentsPath)
		}

		out = append(out, normalizeContentsPath(hdr.Name))
	}
}

// AddDeb records the files of a package under its own name: Section/Package
// from its control file, see ContentsLocation.
func (b *ContentsBuilder) AddDeb(d *DebFile) error {
	if d.ControlFile == nil {
		return fmt.Errorf("%w: package without a control file", ErrInvalidPackage)
	}

	return b.AddDebAs(d, ContentsLocation(d.ControlFile))
}

// AddDebAs records the files of a package under location instead of the name
// its control file gives, such as the qualified name an override file assigns.
func (b *ContentsBuilder) AddDebAs(d *DebFile, location string) error {
	files, err := DebContentsFiles(d)
	if err != nil {
		return err
	}

	return b.Add(location, files...)
}

// Len is the number of distinct file paths.
func (b *ContentsBuilder) Len() int { return len(b.files) }

// Locations returns the packages that contain the file, sorted.
func (b *ContentsBuilder) Locations(path string) []string {
	return sortedKeys(b.files[normalizeContentsPath(path)])
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}

	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}

// Entries yields the files in path order, with their packages sorted.
func (b *ContentsBuilder) Entries() iter.Seq[ContentsEntry] {
	return func(yield func(ContentsEntry) bool) {
		paths := make([]string, 0, len(b.files))
		for p := range b.files {
			paths = append(paths, p)
		}

		sort.Strings(paths)

		for _, p := range paths {
			if !yield(ContentsEntry{Path: p, Locations: sortedKeys(b.files[p])}) {
				return
			}
		}
	}
}

// contentsPadTo is the column apt-ftparchive aligns the package column at.
const contentsPadTo = 60

// appendContentsLine appends the line of an entry.
func appendContentsLine(sb *strings.Builder, path string, locations []string) {
	sb.WriteString(path)

	// Tabs to column 56, then spaces to 60, like apt-ftparchive; a path of 56
	// columns or more gets spaces up to column 60 and at least one.
	col := len(path)
	if col >= contentsPadTo-4 {
		for range max(contentsPadTo-col, 1) {
			sb.WriteByte(' ')
		}
	} else {
		for col < contentsPadTo-4 {
			sb.WriteByte('\t')

			col = (col/8 + 1) * 8
		}

		sb.WriteString("    ")
	}

	sb.WriteString(strings.Join(locations, ","))
	sb.WriteByte('\n')
}

// Bytes renders the index, deterministically: the same files and packages give
// the same bytes however they were added.
func (b *ContentsBuilder) Bytes() []byte {
	var sb strings.Builder

	for e := range b.Entries() {
		appendContentsLine(&sb, e.Path, e.Locations)
	}

	return []byte(sb.String())
}

// Compressed renders the index compressed with c.
func (b *ContentsBuilder) Compressed(c Compression) ([]byte, error) {
	var buf sliceWriter

	if _, err := b.WriteTo(&buf, c); err != nil {
		return nil, err
	}

	return buf.b, nil
}

// WriteTo writes the index compressed with c to w and returns the number of
// bytes written to w. It streams: the index is not rendered in memory first.
func (b *ContentsBuilder) WriteTo(w io.Writer, c Compression) (int64, error) {
	cw := &countingWriter{w: w}

	zw, err := compressWriter(cw, c)
	if err != nil {
		return 0, err
	}

	bw := bufio.NewWriterSize(zw, 64<<10)

	var sb strings.Builder

	for e := range b.Entries() {
		sb.Reset()
		appendContentsLine(&sb, e.Path, e.Locations)

		if _, err := bw.WriteString(sb.String()); err != nil {
			_ = zw.Close()

			return cw.n, fmt.Errorf("deb: writing contents: %w", err)
		}
	}

	if err := bw.Flush(); err != nil {
		_ = zw.Close()

		return cw.n, fmt.Errorf("deb: writing contents: %w", err)
	}

	if err := zw.Close(); err != nil {
		return cw.n, fmt.Errorf("deb: closing contents: %w", err)
	}

	return cw.n, nil
}

// ScanContents yields the files of a Contents index (read decompressed), with
// the packages that contain them, in file order. A header line ("FILE
// LOCATION"), blank lines and lines without a package column are skipped. The
// path may contain blanks: the package column is the last blank-separated word
// of the line, as apt-file reads it. A line over MaxLineBytes or with more
// than MaxContentsLocations packages ends the scan with ErrTooLarge. Reading
// is streaming; stopping the loop stops the read.
func ScanContents(r io.Reader) iter.Seq2[ContentsEntry, error] {
	return func(yield func(ContentsEntry, error) bool) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64<<10), MaxLineBytes)

		for sc.Scan() {
			e, ok, err := parseContentsLine(sc.Text())
			if err != nil {
				yield(ContentsEntry{}, err)

				return
			}

			if ok && !yield(e, nil) {
				return
			}
		}

		if err := sc.Err(); err != nil {
			if errors.Is(err, bufio.ErrTooLong) {
				err = fmt.Errorf("%w: contents line over %d bytes", ErrTooLarge, MaxLineBytes)
			} else {
				err = fmt.Errorf("deb: reading contents: %w", err)
			}

			yield(ContentsEntry{}, err)
		}
	}
}

// parseContentsLine reads one line; ok is false for a line to skip.
func parseContentsLine(line string) (e ContentsEntry, ok bool, err error) {
	line = strings.TrimRight(line, " \t\r")

	i := strings.LastIndexAny(line, " \t")
	if i < 0 {
		return ContentsEntry{}, false, nil
	}

	path := strings.TrimRight(line[:i], " \t")
	locs := line[i+1:]

	if path == "" || locs == "" || (path == "FILE" && locs == "LOCATION") {
		return ContentsEntry{}, false, nil
	}

	if strings.Count(locs, ",") >= MaxContentsLocations {
		return ContentsEntry{}, false, fmt.Errorf("%w: file %q lists over %d packages", ErrTooLarge, path, MaxContentsLocations)
	}

	parts := strings.Split(locs, ",")
	kept := parts[:0]

	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}

	if len(kept) == 0 {
		return ContentsEntry{}, false, nil
	}

	return ContentsEntry{Path: path, Locations: kept}, true, nil
}

// ContentsIndex is a parsed Contents index: which packages contain a file,
// which is what apt-file searches. Build one with ParseContents.
type ContentsIndex struct {
	files map[string][]string
}

// ParseContents reads a whole Contents index (see ScanContents). The input is
// expected decompressed; wrap a compressed one with OpenIndex. A file listed
// twice has its packages merged. More than MaxContentsFiles files fail with
// ErrTooLarge.
func ParseContents(r io.Reader) (*ContentsIndex, error) {
	c := &ContentsIndex{files: make(map[string][]string)}

	for e, err := range ScanContents(r) {
		if err != nil {
			return nil, err
		}

		p := normalizeContentsPath(e.Path)
		if p == "" {
			continue
		}

		old, known := c.files[p]
		if !known && len(c.files) >= MaxContentsFiles {
			return nil, fmt.Errorf("%w: more than %d files in a contents index", ErrTooLarge, MaxContentsFiles)
		}

		c.files[p] = mergeSorted(old, e.Locations)
	}

	return c, nil
}

// mergeSorted returns the sorted union of a sorted list and any list.
func mergeSorted(sorted, more []string) []string {
	set := make(map[string]struct{}, len(sorted)+len(more))

	for _, s := range sorted {
		set[s] = struct{}{}
	}

	for _, s := range more {
		set[s] = struct{}{}
	}

	return sortedKeys(set)
}

// Len is the number of distinct file paths.
func (c *ContentsIndex) Len() int { return len(c.files) }

// Locations returns the packages that contain the file, sorted.
func (c *ContentsIndex) Locations(path string) []string {
	return append([]string(nil), c.files[normalizeContentsPath(path)]...)
}

// Find returns the paths for which match is true, with their packages.
func (c *ContentsIndex) Find(match func(path string) bool) map[string][]string {
	out := make(map[string][]string)

	for p, locs := range c.files {
		if match(p) {
			out[p] = append([]string(nil), locs...)
		}
	}

	return out
}

// Entries yields the files in path order.
func (c *ContentsIndex) Entries() iter.Seq[ContentsEntry] {
	return func(yield func(ContentsEntry) bool) {
		paths := make([]string, 0, len(c.files))
		for p := range c.files {
			paths = append(paths, p)
		}

		sort.Strings(paths)

		for _, p := range paths {
			if !yield(ContentsEntry{Path: p, Locations: append([]string(nil), c.files[p]...)}) {
				return
			}
		}
	}
}
