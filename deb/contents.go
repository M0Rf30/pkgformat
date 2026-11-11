package deb

import (
	"archive/tar"
	"bufio"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

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

// ContentsIndex maps the files of a set of packages to the packages that
// contain them, which is what a Contents file records and what apt-file
// searches. The zero value is empty and ready to use.
type ContentsIndex struct {
	files map[string]map[string]struct{}
}

// ContentsLocation is the name a package goes by in a Contents file:
// "section/name", or just the name for a package without a Section, as
// apt-ftparchive and dak write it.
func ContentsLocation(cf *ControlFile) string {
	name := cf.Get("Package")
	if section := cf.Get("Section"); section != "" {
		return section + "/" + name
	}

	return name
}

// normalizeContentsPath strips the "./" or "/" a tar member name starts with.
func normalizeContentsPath(p string) string {
	for strings.HasPrefix(p, "./") || strings.HasPrefix(p, "/") {
		p = strings.TrimPrefix(strings.TrimPrefix(p, "./"), "/")
	}

	return p
}

// Add records that the package at location (see ContentsLocation) contains
// paths. Paths are stored without leading "./" or "/"; empty ones and
// directory names (trailing "/") are ignored.
func (c *ContentsIndex) Add(location string, paths ...string) {
	if c.files == nil {
		c.files = make(map[string]map[string]struct{})
	}

	for _, p := range paths {
		p = normalizeContentsPath(p)
		if p == "" || strings.HasSuffix(p, "/") {
			continue
		}

		locs := c.files[p]
		if locs == nil {
			locs = make(map[string]struct{}, 1)
			c.files[p] = locs
		}

		locs[location] = struct{}{}
	}
}

// AddDeb records the files a package contains: the regular files, symbolic and
// hard links of its data archive, not the directories.
func (c *ContentsIndex) AddDeb(d *DebFile, location string) error {
	rc, err := d.OpenData()
	if err != nil {
		return err
	}

	defer func() { _ = rc.Close() }()

	tr := tar.NewReader(rc)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("%w: reading data archive: %w", ErrInvalidPackage, err)
		}

		switch hdr.Typeflag {
		case tar.TypeDir, tar.TypeXGlobalHeader, tar.TypeXHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			continue
		}

		c.Add(location, hdr.Name)
	}
}

// Len is the number of distinct file paths.
func (c *ContentsIndex) Len() int { return len(c.files) }

// Locations returns the packages that contain the file, sorted.
func (c *ContentsIndex) Locations(path string) []string {
	return sortedKeys(c.files[normalizeContentsPath(path)])
}

// Find returns the sorted paths for which match is true, with their packages.
func (c *ContentsIndex) Find(match func(path string) bool) map[string][]string {
	out := make(map[string][]string)

	for p, locs := range c.files {
		if match(p) {
			out[p] = sortedKeys(locs)
		}
	}

	return out
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

// contentsPadTo is the column apt-ftparchive aligns the package column at.
const contentsPadTo = 60

// Marshal renders the index as apt-ftparchive does: one line per file, sorted
// by path, the path padded with tabs and spaces to the package column and the
// packages after it, comma separated.
func (c *ContentsIndex) Marshal() []byte {
	paths := make([]string, 0, len(c.files))
	for p := range c.files {
		paths = append(paths, p)
	}

	sort.Strings(paths)

	var sb strings.Builder

	for _, p := range paths {
		sb.WriteString(p)

		// Tabs to column 56, then spaces to 60, like apt-ftparchive; a path that
		// is too long gets one tab.
		col := len(p)
		if col >= contentsPadTo-4 {
			sb.WriteByte('\t')
		} else {
			for col < contentsPadTo-4 {
				sb.WriteByte('\t')

				col = (col/8 + 1) * 8
			}

			sb.WriteString("    ")
		}

		sb.WriteString(strings.Join(sortedKeys(c.files[p]), ","))
		sb.WriteByte('\n')
	}

	return []byte(sb.String())
}

// Compressed renders the index compressed with c.
func (c *ContentsIndex) Compressed(comp Compression) ([]byte, error) {
	var buf sliceWriter

	zw, err := compressWriter(&buf, comp)
	if err != nil {
		return nil, err
	}

	if _, err := zw.Write(c.Marshal()); err != nil {
		_ = zw.Close()

		return nil, fmt.Errorf("deb: writing contents: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("deb: closing contents: %w", err)
	}

	return buf.b, nil
}

// ScanContents calls fn for every file of a Contents index, with the packages
// that contain it, in file order. A header line ("FILE LOCATION"), blank lines
// and lines without a package column are skipped. The path may contain blanks:
// the package column is the last blank-separated word of the line. fn
// returning an error stops the scan with it.
func ScanContents(r io.Reader, fn func(path string, locations []string) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineBytes)

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t\r")

		i := strings.LastIndexAny(line, " \t")
		if i < 0 {
			continue
		}

		path := strings.TrimRight(line[:i], " \t")
		locs := line[i+1:]

		if path == "" || locs == "" || (path == "FILE" && locs == "LOCATION") {
			continue
		}

		if err := fn(path, strings.Split(locs, ",")); err != nil {
			return err
		}
	}

	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("%w: contents line over %d bytes", ErrTooLarge, MaxLineBytes)
		}

		return fmt.Errorf("deb: reading contents: %w", err)
	}

	return nil
}

// ParseContents reads a whole Contents index (see ScanContents). The input is
// expected decompressed; wrap a compressed one with OpenIndex.
func ParseContents(r io.Reader) (*ContentsIndex, error) {
	c := &ContentsIndex{}

	err := ScanContents(r, func(path string, locs []string) error {
		c.Add(locs[0], path)

		for _, l := range locs[1:] {
			c.Add(l, path)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}
