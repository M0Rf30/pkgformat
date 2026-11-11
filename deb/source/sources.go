package source

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
)

// SourceEntry is one stanza of a Sources index: the description of a source
// package, the directory of the archive that holds its files, and the Priority
// and Section the archive assigns.
type SourceEntry struct {
	DSC
	// Directory is the directory that holds the files, relative to the archive
	// root ("pool/main/h/hello").
	Directory string
	Priority  string
	Section   string
}

var indexKnown = nameSet(append(dscKnownNames(), "Package", "Directory", "Priority", "Section")...)

func dscKnownNames() []string {
	names := make([]string, 0, len(dscKnown))
	for n := range dscKnown {
		names = append(names, n)
	}

	return names
}

// indexOrder is the order apt-ftparchive writes the fields of a Sources stanza
// in; the fields it does not list follow in document order.
var indexOrder = []string{
	"Package", "Format", "Binary", "Architecture", "Version", "Priority", "Section", "Maintainer",
	"Original-Maintainer", "Uploaders", "Standards-Version",
	"Build-Depends", "Build-Depends-Arch", "Build-Depends-Indep",
	"Build-Conflicts", "Build-Conflicts-Arch", "Build-Conflicts-Indep",
	"Testsuite", "Testsuite-Triggers", "Homepage",
	"Vcs-Browser", "Vcs-Arch", "Vcs-Bzr", "Vcs-Cvs", "Vcs-Darcs", "Vcs-Git", "Vcs-Hg", "Vcs-Mtn", "Vcs-Svn",
	"Directory", "Package-List",
	"Files", "Checksums-Sha1", "Checksums-Sha256", "Checksums-Sha512",
}

// Control renders the stanza of the index.
func (e *SourceEntry) Control() *deb.ControlFile {
	src := e.DSC.Control()

	// The index calls the source "Package"; the fields that a .dsc keeps in
	// another order are put in the order of the index.
	src.Fields["Package"] = src.Fields["Source"]
	src.Fields["Directory"] = e.Directory
	src.Fields["Priority"] = e.Priority
	src.Fields["Section"] = e.Section

	delete(src.Fields, "Source")

	out := deb.NewControlFile()
	done := map[string]bool{}

	put := func(name string) {
		if v, ok := src.Fields[name]; ok && v != "" && !done[name] {
			out.Set(name, v)

			done[name] = true
		}
	}

	for _, name := range indexOrder {
		put(name)
	}

	for _, name := range src.Order {
		put(name)
	}

	return out
}

// Marshal renders the stanza, ending with a newline.
func (e *SourceEntry) Marshal() []byte { return []byte(e.Control().String()) }

// SourcesFileName returns the name of the index file for a compression:
// "Sources", "Sources.gz", "Sources.xz" or "Sources.zst".
func SourcesFileName(compression string) (string, error) {
	c, err := parseWriteCompression(compression)
	if err != nil {
		return "", err
	}

	return "Sources" + c.ext, nil
}

// WriteSources writes entries as a Sources index to w, in the order given,
// each followed by an empty line, compressed according to compression ("", "none",
// "gzip", "xz" or "zstd").
func WriteSources(w io.Writer, entries []SourceEntry, compression string) error {
	c, err := parseWriteCompression(compression)
	if err != nil {
		return err
	}

	cw, err := c.write(w)
	if err != nil {
		return err
	}

	for i := range entries {
		if _, err := cw.Write(entries[i].Marshal()); err != nil {
			_ = cw.Close()

			return err
		}

		if _, err := io.WriteString(cw, "\n"); err != nil {
			_ = cw.Close()

			return err
		}
	}

	return cw.Close()
}

// ReadSources reads a Sources index from r. name selects the decompression by
// its extension (".gz", ".bz2", ".xz", ".lz4", ".zst", or none); reading more
// than [deb.MaxIndexBytes] of decompressed data fails with [deb.ErrTooLarge].
func ReadSources(r io.Reader, name string) ([]SourceEntry, error) {
	rc, err := deb.OpenIndex(r, name)
	if err != nil {
		return nil, err
	}

	defer rc.Close()

	var entries []SourceEntry

	err = deb.ScanControl(rc, func(cf *deb.ControlFile) error {
		d, err := dscFromControl(cf, true)
		if err != nil {
			return err
		}

		entries = append(entries, SourceEntry{
			DSC: *d, Directory: cf.Get("Directory"), Priority: cf.Get("Priority"), Section: cf.Get("Section"),
		})

		return nil
	})
	if err != nil {
		return nil, err
	}

	return entries, nil
}

// SourcesOptions tunes [IndexSources].
type SourcesOptions struct {
	// Directory is the Directory field of the stanzas for packages found
	// directly in root; a package in a subdirectory appends it.
	Directory string
	// Priority and Section are given to every stanza. apt-ftparchive writes
	// none without an override file; dpkg-scansources writes "optional" and
	// "unknown".
	Priority, Section string
}

// IndexSources builds the Sources stanzas of the .dsc files below root, like
// apt-ftparchive sources: the .dsc and every file it lists are hashed from
// disk with MD5, SHA-1, SHA-256 and SHA-512 and listed, the .dsc first. The
// entries are sorted by source name and version.
func IndexSources(root string, opts *SourcesOptions) ([]SourceEntry, error) {
	if opts == nil {
		opts = &SourcesOptions{}
	}

	var entries []SourceEntry

	err := filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() || !strings.HasSuffix(p, ".dsc") {
			return err
		}

		e, err := indexEntry(root, p, opts)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}

		entries = append(entries, e)

		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}

		return deb.CompareVersions(entries[i].Version, entries[j].Version) < 0
	})

	return entries, nil
}

func indexEntry(root, dscPath string, opts *SourcesOptions) (SourceEntry, error) {
	data, err := os.ReadFile(dscPath)
	if err != nil {
		return SourceEntry{}, err
	}

	if len(data) > MaxDocumentBytes {
		return SourceEntry{}, ErrTooLarge
	}

	d, err := ParseDSC(data)
	if err != nil {
		return SourceEntry{}, err
	}

	dir := filepath.Dir(dscPath)

	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return SourceEntry{}, err
	}

	files := make([]FileRef, 0, len(d.Files)+1)

	for _, name := range append([]string{filepath.Base(dscPath)}, fileNames(d.Files)...) {
		f, err := hashFile(filepath.Join(dir, name), name)
		if err != nil {
			return SourceEntry{}, err
		}

		files = append(files, f)
	}

	if err := checkListed(d.Files, files[1:]); err != nil {
		return SourceEntry{}, err
	}

	d.Files = files

	e := SourceEntry{DSC: *d, Priority: opts.Priority, Section: opts.Section}
	e.Directory = path.Join(opts.Directory, filepath.ToSlash(rel))

	return e, nil
}

func fileNames(files []FileRef) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Name
	}

	return out
}

// checkListed verifies that the hashed files are the ones the .dsc declares.
func checkListed(declared, hashed []FileRef) error {
	for i := range declared {
		d, h := &declared[i], &hashed[i]
		if d.Size != h.Size {
			return fmt.Errorf("%w: %s is %d bytes, the .dsc lists %d", ErrChecksum, d.Name, h.Size, d.Size)
		}

		for _, k := range []int{hashMD5, hashSHA1, hashSHA256, hashSHA512} {
			if want := d.get(k); want != "" && !strings.EqualFold(want, h.get(k)) {
				return fmt.Errorf("%w: %s %s", ErrChecksum, d.Name, checksumFields[k])
			}
		}
	}

	return nil
}

// hashFile returns the FileRef of the file at p with all four digests.
func hashFile(p, name string) (FileRef, error) {
	f, err := os.Open(p)
	if err != nil {
		return FileRef{}, err
	}

	defer f.Close()

	fi, err := deb.HashReader(name, f)
	if err != nil {
		return FileRef{}, err
	}

	return FileRef{
		Name: name, Size: fi.Size, MD5: fi.MD5sum, SHA1: fi.SHA1, SHA256: fi.SHA256, SHA512: fi.SHA512,
	}, nil
}
