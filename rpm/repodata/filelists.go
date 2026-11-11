package repodata

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// ErrDocKind means a [DocWriter] was given a package that its document kind
// cannot hold.
var ErrDocKind = errors.New("repodata: package does not fit the document kind")

// The types of a <file> element of filelists.xml and filelists-ext.xml. A
// regular file, a symbolic link or any other entry has no type.
const (
	FileTypeRegular = ""
	FileTypeDir     = "dir"
	FileTypeGhost   = "ghost"
)

// FilelistsFile is a <file> element of filelists-ext.xml.
type FilelistsFile struct {
	// Path is the absolute path of the file.
	Path string
	// Type is [FileTypeDir], [FileTypeGhost] or empty for any other entry.
	Type string
	// Hash is the hex digest of the content of a regular file, computed with
	// the algorithm of [FilelistsExtPackage.ChecksumType]; empty for
	// directories, ghost files, symbolic links and files the package carries
	// no digest for.
	Hash string
}

// FilelistsExtPackage is a <package> element of filelists-ext.xml, the
// document createrepo_c --filelists-ext writes: the file list of the package
// with the digest of every regular file. A filelists.xml package reads into
// the same type with empty digests.
type FilelistsExtPackage struct {
	// PkgID is the checksum of the package, the pkgid of its primary.xml
	// entry.
	PkgID   string
	Name    string
	Arch    string
	Epoch   uint32
	Version string
	Release string
	// ChecksumType is the algorithm of the file digests, the type of the
	// <checksum> element: "sha256" for the packages rpm builds by default.
	ChecksumType string
	Files        []FilelistsFile
}

// FilelistsLimits bounds [ReadFilelistsExt]. A zero field selects its
// default.
type FilelistsLimits struct {
	// MaxFiles bounds the <file> entries of a package; a package with more
	// fails the read with [ErrTooLarge].
	MaxFiles int
	// MaxFileBytes bounds the total size of the paths of a package.
	MaxFileBytes int
	// MaxFieldBytes bounds one path, digest or attribute.
	MaxFieldBytes int
}

func (l FilelistsLimits) normalized() FilelistsLimits {
	if l.MaxFiles <= 0 {
		l.MaxFiles = DefaultMaxFiles
	}

	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = DefaultMaxFileBytes
	}

	if l.MaxFieldBytes <= 0 {
		l.MaxFieldBytes = DefaultMaxFieldBytes
	}

	return l
}

// ReadFilelistsExt decodes filelists-ext.xml, or filelists.xml, from r and
// calls fn for every package, in document order. The package is only valid
// during the call. A package without a name or an architecture, or with a
// malformed epoch, is skipped; malformed XML, a limit exceeded
// ([ErrTooLarge]) or an error of fn stops the read and is returned. Bound the
// decompressed size of r with [OpenMetadata].
func ReadFilelistsExt(r io.Reader, lim FilelistsLimits, fn func(*FilelistsExtPackage) error) error {
	lim = lim.normalized()
	dec := xml.NewDecoder(r)

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("repodata: parsing filelists-ext.xml: %w", err)
		}

		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "package" {
			continue
		}

		pkg, valid, err := readFilelistsPackage(dec, start, lim)
		if err != nil {
			return err
		}

		if !valid || pkg.Name == "" || pkg.Arch == "" {
			continue
		}

		if err := fn(pkg); err != nil {
			return err
		}
	}
}

func readFilelistsPackage(dec *xml.Decoder, start xml.StartElement, lim FilelistsLimits) (*FilelistsExtPackage, bool, error) {
	pkg := &FilelistsExtPackage{
		PkgID: attrOf(start.Attr, "pkgid"),
		Name:  attrOf(start.Attr, "name"),
		Arch:  attrOf(start.Attr, "arch"),
	}
	valid := true
	fileBytes := 0

	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, false, fmt.Errorf("repodata: parsing filelists-ext.xml: %w", err)
		}

		t, ok := tok.(xml.StartElement)
		if !ok {
			if _, end := tok.(xml.EndElement); end {
				return pkg, valid, nil
			}

			continue
		}

		switch t.Name.Local {
		case "version":
			if epoch := attrOf(t.Attr, "epoch"); epoch != "" {
				n, err := strconv.ParseUint(epoch, 10, 32)
				if err != nil {
					valid = false
				}

				pkg.Epoch = uint32(n)
			}

			pkg.Version, pkg.Release = attrOf(t.Attr, "ver"), attrOf(t.Attr, "rel")
		case "checksum":
			pkg.ChecksumType = attrOf(t.Attr, "type")
		case "file":
			f := FilelistsFile{Type: attrOf(t.Attr, "type"), Hash: attrOf(t.Attr, "hash")}

			if len(f.Hash) > lim.MaxFieldBytes || len(f.Type) > lim.MaxFieldBytes {
				return nil, false, fieldTooLarge("a <file> attribute", lim.MaxFieldBytes)
			}

			if f.Path, err = readText(dec, lim.MaxFieldBytes, false); err != nil {
				return nil, false, wrapFilelistsXML(err)
			}

			if f.Path == "" {
				continue
			}

			fileBytes += len(f.Path)
			if len(pkg.Files) >= lim.MaxFiles || fileBytes > lim.MaxFileBytes {
				return nil, false, fmt.Errorf("%w: the file list of a package exceeds %d entries or %d bytes",
					ErrTooLarge, lim.MaxFiles, lim.MaxFileBytes)
			}

			pkg.Files = append(pkg.Files, f)

			continue
		}

		if err := dec.Skip(); err != nil {
			return nil, false, fmt.Errorf("repodata: parsing filelists-ext.xml: %w", err)
		}
	}
}

func wrapFilelistsXML(err error) error {
	if errors.Is(err, ErrTooLarge) {
		return err
	}

	return fmt.Errorf("repodata: parsing filelists-ext.xml: %w", err)
}

// WriteFilelistsExt streams packages as filelists-ext.xml to w, in the layout
// and with the escaping createrepo_c --filelists-ext uses: reading a document
// it wrote with [ReadFilelistsExt] and writing the packages back gives the
// same bytes.
func WriteFilelistsExt(w io.Writer, packages []FilelistsExtPackage) error {
	d := NewDocWriter(w, DocFilelistsExt, len(packages))

	for i := range packages {
		if err := d.FilelistsExt(&packages[i]); err != nil {
			return err
		}
	}

	return d.Close()
}

// FilelistsExt renders p into a filelists-ext document, with the digest of
// the files that have one. It fails with [ErrDocKind] when d writes another
// kind of document. A package without a ChecksumType is written with
// "sha256".
func (d *DocWriter) FilelistsExt(p *FilelistsExtPackage) error {
	if d.kind != DocFilelistsExt {
		return fmt.Errorf("%w: a filelists-ext package in a document of kind %d", ErrDocKind, d.kind)
	}

	o := d.o

	o.raw("\n<package")
	o.attr("pkgid", p.PkgID)
	o.attr("name", p.Name)
	o.attr("arch", p.Arch)
	o.raw(">")

	o.open("  ", "version")
	o.raw(` epoch="`)
	o.u32(p.Epoch)
	o.raw(`"`)
	o.attr("ver", p.Version)
	o.attr("rel", p.Release)
	o.selfClose()

	sum := p.ChecksumType
	if sum == "" {
		sum = "sha256"
	}

	o.open("  ", "checksum")
	o.attr("type", sum)
	o.selfClose()

	for i := range p.Files {
		f := &p.Files[i]

		o.open("  ", "file")
		o.optAttr("type", f.Type)
		o.optAttr("hash", f.Hash)
		o.raw(">")
		o.text(f.Path)
		o.closeTag("file")
	}

	o.raw("\n</package>")
	o.flushIfFull()

	return nil
}
