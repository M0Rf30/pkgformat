package deb

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

const (
	// MaxDebFileSize is the default limit on the size of a .deb file read by
	// ParseDebFileAt.
	MaxDebFileSize = 500 << 20

	// MaxControlArchiveSize caps the decompressed size of a control archive
	// (control.tar.{gz,xz,zst}). Without a cap, reading the decompressor to the
	// end lets a small compressed payload exhaust memory.
	MaxControlArchiveSize = 64 << 20

	// MaxControlFileSize caps one file of the control archive.
	MaxControlFileSize = 1 << 20

	// MaxSignatureSize caps one package signature member.
	MaxSignatureSize = 1 << 20

	// maxControlEntries bounds the number of entries read from a control
	// archive; real ones hold fewer than ten.
	maxControlEntries = 256
)

// ParseOptions tunes ParseDebFile. The zero value applies the defaults.
type ParseOptions struct {
	// MaxFileSize is the largest .deb accepted, in bytes. Zero means
	// MaxDebFileSize.
	MaxFileSize int64
}

// DebFile is a parsed .deb file. It keeps the reader it was parsed from, which
// must stay valid for OpenData and Extract.
type DebFile struct {
	Package     *Package
	ControlFile *ControlFile
	// ControlTarGz is the raw control archive member, whatever its compression.
	ControlTarGz []byte
	// Control holds the files of the control archive (control, md5sums,
	// conffiles, preinst, postinst, prerm, postrm, config, templates, ...) by
	// name, without a leading "./".
	Control map[string][]byte
	// Signatures are the package signature members (debsigs' _gpgorigin and
	// dpkg-sig's _gpgbuilder, _gpgmaint, ...) in archive order. They are not
	// verified here; see VerifySignatures.
	Signatures []SignatureMember

	r       io.ReaderAt
	data    *arMember
	members []arMember
}

// SignatureMember is one package signature member of the ar archive.
type SignatureMember struct {
	// Name is the member name, such as "_gpgorigin".
	Name string
	// Data is the raw content of the member.
	Data []byte
}

// Triggers parses the triggers control member. A package without one has no
// triggers.
func (d *DebFile) Triggers() ([]Trigger, error) {
	return ParseTriggers(bytes.NewReader(d.Control["triggers"]))
}

// Shlibs parses the shlibs control member.
func (d *DebFile) Shlibs() ([]Shlib, error) {
	return ParseShlibs(bytes.NewReader(d.Control["shlibs"]))
}

// Symbols parses the symbols control member.
func (d *DebFile) Symbols() ([]SymbolsLibrary, error) {
	return ParseSymbols(bytes.NewReader(d.Control["symbols"]))
}

// Conffiles returns the configuration files the package declares, one path per
// line of the conffiles member.
func (d *DebFile) Conffiles() []string {
	var out []string

	for line := range strings.SplitSeq(string(d.Control["conffiles"]), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}

	return out
}

// ParseDebFileAt parses a .deb file with the default limits. See ParseDebFile.
func ParseDebFileAt(r io.ReaderAt, size int64) (*DebFile, error) {
	return ParseDebFile(r, size, ParseOptions{})
}

// ParseDebFile parses a .deb file by walking the ar headers with ReadAt and
// reading only the control archive, so memory use does not depend on the size
// of the package. Every failure wraps ErrInvalidPackage.
func ParseDebFile(r io.ReaderAt, size int64, opts ParseOptions) (*DebFile, error) {
	d, err := parseDebFile(r, size, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPackage, err)
	}

	return d, nil
}

func parseDebFile(r io.ReaderAt, size int64, opts ParseOptions) (*DebFile, error) {
	maxSize := opts.MaxFileSize
	if maxSize <= 0 {
		maxSize = MaxDebFileSize
	}

	if size > maxSize {
		return nil, fmt.Errorf("%w: max %d bytes", ErrDebFileTooLarge, maxSize)
	}

	members, err := readARMembers(r, size)
	if err != nil {
		return nil, err
	}

	var control, data *arMember

	for i := range members {
		m := &members[i]

		switch {
		case control == nil && strings.HasPrefix(m.Name, "control.tar"):
			control = m
		case data == nil && strings.HasPrefix(m.Name, "data.tar"):
			data = m
		}
	}

	if control == nil {
		return nil, ErrControlArchiveNotFound
	}

	if control.Size > MaxControlArchiveSize {
		return nil, fmt.Errorf("%w: member %q declares size %d, max %d",
			ErrARMemberTooLarge, control.Name, control.Size, int64(MaxControlArchiveSize))
	}

	raw := make([]byte, control.Size)
	if _, err := r.ReadAt(raw, control.dataOff); err != nil && (!errors.Is(err, io.EOF) || control.Size != 0) {
		return nil, fmt.Errorf("reading %s: %w", control.Name, err)
	}

	files, err := readControlArchive(raw, control.Name)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", control.Name, err)
	}

	cfData, ok := files["control"]
	if !ok {
		return nil, fmt.Errorf("extracting control file: %w: 'control'", ErrFileNotFoundInTar)
	}

	cf, err := ParseControlFile(bytes.NewReader(cfData))
	if err != nil {
		return nil, fmt.Errorf("parsing control file: %w", err)
	}

	pkg, err := cf.ParsePackage()
	if err != nil {
		return nil, fmt.Errorf("parsing package metadata: %w", err)
	}

	sigs, err := readSignatureMembers(r, members)
	if err != nil {
		return nil, err
	}

	return &DebFile{
		Package: pkg, ControlFile: cf, ControlTarGz: raw, Control: files, Signatures: sigs,
		r: r, data: data, members: members,
	}, nil
}

// readSignatureMembers reads the members whose name starts with "_gpg".
func readSignatureMembers(r io.ReaderAt, members []arMember) ([]SignatureMember, error) {
	var out []SignatureMember

	for i := range members {
		m := &members[i]
		if !strings.HasPrefix(m.Name, "_gpg") {
			continue
		}

		if m.Size > MaxSignatureSize {
			return nil, fmt.Errorf("%w: member %q declares size %d, max %d",
				ErrARMemberTooLarge, m.Name, m.Size, int64(MaxSignatureSize))
		}

		buf := make([]byte, m.Size)
		if _, err := r.ReadAt(buf, m.dataOff); err != nil && (!errors.Is(err, io.EOF) || m.Size != 0) {
			return nil, fmt.Errorf("reading %s: %w", m.Name, err)
		}

		out = append(out, SignatureMember{Name: m.Name, Data: buf})
	}

	return out, nil
}

// readControlArchive decompresses a control archive member and returns the
// regular files in it by cleaned name.
func readControlArchive(raw []byte, member string) (map[string][]byte, error) {
	ext := compressionOf(member)
	if ext == ".lz4" || (ext == "" && member != "control.tar") {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedArchiveFormat, member)
	}

	dec, err := newDecoder(bytes.NewReader(raw), ext)
	if err != nil {
		return nil, err
	}

	defer func() { _ = dec.Close() }()

	tarData, err := limitio.ReadAll(dec, MaxControlArchiveSize, ErrControlArchiveTooLarge)
	if err != nil {
		return nil, err
	}

	tr := tar.NewReader(bytes.NewReader(tarData))
	files := make(map[string][]byte)

	for n := 0; ; n++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}

		if err != nil {
			return nil, fmt.Errorf("reading tar entry: %w", err)
		}

		if n >= maxControlEntries {
			return nil, fmt.Errorf("%w: more than %d control archive entries", ErrTooLarge, maxControlEntries)
		}

		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA { //nolint:staticcheck // old archives use the NUL type
			continue
		}

		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))

		content, err := limitio.ReadAll(tr, MaxControlFileSize, ErrControlFileTooLarge)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}

		files[name] = content
	}
}

// OpenData returns the decompressed data archive (a tar stream) of the
// package. The size of the output is not limited here; Extract bounds it.
func (d *DebFile) OpenData() (io.ReadCloser, error) {
	if d.data == nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPackage, ErrDataArchiveNotFound)
	}

	ext := compressionOf(d.data.Name)
	if ext == ".lz4" || (ext == "" && d.data.Name != "data.tar") {
		return nil, fmt.Errorf("%w: %w: %s", ErrInvalidPackage, ErrUnsupportedArchiveFormat, d.data.Name)
	}

	dec, err := newDecoder(io.NewSectionReader(d.r, d.data.dataOff, d.data.Size), ext)
	if err != nil {
		return nil, fmt.Errorf("%w: opening %s: %w", ErrInvalidPackage, d.data.Name, err)
	}

	return dec, nil
}
