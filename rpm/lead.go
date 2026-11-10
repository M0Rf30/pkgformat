package rpm

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

const (
	// LeadMagic is the magic number at the start of every RPM.
	LeadMagic uint32 = 0xEDABEEDB
	// LeadSize is the size in bytes of the lead, the fixed block in front of
	// the signature header.
	LeadSize = 96
)

// Lead is the fixed block at the start of an RPM. Everything it holds is
// repeated, authoritatively, in the headers; rpm only checks the magic.
type Lead struct {
	// MajorVersion and MinorVersion are the version of the lead: 3.0 for
	// format 4 packages, 4.0 for format 6.
	MajorVersion uint8
	MinorVersion uint8
	// Type is 0 for a binary package and 1 for a source package.
	Type uint16
	// Arch is the numeric architecture of the lead.
	Arch uint16
	// Name is the "name-version-release" the package was built as.
	Name string
	// OS is the numeric operating system of the lead.
	OS uint16
	// SignatureType is 5 for a package with a header-style signature.
	SignatureType uint16
}

// ParseLead reads and checks the lead of a package from r.
func ParseLead(r io.Reader) (*Lead, error) {
	buf, err := readExact(r, LeadSize)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the lead: %w", ErrNotRPM, err)
	}

	return parseLead(buf)
}

// parseLead decodes the 96 bytes of a lead.
func parseLead(buf []byte) (*Lead, error) {
	if len(buf) < LeadSize {
		return nil, fmt.Errorf("%w: the lead is %d bytes, want %d", ErrNotRPM, len(buf), LeadSize)
	}

	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != LeadMagic {
		return nil, fmt.Errorf("%w: lead magic %#x, want %#x", ErrNotRPM, magic, LeadMagic)
	}

	if buf[4] < 3 {
		return nil, fmt.Errorf("%w: lead major version %d, want 3 or later", ErrUnsupportedVersion, buf[4])
	}

	return &Lead{
		MajorVersion:  buf[4],
		MinorVersion:  buf[5],
		Type:          binary.BigEndian.Uint16(buf[6:8]),
		Arch:          binary.BigEndian.Uint16(buf[8:10]),
		Name:          strings.TrimRight(string(buf[10:76]), "\x00"),
		OS:            binary.BigEndian.Uint16(buf[76:78]),
		SignatureType: binary.BigEndian.Uint16(buf[78:80]),
	}, nil
}

// Lead returns the lead of the package.
func (hdr *RpmHeader) Lead() *Lead {
	l, err := parseLead(hdr.lead)
	if err != nil {
		// The lead was checked when the header was read.
		return &Lead{}
	}

	return l
}
