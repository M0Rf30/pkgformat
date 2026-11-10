package repodata

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

const (
	nsRepo = "http://linux.duke.edu/metadata/repo"

	// maxRepomdSize bounds the repomd.xml read from a mirror: a real one is
	// a few kilobytes.
	maxRepomdSize = 4 << 20
	// maxRepomdEntries bounds the data entries of a repomd.xml.
	maxRepomdEntries = 1024
)

// ErrTooLarge means a document or one of its lists exceeds a limit.
var ErrTooLarge = errors.New("repodata: document exceeds a limit")

// RepomdData is one data entry of repomd.xml: a metadata file of the
// repository and how to check it.
type RepomdData struct {
	// Type is the kind of the file: "primary", "filelists", "other",
	// "group", "modules", and so on.
	Type string
	// Location is the path of the file relative to the repository root.
	Location string
	// Checksum is the hex digest of the file and ChecksumType its algorithm,
	// "sha256" for the files this package writes.
	Checksum     string
	ChecksumType string
	// OpenChecksum is the digest of the uncompressed content; optional.
	OpenChecksum     string
	OpenChecksumType string
	// Timestamp is the Unix time the file was generated.
	Timestamp int64
	// Size is the size of the file and OpenSize that of the uncompressed
	// content; OpenSize is optional.
	Size     int64
	OpenSize int64
}

// Repomd is a parsed repomd.xml.
type Repomd struct {
	Revision string
	Data     []RepomdData
}

// Find returns the first data entry of the given type.
func (m *Repomd) Find(dataType string) (RepomdData, bool) {
	for _, d := range m.Data {
		if d.Type == dataType {
			return d, true
		}
	}

	return RepomdData{}, false
}

type repomdXML struct {
	XMLName  xml.Name        `xml:"repomd"`
	Xmlns    string          `xml:"xmlns,attr"`
	XmlnsRpm string          `xml:"xmlns:rpm,attr"`
	Revision string          `xml:"revision"`
	Data     []repomdDataXML `xml:"data"`
}

type repomdDataXML struct {
	XMLName      xml.Name     `xml:"data"`
	Type         string       `xml:"type,attr"`
	Location     locationXML  `xml:"location"`
	Checksum     checksumXML  `xml:"checksum"`
	OpenChecksum *checksumXML `xml:"open-checksum,omitempty"`
	Timestamp    int64        `xml:"timestamp"`
	Size         int64        `xml:"size"`
	OpenSize     int64        `xml:"open-size,omitempty"`
}

type locationXML struct {
	Href string `xml:"href,attr"`
}

type checksumXML struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

// GenerateRepomdXML renders repomd.xml for entries. An empty revision becomes
// the current Unix time.
func GenerateRepomdXML(revision string, entries []RepomdData) ([]byte, error) {
	dataEntries := make([]repomdDataXML, len(entries))
	for i, e := range entries {
		dataEntries[i] = repomdDataXML{
			Type:      e.Type,
			Location:  locationXML{Href: e.Location},
			Checksum:  checksumXML{Type: e.ChecksumType, Value: e.Checksum},
			Timestamp: e.Timestamp,
			Size:      e.Size,
			OpenSize:  e.OpenSize,
		}

		if e.OpenChecksum != "" {
			dataEntries[i].OpenChecksum = &checksumXML{Type: e.OpenChecksumType, Value: e.OpenChecksum}
		}
	}

	if revision == "" {
		revision = strconv.FormatInt(time.Now().Unix(), 10)
	}

	repomd := repomdXML{
		Xmlns:    nsRepo,
		XmlnsRpm: nsRPM,
		Revision: revision,
		Data:     dataEntries,
	}

	output, err := xml.MarshalIndent(repomd, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("repodata: marshaling repomd.xml: %w", err)
	}

	return append([]byte(xml.Header), output...), nil
}

// ParseRepomd parses a repomd.xml. The document is bounded to a few megabytes
// and a thousand data entries; a larger one fails with [ErrTooLarge].
func ParseRepomd(r io.Reader) (*Repomd, error) {
	var doc repomdXML

	if err := xml.NewDecoder(limitio.Capped(r, maxRepomdSize+1, ErrTooLarge)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("repodata: parsing repomd.xml: %w", err)
	}

	if len(doc.Data) > maxRepomdEntries {
		return nil, fmt.Errorf("%w: %d repomd.xml data entries, at most %d", ErrTooLarge, len(doc.Data), maxRepomdEntries)
	}

	out := &Repomd{Revision: doc.Revision, Data: make([]RepomdData, 0, len(doc.Data))}

	for _, d := range doc.Data {
		e := RepomdData{
			Type:         d.Type,
			Location:     d.Location.Href,
			Checksum:     d.Checksum.Value,
			ChecksumType: d.Checksum.Type,
			Timestamp:    d.Timestamp,
			Size:         d.Size,
			OpenSize:     d.OpenSize,
		}

		if d.OpenChecksum != nil {
			e.OpenChecksum, e.OpenChecksumType = d.OpenChecksum.Value, d.OpenChecksum.Type
		}

		out.Data = append(out.Data, e)
	}

	return out, nil
}
