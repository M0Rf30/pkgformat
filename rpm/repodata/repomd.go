package repodata

import (
	"bytes"
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
	// HeaderChecksum is the digest of the header of a zchunk file and
	// HeaderSize the length of that header; both are empty for any other
	// kind of file.
	HeaderChecksum     string
	HeaderChecksumType string
	HeaderSize         int64
	// Timestamp is the Unix time the file was generated.
	Timestamp int64
	// Size is the size of the file and OpenSize that of the uncompressed
	// content; OpenSize is optional.
	Size     int64
	OpenSize int64
	// DatabaseVersion is the schema version of a SQLite database
	// ([DatabaseVersion] for the ones this package writes); zero for any
	// other kind of file.
	DatabaseVersion int
}

// DistroTag is a <distro> tag of repomd.xml: the name of a distribution and
// the CPE identifiers that designate it.
type DistroTag struct {
	// CPEID is the cpeid attribute; optional.
	CPEID string
	Name  string
}

// Repomd is a repomd.xml: the index of the metadata files of a repository.
type Repomd struct {
	// Revision identifies the state of the repository; the current Unix time
	// when empty at [Repomd.Marshal].
	Revision string
	// Content, Repo and Distro are the <tags> of the repository: what it
	// contains, what it is, and the distributions it is for.
	Content []string
	Repo    []string
	Distro  []DistroTag
	Data    []RepomdData
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

// DatabaseVersion is the schema version of the SQLite databases createrepo_c
// and this package write.
const DatabaseVersion = 10

// The decoding view of repomd.xml.
type repomdXML struct {
	Revision string          `xml:"revision"`
	Tags     repomdTagsXML   `xml:"tags"`
	Data     []repomdDataXML `xml:"data"`
}

type repomdTagsXML struct {
	Content []string        `xml:"content"`
	Repo    []string        `xml:"repo"`
	Distro  []repomdDistroX `xml:"distro"`
}

type repomdDistroX struct {
	CPEID string `xml:"cpeid,attr"`
	Name  string `xml:",chardata"`
}

type repomdDataXML struct {
	Type           string       `xml:"type,attr"`
	Checksum       checksumXML  `xml:"checksum"`
	OpenChecksum   *checksumXML `xml:"open-checksum"`
	HeaderChecksum *checksumXML `xml:"header-checksum"`
	Location       locationXML  `xml:"location"`
	Timestamp      int64        `xml:"timestamp"`
	Size           int64        `xml:"size"`
	OpenSize       int64        `xml:"open-size"`
	HeaderSize     int64        `xml:"header-size"`
	DatabaseVer    int          `xml:"database_version"`
}

type locationXML struct {
	Href string `xml:"href,attr"`
}

type checksumXML struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

// GenerateRepomdXML renders repomd.xml for entries. An empty revision becomes
// the current Unix time. It is [Repomd.Marshal] for a repository without tags.
func GenerateRepomdXML(revision string, entries []RepomdData) ([]byte, error) {
	return (&Repomd{Revision: revision, Data: entries}).Marshal()
}

// Marshal renders m as repomd.xml exactly as createrepo_c does: revision,
// tags, then the data entries, each with its checksum, open-checksum,
// header-checksum, location, timestamp, size, open-size, header-size and
// database_version; an element without a value is left out.
func (m *Repomd) Marshal() ([]byte, error) {
	revision := m.Revision
	if revision == "" {
		revision = strconv.FormatInt(time.Now().Unix(), 10)
	}

	var buf bytes.Buffer

	o := newXMLOut(&buf)
	o.raw(xmlHeader)
	o.raw(`<repomd xmlns="` + nsRepo + `" xmlns:rpm="` + nsRPM + `">`)
	o.elem("  ", "revision", revision)

	if len(m.Content)+len(m.Repo)+len(m.Distro) > 0 {
		o.raw("\n  <tags>")

		for _, c := range m.Content {
			o.elem("    ", "content", c)
		}

		for _, r := range m.Repo {
			o.elem("    ", "repo", r)
		}

		for _, d := range m.Distro {
			o.open("    ", "distro")
			o.optAttr("cpeid", d.CPEID)
			o.raw(">")
			o.text(d.Name)
			o.closeTag("distro")
		}

		o.raw("\n  </tags>")
	}

	for i := range m.Data {
		writeRepomdData(o, &m.Data[i])
	}

	o.raw("\n</repomd>\n")

	if err := o.finish(); err != nil {
		return nil, fmt.Errorf("repodata: marshaling repomd.xml: %w", err)
	}

	return buf.Bytes(), nil
}

func writeRepomdData(o *xmlOut, e *RepomdData) {
	o.open("  ", "data")
	o.attr("type", e.Type)
	o.raw(">")

	checksum := func(tag, typ, value string) {
		o.open("    ", tag)
		o.attr("type", typ)
		o.raw(">")
		o.text(value)
		o.closeTag(tag)
	}

	checksum("checksum", e.ChecksumType, e.Checksum)

	if e.OpenChecksum != "" {
		checksum("open-checksum", e.OpenChecksumType, e.OpenChecksum)
	}

	if e.HeaderChecksum != "" {
		checksum("header-checksum", e.HeaderChecksumType, e.HeaderChecksum)
	}

	o.open("    ", "location")
	o.attr("href", e.Location)
	o.selfClose()

	number := func(tag string, v int64, always bool) {
		if v == 0 && !always {
			return
		}

		o.open("    ", tag)
		o.raw(">")
		o.i64(v)
		o.closeTag(tag)
	}

	number("timestamp", e.Timestamp, true)
	number("size", e.Size, true)
	number("open-size", e.OpenSize, false)
	number("header-size", e.HeaderSize, false)
	number("database_version", int64(e.DatabaseVersion), false)

	o.raw("\n  </data>")
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

	out.Content, out.Repo = doc.Tags.Content, doc.Tags.Repo

	for _, d := range doc.Tags.Distro {
		out.Distro = append(out.Distro, DistroTag{CPEID: d.CPEID, Name: d.Name})
	}

	for _, d := range doc.Data {
		e := RepomdData{
			Type:            d.Type,
			Location:        d.Location.Href,
			Checksum:        d.Checksum.Value,
			ChecksumType:    d.Checksum.Type,
			Timestamp:       d.Timestamp,
			Size:            d.Size,
			OpenSize:        d.OpenSize,
			HeaderSize:      d.HeaderSize,
			DatabaseVersion: d.DatabaseVer,
		}

		if d.OpenChecksum != nil {
			e.OpenChecksum, e.OpenChecksumType = d.OpenChecksum.Value, d.OpenChecksum.Type
		}

		if d.HeaderChecksum != nil {
			e.HeaderChecksum, e.HeaderChecksumType = d.HeaderChecksum.Value, d.HeaderChecksum.Type
		}

		out.Data = append(out.Data, e)
	}

	return out, nil
}
