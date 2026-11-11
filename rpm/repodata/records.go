package repodata

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/internal/pathseg"
)

// The data types of the records that carry a file this package does not
// interpret, or interprets in another file.
const (
	// RecordAppStream is the AppStream catalog, appstream.xml.
	RecordAppStream = "appstream"
	// RecordAppStreamIcons is the tarball of the icons the catalog names,
	// appstream-icons.tar.
	RecordAppStreamIcons = "appstream-icons"
	// RecordPrestoDelta is prestodelta.xml, see [DeltaInfo].
	RecordPrestoDelta = "prestodelta"
)

// ErrInvalidRecord means the name or type of a record is not usable: the name
// is not a plain file name or the type cannot be derived from it.
var ErrInvalidRecord = errors.New("repodata: invalid repomd.xml record")

// RecordOptions selects how [NewRecord] stores a file in the repository. The
// zero value is what modifyrepo_c does by default: gzip compression, a file
// name with the checksum in front of it, and the current time as timestamp.
type RecordOptions struct {
	// Compression is the compression of the stored file; it is ignored when
	// Store is set.
	Compression Compression
	// Store keeps the file as it is, with no compression: the record has no
	// open-checksum or open-size (modifyrepo_c --no-compress).
	Store bool
	// SimpleNames names the file repodata/<name> instead of
	// repodata/<checksum>-<name> (modifyrepo_c --simple-md-filenames).
	SimpleNames bool
	// Timestamp is the Unix time recorded in repomd.xml. Zero is the current
	// time; pin it for reproducible metadata.
	Timestamp int64
	// MaxSize bounds the decompressed size of an input that arrives
	// compressed; zero selects [DefaultMaxDocument].
	MaxSize int64
}

// MetadataFile is a metadata file ready for the repodata directory: the
// repomd.xml record that describes it and the bytes to store under the
// record's Location.
type MetadataFile struct {
	Record RepomdData
	Data   []byte
}

// NewOpaqueRecord compresses data with comp and returns the repomd.xml record
// of type typ for it together with the file to store, as modifyrepo_c does:
// the file is repodata/<checksum>-<name>.<extension>, the record carries the
// checksum and size of the file and the open-checksum and open-size of data,
// and ts is its timestamp (zero is the current time).
//
// name is the name of the document the record is for, "appstream.xml" for
// example. When it ends in .gz, .xz, .zst or .bz2, data is read as that
// compressed file and decompressed first, and the suffix is not part of the
// name. An empty typ is derived from name, the part before its first dot.
func NewOpaqueRecord(typ, name string, data []byte, comp Compression, ts int64) (RepomdData, []byte, error) {
	return NewRecord(typ, name, data, RecordOptions{Compression: comp, Timestamp: ts})
}

// NewRecord is [NewOpaqueRecord] with the options of modifyrepo_c: storing the
// file uncompressed and naming it without the checksum.
func NewRecord(typ, name string, data []byte, opts RecordOptions) (RepomdData, []byte, error) {
	if !pathseg.Name(name) {
		return RepomdData{}, nil, fmt.Errorf("%w: %q is not a plain file name", ErrInvalidRecord, name)
	}

	doc, base, err := openRecordInput(name, data, opts.MaxSize)
	if err != nil {
		return RepomdData{}, nil, err
	}

	if typ == "" {
		typ, _, _ = strings.Cut(base, ".")
	}

	if typ == "" {
		return RepomdData{}, nil, fmt.Errorf("%w: no type can be derived from %q", ErrInvalidRecord, name)
	}

	ts := opts.Timestamp
	if ts == 0 {
		ts = time.Now().Unix()
	}

	if opts.Store {
		return storeRecord(typ, base, doc, ts, opts.SimpleNames)
	}

	cm, err := CompressMetadataStream(opts.Compression, func(w io.Writer) error {
		_, err := w.Write(doc)

		return err
	})
	if err != nil {
		return RepomdData{}, nil, err
	}

	file := base + opts.Compression.Extension()
	if !opts.SimpleNames {
		file = cm.SHA256 + "-" + file
	}

	return cm.Entry(typ, file, ts), cm.Data, nil
}

func storeRecord(typ, base string, doc []byte, ts int64, simple bool) (RepomdData, []byte, error) {
	if len(doc) == 0 {
		return RepomdData{}, nil, ErrEmptyDocument
	}

	sum := sha256.Sum256(doc)
	hexSum := hex.EncodeToString(sum[:])

	file := base
	if !simple {
		file = hexSum + "-" + file
	}

	return RepomdData{
		Type:         typ,
		Location:     "repodata/" + file,
		Checksum:     hexSum,
		ChecksumType: "sha256",
		Timestamp:    ts,
		Size:         int64(len(doc)),
	}, doc, nil
}

// openRecordInput returns the document an input file holds and the file name
// without a compression suffix.
func openRecordInput(name string, data []byte, maxSize int64) (doc []byte, base string, err error) {
	base = name

	for _, ext := range [...]string{".gz", ".xz", ".zst", ".bz2"} {
		if trimmed, ok := strings.CutSuffix(name, ext); ok {
			base = trimmed

			break
		}
	}

	if base == "" || !pathseg.Name(base) {
		return nil, "", fmt.Errorf("%w: %q is not a plain file name", ErrInvalidRecord, name)
	}

	if base == name {
		return data, base, nil
	}

	rc, err := OpenMetadata(io.NopCloser(bytes.NewReader(data)), name, maxSize)
	if err != nil {
		return nil, "", err
	}

	defer func() { _ = rc.Close() }()

	doc, err = io.ReadAll(rc)
	if err != nil {
		return nil, "", fmt.Errorf("repodata: decompressing %s: %w", name, err)
	}

	return doc, base, nil
}

// AppStream is the AppStream data of a repository: the catalog of the
// components its packages ship and the icons the catalog refers to.
type AppStream struct {
	// Components is the content of appstream.xml; empty to leave the catalog
	// out.
	Components []byte
	// Icons is the content of the icon tarball, appstream-icons.tar
	// (uncompressed); empty to leave the icons out.
	Icons []byte
}

// AppStreamRecords returns the files and records that publish a: the
// "appstream" record for appstream.xml and the "appstream-icons" record for
// appstream-icons.tar, each stored as [NewRecord] does with opts. Register the
// records with [AddRecord] and write the files under the repository root.
func AppStreamRecords(a AppStream, opts RecordOptions) ([]MetadataFile, error) {
	var files []MetadataFile

	for _, part := range [...]struct {
		typ, name string
		data      []byte
	}{
		{RecordAppStream, "appstream.xml", a.Components},
		{RecordAppStreamIcons, "appstream-icons.tar", a.Icons},
	} {
		if len(part.data) == 0 {
			continue
		}

		rec, data, err := NewRecord(part.typ, part.name, part.data, opts)
		if err != nil {
			return nil, err
		}

		files = append(files, MetadataFile{Record: rec, Data: data})
	}

	return files, nil
}

// PrestoDeltaRecord renders info as prestodelta.xml and returns the
// "prestodelta" record and file for it, stored as [NewRecord] does with opts.
func PrestoDeltaRecord(info *DeltaInfo, opts RecordOptions) (RepomdData, []byte, error) {
	var doc bytes.Buffer

	if err := WriteDeltaInfoXML(&doc, info); err != nil {
		return RepomdData{}, nil, err
	}

	return NewRecord(RecordPrestoDelta, "prestodelta.xml", doc.Bytes(), opts)
}

// AddRecord registers rec in m the way modifyrepo_c does: every record of the
// same type is replaced, and the records are then sorted by [Repomd.SortData].
// The file of a record it replaced is not touched; the caller removes it (the
// old record is what [Repomd.Find] returned before the call).
func AddRecord(m *Repomd, rec RepomdData) {
	m.Data = slices.DeleteFunc(m.Data, func(d RepomdData) bool { return d.Type == rec.Type })
	m.Data = append(m.Data, rec)
	m.SortData()
}

// RemoveRecord removes the records of type typ from m as modifyrepo_c
// --remove does, sorts the rest with [Repomd.SortData] and returns what it
// removed, so that the caller can delete the files that are no longer
// referenced. It returns nil when m has no such record.
func RemoveRecord(m *Repomd, typ string) []RepomdData {
	var removed []RepomdData

	m.Data = slices.DeleteFunc(m.Data, func(d RepomdData) bool {
		if d.Type != typ {
			return false
		}

		removed = append(removed, d)

		return true
	})

	m.SortData()

	return removed
}

// SortData orders the data entries of m as createrepo_c does: primary,
// filelists, other, their sqlite databases and then their zchunk files,
// followed by every other record by type and location.
func (m *Repomd) SortData() {
	slices.SortStableFunc(m.Data, func(a, b RepomdData) int {
		return cmp.Or(
			cmp.Compare(recordRank(a.Type), recordRank(b.Type)),
			strings.Compare(a.Type, b.Type),
			strings.Compare(a.Location, b.Location),
		)
	})
}

func recordRank(typ string) int {
	switch typ {
	case "primary":
		return 1
	case "filelists":
		return 2
	case "other":
		return 3
	case "primary_db":
		return 4
	case "filelists_db":
		return 5
	case "other_db":
		return 6
	case "primary_zck":
		return 7
	case "filelists_zck":
		return 8
	case "other_zck":
		return 9
	default:
		return 10
	}
}
