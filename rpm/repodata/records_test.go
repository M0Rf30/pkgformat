package repodata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func recordsPath(parts ...string) string {
	return filepath.Join(append([]string{"testdata", "records"}, parts...)...)
}

func recordsInput(t testing.TB, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(recordsPath("inputs", name))
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

// openedDocument decompresses file as OpenMetadata does for a client.
func openedDocument(t testing.TB, name string, file []byte) []byte {
	t.Helper()

	rc, err := OpenMetadata(io.NopCloser(bytes.NewReader(file)), name, 0)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = rc.Close() }()

	doc, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}

	return doc
}

func TestNewOpaqueRecord(t *testing.T) {
	doc := recordsInput(t, "appstream.xml")

	for _, comp := range []Compression{Gzip, Zstd, XZ} {
		t.Run(comp.String(), func(t *testing.T) {
			rec, file, err := NewOpaqueRecord("appstream", "appstream.xml", doc, comp, 1700000042)
			if err != nil {
				t.Fatal(err)
			}

			name := rec.Checksum + "-appstream.xml" + comp.Extension()
			want := RepomdData{
				Type: "appstream", Location: "repodata/" + name,
				Checksum: hexSHA256(file), ChecksumType: "sha256",
				OpenChecksum: hexSHA256(doc), OpenChecksumType: "sha256",
				Timestamp: 1700000042, Size: int64(len(file)), OpenSize: int64(len(doc)),
			}
			if rec != want {
				t.Fatalf("record = %+v\nwant     %+v", rec, want)
			}

			if got := openedDocument(t, name, file); !bytes.Equal(got, doc) {
				t.Fatal("the stored file does not decompress to the document")
			}
		})
	}
}

func TestNewRecordOptions(t *testing.T) {
	doc := recordsInput(t, "appstream.xml")
	sum := hexSHA256(doc)

	t.Run("store", func(t *testing.T) {
		rec, file, err := NewRecord("appstream", "appstream.xml", doc, RecordOptions{Store: true, Timestamp: 5, Compression: XZ})
		if err != nil {
			t.Fatal(err)
		}

		want := RepomdData{
			Type: "appstream", Location: "repodata/" + sum + "-appstream.xml", Checksum: sum, ChecksumType: "sha256",
			Timestamp: 5, Size: int64(len(doc)),
		}
		if rec != want || !bytes.Equal(file, doc) {
			t.Fatalf("record = %+v, want %+v", rec, want)
		}
	})

	t.Run("simple names", func(t *testing.T) {
		rec, _, err := NewRecord("appstream", "appstream.xml", doc, RecordOptions{SimpleNames: true, Timestamp: 5, Compression: Zstd})
		if err != nil || rec.Location != "repodata/appstream.xml.zst" {
			t.Fatalf("record = %+v (%v)", rec, err)
		}

		rec, _, err = NewRecord("appstream", "appstream.xml", doc, RecordOptions{Store: true, SimpleNames: true, Timestamp: 5})
		if err != nil || rec.Location != "repodata/appstream.xml" {
			t.Fatalf("stored record = %+v (%v)", rec, err)
		}
	})

	t.Run("derived type", func(t *testing.T) {
		for name, want := range map[string]string{
			"appstream.xml": "appstream", "appstream-icons.tar": "appstream-icons", "prestodelta.xml.gz": "prestodelta", "x.y.z": "x",
		} {
			data := doc
			if strings.HasSuffix(name, ".gz") {
				data = gzipped(t, doc)
			}

			rec, _, err := NewRecord("", name, data, RecordOptions{Timestamp: 1})
			if err != nil || rec.Type != want {
				t.Fatalf("%s: type = %q (%v), want %q", name, rec.Type, err, want)
			}
		}
	})

	t.Run("timestamp defaults to now", func(t *testing.T) {
		before := time.Now().Unix()

		rec, _, err := NewRecord("t", "t.xml", doc, RecordOptions{})
		if err != nil || rec.Timestamp < before || rec.Timestamp > time.Now().Unix() {
			t.Fatalf("timestamp = %d (%v), want about %d", rec.Timestamp, err, before)
		}
	})

	t.Run("compressed input", func(t *testing.T) {
		// A file that arrives compressed, whatever the format, is the same
		// document once opened, and is named without the suffix.
		want, _, err := NewRecord("appstream", "appstream.xml", doc, RecordOptions{Timestamp: 1})
		if err != nil {
			t.Fatal(err)
		}

		for _, comp := range []Compression{Gzip, Zstd, XZ} {
			cm, err := CompressMetadataStream(comp, func(w io.Writer) error { _, err := w.Write(doc); return err })
			if err != nil {
				t.Fatal(err)
			}

			rec, _, err := NewRecord("", "appstream.xml"+comp.Extension(), cm.Data, RecordOptions{Timestamp: 1})
			if err != nil {
				t.Fatal(err)
			}

			if rec != want {
				t.Fatalf("%s input: record = %+v, want %+v", comp, rec, want)
			}
		}
	})
}

func TestNewRecordErrors(t *testing.T) {
	doc := []byte("<x/>")

	for name, tc := range map[string]struct {
		typ, name string
		data      []byte
		opts      RecordOptions
		want      error
	}{
		"empty name":     {"t", "", doc, RecordOptions{}, ErrInvalidRecord},
		"path":           {"t", "a/b.xml", doc, RecordOptions{}, ErrInvalidRecord},
		"dotdot":         {"t", "..", doc, RecordOptions{}, ErrInvalidRecord},
		"backslash":      {"t", `a\b.xml`, doc, RecordOptions{}, ErrInvalidRecord},
		"only suffix":    {"t", ".gz", doc, RecordOptions{}, ErrInvalidRecord},
		"no type":        {"", ".xml", doc, RecordOptions{}, ErrInvalidRecord},
		"empty document": {"t", "t.xml", nil, RecordOptions{}, ErrEmptyDocument},
		"empty stored":   {"t", "t.xml", nil, RecordOptions{Store: true}, ErrEmptyDocument},
		"bad gzip":       {"t", "t.xml.gz", doc, RecordOptions{}, nil},
		"bad zstd":       {"t", "t.xml.zst", doc, RecordOptions{}, nil},
		"bad xz":         {"t", "t.xml.xz", doc, RecordOptions{}, nil},
		"too large":      {"t", "t.xml.gz", gzipped(t, bytes.Repeat([]byte("a"), 1000)), RecordOptions{MaxSize: 100}, ErrTooLarge},
		"unknown":        {"t", "t.xml", doc, RecordOptions{Compression: Compression(42)}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := NewRecord(tc.typ, tc.name, tc.data, tc.opts)
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func gzipped(t testing.TB, doc []byte) []byte {
	t.Helper()

	cm, err := CompressMetadataStream(Gzip, func(w io.Writer) error { _, err := w.Write(doc); return err })
	if err != nil {
		t.Fatal(err)
	}

	return cm.Data
}

func TestAddAndRemoveRecord(t *testing.T) {
	rec := func(typ, loc string) RepomdData { return RepomdData{Type: typ, Location: loc, Checksum: loc} }

	m := &Repomd{Revision: "7", Data: []RepomdData{
		rec("other", "o"), rec("zzz", "z1"), rec("primary", "p"), rec("filelists", "f"), rec("zzz", "z0"), rec("modules", "m"),
	}}

	AddRecord(m, rec("appstream", "a"))

	var types []string
	for _, d := range m.Data {
		types = append(types, d.Type+":"+d.Location)
	}

	// The base documents in their order, then the rest by type and location;
	// the two "zzz" records, added by hand in the wrong order, are sorted.
	if want := []string{"primary:p", "filelists:f", "other:o", "appstream:a", "modules:m", "zzz:z0", "zzz:z1"}; !reflect.DeepEqual(types, want) {
		t.Fatalf("order = %v, want %v", types, want)
	}

	// An added record replaces every record of its type.
	AddRecord(m, rec("zzz", "z2"))

	if got, _ := m.Find("zzz"); got.Location != "z2" || len(m.Data) != 6 || m.Revision != "7" {
		t.Fatalf("after replacing: %+v (revision %q)", m.Data, m.Revision)
	}

	removed := RemoveRecord(m, "appstream")
	if len(removed) != 1 || removed[0].Location != "a" || len(m.Data) != 5 {
		t.Fatalf("removed %+v, left %+v", removed, m.Data)
	}

	if _, ok := m.Find("appstream"); ok {
		t.Fatal("the record is still there")
	}

	if got := RemoveRecord(m, "appstream"); got != nil || len(m.Data) != 5 {
		t.Fatalf("removing a missing record returned %+v", got)
	}
}

func TestSortDataRanks(t *testing.T) {
	var m Repomd

	for _, typ := range []string{"z", "other_zck", "a", "filelists_zck", "primary_zck", "other_db", "filelists_db", "primary_db", "other", "filelists", "primary"} {
		m.Data = append(m.Data, RepomdData{Type: typ})
	}

	m.SortData()

	var got []string
	for _, d := range m.Data {
		got = append(got, d.Type)
	}

	want := []string{
		"primary", "filelists", "other", "primary_db", "filelists_db", "other_db",
		"primary_zck", "filelists_zck", "other_zck", "a", "z",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestAppStreamRecords(t *testing.T) {
	a := AppStream{Components: recordsInput(t, "appstream.xml"), Icons: recordsInput(t, "appstream-icons.tar")}

	files, err := AppStreamRecords(a, RecordOptions{Timestamp: 9})
	if err != nil {
		t.Fatal(err)
	}

	if len(files) != 2 || files[0].Record.Type != "appstream" || files[1].Record.Type != "appstream-icons" {
		t.Fatalf("files = %+v", files)
	}

	for i, want := range [][]byte{a.Components, a.Icons} {
		f := files[i]
		if f.Record.OpenChecksum != hexSHA256(want) || f.Record.Checksum != hexSHA256(f.Data) || f.Record.Timestamp != 9 {
			t.Fatalf("record %d = %+v", i, f.Record)
		}

		if got := openedDocument(t, f.Record.Location, f.Data); !bytes.Equal(got, want) {
			t.Fatalf("file %d does not decompress to its input", i)
		}
	}

	if !strings.HasSuffix(files[0].Record.Location, "-appstream.xml.gz") || !strings.HasSuffix(files[1].Record.Location, "-appstream-icons.tar.gz") {
		t.Fatalf("locations %q, %q", files[0].Record.Location, files[1].Record.Location)
	}

	only, err := AppStreamRecords(AppStream{Icons: a.Icons}, RecordOptions{Timestamp: 9, Compression: Zstd})
	if err != nil || len(only) != 1 || only[0].Record.Type != "appstream-icons" || !strings.HasSuffix(only[0].Record.Location, ".tar.zst") {
		t.Fatalf("icons only: %+v (%v)", only, err)
	}

	none, err := AppStreamRecords(AppStream{}, RecordOptions{})
	if err != nil || len(none) != 0 {
		t.Fatalf("nothing: %+v (%v)", none, err)
	}

	if _, err := AppStreamRecords(a, RecordOptions{Compression: Compression(9)}); err == nil {
		t.Fatal("an unknown compression was accepted")
	}
}

func TestPrestoDeltaRecord(t *testing.T) {
	rec, file, err := PrestoDeltaRecord(fixtureDeltaInfo, RecordOptions{Timestamp: 3, Store: true, SimpleNames: true})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(file, deltaFixtureBytes(t, "prestodelta.xml")) || rec.Type != "prestodelta" || rec.Location != "repodata/prestodelta.xml" ||
		rec.Checksum != hexSHA256(file) {
		t.Fatalf("record = %+v", rec)
	}

	if _, _, err := PrestoDeltaRecord(&DeltaInfo{NewPackages: []DeltaPackage{{}}}, RecordOptions{}); !errors.Is(err, ErrMalformedDeltaInfo) {
		t.Fatalf("invalid info: err = %v", err)
	}
}

// addCase is one modifyrepo_c invocation that adds a file: the input, the
// options of the helper that match the command line, and the fixture
// directory holding the result of the real tool.
type addCase struct {
	fixture string
	input   string
	typ     string
	opts    RecordOptions
	args    []string
}

var addCases = []addCase{
	{"add-store", "appstream.xml", "", RecordOptions{Store: true}, []string{"--no-compress"}},
	{"add-store-simple", "appstream.xml", "", RecordOptions{Store: true, SimpleNames: true}, []string{"--no-compress", "--simple-md-filenames"}},
	{"add-gz", "appstream.xml", "", RecordOptions{Compression: Gzip}, []string{"--compress-type", "gz"}},
	{"add-zst", "appstream.xml", "", RecordOptions{Compression: Zstd}, []string{"--compress-type", "zstd"}},
	{"add-xz", "appstream.xml", "", RecordOptions{Compression: XZ}, []string{"--compress-type", "xz"}},
	{"add-from-gz", "appstream.xml.gz", "", RecordOptions{Compression: Gzip}, []string{"--compress-type", "gz"}},
	{"add-icons", "appstream-icons.tar", "appstream-icons", RecordOptions{Compression: Gzip}, []string{"--compress-type", "gz", "--mdtype", "appstream-icons"}},
	{"add-prestodelta", "prestodelta.xml", "", RecordOptions{Compression: Gzip}, []string{"--compress-type", "gz"}},
}

// The operations of the fixtures "all", "replace" and "remove".
var (
	chainCases = []addCase{addCases[2], addCases[6], addCases[7]}
	replaceAdd = addCase{"replace", "appstream-replacement.xml", "appstream", RecordOptions{Compression: Gzip}, []string{"--compress-type", "gz", "--mdtype", "appstream"}}
)

func (c addCase) recordType() string {
	if c.typ != "" {
		return c.typ
	}

	typ, _, _ := strings.Cut(c.input, ".")

	return typ
}

func parseRepomdFile(t testing.TB, path string) (*Repomd, []byte) {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	m, err := ParseRepomd(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	return m, raw
}

// ourRecord makes the record the helper produces for the case and compares it
// with the one modifyrepo_c wrote (want, whose files are under filesDir). All
// that does not depend on the compressor must be equal: type, algorithms,
// open-checksum, open-size, timestamp and the shape of the location. The
// checksum and size of a compressed file differ between compressors; there the
// check is that both files are valid and hold the same document. The returned
// record carries want's checksum, size and location when the file is
// compressed, so that the whole repomd.xml can be compared.
func ourRecord(t testing.TB, c addCase, want RepomdData, filesDir string) RepomdData {
	t.Helper()

	input := recordsInput(t, c.input)
	opts := c.opts
	opts.Timestamp = want.Timestamp

	rec, data, err := NewRecord(c.typ, c.input, input, opts)
	if err != nil {
		t.Fatal(err)
	}

	if rec.Type != want.Type || rec.ChecksumType != want.ChecksumType || rec.OpenChecksum != want.OpenChecksum ||
		rec.OpenChecksumType != want.OpenChecksumType || rec.OpenSize != want.OpenSize || rec.Timestamp != want.Timestamp {
		t.Fatalf("%s: record = %+v\nmodifyrepo_c: %+v", c.input, rec, want)
	}

	// The location is the same with the checksum of the respective file.
	if loc := strings.ReplaceAll(want.Location, want.Checksum, rec.Checksum); loc != rec.Location {
		t.Fatalf("%s: location %q, modifyrepo_c %q", c.input, rec.Location, want.Location)
	}

	// An input that is already compressed stands for its content.
	content := input
	if strings.HasSuffix(c.input, ".gz") {
		content = openedDocument(t, c.input, input)
	}

	if got := openedDocument(t, rec.Location, data); !bytes.Equal(got, content) {
		t.Fatalf("%s: our file does not hold the input", c.input)
	}

	file, err := os.ReadFile(filepath.Join(filesDir, filepath.FromSlash(want.Location)))
	if err != nil {
		t.Fatal(err)
	}

	if hexSHA256(file) != want.Checksum || int64(len(file)) != want.Size {
		t.Fatalf("%s: modifyrepo_c file has sha256 %s and size %d, its record says %s and %d",
			c.input, hexSHA256(file), len(file), want.Checksum, want.Size)
	}

	if got := openedDocument(t, want.Location, file); !bytes.Equal(got, content) {
		t.Fatalf("%s: modifyrepo_c file does not hold the input", c.input)
	}

	if c.opts.Store {
		if rec != want {
			t.Fatalf("%s: stored record = %+v\nmodifyrepo_c: %+v", c.input, rec, want)
		}

		return rec
	}

	rec.Checksum, rec.Size, rec.Location = want.Checksum, want.Size, want.Location

	if rec != want {
		t.Fatalf("%s: record = %+v\nmodifyrepo_c: %+v", c.input, rec, want)
	}

	return rec
}

func marshalRepomd(t testing.TB, m *Repomd) []byte {
	t.Helper()

	out, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	return out
}

func equalDocuments(t testing.TB, what string, got, want []byte) {
	t.Helper()

	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs at byte %d:\n%s", what, firstStringDiff(string(got), string(want)), context(string(got), string(want)))
	}
}

// TestRecordsMatchModifyrepoFixtures replays, offline, what modifyrepo_c did
// to the repository of testdata/records (generate.sh): adding a file stored,
// compressed three ways and from an already compressed input, replacing a
// record and removing one. Registering the same files with the helpers
// yields the repomd.xml modifyrepo_c wrote, byte for byte.
func TestRecordsMatchModifyrepoFixtures(t *testing.T) {
	base, _ := parseRepomdFile(t, recordsPath("base", "repodata", "repomd.xml"))

	for _, c := range addCases {
		t.Run(c.fixture, func(t *testing.T) {
			m := cloneRepomd(base)
			want, raw := parseRepomdFile(t, recordsPath(c.fixture, "repodata", "repomd.xml"))

			rec, ok := want.Find(c.recordType())
			if !ok {
				t.Fatalf("fixture has no %q record", c.recordType())
			}

			AddRecord(m, ourRecord(t, c, rec, recordsPath(c.fixture)))
			equalDocuments(t, "repomd.xml", marshalRepomd(t, m), raw)
		})
	}

	t.Run("all", func(t *testing.T) {
		m := cloneRepomd(base)
		want, raw := parseRepomdFile(t, recordsPath("all", "repodata", "repomd.xml"))

		for _, c := range chainCases {
			rec, _ := want.Find(c.recordType())
			AddRecord(m, ourRecord(t, c, rec, recordsPath("all")))
		}

		equalDocuments(t, "repomd.xml", marshalRepomd(t, m), raw)
	})

	t.Run("replace", func(t *testing.T) {
		m, _ := parseRepomdFile(t, recordsPath("all", "repodata", "repomd.xml"))
		want, raw := parseRepomdFile(t, recordsPath("replace", "repodata", "repomd.xml"))

		rec, _ := want.Find("appstream")
		AddRecord(m, ourRecord(t, replaceAdd, rec, recordsPath("replace")))
		equalDocuments(t, "repomd.xml", marshalRepomd(t, m), raw)
	})

	t.Run("remove", func(t *testing.T) {
		m, _ := parseRepomdFile(t, recordsPath("all", "repodata", "repomd.xml"))
		_, raw := parseRepomdFile(t, recordsPath("remove", "repodata", "repomd.xml"))
		before, _ := m.Find("appstream")

		removed := RemoveRecord(m, "appstream")
		if len(removed) != 1 || removed[0] != before {
			t.Fatalf("removed %+v, want %+v", removed, before)
		}

		equalDocuments(t, "repomd.xml", marshalRepomd(t, m), raw)

		// modifyrepo_c deleted the file of the record it removed.
		if _, err := os.Stat(recordsPath("remove", filepath.FromSlash(before.Location))); !os.IsNotExist(err) {
			t.Fatalf("the file of the removed record exists in the fixture: %v", err)
		}
	})
}

func cloneRepomd(m *Repomd) *Repomd {
	cp := *m
	cp.Data = append([]RepomdData(nil), m.Data...)

	return &cp
}

// runModifyrepo runs modifyrepo_c with args on the repodata directory.
func runModifyrepo(t *testing.T, repodata string, args ...string) {
	t.Helper()

	out, err := exec.Command("modifyrepo_c", append(args, repodata)...).CombinedOutput()
	if err != nil {
		t.Fatalf("modifyrepo_c %v: %v\n%s", args, err, out)
	}
}

func copyRepodata(t *testing.T, from, to string) {
	t.Helper()

	if err := os.MkdirAll(to, 0o755); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}

	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(to, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRecordsMatchModifyrepo runs modifyrepo_c itself, with the timestamps it
// chooses, and compares its repomd.xml with the one the helpers produce.
func TestRecordsMatchModifyrepo(t *testing.T) {
	if _, err := exec.LookPath("modifyrepo_c"); err != nil {
		t.Skip("modifyrepo_c is not installed")
	}

	inputPath := func(name string) string {
		abs, err := filepath.Abs(recordsPath("inputs", name))
		if err != nil {
			t.Fatal(err)
		}

		return abs
	}

	base, _ := parseRepomdFile(t, recordsPath("base", "repodata", "repomd.xml"))

	for _, c := range addCases {
		t.Run(c.fixture, func(t *testing.T) {
			dir := t.TempDir()
			copyRepodata(t, recordsPath("base", "repodata"), filepath.Join(dir, "repodata"))
			runModifyrepo(t, filepath.Join(dir, "repodata"), append(append([]string{}, c.args...), inputPath(c.input))...)

			m := cloneRepomd(base)
			want, raw := parseRepomdFile(t, filepath.Join(dir, "repodata", "repomd.xml"))

			rec, ok := want.Find(c.recordType())
			if !ok {
				t.Fatalf("modifyrepo_c wrote no %q record", c.recordType())
			}

			AddRecord(m, ourRecord(t, c, rec, dir))
			equalDocuments(t, "repomd.xml", marshalRepomd(t, m), raw)
		})
	}

	t.Run("chain", func(t *testing.T) {
		dir := t.TempDir()
		repodata := filepath.Join(dir, "repodata")
		copyRepodata(t, recordsPath("base", "repodata"), repodata)

		m := cloneRepomd(base)

		step := func(c addCase) {
			runModifyrepo(t, repodata, append(append([]string{}, c.args...), inputPath(c.input))...)

			want, raw := parseRepomdFile(t, filepath.Join(repodata, "repomd.xml"))
			rec, _ := want.Find(c.recordType())

			AddRecord(m, ourRecord(t, c, rec, dir))
			equalDocuments(t, "repomd.xml", marshalRepomd(t, m), raw)
		}

		for _, c := range chainCases {
			step(c)
		}

		old, _ := m.Find("appstream")

		step(replaceAdd)

		// modifyrepo_c deleted the file the replaced record named, which is
		// the one the helper's caller learns of from Find before AddRecord.
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(old.Location))); !os.IsNotExist(err) {
			t.Fatalf("the replaced file is still there: %v", err)
		}

		runModifyrepo(t, repodata, "--remove", "appstream-icons")

		want, raw := parseRepomdFile(t, filepath.Join(repodata, "repomd.xml"))
		before, _ := m.Find("appstream-icons")

		removed := RemoveRecord(m, "appstream-icons")
		if len(removed) != 1 || removed[0] != before {
			t.Fatalf("removed %+v, want %+v", removed, before)
		}

		equalDocuments(t, "repomd.xml", marshalRepomd(t, m), raw)

		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(before.Location))); !os.IsNotExist(err) {
			t.Fatalf("the file of the removed record is still there: %v", err)
		}

		if _, ok := want.Find("appstream-icons"); ok {
			t.Fatal("modifyrepo_c left the record")
		}
	})

	// modifyrepo_c --mdtype prestodelta takes the document this package
	// writes and registers it.
	t.Run("deltainfo", func(t *testing.T) {
		dir := t.TempDir()
		repodata := filepath.Join(dir, "repodata")
		copyRepodata(t, recordsPath("base", "repodata"), repodata)

		doc := filepath.Join(dir, "deltainfo.xml")

		var buf bytes.Buffer
		if err := WriteDeltaInfoXML(&buf, fixtureDeltaInfo); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(doc, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}

		runModifyrepo(t, repodata, "--mdtype", "prestodelta", "--compress-type", "gz", doc)

		m, _ := parseRepomdFile(t, filepath.Join(repodata, "repomd.xml"))

		rec, ok := m.Find("prestodelta")
		if !ok || rec.OpenChecksum != hexSHA256(buf.Bytes()) {
			t.Fatalf("record = %+v (found %v)", rec, ok)
		}

		file, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rec.Location)))
		if err != nil {
			t.Fatal(err)
		}

		got, err := ParseDeltaInfo(bytes.NewReader(openedDocument(t, rec.Location, file)), DeltaInfoLimits{})
		if err != nil || !reflect.DeepEqual(got, fixtureDeltaInfo) {
			t.Fatalf("the registered document reads as %+v (%v)", got, err)
		}
	})
}

// TestRepomdWithRecordsIsReadByModifyrepo has modifyrepo_c parse a repomd.xml
// this package wrote after AddRecord and operate on it.
func TestRepomdWithRecordsIsReadByModifyrepo(t *testing.T) {
	if _, err := exec.LookPath("modifyrepo_c"); err != nil {
		t.Skip("modifyrepo_c is not installed")
	}

	dir := t.TempDir()
	repodata := filepath.Join(dir, "repodata")
	copyRepodata(t, recordsPath("base", "repodata"), repodata)

	m, _ := parseRepomdFile(t, filepath.Join(repodata, "repomd.xml"))

	files, err := AppStreamRecords(AppStream{Components: recordsInput(t, "appstream.xml"), Icons: recordsInput(t, "appstream-icons.tar")}, RecordOptions{Timestamp: 1700000001})
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range files {
		AddRecord(m, f.Record)

		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(f.Record.Location)), f.Data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(filepath.Join(repodata, "repomd.xml"), marshalRepomd(t, m), 0o644); err != nil {
		t.Fatal(err)
	}

	runModifyrepo(t, repodata, "--remove", "appstream")

	after, _ := parseRepomdFile(t, filepath.Join(repodata, "repomd.xml"))
	if _, ok := after.Find("appstream"); ok {
		t.Fatal("modifyrepo_c did not remove the record it read")
	}

	if _, ok := after.Find("appstream-icons"); !ok {
		t.Fatal("modifyrepo_c dropped a record it was not asked to")
	}

	// Its own parser keeps the record and its file when the other one goes.
	icons, _ := after.Find("appstream-icons")
	if icons != files[1].Record {
		t.Fatalf("icons record = %+v, wrote %+v", icons, files[1].Record)
	}

	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(files[0].Record.Location))); !os.IsNotExist(err) {
		t.Fatalf("modifyrepo_c did not delete the removed file: %v", err)
	}
}

func FuzzNewRecord(f *testing.F) {
	f.Add("appstream", "appstream.xml", []byte("<c/>"), uint8(0), false, false)
	f.Add("", "x.tar.gz", gzipped(f, []byte("data")), uint8(1), true, false)
	f.Add("t", "t.xml.zst", []byte{0x28, 0xb5, 0x2f, 0xfd}, uint8(2), false, true)
	f.Add("", "../x", []byte("a"), uint8(0), false, false)

	f.Fuzz(func(t *testing.T, typ, name string, data []byte, comp uint8, store, simple bool) {
		opts := RecordOptions{Compression: Compression(comp % 3), Store: store, SimpleNames: simple, Timestamp: 1, MaxSize: 1 << 16}

		rec, file, err := NewRecord(typ, name, data, opts)
		if err != nil {
			return
		}

		if rec.Type == "" || !strings.HasPrefix(rec.Location, "repodata/") || strings.Contains(rec.Location[len("repodata/"):], "/") ||
			rec.Checksum != hexSHA256(file) || rec.Size != int64(len(file)) {
			t.Fatalf("inconsistent record %+v for %q", rec, name)
		}

		// A record registers and unregisters.
		m := &Repomd{}
		AddRecord(m, rec)

		if got, ok := m.Find(rec.Type); !ok || got != rec {
			t.Fatalf("AddRecord lost the record")
		}

		if removed := RemoveRecord(m, rec.Type); len(removed) != 1 || len(m.Data) != 0 {
			t.Fatalf("RemoveRecord removed %+v", removed)
		}
	})
}
