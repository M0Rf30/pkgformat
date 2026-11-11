package repodata

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRepomdRoundTripAndOrder(t *testing.T) {
	in := &Repomd{
		Revision: "5",
		Content:  []string{"c1", "c2"},
		Repo:     []string{"r1"},
		Distro:   []DistroTag{{CPEID: "cpe:/o:fedoraproject:fedora:17", Name: "Fedora 17"}, {Name: "plain"}},
		Data: []RepomdData{
			{
				Type: "primary_zck", Location: "repodata/p.xml.zck",
				Checksum: "a", ChecksumType: "sha256", OpenChecksum: "b", OpenChecksumType: "sha256",
				HeaderChecksum: "c", HeaderChecksumType: "sha256", HeaderSize: 134,
				Timestamp: 7, Size: 871, OpenSize: 1320,
			},
			{
				Type: "primary_db", Location: "repodata/p.sqlite.zst",
				Checksum: "d", ChecksumType: "sha256", Timestamp: 7, Size: 1, DatabaseVersion: DatabaseVersion,
			},
		},
	}

	doc, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// createrepo_c orders the children of <data> checksum, open-checksum,
	// header-checksum, location, timestamp, size, open-size, header-size,
	// database_version, and the children of <repomd> revision, tags, data.
	order := []string{
		"<revision>", "<tags>", "<content>c1", "<content>c2", "<repo>r1", `<distro cpeid="cpe:/o:fedoraproject:fedora:17">Fedora 17`,
		"<distro>plain", `<data type="primary_zck">`, "<checksum", "<open-checksum", "<header-checksum", "<location",
		"<timestamp>", "<size>", "<open-size>", "<header-size>134", `<data type="primary_db">`, "<database_version>10",
	}

	pos := 0

	for _, want := range order {
		i := strings.Index(string(doc[pos:]), want)
		if i < 0 {
			t.Fatalf("%q missing or out of order after offset %d in:\n%s", want, pos, doc)
		}

		pos += i + len(want)
	}

	out, err := ParseRepomd(bytes.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip differs:\n in: %+v\nout: %+v", in, out)
	}
}

func TestRepomdWithoutTagsHasNone(t *testing.T) {
	doc, err := GenerateRepomdXML("1", nil)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(doc), "<tags>") {
		t.Errorf("unexpected tags:\n%s", doc)
	}
}

func TestCompressedMetadataEntry(t *testing.T) {
	cm := &CompressedMetadata{SHA256: "a", Size: 1, OpenSHA256: "b", OpenSize: 2, HeaderSHA256: "c", HeaderSize: 3}

	e := cm.Entry("primary_zck", "x-primary.xml.zck", 9)
	want := RepomdData{
		Type: "primary_zck", Location: "repodata/x-primary.xml.zck", Checksum: "a", ChecksumType: "sha256",
		OpenChecksum: "b", OpenChecksumType: "sha256", HeaderChecksum: "c", HeaderChecksumType: "sha256",
		Timestamp: 9, Size: 1, OpenSize: 2, HeaderSize: 3,
	}

	if e != want {
		t.Errorf("Entry = %+v, want %+v", e, want)
	}
}

// TestRepomdMatchesCreaterepo parses the repomd.xml createrepo_c writes with
// every option that adds an element (tags, database, zchunk) and writes it
// back byte for byte, but for the timestamps it must keep.
func TestRepomdMatchesCreaterepo(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "repomd", "repomd.xml"))
	if err != nil {
		t.Fatal(err)
	}

	m, err := ParseRepomd(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	out, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out, data) {
		t.Errorf("repomd.xml differs from createrepo_c:\n%s\n---\n%s", out, data)
	}

	for _, typ := range []string{"primary_zck", "filelists_db"} {
		if _, ok := m.Find(typ); !ok {
			t.Errorf("no %s entry", typ)
		}
	}
}

// TestRepomdReadByCreaterepoTools has modifyrepo_c, which parses repomd.xml
// strictly, add a record to a repomd.xml written by this package.
func TestRepomdReadByCreaterepoTools(t *testing.T) {
	if _, err := exec.LookPath("modifyrepo_c"); err != nil {
		t.Skip("modifyrepo_c is not installed")
	}

	dir := t.TempDir()
	repodata := filepath.Join(dir, "repodata")

	if err := os.Mkdir(repodata, 0o755); err != nil {
		t.Fatal(err)
	}

	m := &Repomd{
		Revision: "1", Content: []string{"c"}, Repo: []string{"r"},
		Distro: []DistroTag{{CPEID: "cpe:/o:x:y:1", Name: "Y 1"}},
	}

	doc, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(repodata, "repomd.xml"), doc, 0o600); err != nil {
		t.Fatal(err)
	}

	extra := filepath.Join(dir, "extra.xml")
	if err := os.WriteFile(extra, []byte("<x/>"), 0o600); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command("modifyrepo_c", "--mdtype", "extra", extra, repodata).CombinedOutput(); err != nil {
		t.Fatalf("modifyrepo_c: %v\n%s", err, out)
	}

	raw, err := os.ReadFile(filepath.Join(repodata, "repomd.xml"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := ParseRepomd(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := got.Find("extra"); !ok || !reflect.DeepEqual(got.Distro, m.Distro) || got.Revision != "1" {
		t.Errorf("modifyrepo_c lost information: %+v", got)
	}
}
