package repodata

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// dnfImage is a Fedora image with dnf5; the tests that need it are skipped
// when podman or the image is not there.
const dnfImage = "localhost/s3tools:latest"

// dnfMakecache serves repo over http inside the image and runs
// `dnf5 makecache` with the presto metadata enabled, so that dnf downloads,
// verifies and parses prestodelta.xml. It returns the output of dnf and the
// requests the server saw.
const dnfScript = `
cd /repo && (python3 -m http.server 8123 >/tmp/http.log 2>&1 &)
sleep 1
cd /
rc=0
dnf5 -y --repofrompath=dl,http://127.0.0.1:8123/ --setopt=dl.gpgcheck=0 --setopt=dl.repo_gpgcheck=0 \
    --setopt=optional_metadata_types=presto --disable-repo='*' --enable-repo=dl makecache 2>&1 || rc=$?
echo "exit=$rc"
cat /tmp/http.log
`

func dnfMakecache(t *testing.T, repo string) string {
	t.Helper()

	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman is not installed")
	}

	if err := exec.Command("podman", "image", "exists", dnfImage).Run(); err != nil {
		t.Skipf("image %s is not available", dnfImage)
	}

	abs, err := filepath.Abs(repo)
	if err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("podman", "run", "--rm", "-v", abs+":/repo:ro,Z", dnfImage, "sh", "-c", dnfScript).CombinedOutput()
	if err != nil {
		t.Fatalf("podman: %v\n%s", err, out)
	}

	return string(out)
}

// TestDnfReadsRecords registers the records this package makes in the
// repository of testdata/deltainfo and has dnf5 load it: a prestodelta
// record written by PrestoDeltaRecord, which dnf downloads and verifies, next
// to AppStream records it does not use but must tolerate. A record with a
// wrong checksum is reported by the same command, so the clean first run
// proves the checksums are the ones the tools compute.
func TestDnfReadsRecords(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "repo")
	copyRepodata(t, deltaFixturePath("repo", "repodata"), filepath.Join(repo, "repodata"))

	m, _ := parseRepomdFile(t, filepath.Join(repo, "repodata", "repomd.xml"))

	old, ok := m.Find("prestodelta")
	if !ok {
		t.Fatal("the fixture repository has no prestodelta record")
	}

	// The record of createrepo_c is replaced by the one written here.
	info, err := ParseDeltaInfo(bytes.NewReader(deltaFixtureBytes(t, "prestodelta.xml")), DeltaInfoLimits{})
	if err != nil {
		t.Fatal(err)
	}

	write := func(rec RepomdData, data []byte) {
		if err := os.WriteFile(filepath.Join(repo, filepath.FromSlash(rec.Location)), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	rec, file, err := PrestoDeltaRecord(info, RecordOptions{Timestamp: old.Timestamp})
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(filepath.Join(repo, filepath.FromSlash(old.Location))); err != nil {
		t.Fatal(err)
	}

	write(rec, file)
	AddRecord(m, rec)

	files, err := AppStreamRecords(AppStream{Components: recordsInput(t, "appstream.xml"), Icons: recordsInput(t, "appstream-icons.tar")}, RecordOptions{Timestamp: old.Timestamp})
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range files {
		write(f.Record, f.Data)
		AddRecord(m, f.Record)
	}

	repomd := filepath.Join(repo, "repodata", "repomd.xml")
	if err := os.WriteFile(repomd, marshalRepomd(t, m), 0o644); err != nil {
		t.Fatal(err)
	}

	out := dnfMakecache(t, repo)
	if !strings.Contains(out, "exit=0") || !strings.Contains(out, "Metadata cache created") || strings.Contains(out, "checksum doesn't match") {
		t.Fatalf("dnf5 makecache failed:\n%s", out)
	}

	if !strings.Contains(out, "GET /"+rec.Location) {
		t.Fatalf("dnf5 did not download %s:\n%s", rec.Location, out)
	}

	// The negative control: the same repository with a wrong checksum.
	bad := rec
	bad.Checksum = strings.Repeat("0", 64)

	AddRecord(m, bad)

	if err := os.WriteFile(repomd, marshalRepomd(t, m), 0o644); err != nil {
		t.Fatal(err)
	}

	// dnf treats the optional metadata as optional: it reports the failure
	// and carries on.
	if out := dnfMakecache(t, repo); !strings.Contains(out, "checksum doesn't match") {
		t.Fatalf("dnf5 did not notice the wrong checksum:\n%s", out)
	}
}
