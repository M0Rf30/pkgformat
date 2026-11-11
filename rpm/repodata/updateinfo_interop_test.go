package repodata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
)

var updateinfoTestdata = filepath.Join("testdata", "updateinfo")

// dnfAdvisories are the advisories testdata/updateinfo/ground_truth.py writes
// to dnf.xml: about bash, coreutils and filesystem at epoch 99, which makes
// them newer than any installed version, so that dnf lists them.
func dnfAdvisories() []Advisory {
	pkg := func(name, version, sum string, reboot bool) AdvisoryPackage {
		p := AdvisoryPackage{
			Name: name, Version: version, Release: "1.fc45", Epoch: "99", Arch: "x86_64",
			Src: name + "-" + version + "-1.fc45.src.rpm", Filename: name + "-" + version + "-1.fc45.x86_64.rpm",
			RebootSuggested: reboot,
		}
		if sum != "" {
			p.Sum = AdvisorySum{Type: "sha256", Value: sum}
		}

		return p
	}

	const (
		from   = "updates@fedoraproject.org"
		rights = "Copyright (C) 2026 Red Hat, Inc. and others."
	)

	return []Advisory{{
		ID: "FEDORA-2026-c3b1d2e4f5", Title: "bash-5.3.99-1.fc45", Type: "security", Severity: "Important",
		Status: "stable", Version: "2.0", From: from,
		Issued: utc(2026, 10, 2, 11, 43, 19), Updated: utc(2026, 10, 15, 1, 7, 46),
		Release: "Fedora 45", Rights: rights, Summary: "bash-5.3.99-1.fc45 security update",
		Description: "Update to bash 5.3 patch level 99.\n\nFixes an out-of-bounds read in the history expansion code (CVE-2026-0101).",
		References: []AdvisoryReference{
			{
				Href: "https://bugzilla.redhat.com/show_bug.cgi?id=2410101", ID: "2410101", Type: "bugzilla",
				Title: "CVE-2026-0101 bash: out-of-bounds read in history expansion",
			},
			{
				Href: "https://bodhi.fedoraproject.org/updates/FEDORA-2026-c3b1d2e4f5",
				ID:   "FEDORA-2026-c3b1d2e4f5", Type: "self", Title: "FEDORA-2026-c3b1d2e4f5",
			},
		},
		Collections: []AdvisoryCollection{{Short: "F45", Name: "Fedora 45", Packages: []AdvisoryPackage{
			pkg("bash", "5.3.99", "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0", false),
		}}},
	}, {
		ID: "FEDORA-2026-7e8f9a0b1c", Title: "coreutils-9.99-1.fc45", Type: "bugfix", Severity: "None",
		Status: "stable", Version: "2.0", From: from,
		Issued: utc(2026, 9, 12, 8, 30, 0), Updated: utc(2026, 9, 20, 17, 5, 1),
		Release: "Fedora 45", Rights: rights, Summary: "coreutils-9.99-1.fc45 bugfix update",
		Description:     "Fix `ls --color` crashing on a dangling symlink in a directory that is being removed.",
		RebootSuggested: true,
		References: []AdvisoryReference{{
			Href: "https://bugzilla.redhat.com/show_bug.cgi?id=2409999", ID: "2409999", Type: "bugzilla",
			Title: "ls --color segfaults on a dangling symlink",
		}},
		Collections: []AdvisoryCollection{{Short: "F45", Name: "Fedora 45", Packages: []AdvisoryPackage{
			pkg("coreutils", "9.99", "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809", true),
		}}},
	}, {
		ID: "FEDORA-2026-a0b1c2d3e4", Title: "filesystem-3.99-1.fc45", Type: "enhancement", Severity: "Low",
		Status: "stable", Version: "2.0", From: from,
		Issued: utc(2026, 8, 1, 6, 0, 0), Updated: utc(2026, 8, 3, 6, 0, 0),
		Release: "Fedora 45", Rights: rights, Summary: "filesystem-3.99-1.fc45 enhancement update",
		Description: "Add /usr/share/factory to the directories the filesystem package owns.",
		Collections: []AdvisoryCollection{{Short: "F45", Name: "Fedora 45", Packages: []AdvisoryPackage{
			pkg("filesystem", "3.99", "", false),
		}}},
	}}
}

func TestDnfAdvisoriesMatchCreaterepo(t *testing.T) {
	want, err := os.ReadFile(filepath.Join(updateinfoTestdata, "dnf.xml"))
	if err != nil {
		t.Fatal(err)
	}

	if got := renderUpdateinfo(t, dnfAdvisories()); !bytes.Equal(got, want) {
		t.Errorf("dnf.xml differs from createrepo_c's:\n%s", got)
	}

	if got := readUpdateinfoFile(t, filepath.Join(updateinfoTestdata, "dnf.xml")); !reflect.DeepEqual(got, dnfAdvisories()) {
		t.Errorf("advisories read from dnf.xml = %+v", got)
	}
}

func updFileSHA256(t *testing.T, path string) (string, int64) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:]), int64(len(data))
}

// readRegistered opens the document the "updateinfo" entry of the repomd.xml
// in repo/repodata names, after checking its checksums, and returns its
// advisories.
func readRegistered(t *testing.T, repo string) []Advisory {
	t.Helper()

	f, err := os.Open(filepath.Join(repo, "repodata", "repomd.xml"))
	if err != nil {
		t.Fatal(err)
	}

	defer f.Close()

	repomd, err := ParseRepomd(f)
	if err != nil {
		t.Fatal(err)
	}

	entry, ok := repomd.Find("updateinfo")
	if !ok {
		t.Fatalf("repomd.xml has no updateinfo entry: %+v", repomd.Data)
	}

	path := filepath.Join(repo, filepath.FromSlash(entry.Location))
	if sum, size := updFileSHA256(t, path); sum != entry.Checksum || size != entry.Size {
		t.Errorf("%s: sha256 %s, size %d; repomd.xml says %s, %d", entry.Location, sum, size, entry.Checksum, entry.Size)
	}

	doc, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	rc, err := OpenMetadata(doc, entry.Location, 0)
	if err != nil {
		t.Fatal(err)
	}

	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}

	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != entry.OpenChecksum || int64(len(data)) != entry.OpenSize {
		t.Errorf("%s: the decompressed document does not match the open-checksum and open-size of repomd.xml", entry.Location)
	}

	return collectAdvisories(t, bytes.NewReader(data), UpdateinfoLimits{})
}

// TestCommittedRepo reads the repository testdata/updateinfo/repo, built by
// createrepo_c with the advisories added by modifyrepo_c.
func TestCommittedRepo(t *testing.T) {
	if got := readRegistered(t, filepath.Join(updateinfoTestdata, "repo")); !reflect.DeepEqual(got, dnfAdvisories()) {
		t.Errorf("advisories = %+v", got)
	}
}

// TestModifyrepoAcceptsUpdateinfo checks that modifyrepo_c registers a
// generated updateinfo.xml, that its contents survive, and that createrepo_c
// --update keeps it.
func TestModifyrepoAcceptsUpdateinfo(t *testing.T) {
	for _, tool := range []string{"createrepo_c", "modifyrepo_c"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}

	repo := t.TempDir()

	hello, err := os.ReadFile(filepath.Join("..", "testdata", "hello.rpm"))
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(repo, "hello.rpm"), hello, 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(name string, args ...string) {
		t.Helper()

		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
	}

	run("createrepo_c", "-q", repo)

	src := filepath.Join(t.TempDir(), "updateinfo.xml")
	if err := os.WriteFile(src, renderUpdateinfo(t, modelAdvisories()), 0o600); err != nil {
		t.Fatal(err)
	}

	run("modifyrepo_c", "--mdtype", "updateinfo", src, filepath.Join(repo, "repodata"))

	if got := readRegistered(t, repo); !reflect.DeepEqual(got, modelAdvisories()) {
		t.Errorf("after modifyrepo_c: advisories = %+v", got)
	}

	run("createrepo_c", "-q", "--update", repo)

	if got := readRegistered(t, repo); !reflect.DeepEqual(got, modelAdvisories()) {
		t.Errorf("after createrepo_c --update: advisories = %+v", got)
	}
}

const updDNFImage = "localhost/s3tools:latest"

// TestDnfListsAdvisories serves a repository whose repomd.xml registers the
// updateinfo.xml this package wrote (gzip, zstd and xz compressed) and asks
// dnf5 in a container for the advisories; the output must equal what dnf5
// printed for the repository createrepo_c and modifyrepo_c built.
func TestDnfListsAdvisories(t *testing.T) {
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman is not installed")
	}

	if err := exec.Command("podman", "image", "exists", updDNFImage).Run(); err != nil {
		t.Skipf("the %s image is not available", updDNFImage)
	}

	wantList, err := os.ReadFile(filepath.Join(updateinfoTestdata, "dnf-updateinfo-list.txt"))
	if err != nil {
		t.Fatal(err)
	}

	wantInfo, err := os.ReadFile(filepath.Join(updateinfoTestdata, "dnf-updateinfo-info.txt"))
	if err != nil {
		t.Fatal(err)
	}

	for _, comp := range []Compression{Gzip, Zstd, XZ} {
		t.Run(comp.String(), func(t *testing.T) {
			repo := updBuildRepo(t, comp)

			for _, c := range []struct {
				verb string
				want []byte
			}{{"list", wantList}, {"info", wantInfo}} {
				out, err := exec.Command("podman", "run", "--rm", "--network=none", "-v", repo+":/repo:ro", updDNFImage,
					"dnf5", "-q", "-y", "--setopt=cachedir=/tmp/c", "--repofrompath=t,file:///repo", "--repo=t",
					"--no-gpgchecks", "updateinfo", c.verb, "--available").Output()
				if err != nil {
					t.Fatalf("dnf5 updateinfo %s: %v\n%s", c.verb, err, out)
				}

				if !bytes.Equal(out, c.want) {
					t.Errorf("dnf5 updateinfo %s:\n%s\nwant\n%s", c.verb, out, c.want)
				}
			}
		})
	}
}

// updBuildRepo writes a repository of one package whose repomd.xml registers the
// updateinfo.xml of dnfAdvisories, compressed with comp.
func updBuildRepo(t *testing.T, comp Compression) string {
	t.Helper()

	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, "repodata"), 0o755); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join("..", "testdata", "hello.rpm"))
	if err != nil {
		t.Fatal(err)
	}

	pkg, err := rpm.ReadPackage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(data)
	pkg.SHA256 = hex.EncodeToString(sum[:])
	pkg.PackageSize = int64(len(data))
	pkgs := []rpm.Package{*pkg}

	const timestamp = 1700000000

	repomd := &Repomd{Revision: "1700000000"}
	add := func(typ string, write func(io.Writer) error) {
		cm, err := CompressMetadataStream(comp, write)
		if err != nil {
			t.Fatal(err)
		}

		name := typ + ".xml" + comp.Extension()
		if err := os.WriteFile(filepath.Join(repo, "repodata", name), cm.Data, 0o600); err != nil {
			t.Fatal(err)
		}

		repomd.Data = append(repomd.Data, cm.Entry(typ, name, timestamp))
	}

	add("primary", func(w io.Writer) error { return WritePrimaryXML(w, pkgs) })
	add("filelists", func(w io.Writer) error { return WriteFilelistsXML(w, pkgs) })
	add("other", func(w io.Writer) error { return WriteOtherXML(w, pkgs) })
	add("updateinfo", func(w io.Writer) error { return WriteUpdateinfoXML(w, dnfAdvisories()) })

	index, err := repomd.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(repo, "repodata", "repomd.xml"), index, 0o600); err != nil {
		t.Fatal(err)
	}

	if got := readRegistered(t, repo); !reflect.DeepEqual(got, dnfAdvisories()) {
		t.Fatalf("advisories read back = %+v", got)
	}

	return repo
}
