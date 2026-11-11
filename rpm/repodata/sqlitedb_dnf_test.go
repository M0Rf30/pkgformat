package repodata

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sqliteDNFImage is a Fedora image with dnf5; the test skips when it is not present.
const sqliteDNFImage = "localhost/s3tools:latest"

// dnfScript serves /repo over HTTP, points dnf5 at it, lists the packages, and
// prints the requests the server saw after a marker line.
const dnfScript = `
cd /repo && (python3 -m http.server 8000 >/tmp/http.log 2>&1 &)
sleep 1
cat > /etc/yum.repos.d/t.repo <<R
[t]
name=t
baseurl=http://127.0.0.1:8000/
gpgcheck=0
R
dnf5 --setopt=reposdir=/etc/yum.repos.d --setopt=cachedir=/tmp/c --repo t repoquery --qf '%{name}\n' 2>&1
dnf5 --setopt=reposdir=/etc/yum.repos.d --setopt=cachedir=/tmp/c --repo t repoquery --file /usr/bin/bash --qf '%{name}\n' 2>&1
echo ==REQUESTS==
grep -o 'GET [^ ]*' /tmp/http.log
`

func runDnf(t *testing.T, repo string) (output string, requests []string) {
	t.Helper()

	cmd := exec.Command("podman", "run", "--rm", "-v", repo+":/repo:ro,Z", sqliteDNFImage, "sh", "-c", dnfScript)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("podman: %v", err)
	}

	before, after, _ := strings.Cut(string(out), "==REQUESTS==")

	for _, l := range strings.Fields(strings.ReplaceAll(after, "GET ", "\nGET ")) {
		if strings.HasPrefix(l, "/") {
			requests = append(requests, l)
		}
	}

	return before, requests
}

// TestSQLiteRepositoryWithDnf serves a repository that carries the XML
// documents and the databases to dnf5. dnf5 does not use the databases: it
// loads the repository from the XML and never requests them, and a repository
// that lists only databases is rejected for lack of primary data. The schema
// match with createrepo_c, not dnf5, is what the databases are checked against.
func TestSQLiteRepositoryWithDnf(t *testing.T) {
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman is not installed")
	}

	if err := exec.Command("podman", "image", "exists", sqliteDNFImage).Run(); err != nil {
		t.Skipf("image %s is not present", sqliteDNFImage)
	}

	pkgs, opts := refCorpus(t)
	repo, _ := sqliteBuildRepo(t, pkgs, opts, true)

	// The packages the metadata points at, so that the repository is whole.
	if err := os.CopyFS(filepath.Join(repo, "Packages"), os.DirFS(filepath.Join("testdata", "createrepo", "Packages"))); err != nil {
		t.Fatal(err)
	}

	out, requests := runDnf(t, repo)

	if got := strings.Count(out, "\n"); got < len(pkgs) {
		t.Fatalf("dnf5 listed fewer than the %d packages:\n%s", len(pkgs), out)
	}

	if !strings.Contains(out, "bash\n") || !strings.Contains(out, "filesystem\n") {
		t.Errorf("dnf5 did not list the packages of the repository:\n%s", out)
	}

	var sawPrimary bool

	for _, r := range requests {
		if strings.Contains(r, "sqlite") {
			t.Errorf("dnf5 requested a database: %s", r)
		}

		if strings.HasSuffix(r, "/primary.xml.gz") {
			sawPrimary = true
		}
	}

	if !sawPrimary {
		t.Errorf("dnf5 did not request primary.xml.gz: %v", requests)
	}

	// A repository with the databases only has no primary data.
	m, err := ParseRepomd(bytes.NewReader(mustRead(t, filepath.Join(repo, "repodata", "repomd.xml"))))
	if err != nil {
		t.Fatal(err)
	}

	var dbOnly []RepomdData

	for _, d := range m.Data {
		if d.DatabaseVersion != 0 {
			dbOnly = append(dbOnly, d)
		}
	}

	if len(dbOnly) != len(sqliteKinds) {
		t.Fatalf("repomd.xml lists %d databases, want %d", len(dbOnly), len(sqliteKinds))
	}

	m.Data = dbOnly

	doc, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(repo, "repodata", "repomd.xml"), doc, 0o600); err != nil {
		t.Fatal(err)
	}

	out, _ = runDnf(t, repo)
	if !strings.Contains(out, "primary") || !strings.Contains(out, "not present") {
		t.Errorf("dnf5 did not reject the repository without primary data:\n%s", out)
	}
}
