package deb_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

// buildContentsRepo writes a repository for suite x whose component main has
// the committed packages and a Contents-amd64.gz built by ContentsBuilder.
func buildContentsRepo(t *testing.T, root string) {
	t.Helper()

	dist := filepath.Join(root, "dists", "x")
	require.NoError(t, os.MkdirAll(filepath.Join(dist, "main", "binary-amd64"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "pool", "main"), 0o755))

	var contents deb.ContentsBuilder

	var packages deb.Index

	names, err := filepath.Glob(filepath.Join("testdata", "repo-contents", "pool", "*.deb"))
	require.NoError(t, err)

	for _, n := range names {
		raw, err := os.ReadFile(n)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(root, "pool", "main", filepath.Base(n)), raw, 0o644))

		packages.Add(indexEntryOf(t, n, "pool/main/"+filepath.Base(n)))
	}

	for _, d := range poolDebs(t) {
		require.NoError(t, contents.AddDeb(d))
	}

	rel := &deb.Release{Codename: "x", Date: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC), Architectures: []string{"amd64"}, Components: []string{"main"}}

	gz, err := contents.Compressed(deb.CompressionGzip)
	require.NoError(t, err)

	// apt only fetches an index whose uncompressed form the Release lists too.
	for p, data := range map[string][]byte{
		"main/Contents-amd64":        contents.Bytes(),
		"main/Contents-amd64.gz":     gz,
		"main/binary-amd64/Packages": packages.Bytes(),
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dist, filepath.FromSlash(p)), data, 0o644))
		rel.AddFile(deb.HashBytes(p, data))
	}

	require.NoError(t, os.WriteFile(filepath.Join(dist, "Release"), rel.Marshal(), 0o644))
}

// With PKGFORMAT_E2E=1 and podman (and network, to install apt-file), apt-file
// downloads and searches the Contents index ContentsBuilder wrote. Set
// PKGFORMAT_UPDATE=1 as well to record testdata/repo-contents/apt-file.expected.
func TestContentsReadByAptFile(t *testing.T) {
	if os.Getenv("PKGFORMAT_E2E") != "1" {
		t.Skip("set PKGFORMAT_E2E=1 to run the podman end-to-end test")
	}

	podman, err := exec.LookPath("podman")
	if err != nil {
		t.Skip("podman not installed")
	}

	image := os.Getenv("PKGFORMAT_E2E_IMAGE")
	if image == "" {
		image = "docker.io/library/debian:bookworm-slim"
	}

	script, err := filepath.Abs(filepath.Join("testdata", "repo-contents", "apt-file.sh"))
	require.NoError(t, err)

	repo := t.TempDir()
	buildContentsRepo(t, repo)

	// The network is needed for apt-file's own installation only.
	cmd := exec.Command(podman, "run", "--rm", "--network=host",
		"-v", repo+":/repo:ro,z", "-v", script+":/apt-file.sh:ro,z", image, "sh", "/apt-file.sh")

	var stderr []byte

	out, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok { //nolint:errorlint // only the stderr is wanted
		stderr = ee.Stderr
	}

	require.NoError(t, err, string(stderr))

	expectedPath := filepath.Join("testdata", "repo-contents", "apt-file.expected")

	if os.Getenv("PKGFORMAT_UPDATE") == "1" {
		require.NoError(t, os.WriteFile(expectedPath, out, 0o644))
	}

	assert.Equal(t, string(readFixture(t, "repo-contents", "apt-file.expected")), string(out))
}

// The committed apt-file output lists what ContentsBuilder was given.
func TestContentsAptFileExpected(t *testing.T) {
	expected := string(readFixture(t, "repo-contents", "apt-file.expected"))

	for _, line := range []string{
		"alpha: /usr/bin/alpha\n", "beta: /usr/bin/alpha\n", "gamma: /usr/lib/gamma/libgamma.so.1.0\n",
		"alpha: /usr/share/with space/file one.txt\n", "beta: /etc/beta.conf\n",
	} {
		assert.Contains(t, expected, line)
	}

	// The packages are named Section/name in the index; apt-file shows the name.
	var contents deb.ContentsBuilder
	for _, d := range poolDebs(t) {
		require.NoError(t, contents.AddDeb(d))
	}

	assert.Equal(t, []string{"beta", "utils/alpha"}, contents.Locations("usr/bin/alpha"))
}
