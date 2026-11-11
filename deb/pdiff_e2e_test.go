package deb_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestPDiffAptE2E runs testdata/repo-pdiff-e2e/run.sh: a repository published
// with PDiffIndexBuilder is updated by apt-get in a Debian container, which
// has to fetch Packages.diff/Index and the patches (one merged patch when the
// patches are merged) and end up with exactly the published Packages file.
//
// It needs PKGFORMAT_E2E=1, go, podman and a local Debian image with apt
// (see pdiffContainerImage); the repository is served on the loopback only.
func TestPDiffAptE2E(t *testing.T) {
	if os.Getenv("PKGFORMAT_E2E") != "1" {
		t.Skip("PKGFORMAT_E2E=1 not set")
	}

	img := pdiffContainerImage(t)

	script, err := filepath.Abs(filepath.Join("testdata", "repo-pdiff-e2e", "run.sh"))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", script)
	cmd.Env = append(os.Environ(), "IMAGE="+img)

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	require.Contains(t, string(out), "\nOK\n")
}
