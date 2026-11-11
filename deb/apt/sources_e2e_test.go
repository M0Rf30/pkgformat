package apt

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListFileNameAgainstLiveApt runs testdata/sources/listnames/container.sh
// in a debian container, which makes the real `apt-get update` name its files,
// and checks ListFileNameFor against what it produced. It needs podman (or
// docker named by CONTAINER_ENGINE), network access to install the tools in
// the container, and PKGFORMAT_E2E=1; the committed expected.tsv that
// TestListFileNameForGolden reads is a recording of the same run.
func TestListFileNameAgainstLiveApt(t *testing.T) {
	if os.Getenv("PKGFORMAT_E2E") != "1" {
		t.Skip("set PKGFORMAT_E2E=1 to run the container test (it uses the network)")
	}

	engine := os.Getenv("CONTAINER_ENGINE")
	if engine == "" {
		engine = "podman"
	}

	path, err := exec.LookPath(engine)
	if err != nil {
		t.Skipf("%s not found", engine)
	}

	image := os.Getenv("IMAGE")
	if image == "" {
		image = "docker.io/library/debian:stable-slim"
	}

	script, err := filepath.Abs(filepath.Join("testdata", "sources", "listnames", "container.sh"))
	require.NoError(t, err)

	out := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "run", "--rm",
		"-v", out+":/out:Z", "-v", script+":/container.sh:Z,ro", image, "bash", "/container.sh")

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("container run: %v\n%s", err, output)
	}

	f, err := os.Open(filepath.Join(out, "expected.tsv"))
	require.NoError(t, err)

	defer func() { _ = f.Close() }()

	rows := 0

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		cols := strings.Split(sc.Text(), "\t")
		require.Len(t, cols, 3, sc.Text())

		srcs, err := ParseSourcesList(cols[0])
		require.NoError(t, err, cols[0])
		require.Len(t, srcs, 1)

		assert.Equal(t, cols[2], ListFileNameFor(&srcs[0], cols[1]), "%s: %s", cols[0], cols[1])

		rows++
	}

	require.NoError(t, sc.Err())
	assert.Greater(t, rows, 60)
}
