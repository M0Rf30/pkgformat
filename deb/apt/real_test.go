package apt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// run executes a tool and returns its trimmed standard output.
func run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)

	out, err := cmd.Output()
	if err != nil {
		stderr := ""

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr = string(exitErr.Stderr)
		}

		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr)
	}

	return strings.TrimSpace(string(out))
}

// buildRealDeb assembles a package with dpkg-deb into the pool of repoRoot and
// returns its path.
func buildRealDeb(t *testing.T, repoRoot, name, version, depends string) string {
	t.Helper()

	pkgDir := filepath.Join(t.TempDir(), name)
	control := "Package: " + name + "\nVersion: " + version + "\nArchitecture: amd64\nMaintainer: Test <test@example.org>\n" +
		"Description: " + name + " test package\n"

	if depends != "" {
		control += "Depends: " + depends + "\n"
	}

	writeFile(t, filepath.Join(pkgDir, "DEBIAN", "control"), control)
	writeFile(t, filepath.Join(pkgDir, "usr", "share", name, "hello"), "hello from "+name+"\n")

	out := filepath.Join(repoRoot, "pool", "main", name[:1], name, name+"_"+version+"_amd64.deb")
	require.NoError(t, os.MkdirAll(filepath.Dir(out), 0o755))

	run(t, "", nil, "dpkg-deb", "--root-owner-group", "-Zgzip", "-b", pkgDir, out)

	return out
}

// TestRealRepositoryRoundTrip publishes packages built by dpkg-deb through an
// index and a Release made by apt-ftparchive, signed by gpg, and takes them
// through Update, Load, ResolveDeps and Download.
func TestRealRepositoryRoundTrip(t *testing.T) {
	for _, tool := range []string{"dpkg-deb", "apt-ftparchive", "gpg"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}

	root := t.TempDir()
	appDeb := buildRealDeb(t, root, "app", "1.2-3", "lib (>= 1.0), tool | other")
	libDeb := buildRealDeb(t, root, "lib", "1.0-1", "")
	buildRealDeb(t, root, "tool", "0.5", "")
	buildRealDeb(t, root, "other", "0.5", "")

	// The index and Release, laid out like an archive.
	indexDir := filepath.Join(root, "dists", "stable", "main", "binary-amd64")
	require.NoError(t, os.MkdirAll(indexDir, 0o755))

	packages := run(t, root, nil, "apt-ftparchive", "packages", "pool")
	require.Contains(t, packages, "Package: app")

	writeFile(t, filepath.Join(indexDir, "Packages"), packages+"\n")
	require.NoError(t, os.WriteFile(filepath.Join(indexDir, "Packages.gz"), gzipBytes(t, []byte(packages+"\n")), 0o644))

	distDir := filepath.Join(root, "dists", "stable")
	release := run(t, root, nil, "apt-ftparchive",
		"-o", "APT::FTPArchive::Release::Suite=stable",
		"-o", "APT::FTPArchive::Release::Codename=stable",
		"-o", "APT::FTPArchive::Release::Architectures=amd64",
		"-o", "APT::FTPArchive::Release::Components=main",
		"release", distDir)
	writeFile(t, filepath.Join(distDir, "Release"), release+"\n")

	// Sign it with the real gpg, in a throwaway home (short path: gpg sockets
	// live in it).
	gnupgHome, err := os.MkdirTemp("", "gnupg")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(gnupgHome, 0o700))

	env := []string{"GNUPGHOME=" + gnupgHome}

	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--kill", "gpg-agent").Run()
		_ = os.RemoveAll(gnupgHome)
	})

	gpgArgs := []string{"--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ""}

	run(t, "", env, "gpg", append(gpgArgs, "--quick-generate-key", "Real Test <real@example.org>", "ed25519", "sign", "never")...)
	run(t, distDir, env, "gpg", append(gpgArgs, "--clearsign", "-o", "InRelease", "Release")...)
	run(t, distDir, env, "gpg", append(gpgArgs, "--armor", "--detach-sign", "-o", "Release.gpg", "Release")...)

	keyring := filepath.Join(t.TempDir(), "real.gpg")
	run(t, "", env, "gpg", "--batch", "--export", "-o", keyring)

	for _, mode := range []string{"InRelease", "Release.gpg"} {
		t.Run(mode, func(t *testing.T) {
			files := http.FileServer(http.Dir(root))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "Release.gpg" && strings.HasSuffix(r.URL.Path, "/InRelease") {
					http.NotFound(w, r)

					return
				}

				files.ServeHTTP(w, r)
			}))
			t.Cleanup(srv.Close)

			src := Source{URL: srv.URL + "/", Suite: "stable", Components: []string{"main"}, SignedBy: keyring}
			lists := filepath.Join(t.TempDir(), "lists")

			n, err := Update(context.Background(), []Source{src}, UpdateOptions{
				ListsDir: lists, DefaultArch: "amd64", Client: testClient(2),
			})
			require.NoError(t, err)
			require.Equal(t, 1, n)

			// A different key must not verify the same repository.
			other := src
			other.SignedBy = writeKeyring(t, t.TempDir(), newSigner(t))

			_, err = Update(context.Background(), []Source{other}, UpdateOptions{
				ListsDir: filepath.Join(t.TempDir(), "lists"), DefaultArch: "amd64", Client: testClient(2),
			})
			require.True(t, IsVerificationError(err), "%v", err)

			status := filepath.Join(t.TempDir(), "status")
			writeFile(t, status, para("Package: tool", "Status: install ok installed", "Architecture: amd64", "Version: 0.5"))

			c, err := Load(LoadOptions{ListsDir: lists, StatusFile: status, HostArch: "amd64", Sources: []Source{src}})
			require.NoError(t, err)

			app, ok := c.Lookup("app")
			require.True(t, ok)
			assert.Equal(t, "1.2-3", app.Version)
			assert.Equal(t, src.URL, app.BaseURL)
			assert.Equal(t, "pool/main/a/app/app_1.2-3_amd64.deb", app.Filename)
			assert.Equal(t, []string{"lib", "tool"}, app.Depends)

			info, err := os.Stat(appDeb)
			require.NoError(t, err)
			assert.Equal(t, info.Size(), app.Size)

			tool, _ := c.Lookup("tool")
			assert.True(t, tool.Installed)

			order, unresolved, err := c.ResolveDeps([]string{"app"})
			require.NoError(t, err)
			assert.Empty(t, unresolved)
			assert.Equal(t, []string{"lib:amd64", "app:amd64"}, names(order), "tool is installed, so it is skipped")

			dest := filepath.Join(t.TempDir(), "debs")
			resolved, _, err := c.DownloadClosure(context.Background(), dest, []string{"app"}, DownloadOptions{Client: testClient(2)})
			require.NoError(t, err)
			require.Len(t, resolved, 2)

			for _, name := range []string{"app_1.2-3_amd64.deb", "lib_1.0-1_amd64.deb"} {
				downloaded := filepath.Join(dest, name)
				pkg := strings.SplitN(name, "_", 2)[0]

				assert.Equal(t, pkg, run(t, "", nil, "dpkg-deb", "-f", downloaded, "Package"))
				assert.Contains(t, run(t, "", nil, "dpkg-deb", "-I", downloaded), "Package: "+pkg)
			}

			got, err := os.ReadFile(filepath.Join(dest, "lib_1.0-1_amd64.deb"))
			require.NoError(t, err)

			want, err := os.ReadFile(libDeb)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}
