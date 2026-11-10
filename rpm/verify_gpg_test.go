//go:build unix

package rpm

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/gpg"
)

// gnupgHome creates a GnuPG home directory with a key that expires in two
// days, and returns it with the fingerprint of the key. The tests skip when
// gpg or rpmsign is missing.
func gnupgHome(t *testing.T) (home, fingerprint string) {
	t.Helper()

	for _, tool := range []string{"gpg", "gpgconf", "rpmsign"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}

	// the agent socket lives in the home directory: keep its path short
	home, err := os.MkdirTemp("", "gnupg")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()
		_ = os.RemoveAll(home)
	})
	require.NoError(t, os.Chmod(home, 0o700))

	run := func(args ...string) string {
		t.Helper()

		cmd := exec.Command("gpg", append([]string{"--homedir", home, "--batch", "--no-tty", "--yes"}, args...)...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		require.NoError(t, cmd.Run(), "gpg %v: %s", args, stderr.String())

		return stdout.String()
	}

	run("--passphrase", "", "--quick-generate-key", "Real Tool <real@example.com>", "ed25519", "sign", "2d")

	for _, line := range strings.Split(run("--list-keys", "--with-colons"), "\n") {
		if f := strings.Split(line, ":"); f[0] == "fpr" {
			return home, f[9]
		}
	}

	t.Fatal("no fingerprint")

	return "", ""
}

// publicKey exports the public key of home.
func publicKey(t *testing.T, home string) openpgp.EntityList {
	t.Helper()

	out, err := exec.Command("gpg", "--homedir", home, "--batch", "--export").Output()
	require.NoError(t, err)

	keys, err := openpgp.ReadKeyRing(bytes.NewReader(out))
	require.NoError(t, err)

	return keys
}

// TestVerifyKeyStateAgainstRpmsign signs packages with rpmsign and GnuPG, and
// checks how Verify treats the key over its life: valid, expired, revoked.
func TestVerifyKeyStateAgainstRpmsign(t *testing.T) {
	for format, pkg := range verifyPackages(t) {
		t.Run(format, func(t *testing.T) {
			home, fingerprint := gnupgHome(t) // revoked below: one key per package

			path := filepath.Join(t.TempDir(), "signed.rpm")
			require.NoError(t, os.WriteFile(path, pkg, 0o600))

			out, err := exec.Command("rpmsign", "--addsign", "--define", "_gpg_name "+fingerprint,
				"--define", "_gpg_path "+home, path).CombinedOutput()
			require.NoError(t, err, string(out))

			signed, err := os.ReadFile(path)
			require.NoError(t, err)

			keys := publicKey(t, home)

			// valid now
			_, sigs, err := Verify(bytes.NewReader(signed), keys)
			require.NoError(t, err)
			require.NotEmpty(t, sigs)

			// expired in three days, like GnuPG says
			_, _, err = VerifyWithOptions(bytes.NewReader(signed), keys, &VerifyOptions{
				Now: at(time.Now().Add(3 * 24 * time.Hour)),
			})
			require.ErrorIs(t, err, gpg.ErrKeyExpired)

			// revoked: gpg wrote a revocation certificate when it made the key
			rev, err := os.ReadFile(filepath.Join(home, "openpgp-revocs.d", fingerprint+".rev"))
			require.NoError(t, err)
			// the file is made unimportable by a ':' in front of the armor header
			rev = bytes.ReplaceAll(rev, []byte(":-----BEGIN"), []byte("-----BEGIN"))

			cmd := exec.Command("gpg", "--homedir", home, "--batch", "--no-tty", "--import")
			cmd.Stdin = bytes.NewReader(rev)
			out, err = cmd.CombinedOutput()
			require.NoError(t, err, string(out))

			_, _, err = Verify(bytes.NewReader(signed), publicKey(t, home))
			require.ErrorIs(t, err, gpg.ErrKeyRevoked)
		})
	}
}
