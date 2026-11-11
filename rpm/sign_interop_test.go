package rpm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/gpg"
)

// hsmKey hides the concrete key type behind crypto.Signer, the way an HSM or
// KMS client does.
type hsmKey struct{ s crypto.Signer }

func (k hsmKey) Public() crypto.PublicKey { return k.s.Public() }

func (k hsmKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.s.Sign(r, digest, opts)
}

// TestSignersPassRpmkeys signs format 4 and 6 packages with every kind of
// signer and checks the result with the rpmkeys of the host.
func TestSignersPassRpmkeys(t *testing.T) {
	rpmkeys, err := exec.LookPath("rpmkeys")
	if err != nil {
		t.Skip("rpmkeys not installed")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	created := time.Now().Add(-time.Hour)
	signers := map[string]gpg.Signer{}

	for name, key := range map[string]crypto.Signer{"hsm-rsa3072": rsaKey, "hsm-p256": p256, "hsm-p384": p384} {
		s, err := gpg.NewCryptoSigner(hsmKey{key}, created, "rpm "+name, "", "hsm@example.com")
		require.NoError(t, err, name)
		signers[name] = s
	}

	for _, alg := range []gpg.Algorithm{
		gpg.AlgorithmRSA3072, gpg.AlgorithmP256, gpg.AlgorithmP384, gpg.AlgorithmED25519,
		gpg.AlgorithmED25519V6, gpg.AlgorithmED448V6,
	} {
		s, _ := newTestSigner(t, alg)
		signers[string(alg)] = s
		signers["opaque-"+string(alg)] = foreignSigner{s}
	}

	for name, signer := range signers {
		for _, pkg := range []string{"hello.rpm", "v6/ref-v6.rpm"} {
			t.Run(name+"/"+pkg, func(t *testing.T) {
				orig, err := os.ReadFile(filepath.Join("testdata", pkg))
				require.NoError(t, err)

				var signed bytes.Buffer
				require.NoError(t, Sign(bytes.NewReader(orig), &signed, signer))

				dir := t.TempDir()
				out := filepath.Join(dir, "p.rpm")
				pub := filepath.Join(dir, "pub.asc")
				key, err := signer.PublicKey()
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(out, signed.Bytes(), 0o600))
				require.NoError(t, os.WriteFile(pub, key, 0o600))

				db := filepath.Join(dir, "db")
				run := func(args ...string) string {
					cmd := exec.CommandContext(context.Background(), rpmkeys, append([]string{"--dbpath", db}, args...)...)
					cmd.Env = append(os.Environ(), "LC_ALL=C")
					b, err := cmd.CombinedOutput()
					require.NoError(t, err, "rpmkeys %v: %s", args, b)

					return string(b)
				}

				run("--import", pub)
				got := run("-Kv", out)
				require.Contains(t, got, "Header OpenPGP", got)
				require.NotContains(t, got, "NOKEY")
				require.NotContains(t, got, "BAD")
				require.True(t, strings.HasSuffix(strings.TrimSpace(got), "OK") ||
					strings.Contains(got, "signatures OK"), got)
			})
		}
	}
}
