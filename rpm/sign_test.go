package rpm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/require"
)

func helloRPM(t testing.TB) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", "hello.rpm"))
	require.NoError(t, err)

	return data
}

func newTestSigner(t testing.TB, alg gpg.Algorithm) (*gpg.LocalSigner, *openpgp.Entity) {
	t.Helper()

	entity, err := gpg.GenerateEntity("rpm sign test", "", "sign@example.com", alg)
	require.NoError(t, err)

	signer, err := gpg.NewLocalSignerFromEntity(entity)
	require.NoError(t, err)

	return signer, entity
}

func TestSignProducesAVerifiablePackage(t *testing.T) {
	for _, alg := range []gpg.Algorithm{gpg.AlgorithmED25519, gpg.AlgorithmRSA4096} {
		t.Run(string(alg), func(t *testing.T) {
			signer, entity := newTestSigner(t, alg)
			orig := helloRPM(t)

			var signed bytes.Buffer
			require.NoError(t, Sign(bytes.NewReader(orig), &signed, signer))
			require.NotEqual(t, sha256.Sum256(orig), sha256.Sum256(signed.Bytes()))

			// The key verifies both signatures: the header, and header plus payload.
			_, sigs, err := Verify(bytes.NewReader(signed.Bytes()), openpgp.EntityList{entity})
			require.NoError(t, err)
			require.GreaterOrEqual(t, len(sigs), 2)

			// The package still reads and keeps its identity and metadata.
			before, err := ReadPackage(bytes.NewReader(orig))
			require.NoError(t, err)

			after, err := ReadPackage(bytes.NewReader(signed.Bytes()))
			require.NoError(t, err)
			require.Equal(t, before.Name, after.Name)
			require.Equal(t, before.Version, after.Version)
			require.Equal(t, before.Arch, after.Arch)
			require.NotZero(t, after.HeaderStart)
			require.Greater(t, after.HeaderEnd, after.HeaderStart)
		})
	}
}

func TestSignedPackageIsRejectedByAnotherKey(t *testing.T) {
	signer, _ := newTestSigner(t, gpg.AlgorithmED25519)
	_, other := newTestSigner(t, gpg.AlgorithmED25519)

	var signed bytes.Buffer
	require.NoError(t, Sign(bytes.NewReader(helloRPM(t)), &signed, signer))

	_, _, err := Verify(bytes.NewReader(signed.Bytes()), openpgp.EntityList{other})
	require.Error(t, err)
}

func TestSigningTwiceReplacesTheSignature(t *testing.T) {
	first, firstEntity := newTestSigner(t, gpg.AlgorithmED25519)
	second, secondEntity := newTestSigner(t, gpg.AlgorithmRSA4096)

	var once, twice bytes.Buffer
	require.NoError(t, Sign(bytes.NewReader(helloRPM(t)), &once, first))
	require.NoError(t, Sign(bytes.NewReader(once.Bytes()), &twice, second))

	_, _, err := Verify(bytes.NewReader(twice.Bytes()), openpgp.EntityList{secondEntity})
	require.NoError(t, err)

	_, _, err = Verify(bytes.NewReader(twice.Bytes()), openpgp.EntityList{firstEntity})
	require.Error(t, err, "the old signature survived re-signing")
}

func TestSignRejectsNonRPMAndForeignSigners(t *testing.T) {
	signer, _ := newTestSigner(t, gpg.AlgorithmED25519)

	var out bytes.Buffer
	require.Error(t, Sign(bytes.NewReader([]byte("not an rpm at all, just text")), &out, signer))
	require.ErrorIs(t, Sign(bytes.NewReader(helloRPM(t)), &out, foreignSigner{}), ErrKeyNotSupported)
}

// TestSignedPackagePassesRpmCheck cross-checks with the real rpm tool when
// installed.
func TestSignedPackagePassesRpmCheck(t *testing.T) {
	rpmBin, err := exec.LookPath("rpm")
	if err != nil {
		t.Skip("rpm not installed")
	}

	signer, _ := newTestSigner(t, gpg.AlgorithmRSA4096)

	dir := t.TempDir()
	pkg := filepath.Join(dir, "p.rpm")
	pub := filepath.Join(dir, "pub.asc")

	var signed bytes.Buffer
	require.NoError(t, Sign(bytes.NewReader(helloRPM(t)), &signed, signer))

	key, err := signer.PublicKey()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pkg, signed.Bytes(), 0o600))
	require.NoError(t, os.WriteFile(pub, key, 0o600))

	db := filepath.Join(dir, "db")

	for _, args := range [][]string{{"--dbpath", db, "--import", pub}, {"--dbpath", db, "-K", pkg}} {
		cmd := exec.CommandContext(context.Background(), rpmBin, args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C")

		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "rpm %v: %s", args, out)

		if args[2] == "-K" {
			require.Contains(t, string(out), "signatures OK")
		}
	}
}

type foreignSigner struct{ gpg.Signer }

var errBoom = errors.New("boom")

// lockedSigner is a signer whose key cannot be used.
type lockedSigner struct{ gpg.Signer }

func (lockedSigner) SigningKey() (*packet.PrivateKey, error) { return nil, gpg.ErrKeyCannotSign }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errBoom }

// brokenSeeker reads normally but cannot be repositioned.
type brokenSeeker struct{ io.Reader }

func (brokenSeeker) Seek(int64, int) (int64, error) { return 0, errBoom }

// limitedWriter accepts n bytes, then fails.
type limitedWriter struct{ left int }

func (w *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > w.left {
		return 0, errBoom
	}

	w.left -= len(p)

	return len(p), nil
}

func TestSignFailures(t *testing.T) {
	signer, _ := newTestSigner(t, gpg.AlgorithmED25519)

	var signed bytes.Buffer
	require.NoError(t, Sign(bytes.NewReader(helloRPM(t)), &signed, signer))

	for _, tt := range []struct {
		name   string
		src    io.ReadSeeker
		dst    io.Writer
		signer gpg.Signer
		want   error
	}{
		{"signer key unusable", bytes.NewReader(helloRPM(t)), io.Discard, lockedSigner{}, gpg.ErrKeyCannotSign},
		{"source cannot rewind", brokenSeeker{bytes.NewReader(helloRPM(t))}, io.Discard, signer, errBoom},
		{"signature header write fails", bytes.NewReader(helloRPM(t)), failingWriter{}, signer, errBoom},
		{"package body write fails", bytes.NewReader(helloRPM(t)), &limitedWriter{left: signed.Len() - 1}, signer, errBoom},
		{"empty source", bytes.NewReader(nil), io.Discard, signer, nil},
		{"truncated package", bytes.NewReader(helloRPM(t)[:200]), io.Discard, signer, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := Sign(tt.src, tt.dst, tt.signer)
			require.Error(t, err)

			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
			}
		})
	}
}
