package deb_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
)

func newSigner(t testing.TB, name string) *gpg.LocalSigner {
	t.Helper()

	entity, err := gpg.GenerateEntity(name, "test", name+"@example.org", gpg.AlgorithmED25519)
	require.NoError(t, err)

	signer, err := gpg.NewLocalSignerFromEntity(entity)
	require.NoError(t, err)

	return signer
}

func keyringOf(t testing.TB, s *gpg.LocalSigner) *gpg.Keyring {
	t.Helper()

	kr, err := s.Keyring()
	require.NoError(t, err)

	return kr
}

// recordHandler collects log records.
type recordHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.records = append(h.records, r)

	return nil
}
func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordHandler) levels() []slog.Level {
	var out []slog.Level
	for _, r := range h.records {
		out = append(out, r.Level)
	}

	return out
}

func (h *recordHandler) attr(i int, key string) string {
	var v string

	h.records[i].Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			v = a.Value.String()

			return false
		}

		return true
	})

	return v
}

func signedSample(t *testing.T, signer *gpg.LocalSigner) (*deb.SignedRelease, []byte) {
	t.Helper()

	body := sampleRelease().Marshal()

	signed, err := deb.SignRelease(signer, body)
	require.NoError(t, err)

	return signed, body
}

func TestSignRelease(t *testing.T) {
	signer := newSigner(t, "signer")
	signed, body := signedSample(t, signer)

	assert.Equal(t, body, signed.Release)
	assert.Equal(t, signer.KeyFingerprint(), signed.Fingerprint)
	assert.True(t, bytes.HasPrefix(signed.InRelease, []byte("-----BEGIN PGP SIGNED MESSAGE-----")))
	assert.Contains(t, string(signed.InRelease), "-----BEGIN PGP SIGNATURE-----")
	assert.True(t, bytes.HasPrefix(signed.ReleaseGPG, []byte("-----BEGIN PGP SIGNATURE-----")))

	// The clear-signed text reads back as the document.
	rel, err := deb.ParseRelease(signed.InRelease)
	require.NoError(t, err)
	assert.Equal(t, sampleRelease().Files, rel.Files)

	_, err = deb.SignRelease(nil, body)
	require.ErrorIs(t, err, deb.ErrNoSigner)
}

func TestVerifyRoundTrip(t *testing.T) {
	signer := newSigner(t, "good")
	signed, body := signedSample(t, signer)
	trust := deb.Trust{Keyring: keyringOf(t, signer)}

	got, err := trust.VerifyInRelease(signed.InRelease)
	require.NoError(t, err)

	// The signed text is the document up to its final newline.
	assert.Equal(t, strings.TrimRight(string(body), "\n"), strings.TrimRight(string(got), "\n"))

	got, err = trust.VerifyReleaseGPG(signed.Release, signed.ReleaseGPG, nil)
	require.NoError(t, err)
	assert.Equal(t, body, got)

	// Whole pipeline: verified text parses.
	_, err = deb.ParseRelease(got)
	require.NoError(t, err)
}

func TestVerifyInReleasePolicy(t *testing.T) {
	signer := newSigner(t, "trusted")
	other := newSigner(t, "stranger")
	signed, _ := signedSample(t, signer)
	strangerSigned, _ := signedSample(t, other)

	unsigned := signed.Release
	keyringErr := errors.New("keyring unreadable")

	tamper := func(in []byte) []byte {
		return bytes.Replace(in, []byte("Suite: stable"), []byte("Suite: evilxx"), 1)
	}

	tests := []struct {
		name     string
		trust    deb.Trust
		input    []byte
		wantErr  error // nil: accepted
		verified bool  // true when the signature actually counted
	}{
		{"good signature", deb.Trust{Keyring: keyringOf(t, signer)}, signed.InRelease, nil, true},
		{"good signature, lenient", deb.Trust{Keyring: keyringOf(t, signer), AllowUnverified: true}, signed.InRelease, nil, true},

		{"no keyring", deb.Trust{}, signed.InRelease, deb.ErrNoTrustAnchor, false},
		{"empty keyring", deb.Trust{Keyring: &gpg.Keyring{}}, signed.InRelease, deb.ErrNoTrustAnchor, false},
		{"no keyring, lenient", deb.Trust{AllowUnverified: true}, signed.InRelease, nil, false},
		{"keyring error surfaced", deb.Trust{KeyringErr: keyringErr}, signed.InRelease, keyringErr, false},
		{"keyring error, lenient", deb.Trust{KeyringErr: keyringErr, AllowUnverified: true}, signed.InRelease, nil, false},

		{"unknown signer", deb.Trust{Keyring: keyringOf(t, other)}, signed.InRelease, deb.ErrUnknownSigner, false},
		{"unknown signer, lenient", deb.Trust{Keyring: keyringOf(t, other), AllowUnverified: true}, signed.InRelease, nil, false},

		{"not clearsigned", deb.Trust{Keyring: keyringOf(t, signer)}, unsigned, gpg.ErrNotClearsigned, false},
		{"not clearsigned, lenient", deb.Trust{Keyring: keyringOf(t, signer), AllowUnverified: true}, unsigned, nil, false},

		{"tampered", deb.Trust{Keyring: keyringOf(t, signer)}, tamper(signed.InRelease), gpg.ErrBadSignature, false},
		{"tampered, lenient is still fatal", deb.Trust{Keyring: keyringOf(t, signer), AllowUnverified: true}, tamper(signed.InRelease), gpg.ErrBadSignature, false},
		{"tampered, signed by stranger, lenient", deb.Trust{Keyring: keyringOf(t, signer), AllowUnverified: true}, strangerSigned.InRelease, nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordHandler{}
			tc.trust.Logger = slog.New(rec)
			tc.trust.Source = "https://repo.example"

			got, err := tc.trust.VerifyInRelease(tc.input)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, got)
				assert.Empty(t, rec.records, "failures are returned, not logged")

				return
			}

			require.NoError(t, err)
			assert.Contains(t, string(got), "Suite: stable")
			require.Len(t, rec.records, 1)
			assert.Equal(t, "https://repo.example", rec.attr(0, "source"))

			if tc.verified {
				assert.Equal(t, []slog.Level{slog.LevelInfo}, rec.levels())
				assert.Equal(t, signer.KeyFingerprint(), strings.ToUpper(rec.attr(0, "fingerprint")))
				assert.NotEmpty(t, rec.attr(0, "signer"))
			} else {
				assert.Equal(t, []slog.Level{slog.LevelWarn}, rec.levels())
			}
		})
	}
}

func TestVerifyReleaseGPGPolicy(t *testing.T) {
	signer := newSigner(t, "trusted")
	other := newSigner(t, "stranger")
	signed, body := signedSample(t, signer)

	strangerSig := func() []byte {
		s, _ := signedSample(t, other)

		return s.ReleaseGPG
	}()

	keyringErr := errors.New("keyring unreadable")
	fetchErr := errors.New("404")
	tampered := append([]byte("# x\n"), body...)

	tests := []struct {
		name    string
		trust   deb.Trust
		body    []byte
		sig     []byte
		sigErr  error
		wantErr error
	}{
		{"good", deb.Trust{Keyring: keyringOf(t, signer)}, body, signed.ReleaseGPG, nil, nil},
		{"good, lenient", deb.Trust{Keyring: keyringOf(t, signer), AllowUnverified: true}, body, signed.ReleaseGPG, nil, nil},

		{"signature fetch failed", deb.Trust{Keyring: keyringOf(t, signer)}, body, nil, fetchErr, fetchErr},
		{"signature fetch failed, lenient", deb.Trust{Keyring: keyringOf(t, signer), AllowUnverified: true}, body, nil, fetchErr, nil},
		{"fetch failed beats missing keyring", deb.Trust{KeyringErr: keyringErr}, body, nil, fetchErr, fetchErr},

		{"no keyring", deb.Trust{}, body, signed.ReleaseGPG, nil, deb.ErrNoTrustAnchor},
		{"keyring error surfaced", deb.Trust{KeyringErr: keyringErr}, body, signed.ReleaseGPG, nil, keyringErr},
		{"no keyring, lenient", deb.Trust{AllowUnverified: true}, body, signed.ReleaseGPG, nil, nil},

		{"unknown signer", deb.Trust{Keyring: keyringOf(t, signer)}, body, strangerSig, nil, deb.ErrUnknownSigner},
		{"unknown signer, lenient", deb.Trust{Keyring: keyringOf(t, signer), AllowUnverified: true}, body, strangerSig, nil, nil},

		{"tampered", deb.Trust{Keyring: keyringOf(t, signer)}, tampered, signed.ReleaseGPG, nil, gpg.ErrBadSignature},
		{"tampered, lenient is still fatal", deb.Trust{Keyring: keyringOf(t, signer), AllowUnverified: true}, tampered, signed.ReleaseGPG, nil, gpg.ErrBadSignature},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordHandler{}
			tc.trust.Logger = slog.New(rec)

			got, err := tc.trust.VerifyReleaseGPG(tc.body, tc.sig, tc.sigErr)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, got)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.body, got)
			require.Len(t, rec.records, 1)
		})
	}
}

func TestTrustNilLoggerIsSafe(t *testing.T) {
	signer := newSigner(t, "quiet")
	signed, _ := signedSample(t, signer)

	cases := []deb.Trust{
		{Keyring: keyringOf(t, signer)},
		{AllowUnverified: true},
		{Keyring: keyringOf(t, newSigner(t, "x")), AllowUnverified: true},
	}

	for _, trust := range cases {
		_, err := trust.VerifyInRelease(signed.InRelease)
		require.NoError(t, err)

		_, err = trust.VerifyReleaseGPG(signed.Release, signed.ReleaseGPG, nil)
		require.NoError(t, err)

		_, err = trust.VerifyReleaseGPG(signed.Release, nil, errors.New("x"))
		assert.Equal(t, !trust.AllowUnverified, err != nil, "a fetch error is only accepted when lenient")
	}
}

func TestErrUnsignedWrapsGPG(t *testing.T) {
	require.ErrorIs(t, deb.ErrUnsigned, gpg.ErrUnsigned)
	require.ErrorIs(t, deb.ErrUnknownSigner, gpg.ErrUnknownSigner)
}

// gpgEnv returns the gpg binary and a fresh home directory.
func gpgEnv(t *testing.T) (string, string) {
	t.Helper()

	bin, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not installed")
	}

	home, err := os.MkdirTemp("", "gnupg") // short path: gpg-agent sockets have a length limit
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()
		_ = os.RemoveAll(home)
	})
	require.NoError(t, os.Chmod(home, 0o700))

	return bin, home
}

func runGPG(t *testing.T, bin, home string, stdin []byte, args ...string) []byte {
	t.Helper()

	cmd := exec.Command(bin, append([]string{"--homedir", home, "--batch", "--no-tty"}, args...)...)
	cmd.Stdin = bytes.NewReader(stdin)

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	out, err := cmd.Output()
	require.NoError(t, err, stderr.String())

	return out
}

func TestSignedReleaseAcceptedByGPG(t *testing.T) {
	bin, home := gpgEnv(t)

	signer := newSigner(t, "ours")
	signed, _ := signedSample(t, signer)

	pub, err := signer.PublicKey()
	require.NoError(t, err)

	runGPG(t, bin, home, pub, "--import")

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "InRelease"), signed.InRelease, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Release"), signed.Release, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Release.gpg"), signed.ReleaseGPG, 0o644))

	runGPG(t, bin, home, nil, "--verify", filepath.Join(dir, "InRelease"))
	runGPG(t, bin, home, nil, "--verify", filepath.Join(dir, "Release.gpg"), filepath.Join(dir, "Release"))

	// gpg's own view of the clear-signed text matches ours.
	out := runGPG(t, bin, home, nil, "--decrypt", filepath.Join(dir, "InRelease"))
	assert.Equal(t, strings.TrimRight(string(signed.Release), "\n"), strings.TrimRight(string(out), "\n"))

	// A tampered file is rejected by gpg as well.
	bad := bytes.Replace(signed.InRelease, []byte("Suite: stable"), []byte("Suite: evilxx"), 1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Bad"), bad, 0o644))

	err = exec.Command(bin, "--homedir", home, "--batch", "--verify", filepath.Join(dir, "Bad")).Run()
	require.Error(t, err)
}

func TestGPGSignedReleaseAcceptedByTrust(t *testing.T) {
	bin, home := gpgEnv(t)

	runGPG(t, bin, home, nil, "--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key", "Real GPG <real@example.org>", "ed25519", "sign", "never")

	pub := runGPG(t, bin, home, nil, "--export")
	require.NotEmpty(t, pub)

	kr, err := gpg.ParseKeyring(pub)
	require.NoError(t, err)
	require.Equal(t, 1, kr.Len())

	body := sampleRelease().Marshal()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Release"), body, 0o644))

	inRelease := runGPG(t, bin, home, nil, "--clearsign", "--digest-algo", "SHA512", "--output", "-", filepath.Join(dir, "Release"))
	detached := runGPG(t, bin, home, nil, "--armor", "--detach-sign", "--output", "-", filepath.Join(dir, "Release"))

	trust := deb.Trust{Keyring: kr}

	got, err := trust.VerifyInRelease(inRelease)
	require.NoError(t, err)

	rel, err := deb.ParseRelease(got)
	require.NoError(t, err)
	assert.Equal(t, sampleRelease().Files, rel.Files)

	_, err = trust.VerifyReleaseGPG(body, detached, nil)
	require.NoError(t, err)

	// Another key does not vouch for it.
	stranger := deb.Trust{Keyring: keyringOf(t, newSigner(t, "stranger"))}
	_, err = stranger.VerifyInRelease(inRelease)
	require.ErrorIs(t, err, deb.ErrUnknownSigner)

	_, err = stranger.VerifyReleaseGPG(body, detached, nil)
	require.ErrorIs(t, err, deb.ErrUnknownSigner)

	// And a changed body fails the real signature.
	_, err = trust.VerifyReleaseGPG(append(body, '#'), detached, nil)
	require.ErrorIs(t, err, gpg.ErrBadSignature)
}
