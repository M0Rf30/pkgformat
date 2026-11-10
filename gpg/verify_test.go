package gpg

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const sampleManifest = `Origin: Test
Suite: jammy
Codename: jammy
SHA256:
 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 12345 main/binary-amd64/Packages.xz
`

// smallEntity builds a fast, throwaway RSA identity; security is irrelevant
// for test data.
func smallEntity(t *testing.T, name string) *openpgp.Entity {
	t.Helper()

	return smallEntityAt(t, name, time.Now)
}

func smallEntityAt(t *testing.T, name string, now func() time.Time) *openpgp.Entity {
	t.Helper()

	cfg := &packet.Config{DefaultHash: crypto.SHA256, RSABits: 1024, Rand: rand.Reader, Time: now}

	e, err := openpgp.NewEntity(name, "", name+"@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}

	return e
}

func signerOf(t *testing.T, e *openpgp.Entity) *LocalSigner {
	t.Helper()

	s, err := NewLocalSignerFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}

	return s
}

func keyringOf(t *testing.T, s *LocalSigner) *Keyring {
	t.Helper()

	kr, err := s.Keyring()
	if err != nil {
		t.Fatal(err)
	}

	return kr
}

func armoredPublic(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()

	var buf bytes.Buffer

	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func binaryPublic(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()

	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func TestVerifyClearsignedRoundTrip(t *testing.T) {
	e := smallEntity(t, "Signer")
	s := signerOf(t, e)
	kr := keyringOf(t, s)

	r, err := s.CleartextSign(strings.NewReader(sampleManifest))
	if err != nil {
		t.Fatal(err)
	}

	signed, _ := io.ReadAll(r)

	body, v, err := VerifyClearsigned(kr, signed)
	if err != nil {
		t.Fatalf("VerifyClearsigned: %v", err)
	}

	if string(body) != sampleManifest {
		t.Errorf("body = %q", body)
	}

	if v.Identity != "Signer <Signer@example.com>" || v.Fingerprint != s.KeyFingerprint() || v.KeyID != s.KeyID() {
		t.Errorf("Verified = %+v (fingerprint %s)", v, s.KeyFingerprint())
	}

	// CRLF input is normalised to LF.
	crlf := bytes.ReplaceAll(signed, []byte("\n"), []byte("\r\n"))
	if body, _, err := VerifyClearsigned(kr, crlf); err != nil || string(body) != sampleManifest {
		t.Errorf("CRLF: body %q err %v", body, err)
	}
}

func TestVerifyClearsignedFailures(t *testing.T) {
	signer := signerOf(t, smallEntity(t, "signer"))
	other := keyringOf(t, signerOf(t, smallEntity(t, "other")))
	kr := keyringOf(t, signer)

	r, _ := signer.CleartextSign(strings.NewReader(sampleManifest))
	signed, _ := io.ReadAll(r)

	tests := []struct {
		name string
		kr   *Keyring
		data []byte
		want error
	}{
		{"unknown signer", other, signed, ErrUnknownSigner},
		{"tampered body", kr, bytes.Replace(signed, []byte("jammy"), []byte("evil!"), 1), ErrBadSignature},
		{"plain text", kr, []byte(sampleManifest), ErrNotClearsigned},
		{"empty", kr, nil, ErrNotClearsigned},
		{"nil keyring", nil, signed, ErrNoKeys},
		{"empty keyring", &Keyring{}, signed, ErrNoKeys},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := VerifyClearsigned(tt.kr, tt.data); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}

	// A clear-signed header without a signature block is "unsigned".
	unsigned := []byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nhello\n")
	if _, _, err := VerifyClearsigned(kr, unsigned); err == nil {
		t.Error("message without signature accepted")
	}
}

func TestVerifyDetachedArmoredAndBinary(t *testing.T) {
	s := signerOf(t, smallEntity(t, "signer"))
	kr := keyringOf(t, s)
	data := []byte("pacman package bytes")

	armoredSig, err := s.DetachedSign(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	binarySig, err := s.DetachedSignBinary(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.HasPrefix(binarySig, []byte("-----BEGIN")) {
		t.Fatal("DetachedSignBinary returned an armored signature")
	}

	for name, sig := range map[string][]byte{"armored": armoredSig, "binary": binarySig, "armored with leading space": append([]byte("\n  "), armoredSig...)} {
		t.Run(name, func(t *testing.T) {
			v, err := VerifyDetached(kr, bytes.NewReader(data), sig)
			if err != nil || v.Fingerprint != s.KeyFingerprint() {
				t.Fatalf("VerifyDetached = %+v, %v", v, err)
			}

			if _, err := VerifyDetached(kr, bytes.NewReader(append(data, 'x')), sig); !errors.Is(err, ErrBadSignature) {
				t.Errorf("tampered data: err = %v, want ErrBadSignature", err)
			}

			stranger := keyringOf(t, signerOf(t, smallEntity(t, "stranger")))
			if _, err := VerifyDetached(stranger, bytes.NewReader(data), sig); !errors.Is(err, ErrUnknownSigner) {
				t.Errorf("unknown key: err = %v, want ErrUnknownSigner", err)
			}
		})
	}

	for _, garbage := range [][]byte{nil, []byte("not a signature"), binarySig[:len(binarySig)/2]} {
		if _, err := VerifyDetached(kr, bytes.NewReader(data), garbage); err == nil {
			t.Errorf("garbage signature %q accepted", garbage)
		}
	}

	if _, err := VerifyDetached(nil, bytes.NewReader(data), binarySig); !errors.Is(err, ErrNoKeys) {
		t.Errorf("nil keyring: err = %v", err)
	}
}

func TestVerifyExpiredAndRevokedKeys(t *testing.T) {
	// The key was created two days ago with a one-hour lifetime and signed
	// while it was still valid; today it is expired.
	created := time.Now().Add(-48 * time.Hour)
	at := func() time.Time { return created }
	e := smallEntityAt(t, "expiring", at)
	life := uint32(3600)

	for _, id := range e.Identities {
		id.SelfSignature.KeyLifetimeSecs = &life
		if err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, &packet.Config{Time: at}); err != nil {
			t.Fatal(err)
		}
	}

	data := []byte("data")

	var sig bytes.Buffer

	signAt := func() time.Time { return created.Add(10 * time.Minute) }
	if err := openpgp.DetachSign(&sig, e, bytes.NewReader(data), &packet.Config{Time: signAt}); err != nil {
		t.Fatal(err)
	}

	kr, err := ParseKeyring(binaryPublic(t, e))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyDetached(kr, bytes.NewReader(data), sig.Bytes()); !errors.Is(err, ErrKeyExpired) {
		t.Errorf("expired key: err = %v, want ErrKeyExpired", err)
	}
}

func TestParseKeyringFormats(t *testing.T) {
	e := smallEntity(t, "k")

	for name, blob := range map[string][]byte{"armored": armoredPublic(t, e), "binary": binaryPublic(t, e)} {
		kr, err := ParseKeyring(blob)
		if err != nil || kr.Len() != 1 {
			t.Errorf("%s: kr=%v err=%v", name, kr, err)
		}

		kr2, err := ReadKeyring(bytes.NewReader(blob))
		if err != nil || kr2.Len() != 1 {
			t.Errorf("%s ReadKeyring: %v", name, err)
		}
	}

	for _, bad := range [][]byte{nil, []byte("garbage"), []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n")} {
		if _, err := ParseKeyring(bad); err == nil {
			t.Errorf("ParseKeyring(%q) succeeded", bad)
		}
	}

	if _, err := ParseKeyring(make([]byte, MaxKeyringBytes+1)); !errors.Is(err, ErrKeyringTooLarge) {
		t.Errorf("oversized keyring: %v", err)
	}

	if _, err := ReadKeyring(bytes.NewReader(make([]byte, MaxKeyringBytes+1))); !errors.Is(err, ErrKeyringTooLarge) {
		t.Errorf("oversized reader keyring: %v", err)
	}

	var nilKR *Keyring

	nilKR.Merge(nil)

	if nilKR.Len() != 0 {
		t.Error("nil keyring Len != 0")
	}
}

func TestLoadKeyringFileAndDir(t *testing.T) {
	a, b := smallEntity(t, "a"), smallEntity(t, "b")
	dir := t.TempDir()

	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}

		return p
	}

	pa := write("a.gpg", binaryPublic(t, a))
	write("b.asc", armoredPublic(t, b))
	write("README", []byte("ignored"))
	write("broken.gpg", []byte("garbage"))

	if err := os.Mkdir(filepath.Join(dir, "sub.gpg"), 0o700); err != nil {
		t.Fatal(err)
	}

	kr, err := LoadKeyringFile(pa)
	if err != nil || kr.Len() != 1 {
		t.Fatalf("LoadKeyringFile: %v %v", kr, err)
	}

	if _, err := LoadKeyringFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}

	all, err := LoadKeyringDir(dir)
	if err != nil || all.Len() != 2 {
		t.Fatalf("LoadKeyringDir: len %d err %v", all.Len(), err)
	}

	empty, err := LoadKeyringDir(t.TempDir())
	if err != nil || empty.Len() != 0 {
		t.Fatalf("empty dir: %v %v", empty, err)
	}

	if _, err := LoadKeyringDir(filepath.Join(dir, "nope")); err == nil {
		t.Error("missing dir accepted")
	}

	// Both keys verify: merge keeps each usable.
	for _, e := range []*openpgp.Entity{a, b} {
		sig := new(bytes.Buffer)
		if err := openpgp.DetachSign(sig, e, strings.NewReader("x"), nil); err != nil {
			t.Fatal(err)
		}

		if _, err := VerifyDetached(all, strings.NewReader("x"), sig.Bytes()); err != nil {
			t.Errorf("merged keyring rejects %v: %v", e.PrimaryKey.KeyIdString(), err)
		}
	}
}

// TestVerifyForeignClearsign checks interoperability with clearsign output
// produced outside LocalSigner (the shape mirrors serve as InRelease).
func TestVerifyForeignClearsign(t *testing.T) {
	e := smallEntity(t, "foreign")

	var buf bytes.Buffer

	w, err := clearsign.Encode(&buf, e.PrivateKey, &packet.Config{DefaultHash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}

	_, _ = w.Write([]byte(sampleManifest))

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	kr, _ := ParseKeyring(armoredPublic(t, e))

	body, _, err := VerifyClearsigned(kr, buf.Bytes())
	if err != nil || string(body) != sampleManifest {
		t.Fatalf("body %q err %v", body, err)
	}
}

func FuzzVerify(f *testing.F) {
	e, err := openpgp.NewEntity("fuzz", "", "", &packet.Config{RSABits: 1024})
	if err != nil {
		f.Fatal(err)
	}

	var pub, sig bytes.Buffer

	_ = e.Serialize(&pub)
	_ = openpgp.DetachSign(&sig, e, strings.NewReader("data"), nil)

	kr, err := ParseKeyring(pub.Bytes())
	if err != nil {
		f.Fatal(err)
	}

	f.Add(sig.Bytes())
	f.Add([]byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nx\n-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n"))
	f.Add(pub.Bytes())

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = VerifyClearsigned(kr, data)
		_, _ = VerifyDetached(kr, strings.NewReader("data"), data)
		_, _ = ParseKeyring(data)
	})
}

// TestParsePrivateKeyToleratesLockedSubkey: a passphrase that unlocks the
// primary signing key is enough even when an encryption-only subkey is locked
// with a different one.
func TestParsePrivateKeyToleratesLockedSubkey(t *testing.T) {
	e := smallEntity(t, "locked")

	if err := e.PrivateKey.Encrypt([]byte("primary")); err != nil {
		t.Fatal(err)
	}

	if len(e.Subkeys) == 0 {
		t.Fatal("test entity has no subkey")
	}

	for i := range e.Subkeys {
		e.Subkeys[i].Sig.FlagsValid = true
		e.Subkeys[i].Sig.FlagSign = false

		if err := e.Subkeys[i].PrivateKey.Encrypt([]byte("different")); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer

	aw, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := e.SerializePrivateWithoutSigning(aw, nil); err != nil {
		t.Fatal(err)
	}

	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := ParsePrivateKey(bytes.NewReader(buf.Bytes()), []byte("primary"))
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	if _, err := s.DetachedSignBinary(strings.NewReader("x")); err != nil {
		t.Errorf("sign: %v", err)
	}

	if _, err := ParsePrivateKey(bytes.NewReader(buf.Bytes()), []byte("wrong")); !errors.Is(err, ErrBadPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
}

func TestVerifyRevokedKey(t *testing.T) {
	e := smallEntity(t, "revoked")
	data := []byte("data")

	var sig bytes.Buffer
	if err := openpgp.DetachSign(&sig, e, bytes.NewReader(data), nil); err != nil {
		t.Fatal(err)
	}

	if err := e.RevokeKey(packet.KeyCompromised, "test", nil); err != nil {
		t.Fatal(err)
	}

	kr, err := ParseKeyring(binaryPublic(t, e))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyDetached(kr, bytes.NewReader(data), sig.Bytes()); !errors.Is(err, ErrKeyRevoked) {
		t.Errorf("err = %v, want ErrKeyRevoked", err)
	}
}
