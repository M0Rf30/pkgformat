package gpg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"
)

func TestCryptoSigner(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	keys := map[string]crypto.Signer{"rsa": rsaKey}
	for name, curve := range map[string]elliptic.Curve{"p256": elliptic.P256(), "p384": elliptic.P384(), "p521": elliptic.P521()} {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		keys[name] = k
	}

	created := time.Unix(1700000000, 0)

	for name, key := range keys {
		s, err := NewCryptoSigner(key, created, "HSM key", "", "hsm@example.com")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		again, err := NewCryptoSigner(key, created, "HSM key", "", "hsm@example.com")
		if err != nil || again.KeyFingerprint() != s.KeyFingerprint() {
			t.Fatalf("%s: fingerprint not stable: %v", name, err)
		}

		sig, err := s.DetachedSign(bytes.NewReader([]byte("data")))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		kr, err := s.Keyring()
		if err != nil {
			t.Fatal(err)
		}

		if _, err := VerifyDetached(kr, bytes.NewReader([]byte("data")), sig); err != nil {
			t.Fatalf("%s: verify: %v", name, err)
		}

		if _, err := VerifyDetached(kr, bytes.NewReader([]byte("other")), sig); err == nil {
			t.Fatalf("%s: verified altered data", name)
		}

		if _, err := s.PublicKey(); err != nil {
			t.Fatalf("%s: public key: %v", name, err)
		}

		if name != "rsa" && algorithmName(s.entity.PrimaryKey) != name {
			t.Fatalf("%s: named %s", name, algorithmName(s.entity.PrimaryKey))
		}

		if _, err := s.ExportPrivateKey(); !errors.Is(err, ErrPrivateKeyNotExportable) {
			t.Fatalf("%s: exported a private key it does not hold", name)
		}
		if _, err := s.ExportUnprotectedPrivateKey(); !errors.Is(err, ErrPrivateKeyNotExportable) {
			t.Fatalf("%s: unprotected export: %v", name, err)
		}
	}

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewCryptoSigner(edKey, created, "x", "", "x@example.com"); !errors.Is(err, ErrUnsupportedSigner) {
		t.Fatalf("ed25519: %v", err)
	}
}
