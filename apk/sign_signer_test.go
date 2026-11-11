package apk

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"strings"
	"testing"
)

// opaqueSigner exposes only the crypto.Signer methods, as an HSM or KMS
// client does: the private key is out of reach.
type opaqueSigner struct{ key *rsa.PrivateKey }

func (o opaqueSigner) Public() crypto.PublicKey { return &o.key.PublicKey }

func (o opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.key.Sign(r, digest, opts)
}

type badSigner struct {
	opaqueSigner
	mode string
}

func (b badSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch b.mode {
	case "error":
		return nil, errors.New("kms unavailable")
	case "long":
		return make([]byte, maxSignatureLen+1), nil
	default: // a valid signature of other data
		return b.key.Sign(r, make([]byte, len(digest)), opts)
	}
}

type pubSigner struct{ pub crypto.PublicKey }

func (p pubSigner) Public() crypto.PublicKey { return p.pub }

func (pubSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }

func TestSigner_opaque(t *testing.T) {
	key := testKey(t)

	for _, alg := range []SigAlgorithm{SigRSASHA1, SigRSASHA256} {
		s, err := NewSigner("hsm@example.org-1a2b3c4d.rsa.pub", opaqueSigner{key}, alg)
		if err != nil {
			t.Fatal(err)
		}

		raw, _ := mustWrite(t, sampleSpec(), WriteOptions{Signer: s, TempDir: t.TempDir()})

		ring := NewKeyring()
		if err := ring.Add(s.KeyName(), s.PublicKey()); err != nil {
			t.Fatal(err)
		}

		if _, err := VerifyPackage(bytes.NewReader(raw), int64(len(raw)), VerifyOptions{Keys: ring, Algorithms: []SigAlgorithm{alg}}); err != nil {
			t.Fatalf("%v: %v", alg, err)
		}
	}
}

func TestNewSigner_rejects(t *testing.T) {
	key := testKey(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	for name, k := range map[string]crypto.Signer{
		"nil":         nil,
		"ecdsa":       ec,
		"small":       opaqueSigner{small},
		"nil public":  pubSigner{pub: nil},
		"empty N":     pubSigner{pub: &rsa.PublicKey{}},
		"wrong type":  pubSigner{pub: "x"},
		"nil rsa key": (*rsa.PrivateKey)(nil),
	} {
		if _, err := NewSigner("a.rsa.pub", k, SigRSASHA256); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	if _, err := NewSigner("a.rsa.pub", opaqueSigner{key}, 0); !errors.Is(err, ErrNoAlgorithm) {
		t.Errorf("zero algorithm: %v", err)
	}

	if _, err := NewSigner("bad name", opaqueSigner{key}, SigRSASHA1); err == nil {
		t.Error("bad key name accepted")
	}
}

func TestSigner_misbehaving(t *testing.T) {
	key := testKey(t)

	for _, mode := range []string{"error", "long", "wrong"} {
		s, err := NewSigner("a.rsa.pub", badSigner{opaqueSigner{key}, mode}, SigRSASHA256)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := s.Sign([]byte("data")); !errors.Is(err, ErrSign) {
			t.Errorf("%s: got %v, want ErrSign", mode, err)
		}

		if _, err := WritePackage(io.Discard, sampleSpec(), WriteOptions{Signer: s, TempDir: t.TempDir()}); !errors.Is(err, ErrSign) {
			t.Errorf("%s: WritePackage %v", mode, err)
		}
	}
}

func TestKeyPEM_formats(t *testing.T) {
	key := testKey(t)

	for name, pem := range map[string][]byte{
		"pkcs8": MarshalPrivateKeyPEM(key),
		"pkcs1": MarshalPrivateKeyPKCS1PEM(key),
	} {
		got, err := ParsePrivateKeyPEM(pem)
		if err != nil || !got.Equal(key) {
			t.Errorf("%s: %v", name, err)
		}
	}

	if !bytes.Contains(MarshalPrivateKeyPKCS1PEM(key), []byte("RSA PRIVATE KEY")) ||
		!bytes.Contains(MarshalPrivateKeyPEM(key), []byte("BEGIN PRIVATE KEY")) {
		t.Error("PEM types")
	}

	if MarshalPrivateKeyPKCS1PEM(nil) != nil || MarshalPublicKeyPEM(nil) != nil || MarshalPublicKeyPEM(&rsa.PublicKey{}) != nil {
		t.Error("nil keys must give nil")
	}

	pub, err := ParsePublicKeyPEM(MarshalPublicKeyPEM(&key.PublicKey))
	if err != nil || !pub.Equal(&key.PublicKey) {
		t.Fatalf("public key round trip: %v", err)
	}

	name, err := PublicKeyName("me@example.org", &key.PublicKey)
	if err != nil || !strings.HasPrefix(name, "me@example.org-") || !strings.HasSuffix(name, ".rsa.pub") || len(name) != len("me@example.org-")+8+len(".rsa.pub") {
		t.Fatalf("name %q, %v", name, err)
	}

	again, _ := PublicKeyName("me@example.org", &key.PublicKey)
	if again != name {
		t.Error("name is not stable")
	}

	if _, err := PublicKeyName("bad owner", &key.PublicKey); err == nil {
		t.Error("owner with a space accepted")
	}

	if _, err := PublicKeyName("x", nil); err == nil {
		t.Error("nil key accepted")
	}

	if _, err := NewSigner(name, key, SigRSASHA256); err != nil {
		t.Errorf("generated name is not a valid key name: %v", err)
	}
}
