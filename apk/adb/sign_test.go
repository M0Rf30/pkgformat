package adb

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyPEMRoundTrip(t *testing.T) {
	rsaKey := keysOf(t)[0].signer.key
	ec256 := keysOf(t)[1].signer.key

	ec384, err := GenerateECKey(elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}

	ec521, err := GenerateECKey(elliptic.P521())
	if err != nil {
		t.Fatal(err)
	}

	for name, key := range map[string]crypto.Signer{"rsa": rsaKey, "p256": ec256, "p384": ec384, "p521": ec521} {
		priv, err := MarshalPrivateKeyPEM(key)
		if err != nil {
			t.Fatal(err)
		}

		back, err := ParsePrivateKeyPEM(priv)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		id1, err := KeyIDOf(key.Public())
		if err != nil {
			t.Fatal(err)
		}

		if id2, _ := KeyIDOf(back.Public()); id1 != id2 {
			t.Errorf("%s: key id changed through PEM", name)
		}

		pub, err := MarshalPublicKeyPEM(key.Public())
		if err != nil {
			t.Fatal(err)
		}

		pk, err := ParsePublicKeyPEM(pub)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if id3, _ := KeyIDOf(pk); id1 != id3 {
			t.Errorf("%s: public key id changed through PEM", name)
		}

		// A package signed with it verifies against its public key.
		s, err := NewSigner(back)
		if err != nil {
			t.Fatal(err)
		}

		var out bytes.Buffer

		spec := &Spec{Info: Info{Name: "k", Version: "1", Arch: "noarch"}}
		if _, err := WritePackage(&out, spec, WriteOptions{Signers: []*Signer{s}}); err != nil {
			t.Fatal(err)
		}

		kr := NewKeyring()
		if err := kr.Add(pk); err != nil {
			t.Fatal(err)
		}

		if _, got, err := VerifyPackage(&out, kr, ReadOptions{}); err != nil || got != id1 {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The other encodings apk and openssl write.
	der1 := x509.MarshalPKCS1PrivateKey(rsaKey.(*rsa.PrivateKey))

	der2, err := x509.MarshalECPrivateKey(ec256.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	for typ, der := range map[string][]byte{"RSA PRIVATE KEY": der1, "EC PRIVATE KEY": der2} {
		if _, err := ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})); err != nil {
			t.Errorf("%s: %v", typ, err)
		}
	}

	pkcs1 := x509.MarshalPKCS1PublicKey(&rsaKey.(*rsa.PrivateKey).PublicKey)
	if _, err := ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pkcs1})); err != nil {
		t.Errorf("RSA PUBLIC KEY: %v", err)
	}
}

func TestKeyErrors(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pkcs8 := func(k any) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}

	pkix := func(k any) []byte {
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			t.Fatal(err)
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}

	goodPub, _ := MarshalPublicKeyPEM(keysOf(t)[0].signer.key.Public())

	for name, f := range map[string]func() error{
		"private: no PEM":     func() error { _, err := ParsePrivateKeyPEM([]byte("junk")); return err },
		"private: wrong type": func() error { _, err := ParsePrivateKeyPEM(goodPub); return err },
		"private: bad DER": func() error {
			_, err := ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}))
			return err
		},
		"private: bad RSA DER": func() error {
			_, err := ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}}))
			return err
		},
		"private: bad EC DER": func() error {
			_, err := ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}))
			return err
		},
		"private: ed25519":   func() error { _, err := ParsePrivateKeyPEM(pkcs8(edPriv)); return err },
		"private: small RSA": func() error { _, err := ParsePrivateKeyPEM(pkcs8(small)); return err },
		"private: P-224":     func() error { _, err := ParsePrivateKeyPEM(pkcs8(p224)); return err },
		"public: no PEM":     func() error { _, err := ParsePublicKeyPEM(nil); return err },
		"public: wrong type": func() error { _, err := ParsePublicKeyPEM(pkcs8(small)); return err },
		"public: bad DER": func() error {
			_, err := ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}))
			return err
		},
		"public: bad RSA DER": func() error {
			_, err := ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: []byte{1}}))
			return err
		},
		"public: ed25519":       func() error { _, err := ParsePublicKeyPEM(pkix(edPub)); return err },
		"public: small RSA":     func() error { _, err := ParsePublicKeyPEM(pkix(&small.PublicKey)); return err },
		"KeyIDOf ed25519":       func() error { _, err := KeyIDOf(edPub); return err },
		"KeyIDOf small":         func() error { _, err := KeyIDOf(&small.PublicKey); return err },
		"KeyIDOf P-224":         func() error { _, err := KeyIDOf(&p224.PublicKey); return err },
		"NewSigner ed25519":     func() error { _, err := NewSigner(edPriv); return err },
		"Keyring.Add ed25519":   func() error { return NewKeyring().Add(edPub) },
		"Keyring.Add small":     func() error { return NewKeyring().Add(&small.PublicKey) },
		"GenerateKey small":     func() error { _, err := GenerateKey(1024); return err },
		"GenerateKey huge":      func() error { _, err := GenerateKey(1 << 20); return err },
		"GenerateECKey P-224":   func() error { _, err := GenerateECKey(elliptic.P224()); return err },
		"MarshalPublic ed25519": func() error { _, err := MarshalPublicKeyPEM(edPub); return err },
		"MarshalPrivate ed":     func() error { _, err := MarshalPrivateKeyPEM(edPriv); return err },
	} {
		if err := f(); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: %v, want ErrInvalidKey", name, err)
		}
	}
}

func TestLoadKeyring(t *testing.T) {
	dir := t.TempDir()
	rsaPub, _ := MarshalPublicKeyPEM(keysOf(t)[0].signer.key.Public())
	ecPub, _ := MarshalPublicKeyPEM(keysOf(t)[1].signer.key.Public())
	ecPriv, _ := MarshalPrivateKeyPEM(keysOf(t)[1].signer.key)

	for name, data := range map[string][]byte{
		"a.rsa.pub": rsaPub, "b.ec.pub": ecPub, "private.pem": ecPriv, "notes.txt": []byte("hello"), "empty": nil,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	kr, err := LoadKeyring(dir)
	if err != nil {
		t.Fatal(err)
	}

	if kr.Len() != 2 {
		t.Errorf("%d keys, want the two public ones", kr.Len())
	}

	if _, err := LoadKeyring(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing directory")
	}

	if _, err := LoadKeyring(filepath.Join(dir, "notes.txt")); err == nil {
		t.Error("a file is not a directory")
	}

	var nilRing *Keyring
	if nilRing.Len() != 0 {
		t.Error("nil keyring has keys")
	}

	// A nil keyring trusts nothing.
	if _, _, err := VerifyPackage(bytes.NewReader(signedBase(t)), nilRing, ReadOptions{}); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("nil keyring: %v", err)
	}
}

// bigSigner returns more than a signature block can hold.
type bigSigner struct{ crypto.Signer }

func (bigSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return make([]byte, 4096), nil
}

type failSigner struct{ crypto.Signer }

func (failSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("hsm unplugged")
}

func TestSignerFailures(t *testing.T) {
	inner := keysOf(t)[0].signer.key
	spec := &Spec{Info: Info{Name: "k", Version: "1", Arch: "noarch"}}

	for name, key := range map[string]crypto.Signer{"too large": bigSigner{inner}, "failing": failSigner{inner}} {
		s, err := NewSigner(key)
		if err != nil {
			t.Fatal(err)
		}

		_, err = WritePackage(io.Discard, spec, WriteOptions{Signers: []*Signer{s}})
		if err == nil {
			t.Errorf("%s: no error", name)
		}

		if name == "too large" && !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", name, err)
		}

		if err := BuildIndex(io.Discard, &Index{}, WriteOptions{Signers: []*Signer{s}}); err == nil {
			t.Errorf("%s: index signed", name)
		}
	}
}

func TestMultipleKeysSameID(t *testing.T) {
	good := keysOf(t)[0].signer.key.Public()
	kr := NewKeyring()

	if err := kr.Add(good); err != nil {
		t.Fatal(err)
	}

	if err := kr.Add(good); err != nil {
		t.Fatal(err)
	}

	if kr.Len() != 2 {
		t.Errorf("Len = %d", kr.Len())
	}

	if _, _, err := VerifyPackage(bytes.NewReader(signedBase(t)), kr, ReadOptions{}); err != nil {
		t.Error(err)
	}
}
