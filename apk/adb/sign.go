package adb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Digest algorithms of a signature, numbered as in the file.
const (
	// DigestSHA256 signs the SHA-256 of the ADB block.
	DigestSHA256 uint8 = 3
	// DigestSHA512 signs the SHA-512 of the ADB block. It is what this
	// package writes.
	DigestSHA512 uint8 = 4
	// DigestSHA256_160 signs the first 20 bytes of the SHA-256 of the ADB
	// block.
	DigestSHA256_160 uint8 = 5
)

const (
	// KeyIDSize is the size of a key id.
	KeyIDSize = 16

	minRSABits = 2048
	maxRSABits = 16384

	// sigHdrSize is the signature header: version, digest algorithm and key id.
	sigHdrSize = 2 + KeyIDSize
)

// KeyID is the identifier a signature carries to name its key: the first 16
// bytes of the SHA-512 of the public key, as the DER RSAPublicKey (PKCS #1) of
// an RSA key and the uncompressed point of an EC key.
type KeyID [KeyIDSize]byte

// Signature is a signature block of a file.
type Signature struct {
	// Version is the signature format; only 0 is defined.
	Version uint8
	// Digest is the algorithm of the digest of the ADB block that is signed.
	Digest uint8
	// KeyID names the key.
	KeyID KeyID
	// Data is the signature.
	Data []byte
}

func parseSignature(p []byte) (Signature, error) {
	if len(p) < 2 {
		return Signature{}, blockErr("signature block of %d bytes", len(p))
	}

	s := Signature{Version: p[0], Digest: p[1]}
	if s.Version != 0 {
		return s, nil
	}

	if len(p) < sigHdrSize {
		return Signature{}, blockErr("signature block of %d bytes", len(p))
	}

	copy(s.KeyID[:], p[2:sigHdrSize])
	s.Data = append([]byte(nil), p[sigHdrSize:]...)

	return s, nil
}

// checkKey validates a public key and returns its id.
func checkKey(pub crypto.PublicKey) (KeyID, error) {
	var id KeyID

	switch k := pub.(type) {
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < minRSABits || bits > maxRSABits {
			return id, fmt.Errorf("%w: RSA key of %d bits, want %d to %d", ErrInvalidKey, bits, minRSABits, maxRSABits)
		}

		sum := sha512.Sum512(x509.MarshalPKCS1PublicKey(k))
		copy(id[:], sum[:])
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
		default:
			return id, fmt.Errorf("%w: unsupported elliptic curve", ErrInvalidKey)
		}

		point, err := k.Bytes()
		if err != nil {
			return id, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}

		sum := sha512.Sum512(point)
		copy(id[:], sum[:])
	default:
		return id, fmt.Errorf("%w: %T is neither an RSA nor an ECDSA key", ErrInvalidKey, pub)
	}

	return id, nil
}

// KeyIDOf returns the id of a public key: an *rsa.PublicKey of 2048 to 16384
// bits or an *ecdsa.PublicKey on P-256, P-384 or P-521. Ed25519 keys are not
// supported by the format as apk-tools implements it.
func KeyIDOf(pub crypto.PublicKey) (KeyID, error) { return checkKey(pub) }

// signedDigest is what is fed to the key: the schema, the signature header and
// the digest of the ADB block, hashed with SHA-512.
func signedDigest(schema uint32, version, alg uint8, id KeyID, md []byte) []byte {
	msg := binary.LittleEndian.AppendUint32(nil, schema)
	msg = append(msg, version, alg)
	msg = append(msg, id[:]...)
	msg = append(msg, md...)
	sum := sha512.Sum512(msg)

	return sum[:]
}

// adbDigest returns the digest of the ADB block named by a signature
// algorithm, or nil when the algorithm is not known.
func adbDigest(alg uint8, adbBlock []byte) []byte {
	switch alg {
	case DigestSHA256:
		sum := sha256.Sum256(adbBlock)

		return sum[:]
	case DigestSHA256_160:
		sum := sha256.Sum256(adbBlock)

		return sum[:20]
	case DigestSHA512:
		sum := sha512.Sum512(adbBlock)

		return sum[:]
	default:
		return nil
	}
}

// Signer signs the ADB block of a file.
type Signer struct {
	key crypto.Signer
	id  KeyID
}

// NewSigner returns a signer that uses key: an *rsa.PrivateKey of 2048 to
// 16384 bits or an *ecdsa.PrivateKey on P-256, P-384 or P-521. RSA signs with
// PKCS #1 v1.5 and EC with ECDSA, both over SHA-512.
func NewSigner(key crypto.Signer) (*Signer, error) {
	id, err := checkKey(key.Public())
	if err != nil {
		return nil, err
	}

	return &Signer{key: key, id: id}, nil
}

// KeyID returns the id of the key of the signer.
func (s *Signer) KeyID() KeyID { return s.id }

// sign returns the payload of the signature block of an ADB block.
func (s *Signer) sign(schema uint32, adbBlock []byte) ([]byte, error) {
	md := adbDigest(DigestSHA512, adbBlock)
	digest := signedDigest(schema, 0, DigestSHA512, s.id, md)

	sig, err := s.key.Sign(rand.Reader, digest, crypto.SHA512)
	if err != nil {
		return nil, fmt.Errorf("adb: signing: %w", err)
	}

	if len(sig)+sigHdrSize > maxSignature {
		return nil, fmt.Errorf("%w: signature of %d bytes", ErrTooLarge, len(sig))
	}

	out := append([]byte{0, DigestSHA512}, s.id[:]...)

	return append(out, sig...), nil
}

// verify reports whether the signature was made by pub over the ADB block.
func (s Signature) verify(pub crypto.PublicKey, schema uint32, adbBlock []byte) bool {
	if s.Version != 0 {
		return false
	}

	md := adbDigest(s.Digest, adbBlock)
	if md == nil {
		return false
	}

	digest := signedDigest(schema, s.Version, s.Digest, s.KeyID, md)

	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA512, digest, s.Data) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, digest, s.Data)
	default:
		return false
	}
}

// Keyring is a set of trusted public keys.
type Keyring struct {
	keys map[KeyID][]crypto.PublicKey
	n    int
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring { return &Keyring{keys: make(map[KeyID][]crypto.PublicKey)} }

// Add trusts a public key. See [KeyIDOf] for the types it takes.
func (k *Keyring) Add(pub crypto.PublicKey) error {
	id, err := checkKey(pub)
	if err != nil {
		return err
	}

	k.keys[id] = append(k.keys[id], pub)
	k.n++

	return nil
}

// Len returns the number of keys.
func (k *Keyring) Len() int {
	if k == nil {
		return 0
	}

	return k.n
}

const maxKeyFiles = 4096

// LoadKeyring reads the public keys of a directory in the PEM format apk uses
// for its keys directory (/etc/apk/keys). Files that are not a supported
// public key are skipped, as apk does.
func LoadKeyring(dir string) (*Keyring, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("adb: reading keys directory: %w", err)
	}

	if len(entries) > maxKeyFiles {
		return nil, fmt.Errorf("adb: keys directory %q holds more than %d files", dir, maxKeyFiles)
	}

	kr := NewKeyring()

	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("adb: reading key %q: %w", e.Name(), err)
		}

		// ParsePublicKeyPEM has validated the key, so Add cannot fail.
		if pub, err := ParsePublicKeyPEM(data); err == nil {
			_ = kr.Add(pub)
		}
	}

	return kr, nil
}

// trustedBy checks the signatures of a file against the keyring. It returns
// the key that verified one, or ErrUnsigned, ErrBadSignature or ErrUntrusted.
func (k *Keyring) trustedBy(sigs []Signature, schema uint32, adbBlock []byte) (KeyID, error) {
	if len(sigs) == 0 {
		return KeyID{}, ErrUnsigned
	}

	if k.Len() == 0 {
		return KeyID{}, ErrNoKeyring
	}

	bad := false

	for _, s := range sigs {
		for _, pub := range k.keys[s.KeyID] {
			if s.verify(pub, schema, adbBlock) {
				return s.KeyID, nil
			}

			bad = true
		}
	}

	if bad {
		return KeyID{}, ErrBadSignature
	}

	return KeyID{}, ErrUntrusted
}

// GenerateKey creates an RSA key of the given size in bits.
func GenerateKey(bits int) (*rsa.PrivateKey, error) {
	if bits < minRSABits || bits > maxRSABits {
		return nil, fmt.Errorf("%w: RSA key of %d bits, want %d to %d", ErrInvalidKey, bits, minRSABits, maxRSABits)
	}

	return rsa.GenerateKey(rand.Reader, bits)
}

// GenerateECKey creates an ECDSA key on the given curve: P-256, P-384 or P-521.
func GenerateECKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	switch curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
	default:
		return nil, fmt.Errorf("%w: unsupported elliptic curve", ErrInvalidKey)
	}

	return ecdsa.GenerateKey(curve, rand.Reader)
}

// ParsePrivateKeyPEM parses a private key in PEM: PKCS #8, PKCS #1 (RSA) or
// SEC 1 (EC), as the files apk reads.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", ErrInvalidKey)
	}

	var (
		key any
		err error
	)

	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: PEM block %q", ErrInvalidKey, block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: %T cannot sign", ErrInvalidKey, key)
	}

	if _, err := checkKey(signer.Public()); err != nil {
		return nil, err
	}

	return signer, nil
}

// ParsePublicKeyPEM parses a public key in PEM: PKIX ("PUBLIC KEY") or PKCS #1
// ("RSA PUBLIC KEY").
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", ErrInvalidKey)
	}

	var (
		pub any
		err error
	)

	switch block.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: PEM block %q", ErrInvalidKey, block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	if _, err := checkKey(pub); err != nil {
		return nil, err
	}

	return pub, nil
}

// MarshalPublicKeyPEM encodes a public key as PKIX PEM, the format of the
// files in an apk keys directory.
func MarshalPublicKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	if _, err := checkKey(pub); err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// MarshalPrivateKeyPEM encodes a private key as PKCS #8 PEM.
func MarshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	if _, err := checkKey(key.Public()); err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
