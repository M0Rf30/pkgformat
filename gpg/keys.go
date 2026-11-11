package gpg

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Algorithm names a key type GenerateEntity can generate.
type Algorithm string

const (
	// AlgorithmED25519 is an EdDSA key over Curve25519 (OpenPGP algorithm 22,
	// understood by GnuPG >= 2.1, apt's gpgv/sqv and dnf).
	AlgorithmED25519 Algorithm = "ed25519"
	// AlgorithmRSA4096 is a 4096-bit RSA key, the most widely compatible choice.
	AlgorithmRSA4096 Algorithm = "rsa4096"
	// AlgorithmRSA3072 is a 3072-bit RSA key, the GnuPG default size.
	AlgorithmRSA3072 Algorithm = "rsa3072"
	// AlgorithmP256 and AlgorithmP384 are ECDSA keys over NIST P-256 and P-384
	// (OpenPGP algorithm 19).
	AlgorithmP256 Algorithm = "p256"
	AlgorithmP384 Algorithm = "p384"
	// AlgorithmED25519V6 and AlgorithmED448V6 are version 6 keys (RFC 9580)
	// with the native Ed25519 and Ed448 algorithms (27 and 28), understood
	// by rpm 6 (Sequoia) and GnuPG-incompatible tools only.
	AlgorithmED25519V6 Algorithm = "ed25519-v6"
	AlgorithmED448V6   Algorithm = "ed448-v6"
)

// Sentinel errors for key parsing.
var (
	ErrUnsupportedAlgorithm = errors.New("unsupported key algorithm")
	ErrInvalidKey           = errors.New("not an ASCII-armored OpenPGP key")
	ErrNotPrivateKey        = errors.New("armored block does not contain a private key")
	ErrPassphraseRequired   = errors.New("private key is passphrase-protected")
	ErrBadPassphrase        = errors.New("wrong passphrase for private key")
	ErrKeyCannotSign        = errors.New("key cannot sign")
	ErrKeyRevoked           = errors.New("key is revoked")
	ErrKeyExpired           = errors.New("key is expired")
)

// KeyInfo is the public description of a signing key.
type KeyInfo struct {
	// Fingerprint is the upper-case hex fingerprint of the primary key.
	Fingerprint string
	// KeyID is the long (16 hex digit) key id.
	KeyID string
	// Algorithm is "ed25519", "rsa<bits>" or the OpenPGP algorithm name.
	Algorithm string
	// UserID is the primary user id ("Name (Comment) <email>"), if any.
	UserID string
	// ExpiresAt is nil for keys that never expire.
	ExpiresAt *time.Time
}

// ParseAlgorithm validates an algorithm name; the empty string selects ed25519.
func ParseAlgorithm(s string) (Algorithm, error) {
	switch a := Algorithm(strings.ToLower(strings.TrimSpace(s))); a {
	case "":
		return AlgorithmED25519, nil
	case AlgorithmED25519, AlgorithmRSA4096, AlgorithmRSA3072, AlgorithmP256, AlgorithmP384,
		AlgorithmED25519V6, AlgorithmED448V6:
		return a, nil
	default:
		return "", fmt.Errorf("%w: %q (use ed25519, rsa4096, rsa3072, p256, p384, ed25519-v6 or ed448-v6)",
			ErrUnsupportedAlgorithm, s)
	}
}

// GenerateEntity generates a new key pair of the given type.
func GenerateEntity(name, comment, email string, alg Algorithm) (*openpgp.Entity, error) {
	config := &packet.Config{
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}

	switch alg {
	case AlgorithmRSA4096:
		config.RSABits = 4096
	case AlgorithmRSA3072:
		config.RSABits = 3072
	case AlgorithmED25519:
		config.Algorithm = packet.PubKeyAlgoEdDSA
		config.Curve = packet.Curve25519
	case AlgorithmP256:
		config.Algorithm = packet.PubKeyAlgoECDSA
		config.Curve = packet.CurveNistP256
	case AlgorithmP384:
		config.Algorithm = packet.PubKeyAlgoECDSA
		config.Curve = packet.CurveNistP384
		config.DefaultHash = crypto.SHA384
	case AlgorithmED25519V6:
		config.Algorithm = packet.PubKeyAlgoEd25519
		config.V6Keys = true
	case AlgorithmED448V6:
		config.Algorithm = packet.PubKeyAlgoEd448
		config.V6Keys = true
		config.DefaultHash = crypto.SHA512
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
	}

	entity, err := openpgp.NewEntity(name, comment, email, config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	for _, id := range entity.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, entity.PrimaryKey, entity.PrivateKey, config)
		if err != nil {
			return nil, fmt.Errorf("failed to self-sign identity: %w", err)
		}
	}

	return entity, nil
}

// NewLocalSignerFromEntity wraps an entity that carries a decrypted private key.
func NewLocalSignerFromEntity(entity *openpgp.Entity) (*LocalSigner, error) {
	if err := checkSigningEntity(entity, time.Now()); err != nil {
		return nil, err
	}

	return &LocalSigner{entity: entity}, nil
}

// ParsePrivateKey reads the first key of an armored private key block, unlocks
// it with passphrase when it is protected, and verifies that it can sign and is
// neither revoked nor expired.
func ParsePrivateKey(armored io.Reader, passphrase []byte) (*LocalSigner, error) {
	entities, err := openpgp.ReadArmoredKeyRing(armored)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	if len(entities) == 0 {
		return nil, ErrNoKeysFound
	}

	entity := entities[0]

	if entity.PrivateKey == nil {
		return nil, ErrNotPrivateKey
	}

	if entity.PrivateKey.Encrypted {
		if len(passphrase) == 0 {
			return nil, ErrPassphraseRequired
		}

		if err := decryptEntity(entity, passphrase); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBadPassphrase, err)
		}
	}

	return NewLocalSignerFromEntity(entity)
}

// decryptEntity decrypts the primary key and every encrypted subkey with the
// passphrase. go-crypto prefers a signing-capable subkey over the primary key,
// so subkeys must be unlocked too. A subkey that cannot be decrypted is
// tolerated unless it is the key that would actually sign.
func decryptEntity(entity *openpgp.Entity, passphrase []byte) error {
	if entity.PrivateKey.Encrypted {
		if err := entity.PrivateKey.Decrypt(passphrase); err != nil {
			return err
		}
	}

	var subkeyErr error

	for i := range entity.Subkeys {
		priv := entity.Subkeys[i].PrivateKey
		if priv == nil || priv.Dummy() || !priv.Encrypted {
			continue
		}

		if err := priv.Decrypt(passphrase); err != nil && subkeyErr == nil {
			subkeyErr = err
		}
	}

	if subkeyErr == nil {
		return nil
	}

	// Only fail if the key selected for signing is still locked.
	if key, ok := entity.SigningKey(time.Now()); ok && key.PrivateKey != nil && key.PrivateKey.Encrypted {
		return subkeyErr
	}

	return nil
}

func checkSigningEntity(entity *openpgp.Entity, now time.Time) error {
	if entity == nil || entity.PrivateKey == nil || entity.PrivateKey.Encrypted {
		return ErrNotPrivateKey
	}

	if !entity.PrimaryKey.PubKeyAlgo.CanSign() {
		return ErrKeyCannotSign
	}

	if entity.Revoked(now) {
		return ErrKeyRevoked
	}

	if exp := keyExpiry(entity); exp != nil && !exp.After(now) {
		return ErrKeyExpired
	}

	if key, ok := entity.SigningKey(now); !ok || key.PrivateKey == nil || key.PrivateKey.Encrypted {
		return ErrKeyCannotSign
	}

	return nil
}

func keyExpiry(entity *openpgp.Entity) *time.Time {
	sig, _ := entity.PrimarySelfSignature()
	if sig == nil || sig.KeyLifetimeSecs == nil || *sig.KeyLifetimeSecs == 0 {
		return nil
	}

	exp := entity.PrimaryKey.CreationTime.Add(time.Duration(*sig.KeyLifetimeSecs) * time.Second)

	return &exp
}

// Info describes the key.
func (s *LocalSigner) Info() KeyInfo {
	pk := s.entity.PrimaryKey
	info := KeyInfo{
		Fingerprint: s.KeyFingerprint(),
		KeyID:       s.KeyID(),
		Algorithm:   algorithmName(pk),
		ExpiresAt:   keyExpiry(s.entity),
	}

	if _, ident := s.entity.PrimarySelfSignature(); ident != nil && ident.UserId != nil {
		info.UserID = ident.UserId.Id
	}

	return info
}

func algorithmName(pk *packet.PublicKey) string {
	switch pk.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		if bits, err := pk.BitLength(); err == nil {
			return fmt.Sprintf("rsa%d", bits)
		}

		return "rsa"
	case packet.PubKeyAlgoEdDSA, packet.PubKeyAlgoEd25519:
		return string(AlgorithmED25519)
	case packet.PubKeyAlgoEd448:
		return "ed448"
	case packet.PubKeyAlgoECDSA:
		if bits := ecdsaCurveBits(pk); bits != 0 {
			return fmt.Sprintf("p%d", bits)
		}

		return "ecdsa"
	case packet.PubKeyAlgoDSA:
		return "dsa"
	default:
		return fmt.Sprintf("algo%d", pk.PubKeyAlgo)
	}
}

// ExportUnprotectedPrivateKey serialises the private key without passphrase
// protection, as an armored block. The caller must seal the result before it
// is stored anywhere.
func (s *LocalSigner) ExportUnprotectedPrivateKey() ([]byte, error) {
	var buf bytes.Buffer

	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create armor encoder: %w", err)
	}

	if err := s.entity.SerializePrivateWithoutSigning(w, nil); err != nil {
		return nil, fmt.Errorf("failed to serialize private key: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to finish armor: %w", err)
	}

	return buf.Bytes(), nil
}
