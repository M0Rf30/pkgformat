package gpg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// MaxKeyringBytes bounds the size of a keyring read from a reader or a file.
const MaxKeyringBytes = 16 << 20

// Sentinel errors of the verify side. Test with errors.Is; the cause reported
// by the OpenPGP library stays in the chain.
var (
	// ErrNoKeys is returned for a keyring that holds no usable public key.
	ErrNoKeys = errors.New("gpg: keyring holds no keys")
	// ErrKeyringTooLarge is returned for a keyring over MaxKeyringBytes.
	ErrKeyringTooLarge = errors.New("gpg: keyring too large")
	// ErrNotClearsigned is returned for input that is not a cleartext-signed
	// message.
	ErrNotClearsigned = errors.New("gpg: not a clear-signed message")
	// ErrUnsigned is returned for a cleartext message that carries no signature.
	ErrUnsigned = errors.New("gpg: message is not signed")
	// ErrUnknownSigner is returned when a well-formed signature was made by a
	// key that is not in the keyring. It differs from ErrBadSignature: the
	// signature may be genuine, the signer is merely not trusted yet.
	ErrUnknownSigner = errors.New("gpg: signature made by a key not in the keyring")
	// ErrBadSignature is returned when a signature is malformed or does not
	// match the data. It signals an attack or a broken mirror, never a missing
	// trust anchor.
	ErrBadSignature = errors.New("gpg: invalid signature")
	// ErrSignatureExpired is returned for a signature past its expiry.
	ErrSignatureExpired = errors.New("gpg: signature expired")
	// A signature made by an expired or revoked key fails with ErrKeyExpired
	// or ErrKeyRevoked, declared with the key errors.
)

// Keyring is a set of OpenPGP public keys a signature is checked against. The
// zero value and nil are empty keyrings.
type Keyring struct {
	entities openpgp.EntityList
}

// Len returns the number of primary keys in the keyring.
func (k *Keyring) Len() int {
	if k == nil {
		return 0
	}

	return len(k.entities)
}

// Entities returns the keys of the keyring as OpenPGP entities, for callers
// that check signatures themselves (see package rpm's Verify). The slice is
// a copy; the entities are shared. It is nil for an empty keyring.
func (k *Keyring) Entities() openpgp.EntityList {
	if k == nil {
		return nil
	}

	return slices.Clone(k.entities)
}

// Merge adds the keys of other to k. It is a no-op for a nil other.
func (k *Keyring) Merge(other *Keyring) {
	if other != nil {
		k.entities = append(k.entities, other.entities...)
	}
}

// ParseKeyring reads public keys from data, ASCII-armored or binary
// (auto-detected). It fails with ErrNoKeys when data holds none and with
// ErrKeyringTooLarge above MaxKeyringBytes.
func ParseKeyring(data []byte) (*Keyring, error) {
	if len(data) > MaxKeyringBytes {
		return nil, fmt.Errorf("%w: max %d bytes", ErrKeyringTooLarge, MaxKeyringBytes)
	}

	var (
		entities openpgp.EntityList
		err      error
	)

	if bytes.Contains(data, []byte("-----BEGIN PGP")) {
		entities, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	} else {
		entities, err = openpgp.ReadKeyRing(bytes.NewReader(data))
	}

	if err != nil {
		return nil, fmt.Errorf("gpg: read keyring: %w", err)
	}

	if len(entities) == 0 {
		return nil, ErrNoKeys
	}

	return &Keyring{entities: entities}, nil
}

// ReadKeyring is ParseKeyring over a reader, reading at most MaxKeyringBytes.
func ReadKeyring(r io.Reader) (*Keyring, error) {
	data, err := limitio.ReadAll(r, MaxKeyringBytes, ErrKeyringTooLarge)
	if err != nil {
		return nil, fmt.Errorf("gpg: read keyring: %w", err)
	}

	return ParseKeyring(data)
}

// LoadKeyringFile reads a keyring file, armored or binary.
func LoadKeyringFile(path string) (*Keyring, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("gpg: open keyring: %w", err)
	}

	defer func() { _ = f.Close() }()

	return ReadKeyring(f)
}

// LoadKeyringDir merges every *.gpg and *.asc file directly inside dir (not
// recursive, in name order). Entries that are unreadable or hold no key are
// skipped, as apt does for its trust directory; the result may therefore be
// empty (Len() == 0). An error is returned only when dir cannot be listed.
func LoadKeyringDir(dir string) (*Keyring, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("gpg: read keyring directory: %w", err)
	}

	combined := &Keyring{}

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || (!strings.HasSuffix(name, ".gpg") && !strings.HasSuffix(name, ".asc")) {
			continue
		}

		kr, err := LoadKeyringFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}

		combined.Merge(kr)
	}

	return combined, nil
}

// Keyring returns the public part of the signer's key as a Keyring, ready to
// verify what the signer signed.
func (s *LocalSigner) Keyring() (*Keyring, error) {
	var buf bytes.Buffer

	if err := s.entity.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("gpg: serialize public key: %w", err)
	}

	return ParseKeyring(buf.Bytes())
}

// Verified describes the key that produced a verified signature.
type Verified struct {
	// Identity is the primary user id ("Name (Comment) <email>"), or the key id
	// when the key carries none.
	Identity string
	// KeyID is the long (16 hex digit) key id of the primary key.
	KeyID string
	// Fingerprint is the upper-case hex fingerprint of the primary key.
	Fingerprint string
}

func describe(e *openpgp.Entity) Verified {
	if e == nil || e.PrimaryKey == nil {
		return Verified{}
	}

	v := Verified{
		KeyID:       fmt.Sprintf("%016X", e.PrimaryKey.KeyId),
		Fingerprint: fmt.Sprintf("%X", e.PrimaryKey.Fingerprint),
	}

	if id := e.PrimaryIdentity(); id != nil {
		v.Identity = id.Name
	} else if names := slices.Sorted(identityNames(e)); len(names) > 0 {
		v.Identity = names[0]
	}

	if v.Identity == "" {
		v.Identity = v.KeyID
	}

	return v
}

func identityNames(e *openpgp.Entity) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		for name := range e.Identities {
			if !yield(name) {
				return
			}
		}
	}
}

// VerifyClearsigned verifies an inline clear-signed message (an InRelease
// file) against kr and returns the unwrapped body. The body is LF-terminated:
// CRLF line endings are normalised and dash-escaping is undone. Data after the
// signature block is ignored.
func VerifyClearsigned(kr *Keyring, signed []byte) (body []byte, v Verified, err error) {
	if kr.Len() == 0 {
		return nil, Verified{}, ErrNoKeys
	}

	block, _ := clearsign.Decode(signed)
	if block == nil {
		return nil, Verified{}, ErrNotClearsigned
	}

	if block.ArmoredSignature == nil {
		return nil, Verified{}, ErrUnsigned
	}

	signer, err := openpgp.CheckDetachedSignature(kr.entities, bytes.NewReader(block.Bytes),
		block.ArmoredSignature.Body, nil)
	if err != nil {
		return nil, Verified{}, classify(err)
	}

	return block.Plaintext, describe(signer), nil
}

// VerifyDetached verifies data against a detached signature. sig may be
// binary (a pacman .sig file, an RPM header signature) or ASCII-armored
// (Release.gpg, repomd.xml.asc, .deb.asc); the form is detected.
func VerifyDetached(kr *Keyring, data io.Reader, sig []byte) (Verified, error) {
	if kr.Len() == 0 {
		return Verified{}, ErrNoKeys
	}

	var (
		signer *openpgp.Entity
		err    error
	)

	if bytes.HasPrefix(bytes.TrimLeft(sig, " \t\r\n"), []byte("-----BEGIN PGP")) {
		signer, err = openpgp.CheckArmoredDetachedSignature(kr.entities, data, bytes.NewReader(sig), nil)
	} else {
		signer, err = openpgp.CheckDetachedSignature(kr.entities, data, bytes.NewReader(sig), nil)
	}

	if err != nil {
		return Verified{}, classify(err)
	}

	return describe(signer), nil
}

// classify maps the OpenPGP library's errors onto this package's sentinels.
// The original error stays in the chain.
func classify(err error) error {
	switch {
	case errors.Is(err, pgperrors.ErrUnknownIssuer):
		return fmt.Errorf("%w: %w", ErrUnknownSigner, err)
	case errors.Is(err, pgperrors.ErrSignatureExpired):
		return fmt.Errorf("%w: %w", ErrSignatureExpired, err)
	case errors.Is(err, pgperrors.ErrKeyExpired):
		return fmt.Errorf("%w: %w", ErrKeyExpired, err)
	case errors.Is(err, pgperrors.ErrKeyRevoked):
		return fmt.Errorf("%w: %w", ErrKeyRevoked, err)
	}

	if _, ok := errors.AsType[pgperrors.SignatureError](err); ok {
		return fmt.Errorf("%w: %w", ErrBadSignature, err)
	}

	if _, ok := errors.AsType[pgperrors.StructuralError](err); ok {
		return fmt.Errorf("%w: %w", ErrBadSignature, err)
	}

	if _, ok := errors.AsType[pgperrors.UnsupportedError](err); ok {
		return fmt.Errorf("%w: %w", ErrBadSignature, err)
	}

	return fmt.Errorf("gpg: verify: %w", err)
}
