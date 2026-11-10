package apk

import (
	"archive/tar"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // the abuild-compatible signature type is RSA over SHA-1
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SigAlgorithm selects the signature type of an abuild signature entry. The
// zero value is invalid: every caller states which type it signs with or
// accepts.
type SigAlgorithm int

const (
	// SigRSASHA1 is RSA PKCS#1 v1.5 over SHA-1, the entry
	// .SIGN.RSA.<key name>: what abuild-sign writes and every apk-tools
	// version verifies.
	SigRSASHA1 SigAlgorithm = iota + 1
	// SigRSASHA256 is RSA PKCS#1 v1.5 over SHA-256, the entry
	// .SIGN.RSA256.<key name>.
	SigRSASHA256
)

// Entry name prefixes of the two signature types.
const (
	sigRSA1Prefix   = ".SIGN.RSA."
	sigRSA256Prefix = ".SIGN.RSA256."
)

// ErrNoAlgorithm is returned when a signer, a verifier or a client is used
// without choosing a [SigAlgorithm].
var ErrNoAlgorithm = errors.New("apk: no signature algorithm chosen")

func (a SigAlgorithm) valid() bool { return a == SigRSASHA1 || a == SigRSASHA256 }

// String returns "RSA-SHA1", "RSA-SHA256" or "invalid".
func (a SigAlgorithm) String() string {
	switch a {
	case SigRSASHA1:
		return "RSA-SHA1"
	case SigRSASHA256:
		return "RSA-SHA256"
	default:
		return "invalid"
	}
}

// prefix returns the tar entry name prefix of the algorithm.
func (a SigAlgorithm) prefix() string {
	if a == SigRSASHA256 {
		return sigRSA256Prefix
	}

	return sigRSA1Prefix
}

// hash returns the digest function and the digest of data.
func (a SigAlgorithm) digest(data []byte) (crypto.Hash, []byte) {
	if a == SigRSASHA256 {
		sum := sha256.Sum256(data)

		return crypto.SHA256, sum[:]
	}

	sum := sha1.Sum(data) //nolint:gosec // see the import

	return crypto.SHA1, sum[:]
}

// Key size bounds. Alpine's own keys are 4096 bits; apk accepts what OpenSSL
// can verify. The upper bound only stops a caller from asking for a key that
// takes minutes to generate or verify.
const (
	minKeyBits = 2048
	maxKeyBits = 16384

	keyNameSuffix = ".rsa.pub"

	// maxEntryName is the length of a ustar header name, so a signature needs
	// no PAX or GNU extension header, which apk's tar reader does not have to
	// understand.
	maxEntryName = 100

	// maxSignatureLen bounds one signature entry: 16384 bits are 2048 bytes.
	maxSignatureLen = 4096
	maxSignatures   = 16

	pemPublic    = "PUBLIC KEY"
	pemPublicRSA = "RSA PUBLIC KEY"
	pemPKCS8     = "PRIVATE KEY"
	pemPKCS1     = "RSA PRIVATE KEY"
)

var (
	errKey    = errors.New("invalid signing key")
	errNotRSA = errors.New("not an RSA key")
)

// Signer signs packages and indexes with an RSA key under the name apk looks
// the public key up by: the file name in its keys directory.
type Signer struct {
	name string
	alg  SigAlgorithm
	key  *rsa.PrivateKey
	spki []byte
}

// validKeyName reports whether s is ^[A-Za-z0-9._@+-]+\.rsa\.pub$.
func validKeyName(s string) bool {
	base, ok := strings.CutSuffix(s, keyNameSuffix)
	if !ok || base == "" {
		return false
	}

	for i := range len(base) {
		c := base[i]
		if !isAlnum(c) && c != '.' && c != '_' && c != '@' && c != '+' && c != '-' {
			return false
		}
	}

	return true
}

// NewSigner returns a Signer for key that writes signatures of type alg.
// keyName must match ^[A-Za-z0-9._@+-]+\.rsa\.pub$ and keep the entry name
// (the type's prefix and keyName) within 100 bytes, and the key must be a
// valid RSA key of 2048 to 16384 bits. A zero alg is [ErrNoAlgorithm].
func NewSigner(keyName string, key *rsa.PrivateKey, alg SigAlgorithm) (*Signer, error) {
	if !alg.valid() {
		return nil, ErrNoAlgorithm
	}

	if !validKeyName(keyName) || len(alg.prefix())+len(keyName) > maxEntryName {
		return nil, fmt.Errorf("%w: key name %q must match [A-Za-z0-9._@+-]+%s and fit %d bytes with %s",
			errKey, short(keyName), keyNameSuffix, maxEntryName, alg.prefix())
	}

	if err := checkPrivateKey(key); err != nil {
		return nil, err
	}

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errKey, err)
	}

	return &Signer{name: keyName, alg: alg, key: key, spki: spki}, nil
}

func checkPrivateKey(key *rsa.PrivateKey) error {
	if key == nil || key.N == nil {
		return fmt.Errorf("%w: no key", errKey)
	}

	if bits := key.N.BitLen(); bits < minKeyBits || bits > maxKeyBits {
		return fmt.Errorf("%w: %d bits, want %d to %d", errKey, bits, minKeyBits, maxKeyBits)
	}

	if err := key.Validate(); err != nil {
		return fmt.Errorf("%w: %w", errKey, err)
	}

	return nil
}

// KeyName returns the name of the public key, as given to NewSigner.
func (s *Signer) KeyName() string { return s.name }

// Algorithm returns the signature type the Signer writes.
func (s *Signer) Algorithm() SigAlgorithm { return s.alg }

// EntryName returns the name of the signature tar entry:
// .SIGN.RSA.<KeyName> or .SIGN.RSA256.<KeyName>.
func (s *Signer) EntryName() string { return s.alg.prefix() + s.name }

// PublicKey returns the public half of the signing key.
func (s *Signer) PublicKey() *rsa.PublicKey { return &s.key.PublicKey }

// PublicKeyPEM returns the public key as a "PUBLIC KEY" (SubjectPublicKeyInfo)
// PEM block: what apk keeps in its keys directory.
func (s *Signer) PublicKeyPEM() ([]byte, error) {
	out := pem.EncodeToMemory(&pem.Block{Type: pemPublic, Bytes: s.spki})
	if out == nil {
		return nil, fmt.Errorf("%w: cannot encode the public key", errKey)
	}

	return out, nil
}

// Sign returns the RSA PKCS#1 v1.5 signature of the digest of data: the
// content of the [Signer.EntryName] entry. For a package data is the control
// segment, for an index the index segment; [WritePackage], [SignPackage] and
// [BuildIndex] do that.
func (s *Signer) Sign(data []byte) ([]byte, error) {
	h, sum := s.alg.digest(data)

	return rsa.SignPKCS1v15(rand.Reader, s.key, h, sum)
}

// Fingerprint returns the hex SHA-256 of the DER SubjectPublicKeyInfo.
func (s *Signer) Fingerprint() string {
	sum := sha256.Sum256(s.spki)

	return hex.EncodeToString(sum[:])
}

// GenerateKey generates an RSA key of bits bits, which must be between 2048
// and 16384.
func GenerateKey(bits int) (*rsa.PrivateKey, error) {
	if bits < minKeyBits || bits > maxKeyBits {
		return nil, fmt.Errorf("%w: %d bits, want %d to %d", errKey, bits, minKeyBits, maxKeyBits)
	}

	return rsa.GenerateKey(rand.Reader, bits)
}

// MarshalPrivateKeyPEM encodes k as a PKCS#8 "PRIVATE KEY" PEM block. It
// returns nil for a key that cannot be encoded.
func MarshalPrivateKeyPEM(k *rsa.PrivateKey) []byte {
	if k == nil {
		return nil
	}

	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil
	}

	return pem.EncodeToMemory(&pem.Block{Type: pemPKCS8, Bytes: der})
}

// ParsePrivateKeyPEM decodes the first PEM block of data as an unencrypted
// RSA private key of 2048 to 16384 bits: PKCS#8 ("PRIVATE KEY") or PKCS#1
// ("RSA PRIVATE KEY", what abuild-keygen writes).
func ParsePrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", errKey)
	}

	if _, encrypted := block.Headers["DEK-Info"]; encrypted {
		return nil, fmt.Errorf("%w: encrypted keys are not supported", errKey)
	}

	var (
		key *rsa.PrivateKey
		err error
	)

	switch block.Type {
	case pemPKCS8:
		key, err = parsePKCS8(block.Bytes)
	case pemPKCS1:
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: unsupported PEM type %q", errKey, short(block.Type))
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %w", errKey, err)
	}

	if err := checkPrivateKey(key); err != nil {
		return nil, err
	}

	return key, nil
}

func parsePKCS8(der []byte) (*rsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}

	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: %T", errNotRSA, parsed)
	}

	return key, nil
}

// ParsePublicKeyPEM decodes the first PEM block of data as an RSA public key
// of 2048 to 16384 bits: "PUBLIC KEY" (SubjectPublicKeyInfo, what apk keeps
// in its keys directory) or "RSA PUBLIC KEY" (PKCS#1).
func ParsePublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", errKey)
	}

	var (
		key *rsa.PublicKey
		err error
	)

	switch block.Type {
	case pemPublic:
		var parsed any

		if parsed, err = x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			var ok bool

			if key, ok = parsed.(*rsa.PublicKey); !ok {
				err = fmt.Errorf("%w: %T", errNotRSA, parsed)
			}
		}
	case pemPublicRSA:
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: unsupported PEM type %q", errKey, short(block.Type))
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %w", errKey, err)
	}

	if bits := key.N.BitLen(); bits < minKeyBits || bits > maxKeyBits {
		return nil, fmt.Errorf("%w: %d bits, want %d to %d", errKey, bits, minKeyBits, maxKeyBits)
	}

	return key, nil
}

// Keyring is the set of public keys a signature is checked against, by key
// name: the file names of apk's keys directory.
type Keyring struct {
	keys map[string]*rsa.PublicKey
}

// Limits of [LoadKeyring].
const (
	maxKeyFiles    = 1000
	maxKeyFileSize = 64 << 10
)

// NewKeyring returns an empty Keyring.
func NewKeyring() *Keyring { return &Keyring{keys: make(map[string]*rsa.PublicKey)} }

// Add trusts key under name, which must match ^[A-Za-z0-9._@+-]+\.rsa\.pub$.
// A later Add of the same name replaces the key.
func (k *Keyring) Add(name string, key *rsa.PublicKey) error {
	if !validKeyName(name) {
		return fmt.Errorf("%w: key name %q must match [A-Za-z0-9._@+-]+%s", errKey, short(name), keyNameSuffix)
	}

	if key == nil || key.N == nil {
		return fmt.Errorf("%w: no key", errKey)
	}

	k.keys[name] = key

	return nil
}

// Len returns the number of trusted keys.
func (k *Keyring) Len() int { return len(k.keys) }

// Lookup returns the key trusted under name.
func (k *Keyring) Lookup(name string) (*rsa.PublicKey, bool) {
	key, ok := k.keys[name]

	return key, ok
}

// LoadKeyring reads the public keys of dir: every regular file whose name
// ends in .rsa.pub, as PEM. Other files and subdirectories are ignored; a
// .rsa.pub file that is not a valid key fails the load, so a damaged key is
// never silently dropped from the trust set. At most 1000 files of 64 KiB.
func LoadKeyring(dir string) (*Keyring, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("apk: reading keys directory: %w", err)
	}

	ring := NewKeyring()

	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, keyNameSuffix) {
			continue
		}

		if ring.Len() >= maxKeyFiles {
			return nil, fmt.Errorf("%w: more than %d key files in %s", errKey, maxKeyFiles, dir)
		}

		key, err := readPublicKeyFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("apk: key %s: %w", name, err)
		}

		if key == nil {
			continue
		}

		if err := ring.Add(name, key); err != nil {
			return nil, err
		}
	}

	return ring, nil
}

// readPublicKeyFile reads one key file; it returns nil for something that is
// not a regular file (a directory named like a key).
func readPublicKeyFile(path string) (*rsa.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if !info.Mode().IsRegular() {
		return nil, nil //nolint:nilnil // not a key file: skipped, not an error
	}

	data, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
	if err != nil {
		return nil, err
	}

	if len(data) > maxKeyFileSize {
		return nil, fmt.Errorf("%w: larger than %d bytes", errKey, maxKeyFileSize)
	}

	return ParsePublicKeyPEM(data)
}

// Signature is one signature entry of a package or index.
type Signature struct {
	// KeyName is the key name in the entry name, e.g. "alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub".
	KeyName string
	// Algorithm is the signature type; zero for an entry of a type this
	// package does not know (.SIGN.DSA.…).
	Algorithm SigAlgorithm
	// Value is the signature bytes.
	Value []byte
}

// VerifyOptions says which signatures to trust. Both fields are required: the
// caller chooses the trust anchors and the signature types it accepts, there
// is no default.
type VerifyOptions struct {
	// Keys are the trusted public keys.
	Keys *Keyring
	// Algorithms are the accepted signature types. A SHA-1 signature is only
	// accepted when SigRSASHA1 is listed.
	Algorithms []SigAlgorithm
}

func (o VerifyOptions) allows(a SigAlgorithm) bool {
	for _, x := range o.Algorithms {
		if x == a {
			return true
		}
	}

	return false
}

func (o VerifyOptions) check() error {
	if o.Keys == nil {
		return ErrNoKeyring
	}

	if len(o.Algorithms) == 0 {
		return ErrNoAlgorithm
	}

	for _, a := range o.Algorithms {
		if !a.valid() {
			return ErrNoAlgorithm
		}
	}

	return nil
}

// Errors of signature verification.
var (
	// ErrNoKeyring is returned when verifying without trusted keys.
	ErrNoKeyring = errors.New("apk: no trusted keys")
	// ErrUnsigned means the package or index carries no signature.
	ErrUnsigned = errors.New("apk: not signed")
	// ErrUntrusted means there are signatures, but none by a trusted key in an
	// accepted signature type.
	ErrUntrusted = errors.New("apk: no signature by a trusted key")
	// ErrBadSignature means a signature by a trusted key does not match.
	ErrBadSignature = errors.New("apk: signature does not verify")
)

// parseSignatureName splits ".SIGN.RSA[256].<key>" into its parts. A name
// that is not an RSA signature gives the zero algorithm.
func parseSignatureName(name string) (SigAlgorithm, string) {
	if key, ok := strings.CutPrefix(name, sigRSA256Prefix); ok {
		return SigRSASHA256, key
	}

	if key, ok := strings.CutPrefix(name, sigRSA1Prefix); ok {
		return SigRSASHA1, key
	}

	return 0, strings.TrimPrefix(name, sigPrefix)
}

// readSignatureEntry reads the body of one signature tar entry.
func readSignatureEntry(tr *tar.Reader, hdr *tar.Header) (Signature, error) {
	if hdr.Typeflag != tar.TypeReg {
		return Signature{}, fmt.Errorf("signature %q is not a regular file", short(hdr.Name))
	}

	if hdr.Size > maxSignatureLen {
		return Signature{}, fmt.Errorf("signature %q exceeds %d bytes", short(hdr.Name), maxSignatureLen)
	}

	value, err := io.ReadAll(tr)
	if err != nil {
		return Signature{}, fmt.Errorf("reading signature %q: %w", short(hdr.Name), err)
	}

	alg, key := parseSignatureName(hdr.Name)

	return Signature{KeyName: key, Algorithm: alg, Value: value}, nil
}

// verifySignatures checks that one of sigs is a valid signature of data by a
// key of opts.
func verifySignatures(sigs []Signature, data []byte, opts VerifyOptions) error {
	if err := opts.check(); err != nil {
		return err
	}

	if len(sigs) == 0 {
		return ErrUnsigned
	}

	var bad error

	for _, sig := range sigs {
		if !opts.allows(sig.Algorithm) {
			continue
		}

		key, ok := opts.Keys.Lookup(sig.KeyName)
		if !ok {
			continue
		}

		h, sum := sig.Algorithm.digest(data)
		if err := rsa.VerifyPKCS1v15(key, h, sum, sig.Value); err != nil {
			bad = fmt.Errorf("%w: %s by %s", ErrBadSignature, sig.Algorithm, short(sig.KeyName))

			continue
		}

		return nil
	}

	if bad != nil {
		return bad
	}

	return ErrUntrusted
}
