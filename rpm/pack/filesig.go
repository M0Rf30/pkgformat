package pack

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // the IMA key id is a SHA-1 of the key by definition, not a security digest
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// ErrFileSigning is returned for IMA and fs-verity signing failures: a missing key
// or certificate, or a file digest algorithm that cannot be signed.
var ErrFileSigning = errors.New("rpm file signing")

// FileSigning holds the keys that sign every file of a package while it is
// written, as "rpmsign --signfiles" and "rpmsign --signverity" do afterwards.
type FileSigning struct {
	// IMAKey signs the file digests for the Linux IMA appraisal (the
	// security.ima extended attribute). The signatures use the digest
	// algorithm of the package files, which must be SHA-256 or SHA-512.
	IMAKey *rsa.PrivateKey
	// VerityKey and VerityCert sign the fs-verity digest of every file with a
	// detached PKCS#7 signature, as fsverity-utils and rpmsign produce. The
	// certificate names the key: its issuer and serial number identify the signer.
	VerityKey  *rsa.PrivateKey
	VerityCert *x509.Certificate
}

// SetFileSigning enables the IMA and fs-verity signatures of the files.
func (r *RPM) SetFileSigning(s FileSigning) { r.fileSigning = &s }

func (s *FileSigning) validate(algo int) error {
	if s.IMAKey == nil && s.VerityKey == nil {
		return fmt.Errorf("%w: no IMA key and no fs-verity key", ErrFileSigning)
	}
	if s.IMAKey != nil {
		if _, ok := imaHashID(algo); !ok {
			return fmt.Errorf("%w: IMA cannot sign file digests of algorithm %d", ErrFileSigning, algo)
		}
	}
	if s.VerityKey != nil && s.VerityCert == nil {
		return fmt.Errorf("%w: the fs-verity key has no certificate", ErrFileSigning)
	}
	if s.VerityCert != nil && s.VerityKey == nil {
		return fmt.Errorf("%w: the fs-verity certificate has no key", ErrFileSigning)
	}
	return nil
}

// imaHashID returns the identifier of a hash in IMA signatures (the hash_algo
// enumeration of the kernel) for an rpm file digest algorithm.
func imaHashID(algo int) (byte, bool) {
	switch algo {
	case 8: // SHA-256
		return 4, true
	case 10: // SHA-512
		return 6, true
	}
	return 0, false
}

func cryptoHash(algo int) crypto.Hash {
	if algo == 10 {
		return crypto.SHA512
	}
	return crypto.SHA256
}

// imaKeyID returns the key identifier of IMA signatures: the last four bytes of the
// SHA-1 of the DER encoded RSA public key.
func imaKeyID(pub *rsa.PublicKey) [4]byte {
	sum := sha1.Sum(x509.MarshalPKCS1PublicKey(pub)) //nolint:gosec // see import
	var id [4]byte
	copy(id[:], sum[len(sum)-4:])
	return id
}

// imaSignature returns the IMA version 2 signature of a file digest: the
// signature header (type, version, hash id, key id, length) and the RSA PKCS#1 v1.5
// signature of the digest.
func imaSignature(key *rsa.PrivateKey, algo int, digest []byte) ([]byte, error) {
	id, _ := imaHashID(algo)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, cryptoHash(algo), digest)
	if err != nil {
		return nil, fmt.Errorf("%w: IMA signature: %w", ErrFileSigning, err)
	}
	kid := imaKeyID(&key.PublicKey)
	out := []byte{0x03, 0x02, id}
	out = append(out, kid[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(sig)))
	return append(out, sig...), nil
}

// verityBlockSize is the block size of fs-verity Merkle trees.
const verityBlockSize = 4096

// verityHasher computes the fs-verity digest (SHA-256, 4 KiB blocks, no salt) of a
// stream. It keeps only the unfinished block of every tree level.
type verityHasher struct {
	size uint64
	buf  []byte
	// levels[l] holds the hashes of level l that did not fill a block yet.
	levels [][]byte
}

func newVerityHasher() *verityHasher { return &verityHasher{buf: make([]byte, 0, verityBlockSize)} }

// Write adds content.
func (v *verityHasher) Write(p []byte) (int, error) {
	n := len(p)
	v.size += uint64(n)
	for len(p) > 0 {
		take := min(verityBlockSize-len(v.buf), len(p))
		v.buf = append(v.buf, p[:take]...)
		p = p[take:]
		if len(v.buf) == verityBlockSize {
			v.push(0, v.buf)
			v.buf = v.buf[:0]
		}
	}
	return n, nil
}

// push hashes a block and records its hash in level, hashing the level's own block
// when it is full.
func (v *verityHasher) push(level int, block []byte) {
	sum := sha256.Sum256(block)
	for len(v.levels) <= level {
		v.levels = append(v.levels, nil)
	}
	v.levels[level] = append(v.levels[level], sum[:]...)
	if len(v.levels[level]) == verityBlockSize {
		full := v.levels[level]
		v.levels[level] = nil
		v.push(level+1, full)
	}
}

// Sum returns the fs-verity file digest: the SHA-256 of the file descriptor, which
// holds the file size and the root hash of the Merkle tree.
func (v *verityHasher) Sum() [sha256.Size]byte {
	var root []byte
	if v.size > 0 {
		if len(v.buf) > 0 {
			v.push(0, append(v.buf, make([]byte, verityBlockSize-len(v.buf))...))
		}
		for l := 0; l < len(v.levels); l++ {
			hs := v.levels[l]
			top := true
			for _, up := range v.levels[l+1:] {
				top = top && len(up) == 0
			}
			if top && len(hs) == sha256.Size {
				root = hs
				break
			}
			if len(hs) == 0 {
				continue
			}
			sum := sha256.Sum256(append(hs[:len(hs):len(hs)], make([]byte, verityBlockSize-len(hs))...))
			if l+1 == len(v.levels) {
				v.levels = append(v.levels, nil)
			}
			v.levels[l+1] = append(v.levels[l+1], sum[:]...)
		}
	}
	// the descriptor: version, algorithm, log2 of the block size, salt size,
	// signature size, data size, root hash, salt and reserved space
	desc := make([]byte, 256)
	desc[0] = 1 // version
	desc[1] = 1 // SHA-256
	desc[2] = 12
	binary.LittleEndian.PutUint64(desc[8:], v.size)
	copy(desc[16:], root)
	return sha256.Sum256(desc)
}

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSA        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

type pkcs7AlgID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pkcs7IssuerSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type pkcs7SignerInfo struct {
	Version         int
	IssuerAndSerial pkcs7IssuerSerial
	DigestAlg       pkcs7AlgID
	SigAlg          pkcs7AlgID
	Signature       []byte
}

type pkcs7ContentInfo struct {
	Type asn1.ObjectIdentifier
}

type pkcs7SignedData struct {
	Version     int
	DigestAlgs  []pkcs7AlgID `asn1:"set"`
	Content     pkcs7ContentInfo
	SignerInfos []pkcs7SignerInfo `asn1:"set"`
}

type pkcs7Outer struct {
	Type    asn1.ObjectIdentifier
	Content pkcs7SignedData `asn1:"explicit,tag:0"`
}

var asn1Null = asn1.RawValue{Tag: asn1.TagNull, Class: asn1.ClassUniversal}

// veritySignature returns the detached PKCS#7 signature fsverity-utils creates for an
// fs-verity digest, base64 encoded in lines of 64 characters as rpm stores it.
func veritySignature(key *rsa.PrivateKey, cert *x509.Certificate, digest [sha256.Size]byte) (string, error) {
	// the signed content is the formatted digest: magic, algorithm, size, digest
	content := []byte("FSVerity")
	content = binary.LittleEndian.AppendUint16(content, 1)
	content = binary.LittleEndian.AppendUint16(content, sha256.Size)
	content = append(content, digest[:]...)
	sum := sha256.Sum256(content)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("%w: fs-verity signature: %w", ErrFileSigning, err)
	}
	serial := cert.SerialNumber
	der, err := asn1.Marshal(pkcs7Outer{
		Type: oidSignedData,
		Content: pkcs7SignedData{
			Version:    1,
			DigestAlgs: []pkcs7AlgID{{oidSHA256, asn1Null}},
			Content:    pkcs7ContentInfo{Type: oidData},
			SignerInfos: []pkcs7SignerInfo{{
				Version: 1,
				IssuerAndSerial: pkcs7IssuerSerial{
					Issuer: asn1.RawValue{FullBytes: cert.RawIssuer},
					Serial: serial,
				},
				DigestAlg: pkcs7AlgID{oidSHA256, asn1Null},
				SigAlg:    pkcs7AlgID{oidRSA, asn1Null},
				Signature: sig,
			}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrFileSigning, err)
	}
	return wrapBase64(base64.StdEncoding.EncodeToString(der)), nil
}

// wrapBase64 breaks base64 text into lines of 64 characters, each ended by a newline.
func wrapBase64(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		n := min(64, len(s))
		b.WriteString(s[:n])
		b.WriteByte('\n')
		s = s[n:]
	}
	return b.String()
}
