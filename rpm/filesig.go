package rpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha256" // fs-verity and IMA digests
	_ "crypto/sha512" // fs-verity and IMA digests
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// ErrFileSignature is returned when an IMA or fs-verity file signature is
// malformed or does not verify.
var ErrFileSignature = errors.New("rpm: bad file signature")

// IMASignature is a decoded IMA file signature (the "signature v2" format of
// the security.ima extended attribute): the hash of the file contents signed
// with the key whose identifier it names.
type IMASignature struct {
	// Hash is the algorithm the file digest was computed with.
	Hash crypto.Hash
	// KeyID is the last four bytes of the SHA-1 of the public key (its
	// X.509 subject key identifier, as evmctl computes it).
	KeyID [4]byte
	// Signature is the RSA (PKCS #1 v1.5) or ECDSA (ASN.1) signature.
	Signature []byte
}

// imaHashes maps the kernel hash_algo numbers (include/uapi/linux/hash_info.h)
// to crypto.Hash.
var imaHashes = map[byte]crypto.Hash{
	1: crypto.MD5, 2: crypto.SHA1, 4: crypto.SHA256, 5: crypto.SHA384,
	6: crypto.SHA512, 7: crypto.SHA224, 20: crypto.SHA3_256, 21: crypto.SHA3_384, 22: crypto.SHA3_512,
}

// ParseIMASignature decodes an IMA signature: the hex string of
// FileEntry.IMASignature or the raw bytes of the security.ima attribute.
func ParseIMASignature(sig []byte) (*IMASignature, error) {
	if raw, err := hex.DecodeString(string(sig)); err == nil {
		sig = raw
	}

	// type 3 (EVM_IMA_XATTR_DIGSIG), version 2, hash, key id, length
	if len(sig) < 9 || sig[0] != 3 || sig[1] != 2 {
		return nil, fmt.Errorf("%w: not an IMA signature v2", ErrFileSignature)
	}

	h, ok := imaHashes[sig[2]]
	if !ok || !h.Available() {
		return nil, fmt.Errorf("%w: unsupported IMA hash %d", ErrFileSignature, sig[2])
	}

	n := int(binary.BigEndian.Uint16(sig[7:9]))
	if len(sig) != 9+n {
		return nil, fmt.Errorf("%w: IMA signature length %d, have %d bytes", ErrFileSignature, n, len(sig)-9)
	}

	s := &IMASignature{Hash: h, Signature: sig[9:]}
	copy(s.KeyID[:], sig[3:7])

	return s, nil
}

// VerifyIMASignature checks an IMA signature (see [ParseIMASignature] for
// the accepted encodings) of a file whose contents hash to digest under the
// algorithm the signature names, which for an rpm package is the FILEDIGESTS
// entry of the file. pub is an *rsa.PublicKey or *ecdsa.PublicKey, typically
// the PublicKey of the x509.Certificate given to rpmsign --certpath.
func VerifyIMASignature(sig, digest []byte, pub crypto.PublicKey) error {
	s, err := ParseIMASignature(sig)
	if err != nil {
		return err
	}

	if len(digest) != s.Hash.Size() {
		return fmt.Errorf("%w: digest of %d bytes for %s", ErrFileSignature, len(digest), s.Hash)
	}

	return verifyDigest(pub, s.Hash, digest, s.Signature)
}

func verifyDigest(pub crypto.PublicKey, h crypto.Hash, digest, sig []byte) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, h, digest, sig); err != nil {
			return fmt.Errorf("%w: %w", ErrFileSignature, err)
		}

		return nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return ErrFileSignature
		}

		return nil
	}

	return fmt.Errorf("%w: unsupported public key %T", ErrFileSignature, pub)
}

// fs-verity hash algorithm numbers (VERITYSIGNATUREALGO, FS_VERITY_HASH_ALG_*).
const (
	VeritySHA256 = 1
	VeritySHA512 = 2
)

func verityHash(algo uint32) (crypto.Hash, error) {
	switch algo {
	case VeritySHA256:
		return crypto.SHA256, nil
	case VeritySHA512:
		return crypto.SHA512, nil
	}

	return 0, fmt.Errorf("%w: unknown fs-verity algorithm %d", ErrFileSignature, algo)
}

const verityBlockSize = 4096

// FSVerityDigest computes the fs-verity file digest of the contents read
// from r (4 KiB blocks, no salt: what fsverity(1) and rpmsign use), with the
// fs-verity algorithm algo ([VeritySHA256] or [VeritySHA512]).
func FSVerityDigest(r io.Reader, algo uint32) ([]byte, error) {
	h, err := verityHash(algo)
	if err != nil {
		return nil, err
	}

	// levels[0] collects the hashes of data blocks; a full block of hashes is
	// hashed into the next level, so memory stays O(depth * block).
	var (
		levels [][]byte
		size   uint64
		block  = make([]byte, verityBlockSize)
	)

	add := func(level int, digest []byte) {
		for {
			if level == len(levels) {
				levels = append(levels, nil)
			}

			levels[level] = append(levels[level], digest...)
			if len(levels[level]) < verityBlockSize {
				return
			}

			sum := h.New()
			sum.Write(levels[level])
			levels[level] = levels[level][:0]
			digest = sum.Sum(nil)
			level++
		}
	}

	for {
		n, err := io.ReadFull(r, block)
		if n > 0 {
			size += uint64(n)
			clear(block[n:])

			sum := h.New()
			sum.Write(block)
			add(0, sum.Sum(nil))
		}

		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}

		if err != nil {
			return nil, err
		}
	}

	root := make([]byte, 64)

	if size > verityBlockSize {
		// Pad and hash every partial level; the root is the single hash the
		// top level holds.
		var carry []byte

		for i := range levels {
			if carry != nil {
				levels[i] = append(levels[i], carry...)
				carry = nil
			}

			if i == len(levels)-1 && len(levels[i]) == h.Size() {
				copy(root, levels[i])

				break
			}

			if len(levels[i]) > 0 {
				buf := make([]byte, verityBlockSize)
				copy(buf, levels[i])

				sum := h.New()
				sum.Write(buf)
				carry = sum.Sum(nil)
			}

			if i == len(levels)-1 {
				copy(root, carry)
			}
		}
	} else if size > 0 {
		copy(root, levels[0])
	}

	// struct fsverity_descriptor
	desc := make([]byte, 256)
	desc[0] = 1 // version
	desc[1] = byte(algo)
	desc[2] = 12 // log2 of the block size
	binary.LittleEndian.PutUint64(desc[8:], size)
	copy(desc[16:80], root)

	sum := h.New()
	sum.Write(desc)

	return sum.Sum(nil), nil
}

// VerifyVeritySignature checks an fs-verity signature of a file: sig is the
// FileEntry.VeritySignature of the package (or the raw PKCS #7 DER), digest
// the fs-verity digest of the file contents ([FSVerityDigest]) under algo
// (Package.VeritySignatureAlgorithm), and trusted the certificates the
// signature may come from (the --certpath given to rpmsign). The signature
// is a detached PKCS #7 SignedData over the fsverity_formatted_digest, as the
// kernel checks it.
func VerifyVeritySignature(sig, digest []byte, algo uint32, trusted []*x509.Certificate) error {
	if raw, err := base64.StdEncoding.DecodeString(string(sig)); err == nil {
		sig = raw
	} else if raw, err := hex.DecodeString(string(sig)); err == nil {
		sig = raw
	}

	h, err := verityHash(algo)
	if err != nil {
		return err
	}

	if len(digest) != h.Size() {
		return fmt.Errorf("%w: fs-verity digest of %d bytes", ErrFileSignature, len(digest))
	}

	// struct fsverity_formatted_digest
	signed := make([]byte, 12, 12+len(digest))
	copy(signed, "FSVerity")
	binary.LittleEndian.PutUint16(signed[8:], uint16(algo))
	binary.LittleEndian.PutUint16(signed[10:], uint16(len(digest)))
	signed = append(signed, digest...)

	return verifyPKCS7Detached(sig, signed, trusted)
}

// PKCS #7 / CMS structures (RFC 5652), the subset detached signatures use.
type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []pkcs7SignerInfo `asn1:"set"`
}

type pkcs7IssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type pkcs7Algorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pkcs7SignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkcs7Algorithm
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkcs7Algorithm
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type pkcs7Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	pkcs7Digests     = map[string]crypto.Hash{
		"2.16.840.1.101.3.4.2.1": crypto.SHA256,
		"2.16.840.1.101.3.4.2.2": crypto.SHA384,
		"2.16.840.1.101.3.4.2.3": crypto.SHA512,
		"2.16.840.1.101.3.4.2.4": crypto.SHA224,
	}
)

func verifyPKCS7Detached(der, content []byte, trusted []*x509.Certificate) error {
	var ci pkcs7ContentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) != 0 || !ci.ContentType.Equal(oidSignedData) {
		return fmt.Errorf("%w: not a PKCS #7 SignedData", ErrFileSignature)
	}

	var sd pkcs7SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return fmt.Errorf("%w: SignedData: %w", ErrFileSignature, err)
	}

	if len(sd.SignerInfos) == 0 {
		return fmt.Errorf("%w: no signer", ErrFileSignature)
	}

	for _, si := range sd.SignerInfos {
		cert := signerCertificate(si.SID, trusted)
		if cert == nil {
			continue
		}

		h, ok := pkcs7Digests[si.DigestAlgorithm.Algorithm.String()]
		if !ok || !h.Available() {
			return fmt.Errorf("%w: digest algorithm %s", ErrFileSignature, si.DigestAlgorithm.Algorithm)
		}

		sum := h.New()
		sum.Write(content)
		digest := sum.Sum(nil)

		if len(si.SignedAttrs.FullBytes) > 0 {
			if err := checkMessageDigest(si.SignedAttrs.Bytes, digest); err != nil {
				return err
			}

			// the signature covers the attributes, DER-encoded as a SET
			attrs := bytes.Clone(si.SignedAttrs.FullBytes)
			attrs[0] = 0x31

			sum = h.New()
			sum.Write(attrs)
			digest = sum.Sum(nil)
		}

		return verifyDigest(cert.PublicKey, h, digest, si.Signature)
	}

	return fmt.Errorf("%w: signed by none of the trusted certificates", ErrFileSignature)
}

// signerCertificate finds the certificate a signer identifier names.
func signerCertificate(sid asn1.RawValue, trusted []*x509.Certificate) *x509.Certificate {
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 { // subjectKeyIdentifier
		for _, c := range trusted {
			if bytes.Equal(c.SubjectKeyId, sid.Bytes) {
				return c
			}
		}

		return nil
	}

	var ias pkcs7IssuerAndSerial
	if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
		return nil
	}

	for _, c := range trusted {
		if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 {
			return c
		}
	}

	return nil
}

func checkMessageDigest(attrs, digest []byte) error {
	for len(attrs) > 0 {
		var a pkcs7Attribute

		rest, err := asn1.Unmarshal(attrs, &a)
		if err != nil {
			return fmt.Errorf("%w: signed attributes: %w", ErrFileSignature, err)
		}

		attrs = rest

		if !a.Type.Equal(oidMessageDigest) {
			continue
		}

		var md []byte
		if _, err := asn1.Unmarshal(a.Values.Bytes, &md); err != nil {
			return fmt.Errorf("%w: message digest: %w", ErrFileSignature, err)
		}

		if !bytes.Equal(md, digest) {
			return fmt.Errorf("%w: message digest mismatch", ErrFileSignature)
		}

		return nil
	}

	return fmt.Errorf("%w: signed attributes without message digest", ErrFileSignature)
}
