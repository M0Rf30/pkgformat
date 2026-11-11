package rpm

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys signed packages of RHEL 5 and earlier
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/M0Rf30/pkgformat/gpg"
)

// ErrBadV3Signature is returned for a version 3 signature packet that is
// malformed or does not match the signed data.
var ErrBadV3Signature = errors.New("rpm: bad version 3 OpenPGP signature")

// v3Signature is a version 3 OpenPGP signature packet (RFC 4880 5.2.2), the
// kind rpm made with GnuPG 1 and that the packages of RHEL 7 and earlier
// carry. The OpenPGP library of this module reads only version 4 and later.
type v3Signature struct {
	sigType  byte
	created  time.Time
	keyID    uint64
	pubAlgo  packet.PublicKeyAlgorithm
	hash     crypto.Hash
	left16   [2]byte
	mpis     [][]byte
	hashedV3 [5]byte // signature type and creation time, hashed after the data
}

// hashAlgorithms maps OpenPGP hash identifiers to crypto.Hash.
var hashAlgorithms = map[byte]crypto.Hash{
	1: crypto.MD5, 2: crypto.SHA1, 3: crypto.RIPEMD160, 8: crypto.SHA256,
	9: crypto.SHA384, 10: crypto.SHA512, 11: crypto.SHA224,
}

// parseV3Signature parses a complete signature packet, header included.
func parseV3Signature(blob []byte) (*v3Signature, error) {
	body, err := packetBody(blob)
	if err != nil {
		return nil, err
	}

	// version, hashed length 5, type, time, key id, algorithms, left16
	if len(body) < 19 || body[0] != 3 || body[1] != 5 {
		return nil, fmt.Errorf("%w: not a version 3 signature", ErrBadV3Signature)
	}

	s := &v3Signature{
		sigType: body[2],
		created: time.Unix(int64(binary.BigEndian.Uint32(body[3:7])), 0),
		keyID:   binary.BigEndian.Uint64(body[7:15]),
		pubAlgo: packet.PublicKeyAlgorithm(body[15]),
	}
	copy(s.hashedV3[:], body[2:7])
	copy(s.left16[:], body[17:19])

	h, ok := hashAlgorithms[body[16]]
	if !ok || !h.Available() {
		return nil, fmt.Errorf("%w: unsupported hash algorithm %d", ErrBadV3Signature, body[16])
	}

	s.hash = h

	want := 0

	switch s.pubAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		want = 1
	case packet.PubKeyAlgoDSA:
		want = 2
	default:
		return nil, fmt.Errorf("%w: unsupported public key algorithm %d", ErrBadV3Signature, s.pubAlgo)
	}

	rest := body[19:]
	for range want {
		if len(rest) < 2 {
			return nil, fmt.Errorf("%w: truncated MPI", ErrBadV3Signature)
		}

		n := (int(binary.BigEndian.Uint16(rest)) + 7) / 8
		if len(rest) < 2+n {
			return nil, fmt.Errorf("%w: truncated MPI", ErrBadV3Signature)
		}

		s.mpis = append(s.mpis, rest[2:2+n])
		rest = rest[2+n:]
	}

	if len(rest) != 0 {
		return nil, ErrTrailingGarbage
	}

	return s, nil
}

// packetBody returns the body of a single OpenPGP packet (old or new header
// format).
func packetBody(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0]&0x80 == 0 {
		return nil, fmt.Errorf("%w: not an OpenPGP packet", ErrBadV3Signature)
	}

	var (
		tag    byte
		length int
		header int
	)

	if b[0]&0x40 == 0 { // old format
		tag = (b[0] >> 2) & 0xf

		switch b[0] & 3 {
		case 0:
			length, header = int(b[1]), 2
		case 1:
			if len(b) < 3 {
				return nil, ErrBadV3Signature
			}

			length, header = int(binary.BigEndian.Uint16(b[1:])), 3
		case 2:
			if len(b) < 5 {
				return nil, ErrBadV3Signature
			}

			length, header = int(binary.BigEndian.Uint32(b[1:])), 5
		default:
			length, header = len(b)-1, 1
		}
	} else { // new format
		tag = b[0] & 0x3f

		switch first := int(b[1]); {
		case first < 192:
			length, header = first, 2
		case first < 224:
			if len(b) < 3 {
				return nil, ErrBadV3Signature
			}

			length, header = (first-192)<<8+int(b[2])+192, 3
		case first == 255:
			if len(b) < 6 {
				return nil, ErrBadV3Signature
			}

			length, header = int(binary.BigEndian.Uint32(b[2:])), 6
		default:
			return nil, fmt.Errorf("%w: partial body lengths", ErrBadV3Signature)
		}
	}

	if tag != 2 {
		return nil, fmt.Errorf("%w: packet tag %d is not a signature", ErrBadV3Signature, tag)
	}

	if length < 0 || header+length != len(b) {
		if header+length < len(b) && length >= 0 {
			return nil, ErrTrailingGarbage
		}

		return nil, fmt.Errorf("%w: truncated packet", ErrBadV3Signature)
	}

	return b[header:], nil
}

// isV3Signature reports whether blob is a signature packet of version 3.
func isV3Signature(blob []byte) bool {
	body, err := packetBody(blob)

	return err == nil && len(body) > 0 && body[0] == 3
}

// asSignature describes the v3 signature as a version 4 one, for the key
// lookup and the validity checks that only look at its metadata.
func (s *v3Signature) asSignature() *packet.Signature {
	id := s.keyID

	return &packet.Signature{
		Version:      3,
		SigType:      packet.SignatureType(s.sigType),
		PubKeyAlgo:   s.pubAlgo,
		Hash:         s.hash,
		CreationTime: s.created,
		IssuerKeyId:  &id,
	}
}

// verify checks the signature of h, the hash of the signed data, with key.
func (s *v3Signature) verify(h hash.Hash, key *packet.PublicKey) error {
	h.Write(s.hashedV3[:])
	digest := h.Sum(nil)

	if digest[0] != s.left16[0] || digest[1] != s.left16[1] {
		return fmt.Errorf("%w: hash prefix mismatch", ErrBadV3Signature)
	}

	switch pub := key.PublicKey.(type) {
	case *rsa.PublicKey:
		if s.pubAlgo != packet.PubKeyAlgoRSA && s.pubAlgo != packet.PubKeyAlgoRSASignOnly {
			break
		}

		// the MPI drops leading zeros the PKCS#1 encoding keeps
		sig := make([]byte, pub.Size())
		if len(s.mpis[0]) > len(sig) {
			return ErrBadV3Signature
		}

		copy(sig[len(sig)-len(s.mpis[0]):], s.mpis[0])

		if err := rsa.VerifyPKCS1v15(pub, s.hash, digest, sig); err != nil {
			return fmt.Errorf("%w: %w", ErrBadV3Signature, err)
		}

		return nil
	case *dsa.PublicKey:
		if s.pubAlgo != packet.PubKeyAlgoDSA {
			break
		}

		// FIPS 186-3 4.6: use the leftmost bits of the digest
		if n := (pub.Q.BitLen() + 7) / 8; len(digest) > n {
			digest = digest[:n]
		}

		r, ss := new(big.Int).SetBytes(s.mpis[0]), new(big.Int).SetBytes(s.mpis[1])
		if !dsa.Verify(pub, digest, r, ss) {
			return ErrBadV3Signature
		}

		return nil
	}

	return fmt.Errorf("%w: key algorithm does not match", ErrBadV3Signature)
}

// parseSignatureV3 turns a version 3 signature into a [Signature].
func parseSignatureV3(blob []byte, vf *verifier) (*Signature, error) {
	v3, err := parseV3Signature(blob)
	if err != nil {
		return nil, err
	}

	pkt := v3.asSignature()
	sig := &Signature{Hash: v3.hash, CreationTime: v3.created, KeyId: v3.keyID}
	sig.validate = func(h hash.Hash) error {
		if vf.keys == nil {
			return nil
		}

		entity, key := findKey(pkt, vf.keys)
		if key == nil {
			return KeyNotFoundError{KeyID: sig.KeyId}
		}

		setEntity(sig, entity)

		if err := v3.verify(h, key); err != nil {
			return err
		}

		if err := gpg.CheckSigner(entity, key, pkt, vf.now()); err != nil {
			return &SignatureError{KeyID: sig.KeyId, Fingerprint: sig.KeyFingerprint, Err: err}
		}

		return nil
	}

	return sig, nil
}
