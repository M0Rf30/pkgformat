package gpg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ErrUnsupportedSigner is returned by [NewCryptoSigner] for a crypto.Signer
// whose public key is neither RSA nor ECDSA.
var ErrUnsupportedSigner = errors.New("gpg: crypto.Signer must hold an RSA or ECDSA key")

// ErrPrivateKeyNotExportable is returned by the private key exports of a
// signer made by [NewCryptoSigner]: its key stays behind the crypto.Signer.
var ErrPrivateKeyNotExportable = errors.New("gpg: private key is held by an external signer")

// NewCryptoSigner returns a signer whose private key stays behind signer: a
// hardware security module, a cloud KMS, a smart card or an agent exposing
// the standard crypto.Signer interface. RSA and ECDSA (P-256, P-384, P-521)
// keys are supported; the private key is never read.
//
// OpenPGP identifies a key by a fingerprint computed over its creation time,
// so created must be the same every time the same key is wrapped, or the
// fingerprint and key id change. The returned signer carries a self-signed
// user id built from name, comment and email (made with signer too), so
// [LocalSigner.PublicKey] exports a usable certificate.
//
// The result implements every method of [Signer] and the SigningKey method
// that RPM signing needs; ExportPrivateKey and ExportUnprotectedPrivateKey
// fail with [ErrPrivateKeyNotExportable].
func NewCryptoSigner(signer crypto.Signer, created time.Time, name, comment, email string) (*LocalSigner, error) {
	created = created.Truncate(time.Second)

	priv := &packet.PrivateKey{PrivateKey: signer}

	switch pub := signer.Public().(type) {
	case *rsa.PublicKey:
		priv.PublicKey = *packet.NewRSAPublicKey(created, pub)
	case *ecdsa.PublicKey:
		pk, err := ecdsaPublicKey(created, pub)
		if err != nil {
			return nil, err
		}

		priv.PublicKey = *pk
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedSigner, pub)
	}

	uid := packet.NewUserId(name, comment, email)
	if uid == nil {
		return nil, fmt.Errorf("%w: invalid user id", ErrInvalidKey)
	}

	isPrimary := true
	selfSig := &packet.Signature{
		Version:           priv.Version,
		SigType:           packet.SigTypePositiveCert,
		PubKeyAlgo:        priv.PubKeyAlgo,
		Hash:              signingHash(priv),
		CreationTime:      created,
		IssuerKeyId:       &priv.KeyId,
		IssuerFingerprint: priv.Fingerprint,
		IsPrimaryId:       &isPrimary,
		FlagsValid:        true,
		FlagSign:          true,
		FlagCertify:       true,
	}

	if err := selfSig.SignUserId(uid.Id, &priv.PublicKey, priv, nil); err != nil {
		return nil, fmt.Errorf("gpg: self-signing the user id: %w", err)
	}

	entity := &openpgp.Entity{
		PrimaryKey: &priv.PublicKey,
		PrivateKey: priv,
		Identities: map[string]*openpgp.Identity{
			uid.Id: {Name: uid.Id, UserId: uid, SelfSignature: selfSig, Signatures: []*packet.Signature{selfSig}},
		},
	}

	return &LocalSigner{entity: entity, external: true}, nil
}

// curveOIDs are the OpenPGP object identifiers of the NIST curves (RFC 6637).
var curveOIDs = map[string][]byte{
	"P-256": {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},
	"P-384": {0x2B, 0x81, 0x04, 0x00, 0x22},
	"P-521": {0x2B, 0x81, 0x04, 0x00, 0x23},
}

// ecdsaPublicKey encodes a version 4 ECDSA public key packet (RFC 4880
// 5.5.2, RFC 6637 9) and parses it back.
func ecdsaPublicKey(created time.Time, pub *ecdsa.PublicKey) (*packet.PublicKey, error) {
	oid, ok := curveOIDs[pub.Curve.Params().Name]
	if !ok {
		return nil, fmt.Errorf("%w: curve %s", ErrUnsupportedSigner, pub.Curve.Params().Name)
	}

	point, err := pub.Bytes()
	if err != nil {
		return nil, fmt.Errorf("gpg: encoding the ECDSA point: %w", err)
	}

	body := []byte{4}
	body = binary.BigEndian.AppendUint32(body, uint32(created.Unix()))
	body = append(body, byte(packet.PubKeyAlgoECDSA), byte(len(oid)))
	body = append(body, oid...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(point)*8-5)) // 0x04 prefix: 3 bits
	body = append(body, point...)

	// New-format packet header, tag 6 (public key), two-octet length.
	pkt := []byte{0xC6, byte(192 + (len(body)-192)>>8), byte(len(body) - 192)}
	if len(body) < 192 {
		pkt = []byte{0xC6, byte(len(body))}
	}

	p, err := packet.Read(bytes.NewReader(append(pkt, body...)))
	if err != nil {
		return nil, fmt.Errorf("gpg: building the ECDSA key packet: %w", err)
	}

	pk, ok := p.(*packet.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected packet %T", ErrInvalidKey, p)
	}

	return pk, nil
}

// signingHash picks the hash matching the strength of an ECDSA curve, SHA-256
// otherwise.
func signingHash(priv *packet.PrivateKey) crypto.Hash {
	switch ecdsaCurveBits(&priv.PublicKey) {
	case 521:
		return crypto.SHA512
	case 384:
		return crypto.SHA384
	}

	return crypto.SHA256
}

// ecdsaCurveBits returns the size of the NIST curve of an ECDSA key, or 0.
// BitLength reports the length of the encoded point (0x04 || X || Y).
func ecdsaCurveBits(pk *packet.PublicKey) int {
	if pk.PubKeyAlgo != packet.PubKeyAlgoECDSA {
		return 0
	}

	bits, err := pk.BitLength()
	if err != nil {
		return 0
	}

	switch bits {
	case 2*256 + 3:
		return 256
	case 2*384 + 3:
		return 384
	case 2*528 + 3: // P-521 coordinates take 66 bytes
		return 521
	}

	return 0
}
