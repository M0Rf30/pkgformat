package rpm

import (
	"bytes"
	"fmt"
	"hash"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/M0Rf30/pkgformat/gpg"
)

func parseSignature(blob []byte, vf *verifier) (*Signature, error) {
	reader := bytes.NewReader(blob)
	genpkt, err := packet.Read(reader)
	if err != nil {
		return nil, err
	} else if reader.Len() > 0 {
		return nil, ErrTrailingGarbage
	}
	sig, err := parseSignatureV4(genpkt, vf)
	if err != nil {
		return nil, err
	}
	// crypto.Hash.New panics if the implementation is not linked in; the hash
	// comes from untrusted bytes, so check before anyone calls New.
	if !sig.Hash.Available() {
		return nil, fmt.Errorf("unsupported signature hash algorithm %d", sig.Hash)
	}
	return sig, nil
}

func parseSignatureV4(genpkt packet.Packet, vf *verifier) (*Signature, error) {
	pkt, ok := genpkt.(*packet.Signature)
	if !ok || (pkt.IssuerKeyId == nil && len(pkt.IssuerFingerprint) == 0) {
		return nil, ErrNoPGPSignature
	}
	sig := &Signature{
		Hash:           pkt.Hash,
		CreationTime:   pkt.CreationTime,
		KeyFingerprint: pkt.IssuerFingerprint,
	}
	if pkt.IssuerKeyId != nil {
		sig.KeyId = *pkt.IssuerKeyId
	}
	// version 6 signatures hash a salt before the data
	sig.prepare = pkt.PrepareVerify
	sig.validate = func(h hash.Hash) error {
		if vf.keys == nil {
			return nil
		}
		entity, key := findKey(pkt, vf.keys)
		if key == nil {
			return KeyNotFoundError{
				KeyID:       sig.KeyId,
				Fingerprint: sig.KeyFingerprint,
			}
		}
		setEntity(sig, entity)
		if err := key.VerifySignature(h, pkt); err != nil {
			return err
		}
		// the signature is genuine: check that its key may be relied on
		if err := gpg.CheckSigner(entity, key, pkt, vf.now()); err != nil {
			return &SignatureError{KeyID: sig.KeyId, Fingerprint: sig.KeyFingerprint, Err: err}
		}
		return nil
	}
	return sig, nil
}

// set identity attributes on signature
func setEntity(sig *Signature, entity *openpgp.Entity) {
	sig.Signer = entity
	if sig.KeyId == 0 {
		sig.KeyId = entity.PrimaryKey.KeyId
	}
	if sig.KeyFingerprint == nil {
		sig.KeyFingerprint = entity.PrimaryKey.Fingerprint
	}
	if identity := entity.PrimaryIdentity(); identity != nil {
		sig.PrimaryName = identity.Name
	}
}

// find a key by its fingerprint (if available) or key ID
func findKey(sig *packet.Signature, knownKeys openpgp.EntityList) (*openpgp.Entity, *packet.PublicKey) {
	for _, entity := range knownKeys {
		if sig.CheckKeyIdOrFingerprint(entity.PrimaryKey) {
			return entity, entity.PrimaryKey
		}
		for _, sub := range entity.Subkeys {
			if sig.CheckKeyIdOrFingerprint(sub.PublicKey) {
				return entity, sub.PublicKey
			}
		}
	}
	return nil, nil
}
