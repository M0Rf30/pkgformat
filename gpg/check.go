package gpg

import (
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// CheckSigner reports whether sig may be trusted to come from key, a key of
// entity (its primary key or one of its subkeys), at time now. It is the part
// of verification that does not depend on the signed data, for callers that
// hash the data themselves and call the cryptographic check of the OpenPGP
// library directly. VerifyDetached and VerifyClearsigned apply the same checks.
//
// It fails with:
//
//   - [ErrKeyRevoked]: the primary key, the subkey or the primary user id
//     carries a revocation signature;
//   - [ErrKeyCannotSign]: the key flags of the key do not allow signing, or
//     the key has no valid self-signature or binding signature;
//   - [ErrKeyExpired]: the primary key or the subkey is expired, or was created
//     after now;
//   - [ErrSignatureExpired]: sig, the binding signature of the subkey or its
//     embedded back signature is past its expiry, or was made after now;
//   - [ErrBadSignature]: sig or a self-signature has a critical notation that
//     is not known;
//   - [ErrUnknownSigner]: key is not a key of entity.
func CheckSigner(entity *openpgp.Entity, key *packet.PublicKey, sig *packet.Signature, now time.Time) error {
	if entity == nil || entity.PrimaryKey == nil || key == nil || sig == nil {
		return ErrUnknownSigner
	}

	primarySig, primaryID := entity.PrimarySelfSignature()
	if primarySig == nil {
		return fmt.Errorf("%w: key has no valid self-signature", ErrKeyCannotSign)
	}

	// the signatures that vouch for the key: the self-signature of the
	// primary key and, for a subkey, its binding signature
	vouching := []*packet.Signature{primarySig}

	var subkey *openpgp.Subkey

	flagsSig := primarySig // the self-signature that holds the flags of the key

	if key != entity.PrimaryKey {
		for i := range entity.Subkeys {
			if entity.Subkeys[i].PublicKey == key {
				subkey = &entity.Subkeys[i]

				break
			}
		}

		if subkey == nil {
			return ErrUnknownSigner
		}

		if subkey.Sig == nil {
			return fmt.Errorf("%w: subkey has no valid binding signature", ErrKeyCannotSign)
		}

		flagsSig = subkey.Sig
		vouching = append(vouching, subkey.Sig)
		if subkey.Sig.EmbeddedSignature != nil {
			vouching = append(vouching, subkey.Sig.EmbeddedSignature)
		}
	}

	for _, s := range append([]*packet.Signature{sig}, vouching...) {
		for _, n := range s.Notations {
			if n.IsCritical {
				return fmt.Errorf("%w: unknown critical notation %q", ErrBadSignature, n.Name)
			}
		}
	}

	if entity.Revoked(now) || (subkey != nil && subkey.Revoked(now)) || (primaryID != nil && primaryID.Revoked(now)) {
		return ErrKeyRevoked
	}

	// a key without usage flags (very old keys) can do everything
	if flagsSig.FlagsValid && !flagsSig.FlagSign {
		return ErrKeyCannotSign
	}

	if entity.PrimaryKey.KeyExpired(primarySig, now) {
		return ErrKeyExpired
	}

	if subkey != nil && subkey.PublicKey.KeyExpired(subkey.Sig, now) {
		return ErrKeyExpired
	}

	for _, s := range append([]*packet.Signature{sig}, vouching...) {
		if s.SigExpired(now) {
			return ErrSignatureExpired
		}
	}

	return nil
}
