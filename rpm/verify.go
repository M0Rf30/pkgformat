/*
 * Copyright (c) SAS Institute Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rpm

import (
	"crypto"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/M0Rf30/pkgformat/gpg"
)

// Signature describes a PGP signature found within a RPM while verifying it.
type Signature struct {
	// Signer is the PGP identity that created the signature. It may be nil if
	// the public key is not available at verification time, but KeyId will
	// always be set.
	Signer *openpgp.Entity
	// Hash is the algorithm used to digest the signature contents
	Hash crypto.Hash
	// CreationTime is when the signature was created
	CreationTime time.Time
	// HeaderOnly is true for signatures that only cover the general RPM header,
	// and false for signatures that cover the general header plus the payload
	HeaderOnly bool
	// KeyId is the PGP key that created the signature.
	KeyId uint64
	// KeyFingerprint is the fingerprint of the public key that created the
	// signature, if available.
	KeyFingerprint []byte
	// PrimaryName is the primary identity of the signing key, if available.
	PrimaryName string

	validate func(hash.Hash) error
	prepare  func() (hash.Hash, error)
}

// newHash returns the hash the signed data is written to.
func (s *Signature) newHash() (hash.Hash, error) {
	if s.prepare != nil {
		return s.prepare()
	}

	return s.Hash.New(), nil
}

// VerifyOptions tunes [VerifyWithOptions]. The zero value is what [Verify]
// does.
type VerifyOptions struct {
	// RequireSigned makes a package that carries no PGP signature fail with
	// [ErrUnsigned]. Without it such a package verifies, with an empty list of
	// signatures, as long as its digests are good: an unsigned package is
	// intact, not authentic. Setting it needs known keys (a nil keyring fails
	// with [ErrNoKnownKeys]), since a signature that is not checked proves
	// nothing.
	RequireSigned bool
	// Now is the time source the validity of the keys and signatures is judged
	// at: expiry, creation after the check, revocation. Nil is time.Now.
	Now func() time.Time
}

// verifier is what the signature checks need besides the signature itself.
type verifier struct {
	keys openpgp.EntityList
	now  func() time.Time
}

// Verify the PGP signature over a RPM file. knownKeys should enumerate public
// keys to check against, otherwise the signature validity cannot be verified.
// If knownKeys is nil then digests will be checked but only the raw key ID will
// be available.
//
// A signature is accepted only if it matches the data and its key may be
// relied on now: the key (primary key, subkey and primary user id) is not
// revoked, not expired and allowed to sign, and the signature itself is not
// expired. Otherwise Verify fails with a [*SignatureError] wrapping
// [github.com/M0Rf30/pkgformat/gpg.ErrKeyRevoked], [github.com/M0Rf30/pkgformat/gpg.ErrKeyExpired], [github.com/M0Rf30/pkgformat/gpg.ErrSignatureExpired] or
// [github.com/M0Rf30/pkgformat/gpg.ErrKeyCannotSign].
//
// A package without any signature is not an error: Verify returns an empty
// list of signatures. Use [VerifyWithOptions] with RequireSigned, or check the
// length of the list, when a signature is mandatory.
func Verify(stream io.Reader, knownKeys openpgp.EntityList) (header *RpmHeader, sigs []*Signature, err error) {
	return VerifyWithOptions(stream, knownKeys, nil)
}

// VerifyWithKeyring is [VerifyWithOptions] with the keys of a [gpg.Keyring],
// the keyring type the deb, pacman and repository verifiers of this module
// take. A nil keyring checks digests only, like a nil key list.
func VerifyWithKeyring(stream io.Reader, keyring *gpg.Keyring, opts *VerifyOptions) (*RpmHeader, []*Signature, error) {
	var keys openpgp.EntityList
	if keyring != nil {
		keys = keyring.Entities()
	}

	return VerifyWithOptions(stream, keys, opts)
}

// VerifyWithOptions is [Verify] with options; a nil opts is the zero value.
func VerifyWithOptions(stream io.Reader, knownKeys openpgp.EntityList, opts *VerifyOptions) (header *RpmHeader, sigs []*Signature, err error) {
	vf := &verifier{keys: knownKeys, now: time.Now}
	if opts != nil && opts.Now != nil {
		vf.now = opts.Now
	}
	requireSigned := opts != nil && opts.RequireSigned
	if requireSigned && knownKeys == nil {
		return nil, nil, ErrNoKnownKeys
	}
	lead, sigHeader, err := readSignatureHeader(stream, HeaderLimits{})
	if err != nil {
		return nil, nil, err
	}
	// parse the general header
	genHeader, err := readGeneralHeader(stream, sigHeader, HeaderLimits{})
	if err != nil {
		return nil, nil, err
	}
	// setup digesters for PGP and payload digest
	sigs, hashes, err := digestAndVerify(sigHeader, genHeader, stream, vf)
	if err != nil {
		return nil, nil, err
	}
	if requireSigned && len(sigs) == 0 {
		return nil, nil, ErrUnsigned
	}
	// verify PGP signatures
	for i, sig := range sigs {
		h := hashes[i]
		if err := sig.validate(h); err != nil {
			return nil, nil, err
		}
	}
	hdr := &RpmHeader{
		lead:      lead,
		sigHeader: sigHeader,
		genHeader: genHeader,
		isSource:  sigHeader.isSource,
	}
	return hdr, sigs, nil
}

var (
	ErrNoPGPSignature  = errors.New("no supported PGP signature packet found")
	ErrTrailingGarbage = errors.New("trailing garbage after PGP signature packet")
	// ErrUnsigned means the package carries no PGP signature and
	// VerifyOptions.RequireSigned was set.
	ErrUnsigned = errors.New("rpm: package is not signed")
	// ErrNoKnownKeys means VerifyOptions.RequireSigned was set without keys to
	// check the signatures against.
	ErrNoKnownKeys = errors.New("rpm: signatures are required but no known keys were given")
)

// SignatureError reports a signature that matches the data but whose key
// cannot be relied on. Err is one of [github.com/M0Rf30/pkgformat/gpg.ErrKeyRevoked], [github.com/M0Rf30/pkgformat/gpg.ErrKeyExpired],
// [github.com/M0Rf30/pkgformat/gpg.ErrSignatureExpired], [github.com/M0Rf30/pkgformat/gpg.ErrKeyCannotSign] or [github.com/M0Rf30/pkgformat/gpg.ErrBadSignature],
// and is reachable with errors.Is.
type SignatureError struct {
	KeyID       uint64
	Fingerprint []byte
	Err         error
}

func (e *SignatureError) Error() string {
	return fmt.Sprintf("rpm: signature of key %016X: %v", e.KeyID, e.Err)
}

// Unwrap returns the reason.
func (e *SignatureError) Unwrap() error { return e.Err }

type KeyNotFoundError struct {
	KeyID       uint64
	Fingerprint []byte
}

func (e KeyNotFoundError) Error() string {
	if e.KeyID == 0 && len(e.Fingerprint) > 0 {
		return fmt.Sprintf("key with fingerprint %x not found", e.Fingerprint)
	}
	return fmt.Sprintf("keyid %08x not found", e.KeyID)
}
