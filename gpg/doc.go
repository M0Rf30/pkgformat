// Package gpg signs and verifies with OpenPGP.
//
// Signing: a Signer produces cleartext (InRelease style) and detached
// signatures; LocalSigner implements it over a private key, with ASCII-armored
// (Release.gpg, repomd.xml.asc, .deb.asc) and binary (pacman .sig, RPM header
// signature) detached forms. GenerateEntity and ParsePrivateKey create and load
// keys.
//
// Verifying: a Keyring holds public keys, armored or binary, and
// VerifyClearsigned and VerifyDetached check a signature against it. Failures
// map onto sentinels (ErrUnknownSigner, ErrBadSignature, ErrKeyExpired, ...),
// so a caller can tell "signed by someone we do not trust yet" from "the data
// was altered". Both refuse revoked and expired keys and expired signatures.
// For callers that check a signature themselves with the OpenPGP library (the
// RPM header signatures), Keyring.Entities lists the keys and CheckSigner
// applies the same revocation, expiry and key-flag rules to the key that made a
// signature.
//
// What a caller trusts is policy and stays with the caller: which keyring
// applies to which repository, and whether an unsigned or unknown-signer
// repository is acceptable. The package never reads host paths on its own.
package gpg
