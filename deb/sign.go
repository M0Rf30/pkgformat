package deb

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// SignedRelease is a Release document with the signatures a repository
// publishes next to it.
type SignedRelease struct {
	// Release is the document as signed, published as dists/<dist>/Release.
	Release []byte
	// InRelease is the clear-signed document, dists/<dist>/InRelease.
	InRelease []byte
	// ReleaseGPG is the armored detached signature, dists/<dist>/Release.gpg.
	ReleaseGPG []byte
	// Fingerprint is the fingerprint of the signing key.
	Fingerprint string
}

// ErrNoSigner is returned by SignRelease when no signer is given.
var ErrNoSigner = errors.New("deb: no signer configured")

// SignRelease signs a Release document with signer and returns the three
// files apt reads: Release, InRelease and Release.gpg.
func SignRelease(signer gpg.Signer, release []byte) (*SignedRelease, error) {
	if signer == nil {
		return nil, ErrNoSigner
	}

	detached, err := signer.DetachedSign(bytes.NewReader(release))
	if err != nil {
		return nil, fmt.Errorf("deb: creating detached signature: %w", err)
	}

	clear, err := signer.CleartextSign(bytes.NewReader(release))
	if err != nil {
		return nil, fmt.Errorf("deb: creating cleartext signature: %w", err)
	}

	inRelease, err := limitio.ReadAll(clear, 2*MaxReleaseBytes, ErrTooLarge)
	if err != nil {
		return nil, fmt.Errorf("deb: reading InRelease data: %w", err)
	}

	return &SignedRelease{
		Release:     release,
		InRelease:   inRelease,
		ReleaseGPG:  detached,
		Fingerprint: signer.KeyFingerprint(),
	}, nil
}
