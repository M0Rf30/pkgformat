package repodata

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/M0Rf30/pkgformat/gpg"
)

// Errors of the repository signer.
var (
	// ErrSignerNil means no signer was given.
	ErrSignerNil = errors.New("repodata: signer is nil")
	// ErrEmptyRepomd means there is no repomd.xml to sign.
	ErrEmptyRepomd = errors.New("repodata: empty repomd.xml")
)

// SignRepomdXML returns the armored detached signature of repomd.xml, the
// content of repomd.xml.asc that clients check with repo_gpgcheck.
func SignRepomdXML(signer gpg.Signer, repomdXML []byte) ([]byte, error) {
	if signer == nil {
		return nil, ErrSignerNil
	}

	if len(repomdXML) == 0 {
		return nil, ErrEmptyRepomd
	}

	signature, err := signer.DetachedSign(bytes.NewReader(repomdXML))
	if err != nil {
		return nil, fmt.Errorf("repodata: signing repomd.xml: %w", err)
	}

	return signature, nil
}

// PublicKey returns the armored public key clients import to verify the
// signature of repomd.xml.
func PublicKey(signer gpg.Signer) ([]byte, error) {
	if signer == nil {
		return nil, ErrSignerNil
	}

	return signer.PublicKey()
}
