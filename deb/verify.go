package deb

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"

	"github.com/M0Rf30/pkgformat/gpg"
)

var (
	// ErrNoTrustAnchor is returned when there is no keyring to verify a Release
	// with. The caller decides whether to treat it as fatal or, with
	// Trust.AllowUnverified, to go on.
	ErrNoTrustAnchor = errors.New("deb: no usable trust anchor for source")
	// ErrUnsigned is returned when a Release carries no signature at all.
	ErrUnsigned = fmt.Errorf("deb: release file is not signed: %w", gpg.ErrUnsigned)
	// ErrUnknownSigner is returned when a Release is signed by a key outside the
	// keyring. It is gpg.ErrUnknownSigner.
	ErrUnknownSigner = gpg.ErrUnknownSigner
)

// Trust is the policy for accepting a Release or InRelease document.
//
//   - A signature that exists and does not verify (altered data, expired or
//     revoked key) is always an error, even with AllowUnverified: it points
//     to an attack or a broken mirror, and ignoring it is worse than not
//     verifying at all.
//   - No keys, a signature by an unknown key, or no signature at all fail
//     unless AllowUnverified is set, in which case the document is accepted
//     unverified and a warning is logged.
type Trust struct {
	// Keyring holds the trusted public keys. Nil or empty means no trust anchor.
	Keyring *gpg.Keyring
	// KeyringErr is the reason Keyring is empty (an unreadable file, ...). It is
	// the error returned when no keyring is available and AllowUnverified is
	// not set; nil gives ErrNoTrustAnchor.
	KeyringErr error
	// AllowUnverified lets unsigned documents, unknown signers and a missing
	// keyring through.
	AllowUnverified bool
	// Logger receives the outcome of every verification. Nil is silent.
	Logger *slog.Logger
	// Source names the repository in log records, normally its base URL.
	Source string
}

func (t Trust) log() *slog.Logger {
	if t.Logger != nil {
		return t.Logger
	}

	return slog.New(slog.DiscardHandler)
}

func (t Trust) noAnchor() error {
	if t.KeyringErr != nil {
		return t.KeyringErr
	}

	return ErrNoTrustAnchor
}

// VerifyInRelease verifies a clear-signed InRelease document under the policy
// and returns its signed text.
func (t Trust) VerifyInRelease(data []byte) ([]byte, error) {
	log := t.log()

	if t.Keyring.Len() == 0 {
		if !t.AllowUnverified {
			return nil, t.noAnchor()
		}

		log.Warn("skipping InRelease signature check: no trust anchor", "source", t.Source, "reason", t.KeyringErr)

		return StripClearsign(data), nil
	}

	body, who, err := gpg.VerifyClearsigned(t.Keyring, data)
	if err == nil {
		log.Info("verified InRelease signature", "source", t.Source, "signer", who.Identity, "fingerprint", who.Fingerprint)

		return body, nil
	}

	switch {
	case errors.Is(err, gpg.ErrUnknownSigner):
		if !t.AllowUnverified {
			return nil, fmt.Errorf("deb: InRelease signature verification failed: %w", err)
		}

		log.Warn("skipping InRelease signature check: unknown signer", "source", t.Source, "reason", err)

		return StripClearsign(data), nil
	case errors.Is(err, gpg.ErrUnsigned), errors.Is(err, gpg.ErrNotClearsigned):
		if !t.AllowUnverified {
			return nil, fmt.Errorf("deb: InRelease is not signed: %w", err)
		}

		log.Warn("accepting unsigned InRelease", "source", t.Source)

		return StripClearsign(data), nil
	}

	return nil, fmt.Errorf("deb: InRelease signature verification failed: %w", err)
}

// VerifyReleaseGPG verifies a plain Release document against its detached
// signature under the policy and returns the Release unchanged. sigErr is the
// error of fetching the signature: when not nil the signature is treated as
// missing.
func (t Trust) VerifyReleaseGPG(body, sig []byte, sigErr error) ([]byte, error) {
	log := t.log()

	if sigErr != nil {
		if !t.AllowUnverified {
			return nil, fmt.Errorf("deb: Release.gpg not available: %w", sigErr)
		}

		log.Warn("accepting unsigned Release", "source", t.Source, "reason", sigErr)

		return body, nil
	}

	if t.Keyring.Len() == 0 {
		if !t.AllowUnverified {
			return nil, t.noAnchor()
		}

		log.Warn("skipping Release.gpg signature check: no trust anchor", "source", t.Source, "reason", t.KeyringErr)

		return body, nil
	}

	who, err := gpg.VerifyDetached(t.Keyring, bytes.NewReader(body), sig)
	if err == nil {
		log.Info("verified Release.gpg signature", "source", t.Source, "signer", who.Identity, "fingerprint", who.Fingerprint)

		return body, nil
	}

	if errors.Is(err, gpg.ErrUnknownSigner) && t.AllowUnverified {
		log.Warn("skipping Release.gpg signature check: unknown signer", "source", t.Source, "reason", err)

		return body, nil
	}

	return nil, fmt.Errorf("deb: Release.gpg signature verification failed: %w", err)
}
