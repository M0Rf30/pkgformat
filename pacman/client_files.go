package pacman

import (
	"context"
	"errors"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/M0Rf30/pkgformat/download"
	"github.com/M0Rf30/pkgformat/gpg"
)

// VerifyPackageFile verifies the package file at name, one the caller names
// explicitly (pacman -U on a path), against its detached signature in
// "<name>.sig", under policy: pass Config.LocalFileSigLevel.Package. An unset
// policy falls back to ClientOptions.PackageSignatures. It returns nil, nil
// when the policy is Never or the signature is absent and not required.
func (c *Client) VerifyPackageFile(name string, policy SigPolicy) (*gpg.Verified, error) {
	mode := c.policyMode(policy)
	if mode == VerifyNone {
		return nil, nil //nolint:nilnil // nothing is verified, so there is no signer to report
	}

	if c.opts.Keyring.Len() == 0 {
		return nil, ErrNoKeyring
	}

	sig, err := readSignatureFile(name + ".sig")
	if err != nil {
		return nil, err
	}

	f, err := os.Open(filepath.Clean(name))
	if err != nil {
		return nil, fmt.Errorf("pacman: opening %s: %w", name, err)
	}

	defer func() { _ = f.Close() }()

	v, err := c.verify(f, sig, mode)
	if err != nil {
		return nil, fmt.Errorf("verifying %s: %w", name, err)
	}

	return v, nil
}

// readSignatureFile reads a ".sig" file; a missing one is a nil signature.
func readSignatureFile(name string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil //nolint:nilnil // an absent signature is not an error; the caller applies the policy
	}

	if err != nil {
		return nil, fmt.Errorf("pacman: opening signature: %w", err)
	}

	defer func() { _ = f.Close() }()

	sig, err := io.ReadAll(io.LimitReader(f, MaxSignatureBytes+1))
	if err != nil {
		return nil, fmt.Errorf("pacman: reading signature: %w", err)
	}

	if len(sig) > MaxSignatureBytes {
		return nil, ErrInvalidSignature
	}

	return sig, nil
}

// DownloadPackageFile downloads the package at rawURL into dir, as pacman -U
// does for a URL, and returns its path. The file takes the last element of the
// URL's path as its name. Its signature "<url>.sig" is checked under policy:
// pass Config.RemoteFileSigLevel.Package; an unset policy falls back to
// ClientOptions.PackageSignatures. A package that fails verification is
// removed. The package has no database entry to check its size or digest
// against, so the download is bounded by DefaultMaxPackageBytes only.
func (c *Client) DownloadPackageFile(ctx context.Context, rawURL, dir string, policy SigPolicy) (string, error) {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("pacman: parsing %q: %w", rawURL, err)
	}

	base := path.Base(u.Path)
	if !ValidFileName(base) {
		return "", fmt.Errorf("%w: file name %q", ErrInvalidField, base)
	}

	mode := c.policyMode(policy)
	if mode != VerifyNone && c.opts.Keyring.Len() == 0 {
		return "", ErrNoKeyring
	}

	dest := filepath.Join(dir, base)

	req := download.Request{URL: rawURL, Dest: dest, MaxBytes: DefaultMaxPackageBytes}

	if c.opts.Progress != nil {
		req.Progress = func(done, total int64) { c.opts.Progress(base, done, total) }
	}

	if err := download.Download(ctx, req, download.Options{Client: c.http}); err != nil {
		return "", fmt.Errorf("downloading %s: %w", rawURL, err)
	}

	if mode == VerifyNone {
		return dest, nil
	}

	if err := c.verifyDownloaded(ctx, u, dest, mode); err != nil {
		_ = os.Remove(dest)

		return "", err
	}

	return dest, nil
}

func (c *Client) verifyDownloaded(ctx context.Context, u *neturl.URL, dest string, mode VerifyMode) error {
	sigURL := *u
	sigURL.Path += ".sig"

	sig, err := c.http.FetchBytes(ctx, sigURL.String(), MaxSignatureBytes)

	switch {
	case err == nil:
	case isAbsent(err):
		sig = nil
	default:
		return fmt.Errorf("fetching %s: %w", sigURL.String(), err)
	}

	f, err := os.Open(filepath.Clean(dest))
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()

	if _, err := c.verify(f, sig, mode); err != nil {
		return fmt.Errorf("verifying %s: %w", u.String(), err)
	}

	return nil
}
