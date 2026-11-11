package dnf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/M0Rf30/pkgformat/httpclient"
	"github.com/M0Rf30/pkgformat/rpm"
)

// ErrNoGPGKey means a repository sets gpgcheck=1 but lists no gpgkey, so the
// signatures of its packages cannot be checked. Its packages are not
// downloaded.
var ErrNoGPGKey = errors.New("dnf: gpgcheck is enabled but the repository has no gpgkey")

// ErrRepoSignature means the repomd.xml of a repository with repo_gpgcheck=1
// is not signed by a key of its gpgkey lines: the signature is missing, wrong,
// by an unknown, revoked or expired key, or the repository lists no key.
var ErrRepoSignature = errors.New("dnf: repomd.xml signature check failed")

// ErrUnsupportedKeyURL means a gpgkey URL is not http, https or file.
var ErrUnsupportedKeyURL = errors.New("dnf: unsupported gpgkey URL")

// checkSignature verifies the OpenPGP signature of the package file at file
// when its repository says gpgcheck=1, against the repository's gpgkey keys.
// The package must carry a signature a listed key made and that is valid:
// a revoked or expired key, an expired signature, an unsigned package and an
// unknown signer all fail, wrapping the errors of [rpm.VerifyWithOptions].
func (c *Client) checkSignature(ctx context.Context, p *Package, file string) error {
	repo := p.repo
	if repo == nil || !repo.GPGCheck {
		return nil
	}

	hc, err := c.httpFor(repo)
	if err != nil {
		return err
	}

	keys, err := c.repoKeys(ctx, hc, repo)
	if err != nil {
		return fmt.Errorf("dnf: %s: %w", p.Name, err)
	}

	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("dnf: %s: %w", p.Name, err)
	}

	defer func() { _ = f.Close() }()

	if _, _, err := rpm.VerifyWithOptions(f, keys, &rpm.VerifyOptions{RequireSigned: true}); err != nil {
		return fmt.Errorf("dnf: %s: package signature: %w", p.Name, err)
	}

	return nil
}

// VerifyLocal checks the signature of the package file at path, which is not
// from a repository, when the configuration says localpkg_gpgcheck=1; with it
// off it checks nothing and returns nil. The package must carry a valid
// signature of a key of [Options.LocalKeys] or of the gpgkey lines of an
// enabled repository, and fails with the errors of [rpm.VerifyWithOptions]
// otherwise; [ErrNoGPGKey] means there is no key at all to check against.
func (c *Client) VerifyLocal(ctx context.Context, path string) error {
	cfg, err := c.Config()
	if err != nil {
		return err
	}

	if !cfg.LocalPkgGPGCheck {
		return nil
	}

	ring := new(gpg.Keyring)
	if c.opts.LocalKeys != nil {
		ring.Merge(c.opts.LocalKeys)
	}

	repos, err := c.enabledRepos()
	if err != nil {
		return err
	}

	for i := range repos {
		if len(repos[i].GPGKeys) == 0 {
			continue
		}

		hc, err := c.httpFor(&repos[i])
		if err != nil {
			return err
		}

		kr, err := c.repoKeyring(ctx, hc, &repos[i])
		if err != nil {
			return fmt.Errorf("dnf: %s: %w", path, err)
		}

		ring.Merge(kr)
	}

	keys := ring.Entities()
	if len(keys) == 0 {
		return fmt.Errorf("dnf: %s: %w", path, ErrNoGPGKey)
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("dnf: %w", err)
	}

	defer func() { _ = f.Close() }()

	if _, _, err := rpm.VerifyWithOptions(f, keys, &rpm.VerifyOptions{RequireSigned: true}); err != nil {
		return fmt.Errorf("dnf: %s: package signature: %w", path, err)
	}

	return nil
}

// repoKeys returns the keys of the gpgkey URLs of a repository.
func (c *Client) repoKeys(ctx context.Context, hc *httpclient.Client, repo *Repo) (openpgp.EntityList, error) {
	ring, err := c.repoKeyring(ctx, hc, repo)
	if err != nil {
		return nil, err
	}

	return ring.Entities(), nil
}

// repoKeyring loads the gpgkey files of a repository into one keyring.
func (c *Client) repoKeyring(ctx context.Context, hc *httpclient.Client, repo *Repo) (*gpg.Keyring, error) {
	if len(repo.GPGKeys) == 0 {
		return nil, fmt.Errorf("repository %s: %w", repo.ID, ErrNoGPGKey)
	}

	ring := new(gpg.Keyring)

	for _, raw := range repo.GPGKeys {
		kr, err := c.loadKey(ctx, hc, c.expandVars(raw))
		if err != nil {
			return nil, fmt.Errorf("repository %s: gpgkey %s: %w", repo.ID, raw, err)
		}

		ring.Merge(kr)
	}

	return ring, nil
}

// maxSignatureBytes bounds repomd.xml.asc.
const maxSignatureBytes = 1 << 20

// checkRepomdSignature verifies the detached signature of repomd.xml
// (repodata/repomd.xml.asc on the same mirror) against the gpgkey keys of the
// repository.
func (c *Client) checkRepomdSignature(
	ctx context.Context, hc *httpclient.Client, repo *Repo, base string, repomd []byte,
) error {
	ring, err := c.repoKeyring(ctx, hc, repo)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRepoSignature, err)
	}

	sig, err := hc.FetchBytes(ctx, base+"/"+repodataDir+"/"+repomdName+".asc", maxSignatureBytes)
	if err != nil {
		return fmt.Errorf("%w: %s: fetching repomd.xml.asc: %w", ErrRepoSignature, repo.ID, err)
	}

	if _, err := gpg.VerifyDetached(ring, bytes.NewReader(repomd), sig); err != nil {
		return fmt.Errorf("%w: %s: %s: %w", ErrRepoSignature, repo.ID, base, err)
	}

	return nil
}

// loadKey reads one key file, over HTTP or from the file system, once per URL.
func (c *Client) loadKey(ctx context.Context, hc *httpclient.Client, rawURL string) (*gpg.Keyring, error) {
	if v, ok := c.keyrings.Load(rawURL); ok {
		return v.(*gpg.Keyring), nil //nolint:forcetypeassert // only loadKey stores here
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedKeyURL, rawURL)
	}

	var data []byte

	switch u.Scheme {
	case "https":
		data, err = hc.FetchBytes(ctx, rawURL, gpg.MaxKeyringBytes)
	case "http":
		c.opts.Logger.Warn("fetching a gpgkey over plain http", "url", rawURL)

		data, err = hc.FetchBytes(ctx, rawURL, gpg.MaxKeyringBytes)
	case "file":
		if u.Host != "" && u.Host != "localhost" {
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedKeyURL, rawURL)
		}

		data, err = readCapped(u.Path, gpg.MaxKeyringBytes)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedKeyURL, rawURL)
	}

	if err != nil {
		return nil, err
	}

	ring, err := gpg.ParseKeyring(data)
	if err != nil {
		return nil, err
	}

	actual, _ := c.keyrings.LoadOrStore(rawURL, ring)

	return actual.(*gpg.Keyring), nil //nolint:forcetypeassert // only loadKey stores here
}
