package apt

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
)

// LoadKeyring returns the trust anchor of a source.
//
// With a signedBy path (the Signed-By option) it loads exactly that keyring file
// or directory of keyrings. A path that is missing, or that holds no key, is an
// error that wraps deb.ErrNoTrustAnchor.
//
// Without one it takes the union of every usable key found in defaults, which
// are keyring files or directories such as /etc/apt/trusted.gpg.d, in the same
// way apt trusts them. Paths that do not exist or cannot be parsed are skipped,
// as apt does; no key at all is deb.ErrNoTrustAnchor.
func LoadKeyring(signedBy string, defaults []string) (*gpg.Keyring, error) {
	if signedBy = strings.TrimSpace(signedBy); signedBy != "" {
		kr, err := loadKeyringPath(signedBy)
		if err != nil || kr.Len() == 0 {
			return nil, fmt.Errorf("%w: Signed-By %q", deb.ErrNoTrustAnchor, signedBy)
		}

		return kr, nil
	}

	combined := &gpg.Keyring{}

	for _, p := range defaults {
		kr, err := loadKeyringPath(p)
		if err != nil {
			continue
		}

		combined.Merge(kr)
	}

	if combined.Len() == 0 {
		return nil, deb.ErrNoTrustAnchor
	}

	return combined, nil
}

// loadKeyringPath loads a keyring file, or every keyring file of a directory.
func loadKeyringPath(path string) (*gpg.Keyring, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("apt: keyring: %w", err)
	}

	if info.IsDir() {
		kr, err := gpg.LoadKeyringDir(path)
		if err != nil {
			return nil, errors.Join(errors.New("apt: keyring directory"), err)
		}

		return kr, nil
	}

	return gpg.LoadKeyringFile(path)
}
