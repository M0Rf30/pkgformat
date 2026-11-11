package apt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
)

const (
	pgpBegin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	pgpEnd   = "-----END PGP PUBLIC KEY BLOCK-----"

	// fingerprintLen is the length of a v4 key fingerprint in hex digits.
	fingerprintLen = 40
)

// KeyNotFoundError reports the fingerprints of a Signed-By option that no
// searched keyring holds. It matches deb.ErrNoTrustAnchor.
type KeyNotFoundError struct {
	// Fingerprints are the missing fingerprints, upper-case, without the "!".
	Fingerprints []string
}

// Error lists the missing fingerprints.
func (e *KeyNotFoundError) Error() string {
	return "apt: Signed-By key not found in the keyrings: " + strings.Join(e.Fingerprints, ", ")
}

// Unwrap makes the error match deb.ErrNoTrustAnchor.
func (e *KeyNotFoundError) Unwrap() error { return deb.ErrNoTrustAnchor }

// signedByKey is one fingerprint of a Signed-By option.
type signedByKey struct {
	// fingerprint is 40 upper-case hex digits.
	fingerprint string
	// exact is set by a trailing "!": only signatures made by that very key,
	// not by its subkeys.
	exact bool
}

// signedBySpec is a parsed Signed-By option.
type signedBySpec struct {
	// inline holds the armored key blocks of an inline key, normalised.
	inline []string
	// paths are absolute keyring files or directories.
	paths []string
	// keys are the fingerprints that select keys from the keyrings.
	keys []signedByKey
}

// parseSignedBy checks and splits a Signed-By value the way apt's
// NormalizeSignedBy does: either an inline armored public key block (alone), or
// a list, separated by commas and blanks, of 40-digit fingerprints (with an
// optional trailing "!") and absolute keyring paths. Anything else, in
// particular a relative path or a key block mixed with other words, is an
// ErrInvalidSignedBy.
func parseSignedBy(v string) (*signedBySpec, error) {
	if len(v) > MaxSourcesFileBytes {
		return nil, fmt.Errorf("%w: %w: over %d bytes", ErrInvalidSignedBy, ErrTooLarge, MaxSourcesFileBytes)
	}

	if strings.Contains(v, pgpBegin) {
		return parseInlineKey(v)
	}

	words := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || (r >= '\t' && r <= '\r') })
	if len(words) == 0 {
		return nil, fmt.Errorf("%w: no key", ErrInvalidSignedBy)
	}

	if len(words) > MaxSourceListValues {
		return nil, fmt.Errorf("%w: %w: more than %d values", ErrInvalidSignedBy, ErrTooLarge, MaxSourceListValues)
	}

	spec := &signedBySpec{}

	for _, w := range words {
		if strings.HasPrefix(w, "/") {
			if strings.ContainsRune(w, 0) {
				return nil, fmt.Errorf("%w: path with a NUL byte", ErrInvalidSignedBy)
			}

			spec.paths = append(spec.paths, w)

			continue
		}

		key, ok := parseFingerprint(w)
		if !ok {
			return nil, fmt.Errorf("%w: %q is neither a fingerprint nor an absolute path", ErrInvalidSignedBy, w)
		}

		spec.keys = append(spec.keys, key)
	}

	return spec, nil
}

// parseFingerprint reads 40 hex digits and an optional "!".
func parseFingerprint(w string) (signedByKey, bool) {
	exact := strings.HasSuffix(w, "!")
	fp := strings.ToUpper(strings.TrimSuffix(w, "!"))

	if len(fp) != fingerprintLen {
		return signedByKey{}, false
	}

	if _, err := hex.DecodeString(fp); err != nil {
		return signedByKey{}, false
	}

	return signedByKey{fingerprint: fp, exact: exact}, true
}

// parseInlineKey normalises an inline key like apt: each line is stripped and
// a "." line is an empty line (the deb822 encoding). The value must consist
// of armored public key blocks and blank lines only.
func parseInlineKey(v string) (*signedBySpec, error) {
	var (
		spec  = &signedBySpec{}
		block strings.Builder
		in    bool
	)

	for line := range strings.Lines(v) {
		line = strings.TrimSpace(line)
		if line == "." {
			line = ""
		}

		switch {
		case !in && line == pgpBegin:
			in = true

			block.Reset()
			block.WriteString(line + "\n")
		case in:
			block.WriteString(line + "\n")

			if line == pgpEnd {
				in = false

				spec.inline = append(spec.inline, block.String())
			}
		case line != "":
			return nil, fmt.Errorf("%w: text outside the key block (an inline key cannot be mixed with other values)", ErrInvalidSignedBy)
		}
	}

	if in {
		return nil, fmt.Errorf("%w: key block is not terminated", ErrInvalidSignedBy)
	}

	return spec, nil
}

// LoadKeyring returns the trust anchor of a source: the public keys its
// Release may be signed by.
//
// signedBy is the Signed-By option, in any form apt takes:
//
//   - empty: the union of every usable key found in defaults, which are
//     keyring files or directories such as /etc/apt/trusted.gpg.d, as apt trusts
//     them. Paths that do not exist or cannot be parsed are skipped; no key at
//     all is deb.ErrNoTrustAnchor.
//   - a list of absolute keyring paths, separated by commas or blanks: exactly
//     those keyring files, or directories of *.gpg and *.asc files. A path that
//     is missing, or holds no key, fails. A value that is as a whole one
//     existing absolute path is that path, even with blanks or commas in it.
//   - a list of fingerprints (40 hex digits, optionally ending in "!"): those
//     keys, selected from the keyrings of defaults. A fingerprint selects the
//     key and its subkeys, so signatures by a subkey verify; with "!" only
//     the key itself. The fingerprint of a subkey selects that subkey. A
//     fingerprint found in none of the keyrings fails with *KeyNotFoundError.
//   - paths and fingerprints together: the fingerprints select from the listed
//     keyrings instead of the defaults, as in apt.
//   - an inline armored PGP public key block (the deb822 multi-line form, with
//     " ." for empty lines). It cannot be mixed with other values.
//
// Every failure wraps deb.ErrNoTrustAnchor; an unusable value also wraps
// ErrInvalidSignedBy.
//
// A selection by fingerprint is rebuilt from the selected keys, so the result
// holds only those (and not, say, the other keys of the same file); it keeps
// every certificate and signature of them.
func LoadKeyring(signedBy string, defaults []string) (*gpg.Keyring, error) {
	if signedBy = strings.TrimSpace(signedBy); signedBy == "" {
		kr := loadDefaultKeyrings(defaults)
		if kr.Len() == 0 {
			return nil, deb.ErrNoTrustAnchor
		}

		return kr, nil
	}

	// A value that is, as a whole, an existing absolute path names that one
	// file or directory, whatever blanks or commas are in it (apt cannot
	// express such paths, but a client's temporary directories have them).
	if strings.HasPrefix(signedBy, "/") && !strings.ContainsAny(signedBy, "\n\x00") {
		if _, err := os.Stat(signedBy); err == nil { //nolint:gosec // the path is the source's own configuration
			kr, err := loadKeyringPath(signedBy)
			if err != nil || kr.Len() == 0 {
				return nil, fmt.Errorf("%w: Signed-By %q", deb.ErrNoTrustAnchor, signedBy)
			}

			return kr, nil
		}
	}

	spec, err := parseSignedBy(signedBy)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", deb.ErrNoTrustAnchor, err)
	}

	if len(spec.inline) > 0 {
		return loadInlineKey(spec)
	}

	var pool *gpg.Keyring

	if len(spec.paths) > 0 {
		pool = &gpg.Keyring{}

		for _, p := range spec.paths {
			kr, err := loadKeyringPath(p)
			if err != nil || kr.Len() == 0 {
				return nil, fmt.Errorf("%w: Signed-By %q", deb.ErrNoTrustAnchor, p)
			}

			pool.Merge(kr)
		}
	} else {
		pool = loadDefaultKeyrings(defaults)
	}

	if len(spec.keys) == 0 {
		return pool, nil
	}

	return selectKeys(pool, spec.keys)
}

// loadDefaultKeyrings merges the keyrings of paths, skipping what fails.
func loadDefaultKeyrings(paths []string) *gpg.Keyring {
	combined := &gpg.Keyring{}

	for _, p := range paths {
		if kr, err := loadKeyringPath(p); err == nil {
			combined.Merge(kr)
		}
	}

	return combined
}

// loadInlineKey parses the key blocks of an inline Signed-By.
func loadInlineKey(spec *signedBySpec) (*gpg.Keyring, error) {
	combined := &gpg.Keyring{}

	for _, block := range spec.inline {
		kr, err := gpg.ParseKeyring([]byte(block))
		if err != nil {
			return nil, fmt.Errorf("%w: inline Signed-By key: %w", deb.ErrNoTrustAnchor, err)
		}

		combined.Merge(kr)
	}

	return combined, nil
}

// selection says which parts of one key a Signed-By selects.
type selection struct {
	// whole is set when the key and all its subkeys are selected.
	whole bool
	// subkeys are the indexes of the selected subkeys.
	subkeys map[int]bool
}

// selectKeys returns the keys of pool the fingerprints select, as a new
// keyring, or *KeyNotFoundError.
func selectKeys(pool *gpg.Keyring, keys []signedByKey) (*gpg.Keyring, error) {
	entities := pool.Entities()
	picked := make(map[int]*selection)

	var missing []string

	for _, k := range keys {
		found := false

		for i, e := range entities {
			sel := picked[i]
			if sel == nil {
				sel = &selection{subkeys: make(map[int]bool)}
			}

			hit := false

			if fingerprintHex(e.PrimaryKey.Fingerprint) == k.fingerprint {
				hit = true
				sel.whole = sel.whole || !k.exact
			}

			for j, sk := range e.Subkeys {
				if fingerprintHex(sk.PublicKey.Fingerprint) == k.fingerprint {
					hit = true
					sel.subkeys[j] = true
				}
			}

			if hit {
				found = true
				picked[i] = sel
			}
		}

		if !found {
			missing = append(missing, k.fingerprint)
		}
	}

	if len(missing) > 0 {
		return nil, &KeyNotFoundError{Fingerprints: missing}
	}

	var buf bytes.Buffer

	seen := make(map[string]bool)

	for i, e := range entities {
		sel := picked[i]
		if sel == nil {
			continue
		}

		// The same key in several keyrings is taken once.
		fp := fingerprintHex(e.PrimaryKey.Fingerprint)
		if seen[fp] {
			continue
		}

		seen[fp] = true

		if !sel.whole {
			cp := *e
			cp.Subkeys = nil

			for j, sk := range e.Subkeys {
				if sel.subkeys[j] {
					cp.Subkeys = append(cp.Subkeys, sk)
				}
			}

			e = &cp
		}

		if err := serializePublic(&buf, e); err != nil {
			return nil, fmt.Errorf("%w: %w", deb.ErrNoTrustAnchor, err)
		}
	}

	kr, err := gpg.ParseKeyring(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", deb.ErrNoTrustAnchor, err)
	}

	return kr, nil
}

func serializePublic(buf *bytes.Buffer, e *openpgp.Entity) error {
	if err := e.Serialize(buf); err != nil {
		return fmt.Errorf("apt: serialize key: %w", err)
	}

	return nil
}

// fingerprintHex renders a fingerprint as upper-case hex.
func fingerprintHex(fp []byte) string {
	return strings.ToUpper(hex.EncodeToString(fp))
}

// loadKeyringPath loads a keyring file, or every keyring file of a directory.
func loadKeyringPath(path string) (*gpg.Keyring, error) {
	info, err := os.Stat(path) //nolint:gosec // keyring paths are the caller's configuration
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
