package apt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
)

// The keys and signed files of testdata/keyring are made by gpg (see
// generate.sh there): A and B are signing keys, C is a certify-only key that
// signs through a subkey.
const keyringFixtures = "testdata/keyring"

type keyringFixture struct {
	fpA, fpB, fpC, fpCSub string
	// defaults is a directory holding the keys of A, B and C.
	defaults string
}

func loadKeyringFixture(t *testing.T) keyringFixture {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(keyringFixtures, "fingerprints.txt"))
	require.NoError(t, err)

	fps := map[string]string{}

	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		name, fp, ok := strings.Cut(line, " ")
		require.True(t, ok, line)

		fps[name] = fp
	}

	dir := t.TempDir()

	for _, name := range []string{"a.gpg", "b.asc", "c.asc"} {
		b, err := os.ReadFile(filepath.Join(keyringFixtures, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), b, 0o644))
	}

	return keyringFixture{fpA: fps["A"], fpB: fps["B"], fpC: fps["C"], fpCSub: fps["C-subkey"], defaults: dir}
}

// fixture returns the absolute path of a file of testdata/keyring, which is
// what Signed-By requires.
func (keyringFixture) fixture(name string) string {
	abs, err := filepath.Abs(filepath.Join(keyringFixtures, name))
	if err != nil {
		panic(err)
	}

	return abs
}

// verifies reports whether kr verifies the clear-signed fixture file.
func verifies(t *testing.T, kr *gpg.Keyring, file string) bool {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(keyringFixtures, file))
	require.NoError(t, err)

	body, v, err := gpg.VerifyClearsigned(kr, data)
	if err != nil {
		return false
	}

	assert.Contains(t, string(body), "Origin: keyring-test")
	assert.NotEmpty(t, v.Fingerprint)

	return true
}

func TestLoadKeyringPathsWithGpgKeys(t *testing.T) {
	t.Parallel()

	f := loadKeyringFixture(t)

	kr, err := LoadKeyring(f.fixture("a.asc"), nil)
	require.NoError(t, err)
	require.Equal(t, 1, kr.Len())
	assert.True(t, verifies(t, kr, "signed-by-a.txt"))
	assert.False(t, verifies(t, kr, "signed-by-b.txt"))

	// binary keyring holding two keys, listed with a comma and a blank
	kr, err = LoadKeyring(f.fixture("bc.gpg")+", "+f.fixture("a.asc"), nil)
	require.NoError(t, err)
	assert.Equal(t, 3, kr.Len())
	assert.True(t, verifies(t, kr, "signed-by-a.txt"))
	assert.True(t, verifies(t, kr, "signed-by-b.txt"))
	assert.True(t, verifies(t, kr, "signed-by-c-subkey.txt"))

	kr, err = LoadKeyring(f.defaults, nil)
	require.NoError(t, err)
	assert.Equal(t, 3, kr.Len())

	// newline-separated, as a deb822 field arrives
	kr, err = LoadKeyring(f.fixture("a.asc")+"\n "+f.fixture("b.asc"), nil)
	require.NoError(t, err)
	assert.Equal(t, 2, kr.Len())
}

func TestLoadKeyringFingerprints(t *testing.T) {
	t.Parallel()

	f := loadKeyringFixture(t)
	defaults := []string{filepath.Join(f.defaults, "absent"), f.defaults}

	tests := []struct {
		name     string
		signedBy string
		want     int
		a, b, c  bool
	}{
		{"A", f.fpA, 1, true, false, false},
		{"lower case", strings.ToLower(f.fpA), 1, true, false, false},
		{"A exact", f.fpA + "!", 1, true, false, false},
		{"A and B with a comma", f.fpA + "," + f.fpB, 2, true, true, false},
		{"A and B with blanks and a newline", f.fpA + "\n " + f.fpB + "!", 2, true, true, false},
		{"C takes its subkeys", f.fpC, 1, false, false, true},
		{"C exact has no signing key", f.fpC + "!", 1, false, false, false},
		{"the subkey", f.fpCSub, 1, false, false, true},
		{"the subkey exact", f.fpCSub + "!", 1, false, false, true},
		{"the primary and the subkey exact", f.fpC + "! " + f.fpCSub + "!", 1, false, false, true},
		{"the key twice", f.fpA + " " + f.fpA + "!", 1, true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kr, err := LoadKeyring(tt.signedBy, defaults)
			require.NoError(t, err)
			assert.Equal(t, tt.want, kr.Len())
			assert.Equal(t, tt.a, verifies(t, kr, "signed-by-a.txt"), "key A")
			assert.Equal(t, tt.b, verifies(t, kr, "signed-by-b.txt"), "key B")
			assert.Equal(t, tt.c, verifies(t, kr, "signed-by-c-subkey.txt"), "key C by its subkey")
		})
	}
}

func TestLoadKeyringFingerprintFromKeyringList(t *testing.T) {
	t.Parallel()

	f := loadKeyringFixture(t)

	// Fingerprints select from the listed keyrings, not from the defaults.
	kr, err := LoadKeyring(f.fixture("bc.gpg")+" "+f.fpB, []string{f.defaults})
	require.NoError(t, err)
	require.Equal(t, 1, kr.Len())
	assert.True(t, verifies(t, kr, "signed-by-b.txt"))
	assert.False(t, verifies(t, kr, "signed-by-c-subkey.txt"))

	_, err = LoadKeyring(f.fixture("bc.gpg")+" "+f.fpA, []string{f.defaults})

	var nf *KeyNotFoundError

	require.ErrorAs(t, err, &nf)
	assert.Equal(t, []string{f.fpA}, nf.Fingerprints)

	// a key present in two keyrings is selected once
	kr, err = LoadKeyring(f.fixture("a.asc")+" "+f.fixture("a.gpg")+" "+f.fpA, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, kr.Len())
}

func TestLoadKeyringFingerprintNotFound(t *testing.T) {
	t.Parallel()

	f := loadKeyringFixture(t)
	missing := strings.Repeat("AB", 20)

	_, err := LoadKeyring(f.fpA+" "+missing+" "+strings.Repeat("0", 40)+"!", []string{f.defaults})
	require.ErrorIs(t, err, deb.ErrNoTrustAnchor)

	var nf *KeyNotFoundError

	require.ErrorAs(t, err, &nf)
	assert.Equal(t, []string{missing, strings.Repeat("0", 40)}, nf.Fingerprints)
	assert.Contains(t, nf.Error(), missing)

	_, err = LoadKeyring(missing, nil)
	require.ErrorIs(t, err, deb.ErrNoTrustAnchor)

	_, err = LoadKeyring(missing, []string{filepath.Join(f.defaults, "absent")})
	require.ErrorIs(t, err, deb.ErrNoTrustAnchor)
}

// inlineKey writes an armored key the way a deb822 Signed-By field holds it:
// every line indented, empty lines as ".".
func inlineKey(t *testing.T, name string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(keyringFixtures, name))
	require.NoError(t, err)

	var sb strings.Builder

	for line := range strings.Lines(strings.TrimRight(string(data), "\n")) {
		line = strings.TrimRight(line, "\n")
		if line == "" {
			line = "."
		}

		sb.WriteString(" " + line + "\n")
	}

	return strings.TrimRight(sb.String(), "\n")
}

func TestLoadKeyringInline(t *testing.T) {
	t.Parallel()

	f := loadKeyringFixture(t)

	// as ParseSources822 hands it over
	stanza := "Types: deb\nURIs: http://h/\nSuites: s\nComponents: c\nSigned-By:\n" + inlineKey(t, "a.asc") + "\n"

	srcs, err := ParseSources822(stanza)
	require.NoError(t, err)
	require.Len(t, srcs, 1)

	kr, err := LoadKeyring(srcs[0].SignedBy, nil)
	require.NoError(t, err)
	require.Equal(t, 1, kr.Len())
	assert.True(t, verifies(t, kr, "signed-by-a.txt"))
	assert.False(t, verifies(t, kr, "signed-by-b.txt"))

	// the plain armored text, and two blocks
	a, err := os.ReadFile(f.fixture("a.asc"))
	require.NoError(t, err)

	b, err := os.ReadFile(f.fixture("b.asc"))
	require.NoError(t, err)

	kr, err = LoadKeyring("\n"+string(a)+"\n\n"+string(b), []string{f.defaults})
	require.NoError(t, err)
	assert.Equal(t, 2, kr.Len())
	assert.True(t, verifies(t, kr, "signed-by-b.txt"))
}

func TestLoadKeyringInlineErrors(t *testing.T) {
	t.Parallel()

	f := loadKeyringFixture(t)

	a, err := os.ReadFile(f.fixture("a.asc"))
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(a)), "\n")

	tests := map[string]string{
		"mixed with a fingerprint": string(a) + "\n" + f.fpA,
		"mixed with a path":        f.fixture("b.asc") + "\n" + string(a),
		"not terminated":           strings.Join(lines[:len(lines)-1], "\n"),
		"garbage in the block":     strings.Replace(string(a), lines[2], "AAAA"+lines[2], 1),
	}

	for name, signedBy := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			kr, err := LoadKeyring(signedBy, []string{f.defaults})
			require.ErrorIs(t, err, deb.ErrNoTrustAnchor)
			assert.Nil(t, kr)
		})
	}

	_, err = LoadKeyring("\n"+string(a)+"\n"+f.fpA, nil)
	require.ErrorIs(t, err, ErrInvalidSignedBy)
}

func TestLoadKeyringInvalidSignedBy(t *testing.T) {
	t.Parallel()

	f := loadKeyringFixture(t)

	for name, v := range map[string]string{
		"relative path":    "keys/a.gpg",
		"dot path":         "./a.gpg",
		"word":             "not-a-key",
		"short":            f.fpA[:39],
		"long":             f.fpA + "0",
		"bang only":        "!",
		"double bang":      f.fpA + "!!",
		"bang in front":    "!" + f.fpA,
		"not hex":          strings.Repeat("G", 40),
		"valid then junk":  f.fpA + " junk",
		"v6 fingerprint":   strings.Repeat("A", 64),
		"path with a NUL":  "/a\x00b",
		"only separators":  " , ,\n",
		"fingerprint+path": f.fpA + " relative/key.gpg",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := LoadKeyring(v, []string{f.defaults})
			require.ErrorIs(t, err, deb.ErrNoTrustAnchor)

			if strings.TrimSpace(v) != "" {
				require.ErrorIs(t, err, ErrInvalidSignedBy)
			}
		})
	}
}

func TestLoadKeyringBounds(t *testing.T) {
	t.Parallel()

	many := strings.Repeat("/k ", MaxSourceListValues+1)
	_, err := LoadKeyring(many, nil)
	require.ErrorIs(t, err, ErrTooLarge)
	require.ErrorIs(t, err, ErrInvalidSignedBy)
	require.ErrorIs(t, err, deb.ErrNoTrustAnchor)

	_, err = LoadKeyring(strings.Repeat("A", MaxSourcesFileBytes+1), nil)
	require.ErrorIs(t, err, ErrTooLarge)
	require.ErrorIs(t, err, ErrInvalidSignedBy)

	// exactly the limit of values is fine for the parser
	spec, err := parseSignedBy(strings.Repeat("/k ", MaxSourceListValues))
	require.NoError(t, err)
	assert.Len(t, spec.paths, MaxSourceListValues)
}

func TestLoadKeyringEmptyUsesDefaults(t *testing.T) {
	t.Parallel()

	f := loadKeyringFixture(t)

	kr, err := LoadKeyring("", []string{f.defaults, filepath.Join(f.defaults, "absent")})
	require.NoError(t, err)
	assert.Equal(t, 3, kr.Len())

	kr, err = LoadKeyring(" \n", []string{f.fixture("a.asc")})
	require.NoError(t, err)
	assert.Equal(t, 1, kr.Len())

	_, err = LoadKeyring("", nil)
	require.ErrorIs(t, err, deb.ErrNoTrustAnchor)

	_, err = LoadKeyring("", []string{filepath.Join(f.defaults, "absent")})
	require.ErrorIs(t, err, deb.ErrNoTrustAnchor)
}

func TestLoadKeyringPathFailures(t *testing.T) {
	t.Parallel()

	f := loadKeyringFixture(t)

	// one good keyring does not excuse a bad one
	_, err := LoadKeyring(f.fixture("a.asc")+" "+filepath.Join(f.defaults, "absent.gpg"), nil)
	require.ErrorIs(t, err, deb.ErrNoTrustAnchor)
	assert.ErrorContains(t, err, "absent.gpg")
}

func TestKeyNotFoundError(t *testing.T) {
	t.Parallel()

	err := &KeyNotFoundError{Fingerprints: []string{"AA", "BB"}}
	require.ErrorIs(t, err, deb.ErrNoTrustAnchor)
	assert.Equal(t, "apt: Signed-By key not found in the keyrings: AA, BB", err.Error())
}

func TestParseFingerprint(t *testing.T) {
	t.Parallel()

	key, ok := parseFingerprint(strings.Repeat("a1", 20) + "!")
	require.True(t, ok)
	assert.True(t, key.exact)
	assert.Equal(t, strings.Repeat("A1", 20), key.fingerprint)

	_, ok = parseFingerprint("")
	assert.False(t, ok)
}
