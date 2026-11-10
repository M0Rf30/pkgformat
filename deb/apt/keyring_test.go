package apt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
)

func TestLoadKeyringSignedBy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	signer := newSigner(t)
	keyFile := writeKeyring(t, dir, signer)

	kr, err := LoadKeyring(keyFile, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, kr.Len())

	kr, err = LoadKeyring("  "+keyFile+"  ", []string{filepath.Join(dir, "absent")})
	require.NoError(t, err, "the option is trimmed and the defaults are not consulted")
	assert.Equal(t, 1, kr.Len())

	keyDir := filepath.Join(dir, "keys")
	require.NoError(t, os.Mkdir(keyDir, 0o755))
	writeKeyring(t, keyDir, newSigner(t))
	writeKeyring(t, keyDir, newSigner(t))

	kr, err = LoadKeyring(keyDir, nil)
	require.NoError(t, err)
	assert.Equal(t, 2, kr.Len())
}

func TestLoadKeyringSignedByFailures(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	good := writeKeyring(t, dir, newSigner(t))

	empty := filepath.Join(dir, "empty.gpg")
	require.NoError(t, os.WriteFile(empty, nil, 0o644))

	garbage := filepath.Join(dir, "garbage.gpg")
	require.NoError(t, os.WriteFile(garbage, []byte("this is no key"), 0o644))

	emptyDir := filepath.Join(dir, "emptydir")
	require.NoError(t, os.Mkdir(emptyDir, 0o755))

	for name, path := range map[string]string{
		"missing":   filepath.Join(dir, "absent.gpg"),
		"empty":     empty,
		"garbage":   garbage,
		"empty dir": emptyDir,
	} {
		// A usable default must not rescue an unusable Signed-By.
		kr, err := LoadKeyring(path, []string{good})
		require.ErrorIs(t, err, deb.ErrNoTrustAnchor, name)
		assert.ErrorContains(t, err, path, name)
		assert.Nil(t, kr, name)
	}
}

func TestLoadKeyringDefaults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyA := writeKeyring(t, dir, newSigner(t))

	keyDir := filepath.Join(dir, "trusted.gpg.d")
	require.NoError(t, os.Mkdir(keyDir, 0o755))
	writeKeyring(t, keyDir, newSigner(t))

	garbage := filepath.Join(dir, "garbage.gpg")
	require.NoError(t, os.WriteFile(garbage, []byte("junk"), 0o644))

	kr, err := LoadKeyring("", []string{filepath.Join(dir, "absent"), garbage, keyA, keyDir})
	require.NoError(t, err)
	assert.Equal(t, 2, kr.Len(), "the union of every usable default")

	kr, err = LoadKeyring("   ", []string{keyA})
	require.NoError(t, err)
	assert.Equal(t, 1, kr.Len(), "a blank Signed-By means none")

	for name, defaults := range map[string][]string{
		"none":    nil,
		"absent":  {filepath.Join(dir, "absent")},
		"garbage": {garbage},
	} {
		kr, err = LoadKeyring("", defaults)
		require.ErrorIs(t, err, deb.ErrNoTrustAnchor, name)
		assert.Nil(t, kr, name)
	}
}

func TestLoadKeyringPathDirectoryError(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}

	dir := filepath.Join(t.TempDir(), "locked")
	require.NoError(t, os.Mkdir(dir, 0o755))
	writeKeyring(t, dir, newSigner(t))
	require.NoError(t, os.Chmod(dir, 0o000))

	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	_, err := loadKeyringPath(dir)
	require.Error(t, err)
}

func TestIsVerificationError(t *testing.T) {
	t.Parallel()

	unknown := fmt.Errorf("source a: %w", deb.ErrUnknownSigner)
	noAnchor := fmt.Errorf("source b: %w", deb.ErrNoTrustAnchor)
	network := errors.New("connection refused")

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unknown signer", deb.ErrUnknownSigner, true},
		{"gpg unknown signer", gpg.ErrUnknownSigner, true},
		{"no trust anchor", deb.ErrNoTrustAnchor, true},
		{"wrapped unknown signer", unknown, true},
		{"wrapped no anchor", noAnchor, true},
		{"bad signature", gpg.ErrBadSignature, false},
		{"network", network, false},
		{"sentinel annotated with its cause", fmt.Errorf("%w: %w", deb.ErrUnknownSigner, errors.New("unknown issuer")), true},
		{"update, only verification failures", &UpdateError{Errors: []error{unknown, noAnchor}}, true},
		{"update, mixed with network", &UpdateError{Errors: []error{unknown, network}}, false},
		{"update, only network", &UpdateError{Errors: []error{network, io.EOF}}, false},
		{"update, no failures", &UpdateError{}, false},
		{"update, annotated sentinel with network", &UpdateError{Errors: []error{
			fmt.Errorf("%w: %w", deb.ErrUnknownSigner, io.EOF), network,
		}}, false},
		{"wrapped update", fmt.Errorf("update: %w", &UpdateError{Errors: []error{unknown, noAnchor}}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, IsVerificationError(tt.err))
		})
	}
}

func TestUpdateErrorFlattens(t *testing.T) {
	t.Parallel()

	a, b, c := errors.New("a"), errors.New("b"), errors.New("c")

	require.NoError(t, newUpdateError(nil))
	require.NoError(t, newUpdateError([]error{nil}))

	err := newUpdateError([]error{a, nil, newUpdateError([]error{b, c})})

	var ue *UpdateError

	require.ErrorAs(t, err, &ue)
	assert.Equal(t, []error{a, b, c}, ue.Errors)
	assert.Equal(t, "a\nb\nc", err.Error())
	require.ErrorIs(t, err, b)
}
