package apt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseExtendedStates(t *testing.T) {
	t.Parallel()

	marks, err := ParseExtendedStates([]byte("Package: a\nArchitecture: amd64\nAuto-Installed: 1\n\n" +
		"Package: b\nAuto-Installed: 0\n\nPackage: c\nAuto-Installed: x\n\n" +
		"Package: d\nAuto-Installed: 1\n\nAuto-Installed: 1\n"))
	require.NoError(t, err)
	assert.Equal(t, []AutoMark{{Package: "a", Architecture: "amd64"}, {Package: "d"}}, marks)
}

func TestLoadExtendedStatesAndHold(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	status := filepath.Join(dir, "status")
	states := filepath.Join(dir, "extended_states")

	require.NoError(t, os.WriteFile(status, []byte("Package: a\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n\n"+
		"Package: b\nStatus: hold ok installed\nVersion: 1\nArchitecture: all\n\n"), 0o600))
	require.NoError(t, os.WriteFile(states, []byte("Package: a\nArchitecture: amd64\nAuto-Installed: 1\n\n"+
		"Package: b\nArchitecture: all\nAuto-Installed: 1\n"), 0o600))

	c, err := Load(LoadOptions{HostArch: "amd64", StatusFile: status, ExtendedStatesFile: states})
	require.NoError(t, err)

	a := c.installed["a:amd64"]
	require.NotNil(t, a)
	assert.True(t, a.AutoInstalled)
	assert.False(t, a.Held)

	b := c.installed["b"]
	require.NotNil(t, b)
	assert.True(t, b.AutoInstalled)
	assert.True(t, b.Held)

	// A missing file marks nothing and is no error.
	c, err = Load(LoadOptions{HostArch: "amd64", StatusFile: status, ExtendedStatesFile: filepath.Join(dir, "none")})
	require.NoError(t, err)
	assert.False(t, c.installed["a:amd64"].AutoInstalled)
}

func TestLoadExtendedStatesErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// A directory cannot be read as the file.
	_, err := Load(LoadOptions{HostArch: "amd64", ExtendedStatesFile: dir})

	var ese *ExtendedStatesError

	require.ErrorAs(t, err, &ese)
	assert.Equal(t, dir, ese.Path)
	assert.Contains(t, ese.Error(), dir)
	assert.NotNil(t, ese.Unwrap())

	big := strings.Repeat("Package: p\nAuto-Installed: 1\n\n", maxExtendedStates+1)
	_, err = ParseExtendedStates([]byte(big))
	require.True(t, errors.Is(err, ErrTooManyExtendedStates))
}
