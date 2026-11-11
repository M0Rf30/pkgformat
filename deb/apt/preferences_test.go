package apt

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePreferencesForms(t *testing.T) {
	t.Parallel()

	prefs, err := ParsePreferences(`# comment
Explanation: backports are opt-in
Package: *
Pin: release a=bookworm-backports
Pin-Priority: 100

Package: libfoo1 src:bar /^lib.*-dev$/ multi:i386
Pin: version 1.2*
Pin-Priority: 1001

package: hello
PIN: Origin "deb.example.org"
pin-priority: -1

Package: *
Pin: origin ""
Pin-Priority: never
`)
	require.NoError(t, err)
	require.Len(t, prefs.Pins, 4)

	assert.Equal(t, Pin{Type: PinRelease, Data: "a=bookworm-backports", Priority: 100, Explanation: "backports are opt-in"}, prefs.Pins[0])
	assert.Equal(t, Pin{
		Packages: []string{"libfoo1", "src:bar", "/^lib.*-dev$/", "multi:i386"},
		Type:     PinVersion, Data: "1.2*", Priority: 1001,
	}, prefs.Pins[1])
	assert.Equal(t, Pin{Packages: []string{"hello"}, Type: PinOrigin, Data: `"deb.example.org"`, Priority: -1}, prefs.Pins[2])
	assert.Equal(t, Pin{Type: PinOrigin, Data: `""`, Priority: PriorityNever}, prefs.Pins[3])
	assert.Empty(t, prefs.Warnings)
}

func TestParsePreferencesSourceVersionAndStarWarning(t *testing.T) {
	t.Parallel()

	prefs, err := ParsePreferences("Package: hello\nPin: source-version 2.*\nPin-Priority: 600\n\nPackage: *\nPin: version 1.0\nPin-Priority: 600\n\nPackage: *\nPin: bogus x\nPin-Priority: 600\n")
	require.NoError(t, err)
	require.Len(t, prefs.Pins, 1)
	assert.Equal(t, PinSourceVersion, prefs.Pins[0].Type)
	assert.Equal(t, []string{"Did not understand pin type version", "Did not understand pin type bogus"}, prefs.Warnings)
}

func TestParsePreferencesLenientLayout(t *testing.T) {
	t.Parallel()

	for name, content := range map[string]string{
		"crlf":             "Package: hello\r\nPin: release a=x\r\nPin-Priority: 600\r\n",
		"no final newline": "Package: hello\nPin: release a=x\nPin-Priority: 600",
		"tabs":             "Package:\thello\nPin:\trelease a=x\nPin-Priority:\t600\n",
		"no space":         "Package:hello\nPin:release a=x\nPin-Priority:600\n",
		"comment inside":   "Package: hello\n# c\nPin: release a=x\nPin-Priority: 600\n",
		"padding":          "Package:   hello  \nPin:   release   a=x  \nPin-Priority:   600  \n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			prefs, err := ParsePreferences(content)
			require.NoError(t, err)
			require.Len(t, prefs.Pins, 1)
			assert.Equal(t, []string{"hello"}, prefs.Pins[0].Packages)
			assert.Equal(t, "a=x", strings.TrimSpace(prefs.Pins[0].Data))
			assert.Equal(t, 600, prefs.Pins[0].Priority)
		})
	}
}

func TestParsePreferencesIgnoredRecords(t *testing.T) {
	t.Parallel()

	for _, content := range []string{
		"",
		"\n\n\n",
		"# only a comment\n",
		"Package: hello\nPin-Priority: 600\n", // no Pin field
	} {
		prefs, err := ParsePreferences(content)
		require.NoError(t, err, content)
		assert.Empty(t, prefs.Pins, content)
	}
}

func TestParsePreferencesDuplicateAndContinuation(t *testing.T) {
	t.Parallel()

	prefs, err := ParsePreferences("Package: hello\nPin: release a=stable\nPin: release a=testing\nPin-Priority: 1\nPin-Priority: 2\n")
	require.NoError(t, err)
	require.Len(t, prefs.Pins, 1)
	assert.Equal(t, "a=testing", prefs.Pins[0].Data)
	assert.Equal(t, 2, prefs.Pins[0].Priority)

	prefs, err = ParsePreferences("Package: hello\nPin: release a=testing,\n o=Debian\nPin-Priority: 3\n")
	require.NoError(t, err)
	require.Len(t, prefs.Pins, 1)
	assert.Contains(t, prefs.Pins[0].Data, "o=Debian")
}

func TestParsePreferencesPriorityValues(t *testing.T) {
	t.Parallel()

	for text, want := range map[string]int{
		"600":      600,
		"+600":     600,
		"600abc":   600,
		"3 00":     3,
		"00700":    700,
		"-32768":   -32767,
		"-32767":   -32767,
		"32767":    32767,
		"-1":       -1,
		"never":    PriorityNever,
		"1000":     1000,
		" \t 55  ": 55,
	} {
		prefs, err := ParsePreferences("Package: *\nPin: release a=x\nPin-Priority: " + text + "\n")
		require.NoError(t, err, text)
		require.Len(t, prefs.Pins, 1, text)
		assert.Equal(t, want, prefs.Pins[0].Priority, text)
	}
}

func TestParsePreferencesErrors(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("1", 400)

	for name, tc := range map[string]struct {
		content string
		reason  error
	}{
		"no package":       {"Pin: release a=x\nPin-Priority: 1\n", ErrNoPackageHeader},
		"letters":          {"Package: a\nPin: release a=x\nPin-Priority: abc\n", ErrPinPriority},
		"zero":             {"Package: a\nPin: release a=x\nPin-Priority: 0\n", ErrPinPriority},
		"hex":              {"Package: a\nPin: release a=x\nPin-Priority: 0x1F6\n", ErrPinPriority},
		"missing":          {"Package: a\nPin: release a=x\n", ErrPinPriority},
		"too high":         {"Package: a\nPin: release a=x\nPin-Priority: 32768\n", ErrPinPriority},
		"too low":          {"Package: a\nPin: release a=x\nPin-Priority: -32769\n", ErrPinPriority},
		"overflow":         {"Package: a\nPin: release a=x\nPin-Priority: 99999999999999999999\n", ErrPinPriority},
		"too long":         {"Package: a\nPin: release a=x\nPin-Priority: " + long + "\n", ErrPinPriority},
		"never on a name":  {"Package: a\nPin: release a=x\nPin-Priority: never\n", ErrNeverPin},
		"error after good": {"Package: a\nPin: release a=x\nPin-Priority: 5\n\nPin: release a=x\nPin-Priority: 1\n", ErrNoPackageHeader},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			prefs, err := ParsePreferences(tc.content)
			require.Error(t, err)
			require.NotNil(t, prefs)
			require.ErrorIs(t, err, tc.reason)
			require.ErrorIs(t, err, ErrPreferences)

			var perr *PreferencesError

			require.ErrorAs(t, err, &perr)
			assert.Equal(t, tc.reason, perr.Reason)
			assert.NotEmpty(t, perr.Error())
		})
	}
}

func TestParsePreferencesKeepsPinsBeforeError(t *testing.T) {
	t.Parallel()

	prefs, err := ParsePreferences("Package: a\nPin: release a=x\nPin-Priority: 5\n\nPackage: b\nPin: release a=x\nPin-Priority: zz\n\nPackage: c\nPin: release a=x\nPin-Priority: 7\n")
	require.ErrorIs(t, err, ErrPinPriority)
	require.Len(t, prefs.Pins, 1)
	assert.Equal(t, []string{"a"}, prefs.Pins[0].Packages)

	var perr *PreferencesError

	require.ErrorAs(t, err, &perr)
	assert.Equal(t, 2, perr.Record)
	assert.Equal(t, "b", perr.Package)
	assert.Equal(t, "zz", perr.Value)
}

func TestParsePreferencesBounds(t *testing.T) {
	t.Parallel()

	_, err := ParsePreferences(strings.Repeat("#", maxPreferencesSize+1))
	require.ErrorIs(t, err, ErrTooLarge)

	var b strings.Builder

	for range maxPreferencesPins + 1 {
		b.WriteString("Package: *\nPin: release a=x\nPin-Priority: 1\n\n")
	}

	prefs, err := ParsePreferences(b.String())
	require.ErrorIs(t, err, ErrTooLarge)
	assert.Len(t, prefs.Pins, maxPreferencesPins)
}

func TestPinTypeString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "release", PinRelease.String())
	assert.Equal(t, "version", PinVersion.String())
	assert.Equal(t, "source-version", PinSourceVersion.String())
	assert.Equal(t, "origin", PinOrigin.String())
	assert.Equal(t, "PinType(42)", PinType(42).String())
}

func TestPreferencesError(t *testing.T) {
	t.Parallel()

	err := &PreferencesError{File: "/etc/apt/preferences", Record: 3, Package: "hello", Value: "abc", Reason: ErrPinPriority}
	assert.Contains(t, err.Error(), "/etc/apt/preferences")
	assert.Contains(t, err.Error(), "abc")
	assert.True(t, errors.Is(err, ErrPinPriority))
	assert.True(t, errors.Is(err, ErrPreferences))
	assert.False(t, errors.Is(err, ErrNeverPin))

	assert.NotEmpty(t, (&PreferencesError{Reason: ErrNoPackageHeader}).Error())
}

func TestPreferencesAdd(t *testing.T) {
	t.Parallel()

	a := &Preferences{Pins: []Pin{{Priority: 1}}, Warnings: []string{"w1"}}
	a.Add(&Preferences{Pins: []Pin{{Priority: 2}}, Warnings: []string{"w2"}})
	a.Add(nil)
	assert.Equal(t, []Pin{{Priority: 1}, {Priority: 2}}, a.Pins)
	assert.Equal(t, []string{"w1", "w2"}, a.Warnings)
}

func TestValidPreferenceName(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]bool{
		"10-backports":       true,
		"x.pref":             true,
		"noext":              true,
		"UPPER.pref":         true,
		"a.b.pref":           true,
		"a_b-c:d":            true,
		"note.txt":           false,
		".hidden":            false,
		".pref":              false,
		"bad+name":           false,
		"trailing.":          false,
		"x.pref.dpkg-old":    false,
		"x.PREF":             false,
		"space name":         false,
		"":                   false,
		"uni\u00e9":          false,
		"backup~":            false,
		"x.pref.disabled":    false,
		"a.":                 false,
		"ok.pref.":           false,
		"dotted.name.nopref": false,
	} {
		assert.Equal(t, want, validPreferenceName(name), name)
	}
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()

	for name, content := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
}

func pinStanza(pkg string, prio string) string {
	return "Package: " + pkg + "\nPin: release a=x\nPin-Priority: " + prio + "\n"
}

func TestLoadPreferencesOrderAndFilter(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"preferences":              pinStanza("main", "1"),
		"preferences.d/20-b":       pinStanza("b", "3"),
		"preferences.d/10-a.pref":  pinStanza("a", "2"),
		"preferences.d/note.txt":   pinStanza("ignored-txt", "9"),
		"preferences.d/.hidden":    pinStanza("ignored-hidden", "9"),
		"preferences.d/bad+name":   pinStanza("ignored-char", "9"),
		"preferences.d/x.dpkg-old": pinStanza("ignored-ext", "9"),
		"preferences.d/sub/inner":  pinStanza("ignored-subdir", "9"),
	})

	prefs, err := LoadPreferences(filepath.Join(dir, "preferences"), filepath.Join(dir, "preferences.d"))
	require.NoError(t, err)

	var names []string
	for _, p := range prefs.Pins {
		names = append(names, p.Packages[0])
	}

	assert.Equal(t, []string{"main", "a", "b"}, names)
	assert.Empty(t, prefs.Warnings)
}

func TestLoadPreferencesMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	prefs, err := LoadPreferences(filepath.Join(dir, "absent"), filepath.Join(dir, "absent.d"))
	require.NoError(t, err)
	assert.Empty(t, prefs.Pins)
	assert.Equal(t, []string{"Unable to read " + filepath.Join(dir, "absent.d")}, prefs.Warnings)

	prefs, err = LoadPreferences("", "")
	require.NoError(t, err)
	assert.Empty(t, prefs.Pins)
	assert.Empty(t, prefs.Warnings)
}

func TestLoadPreferencesKeepsReadingAfterAnError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"preferences":     pinStanza("main", "1"),
		"preferences.d/a": pinStanza("a", "abc"),
		"preferences.d/b": pinStanza("b", "2"),
	})

	prefs, err := LoadPreferences(filepath.Join(dir, "preferences"), filepath.Join(dir, "preferences.d"))
	require.ErrorIs(t, err, ErrPinPriority)

	var perr *PreferencesError

	require.ErrorAs(t, err, &perr)
	assert.Equal(t, filepath.Join(dir, "preferences.d", "a"), perr.File)

	var names []string
	for _, p := range prefs.Pins {
		names = append(names, p.Packages[0])
	}

	assert.Equal(t, []string{"main", "b"}, names)
}

func TestLoadPreferencesNonRegularFileIgnored(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "preferences"), 0o750))

	prefs, err := LoadPreferences(filepath.Join(dir, "preferences"), "")
	require.NoError(t, err)
	assert.Empty(t, prefs.Pins)
}

func TestLoadPreferencesSymlinkFollowed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"real": pinStanza("viaLink", "4")})
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "p.d"), 0o750))
	require.NoError(t, os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "p.d", "link")))

	prefs, err := LoadPreferences("", filepath.Join(dir, "p.d"))
	require.NoError(t, err)
	require.Len(t, prefs.Pins, 1)
	assert.Equal(t, []string{"viaLink"}, prefs.Pins[0].Packages)
}

func TestLoadPreferencesBounds(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	require.NoError(t, os.WriteFile(big, []byte(strings.Repeat("#", maxPreferencesSize+1)), 0o600))

	_, err := LoadPreferences(big, "")
	require.ErrorIs(t, err, ErrTooLarge)

	many := filepath.Join(dir, "many.d")
	require.NoError(t, os.Mkdir(many, 0o750))

	for i := range maxPreferencesFiles + 1 {
		require.NoError(t, os.WriteFile(filepath.Join(many, "f"+strconv.Itoa(i)), nil, 0o600))
	}

	_, err = LoadPreferences("", many)
	require.ErrorIs(t, err, ErrTooLarge)
}

func TestPinPriorityValue(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 0, pinPriorityValue(""))
	assert.Equal(t, 0, pinPriorityValue("-"))
	assert.Equal(t, 0, pinPriorityValue("+x"))
	assert.Equal(t, -12, pinPriorityValue("  -12x"))
	assert.Equal(t, 1<<31-1, pinPriorityValue(strings.Repeat("9", 50)))
	assert.Equal(t, 0, pinPriorityValue(strings.Repeat("9", maxPinPriorityText+1)))
}

func TestScanTagFileStopsWithoutColon(t *testing.T) {
	t.Parallel()

	// A field line with no colon anywhere after it ends the file silently.
	prefs, err := ParsePreferences("Package: a\nPin: release a=x\nPin-Priority: 5\n\nnonsense line\n")
	require.NoError(t, err)
	assert.Len(t, prefs.Pins, 1)
}
