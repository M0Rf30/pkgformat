package deb_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

func parseControl(t *testing.T, in string) *deb.ControlFile {
	t.Helper()

	cf, err := deb.ParseControlFile(strings.NewReader(in))
	require.NoError(t, err)

	return cf
}

func TestParseControlFile(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		checks func(*testing.T, *deb.ControlFile)
	}{
		{
			name:  "simple",
			input: "Package: test-package\nVersion: 1.0.0\nArchitecture: amd64\nMaintainer: Test User <test@example.com>\nDescription: A test package\n\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Equal(t, "test-package", cf.Get("Package"))
				assert.Equal(t, "1.0.0", cf.Get("Version"))
				assert.Equal(t, "amd64", cf.Get("Architecture"))
				assert.Equal(t, []string{"Package", "Version", "Architecture", "Maintainer", "Description"}, cf.Order)
			},
		},
		{
			name:  "continuation lines",
			input: "Package: p\nDescription: A test package\n with multiple lines\n of description\n\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Equal(t, "A test package\nwith multiple lines\nof description", cf.Get("Description"))
			},
		},
		{
			name:  "dependencies",
			input: "Package: p\nDepends: libc6 (>= 2.17), libssl1.1 (>= 1.1.0)\nRecommends: curl\n\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Equal(t, "libc6 (>= 2.17), libssl1.1 (>= 1.1.0)", cf.Get("Depends"))
				assert.Equal(t, "curl", cf.Get("Recommends"))
			},
		},
		{
			name:  "dot marker is an empty line",
			input: "Package: p\nDescription: short\n long\n .\n more\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Equal(t, "short\nlong\n\nmore", cf.Get("Description"))
			},
		},
		{
			name:  "tab continuation",
			input: "Package: p\nDescription:\ttab\n\tcont\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Equal(t, "tab\ncont", cf.Get("Description"))
			},
		},
		{
			name:  "crlf",
			input: "Package: x\r\nVersion: 1\r\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Equal(t, "x", cf.Get("Package"))
				assert.Equal(t, "1", cf.Get("Version"))
			},
		},
		{
			name:  "comments are dropped",
			input: "# leading\nPackage: p\n# inside\nVersion: 1\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Equal(t, []string{"Package", "Version"}, cf.Order)
			},
		},
		{
			name:  "only the first paragraph",
			input: "Package: first\n\nPackage: second\nVersion: 2\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Equal(t, "first", cf.Get("Package"))
				assert.Empty(t, cf.Get("Version"))
			},
		},
		{
			name:  "leading blank lines",
			input: "\n\n\nPackage: p\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Equal(t, "p", cf.Get("Package"))
			},
		},
		{
			name:  "duplicate field keeps first position and last value",
			input: "A: 1\nB: 2\nA: 3\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Equal(t, []string{"A", "B"}, cf.Order)
				assert.Equal(t, "3", cf.Get("A"))
			},
		},
		{
			name:  "empty value",
			input: "Package: p\nEmpty:\nOther: x\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				v, ok := cf.Lookup("Empty")
				assert.True(t, ok)
				assert.Empty(t, v)
			},
		},
		{
			name:  "value with colons",
			input: "Homepage: https://example.org:8080/x\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Equal(t, "https://example.org:8080/x", cf.Get("Homepage"))
			},
		},
		{
			name:  "empty input",
			input: "",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Empty(t, cf.Order)
				assert.NotNil(t, cf.Fields)
			},
		},
		{
			name:  "comments only",
			input: "# nothing\n# here\n",
			checks: func(t *testing.T, cf *deb.ControlFile) {
				assert.Empty(t, cf.Order)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.checks(t, parseControl(t, tt.input))
		})
	}
}

func TestParseControlFileStrict(t *testing.T) {
	for name, in := range map[string]string{
		"line without colon":             "Package: a\nnot a field\n",
		"empty field name":               ": no name\n",
		"continuation without a field":   " leading continuation\nPackage: a\n",
		"tab continuation w/o field":     "\tcont\n",
		"garbage in the first paragraph": "Package: a\n\x00\x01\nVersion: 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := deb.ParseControlFile(strings.NewReader(in))
			require.ErrorIs(t, err, deb.ErrInvalidControlFormat)
		})
	}

	// A malformed second paragraph is never looked at.
	cf := parseControl(t, "Package: a\n\nnot a field\n")
	assert.Equal(t, "a", cf.Get("Package"))
}

func TestScanControlLenient(t *testing.T) {
	doc := "# a comment\r\n" +
		"Package: one\r\nVersion: 1\r\nDescription: short\r\n long\r\n .\r\n more\r\n" +
		"\r\n\r\n\r\n" +
		"orphan line without colon\n" +
		": nameless\n" +
		" orphan continuation\n" +
		"\n" +
		"Package: two\n" +
		"junk\n" +
		"Version: 2\n" +
		"\n" +
		"Package: three"

	var got []*deb.ControlFile

	err := deb.ScanControl(strings.NewReader(doc), func(cf *deb.ControlFile) error {
		got = append(got, cf)

		return nil
	})
	require.NoError(t, err)
	require.Len(t, got, 3, "the paragraph made only of malformed lines is not reported")

	assert.Equal(t, "one", got[0].Get("Package"))
	assert.Equal(t, "short\nlong\n\nmore", got[0].Get("Description"))
	assert.Equal(t, "two", got[1].Get("Package"))
	assert.Equal(t, "2", got[1].Get("Version"))
	assert.Equal(t, []string{"Package", "Version"}, got[1].Order)
	assert.Equal(t, "three", got[2].Get("Package"))
}

func TestScanControlCallbackError(t *testing.T) {
	stop := errors.New("stop")
	calls := 0

	err := deb.ScanControl(strings.NewReader("A: 1\n\nB: 2\n\nC: 3\n"), func(*deb.ControlFile) error {
		calls++

		return stop
	})
	require.ErrorIs(t, err, stop)
	assert.Equal(t, 1, calls)
}

func TestScanControlEmpty(t *testing.T) {
	calls := 0
	err := deb.ScanControl(strings.NewReader("\n\n# c\n"), func(*deb.ControlFile) error { calls++; return nil })
	require.NoError(t, err)
	assert.Zero(t, calls)
}

type failingReader struct{}

var errBroken = errors.New("broken pipe")

func (failingReader) Read([]byte) (int, error) { return 0, errBroken }

func TestControlReadError(t *testing.T) {
	_, err := deb.ParseControlFile(failingReader{})
	require.ErrorIs(t, err, errBroken)
	require.NotErrorIs(t, err, deb.ErrTooLarge)

	require.ErrorIs(t, deb.ScanControl(failingReader{}, func(*deb.ControlFile) error { return nil }), errBroken)
}

func TestControlSizeLimits(t *testing.T) {
	t.Run("line over MaxLineBytes", func(t *testing.T) {
		in := "Package: a\nDescription: " + strings.Repeat("x", deb.MaxLineBytes+16) + "\n"

		_, err := deb.ParseControlFile(strings.NewReader(in))
		require.ErrorIs(t, err, deb.ErrTooLarge)

		err = deb.ScanControl(strings.NewReader(in), func(*deb.ControlFile) error { return nil })
		require.ErrorIs(t, err, deb.ErrTooLarge)
	})

	t.Run("line just under MaxLineBytes", func(t *testing.T) {
		in := "Description: " + strings.Repeat("x", deb.MaxLineBytes-64) + "\n"
		cf := parseControl(t, in)
		assert.Len(t, cf.Get("Description"), deb.MaxLineBytes-64)
	})

	t.Run("paragraph over MaxParagraphBytes", func(t *testing.T) {
		line := " " + strings.Repeat("y", 1<<20) + "\n"

		var sb strings.Builder

		sb.WriteString("Package: a\nDescription: d\n")

		for sb.Len() <= deb.MaxParagraphBytes {
			sb.WriteString(line)
		}

		_, err := deb.ParseControlFile(strings.NewReader(sb.String()))
		require.ErrorIs(t, err, deb.ErrTooLarge)

		err = deb.ScanControl(strings.NewReader(sb.String()), func(*deb.ControlFile) error { return nil })
		require.ErrorIs(t, err, deb.ErrTooLarge)
	})

	t.Run("many paragraphs are fine", func(t *testing.T) {
		para := "Package: p\nDescription: " + strings.Repeat("z", 1<<20) + "\n\n"
		n := 0

		err := deb.ScanControl(strings.NewReader(strings.Repeat(para, 20)), func(*deb.ControlFile) error { n++; return nil })
		require.NoError(t, err)
		assert.Equal(t, 20, n)
	})
}

func TestControlFileGetRequired(t *testing.T) {
	cf := &deb.ControlFile{Fields: map[string]string{"Package": "test", "Empty": ""}, Order: []string{"Package", "Empty"}}

	v, err := cf.GetRequired("Package")
	require.NoError(t, err)
	assert.Equal(t, "test", v)

	v, err = cf.GetRequired("package")
	require.NoError(t, err)
	assert.Equal(t, "test", v)

	for _, field := range []string{"Missing", "Empty"} {
		_, err = cf.GetRequired(field)
		require.ErrorIs(t, err, deb.ErrMissingRequiredField)
	}
}

func TestControlFileCaseInsensitive(t *testing.T) {
	cf := parseControl(t, "Package: a\nMulti-Arch: same\n")

	assert.Equal(t, "same", cf.Get("multi-arch"))
	assert.Equal(t, "same", cf.Get("MULTI-ARCH"))
	assert.Equal(t, "a", cf.Get("Package"), "exact spelling first")

	v, ok := cf.Lookup("PACKAGE")
	assert.True(t, ok)
	assert.Equal(t, "a", v)

	_, ok = cf.Lookup("nope")
	assert.False(t, ok)
	assert.Empty(t, cf.Get("nope"))

	// Set replaces a case variant in place and keeps the document spelling.
	cf.Set("package", "b")
	assert.Equal(t, "b", cf.Get("Package"))
	assert.Equal(t, []string{"Package", "Multi-Arch"}, cf.Order)
	assert.NotContains(t, cf.Fields, "package")

	// Set appends an unknown field.
	cf.Set("Section", "utils")
	assert.Equal(t, []string{"Package", "Multi-Arch", "Section"}, cf.Order)
	assert.Equal(t, "utils", cf.Get("section"))
}

func TestControlFileSetOnZeroValue(t *testing.T) {
	var cf deb.ControlFile

	cf.Set("A", "1")
	assert.Equal(t, "1", cf.Get("A"))
	assert.Equal(t, "A: 1\n", cf.String())

	assert.Empty(t, deb.NewControlFile().String())
}

func TestControlFileString(t *testing.T) {
	cf := deb.NewControlFile()
	cf.Set("Package", "a")
	cf.Set("Empty", "")
	cf.Set("Description", "short\nlong line\n\nlast")

	assert.Equal(t, "Package: a\nEmpty:\nDescription: short\n long line\n .\n last\n", cf.String())
}

func TestControlFileStringRoundTrip(t *testing.T) {
	values := map[string]string{
		"Simple":        "value",
		"Empty":         "",
		"Multi":         "first\nsecond\nthird",
		"Blank":         "first\n\nthird",
		"TwoBlank":      "first\n\n\nfourth",
		"Indented":      "first\n  indented\n\ttabbed",
		"Colons":        "a: b: c",
		"Dependencies":  "libc6 (>= 2.31), foo | bar",
		"TrailingSpace": "a\nb \nc",
	}

	cf := deb.NewControlFile()
	for _, k := range []string{"Simple", "Empty", "Multi", "Blank", "TwoBlank", "Indented", "Colons", "Dependencies", "TrailingSpace"} {
		cf.Set(k, values[k])
	}

	back := parseControl(t, cf.String())
	assert.Equal(t, cf.Order, back.Order)
	assert.Equal(t, cf.Fields, back.Fields)
	assert.Equal(t, cf.String(), back.String())
}

func TestParsePackage(t *testing.T) {
	cf := parseControl(t, `Package: test-package
Version: 1:1.0.0-2
Architecture: amd64
Maintainer: Test User <test@example.com>
Description: A test package
 with more
Section: utils
Priority: optional
Homepage: https://example.com
Bugs: https://example.com/bugs
Depends: libc6
Pre-Depends: dpkg
Recommends: a
Suggests: b
Enhances: c
Conflicts: d
Breaks: e
Replaces: f
Provides: g
Source: src
Source-Version: 9
Multi-Arch: same
Built-Using: golang
Filename: pool/main/t/test-package/t.deb
Size: 1234
Installed-Size: 56
MD5sum: m
SHA1: s1
SHA256: s256
SHA512: s512
Essential: yes
X-Custom-Field: custom
x-lower: lower
`)

	pkg, err := cf.ParsePackage()
	require.NoError(t, err)

	assert.Equal(t, "test-package", pkg.Package)
	assert.Equal(t, "1:1.0.0-2", pkg.Version)
	assert.Equal(t, "amd64", pkg.Architecture)
	assert.Equal(t, "Test User <test@example.com>", pkg.Maintainer)
	assert.Equal(t, "A test package\nwith more", pkg.Description)
	assert.Equal(t, "utils", pkg.Section)
	assert.Equal(t, "optional", pkg.Priority)
	assert.Equal(t, "https://example.com", pkg.Homepage)
	assert.Equal(t, "https://example.com/bugs", pkg.Bugs)
	assert.Equal(t, "libc6", pkg.Depends)
	assert.Equal(t, "dpkg", pkg.PreDepends)
	assert.Equal(t, "a", pkg.Recommends)
	assert.Equal(t, "b", pkg.Suggests)
	assert.Equal(t, "c", pkg.Enhances)
	assert.Equal(t, "d", pkg.Conflicts)
	assert.Equal(t, "e", pkg.Breaks)
	assert.Equal(t, "f", pkg.Replaces)
	assert.Equal(t, "g", pkg.Provides)
	assert.Equal(t, "src", pkg.Source)
	assert.Equal(t, "9", pkg.SourceVersion)
	assert.Equal(t, "same", pkg.MultiArch)
	assert.Equal(t, "golang", pkg.BuiltUsing)
	assert.Equal(t, "pool/main/t/test-package/t.deb", pkg.Filename)
	assert.Equal(t, int64(1234), pkg.Size)
	assert.Equal(t, int64(56), pkg.InstalledSize)
	assert.Equal(t, "m", pkg.MD5sum)
	assert.Equal(t, "s1", pkg.SHA1)
	assert.Equal(t, "s256", pkg.SHA256)
	assert.Equal(t, "s512", pkg.SHA512)
	assert.True(t, pkg.Essential)
	assert.Equal(t, map[string]string{"X-Custom-Field": "custom", "x-lower": "lower"}, pkg.Custom)
}

func TestParsePackageRequired(t *testing.T) {
	for name, in := range map[string]string{
		"missing package":      "Version: 1.0.0\nArchitecture: amd64\n",
		"missing version":      "Package: test\nArchitecture: amd64\n",
		"missing architecture": "Package: test\nVersion: 1.0.0\n",
		"empty package":        "Package:\nVersion: 1.0.0\nArchitecture: amd64\n",
		"empty version":        "Package: t\nVersion:\nArchitecture: amd64\n",
		"empty architecture":   "Package: t\nVersion: 1\nArchitecture:\n",
		"nothing":              "",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseControl(t, in).ParsePackage()
			require.ErrorIs(t, err, deb.ErrMissingRequiredField)
		})
	}
}

func TestParsePackageCaseInsensitiveNames(t *testing.T) {
	pkg, err := parseControl(t, "package: a\nversion: 1\narchitecture: all\ndepends: b\nESSENTIAL: Yes\ninstalled-size: 7\n").ParsePackage()
	require.NoError(t, err)

	assert.Equal(t, "a", pkg.Package)
	assert.Equal(t, "b", pkg.Depends)
	assert.True(t, pkg.Essential)
	assert.Equal(t, int64(7), pkg.InstalledSize)
	assert.Empty(t, pkg.Custom)
}

func TestParsePackageSizes(t *testing.T) {
	for name, tc := range map[string]struct {
		size, installed string
		wantSize, wantI int64
	}{
		"numbers":     {"10", "20", 10, 20},
		"garbage":     {"ten", "20 KiB", 0, 0},
		"negative":    {"-3", "-4", -3, -4},
		"overflow":    {"99999999999999999999", "1", 0, 1},
		"leading ws":  {"  5", "6  ", 5, 6},
		"empty value": {"", "", 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			cf := deb.NewControlFile()
			cf.Set("Package", "a")
			cf.Set("Version", "1")
			cf.Set("Architecture", "all")
			cf.Set("Size", strings.TrimSpace(tc.size))
			cf.Set("Installed-Size", strings.TrimSpace(tc.installed))

			pkg, err := cf.ParsePackage()
			require.NoError(t, err)
			assert.Equal(t, tc.wantSize, pkg.Size)
			assert.Equal(t, tc.wantI, pkg.InstalledSize)
		})
	}
}

func TestParsePackageEssentialFalse(t *testing.T) {
	pkg, err := parseControl(t, "Package: a\nVersion: 1\nArchitecture: all\nEssential: no\n").ParsePackage()
	require.NoError(t, err)
	assert.False(t, pkg.Essential)
}

// checkControlInvariants asserts the structural guarantees of a parsed paragraph.
func checkControlInvariants(t *testing.T, cf *deb.ControlFile) {
	t.Helper()

	assert.Len(t, cf.Order, len(cf.Fields))

	seen := map[string]bool{}

	for _, name := range cf.Order {
		assert.NotEmpty(t, name)
		assert.False(t, seen[name], "duplicate %q in Order", name)
		seen[name] = true

		_, ok := cf.Fields[name]
		assert.True(t, ok, "%q in Order but not in Fields", name)
	}
}

// FuzzParseControlFile feeds arbitrary text to the strict control-file parser.
func FuzzParseControlFile(f *testing.F) {
	f.Add("Package: test\nVersion: 1.0\nArchitecture: amd64\nDepends: libc6 (>= 2.3), foo | bar\nDescription: x\n y\n .\n z\n\n")
	f.Add("Package: a\n continuation without field\n")
	f.Add(": no name\n\n\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, in string) {
		cf, err := deb.ParseControlFile(strings.NewReader(in))
		if err != nil {
			return
		}

		checkControlInvariants(t, cf)

		// Rendering never panics and what it renders parses leniently.
		rendered := cf.String()
		n := 0

		require.NoError(t, deb.ScanControl(strings.NewReader(rendered), func(*deb.ControlFile) error { n++; return nil }))
		assert.LessOrEqual(t, n, 1)

		_, _ = cf.ParsePackage()
	})
}

// FuzzScanControl feeds arbitrary text to the lenient multi-paragraph scanner.
func FuzzScanControl(f *testing.F) {
	f.Add("Package: a\nVersion: 1\n\nPackage: b\nVersion: 2\n")
	f.Add("# c\n\n\nx\n y\n: z\n\n \n")
	f.Add("A: 1\r\n\r\nB: 2\r\n .\r\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, in string) {
		_ = deb.ScanControl(strings.NewReader(in), func(cf *deb.ControlFile) error {
			checkControlInvariants(t, cf)
			assert.NotEmpty(t, cf.Order)

			return nil
		})
	})
}
