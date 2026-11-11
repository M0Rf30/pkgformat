package apt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sourceErrors unpacks a joined parse error.
func sourceErrors(tb testing.TB, err error) []*SourceError {
	tb.Helper()

	var out []*SourceError

	var walk func(error)

	walk = func(e error) {
		if e == nil {
			return
		}

		if j, ok := e.(interface{ Unwrap() []error }); ok {
			for _, c := range j.Unwrap() {
				walk(c)
			}

			return
		}

		var se *SourceError
		if errors.As(e, &se) {
			out = append(out, se)

			return
		}

		tb.Fatalf("not a *SourceError: %v", e)
	}

	walk(err)

	return out
}

func TestParseSourcesList(t *testing.T) {
	t.Parallel()

	content := strings.Join([]string{
		"# the main archive",
		"",
		"deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/k.gpg] https://a.example/ubuntu jammy main universe",
		"deb-src http://a.example/ubuntu jammy main",
		"deb file:///srv/repo jammy main",
		"deb cdrom:[Debian 12] bookworm main",
		"deb ftp://a.example/debian bookworm main",
		"deb [trusted=yes] http://d.example/ stable main contrib",
		"   deb   http://e.example/debian/    stable   main   # trailing comment",
		"deb [ arch=i386 ] http://f.example/ stable main",
		"deb http://h.example/\tstable main",
		"deb\thttp://i.example/ stable main",
		"deb http://j.example/ stable main\r",
		"deb mirror+http://k.example/mirrors.txt stable main",
		"deb http://l.example/debian/ stable/ ",
		"deb http://m.example/debian/$(ARCH)/ ./",
	}, "\n")

	got, err := ParseSourcesList(content)
	require.NoError(t, err)

	assert.Equal(t, []Source{
		{
			Type: TypeDeb, URL: "https://a.example/ubuntu/", Suite: "jammy", Components: []string{"main", "universe"},
			Architectures: []string{"amd64", "arm64"}, SignedBy: "/usr/share/keyrings/k.gpg",
		},
		{Type: TypeDebSrc, URL: "http://a.example/ubuntu/", Suite: "jammy", Components: []string{"main"}},
		{Type: TypeDeb, URL: "file:///srv/repo/", Suite: "jammy", Components: []string{"main"}},
		{Type: TypeDeb, URL: "cdrom:[Debian 12]/", Suite: "bookworm", Components: []string{"main"}},
		{Type: TypeDeb, URL: "ftp://a.example/debian/", Suite: "bookworm", Components: []string{"main"}},
		{Type: TypeDeb, URL: "http://d.example/", Suite: "stable", Components: []string{"main", "contrib"}, Trusted: SwitchYes},
		{Type: TypeDeb, URL: "http://e.example/debian/", Suite: "stable", Components: []string{"main"}},
		{Type: TypeDeb, URL: "http://f.example/", Suite: "stable", Components: []string{"main"}, Architectures: []string{"i386"}},
		{Type: TypeDeb, URL: "http://h.example/", Suite: "stable", Components: []string{"main"}},
		{Type: TypeDeb, URL: "http://i.example/", Suite: "stable", Components: []string{"main"}},
		{Type: TypeDeb, URL: "http://j.example/", Suite: "stable", Components: []string{"main"}},
		{Type: TypeDeb, URL: "mirror+http://k.example/mirrors.txt/", Suite: "stable", Components: []string{"main"}},
		{Type: TypeDeb, URL: "http://l.example/debian/", Suite: "stable/"},
		{Type: TypeDeb, URL: "http://m.example/debian/$(ARCH)/", Suite: "./"},
	}, got)

	schemes := make([]string, 6)
	for i := range schemes {
		schemes[i] = got[i].Scheme()
	}

	assert.Equal(t, []string{"https", "http", "file", "cdrom", "ftp", "http"}, schemes)
	assert.Equal(t, "mirror+http", got[11].Scheme())
	assert.True(t, got[1].IsSource())
	assert.True(t, got[12].Flat())

	got, err = ParseSourcesList("")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestParseSourcesListErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, line string
		option     string
		is         error
	}{
		{"unknown type", "debian http://g.example/ stable main", "", ErrMalformedSource},
		{"no uri", "deb", "", ErrMalformedSource},
		{"no suite", "deb http://h.example/", "", ErrMalformedSource},
		{"no component", "deb http://h.example/ stable", "", ErrMalformedSource},
		{"component after flat suite", "deb http://h.example/ ./ main", "", ErrMalformedSource},
		{"uri without scheme", "deb /srv/repo stable main", "", ErrMalformedSource},
		{"unterminated block", "deb [arch=amd64 http://c.example/ stable main", "http://c.example/", ErrMalformedSource},
		{"option too short", "deb [ab] http://c.example/ stable main", "ab", ErrMalformedSource},
		{"unterminated quote", `deb [arch="amd64] http://c.example/ stable main`, "", ErrMalformedSource},
		{"option with a one letter key and no value", "deb [a=] http://c.example/ stable main", "a", ErrMalformedSource},
		{"option without equal", "deb [archamd64] http://c.example/ stable main", "archamd64", ErrMalformedSource},
		{"option without key", "deb [=amd64] http://c.example/ stable main", "=amd64", ErrMalformedSource},
		{"option without value", "deb [arch=] http://c.example/ stable main", "arch", ErrMalformedSource},
		{"bad boolean", "deb [trusted=maybe] http://c.example/ stable main", "trusted", ErrInvalidOption},
		{"bad number", "deb [valid-until-min=soon] http://c.example/ stable main", "valid-until-min", ErrInvalidOption},
		{"negative number", "deb [date-max-future=-5] http://c.example/ stable main", "date-max-future", ErrInvalidOption},
		{"huge number", "deb [valid-until-max=99999999999999999999] http://c.example/ stable main", "valid-until-max", ErrInvalidOption},
		{"bad by-hash", "deb [by-hash=sometimes] http://c.example/ stable main", "by-hash", ErrInvalidOption},
		{"bad signed-by", "deb [signed-by=relative/path] http://c.example/ stable main", "signed-by", ErrInvalidSignedBy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			good := "deb http://good.example/ stable main"

			got, err := ParseSourcesList("# first\n" + tt.line + "\n" + good + "\n")
			require.Error(t, err)
			require.ErrorIs(t, err, tt.is)

			require.Len(t, got, 1, "the other entry still parses")
			assert.Equal(t, "http://good.example/", got[0].URL)

			errs := sourceErrors(t, err)
			require.Len(t, errs, 1)
			assert.Equal(t, 2, errs[0].Line)
			assert.Equal(t, tt.option, errs[0].Option)
			assert.Contains(t, errs[0].Error(), ":2:")
		})
	}
}

func TestParseSourcesListOptions(t *testing.T) {
	t.Parallel()

	line := "deb [ arch=amd64,i386 arch+=arm64 arch-=i386 lang=en,de lang+=fr lang-=de target=Packages,Contents target+=Sources target-=Contents " +
		"trusted=yes allow-insecure=1 allow-weak=true allow-downgrade-to-insecure=on check-valid-until=no check-date=off " +
		"valid-until-min=3600 valid-until-max=86400 date-max-future=10 by-hash=force pdiffs=disable snapshot=20240101T000000Z " +
		"signed-by=/k1.gpg,/k2.gpg Contents-deb=no InRelease-Path=Release.gpg ] http://x.example/ stable main"

	got, err := ParseSourcesList(line)
	require.NoError(t, err)
	require.Len(t, got, 1)

	s := got[0]
	assert.Equal(t, []string{"amd64", "i386"}, s.Architectures)
	assert.Equal(t, []string{"arm64"}, s.ArchitecturesAdd)
	assert.Equal(t, []string{"i386"}, s.ArchitecturesRemove)
	assert.Equal(t, []string{"en", "de"}, s.Languages)
	assert.Equal(t, []string{"fr"}, s.LanguagesAdd)
	assert.Equal(t, []string{"de"}, s.LanguagesRemove)
	assert.Equal(t, []string{"Packages", "Contents"}, s.Targets)
	assert.Equal(t, []string{"Sources"}, s.TargetsAdd)
	assert.Equal(t, []string{"Contents"}, s.TargetsRemove)
	assert.Equal(t, SwitchYes, s.Trusted)
	assert.Equal(t, SwitchYes, s.AllowInsecure)
	assert.Equal(t, SwitchYes, s.AllowWeak)
	assert.Equal(t, SwitchYes, s.AllowDowngradeToInsecure)
	assert.Equal(t, SwitchNo, s.CheckValidUntil)
	assert.Equal(t, SwitchNo, s.CheckDate)
	assert.Equal(t, time.Hour, s.ValidUntilMin)
	assert.Equal(t, 24*time.Hour, s.ValidUntilMax)
	assert.Equal(t, 10*time.Second, s.DateMaxFuture)
	assert.Equal(t, ByHashForce, s.ByHash)
	assert.Equal(t, SwitchNo, s.PDiffs)
	assert.Equal(t, "20240101T000000Z", s.Snapshot)
	assert.Equal(t, "/k1.gpg,/k2.gpg", s.SignedBy)
	assert.Equal(t, map[string]string{"Contents-deb": "no", "InRelease-Path": "Release.gpg"}, s.Options)

	assert.Equal(t, []string{"amd64", "arm64"}, s.EffectiveArchitectures("riscv64"))
}

func TestParseSourcesListQuoting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, line, suite string
		signedBy, url     string
	}{
		{"closing bracket glued to the last option", "deb [arch=amd64] http://h/ s c", "s", "", "http://h/"},
		{"closing bracket glued to a path option", "deb [signed-by=/k.gpg] http://h/ s c", "s", "/k.gpg", "http://h/"},
		{"quoted value", `deb [signed-by="/usr/share/keyrings/a.gpg"] http://h/ s c`, "s", "/usr/share/keyrings/a.gpg", "http://h/"},
		{"percent escape", "deb [signed-by=/usr/share/keyrings/a%2db.gpg] http://h/ s c", "s", "/usr/share/keyrings/a-b.gpg", "http://h/"},
		{"blank inside quotes", `deb [signed-by=/k.gpg,/l.gpg snapshot="a b"] http://h/ s c`, "s", "/k.gpg,/l.gpg", "http://h/"},
		{"hash inside brackets", "deb [signed-by=/k#1.gpg] http://h/ s c # comment", "s", "/k#1.gpg", "http://h/"},
		{"quoted uri", `deb "http://h/a b/" s c`, "s", "", "http://h/a b/"},
		{"escaped uri", "deb http://h/a%20b s c", "s", "", "http://h/a b/"},
		{"escape at the end is kept", "deb http://h/a%4 s c", "s", "", "http://h/a%4/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseSourcesList(tt.line)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, tt.url, got[0].URL)
			assert.Equal(t, tt.suite, got[0].Suite)
			assert.Equal(t, tt.signedBy, got[0].SignedBy)
		})
	}
}

func TestParseSourcesListBounds(t *testing.T) {
	t.Parallel()

	_, err := ParseSourcesList(strings.Repeat("#", MaxSourcesFileBytes+1))
	require.ErrorIs(t, err, ErrTooLarge)

	comps := strings.Repeat("c ", MaxSourceListValues+1)
	got, err := ParseSourcesList("deb http://h/ s " + comps)
	require.ErrorIs(t, err, ErrTooLarge)
	assert.Empty(t, got)

	opts := strings.Repeat("x=y ", MaxSourceListValues+1)
	_, err = ParseSourcesList("deb [" + opts + "] http://h/ s c")
	require.ErrorIs(t, err, ErrTooLarge)

	vals := strings.Repeat("a,", MaxSourceListValues+1)
	_, err = ParseSourcesList("deb [arch=" + vals + "] http://h/ s c")
	require.ErrorIs(t, err, ErrTooLarge)

	// MaxSourcesPerFile caps the sources, and says so once.
	many := strings.Repeat("deb http://h/ s c\n", MaxSourcesPerFile+5)
	got, err = ParseSourcesList(many)
	require.ErrorIs(t, err, ErrTooLarge)
	assert.Len(t, got, MaxSourcesPerFile)
	assert.Len(t, sourceErrors(t, err), 1)
}

func TestParseBoolSpellings(t *testing.T) {
	t.Parallel()

	yes := []string{"yes", "YES", "Yes", "true", "True", "with", "on", "ON", "enable", "Enable", "1", "01"}
	no := []string{"no", "No", "false", "FALSE", "without", "off", "Off", "disable", "DISABLE", "0", "00"}

	for _, v := range yes {
		got, ok := parseSwitch(v)
		assert.True(t, ok, v)
		assert.Equal(t, SwitchYes, got, v)

		line, err := ParseSourcesList("deb [trusted=" + v + "] http://h/ s c")
		require.NoError(t, err, v)
		assert.Equal(t, SwitchYes, line[0].Trusted, v)
	}

	for _, v := range no {
		got, ok := parseSwitch(v)
		assert.True(t, ok, v)
		assert.Equal(t, SwitchNo, got, v)
	}

	for _, v := range []string{"", "2", "-1", "y", "n", "yess", "forced", "0x", "1.0"} {
		_, ok := parseSwitch(v)
		assert.False(t, ok, v)
	}

	by, err := parseByHash("FORCE")
	require.NoError(t, err)
	assert.Equal(t, ByHashForce, by)

	by, err = parseByHash("yes")
	require.NoError(t, err)
	assert.Equal(t, ByHashYes, by)

	by, err = parseByHash("without")
	require.NoError(t, err)
	assert.Equal(t, ByHashNo, by)

	_, err = parseByHash("")
	require.ErrorIs(t, err, ErrInvalidOption)
}

func TestParseSources822(t *testing.T) {
	t.Parallel()

	content := `Types: deb deb-src
URIs: https://a.example/debian https://b.example/debian/
Suites: bookworm bookworm-updates
Components: main contrib
Architectures: amd64 arm64
Signed-By: /usr/share/keyrings/debian.gpg

# a comment between stanzas
Types: deb-src
URIs: https://src.example/
Suites: stable
Components: main

Types: deb
URIs: https://off.example/
Suites: stable
Components: main
Enabled: no

Types: deb
URIs: https://off2.example/
Suites: stable
Components: main
Enabled: False

Types: deb
URIs: https://on.example/
Suites: stable
Components: main
Enabled: yes

Types: deb
URIs: file:///srv/repo ftp://f.example/ http://ok.example
Suites: stable
Components: main

Types: deb
URIs: https://flat.example/debian/
Suites: ./
`

	got, err := ParseSources822(content)
	require.NoError(t, err)

	comps := []string{"main", "contrib"}
	archs := []string{"amd64", "arm64"}
	key := "/usr/share/keyrings/debian.gpg"

	var want []Source

	for _, typ := range []SourceType{TypeDeb, TypeDebSrc} {
		for _, u := range []string{"https://a.example/debian/", "https://b.example/debian/"} {
			for _, suite := range []string{"bookworm", "bookworm-updates"} {
				want = append(want, Source{Type: typ, URL: u, Suite: suite, Components: comps, Architectures: archs, SignedBy: key})
			}
		}
	}

	want = append(want,
		Source{Type: TypeDebSrc, URL: "https://src.example/", Suite: "stable", Components: []string{"main"}},
		Source{Type: TypeDeb, URL: "https://on.example/", Suite: "stable", Components: []string{"main"}},
		Source{Type: TypeDeb, URL: "file:///srv/repo/", Suite: "stable", Components: []string{"main"}},
		Source{Type: TypeDeb, URL: "ftp://f.example/", Suite: "stable", Components: []string{"main"}},
		Source{Type: TypeDeb, URL: "http://ok.example/", Suite: "stable", Components: []string{"main"}},
		Source{Type: TypeDeb, URL: "https://flat.example/debian/", Suite: "./"},
	)

	assert.Equal(t, want, got)

	// The sources of one stanza do not share memory.
	got[0].Components[0] = "changed"
	got[0].Architectures[0] = "changed"

	assert.Equal(t, "main", got[1].Components[0])
	assert.Equal(t, "amd64", got[1].Architectures[0])

	got, err = ParseSources822("")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestParseSources822Options(t *testing.T) {
	t.Parallel()

	content := `Types: deb
URIs: http://x.example/
Suites: stable
Components: main
architectures: amd64 i386
ARCHITECTURES-ADD: arm64
Architectures-Remove: i386
Languages: en de
Languages-Add: fr
Languages-Remove: de
Targets: Packages
Targets-Add: Sources
Targets-Remove: Contents
Trusted: yes
Allow-Insecure: 1
Allow-Weak: true
Allow-Downgrade-To-Insecure: on
Check-Valid-Until: no
Check-Date: off
Valid-Until-Min: 3600
Valid-Until-Max: 86400
Date-Max-Future: 10
By-Hash: force
PDiffs: disable
Snapshot: 20240101T000000Z
Signed-By: 0123456789ABCDEF0123456789ABCDEF01234567
 /usr/share/keyrings/x.gpg
Contents-deb: no
InRelease-Path: Release.gpg
`

	got, err := ParseSources822(content)
	require.NoError(t, err)
	require.Len(t, got, 1)

	s := got[0]
	assert.Equal(t, []string{"amd64", "i386"}, s.Architectures)
	assert.Equal(t, []string{"arm64"}, s.ArchitecturesAdd)
	assert.Equal(t, []string{"i386"}, s.ArchitecturesRemove)
	assert.Equal(t, []string{"en", "de"}, s.Languages)
	assert.Equal(t, []string{"fr"}, s.LanguagesAdd)
	assert.Equal(t, []string{"de"}, s.LanguagesRemove)
	assert.Equal(t, []string{"Packages"}, s.Targets)
	assert.Equal(t, []string{"Sources"}, s.TargetsAdd)
	assert.Equal(t, []string{"Contents"}, s.TargetsRemove)
	assert.Equal(t, SwitchYes, s.Trusted)
	assert.Equal(t, SwitchYes, s.AllowInsecure)
	assert.Equal(t, SwitchYes, s.AllowWeak)
	assert.Equal(t, SwitchYes, s.AllowDowngradeToInsecure)
	assert.Equal(t, SwitchNo, s.CheckValidUntil)
	assert.Equal(t, SwitchNo, s.CheckDate)
	assert.Equal(t, time.Hour, s.ValidUntilMin)
	assert.Equal(t, 24*time.Hour, s.ValidUntilMax)
	assert.Equal(t, 10*time.Second, s.DateMaxFuture)
	assert.Equal(t, ByHashForce, s.ByHash)
	assert.Equal(t, SwitchNo, s.PDiffs)
	assert.Equal(t, "20240101T000000Z", s.Snapshot)
	assert.Contains(t, s.SignedBy, "0123456789ABCDEF0123456789ABCDEF01234567")
	assert.Contains(t, s.SignedBy, "/usr/share/keyrings/x.gpg")
	assert.Equal(t, map[string]string{"Contents-deb": "no", "InRelease-Path": "Release.gpg"}, s.Options)
}

func TestParseSources822Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, stanza, option string
		is                   error
	}{
		{"no types", "URIs: http://h/\nSuites: s\nComponents: c", "", ErrMalformedSource},
		{"unknown type", "Types: deb-foo\nURIs: http://h/\nSuites: s\nComponents: c", "Types", ErrMalformedSource},
		{"no uris", "Types: deb\nSuites: s\nComponents: c", "URIs", ErrMalformedSource},
		{"no suites", "Types: deb\nURIs: http://h/\nComponents: c", "Suites", ErrMalformedSource},
		{"no components", "Types: deb\nURIs: http://h/\nSuites: s", "Components", ErrMalformedSource},
		{"components with flat suite", "Types: deb\nURIs: http://h/\nSuites: ./\nComponents: c", "Components", ErrMalformedSource},
		{"uri without scheme", "Types: deb\nURIs: /srv/x\nSuites: s\nComponents: c", "URIs", ErrMalformedSource},
		{"bad enabled", "Types: deb\nURIs: http://h/\nSuites: s\nComponents: c\nEnabled: perhaps", "Enabled", ErrInvalidOption},
		{"bad trusted", "Types: deb\nURIs: http://h/\nSuites: s\nComponents: c\nTrusted: maybe", "Trusted", ErrInvalidOption},
		{"empty trusted", "Types: deb\nURIs: http://h/\nSuites: s\nComponents: c\nTrusted:", "Trusted", ErrInvalidOption},
		{"bad seconds", "Types: deb\nURIs: http://h/\nSuites: s\nComponents: c\nValid-Until-Max: 1h", "Valid-Until-Max", ErrInvalidOption},
		{"bad signed-by", "Types: deb\nURIs: http://h/\nSuites: s\nComponents: c\nSigned-By: not-a-key", "Signed-By", ErrInvalidSignedBy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			good := "Types: deb\nURIs: http://good.example/\nSuites: s\nComponents: c\n"

			got, err := ParseSources822(good + "\n" + tt.stanza + "\n\n" + good)
			require.ErrorIs(t, err, tt.is)

			assert.Len(t, got, 2, "the other stanzas still parse")

			errs := sourceErrors(t, err)
			require.Len(t, errs, 1)
			assert.Equal(t, 6, errs[0].Line, "the first line of the stanza")
			assert.Equal(t, tt.option, errs[0].Option)
		})
	}
}

func TestParseSources822Bounds(t *testing.T) {
	t.Parallel()

	_, err := ParseSources822(strings.Repeat("#", MaxSourcesFileBytes+1))
	require.ErrorIs(t, err, ErrTooLarge)

	many := func(n int, prefix string) string {
		var sb strings.Builder

		for i := range n {
			sb.WriteString(prefix)
			sb.WriteString(strings.Repeat("x", 1+i%7))
			sb.WriteByte(byte('a' + i%26))
			sb.WriteString(" ")
		}

		return sb.String()
	}

	got, err := ParseSources822("Types: deb\nURIs: http://h/\nSuites: s\nComponents: " + many(MaxSourceListValues+1, "") + "\n")
	require.ErrorIs(t, err, ErrTooLarge)
	assert.Empty(t, got)

	// Types x URIs x Suites over MaxStanzaSources is refused as a whole.
	uris := strings.Repeat("http://h/ ", 33)
	suites := strings.Repeat("s ", 32)
	_, err = ParseSources822("Types: deb deb-src\nURIs: " + uris + "\nSuites: " + suites + "\nComponents: c\n")
	require.ErrorIs(t, err, ErrTooLarge)

	_, err = ParseSources822("Types: deb\nURIs: http://h/\nSuites: s\nComponents: c\nArchitectures: " + many(MaxSourceListValues+1, "") + "\n")
	require.ErrorIs(t, err, ErrTooLarge)

	stanza := "Types: deb\nURIs: http://h/\nSuites: s\nComponents: c\n\n"
	got, err = ParseSources822(strings.Repeat(stanza, MaxSourcesPerFile+5))
	require.ErrorIs(t, err, ErrTooLarge)
	assert.Len(t, got, MaxSourcesPerFile)
}

func TestSourceError(t *testing.T) {
	t.Parallel()

	inner := errors.New("boom")

	e := &SourceError{Path: "/etc/apt/a.list", Line: 3, Option: "arch", Err: inner}
	assert.Equal(t, `apt: sources /etc/apt/a.list:3: option "arch": boom`, e.Error())
	require.ErrorIs(t, e, inner)

	assert.Equal(t, "apt: sources: boom", (&SourceError{Err: inner}).Error())
	assert.Equal(t, "apt: sources x.list: boom", (&SourceError{Path: "x.list", Err: inner}).Error())
}

func TestEffective(t *testing.T) {
	t.Parallel()

	s := &Source{Type: TypeDeb}
	assert.Equal(t, []string{"amd64"}, s.EffectiveArchitectures("amd64"))
	assert.Empty(t, s.EffectiveArchitectures(""))

	s = &Source{
		Architectures: []string{"amd64", "i386", "amd64"}, ArchitecturesAdd: []string{"arm64", "amd64"},
		ArchitecturesRemove: []string{"i386"},
	}
	assert.Equal(t, []string{"amd64", "arm64"}, s.EffectiveArchitectures("riscv64"))

	s = &Source{ArchitecturesAdd: []string{"i386"}}
	assert.Equal(t, []string{"amd64", "i386"}, s.EffectiveArchitectures("amd64"))

	s = &Source{}
	assert.Equal(t, []string{"en"}, s.EffectiveLanguages([]string{"en"}))

	s = &Source{Languages: []string{"de"}, LanguagesAdd: []string{"fr"}, LanguagesRemove: []string{"de"}}
	assert.Equal(t, []string{"fr"}, s.EffectiveLanguages([]string{"en"}))

	// default targets
	assert.Equal(t, []string{"Packages"}, (&Source{}).EffectiveTargets(nil))
	assert.Equal(t, []string{"Packages"}, (&Source{}).EffectiveTargets([]string{"none"}))
	assert.Equal(t, []string{"Packages", "Translations"}, (&Source{}).EffectiveTargets([]string{"en"}))
	assert.Equal(t, []string{"Packages"}, (&Source{Languages: []string{"none"}}).EffectiveTargets([]string{"en"}))
	assert.Equal(t, []string{"Packages", "Translations"}, (&Source{Languages: []string{"de"}}).EffectiveTargets(nil))
	assert.Equal(t, []string{"Packages", "Translations"}, (&Source{LanguagesAdd: []string{"de"}}).EffectiveTargets(nil))
	assert.Equal(t, []string{"Sources"}, (&Source{Type: TypeDebSrc}).EffectiveTargets([]string{"en"}))
	assert.Equal(t, []string{"Packages", "Contents"}, (&Source{TargetsAdd: []string{"Contents"}}).EffectiveTargets(nil))
	assert.Equal(t, []string{"Translations"}, (&Source{TargetsRemove: []string{"Packages"}}).EffectiveTargets([]string{"en"}))
	assert.Equal(t, []string{"Contents"}, (&Source{Targets: []string{"Packages", "Contents"}, TargetsRemove: []string{"Packages"}}).EffectiveTargets(nil))
}

func TestSourceMethods(t *testing.T) {
	t.Parallel()

	s := &Source{URL: "HTTPS://h/x/$(ARCH)/", Suite: "s-$(ARCH)"}
	assert.Equal(t, "https", s.Scheme())
	assert.Empty(t, (&Source{URL: "nothing"}).Scheme())

	got := s.ExpandArch("amd64")
	assert.Equal(t, "HTTPS://h/x/amd64/", got.URL)
	assert.Equal(t, "s-amd64", got.Suite)
	assert.Equal(t, "HTTPS://h/x/$(ARCH)/", s.URL, "the original is unchanged")

	assert.True(t, SwitchYes.Enabled(false))
	assert.False(t, SwitchNo.Enabled(true))
	assert.True(t, SwitchDefault.Enabled(true))
	assert.False(t, SwitchDefault.Enabled(false))
}

func TestLoadSources(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	listFile := filepath.Join(dir, "sources.list")
	listDir := filepath.Join(dir, "sources.list.d")

	writeFile(t, listFile, "deb http://main.example/ stable main\n")
	writeFile(t, filepath.Join(listDir, "b.sources"), "Types: deb\nURIs: http://b.example/\nSuites: s\nComponents: c\n")
	writeFile(t, filepath.Join(listDir, "a.list"), "deb http://a.example/ s c\n")
	writeFile(t, filepath.Join(listDir, "z.txt"), "deb http://ignored.example/ s c\n")
	writeFile(t, filepath.Join(listDir, ".hidden.list"), "deb http://hidden.example/ s c\n")
	writeFile(t, filepath.Join(listDir, "bad name.list"), "deb http://space.example/ s c\n")
	writeFile(t, filepath.Join(listDir, "colon:x.list"), "deb http://colon.example/ s c\n")
	writeFile(t, filepath.Join(listDir, "dot.list."), "deb http://dot.example/ s c\n")
	writeFile(t, filepath.Join(listDir, "UPPER-1_x.list"), "deb http://upper.example/ s c\n")
	require.NoError(t, os.Mkdir(filepath.Join(listDir, "dir.list"), 0o755))
	require.NoError(t, os.Symlink(filepath.Join(listDir, "a.list"), filepath.Join(listDir, "link.list")))
	require.NoError(t, os.Symlink(filepath.Join(listDir, "nowhere"), filepath.Join(listDir, "dangling.list")))

	got, err := LoadSources(listFile, listDir)
	require.NoError(t, err)

	urls := make([]string, len(got))
	for i, s := range got {
		urls[i] = s.URL
	}

	assert.Equal(t, []string{
		"http://main.example/", "http://upper.example/", "http://a.example/", "http://b.example/", "http://a.example/",
	}, urls, "the file first, then the directory in name order")
}

func TestLoadSourcesReportsParseErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	list := filepath.Join(dir, "x.list")
	deb822 := filepath.Join(dir, "y.sources")

	writeFile(t, list, "deb http://ok.example/ s c\ndeb [trusted=maybe] http://bad.example/ s c\n")
	writeFile(t, deb822, "Types: deb\nURIs: http://y.example/\nSuites: s\n")

	got, err := LoadSources(list, dir)
	require.Error(t, err)
	require.Len(t, got, 2, "x.list is read as the list file and again from the directory")

	errs := sourceErrors(t, err)
	require.Len(t, errs, 3)
	assert.Equal(t, list, errs[0].Path)
	assert.Equal(t, 2, errs[0].Line)
	assert.Equal(t, "trusted", errs[0].Option)
	require.ErrorIs(t, errs[0], ErrInvalidOption)

	// the directory is read too, and it holds both files
	assert.Equal(t, list, errs[1].Path)
	assert.Equal(t, deb822, errs[2].Path)
	require.ErrorIs(t, errs[2], ErrMalformedSource)
}

func TestLoadSourcesTolerance(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	got, err := LoadSources("", "")
	require.NoError(t, err)
	assert.Empty(t, got)

	got, err = LoadSources(filepath.Join(dir, "absent.list"), filepath.Join(dir, "absent.d"))
	require.NoError(t, err, "missing files and directories are fine")
	assert.Empty(t, got)

	// a file where the directory should be
	notDir := filepath.Join(dir, "file")
	writeFile(t, notDir, "x")

	_, err = LoadSources("", notDir)
	require.Error(t, err)
}

func TestLoadSourcesOversizedAndUnreadable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	listDir := filepath.Join(dir, "d")

	writeFile(t, filepath.Join(listDir, "a.list"), "deb http://a.example/ s c\n")
	writeFile(t, filepath.Join(listDir, "big.list"), "# "+strings.Repeat("x", MaxSourcesFileBytes)+"\ndeb http://big.example/ s c\n")

	got, err := LoadSources("", listDir)
	require.ErrorIs(t, err, ErrTooLarge)
	assert.ErrorContains(t, err, "big.list")
	require.Len(t, got, 1)
	assert.Equal(t, "http://a.example/", got[0].URL, "the readable sources still load")

	// A file exactly at the limit is accepted.
	exact := filepath.Join(dir, "exact.list")
	line := "deb http://exact.example/ s c\n"
	writeFile(t, exact, line+strings.Repeat("#", MaxSourcesFileBytes-len(line)))

	got, err = LoadSources(exact, "")
	require.NoError(t, err)
	require.Len(t, got, 1)

	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked.list")
		writeFile(t, locked, "deb http://locked.example/ s c\n")
		require.NoError(t, os.Chmod(locked, 0o000))

		t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })

		got, err = LoadSources(locked, "")
		require.Error(t, err)
		assert.Empty(t, got)
	}
}
