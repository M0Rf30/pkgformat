package apt

import (
	"errors"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/deb"
)

// checkParsed verifies what every parsed source must satisfy.
func checkParsed(t *testing.T, srcs []Source, err error) {
	t.Helper()

	if err != nil {
		walkErrors(t, err)
	}

	for _, s := range srcs {
		if s.Type != TypeDeb && s.Type != TypeDebSrc {
			t.Fatalf("type %q", s.Type)
		}

		if !strings.Contains(s.URL, ":") || !strings.HasSuffix(s.URL, "/") {
			t.Fatalf("URL %q has no scheme or trailing slash", s.URL)
		}

		if s.Suite == "" {
			t.Fatalf("source without suite: %+v", s)
		}

		if s.Flat() == (len(s.Components) > 0) {
			t.Fatalf("flat suite %q with components %q", s.Suite, s.Components)
		}

		if got := ListFileNameFor(&s, "Release"); strings.Contains(got, "/") {
			t.Fatalf("list file name %q holds a slash", got)
		}

		_ = s.Scheme()
		_ = s.EffectiveArchitectures("amd64")
		_ = s.EffectiveLanguages([]string{"en"})
		_ = s.EffectiveTargets([]string{"en"})
	}
}

// walkErrors fails unless err is a tree of *SourceError, or ErrTooLarge.
func walkErrors(t *testing.T, err error) {
	t.Helper()

	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range j.Unwrap() {
			walkErrors(t, e)
		}

		return
	}

	var se *SourceError
	if !errors.As(err, &se) && !errors.Is(err, ErrTooLarge) {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
}

func FuzzParseSourcesList(f *testing.F) {
	for _, seed := range []string{
		"",
		"deb http://a.example/ stable main\n",
		"deb [arch=amd64,arm64 signed-by=/k.gpg] https://a.example/ubuntu jammy main universe\ndeb-src http://x/ y z\n",
		"deb [arch+=i386 arch-=amd64 lang=de target-=Contents-deb trusted=yes by-hash=force valid-until-min=5] file:/srv/r ./",
		"deb [arch=amd64 http://broken/ s m\n",
		"deb [] http://x/ s m",
		"deb [arch= signed-by=] http://x/ s m",
		"# comment\n\n   deb\thttp://x/ s m\r\n",
		"deb http://\x00/ s m",
		"deb [signed-by=\"/k#1\" snapshot=\"a b\"] cdrom:[Debian 12] bookworm main # c",
		"deb mirror+http://[::1]:80/x s/ ",
		"deb http://u:p%40@h:99999999999/a%2",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		srcs, err := ParseSourcesList(content)
		checkParsed(t, srcs, err)
	})
}

func FuzzParseSources822(f *testing.F) {
	for _, seed := range []string{
		"",
		"Types: deb\nURIs: https://a.example/debian\nSuites: bookworm\nComponents: main\n",
		"Types: deb deb-src\nURIs: http://a/ http://b/\nSuites: s t\nComponents: c d\nArchitectures: amd64\nSigned-By: /k\n\nTypes: deb\nURIs: http://c/\nSuites: s\nComponents: c\nEnabled: no\n",
		"Types: deb\nURIs: http://a/\n  http://b/\nSuites: s\nComponents: c\n",
		"Types:deb\nURIs:\nSuites:\n\n\n\nComponents: c",
		"# comment\nTypes: deb\n",
		"Types: deb\nURIs: file:/x\nSuites: ./\nBy-Hash: force\nValid-Until-Max: 99999999999999999999\nTrusted:\n",
		"Types: deb\nURIs: http://h/\nSuites: s\nComponents: c\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n -----END PGP PUBLIC KEY BLOCK-----\n",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		srcs, err := ParseSources822(content)
		checkParsed(t, srcs, err)
	})
}

func FuzzListFileName(f *testing.F) {
	for _, seed := range [][3]string{
		{"https://archive.ubuntu.com/ubuntu/", "jammy", "main/binary-amd64/Packages.xz"},
		{"http://127.0.0.1:8080/a/b/", "s", "c/binary-i386/Packages"},
		{"http://[::1", "s", "x"},
		{"http://[::1]:8081/", "a+b~c", "x"},
		{"%zz", "", ""},
		{"", "", ""},
		{"http://h/%2F%2e%2e/", "../s", "a//b"},
		{"file:///srv/r", "./", "Packages"},
		{"copy:/x_~y", "/", "InRelease"},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}

	f.Fuzz(func(t *testing.T, baseURL, suite, rel string) {
		name := ListFileName(baseURL, suite, rel)

		if strings.Contains(name, "/") {
			t.Fatalf("%q still holds a path separator", name)
		}

		// A suite that is a plain name gives a name that has the dists
		// separator and starts with the key BaseURLs derives.
		if name != "" && !strings.HasSuffix(suite, "/") {
			if !strings.Contains(name, "_dists_") {
				t.Fatalf("%q lacks the dists separator", name)
			}

			if key := encodeHostPath(baseURL); !strings.HasPrefix(name, key+"_dists_") {
				t.Fatalf("%q does not start with the base key %q", name, key)
			}
		}

		if again := ListFileName(baseURL, suite, rel); again != name {
			t.Fatalf("unstable result %q vs %q", again, name)
		}

		_ = BaseURLs([]Source{{URL: baseURL}})
	})
}

func FuzzParseSignedBy(f *testing.F) {
	for _, seed := range []string{
		"",
		strings.Repeat("A", 40),
		strings.Repeat("a", 40) + "!,/etc/apt/keyrings/k.gpg",
		"/a /b\n/c",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n.\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\nmixed " + strings.Repeat("A", 40),
		"relative/path",
		"!!",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, v string) {
		spec, err := parseSignedBy(v)
		if err != nil {
			if !errors.Is(err, ErrInvalidSignedBy) {
				t.Fatalf("error %v does not match ErrInvalidSignedBy", err)
			}

			return
		}

		if len(spec.inline) == 0 && len(spec.paths) == 0 && len(spec.keys) == 0 {
			t.Fatalf("empty spec accepted for %q", v)
		}

		if len(spec.inline) > 0 && (len(spec.paths) > 0 || len(spec.keys) > 0) {
			t.Fatalf("inline key mixed with other values for %q", v)
		}

		for _, k := range spec.keys {
			if len(k.fingerprint) != fingerprintLen || k.fingerprint != strings.ToUpper(k.fingerprint) {
				t.Fatalf("fingerprint %q", k.fingerprint)
			}
		}

		for _, p := range spec.paths {
			if !strings.HasPrefix(p, "/") {
				t.Fatalf("relative path %q", p)
			}
		}

		// Nothing is loadable from nowhere: the error, when there is one,
		// is a missing trust anchor.
		if _, err := LoadKeyring(v, nil); err != nil && !errors.Is(err, deb.ErrNoTrustAnchor) {
			t.Fatalf("LoadKeyring error %v does not match ErrNoTrustAnchor", err)
		}
	})
}
