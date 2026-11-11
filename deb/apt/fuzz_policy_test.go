package apt

import (
	"errors"
	"testing"
)

func FuzzParsePreferences(f *testing.F) {
	for _, seed := range []string{
		"Package: *\nPin: release a=stable\nPin-Priority: 990\n",
		"Package: foo bar\nPin: version 1.*\nPin-Priority: 1001\n\nPackage: src:baz\nPin: origin \"deb.example.org\"\nPin-Priority: -1\n",
		"Explanation: x\nPackage: *\nPin: release *\nPin-Priority: never\n",
		"Package: /^lib/\nPin: source-version 2\nPin-Priority: 5\n",
		"# comment\nPackage: a:amd64\nPin: release o=Debian,n=bookworm\nPin-Priority: 600abc\n",
		"Pin: release a=x\nPin-Priority: 1\n",
		"Package: a\nPin: release a=x\nPin-Priority: 99999\n",
		"Package: a\r\nPin: release a=x\r\nPin-Priority: 3\r\n",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		prefs, err := ParsePreferences(content)
		if err != nil && !errors.Is(err, ErrPreferences) && !errors.Is(err, ErrTooLarge) {
			t.Fatalf("untyped error %v", err)
		}

		if prefs == nil {
			t.Fatal("nil Preferences")
		}

		// Whatever was read must be usable.
		p := NewPolicy(prefs, PolicyOptions{NativeArch: "amd64", DefaultRelease: "stable"})
		v := &PackageInfo{Name: "foo", Version: "1.0", Architecture: "amd64", Releases: []*ReleaseInfo{{Suite: "stable", Origin: "Debian", Site: "deb.example.org"}}}
		_ = p.Priority(v)
		_ = p.Candidate([]*PackageInfo{v}, nil)
	})
}

func FuzzFnmatch(f *testing.F) {
	for _, seed := range [][2]string{
		{"*", "abc"}, {"a?c", "ABC"}, {"[[:alpha:]]*", "x1"}, {"[!a-c]", "d"}, {"[a", "[a"}, {`\*`, "*"},
		{"[[.a.]-c]", "b"}, {"[[=a=]]", "a"}, {"*a*b*c*d*e*f*g", "aaaaaaaaaaaaaaaaaaaaaaaaa"},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, pattern, s string) {
		_ = fnmatch(pattern, s)
		// Matching ends however the pattern stacks stars: guard the cost.
		if !fnmatch("*", s) {
			t.Fatalf("* did not match %q", s)
		}
	})
}

func FuzzExpression(f *testing.F) {
	for _, seed := range [][2]string{
		{"/^lib(foo|bar)[0-9]*$/", "libfoo1"}, {"/a**/", "b"}, {"/(?i)a/", "A"}, {`/\<w/`, "w"}, {"/[[:alpha:]]+/", "é"},
		{"/a{,3}/", "aa"}, {"/[/", "["}, {"/(/", "("}, {"//", ""}, {"glob*", "globs"},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, pattern, s string) {
		_ = newExpression(pattern).matches(s)
	})
}

func FuzzPinSpec(f *testing.F) {
	for _, seed := range []string{
		"a=stable", "o=Debian,a=stable,n=bookworm,l=Debian,v=12*,c=main,b=amd64", "*", "12.5", "stable", "v=*", ",,,", "a=", "x=y",
		"origin", `"site"`,
	} {
		f.Add(seed)
	}

	rel := &ReleaseInfo{Origin: "Debian", Label: "Debian", Suite: "stable", Codename: "bookworm", Version: "12.5", Component: "main", Architecture: "amd64", Site: "deb.example.org"}

	f.Fuzz(func(t *testing.T, data string) {
		for _, kind := range []PinType{PinRelease, PinOrigin, PinVersion, PinSourceVersion} {
			s := newPinSpec(kind, data)
			_ = s.matchFile(pinFile{rel: rel})
			_ = s.matchFile(pinFile{status: true})
			_ = s.matchVersion(&PackageInfo{Name: "a", Version: "1"}, nil)
		}
	})
}

func FuzzPhasedDraw(f *testing.F) {
	f.Add("src", "1.0-1", "0123456789abcdef", 0)
	f.Add("", "", "", 1)
	f.Add("sourcé", "1:2~3+4", "\xff\x80", 2)

	f.Fuzz(func(t *testing.T, src, ver, id string, model int) {
		m := PhasedModel(model & 3 % 3)

		d := PhasedDraw(src, ver, id, m)
		if d < 0 || d >= int(m.draws()) {
			t.Fatalf("draw %d outside [0,%d)", d, m.draws())
		}

		if d != PhasedDraw(src, ver, id, m) {
			t.Fatal("not deterministic")
		}
	})
}
