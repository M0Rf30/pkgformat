package pacman

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSigLevelSemantics(t *testing.T) {
	t.Parallel()

	req := SigPolicy{Check: SigRequired}
	opt := SigPolicy{Check: SigOptional}
	never := SigPolicy{Check: SigNever}
	all := func(p SigPolicy) SigPolicy { p.Trust = SigTrustAll; return p }

	for _, tc := range []struct {
		in   string
		want SigLevel
	}{
		{"", SigLevel{req, req}},
		{"Required", SigLevel{req, req}},
		{"Optional", SigLevel{opt, opt}},
		{"Never", SigLevel{never, never}},
		{"TrustAll", SigLevel{all(req), all(req)}},
		{"Optional TrustAll", SigLevel{all(opt), all(opt)}},
		{"PackageNever", SigLevel{never, req}},
		{"DatabaseOptional", SigLevel{req, opt}},
		{"Required DatabaseOptional", SigLevel{req, opt}},
		{"DatabaseOptional Required", SigLevel{req, req}},
		{"PackageTrustAll DatabaseNever", SigLevel{all(req), never}},
		{"Optional  Required", SigLevel{req, req}},
		{"Never TrustAll Optional", SigLevel{all(opt), all(opt)}},
	} {
		got, err := ParseSigLevel(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ParseSigLevel(%q) = %+v, %v; want %+v", tc.in, got, err, tc.want)
		}
	}

	for _, in := range []string{"required", "Package", "Database", "PackageFoo", "Sometimes", "Required,Optional", "Packagerequired"} {
		if _, err := ParseSigLevel(in); !errors.Is(err, ErrInvalidSigLevel) || !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("ParseSigLevel(%q) err = %v", in, err)
		}
	}
}

func TestSigLevelApplyAndRender(t *testing.T) {
	t.Parallel()

	base, err := ParseSigLevel("Required DatabaseOptional")
	if err != nil {
		t.Fatal(err)
	}

	got, err := base.Apply("PackageNever DatabaseTrustAll")
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"PackageNever", "DatabaseOptional", "DatabaseTrustAll"}
	if !reflect.DeepEqual(got.Tokens(), want) || got.String() != strings.Join(want, " ") {
		t.Errorf("tokens = %v, string = %q", got.Tokens(), got.String())
	}

	// The base is unchanged and the rendering parses back.
	if base.String() != "PackageRequired PackageTrustedOnly DatabaseOptional DatabaseTrustedOnly" {
		t.Errorf("base = %q", base)
	}

	back, err := ParseSigLevel(base.String())
	if err != nil || back != base {
		t.Errorf("round trip = %+v, %v", back, err)
	}

	if _, err := base.Apply("Nope"); err == nil {
		t.Error("invalid token accepted")
	}

	if !(SigLevel{}).IsZero() || DefaultSigLevel().IsZero() || (SigLevel{}).String() != "" {
		t.Error("zero level")
	}

	if got := (SigPolicy{Check: SigOptional, Trust: SigTrustAll}).String(); got != "Optional TrustAll" {
		t.Errorf("policy = %q", got)
	}
}

func TestSigPolicyVerifyMode(t *testing.T) {
	t.Parallel()

	for c, want := range map[SigCheck]VerifyMode{
		SigCheckUnset: VerifyNone, SigNever: VerifyNone, SigOptional: VerifyIfPresent, SigRequired: VerifyRequired,
	} {
		if got := (SigPolicy{Check: c}).VerifyMode(); got != want {
			t.Errorf("check %d = %d, want %d", c, got, want)
		}
	}
}

func TestFnmatch(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"glibc", "glibc", true},
		{"glibc", "glibc2", false},
		{"", "", true},
		{"", "a", false},
		{"*", "", true},
		{"*", "anything/at/all", true},
		{"lib32-*", "lib32-glibc", true},
		{"lib32-*", "lib64-glibc", false},
		{"linux*", "linux", true},
		{"*-git", "foo-git", true},
		{"*-git", "foo-gitx", false},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXbYcZ", false},
		{"a**b", "ab", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"?", "é", true},
		{"[gh]cc", "gcc", true},
		{"[gh]cc", "hcc", true},
		{"[gh]cc", "icc", false},
		{"[!gh]cc", "icc", true},
		{"[^gh]cc", "gcc", false},
		{"[a-c]x", "bx", true},
		{"[a-c]x", "dx", false},
		{"[]a]x", "]x", true},
		{"[a-]x", "-x", true},
		{"[[:digit:]]x", "5x", true},
		{"[[:digit:]]x", "ax", false},
		{"[[:alpha:][:digit:]]", "z", true},
		{"[[:alnum:]]", "_", false},
		{"[[:upper:]]", "A", true},
		{"[[:lower:]]", "A", false},
		{"[[:space:]]", " ", true},
		{"[[:punct:]]", "-", true},
		{"[[:xdigit:]]", "f", true},
		{`\*`, "*", true},
		{`\*`, "a", false},
		{`a\`, `a\`, true},
		{`[\]]`, "]", true},
		{"[ab", "[ab", true},
		{"[ab", "a", false},
		{"[", "[", true},
		{"a*", "a/b", true},
		{"é*", "éa", true},
	} {
		if got := fnmatchPattern(tc.pattern, tc.name); got != tc.want {
			t.Errorf("fnmatch(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestConfigHelpers(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfig(strings.NewReader(`
[options]
HoldPkg = pacman glibc linux*
IgnorePkg = firefox lib32-*
IgnoreGroup = gnome kde-*
Architecture = auto x86_64 x86_64_v3
[core]
Server = https://core.example
Usage = Sync Search
[extra]
Server = https://extra.example
`), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for name, want := range map[string]bool{"pacman": true, "glibc": true, "linux-lts": true, "bash": false, "": false} {
		if got := cfg.IsHeld(name); got != want {
			t.Errorf("IsHeld(%q) = %v", name, got)
		}
	}

	if !cfg.IsIgnored("firefox") || !cfg.IsIgnored("lib32-mesa") || cfg.IsIgnored("mesa") ||
		!cfg.IsIgnored("nautilus", "gnome") || !cfg.IsIgnored("x", "a", "kde-games") || cfg.IsIgnored("x", "base") {
		t.Error("IsIgnored")
	}

	if got := cfg.AllowedArchitectures("amd64"); !reflect.DeepEqual(got, []string{"x86_64", "x86_64", "x86_64_v3"}) {
		t.Errorf("AllowedArchitectures(amd64) = %v", got)
	}

	if got := cfg.AllowedArchitectures("arm64"); !reflect.DeepEqual(got, []string{"aarch64", "x86_64", "x86_64_v3"}) {
		t.Errorf("AllowedArchitectures(arm64) = %v", got)
	}

	if cfg.Arch("amd64") != "x86_64" || cfg.Arch("aarch64") != "aarch64" {
		t.Errorf("Arch = %q, %q", cfg.Arch("amd64"), cfg.Arch("aarch64"))
	}

	if (&Config{}).Arch("amd64") != "" || (&Config{}).AllowedArchitectures("amd64") != nil {
		t.Error("Arch without an Architecture option")
	}

	opts := cfg.ResolveOptions()
	if !reflect.DeepEqual(opts.IgnorePkg, cfg.IgnorePkg) || !reflect.DeepEqual(opts.IgnoreGroup, cfg.IgnoreGroup) {
		t.Errorf("ResolveOptions = %+v", opts)
	}

	opts.IgnorePkg[0] = "changed"

	if cfg.IgnorePkg[0] != "firefox" {
		t.Error("ResolveOptions aliases the configuration")
	}

	if got := cfg.ReposFor(UsageSync); len(got) != 2 {
		t.Errorf("ReposFor(Sync) = %v", got)
	}

	if got := cfg.ReposFor(UsageInstall); len(got) != 1 || got[0].Name != "extra" {
		t.Errorf("ReposFor(Install) = %v", got)
	}

	if r, ok := cfg.Repo("core"); !ok || r.Usage != UsageSync|UsageSearch {
		t.Errorf("Repo(core) = %+v, %v", r, ok)
	}

	if _, ok := cfg.Repo("nope"); ok {
		t.Error("Repo(nope) found")
	}
}

func TestConfigApplyUsage(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfig(strings.NewReader("[a]\nServer = s\nUsage = Install\n[b]\nServer = s\nUsage = Search\n"), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}

	var x Index

	if err := x.Add("a", []DBEntry{{Name: "tool", Version: "1-1"}}); err != nil {
		t.Fatal(err)
	}

	if err := x.Add("b", []DBEntry{{Name: "tool", Version: "2-1"}}); err != nil {
		t.Fatal(err)
	}

	cfg.ApplyUsage(&x)

	dep, _ := ParseDependency("tool")

	got, err := x.Resolve(dep)
	if err != nil || got.Repo != "a" || got.Version != "1-1" {
		t.Errorf("Resolve after ApplyUsage = %+v, %v (b is not installable)", got, err)
	}
}
