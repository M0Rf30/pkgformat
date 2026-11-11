package adb

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os/exec"
	"strings"
	"testing"
)

var versionPairs = []struct {
	a, b string
	want int
}{
	{"1.0", "1.0", 0},
	{"1.0", "1.1", -1},
	{"1.1", "1.0", 1},
	{"1.9", "1.10", -1},
	{"1.10", "1.9", 1},
	{"2.0", "1.99.99", 1},
	{"1.0", "1.0.1", -1},
	{"1.0_alpha1", "1.0", -1},
	{"1.0_alpha1", "1.0_beta1", -1},
	{"1.0_beta1", "1.0_pre1", -1},
	{"1.0_pre1", "1.0_rc1", -1},
	{"1.0_rc1", "1.0", -1},
	{"1.0", "1.0_p1", -1},
	{"1.0_p1", "1.0_p2", -1},
	{"1.0_git20200101", "1.0", 1},
	{"1.0_git20200101", "1.0_git20190101", 1},
	{"1.0", "1.0a", -1},
	{"1.0a", "1.0b", -1},
	{"1.0-r0", "1.0-r1", -1},
	{"1.0-r2", "1.0-r10", -1},
	{"1.0", "1.0-r1", -1},
	{"1.0-r1", "1.1-r0", -1},
	{"1.2.3_rc1-r4", "1.2.3_rc1-r4", 0},
	{"1.0_alpha", "1.0_alpha1", -1},
	{"1.01", "1.1", -1},
	{"0.9", "1", -1},
	{"1.0~abc", "1.0~abd", -1},
}

func TestCompareVersions(t *testing.T) {
	for _, c := range versionPairs {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}

		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestValidVersion(t *testing.T) {
	for _, v := range []string{"1", "1.0", "1.2.3a", "1.0_rc1", "1.0_git20200101-r3", "1.0-r0", "1.0_alpha_p1", "1.0~abcdef", "20200101"} {
		if !ValidVersion(v) {
			t.Errorf("%q is not valid", v)
		}
	}

	for _, v := range []string{"", "a", "1.", "1..2", "1.0_", "1.0_foo", "1.0-r", "1.0-rx", "1.0 ", "-1", "1.0-r1-r2", "1.0_alpha-", ".1", "1.0~", "1.0~xyz", "1.0_rc1a"} {
		if ValidVersion(v) {
			t.Errorf("%q is valid", v)
		}
	}
}

// TestVersionsMatchApk compares the ordering with apk version -t over fixed
// pairs and random ones.
func TestVersionsMatchApk(t *testing.T) {
	apk := needApk(t)

	rng := rand.New(rand.NewPCG(1, 2))

	var pairs [][2]string

	for _, c := range versionPairs {
		pairs = append(pairs, [2]string{c.a, c.b})
	}

	random := func() string {
		var sb strings.Builder

		fmt.Fprintf(&sb, "%d", rng.IntN(12))

		for range rng.IntN(3) {
			fmt.Fprintf(&sb, ".%d", rng.IntN(12))
		}

		if rng.IntN(4) == 0 {
			sb.WriteByte(byte('a' + rng.IntN(3)))
		}

		for range rng.IntN(3) {
			sb.WriteString([]string{"_alpha", "_beta", "_pre", "_rc", "_cvs", "_svn", "_git", "_hg", "_p"}[rng.IntN(9)])

			if rng.IntN(2) == 0 {
				fmt.Fprintf(&sb, "%d", rng.IntN(5))
			}
		}

		if rng.IntN(3) == 0 {
			fmt.Fprintf(&sb, "-r%d", rng.IntN(5))
		}

		return sb.String()
	}

	for range 250 {
		pairs = append(pairs, [2]string{random(), random()})
	}

	for _, p := range pairs {
		if !ValidVersion(p[0]) || !ValidVersion(p[1]) {
			t.Fatalf("generated an invalid version: %q %q", p[0], p[1])
		}

		out, err := exec.Command(apk, "version", "-t", p[0], p[1]).Output()
		if err != nil {
			t.Fatalf("apk version %q %q: %v", p[0], p[1], err)
		}

		want := map[string]int{"<": -1, "=": 0, ">": 1}[strings.TrimSpace(string(out))]
		if got := CompareVersions(p[0], p[1]); got != want {
			t.Errorf("CompareVersions(%q, %q) = %d, apk says %q", p[0], p[1], got, out)
		}
	}
}

func TestParseDependency(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Dependency
		str  string
	}{
		{"foo", Dependency{Name: "foo"}, "foo"},
		{"foo=1.0", Dependency{Name: "foo", Version: "1.0"}, "foo=1.0"},
		{"foo>=1.0", Dependency{Name: "foo", Version: "1.0", Match: MatchGreater | MatchEqual}, "foo>=1.0"},
		{"foo<=1.0-r1", Dependency{Name: "foo", Version: "1.0-r1", Match: MatchLess | MatchEqual}, "foo<=1.0-r1"},
		{"foo>1", Dependency{Name: "foo", Version: "1", Match: MatchGreater}, "foo>1"},
		{"foo<1", Dependency{Name: "foo", Version: "1", Match: MatchLess}, "foo<1"},
		{"foo~1.2", Dependency{Name: "foo", Version: "1.2", Match: MatchFuzzy | MatchEqual}, "foo~1.2"},
		{"foo>~1.2", Dependency{Name: "foo", Version: "1.2", Match: MatchGreater | MatchFuzzy | MatchEqual}, "foo>~1.2"},
		{"foo<~1.2", Dependency{Name: "foo", Version: "1.2", Match: MatchLess | MatchFuzzy | MatchEqual}, "foo<~1.2"},
		{"!foo", Dependency{Name: "foo", Match: MatchConflict | MatchEqual | MatchLess | MatchGreater}, "!foo"},
		{"!foo=1", Dependency{Name: "foo", Version: "1", Match: MatchConflict | MatchEqual}, "!foo=1"},
		{"so:libc.musl-x86_64.so.1", Dependency{Name: "so:libc.musl-x86_64.so.1"}, "so:libc.musl-x86_64.so.1"},
		{"cmd:foo=1.0-r0", Dependency{Name: "cmd:foo", Version: "1.0-r0"}, "cmd:foo=1.0-r0"},
		{"foo><1234abcd", Dependency{Name: "foo", Version: "1234abcd", Match: MatchLess | MatchGreater}, "foo><1234abcd"},
	} {
		got, err := ParseDependency(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)

			continue
		}

		if got != c.want {
			t.Errorf("%q = %+v, want %+v", c.in, got, c.want)
		}

		if got.String() != c.str {
			t.Errorf("%q formats as %q, want %q", c.in, got.String(), c.str)
		}
	}

	for _, in := range []string{"", "!", "foo>=", "=1.0", "foo>=1.0_foo", "fo o", "foo=1..0", "foo\x00", "foo>>"} {
		if _, err := ParseDependency(in); err == nil {
			t.Errorf("%q parsed", in)
		} else if !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("%q: %v is not ErrInvalidSpec", in, err)
		}
	}

	if got := (Dependency{Name: "x", Version: "1", Match: 99}).String(); got != "x?1" {
		t.Errorf("unknown match: %q", got)
	}
}

func TestMatchString(t *testing.T) {
	for m, want := range map[Match]string{
		MatchLess:                              "<",
		MatchLess | MatchEqual:                 "<=",
		MatchLess | MatchEqual | MatchFuzzy:    "<~",
		MatchEqual | MatchFuzzy:                "~",
		MatchFuzzy:                             "~",
		MatchEqual:                             "=",
		MatchGreater | MatchEqual:              ">=",
		MatchGreater | MatchEqual | MatchFuzzy: ">~",
		MatchGreater:                           ">",
		MatchLess | MatchGreater:               "><",
		MatchEqual | MatchLess | MatchGreater:  "",
		MatchConflict | MatchLess:              "<",
		MatchLess | MatchGreater | MatchFuzzy:  "?",
	} {
		if got := matchString(m); got != want {
			t.Errorf("matchString(%d) = %q, want %q", m, got, want)
		}
	}
}

func TestDependencyOrder(t *testing.T) {
	a := Dependency{Name: "a", Version: "1"}
	b := Dependency{Name: "b"}
	a2 := Dependency{Name: "a", Version: "2"}
	ge := Dependency{Name: "a", Version: "1", Match: MatchGreater | MatchEqual}

	for _, c := range []struct {
		x, y Dependency
		want int
	}{
		{a, b, -1}, {b, a, 1}, {a, a, 0}, {a, a2, -1}, {a2, a, 1}, {a, ge, -1}, {ge, a, 1},
	} {
		if got := compareDeps(c.x, c.y); got != c.want {
			t.Errorf("compareDeps(%v, %v) = %d, want %d", c.x, c.y, got, c.want)
		}
	}
}

func TestFuzzyVersionMatch(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2", 0},
		{"1.2", "1.2.3", -1},
		{"1.3", "1.2", 1},
		{"1.1", "1.2", -1},
		{"1.2-r5", "1.2", 0},
	} {
		if got := compareVersions(c.a, c.b, true); got != c.want {
			t.Errorf("fuzzy %q %q = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
