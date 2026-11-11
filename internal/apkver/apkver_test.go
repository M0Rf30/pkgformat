package apkver

import (
	"errors"
	"testing"
)

func TestOpString(t *testing.T) {
	for m, want := range map[Op]string{
		Any:                      "",
		Less:                     "<",
		Less | Equal:             "<=",
		Less | Equal | Fuzzy:     "<~",
		Equal | Fuzzy:            "~",
		Fuzzy:                    "~",
		Equal:                    "=",
		Greater | Equal:          ">=",
		Greater | Equal | Fuzzy:  ">~",
		Greater:                  ">",
		Checksum:                 "><",
		Equal | Less | Greater:   "",
		Conflict | Less:          "<",
		Less | Greater | Fuzzy:   "?",
		Conflict | Equal | Fuzzy: "~",
	} {
		if got := m.String(); got != want {
			t.Errorf("Op(%d).String() = %q, want %q", m, got, want)
		}
	}
}

func TestParseOp(t *testing.T) {
	for in, want := range map[string]Op{
		"": Any, "=": Equal, "<": Less, ">": Greater, "~": Fuzzy | Equal, ">=": Greater | Equal,
		"<>": Checksum, "<~": Less | Fuzzy | Equal, "x": Any,
	} {
		if got := ParseOp(in); got != want {
			t.Errorf("ParseOp(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestSatisfied(t *testing.T) {
	for _, c := range []struct {
		op         Op
		have, want string
		ok         bool
	}{
		{Any, "1", "2", true},
		{Equal, "", "2", true},
		{Equal, "2", "2", true},
		{Equal, "1", "2", false},
		{Less, "1", "2", true},
		{Less, "2", "2", false},
		{Less | Equal, "2", "2", true},
		{Greater, "3", "2", true},
		{Greater | Equal, "1", "2", false},
		{Fuzzy | Equal, "1.2.9-r3", "1.2", true},
		{Fuzzy | Equal, "1.3", "1.2", false},
		{Checksum, "Q1abc", "Q1abc", true},
		{Checksum, "Q1abc", "Q1abd", false},
		{Conflict | Less, "1", "2", true},
	} {
		if got := c.op.Satisfied(c.have, c.want); got != c.ok {
			t.Errorf("%v.Satisfied(%q, %q) = %v, want %v", c.op, c.have, c.want, got, c.ok)
		}
	}
}

func TestSplit(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Spec
		err  error
	}{
		{in: "foo", want: Spec{Name: "foo"}},
		{in: "!foo", want: Spec{Name: "foo", Conflict: true}},
		{in: "foo@edge", want: Spec{Name: "foo@edge"}},
		{in: "foo=1.2", want: Spec{Name: "foo", Op: Equal, Version: "1.2"}},
		{in: "!foo>=1.2-r1", want: Spec{Name: "foo", Conflict: true, Op: Greater | Equal, Version: "1.2-r1"}},
		{in: "foo~1.2", want: Spec{Name: "foo", Op: Fuzzy | Equal, Version: "1.2"}},
		{in: "foo><Q1xyz", want: Spec{Name: "foo", Op: Checksum, Version: "Q1xyz"}},
		{in: "foo<>=1.0", want: Spec{Name: "foo"}},
		{in: "foo<>=nonsense", want: Spec{Name: "foo"}},
		{in: "=1", want: Spec{Op: Equal, Version: "1"}},
		{in: "foo>=", err: ErrNoVersion},
		{in: "foo<", err: ErrNoVersion},
		{in: "foo=1.", err: ErrBadVersion},
		{in: "foo>1.0-1", err: ErrBadVersion},
	} {
		got, err := Split(c.in)
		if !errors.Is(err, c.err) {
			t.Errorf("Split(%q) error %v, want %v", c.in, err, c.err)

			continue
		}

		if got != c.want {
			t.Errorf("Split(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestValid(t *testing.T) {
	for _, v := range []string{"1", "1.2.3-r0", "2.0_rc1", "20240101_git~1a2b3c-r2", "1.0a_p3", "1.2.3b_rc2_p4~9fceb02-r5"} {
		if !Valid(v) {
			t.Errorf("%q is invalid", v)
		}
	}

	for _, v := range []string{"", "1.", ".1", "1.0-1", "1.0_foo", "a", "1..2", "1.0~", "1.0-r", "99999999999999999999", "1.0-r1_p1"} {
		if Valid(v) {
			t.Errorf("%q is valid", v)
		}
	}
}

var order = []struct {
	a, b string
	want int
}{
	{"1.0", "1.0", 0},
	{"1.0", "1.0.1", -1},
	{"1.0", "1.0a", -1},
	{"1.0_rc1", "1.0", -1},
	{"1.0_p1", "1.0", 1},
	{"1.0_alpha", "1.0_beta", -1},
	{"1.0_rc1", "1.0_rc2", -1},
	{"1.9", "1.10", -1},
	{"1.01", "1.1", -1},
	{"1.0", "1.0-r1", -1},
	{"1.0-r2", "1.0-r10", -1},
	{"1.0~abc", "1.0~abd", -1},
	{"1.0_git20200101", "1.0_git20190101", 1},
}

func TestCompare(t *testing.T) {
	for _, c := range order {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}

		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareFuzzy(t *testing.T) {
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
		if got := CompareFuzzy(c.a, c.b); got != c.want {
			t.Errorf("CompareFuzzy(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// FuzzCompare: the order is a total order on valid versions.
func FuzzCompare(f *testing.F) {
	for _, p := range order {
		f.Add(p.a, p.b, "1.0")
	}

	f.Fuzz(func(t *testing.T, a, b, c string) {
		if !Valid(a) || !Valid(b) || !Valid(c) {
			return
		}

		if Compare(a, a) != 0 {
			t.Fatalf("%q != itself", a)
		}

		ab, ba := Compare(a, b), Compare(b, a)
		if ab != -ba {
			t.Fatalf("%q vs %q: %d and %d", a, b, ab, ba)
		}

		if ab <= 0 && Compare(b, c) <= 0 && Compare(a, c) > 0 {
			t.Fatalf("not transitive: %q <= %q <= %q", a, b, c)
		}

		if CompareFuzzy(a, a) != 0 {
			t.Fatalf("%q is not fuzzily itself", a)
		}
	})
}

// FuzzSplit: whatever Split accepts has a valid version unless it has none
// or is a checksum, and never panics.
func FuzzSplit(f *testing.F) {
	for _, s := range []string{"foo", "!foo", "foo>=1.0", "foo~1.2", "foo><abc123", "so:libc.so.6", "a=1_rc2-r3", "x<", "", "!", ">="} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		sp, err := Split(s)
		if err != nil {
			return
		}

		if sp.Op != Any && sp.Op != Checksum && !Valid(sp.Version) {
			t.Fatalf("%q: invalid version %q accepted", s, sp.Version)
		}

		if sp.Op == Any && sp.Version != "" {
			t.Fatalf("%q: version %q without an operator", s, sp.Version)
		}
	})
}
