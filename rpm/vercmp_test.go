package rpm

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestVercmp(t *testing.T) {
	// from rpm/tests/rpmvercmp.at
	var values = [][]string{
		{"1.0", "2.0"},
		{"2.0", "2.0.1"},
		{"2.0.1", "2.0.1a"},
		{"5.5p1", "5.5p2"},
		{"5.5p1", "5.5p10"},
		{"10xyz", "10.1xyz"},
		{"xyz10", "xyz10.1"},
		{"xyz.4", "8"},
		{"xyz.4", "2"},
		{"5.5p2", "5.6p1"},
		{"5.6p1", "6.5p1"},
		{"6.0", "6.0.rc1"},
		{"10a2", "10b2"},
		{"1.0a", "1.0aa"},
		{"10.0001", "10.0039"},
		{"4.999.9", "5.0"},
		{"20101121", "20101122"},
		{"1.0~rc1", "1.0"},
		{"1.0~rc1", "1.0~rc2"},
		{"1.0~rc1~git123", "1.0~rc1"},
		{"1.0", "1.0^"},
		{"1.0", "1.0^git1"},
		{"1.0^git1", "1.0^git2"},
		{"1.0^git1", "1.01"},
		{"1.0^20160101", "1.0.1"},
		{"1.0^git1", "1.0a"},
		{"2^a", "2.a"},
		{"1.0^20160101^git1", "1.0^20160102"},
		{"1.0~rc1", "1.0~rc1^git1"},
		{"1.0^git1~pre", "1.0^git1"},
	}
	for _, v := range values {
		assert.Equal(t, -1, Vercmp(v[0], v[1]), "expected: %s should be less than %s", v[0], v[1])
		assert.Equal(t, 1, Vercmp(v[1], v[0]), "expected: %s should be greater than %s", v[1], v[0])
	}
}

// TestVercmpEquivalence covers what the table above does not: equality, the
// end of a version, and characters that are not part of any segment.
func TestVercmpEquivalence(t *testing.T) {
	for _, v := range [][2]string{
		{"1.0", "1.0"}, {"", ""}, {"1_0", "1.0"}, {"1.0", "1..0"}, {"01", "1"}, {"1.0^", "1.0^"},
		{"1.0~", "1.0~"}, {"1.0\n", "1.0"}, {"1\x00x", "1"},
	} {
		assert.Equal(t, 0, Vercmp(v[0], v[1]), "%q %q", v[0], v[1])
		assert.Equal(t, 0, Vercmp(v[1], v[0]), "%q %q", v[1], v[0])
	}
	for _, v := range [][2]string{ // first < second
		{"", "1"}, {"", "a"}, {"~", ""}, {"", "^"}, {"~", "^"}, {"1.0", "1.0 a"}, {"a", "1"},
		{"1.0^", "1.0^1"}, {"1.0^1", "1.0.1"}, {"1.0~", "1.0~^"},
	} {
		assert.Equal(t, -1, Vercmp(v[0], v[1]), "%q %q", v[0], v[1])
		assert.Equal(t, 1, Vercmp(v[1], v[0]), "%q %q", v[1], v[0])
	}
}

// TestVercmpMatchesRpm compares Vercmp with librpm on the pairs of
// testdata/vercmp/golden.jsonl (see generate.sh there; librpm is not needed to
// run this test).
func TestVercmpMatchesRpm(t *testing.T) {
	f, err := os.Open("testdata/vercmp/golden.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var n, withCaret int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var pair [3]any
		if err := json.Unmarshal(sc.Bytes(), &pair); err != nil {
			t.Fatalf("golden line %d: %v", n+1, err)
		}
		a, _ := pair[0].(string)
		b, _ := pair[1].(string)
		want, _ := pair[2].(float64)
		n++
		if strings.Contains(a+b, "^") {
			withCaret++
		}
		if got := Vercmp(a, b); got != int(want) {
			t.Errorf("Vercmp(%q, %q) = %d, librpm says %d", a, b, got, int(want))
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 3000 || withCaret < 500 {
		t.Fatalf("golden file has %d pairs, %d with a caret: too few", n, withCaret)
	}
}

// FuzzVercmp checks that Vercmp is reflexive and antisymmetric, and returns
// one of -1, 0, 1.
func FuzzVercmp(f *testing.F) {
	for _, s := range []string{"1.0", "1.0~rc1", "2.0.0^git1", "a.b.c", "", "1..2", "01", "~", "^", "1.0\n2", "1a", "a1", "~~a", "1.0-é", "1\x00"} {
		f.Add(s, "1.0")
		f.Add("1.0", s)
		f.Add(s, s+"^x")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if Vercmp(a, a) != 0 || Vercmp(b, b) != 0 {
			t.Fatalf("Vercmp is not reflexive for %q or %q", a, b)
		}
		ab, ba := Vercmp(a, b), Vercmp(b, a)
		if ab < -1 || ab > 1 || ab != -ba {
			t.Fatalf("Vercmp(%q, %q) = %d but Vercmp(%q, %q) = %d", a, b, ab, b, a, ba)
		}
	})
}

// TestVercmpLinear checks that the cost of Vercmp grows linearly with the
// input. It compares two sizes measured in the same process, taking the best of
// several runs of each, so that the verdict does not depend on how busy the
// machine is: a linear implementation scales by about 4x for a 4x larger input,
// a quadratic one by about 16x.
func TestVercmpLinear(t *testing.T) {
	best := func(reps int) time.Duration {
		a := strings.Repeat("1.", reps)
		b := a + "1"
		fastest := time.Duration(1<<63 - 1)

		for range 5 {
			start := time.Now()
			got := Vercmp(a, b)
			elapsed := time.Since(start)

			if got != -1 {
				t.Fatalf("Vercmp = %d, want -1", got)
			}

			fastest = min(fastest, elapsed)
		}

		return fastest
	}

	small, large := best(100_000), best(400_000)

	if ratio := float64(large) / float64(max(small, 1)); ratio > 8 {
		t.Fatalf("Vercmp is not linear: 4x the input took %.1fx the time (%v -> %v)", ratio, small, large)
	}
}
