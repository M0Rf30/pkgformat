package rpm

import (
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
		// {"1.0", "1.0^"},
		{"1.0", "1.0^git1"},
		{"1.0^git1", "1.0^git2"},
		{"1.0^git1", "1.01"},
		// {"1.0^20160101", "1.0.1"},
		{"1.0^20160101^git1", "1.0^20160102"},
		{"1.0~rc1", "1.0~rc1^git1"},
		{"1.0^git1~pre", "1.0^git1"},
	}
	for _, v := range values {
		assert.Equal(t, -1, Vercmp(v[0], v[1]), "expected: %s should be less than %s", v[0], v[1])
		assert.Equal(t, 1, Vercmp(v[1], v[0]), "expected: %s should be greater than %s", v[1], v[0])
	}
}

// vercmpRegexp is the original regexp based implementation, kept as a
// reference for differential testing.
func vercmpRegexp(first, second string) int {
	var m1Head, m2Head string
	for first != "" || second != "" {
		m1 := R_NONALNUMTILDE.FindStringSubmatch(first)
		m2 := R_NONALNUMTILDE.FindStringSubmatch(second)
		// This probably needs to return something different.
		if m1 == nil || m2 == nil {
			return 0
		}

		m1Head, first = m1[1], m1[2]
		m2Head, second = m2[1], m2[2]

		// Ignore junk at beginning of version.
		if m1Head != "" || m2Head != "" {
			continue
		}

		// Hnalde the tolde seporator, it sorts before everything else.
		if strings.HasPrefix(first, "~") {
			if !strings.HasPrefix(second, "~") {
				return -1
			}
			first, second = first[1:], second[1:]
			continue
		}
		if strings.HasPrefix(second, "~") {
			return 1
		}

		// If we ran to the end of either, we are finished with the loop.
		if first == "" || second == "" {
			break
		}

		// Grab the first completely alpha or completely numeric segment.
		isnum := false
		m1 = R_NUM.FindStringSubmatch(first)
		m2 = R_NUM.FindStringSubmatch(second)
		if R_NUM.MatchString(first) {
			if !R_NUM.MatchString(second) {
				// numeric segments are always newer than alpha segments.
				return 1
			}
			isnum = true
		} else {
			m1 = R_ALPHA.FindStringSubmatch(first)
			m2 = R_ALPHA.FindStringSubmatch(second)
		}

		if len(m1) == 0 {
			// This condition should not be reached since we previously
			// tested to make sure that the first string has a non-nill
			// segment.
			return -1
		}
		if len(m2) == 0 {
			if isnum {
				return 1
			}
			return -1
		}

		m1Head, first = m1[1], m1[2]
		m2Head, second = m2[1], m2[2]

		if isnum {
			// Throw away any leading zeros.
			m1Head = strings.TrimLeft(m1Head, "0")
			m2Head = strings.TrimLeft(m2Head, "0")

			// Whichever number has more digits wins
			m1Hlen := len(m1Head)
			m2Hlen := len(m2Head)
			if m1Hlen < m2Hlen {
				return -1
			}
			if m1Hlen > m2Hlen {
				return 1
			}
		}

		// Same number of chars
		if m1Head < m2Head {
			return -1
		} else if m1Head > m2Head {
			return 1
		}

		// Both segments equal
		continue
	}

	m1Hlen := len(first)
	m2Hlen := len(second)
	if m1Hlen == 0 && m2Hlen == 0 {
		return 0
	}
	if m1Hlen != 0 {
		return 1
	}
	return -1
}

func FuzzVercmpMatchesReference(f *testing.F) {
	for _, s := range []string{"1.0", "1.0~rc1", "2.0.0^git1", "a.b.c", "", "1..2", "01", "~", "1.0\n2", "\n1", "1a", "a1", "~~a", "1.0-é"} {
		f.Add(s, "1.0")
		f.Add("1.0", s)
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if got, want := Vercmp(a, b), vercmpRegexp(a, b); got != want {
			t.Fatalf("Vercmp(%q, %q) = %d, reference says %d", a, b, got, want)
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
