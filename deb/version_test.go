package deb_test

import (
	"errors"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.1", "1.0", 1},
		{"1.0", "1.0.0", -1},
		{"1.9", "1.10", -1},
		{"1.0010", "1.10", 0},
		{"1.01", "1.1", 0},
		{"0", "00", 0},
		{"a", "b", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1.0", "1.0+b1", -1},
		{"1.0+b1", "1.0-1", 1}, // the version part 1.0+b1 is above 1.0, whatever the revision
		{"1.0a", "1.0+", -1},
		{"1.0a", "1.0.", -1},
		{"1.0A", "1.0a", -1},
		{"1.0Z", "1.0a", -1},
		{"1.0-1", "1.0-2", -1},
		{"1.0-1", "1.0", 1},
		{"1.0-1~bpo1", "1.0-1", -1},
		{"1.0-10", "1.0-9", 1},
		{"1.0-1-1", "1.0-1-2", -1},
		{"1:1.0", "2.0", 1},
		{"0:1.0", "1.0", 0},
		{"00:1.0", "1.0", 0},
		{"1:1.0", "1:1.1", -1},
		{"2:0.1", "1:9.9", 1},
		{"1.2.3-4ubuntu1", "1.2.3-4", 1},
		{"2.30-0ubuntu3", "2.30-0ubuntu3.1", -1},
		{"9999999999999999999999", "10000000000000000000000", -1},
		{"1.0:2", "1.0:3", -1}, // not an epoch: the colon is part of the version
		{"a:1", "a:2", -1},
		{"", "", 0},
		{"", "0", -1},
		{"0", "", 1},
		{"", "~", -1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			assert.Equal(t, tt.want, deb.CompareVersions(tt.a, tt.b))
			assert.Equal(t, -tt.want, deb.CompareVersions(tt.b, tt.a))
		})
	}
}

func TestValidVersion(t *testing.T) {
	valid := []string{
		"1", "1.0", "1.0-1", "1:2.0-1", "0:1", "1.0~rc1", "1.0+dfsg-1ubuntu2", "a", "abc", "1.0.0-1-2",
		"1:1:1", "10:1.0", strings.Repeat("1", 256),
	}
	invalid := []string{
		"", ":", "1:", "1.0:2", "a:1", ":1", "1 0", "1_0", "1.0 ", "1,0", "é", "1.0\n", "1.0/2", "1\x00",
		strings.Repeat("1", 257), "-1:2", "1:2 ",
	}

	for _, v := range valid {
		assert.True(t, deb.ValidVersion(v), "%q", v)
	}

	for _, v := range invalid {
		assert.False(t, deb.ValidVersion(v), "%q", v)
	}
}

func TestStripEpoch(t *testing.T) {
	for in, want := range map[string]string{
		"1:2.0-1":   "2.0-1",
		"0:1":       "1",
		"2.0":       "2.0",
		"":          "",
		"a:1":       "a:1",
		":1":        ":1",
		"1:":        "",
		"1:2:3":     "2:3",
		"1.0-1~rc1": "1.0-1~rc1",
		"12:x":      "x",
	} {
		assert.Equal(t, want, deb.StripEpoch(in), "%q", in)
	}
}

// trickyVersions exercises every rule of deb-version(7).
func trickyVersions() []string {
	return []string{
		"0", "00", "1", "01", "1.0", "1.00", "1.0.0", "1.0~", "1.0~~", "1.0~rc1", "1.0~rc2", "1.0~~a", "1.0~a",
		"1.0a", "1.0A", "1.0+", "1.0+b1", "1.0.", "1.0-", "1.0-1", "1.0-01", "1.0-1~", "1.0-1~bpo1", "1.0-1+b1", "1.0-1a",
		"1.0-2", "1.0-10", "1.0-1-1", "1.0-1-2", "1.1", "1.10", "1.9", "2", "10", "9", "a", "A", "a1", "a~", "~", "~1",
		"1:0", "1:1.0", "0:1.0", "01:0", "2:0.1", "1:1.0-1", "1:1.0~rc1", "1.0.a", "1.0..a", "1+2", "1-2", "1.2.3+dfsg-4",
		"2.30-0ubuntu3", "2.30-0ubuntu3.1", "123456789012345678901234567890", "123456789012345678901234567891",
	}
}

func TestCompareVersionsAgainstDpkg(t *testing.T) {
	dpkg, err := exec.LookPath("dpkg")
	if err != nil {
		t.Skip("dpkg not installed")
	}

	// dpkgCmp asks dpkg for the order of a and b; ok is false when dpkg
	// rejects the syntax of one of them.
	dpkgCmp := func(a, b string) (int, bool) {
		for _, op := range []struct {
			name string
			res  int
		}{{"lt", -1}, {"eq", 0}, {"gt", 1}} {
			err := exec.Command(dpkg, "--compare-versions", a, op.name, b).Run()
			if err == nil {
				return op.res, true
			}

			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 1 {
				return 0, false
			}
		}

		return 0, false
	}

	versions := trickyVersions()

	var checked atomic.Int64

	for _, a := range versions {
		t.Run(a, func(t *testing.T) {
			t.Parallel()

			for _, b := range versions {
				want, ok := dpkgCmp(a, b)
				if !ok {
					continue // dpkg rejects the version syntax
				}

				checked.Add(1)

				if got := deb.CompareVersions(a, b); got != want {
					t.Errorf("CompareVersions(%q, %q) = %d, dpkg says %d", a, b, got, want)
				}
			}
		})
	}

	t.Cleanup(func() {
		require.Greater(t, int(checked.Load()), len(versions)*len(versions)/2, "dpkg must accept most of the versions")
	})
}

// FuzzCompareVersions checks that the ordering is a total preorder.
func FuzzCompareVersions(f *testing.F) {
	f.Add("1.0", "1.0~rc1", "1:0.5")
	f.Add("", "~", "0")
	f.Add("1.0-1", "1.0-1+b1", "1.0-1~bpo1")
	f.Add("00:1", "0:01", "1")
	f.Add("a:b:c-d-e", "::", "-")

	f.Fuzz(func(t *testing.T, a, b, c string) {
		assert.Zero(t, deb.CompareVersions(a, a))
		assert.Zero(t, deb.CompareVersions(b, b))

		ab, ba := deb.CompareVersions(a, b), deb.CompareVersions(b, a)
		assert.Equal(t, ab, -ba, "antisymmetry of %q and %q", a, b)

		bc, cb := deb.CompareVersions(b, c), deb.CompareVersions(c, b)
		assert.Equal(t, bc, -cb)

		ac := deb.CompareVersions(a, c)

		// Transitivity of <= and of ==.
		if ab <= 0 && bc <= 0 {
			assert.LessOrEqual(t, ac, 0, "%q <= %q <= %q", a, b, c)
		}

		if ab >= 0 && bc >= 0 {
			assert.GreaterOrEqual(t, ac, 0, "%q >= %q >= %q", a, b, c)
		}

		if ab == 0 && bc == 0 {
			assert.Zero(t, ac)
		}

		// Stripping the epoch leaves a version that compares like the original
		// when the epochs are both absent.
		if !strings.Contains(a, ":") && !strings.Contains(b, ":") {
			assert.Equal(t, ab, deb.CompareVersions(deb.StripEpoch(a), deb.StripEpoch(b)))
		}
	})
}
