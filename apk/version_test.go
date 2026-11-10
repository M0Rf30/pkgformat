package apk

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompareVersionsGolden checks CompareVersions against what apk-tools'
// "apk version -t" printed for every pair of testdata/version/pairs.golden.
func TestCompareVersionsGolden(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "version", "pairs.golden"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	want := map[string]int{"<": -1, "=": 0, ">": 1}
	n := 0

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 3 {
			t.Fatalf("bad golden line %q", sc.Text())
		}

		a, op, b := fields[0], fields[1], fields[2]
		n++

		if got := CompareVersions(a, b); got != want[op] {
			t.Errorf("CompareVersions(%q, %q) = %d, apk says %q", a, b, got, op)
		}

		// The order is antisymmetric.
		if got := CompareVersions(b, a); got != -want[op] {
			t.Errorf("CompareVersions(%q, %q) = %d, apk says %q the other way", b, a, got, op)
		}
	}

	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	if n < 3000 {
		t.Fatalf("only %d golden pairs", n)
	}
}

// TestValidVersionGolden checks ValidVersion against "apk version -c".
func TestValidVersionGolden(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "version", "valid.golden"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		kind, v, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			t.Fatalf("bad golden line %q", sc.Text())
		}

		if got := ValidVersion(v); got != (kind == "V") {
			t.Errorf("ValidVersion(%q) = %v, apk says %s", v, got, kind)
		}
	}
}
