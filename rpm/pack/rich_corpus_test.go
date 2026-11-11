package pack

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// TestRichDepsMatchRpm checks ValidateRich against the verdicts of the spec parser
// of rpm on a corpus of boolean dependencies (testdata/interop/corpus-gen.sh).
func TestRichDepsMatchRpm(t *testing.T) {
	f, err := os.Open("testdata/interop/richdeps.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		verdict, expr, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			t.Fatalf("bad corpus line %q", sc.Text())
		}
		n++
		err := validateRich(expr, richAnd)
		if (err == nil) != (verdict == "ok") {
			t.Errorf("%q: rpm says %s, ValidateRich returned %v", expr, verdict, err)
		}
	}
	if n < 50 {
		t.Errorf("only %d corpus entries", n)
	}
}
