package apt

import (
	"strings"
	"testing"
)

func FuzzParseMirrorList(f *testing.F) {
	f.Add([]byte("# c\nhttp://a/\nhttps://b/x\tpriority:2\nfile:///m/\n"))
	f.Add([]byte("ftp://z/\n\n\x00\xff"))

	f.Fuzz(func(t *testing.T, data []byte) {
		seen := map[string]bool{}

		for _, m := range parseMirrorList(data) {
			if !strings.HasSuffix(m, "/") {
				t.Fatalf("mirror %q has no trailing slash", m)
			}

			if seen[m] {
				t.Fatalf("mirror %q listed twice", m)
			}

			seen[m] = true
		}
	})
}

func FuzzLocalPath(f *testing.F) {
	f.Add("file:///a/b")
	f.Add("copy://localhost/%2e%2e/x")
	f.Add("file:relative")

	f.Fuzz(func(t *testing.T, raw string) {
		if p, ok := localPath(raw); ok && !strings.HasPrefix(p, "/") {
			t.Fatalf("localPath(%q) = %q, not absolute", raw, p)
		}
	})
}
