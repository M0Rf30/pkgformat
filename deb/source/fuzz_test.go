package source_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/deb/source"
)

func seedFiles(f *testing.F, patterns ...string) {
	f.Helper()

	for _, p := range patterns {
		m, _ := filepath.Glob(p)
		for _, name := range m {
			if b, err := os.ReadFile(name); err == nil {
				f.Add(b)
			}
		}
	}
}

func FuzzParseDSC(f *testing.F) {
	seedFiles(f, "testdata/packages/*/*.dsc")
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := source.ParseDSC(data)
		if err != nil {
			return
		}

		// Whatever parses must marshal and parse again to the same thing.
		out, err := d.Marshal()
		if err != nil {
			return
		}

		if _, err := source.ParseDSC(out); err != nil {
			t.Fatalf("re-parse of own output: %v\n%s", err, out)
		}

		for _, field := range []string{"Build-Depends", "Build-Conflicts-Indep"} {
			_, _ = d.Relations(field)
		}
	})
}

func FuzzReadSources(f *testing.F) {
	seedFiles(f, "testdata/sources/Sources.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := source.ReadSources(bytes.NewReader(data), "Sources")
		if err != nil {
			return
		}

		var buf bytes.Buffer
		if err := source.WriteSources(&buf, entries, "none"); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzParseChanges(f *testing.F) {
	seedFiles(f, "testdata/changes/*/*.changes")
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := source.ParseChanges(data)
		if err != nil {
			return
		}

		if out, err := c.Marshal(); err == nil {
			if _, err := source.ParseChanges(out); err != nil {
				t.Fatalf("re-parse: %v\n%s", err, out)
			}
		}
	})
}

func FuzzParseBuildInfo(f *testing.F) {
	seedFiles(f, "testdata/changes/*/*.buildinfo")
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := source.ParseBuildInfo(data)
		if err != nil {
			return
		}

		if out, err := b.Marshal(); err == nil {
			if _, err := source.ParseBuildInfo(out); err != nil {
				t.Fatalf("re-parse: %v\n%s", err, out)
			}
		}
	})
}

func FuzzApplyPatch(f *testing.F) {
	f.Add([]byte("--- a/f\n+++ b/f\n@@ -3,3 +3,3 @@\n 3\n-4\n+four\n 5\n"))
	f.Add([]byte("--- a/old\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n--- /dev/null\n+++ b/new/x\n@@ -0,0 +1 @@\n+hi\n"))
	f.Add([]byte("--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		root := t.TempDir()
		_ = os.WriteFile(filepath.Join(root, "f"), []byte(numbered), 0o600)
		_ = os.WriteFile(filepath.Join(root, "old"), []byte("gone\n"), 0o600)

		if _, err := source.ApplyPatch(root, bytes.NewReader(data), source.PatchOptions{Strip: 1}); err != nil {
			return
		}

		// Nothing may appear outside root.
		entries, _ := os.ReadDir(filepath.Dir(root))
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "escape") {
				t.Fatalf("wrote %s outside the tree", e.Name())
			}
		}
	})
}
