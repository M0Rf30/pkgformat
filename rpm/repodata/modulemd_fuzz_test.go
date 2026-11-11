package repodata

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func addModulemdSeeds(f *testing.F) {
	f.Helper()

	files, err := filepath.Glob(filepath.Join("testdata", "modules", "*.yaml"))
	if err != nil {
		f.Fatal(err)
	}

	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}

		f.Add(data)
	}

	f.Add([]byte("---\ndocument: modulemd\nversion: 2\ndata:\n  name: n\n"))
	f.Add([]byte("---\ndocument: modulemd-defaults\nversion: 1\ndata:\n  module: m\n  profiles: {a: [b]}\n...\n---\n"))
	f.Add([]byte("---\n&a x: *a\n"))
	f.Add([]byte(""))
}

var fuzzModulemdLimits = ModulemdLimits{MaxBytes: 1 << 20, MaxDocumentBytes: 1 << 18, MaxEntries: 1 << 12, MaxDepth: 16}

func FuzzReadModulemd(f *testing.F) {
	addModulemdSeeds(f)

	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = ReadModulemd(bytes.NewReader(data), fuzzModulemdLimits, func(ModuleDocument) error { return nil })
	})
}

// Whatever the reader accepts the writer writes, and what it wrote reads back
// to a document that writes the same bytes.
func FuzzModulemdWriteRoundTrip(f *testing.F) {
	addModulemdSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		set, err := ParseModulemd(bytes.NewReader(data), fuzzModulemdLimits)
		if err != nil {
			return
		}

		var first bytes.Buffer
		if err := WriteModules(&first, set); err != nil {
			t.Fatalf("the writer refuses what the reader accepts: %v", err)
		}

		again, err := ParseModulemd(bytes.NewReader(first.Bytes()), fuzzModulemdLimits)
		if err != nil {
			t.Fatalf("reading back: %v\n%s", err, first.Bytes())
		}

		var second bytes.Buffer
		if err := WriteModules(&second, again); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(first.Bytes(), second.Bytes()) {
			t.Fatalf("not stable:\n%s\n---\n%s", first.Bytes(), second.Bytes())
		}
	})
}

// Any text survives being written as a value and as a key: the layout rules
// copied from libyaml (quoting, folding, escapes) never produce a document
// that reads back differently.
func FuzzModulemdText(f *testing.F) {
	for _, s := range []string{"", "plain", " x", "x ", "a: b", "line\nbreak", "1.0", "日本", "\x00", "\u0085", strings.Repeat("word ", 50), " " + strings.Repeat("0", 76) + " "} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, text string) {
		s := validStream()
		s.Summary = "s" + text
		s.Description = text + "d"
		s.Context = text
		s.Profiles = map[string]ModuleProfile{text + "p": {Description: text, RPMs: []string{text + "r"}}}
		s.XMD = map[string]any{text + "k": []any{text + "v"}}
		set := &ModuleSet{Streams: []*ModuleStream{s}}

		var buf bytes.Buffer
		if err := WriteModules(&buf, set); err != nil {
			return // not UTF-8
		}

		got, err := ParseModulemd(bytes.NewReader(buf.Bytes()), ModulemdLimits{})
		if err != nil {
			t.Fatalf("%q: %v\n%s", text, err, buf.Bytes())
		}

		if !reflect.DeepEqual(got, set) {
			t.Fatalf("%q read back as %+v", text, got.Streams[0])
		}
	})
}
