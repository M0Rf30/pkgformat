package apk

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// replaceCase is a pair of packages that both ship the file "shared".
type replaceCase struct {
	name            string
	owner, incoming Info
}

func replaceCases() []replaceCase {
	base := func(name, origin string) Info {
		return Info{Name: name, Version: "2-r0", Arch: "noarch", Origin: origin}
	}

	with := func(i Info, replaces []string, prio int) Info {
		i.Replaces, i.ReplacesPriority = replaces, prio

		return i
	}

	return []replaceCase{
		{"plain", base("own", "own"), base("inc", "inc")},
		{"incoming-replaces", base("own", "own"), with(base("inc", "inc"), []string{"own"}, 0)},
		{"owner-replaces", with(base("own", "own"), []string{"inc"}, 0), base("inc", "inc")},
		{"priority-owner", with(base("own", "own"), []string{"inc"}, 5), with(base("inc", "inc"), []string{"own"}, 1)},
		{"priority-incoming", with(base("own", "own"), []string{"inc"}, 1), with(base("inc", "inc"), []string{"own"}, 5)},
		{"same-origin", base("own", "src"), base("inc", "src")},
		{"version-mismatch", base("own", "own"), with(base("inc", "inc"), []string{"own<2"}, 0)},
		{"version-match", base("own", "own"), with(base("inc", "inc"), []string{"own>=2"}, 0)},
		{"provides-only", base("own", "own"), with(base("inc", "inc"), []string{"virt"}, 0)},
	}
}

func replaceSpec(info Info, content string) *Spec {
	return &Spec{Info: info, Files: []File{MemFile("shared", 0o644, []byte(content))}}
}

// TestReplacesFile compares ReplacesFile with what apk does when the
// "incoming" package is added to a system with the "owner" installed
// (testdata/replaces/generate.sh): the file is the incoming package's, the
// owner's, or apk refuses.
func TestReplacesFile(t *testing.T) {
	dir := filepath.Join("testdata", "replaces")

	if os.Getenv("PKGFORMAT_UPDATE") != "" {
		for _, c := range replaceCases() {
			for role, spec := range map[string]*Spec{
				"owner":    replaceSpec(c.owner, "owner"),
				"incoming": replaceSpec(c.incoming, "incoming"),
			} {
				var buf bytes.Buffer
				if _, err := WritePackage(&buf, spec, WriteOptions{}); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(filepath.Join(dir, c.name+"-"+role+".apk"), buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}

		t.Skip("fixtures rewritten; run generate.sh for the expected file")
	}

	golden, err := os.ReadFile(filepath.Join(dir, "expected"))
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{}

	for _, line := range strings.Split(strings.TrimSpace(string(golden)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			t.Fatalf("bad line %q", line)
		}

		want[f[0]] = f[1]
	}

	for _, c := range replaceCases() {
		t.Run(c.name, func(t *testing.T) {
			owner := Package{Name: c.owner.Name, Version: c.owner.Version, Origin: c.owner.Origin, Replaces: c.owner.Replaces, ReplacesPriority: c.owner.ReplacesPriority}
			incoming := Package{Name: c.incoming.Name, Version: c.incoming.Version, Origin: c.incoming.Origin, Replaces: c.incoming.Replaces, ReplacesPriority: c.incoming.ReplacesPriority}

			if got := ReplacesFile(&owner, &incoming).String(); got != want[c.name] {
				t.Fatalf("got %s, apk %s", got, want[c.name])
			}
		})
	}
}

func TestReplacesFile_special(t *testing.T) {
	p := &Package{Name: "a", Version: "1"}

	if ReplacesFile(nil, p) != ReplaceYes || ReplacesFile(p, nil) != ReplaceNo || ReplacesFile(p, &Package{Name: "a", Version: "2"}) != ReplaceYes {
		t.Fatal("overlay, absent and same-name rules")
	}

	if Replacement(0).String() != "unknown" {
		t.Fatal("zero value")
	}

	b := &Package{Name: "b", Version: "1", Replaces: []string{"!zzz", "bad dep", "a=1"}}
	if ReplacesFile(p, b) != ReplaceYes {
		t.Fatal("a conflict entry and an equal version")
	}

	c := &Package{Name: "c", Version: "1", Checksum: "Q1x", Replaces: []string{"a><Q1x"}}
	d := &Package{Name: "a", Checksum: "Q1x"}

	if !replacesPackage(c, d) {
		t.Fatal("checksum replaces")
	}
}
