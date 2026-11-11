package repodata

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The interop tests run real tools on what WriteModules writes and skip when
// a tool is missing: the fixtures keep the proof that libmodulemd reads and
// writes the same layout valid offline (see TestWriteModulesMatchesLibmodulemd).

const s3toolsImage = "localhost/s3tools:latest"

func requireTool(t *testing.T, names ...string) {
	t.Helper()

	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is not installed", name)
		}
	}
}

func runTool(t *testing.T, dir, name string, args ...string) string {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}

	return string(out)
}

// modulemd-validator, libmodulemd's own checker, accepts every document kind
// as written here, and the documents written from the validator's own
// examples.
func TestModulemdValidator(t *testing.T) {
	requireTool(t, "modulemd-validator")

	for _, f := range moduleFixtures(t) {
		t.Run(filepath.Base(f), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "modules.yaml")
			if err := os.WriteFile(out, []byte(writeModules(t, parseModulesFile(t, filepath.Base(f)))), 0o600); err != nil {
				t.Fatal(err)
			}

			runTool(t, "", "modulemd-validator", out)
		})
	}
}

// And it rejects what the writer refuses to write, so the checks here are the
// validator's.
func TestModulemdValidatorAgreesOnRejects(t *testing.T) {
	requireTool(t, "modulemd-validator")

	// A stream without a summary, a component with both buildorder and
	// buildafter, and an rpm-map entry without a version.
	const head = "---\ndocument: modulemd\nversion: 2\ndata:\n  name: n\n  stream: s\n  summary: s\n  description: d\n  license:\n    module: [MIT]\n"

	for name, text := range map[string]string{
		"summary":    "---\ndocument: modulemd\nversion: 2\ndata:\n  name: n\n  stream: s\n  description: d\n  license:\n    module: [MIT]\n...\n",
		"order":      head + "  components:\n    rpms:\n      a: {buildorder: 1, buildafter: [b]}\n...\n",
		"rpm-map":    head + "  artifacts:\n    rpm-map:\n      sha256:\n        ab:\n          name: n\n...\n",
		"no license": "---\ndocument: modulemd\nversion: 2\ndata:\n  name: n\n  stream: s\n  summary: s\n  description: d\n...\n",
	} {
		path := filepath.Join(t.TempDir(), name+".yaml")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := exec.Command("modulemd-validator", path).Run(); err == nil {
			t.Errorf("%s: the validator accepted the document", name)
		}

		if _, err := ParseModulemd(strings.NewReader(text), ModulemdLimits{}); err == nil {
			t.Errorf("%s: ParseModulemd accepted the document", name)
		}
	}
}

// modifyrepo_c registers the file as the "modules" metadata of a repository
// built by createrepo_c, and what it stores reads back to the same documents.
func TestModifyrepoAcceptsModules(t *testing.T) {
	requireTool(t, "createrepo_c", "modifyrepo_c")

	for _, name := range []string{"rocky9-appstream.yaml", "rocky8-appstream.yaml"} {
		t.Run(name, func(t *testing.T) {
			repo := newModulesRepoWithModifyrepo(t, name)

			f, err := os.Open(filepath.Join(repo, "repodata", "repomd.xml"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			repomd, err := ParseRepomd(f)
			if err != nil {
				t.Fatal(err)
			}

			entry, ok := repomd.Find("modules")
			if !ok {
				t.Fatal("repomd.xml has no modules entry")
			}

			rc, err := os.Open(filepath.Join(repo, entry.Location))
			if err != nil {
				t.Fatal(err)
			}

			open, err := OpenMetadata(rc, entry.Location, 1<<30)
			if err != nil {
				t.Fatal(err)
			}
			defer open.Close()

			got, err := ParseModulemd(open, ModulemdLimits{})
			if err != nil {
				t.Fatalf("reading what modifyrepo_c stored: %v", err)
			}

			want := parseModulesFile(t, name)
			if !reflect.DeepEqual(canonicalModules(got), canonicalModules(parseModules(t, writeModules(t, want)))) {
				t.Error("the stored modules.yaml differs from the one written")
			}
		})
	}
}

// newModulesRepoWithModifyrepo builds an empty repository with createrepo_c and
// adds the written modules.yaml with modifyrepo_c.
func newModulesRepoWithModifyrepo(t *testing.T, fixture string) string {
	t.Helper()

	repo := t.TempDir()
	runTool(t, "", "createrepo_c", "--no-database", repo)

	modules := filepath.Join(t.TempDir(), "modules.yaml")
	if err := os.WriteFile(modules, []byte(writeModules(t, parseModulesFile(t, fixture))), 0o600); err != nil {
		t.Fatal(err)
	}

	runTool(t, "", "modifyrepo_c", "--mdtype", "modules", modules, filepath.Join(repo, "repodata"))

	return repo
}

// newModulesRepoWithGo builds the same repository with this package alone:
// the modules.yaml is written and compressed here and added to the repomd.xml
// createrepo_c wrote for the empty repository.
func newModulesRepoWithGo(t *testing.T, fixture string) string {
	t.Helper()

	repo := t.TempDir()
	runTool(t, "", "createrepo_c", "--no-database", repo)

	meta, err := CompressMetadataStream(Zstd, func(w io.Writer) error {
		return WriteModules(w, parseModulesFile(t, fixture))
	})
	if err != nil {
		t.Fatal(err)
	}

	name := meta.SHA256 + "-modules.yaml" + Zstd.Extension()
	if err := os.WriteFile(filepath.Join(repo, "repodata", name), meta.Data, 0o600); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(repo, "repodata", "repomd.xml")

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	repomd, err := ParseRepomd(f)
	_ = f.Close()

	if err != nil {
		t.Fatal(err)
	}

	repomd.Data = append(repomd.Data, meta.Entry("modules", name, 1))

	out, err := repomd.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	return repo
}

// dnf lists the modules of a repository whose modules.yaml was written here,
// the same whether modifyrepo_c or this package registered it.
func TestDNFListsModules(t *testing.T) {
	requireTool(t, "createrepo_c", "modifyrepo_c", "podman")

	if err := exec.Command("podman", "image", "exists", s3toolsImage).Run(); err != nil {
		t.Skipf("the image %s is not available", s3toolsImage)
	}

	for _, fixture := range []string{"rocky9-appstream.yaml", "rocky8-appstream.yaml"} {
		t.Run(fixture, func(t *testing.T) {
			set := parseModulesFile(t, fixture)

			byModifyrepo := newModulesRepoWithModifyrepo(t, fixture)
			byGo := newModulesRepoWithGo(t, fixture)

			var lists [2]string

			for i, repo := range []string{byModifyrepo, byGo} {
				lists[i] = dnfModuleList(t, repo)
			}

			if lists[0] != lists[1] {
				t.Errorf("dnf lists different modules:\nmodifyrepo_c:\n%s\nthis package:\n%s", lists[0], lists[1])
			}

			seen := make(map[string]bool)

			for _, s := range set.Streams {
				key := s.Name + " " + s.Stream
				if seen[key] {
					continue
				}

				seen[key] = true

				if !hasModuleLine(lists[1], s.Name, s.Stream) {
					t.Errorf("dnf does not list %s:%s:\n%s", s.Name, s.Stream, lists[1])
				}
			}

			for _, d := range set.Defaults {
				if d.Stream == "" {
					continue
				}

				if !strings.Contains(lists[1], d.Module) {
					t.Errorf("dnf does not list the module %s", d.Module)
				}
			}
		})
	}
}

func hasModuleLine(list, name, stream string) bool {
	for line := range strings.SplitSeq(list, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == name && f[1] == stream {
			return true
		}
	}

	return false
}

// dnfModuleList runs "dnf module list" against a repository, in the image,
// without a network.
func dnfModuleList(t *testing.T, repo string) string {
	t.Helper()

	script := `dnf5 --disablerepo='*' --repofrompath=t,file:///repo --setopt=t.gpgcheck=0 --setopt=t.repo_gpgcheck=0 module list`

	cmd := exec.Command("podman", "run", "--rm", "--network", "none", "-v", repo+":/repo:ro", "--entrypoint", "sh", s3toolsImage, "-c", script)

	var stdout, stderr bytes.Buffer

	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("dnf module list: %v\n%s%s", err, stdout.String(), stderr.String())
	}

	// The header and the hint line vary in width; keep the table.
	var rows []string

	for line := range strings.SplitSeq(stdout.String(), "\n") {
		if f := strings.Fields(line); len(f) >= 3 && !strings.HasPrefix(line, "Hint") && !strings.HasPrefix(line, "Name ") {
			rows = append(rows, strings.Join(f, " "))
		}
	}

	if len(rows) == 0 {
		t.Fatalf("dnf listed no module:\n%s%s", stdout.String(), stderr.String())
	}

	return strings.Join(rows, "\n")
}

// pythonDump loads a modules.yaml with libmodulemd's python bindings and
// returns what libmodulemd writes for it.
func pythonDump(t *testing.T, path string) string {
	t.Helper()

	const script = `
import sys
import gi
gi.require_version("Modulemd", "2.0")
from gi.repository import Modulemd
index = Modulemd.ModuleIndex.new()
ok, failures = index.update_from_file(sys.argv[1], True)
if not ok:
    sys.exit("; ".join(f.get_gerror().message for f in failures))
sys.stdout.write(index.dump_to_string())
`

	cmd := exec.Command("python3", "-c", script, path)

	var stdout, stderr bytes.Buffer

	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("libmodulemd: %v\n%s", err, stderr.String())
	}

	return stdout.String()
}

func requireLibmodulemd(t *testing.T) {
	t.Helper()
	requireTool(t, "python3")

	if err := exec.Command("python3", "-c", "import gi; gi.require_version('Modulemd', '2.0')").Run(); err != nil {
		t.Skip("the libmodulemd python bindings are not installed")
	}
}

// libmodulemd loads the written documents and writes them back byte for byte:
// the fixtures, and a stream whose texts exercise the quoting, folding and
// escaping rules.
func TestLibmodulemdRewritesUnchanged(t *testing.T) {
	requireLibmodulemd(t)

	check := func(t *testing.T, text string) {
		t.Helper()

		path := filepath.Join(t.TempDir(), "modules.yaml")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}

		if got := pythonDump(t, path); got != text {
			t.Errorf("libmodulemd rewrites the output:\n%s", firstDifference(got, text))
		}
	}

	for _, f := range moduleFixtures(t) {
		set := parseModulesFile(t, filepath.Base(f))
		if len(set.Translations) != 0 {
			continue // libmodulemd orders locales by hash
		}

		t.Run(filepath.Base(f), func(t *testing.T) { check(t, writeModules(t, set)) })
	}

	t.Run("texts", func(t *testing.T) {
		s := validStream()
		s.Version = 1
		s.Description = strings.Join(oddTexts(), "\n\n")
		s.Profiles = map[string]ModuleProfile{}
		s.XMD = map[string]any{}
		s.Components.RPMs = map[string]ModuleRPMComponent{}

		for i, text := range oddTexts() {
			if strings.ContainsAny(text, "\x00\x7f\u0085\u2028\u2029\ufeff") {
				continue // libmodulemd (libyaml) does not carry these through a reader
			}

			key := fmt.Sprintf("k%d %s", i, text)
			s.Profiles[key] = ModuleProfile{Description: text + "!", RPMs: []string{text + "-rpm"}}
			// libmodulemd keeps the elements of a list that have the type of the
			// first one, so each list holds one type.
			s.XMD[key] = []any{text + "!", text + "?"}
			s.XMD[key+"/bools"] = []any{true, false}
			s.XMD[key+"/maps"] = []any{map[string]any{"x": text + "?"}, map[string]any{text: "y"}}
			s.Components.RPMs[key] = ModuleRPMComponent{Rationale: text + "!", Repository: text + "#"}
		}

		check(t, writeModules(t, &ModuleSet{Streams: []*ModuleStream{s}}))
	})
}

// oddTexts are values that trip the quoting, folding and escaping rules.
func oddTexts() []string {
	return []string{
		"plain", "a: b", "a #b", "- x", "? x", "[x]", "{x}", "*x", "&x", "!x", "|x", ">x", "%x", "@x", "`x",
		"'quoted'", `"double"`, "back\\slash", "tab\there", "line\nbreak", "two\n\nbreaks", "ends\n", "cr\rhere", "crlf\r\nhere",
		"1", "1.0", "0x1F", "0o17", "-5", "+.5", "1e5", ".inf", ".nan", "true", "null", "~", "yes", "2020-01-01",
		"é", "日本語", "emoji 🎉", "bell\a", "esc\x1b",
		strings.Repeat("word ", 60), strings.Repeat("x", 300), strings.Repeat("a b\n", 40), "# comment-like", "key: value\nother: value",
		"---", "...", "--- x", "x ...", "a  b   c", "trailing ", "inner  double  space  " + strings.Repeat("y ", 50),
		strings.Repeat("long ", 20) + "\n  indented line\nback", "\ttabbed", "a\tb\n",
	}
}
