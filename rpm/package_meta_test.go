package rpm_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
)

// metaGolden is what librpm reads from the fixtures of testdata/meta
// (golden.py writes it).
type metaGolden struct {
	Scripts map[string]struct {
		Body  string   `json:"body"`
		Prog  []string `json:"prog"`
		Flags uint32   `json:"flags"`
	} `json:"scripts"`
	Files []struct {
		Path   string `json:"path"`
		Caps   string `json:"caps"`
		Nlink  uint32 `json:"nlink"`
		Lang   string `json:"lang"`
		Class  string `json:"class"`
		Verify uint32 `json:"verify"`
		Rdev   uint32 `json:"rdev"`
	} `json:"files"`
	Triggers                   []string `json:"triggers"`
	TriggerScripts             []string `json:"triggerscripts"`
	FileTriggerScripts         []string `json:"filetriggerscripts"`
	TransFileTriggerScripts    []string `json:"transfiletriggerscripts"`
	FileTriggerPriorities      []uint32 `json:"filetriggerpriorities"`
	TransFileTriggerPriorities []uint32 `json:"transfiletriggerpriorities"`
	Sources                    []string `json:"sources"`
	Patches                    []string `json:"patches"`
	ModularityLabel            string   `json:"modularitylabel"`
	DistTag                    string   `json:"disttag"`
	BugURL                     string   `json:"bugurl"`
	VCS                        string   `json:"vcs"`
	Distribution               string   `json:"distribution"`
	Platform                   string   `json:"platform"`
	Cookie                     string   `json:"cookie"`
	PayloadFlags               string   `json:"payloadflags"`
	ExclusiveArch              []string `json:"exclusivearch"`
	ExcludeArch                []string `json:"excludearch"`
	ExclusiveOS                []string `json:"exclusiveos"`
	ExcludeOS                  []string `json:"excludeos"`
	Source                     bool     `json:"source"`
	Requires                   []struct {
		Name  string `json:"name"`
		Flags uint32 `json:"flags"`
	} `json:"requires"`
}

func TestPackageMetadataMatchesLibrpm(t *testing.T) {
	raw, err := os.ReadFile("testdata/meta/golden.json")
	if err != nil {
		t.Fatal(err)
	}

	var golden map[string]metaGolden
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}

	for name, want := range golden {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata/meta", name))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			pkg, err := rpm.ReadPackage(f)
			if err != nil {
				t.Fatal(err)
			}

			checkScripts(t, pkg, want)
			checkFiles(t, pkg, want)
			checkTriggers(t, pkg, want)

			eq(t, "modularity label", pkg.ModularityLabel, want.ModularityLabel)
			eq(t, "dist tag", pkg.DistTag, want.DistTag)
			eq(t, "bug url", pkg.BugURL, want.BugURL)
			eq(t, "vcs", pkg.VCS, want.VCS)
			eq(t, "distribution", pkg.Distribution, want.Distribution)
			eq(t, "platform", pkg.Platform, want.Platform)
			eq(t, "cookie", pkg.Cookie, want.Cookie)
			eq(t, "payload flags", pkg.PayloadFlags, want.PayloadFlags)
			eq(t, "source", pkg.IsSource, want.Source)
			eqs(t, "exclusive arch", pkg.ExclusiveArch, want.ExclusiveArch)
			eqs(t, "exclude arch", pkg.ExcludeArch, want.ExcludeArch)
			eqs(t, "exclusive os", pkg.ExclusiveOS, want.ExclusiveOS)
			eqs(t, "exclude os", pkg.ExcludeOS, want.ExcludeOS)
			eqs(t, "sources", names(pkg.Sources), want.Sources)
			eqs(t, "patches", names(pkg.Patches), want.Patches)

			eq(t, "require count", len(pkg.Requires), len(want.Requires))

			for i, d := range pkg.Requires {
				if i < len(want.Requires) {
					eq(t, "require "+d.Name, d.Name, want.Requires[i].Name)
					eq(t, "require flags "+d.Name, uint32(d.Flags), want.Requires[i].Flags)
				}
			}
		})
	}
}

func checkScripts(t *testing.T, pkg *rpm.Package, want metaGolden) {
	t.Helper()

	got := map[string]rpm.NamedScript{}
	for _, s := range pkg.Scripts.All() {
		got[s.Name] = s
	}

	eq(t, "scriptlet count", len(got), len(want.Scripts))

	for name, w := range want.Scripts {
		g, ok := got[name]
		if !ok {
			t.Errorf("scriptlet %s missing", name)

			continue
		}

		eq(t, name+" body", g.Body, w.Body)
		eqs(t, name+" program", g.Program(), w.Prog)
		eq(t, name+" flags", uint32(g.Flags), w.Flags)
	}
}

func checkFiles(t *testing.T, pkg *rpm.Package, want metaGolden) {
	t.Helper()

	byPath := map[string]rpm.FileEntry{}
	for _, f := range pkg.Files {
		byPath[f.Path] = f
	}

	for _, w := range want.Files {
		g, ok := byPath[w.Path]
		if !ok {
			t.Errorf("file %s missing", w.Path)

			continue
		}

		eq(t, w.Path+" caps", g.Caps, w.Caps)
		eq(t, w.Path+" nlink", g.Nlink, w.Nlink)
		eq(t, w.Path+" lang", g.Lang, w.Lang)
		eq(t, w.Path+" class", g.Class, w.Class)
		eq(t, w.Path+" verify", g.VerifyFlags, w.Verify)
		eq(t, w.Path+" rdev", g.Rdev, w.Rdev)
	}
}

func checkTriggers(t *testing.T, pkg *rpm.Package, want metaGolden) {
	t.Helper()

	var conds, scripts []string

	for _, tr := range pkg.Triggers {
		scripts = append(scripts, tr.Script.Body)
		for _, c := range tr.Conditions {
			conds = append(conds, c.Name)
		}
	}

	eqs(t, "trigger conditions", sorted(conds), sorted(want.Triggers))
	eqs(t, "trigger scripts", sorted(scripts), sorted(want.TriggerScripts))

	var ft, tft []string

	var ftp, tftp []uint32

	for _, tr := range pkg.FileTriggers {
		if tr.Transaction {
			tft = append(tft, tr.Script.Body)
			tftp = append(tftp, tr.Priority)
		} else {
			ft = append(ft, tr.Script.Body)
			ftp = append(ftp, tr.Priority)
		}
	}

	eqs(t, "file trigger scripts", ft, want.FileTriggerScripts)
	eqs(t, "transaction file trigger scripts", tft, want.TransFileTriggerScripts)
	eqs(t, "file trigger priorities", ftp, want.FileTriggerPriorities)
	eqs(t, "transaction file trigger priorities", tftp, want.TransFileTriggerPriorities)
}

func names(s []rpm.SourceFile) []string {
	var out []string
	for _, f := range s {
		out = append(out, f.Name)
	}

	return out
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)

	return s
}

func eq[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()

	if got != want {
		t.Errorf("%s: got %v, librpm %v", what, got, want)
	}
}

func eqs[T comparable](t *testing.T, what string, got, want []T) {
	t.Helper()

	if len(got) == 0 && len(want) == 0 {
		return
	}

	if !slices.Equal(got, want) {
		t.Errorf("%s: got %v, librpm %v", what, got, want)
	}
}
