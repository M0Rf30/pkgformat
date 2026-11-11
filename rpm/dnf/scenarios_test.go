package dnf

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm/rpmdb"
)

// The scenario test replays testdata/scenarios: small synthetic repositories
// (build.py) and, for each line of scenarios.txt, an installed state (the rpm
// database dnf5 wrote when it installed the "installed first" packages), the
// repository priorities and costs and the dnf.conf options of the line, and the
// transaction real dnf5 computes for the specs (expected/<label>.txt, recorded
// by generate.sh). Resolve must give the same: the packages it installs or
// upgrades to ("+ name arch version repository"), the installed packages it
// replaces or removes ("- name arch version"), or a failure where dnf fails.

const scenariosDir = "testdata/scenarios"

type scenario struct {
	label string
	repos []string
	opts  []string
	specs []string
}

func readScenarios(t *testing.T) []scenario {
	t.Helper()

	f, err := os.Open(filepath.Join(scenariosDir, "scenarios.txt"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	var out []scenario

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, "|")
		if len(fields) != 5 {
			t.Fatalf("scenarios.txt: %q has %d fields, want 5", line, len(fields))
		}

		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}

		s := scenario{
			label: fields[0],
			repos: strings.Split(fields[1], ","),
			specs: strings.Fields(fields[4]),
		}
		if fields[3] != "-" {
			s.opts = strings.Fields(fields[3])
		}

		out = append(out, s)
	}

	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	return out
}

// repoSections writes the .repo sections of a scenario: id[:priority[:cost]].
func repoSections(base string, entries []string) string {
	var b strings.Builder

	for _, e := range entries {
		parts := strings.Split(e, ":")
		b.WriteString("[" + parts[0] + "]\nname=" + parts[0] + "\nenabled=1\nbaseurl=" + base + "/" + parts[0] + "\n")

		if len(parts) > 1 {
			b.WriteString("priority=" + parts[1] + "\n")
		}

		if len(parts) > 2 {
			b.WriteString("cost=" + parts[2] + "\n")
		}
	}

	return b.String()
}

// scenarioWant reads expected/<label>.txt: the lines of the transaction, or
// the error text.
func scenarioWant(t *testing.T, label string) (lines []string, solverError string) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(scenariosDir, "expected", label+".txt"))
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		switch {
		case strings.HasPrefix(line, "error:"):
			solverError += line + "\n"
		case line != "":
			lines = append(lines, line)
		}
	}

	slices.Sort(lines)

	return lines, solverError
}

// scenarioGot renders a resolution as expected/<label>.txt does.
func scenarioGot(res *Resolution) []string {
	var got []string

	for _, p := range res.Packages {
		got = append(got, "+ "+p.Name+" "+p.Arch+" "+evrOf(p)+" "+p.Repo)
	}

	for _, r := range slices.Concat(res.Upgrades, res.Obsoleted) {
		got = append(got, "- "+r.Old.Name+" "+r.Old.Arch+" "+evrOf(r.Old))
	}

	for _, p := range res.Removed {
		got = append(got, "- "+p.Name+" "+p.Arch+" "+evrOf(p))
	}

	slices.Sort(got)

	return got
}

func TestScenariosAgainstDnf(t *testing.T) {
	srv := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(scenariosDir, "repos"))))
	t.Cleanup(srv.Close)

	divergences := readDivergences(t, scenariosDir)
	seen := map[string]bool{}

	for _, sc := range readScenarios(t) {
		t.Run(sc.label, func(t *testing.T) {
			want, solverError := scenarioWant(t, sc.label)

			confPath := filepath.Join(t.TempDir(), "dnf.conf")
			conf := "[main]\n" + strings.Join(sc.opts, "\n") + "\n"

			if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
				t.Fatal(err)
			}

			var installed Installed

			if path := filepath.Join(scenariosDir, "installed", sc.label, "rpmdb.sqlite"); fileExists(path) {
				db, err := rpmdb.Open(path, rpmdb.Options{SQLite: rpmdb.SQLiteImmutable})
				if err != nil {
					t.Fatal(err)
				}

				t.Cleanup(func() { _ = db.Close() })

				installed = db
			}

			env := newEnv(t, repoSections(srv.URL, sc.repos), func(o *Options) {
				o.Releasever = "43"
				o.ConfigFile = confPath
				o.Installed = installed
			})
			ix := loadIndex(t, env)

			res, err := ix.Resolve(context.Background(), sc.specs)
			if err != nil {
				t.Fatal(err)
			}

			got := scenarioGot(res)
			failed := len(res.Unresolved) > 0 || len(res.Conflicts) > 0

			if solverError != "" {
				if !failed {
					t.Errorf("dnf refuses the transaction:\n%swe give %v", solverError, got)
				}

				return
			}

			if failed {
				t.Errorf("unresolved %v, conflicts %+v", res.Unresolved, res.Conflicts)
			}

			missing, extra := diff(want, got)

			reason, known := divergences[sc.label]
			if known {
				seen[sc.label] = true
			}

			switch {
			case len(missing)+len(extra) == 0 && known:
				t.Errorf("listed as divergent (%s) but identical to dnf: remove it from divergences.txt", reason)
			case len(missing)+len(extra) > 0 && !known:
				t.Errorf("differs from dnf\n  dnf only:  %v\n  ours only: %v", missing, extra)
			case len(missing)+len(extra) > 0:
				t.Logf("known divergence (%s)\n  dnf only:  %v\n  ours only: %v", reason, missing, extra)
			}
		})
	}

	for label := range divergences {
		if !seen[label] {
			t.Errorf("scenarios/divergences.txt names %q, which does not diverge or is not a scenario", label)
		}
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}
