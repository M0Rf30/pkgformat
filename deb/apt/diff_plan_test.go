package apt

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Plan differential tests compare Cache.Plan with what `apt-get -s` plans,
// recorded in testdata/diff by generate.sh (README.md there explains the
// layout and the format of expected.tsv):
//
//   - the targets of testdata/diff/targets.txt, installed on the base image;
//   - testdata/diff/installed: scenarios that remove or replace packages, on
//     the base image with an MTA and sudo installed;
//   - testdata/diff/worlds/*: synthetic package universes with the removals,
//     upgrades, Conflicts, Breaks, alternatives, providers, holds and pins
//     the real archive does not offer in a small enough size.
//
// Every scenario must match apt exactly (the same packages in the same
// kinds of change at the same versions, the same kept-back set). A scenario
// that cannot is listed in aptDivergences with the reason, never left to
// fail.
var aptDivergences = map[string]string{
	"scoring/s13": "two packages Pre-Depend on each other: apt's resolver accepts the " +
		"plan and its simulation then fails ordering the unpack and configure steps " +
		"(immediate configuration); Plan stops at what the resolver decides and does " +
		"not order configuration, so it plans both",
}

// aptRow is one line of an expected.tsv.
type aptRow struct{ kind, name, version string }

func (r aptRow) String() string { return r.kind + " " + r.name + " " + r.version }

// rowOrder sorts the kinds the way the tests print them.
var rowOrder = map[string]int{"Fail": 0, "Solver3": 1, "None": 2, "Remv": 3, "Down": 4, "Upgr": 5, "Inst": 6, "Kept": 7}

func sortRows(rows []aptRow) {
	slices.SortFunc(rows, func(a, b aptRow) int {
		if d := rowOrder[a.kind] - rowOrder[b.kind]; d != 0 {
			return d
		}

		return strings.Compare(a.name, b.name)
	})
}

// loadAptRows reads an expected.tsv: id, kind, package, version.
func loadAptRows(t *testing.T, path string) (map[string][]aptRow, []string) {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)

	defer func() { _ = f.Close() }()

	rows := map[string][]aptRow{}

	var ids []string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		require.Len(t, fields, 4, sc.Text())
		require.Contains(t, rowOrder, fields[1], sc.Text())

		if _, seen := rows[fields[0]]; !seen {
			ids = append(ids, fields[0])
		}

		rows[fields[0]] = append(rows[fields[0]], aptRow{fields[1], fields[2], fields[3]})
	}

	require.NoError(t, sc.Err())

	return rows, ids
}

// scenarioRequest turns the apt-get arguments of a scenario into a request.
func scenarioRequest(t *testing.T, args string) PlanRequest {
	t.Helper()

	words := strings.Fields(args)
	require.NotEmpty(t, words)

	var req PlanRequest

	switch words[0] {
	case "upgrade":
		req.Upgrade = UpgradeSafe
	case "dist-upgrade":
		req.Upgrade = UpgradeFull
	case "install", "remove":
	default:
		t.Fatalf("unknown apt-get command %q", args)
	}

	for _, w := range words[1:] {
		switch {
		case w == "--with-new-pkgs":
			req.Upgrade = UpgradeWithNew
		case w == "-f":
			req.FixBroken = true
		case strings.HasPrefix(w, "-"):
		case words[0] == "install":
			if name, ver, ok := strings.Cut(w, "="); ok {
				w = name + " (= " + ver + ")"
			}

			req.Install = append(req.Install, w)
		case words[0] == "remove":
			req.Remove = append(req.Remove, w)
		}
	}

	return req
}

// planRows renders a plan in the rows of an expected.tsv.
func planRows(req PlanRequest, p *Plan, err error) []aptRow {
	if err != nil || (len(req.Install) > 0 && len(p.Unresolved) > 0) {
		return []aptRow{{"Fail", "-", "-"}}
	}

	var rows []aptRow

	for _, ch := range p.Changes {
		kind := map[ChangeKind]string{
			ChangeInstall: "Inst", ChangeUpgrade: "Upgr", ChangeDowngrade: "Down", ChangeRemove: "Remv",
		}[ch.Kind]

		rows = append(rows, aptRow{kind, ch.Package.Name, ch.Package.Version})
	}

	// apt-get names the kept-back packages for the upgrade commands only.
	if req.Upgrade != UpgradeNone {
		for _, h := range p.Held {
			rows = append(rows, aptRow{"Kept", h.Name, "-"})
		}
	}

	if len(rows) == 0 {
		rows = []aptRow{{"None", "-", "-"}}
	}

	return rows
}

// checkScenarios plans every scenario of a file on the cache and compares it
// with the recorded rows.
func checkScenarios(t *testing.T, c *Cache, opts PlanOptions, scenarios, expected, prefix string) int {
	t.Helper()

	want, ids := loadAptRows(t, expected)

	f, err := os.Open(scenarios)
	require.NoError(t, err)

	defer func() { _ = f.Close() }()

	args := map[string]string{}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		id, cmd, ok := strings.Cut(line, "\t")
		require.True(t, ok, line)

		args[id] = cmd
	}

	require.NoError(t, sc.Err())
	require.ElementsMatch(t, ids, mapKeys(args), "scenarios and expected.tsv list the same ids")

	matched := 0

	for _, id := range ids {
		t.Run(id+" "+args[id], func(t *testing.T) {
			if why, ok := aptDivergences[prefix+id]; ok {
				t.Skip("documented divergence: " + why)
			}

			rows := want[id]
			if rows[0].kind == "Solver3" {
				t.Skip("apt's second solver produced this result; the first one is what Plan ports")
			}

			req := scenarioRequest(t, args[id])
			plan, err := c.Plan(req, opts)

			got := planRows(req, plan, err)
			sortRows(got)
			sortRows(rows)

			gotText, wantText := rowsText(got), rowsText(rows)
			assert.Equal(t, wantText, gotText, "plan for %q", args[id])

			if !t.Failed() {
				matched++
			}
		})
	}

	return matched
}

func rowsText(rows []aptRow) string {
	lines := make([]string, len(rows))
	for i, r := range rows {
		lines[i] = r.String()
	}

	return strings.Join(lines, "\n")
}

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}

func TestPlanAgainstAptWorlds(t *testing.T) {
	t.Parallel()

	root := filepath.Join("testdata", "diff", "worlds")

	worlds, err := os.ReadDir(root)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(worlds), 4)

	total := 0

	for _, w := range worlds {
		if !w.IsDir() {
			continue
		}

		dir := filepath.Join(root, w.Name())

		t.Run(w.Name(), func(t *testing.T) {
			index, err := os.ReadFile(filepath.Join(dir, "Packages"))
			require.NoError(t, err)

			lists := t.TempDir()
			writeFile(t, filepath.Join(lists, indexName("world", "main", "amd64")), string(index))

			c, err := Load(LoadOptions{ListsDir: lists, StatusFile: filepath.Join(dir, "status"), HostArch: "amd64"})
			require.NoError(t, err)

			var opts PlanOptions

			if text, err := os.ReadFile(filepath.Join(dir, "preferences")); err == nil {
				prefs, err := ParsePreferences(string(text))
				require.NoError(t, err)

				opts.Policy = NewPolicy(prefs, PolicyOptions{})
			}

			if text, err := os.ReadFile(filepath.Join(dir, "holds")); err == nil {
				opts.Held = strings.Fields(string(text))
			}

			total += checkScenarios(t, c, opts,
				filepath.Join(dir, "scenarios.txt"), filepath.Join(dir, "expected.tsv"), w.Name()+"/")
		})
	}
}

func TestPlanAgainstAptInstalled(t *testing.T) {
	t.Parallel()

	dir := filepath.Join("testdata", "diff")

	c, err := Load(LoadOptions{
		ListsDir:   filepath.Join(dir, "lists"),
		StatusFile: filepath.Join(dir, "installed", "status"),
		HostArch:   "amd64",
	})
	require.NoError(t, err)

	checkScenarios(t, c, PlanOptions{},
		filepath.Join(dir, "installed", "scenarios.txt"), filepath.Join(dir, "installed", "expected.tsv"), "installed/")
}

func TestPlanAgainstAptTargets(t *testing.T) {
	t.Parallel()

	dir := filepath.Join("testdata", "diff")

	targetsText, err := os.ReadFile(filepath.Join(dir, "targets.txt"))
	require.NoError(t, err)

	plans, _ := loadAptRows(t, filepath.Join(dir, "expected.tsv"))

	c, err := Load(LoadOptions{
		ListsDir:   filepath.Join(dir, "lists"),
		StatusFile: filepath.Join(dir, "status"),
		HostArch:   "amd64",
	})
	require.NoError(t, err)

	targets := 0

	for line := range strings.SplitSeq(string(targetsText), "\n") {
		target := strings.TrimSpace(line)
		if target == "" || strings.HasPrefix(target, "#") {
			continue
		}

		targets++

		t.Run(target, func(t *testing.T) {
			if why, ok := aptDivergences["targets/"+target]; ok {
				t.Skip("documented divergence: " + why)
			}

			// targets recorded before the format had a kind for upgrades
			// list installs only; a Plan names an upgrade as such.
			req := PlanRequest{Install: []string{target}}
			plan, err := c.Plan(req, PlanOptions{})
			require.NoError(t, err)

			want := plans[target]
			got := planRows(req, plan, err)

			sortRows(want)
			sortRows(got)

			var wantRows []aptRow

			for _, r := range want {
				wantRows = append(wantRows, aptRow{r.kind, r.name, r.version})
			}

			// The base image's apt lists no Kept rows; the fixture has no
			// newer candidates for installed packages.
			got = slices.DeleteFunc(got, func(r aptRow) bool { return r.kind == "Kept" || r.kind == "None" })

			assert.Equal(t, rowsText(wantRows), rowsText(got), "plan for %s", target)
		})
	}

	require.GreaterOrEqual(t, targets, 20)
}
