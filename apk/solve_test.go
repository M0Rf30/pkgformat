package apk

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func loadIndexFile(t testing.TB, path string) []Package {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	pkgs, err := ParseIndex(f)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}

	return pkgs
}

// resolveCase is one line of testdata/resolve/cases.txt.
type resolveCase struct {
	name      string
	installed []string
	world     []string
	command   []string
}

func loadCases(t testing.TB, path string) []resolveCase {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	var cases []resolveCase

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}

		f := strings.Split(line, "|")
		if len(f) != 4 {
			t.Fatalf("%s: malformed line %q", path, line)
		}

		cases = append(cases, resolveCase{
			name:      strings.TrimSpace(f[0]),
			installed: strings.Fields(f[1]),
			world:     strings.Fields(f[2]),
			command:   strings.Fields(f[3]),
		})
	}

	return cases
}

// normalizeChanges renders a solution the way generate.sh normalizes apk's
// output.
func normalizeChanges(changes []Change) []string {
	var out []string

	for _, c := range changes {
		switch c.Kind() {
		case ChangeRemove:
			out = append(out, "remove "+c.Old.Name+"-"+c.Old.Version)
		default:
			out = append(out, c.Kind().String()+" "+c.New.Name+"-"+c.New.Version)
		}
	}

	slices.Sort(out)

	return out
}

// TestSolve_differential replays the cases of testdata/resolve against the
// answers apk-tools gave (see generate.sh there).
func TestSolve_differential(t *testing.T) {
	dir := filepath.Join("testdata", "resolve")
	mainPkgs := loadIndexFile(t, filepath.Join(dir, "main.index"))
	edgePkgs := loadIndexFile(t, filepath.Join(dir, "edge.index"))

	idx := NewIndex()
	idx.Add(Repo{URL: "/u/main"}, "x86_64", mainPkgs)
	idx.Add(Repo{URL: "/u/edge", Tag: "edge"}, "x86_64", edgePkgs)

	all := append(slices.Clone(mainPkgs), edgePkgs...)

	for _, tc := range loadCases(t, filepath.Join(dir, "cases.txt")) {
		t.Run(tc.name, func(t *testing.T) {
			var installed []Package

			for _, nv := range tc.installed {
				found := false

				for _, p := range all {
					if p.Name+"-"+p.Version == nv {
						installed, found = append(installed, p), true

						break
					}
				}

				if !found {
					t.Fatalf("installed %q is not in the universe", nv)
				}
			}

			world, err := WorldAdd(nil, tc.world...)
			if err != nil {
				t.Fatal(err)
			}

			req := SolveRequest{Installed: installed}

			switch tc.command[0] {
			case "add":
				if world, err = WorldAdd(world, tc.command[1:]...); err != nil {
					t.Fatal(err)
				}
			case "upgrade":
				req.Upgrade = true
			default:
				t.Fatalf("unknown command %q", tc.command[0])
			}

			req.World = world

			want, err := os.ReadFile(filepath.Join(dir, "expected", tc.name))
			if err != nil {
				t.Fatal(err)
			}

			sol, err := idx.Solve(req)
			if strings.TrimSpace(string(want)) == "error" {
				if err == nil {
					t.Fatalf("apk refuses the request, Solve found %v", normalizeChanges(sol.Changes))
				}

				return
			}

			if err != nil {
				t.Fatalf("apk accepts the request, Solve: %v", err)
			}

			got := strings.Join(normalizeChanges(sol.Changes), "\n")
			if got != strings.TrimSpace(string(want)) {
				t.Fatalf("got\n%s\nwant\n%s", got, strings.TrimSpace(string(want)))
			}
		})
	}
}

// TestSolve_realAlpine replays targets against a reduced real Alpine index
// and the installed database of the image, as answered by apk (see
// testdata/resolve/real/generate.sh).
func TestSolve_realAlpine(t *testing.T) {
	dir := filepath.Join("testdata", "resolve", "real")

	idx := NewIndex()
	idx.Add(Repo{URL: "/u/main"}, "x86_64", loadIndexFile(t, filepath.Join(dir, "APKINDEX")))

	f, err := os.Open(filepath.Join(dir, "installed"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	list, err := NewInstalledDB(f, st.Size(), InstalledOptions{}).List(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	var installed []Package
	for _, p := range list {
		installed = append(installed, p.Package)
	}

	wf, err := os.Open(filepath.Join(dir, "world"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = wf.Close() }()

	world, err := ParseWorld(wf)
	if err != nil {
		t.Fatal(err)
	}

	targets, err := os.ReadFile(filepath.Join(dir, "targets.txt"))
	if err != nil {
		t.Fatal(err)
	}

	for _, target := range strings.Fields(string(targets)) {
		t.Run(target, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join(dir, "expected", target))
			if err != nil {
				t.Fatal(err)
			}

			w, err := WorldAdd(world, target)
			if err != nil {
				t.Fatal(err)
			}

			sol, err := idx.Solve(SolveRequest{World: w, Installed: installed})
			if strings.TrimSpace(string(want)) == "error" {
				if err == nil {
					t.Fatal("apk refuses, Solve accepts")
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if got := strings.Join(normalizeChanges(sol.Changes), "\n"); got != strings.TrimSpace(string(want)) {
				t.Fatalf("got\n%s\nwant\n%s", got, want)
			}
		})
	}
}
