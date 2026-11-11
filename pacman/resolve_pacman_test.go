package pacman

import (
	"bufio"
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The scenarios of testdata/resolver were run through pacman (see its
// generate.sh); each test below replays one against the same databases and
// compares the packages and the installed set that pacman ended with.

type scenario struct {
	name    string
	mode    string
	set     string
	options map[string]string
	targets []string
}

func readLines(t *testing.T, name string) [][]string {
	t.Helper()

	f, err := os.Open(filepath.Join("testdata", "resolver", name))
	if err != nil {
		t.Fatal(err)
	}

	defer f.Close()

	var rows [][]string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rows = append(rows, strings.Split(line, "|"))
	}

	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	return rows
}

func readScenarios(t *testing.T) []scenario {
	t.Helper()

	var out []scenario

	for _, f := range readLines(t, "scenarios.txt") {
		if len(f) != 5 {
			t.Fatalf("bad scenario line %q", f)
		}

		s := scenario{name: f[0], mode: f[1], set: f[2], options: map[string]string{}, targets: strings.Fields(f[4])}

		for _, o := range strings.Split(f[3], ";") {
			if k, v, ok := strings.Cut(o, "="); ok {
				s.options[k] = v
			}
		}

		out = append(out, s)
	}

	return out
}

type expected struct {
	ok    bool
	pkgs  []string // "repo name version"
	final map[string]string
	text  string // the error lines
}

func readExpected(t *testing.T, name string) expected {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", "resolver", "expected", name+".txt"))
	if err != nil {
		t.Fatal(err)
	}

	e := expected{final: map[string]string{}}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		kind, rest, _ := strings.Cut(line, " ")

		switch kind {
		case "status":
			e.ok = rest == "ok"
		case "pkg":
			e.pkgs = append(e.pkgs, rest)
		case "final":
			n, v, _ := strings.Cut(rest, " ")
			e.final[n] = v
		default:
			e.text += line + "\n"
		}
	}

	return e
}

func scenarioUsage(s string) Usage {
	var u Usage

	for _, w := range strings.Fields(s) {
		switch w {
		case "Sync":
			u |= UsageSync
		case "Search":
			u |= UsageSearch
		case "Install":
			u |= UsageInstall
		case "Upgrade":
			u |= UsageUpgrade
		case "All":
			u |= UsageAll
		}
	}

	return u
}

func loadResolverIndex(t *testing.T, s scenario) *Index {
	t.Helper()

	x := &Index{}

	for _, repo := range []string{"core", "extra"} {
		f, err := os.Open(filepath.Join("testdata", "resolver", "sync", repo+".db"))
		if err != nil {
			t.Fatal(err)
		}

		err = x.AddDatabase(repo, f)

		f.Close()

		if err != nil {
			t.Fatal(err)
		}

		if u, ok := s.options["Usage."+repo]; ok {
			x.SetUsage(repo, scenarioUsage(u))
		}
	}

	return x
}

func loadResolverLocal(t *testing.T, set string) []*InstalledPackage {
	t.Helper()

	db, err := OpenLocalDB(filepath.Join("testdata", "resolver", "local", set), LocalDBOptions{SkipFiles: true})
	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	pkgs, err := db.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	return pkgs
}

func (s scenario) run(t *testing.T) (*Transaction, []*InstalledPackage, error) {
	t.Helper()

	x := loadResolverIndex(t, s)
	local := loadResolverLocal(t, s.set)
	opts := ResolveOptions{
		Local:       local,
		IgnorePkg:   strings.Fields(s.options["IgnorePkg"]),
		IgnoreGroup: strings.Fields(s.options["IgnoreGroup"]),
	}

	var (
		tx  *Transaction
		err error
	)

	if s.mode == "Su" {
		tx, err = x.Sysupgrade(local, opts)
	} else {
		tx, err = x.Install(s.targets, opts)
	}

	return tx, local, err
}

// pacmanErrorKind maps the message pacman gave to the sentinel the resolver
// reports for the same situation.
func pacmanErrorKind(text string) error {
	switch {
	case strings.Contains(text, "breaks dependency"):
		return ErrBrokenDependency
	case strings.Contains(text, "conflict"):
		return ErrConflict
	case strings.Contains(text, "unable to satisfy") || strings.Contains(text, "target not found"):
		return ErrUnresolved
	}

	return nil
}

var conflictPair = regexp.MustCompile(`info (\S+)-\S+-\S+ and (\S+)-\S+-\S+ are in conflict`)

// printSkipsConflicts lists the scenarios where "pacman --print" names a package
// that the real transaction leaves out because another one provides it.
var printSkipsConflicts = map[string]bool{ //nolint:gochecknoglobals // test table
	"conflict-provided-name":          true,
	"conflict-target-provides-target": true,
}

func TestResolverMatchesPacman(t *testing.T) {
	t.Parallel()

	scenarios := readScenarios(t)
	if len(scenarios) < 15 {
		t.Fatalf("only %d scenarios", len(scenarios))
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()

			want := readExpected(t, s.name)
			tx, local, err := s.run(t)

			if !want.ok {
				kind := pacmanErrorKind(want.text)
				if kind == nil {
					t.Fatalf("unclassified pacman error:\n%s", want.text)
				}

				if !errors.Is(err, kind) {
					t.Fatalf("err = %v, want one wrapping %v (pacman: %s)", err, kind, want.text)
				}

				if m := conflictPair.FindStringSubmatch(want.text); m != nil {
					for _, n := range m[1:] {
						if !strings.Contains(err.Error(), n) {
							t.Errorf("error %q does not name %s", err, n)
						}
					}
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got := make([]string, len(tx.Packages))
			for i, p := range tx.Packages {
				got[i] = p.Repo + " " + p.Name + " " + p.Version
			}

			slices.Sort(got)

			if printSkipsConflicts[s.name] {
				for _, g := range got {
					if !slices.Contains(want.pkgs, g) {
						t.Errorf("package %s not in pacman's list %v", g, want.pkgs)
					}
				}
			} else if !slices.Equal(got, want.pkgs) {
				t.Errorf("packages = %v\npacman   = %v", got, want.pkgs)
			}

			final := map[string]string{}
			for _, l := range local {
				final[l.Name] = l.Version
			}

			for _, l := range tx.Removals {
				delete(final, l.Name)
			}

			for _, p := range tx.Packages {
				final[p.Name] = p.Version
			}

			if !maps.Equal(final, want.final) {
				t.Errorf("installed set = %v\npacman        = %v", final, want.final)
			}

			if s.name != "cycle" {
				checkDependencyOrder(t, tx.Packages)
			}

			checkClassification(t, tx, local)
		})
	}
}

// checkDependencyOrder verifies that every package comes after the packages of
// the transaction that satisfy its dependencies.
func checkDependencyOrder(t *testing.T, pkgs []*IndexedPackage) {
	t.Helper()

	for i, p := range pkgs {
		for _, s := range p.Depends {
			d, err := ParseDependency(s)
			if err != nil {
				t.Fatal(err)
			}

			var sat []int

			for j, q := range pkgs {
				if j != i && q.Satisfies(d) {
					sat = append(sat, j)
				}
			}

			if len(sat) > 0 && !slices.ContainsFunc(sat, func(j int) bool { return j < i }) {
				t.Errorf("%s comes before every package that satisfies %s", p.Name, s)
			}
		}
	}
}

// checkClassification verifies that Installs, Upgrades and Replacements
// partition Packages.
func checkClassification(t *testing.T, tx *Transaction, local []*InstalledPackage) {
	t.Helper()

	n := len(tx.Installs) + len(tx.Upgrades) + len(tx.Replacements)
	if n != len(tx.Packages) {
		t.Errorf("installs %d + upgrades %d + replacements %d != packages %d", len(tx.Installs), len(tx.Upgrades), len(tx.Replacements), len(tx.Packages))
	}

	installed := map[string]bool{}
	for _, l := range local {
		installed[l.Name] = true
	}

	for _, p := range tx.Installs {
		if installed[p.Name] {
			t.Errorf("%s listed as new but installed", p.Name)
		}
	}

	for _, u := range tx.Upgrades {
		if u.Installed.Name != u.Package.Name {
			t.Errorf("upgrade %s -> %s", u.Installed.Name, u.Package.Name)
		}
	}

	for _, r := range tx.Replacements {
		if !slices.Contains(tx.Removals, r.Installed) {
			t.Errorf("replaced %s not in Removals", r.Installed.Name)
		}
	}
}
