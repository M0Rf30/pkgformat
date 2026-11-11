package pacman

import (
	"errors"
	"strings"
	"testing"
)

func FuzzParseOptionalDep(f *testing.F) {
	for _, s := range []string{"nice: a nice extra", "lib>=2: x: y", "name", "name:", ": x", "a b", "x=1:2-3: desc"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		o, err := ParseOptionalDep(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidDependency) {
				t.Fatalf("error %v does not wrap ErrInvalidDependency", err)
			}

			return
		}

		again, err := ParseOptionalDep(o.String())
		if err != nil || again != o {
			t.Fatalf("%q -> %+v -> %q -> %+v, %v", s, o, o.String(), again, err)
		}
	})
}

// fuzzIndex builds an index from lines "repo|name|version|depends|provides|
// conflicts|replaces|groups", the lists separated by spaces, and the installed
// packages from the entries of the repository "local".
func fuzzIndex(data string) (*Index, []*InstalledPackage) {
	x := &Index{}
	byRepo := map[string][]DBEntry{}

	var (
		repos []string
		local []*InstalledPackage
	)

	for i, line := range strings.Split(data, "\n") {
		if i >= 64 {
			break
		}

		f := strings.Split(line, "|")
		for len(f) < 8 {
			f = append(f, "")
		}

		list := func(s string) []string { return strings.Fields(s) }

		if f[0] == "local" {
			local = append(local, &InstalledPackage{
				Name: f[1], Version: f[2], Depends: list(f[3]), Provides: list(f[4]),
				Conflicts: list(f[5]), Replaces: list(f[6]), Groups: list(f[7]),
			})

			continue
		}

		if _, ok := byRepo[f[0]]; !ok {
			repos = append(repos, f[0])
		}

		byRepo[f[0]] = append(byRepo[f[0]], DBEntry{
			Name: f[1], Version: f[2], Depends: list(f[3]), Provides: list(f[4]),
			Conflicts: list(f[5]), Replaces: list(f[6]), Groups: list(f[7]), OptDepends: list(f[3]),
		})
	}

	for _, r := range repos {
		_ = x.Add(r, byRepo[r])
	}

	return x, local
}

func checkTransaction(t *testing.T, tx *Transaction, err error) {
	t.Helper()

	if err != nil {
		for _, known := range []error{ErrUnresolved, ErrConflict, ErrBrokenDependency, ErrInvalidDependency} {
			if errors.Is(err, known) {
				return
			}
		}

		t.Fatalf("unclassified error: %v", err)
	}

	seen := map[string]bool{}

	for _, p := range tx.Packages {
		if seen[p.Name] {
			t.Fatalf("%s twice in the transaction", p.Name)
		}

		seen[p.Name] = true
	}

	if len(tx.Installs)+len(tx.Upgrades)+len(tx.Replacements) != len(tx.Packages) {
		t.Fatalf("classification does not partition: %+v", tx)
	}
}

func FuzzInstall(f *testing.F) {
	f.Add("app glibc", "core|app|1-1|glibc sh||||\ncore|glibc|2-1||||base|\ncore|dash|1-1||sh|||")
	f.Add("a b", "core|a|1-1||||b|\ncore|b|1-1||a|a|a|\nlocal|c|1-1|a|||a|")
	f.Add("g", "core|x|1-1|y>=2|y=3|x|x|g\nextra|y|1-1|x|||x|g\nlocal|y|1-1||||x|")

	f.Fuzz(func(t *testing.T, roots, db string) {
		x, local := fuzzIndex(db)
		opts := ResolveOptions{Local: local, WithOptional: len(roots)%2 == 0, IgnorePkg: []string{"a*"}, IgnoreGroup: []string{"g"}}

		tx, err := x.Install(strings.Fields(roots), opts)
		checkTransaction(t, tx, err)

		tx, err = x.Sysupgrade(local, opts)
		checkTransaction(t, tx, err)
	})
}
