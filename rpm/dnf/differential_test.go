package dnf

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The differential test replays testdata/differential: a trimmed snapshot of the
// Fedora 43 repository and, for each line of targets.txt, the packages real
// dnf5 would install on an empty system (expected/<label>.txt, recorded by
// generate.sh). The same snapshot is served over HTTP, loaded through Update
// and Load, and every target is resolved with weak dependencies off, as dnf was
// run. testdata/differential/README.md lists the divergences that are known and
// intended; they are in divergences.txt and a target that is listed there must
// still diverge, so the list cannot go stale.

const differentialDir = "testdata/differential"

type target struct {
	label string
	specs []string
}

func readTargets(t *testing.T) []target {
	t.Helper()

	f, err := os.Open(filepath.Join(differentialDir, "targets.txt"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	var out []target

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		label, specs, _ := strings.Cut(line, ":")
		out = append(out, target{label: strings.TrimSpace(label), specs: strings.Fields(specs)})
	}

	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	return out
}

// readDivergences returns label -> reason.
func readDivergences(t *testing.T, dir string) map[string]string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, "divergences.txt"))
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		t.Fatal(err)
	}

	out := map[string]string{}

	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		label, reason, _ := strings.Cut(line, "\t")
		out[label] = reason
	}

	return out
}

// expectedSet reads expected/<label>.txt: the lines "name arch evr", or the
// "error:" lines dnf printed when it could not solve the transaction.
func expectedSet(t *testing.T, label string) (set []string, solverError string) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(differentialDir, "expected", label+".txt"))
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "error:") {
			solverError += line + "\n"

			continue
		}

		if f := strings.Fields(line); len(f) == 3 {
			set = append(set, f[0]+" "+f[1]+" "+f[2])
		}
	}

	slices.Sort(set)

	return set, solverError
}

func evrOf(p *Package) string {
	if p.Epoch == 0 {
		return p.Version + "-" + p.Release
	}

	return strconv.FormatUint(uint64(p.Epoch), 10) + ":" + p.Version + "-" + p.Release
}

func snapshotIndex(t *testing.T) *Index {
	t.Helper()

	srv := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(differentialDir, "snapshot"))))
	t.Cleanup(srv.Close)

	env := newEnv(t, baseurlSection(srv.URL), func(o *Options) { o.Releasever = "43" })

	ix := loadIndex(t, env)
	if ix.Len() < 500 {
		t.Fatalf("the snapshot holds only %d package names", ix.Len())
	}

	return ix
}

func TestDifferentialAgainstDnf(t *testing.T) {
	ix := snapshotIndex(t)
	divergences := readDivergences(t, differentialDir)
	seen := map[string]bool{}

	for _, tg := range readTargets(t) {
		t.Run(tg.label, func(t *testing.T) {
			want, solverError := expectedSet(t, tg.label)

			res, err := ix.ResolveWith(context.Background(), tg.specs, ResolveOptions{WeakDeps: WeakDisabled})
			if err != nil {
				t.Fatal(err)
			}

			var got []string
			for _, p := range res.Packages {
				got = append(got, p.Name+" "+p.Arch+" "+evrOf(p))
			}

			slices.Sort(got)

			failed := len(res.Unresolved) > 0 || len(res.Conflicts) > 0
			if solverError != "" {
				// dnf could not do it, and neither may we
				if !failed {
					t.Errorf("dnf refuses the transaction:\n%swe install %d packages", solverError, len(got))
				}

				return
			}

			if failed {
				t.Errorf("unresolved %v, conflicts %+v", res.Unresolved, res.Conflicts)
			}

			missing, extra := diff(want, got)

			reason, known := divergences[tg.label]
			if known {
				seen[tg.label] = true
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
			t.Errorf("divergences.txt names %q, which is not a target", label)
		}
	}
}

// diff returns what only a has and what only b has, both sorted.
func diff(a, b []string) (onlyA, onlyB []string) {
	for _, x := range a {
		if !slices.Contains(b, x) {
			onlyA = append(onlyA, x)
		}
	}

	for _, x := range b {
		if !slices.Contains(a, x) {
			onlyB = append(onlyB, x)
		}
	}

	return onlyA, onlyB
}
