// Command softgen writes one synthetic package universe for the differential
// tests: a seeded random dependency graph with Depends, Recommends,
// Suggests, Conflicts, Breaks, virtual packages, two versions of many
// packages, a consistent installed system with automatic marks and a hold,
// and a list of apt-get scenarios over it. The same seed always writes the
// same files.
//
//	go run ./deb/apt/testdata/diff/softgen -seed 3 -out deb/apt/testdata/diff/worlds/soft3
//
// It is run by hand to create a world, not by generate.sh or the tests: the
// files it writes are the fixed input, and generate.sh records what apt
// plans for them.
package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	packageCount = 46
	virtuals     = 5
	rootCount    = 12
	scenarios    = 48
)

type version struct {
	ver     string
	deps    [][]string
	recs    [][]string
	sugs    [][]string
	conf    []string
	brk     []string
	prov    []string
	section string
	prio    string
}

type pkg struct {
	name      string
	essential bool
	versions  []*version // lowest first
}

type world struct {
	rng  *rand.Rand
	pkgs []*pkg
	byN  map[string]*pkg
}

func main() {
	seed := flag.Uint64("seed", 1, "random seed")
	out := flag.String("out", "", "directory to write")
	flag.Parse()

	if *out == "" {
		fmt.Fprintln(os.Stderr, "softgen: -out is required")
		os.Exit(2)
	}

	w := &world{rng: rand.New(rand.NewPCG(*seed, *seed*7919+1)), byN: map[string]*pkg{}}
	w.build()

	if err := w.write(*out); err != nil {
		fmt.Fprintln(os.Stderr, "softgen:", err)
		os.Exit(1)
	}
}

func (w *world) pick(n int) int { return w.rng.IntN(n) }

func (w *world) chance(p float64) bool { return w.rng.Float64() < p }

func pname(i int) string { return fmt.Sprintf("p%02d", i) }

func vname(i int) string { return fmt.Sprintf("virt%d", i) }

// target names a package or a virtual one, with a version restriction now and
// then.
func (w *world) target(self int) string {
	if w.chance(0.12) {
		return vname(w.pick(virtuals))
	}

	// Mostly lower numbers (a mostly acyclic graph), sometimes any.
	j := w.pick(packageCount)
	if w.chance(0.8) && self > 0 {
		j = w.pick(self)
	}

	if j == self {
		j = (j + 1) % packageCount
	}

	name := pname(j)

	switch {
	case w.chance(0.12):
		return name + " (>= 1.0)"
	case w.chance(0.10):
		return name + " (>= 2.0)"
	case w.chance(0.04):
		return name + " (<< 2.0)"
	}

	return name
}

func (w *world) groups(self, maxGroups int, altChance float64) [][]string {
	n := w.pick(maxGroups + 1)
	out := make([][]string, 0, n)

	for range n {
		g := []string{w.target(self)}
		if w.chance(altChance) {
			g = append(g, w.target(self))
		}

		out = append(out, g)
	}

	return out
}

func (w *world) build() {
	prios := []string{"required", "important", "standard", "optional", "optional", "optional", "extra"}
	sections := []string{"libs", "admin", "utils", "metapackages", "oldlibs", "libs", "net"}

	for i := range packageCount {
		p := &pkg{name: pname(i), essential: w.chance(0.02)}
		count := 1
		if w.chance(0.45) {
			count = 2
		}

		for v := range count {
			ver := &version{
				ver:     fmt.Sprintf("%d.0", v+1),
				deps:    w.groups(i, 3, 0.25),
				recs:    w.groups(i, 2, 0.2),
				sugs:    w.groups(i, 2, 0.1),
				section: sections[w.pick(len(sections))],
				prio:    prios[w.pick(len(prios))],
			}
			if w.chance(0.06) {
				ver.conf = []string{w.target(i)}
			}

			if w.chance(0.05) {
				ver.brk = []string{w.target(i)}
			}

			if w.chance(0.18) {
				ver.prov = []string{vname(w.pick(virtuals))}
			}

			p.versions = append(p.versions, ver)
		}

		w.pkgs = append(w.pkgs, p)
		w.byN[p.name] = p
	}
}

func relName(r string) string {
	name, _, _ := strings.Cut(r, " ")

	return name
}

// satisfies reports whether a version meets a relation of the generated
// forms ("name", "name (>= V)", "name (<< V)") by its own name, or, for a
// virtual name, by a Provides.
func satisfies(p *pkg, v *version, r string) bool {
	name := relName(r)
	if name == p.name {
		switch {
		case strings.Contains(r, "(>= 1.0)"):
			return true
		case strings.Contains(r, "(>= 2.0)"):
			return v.ver >= "2.0"
		case strings.Contains(r, "(<< 2.0)"):
			return v.ver < "2.0"
		}

		return true
	}

	for _, pr := range v.prov {
		if pr == name && !strings.Contains(r, "(") {
			return true
		}
	}

	return false
}

type system struct {
	w      *world
	chosen map[string]*version
	roots  []string
}

// provides returns the packages that can meet a relation.
func (s *system) meets(r string) []*pkg {
	name := relName(r)

	var out []*pkg

	for _, p := range s.w.pkgs {
		for _, v := range p.versions {
			if satisfies(p, v, r) && (name == p.name || len(v.prov) > 0) {
				out = append(out, p)

				break
			}
		}
	}

	return out
}

// add installs p at a version and what its Depends need; false when it cannot
// be done consistently.
func (s *system) add(p *pkg, depth int) bool {
	if _, ok := s.chosen[p.name]; ok {
		return true
	}

	if depth > 8 {
		return false
	}

	v := p.versions[len(p.versions)-1]
	if len(p.versions) > 1 && s.w.chance(0.35) {
		v = p.versions[0]
	}

	s.chosen[p.name] = v

	if !s.conflictFree(p, v) {
		delete(s.chosen, p.name)

		return false
	}

	for _, g := range v.deps {
		ok := false

		for _, alt := range g {
			if s.metBy(alt) {
				ok = true

				break
			}
		}

		if ok {
			continue
		}

		for _, alt := range g {
			for _, c := range s.meets(alt) {
				if c.name == p.name {
					continue
				}

				if s.add(c, depth+1) && s.metBy(alt) {
					ok = true

					break
				}
			}

			if ok {
				break
			}
		}

		if !ok {
			delete(s.chosen, p.name)

			return false
		}
	}

	return true
}

func (s *system) metBy(r string) bool {
	for name, v := range s.chosen {
		if satisfies(s.w.byN[name], v, r) {
			return true
		}
	}

	return false
}

func (s *system) conflictFree(p *pkg, v *version) bool {
	check := func(owner string, ov *version) bool {
		for _, r := range append(append([]string{}, ov.conf...), ov.brk...) {
			for name, cv := range s.chosen {
				if name != owner && satisfies(s.w.byN[name], cv, r) {
					return false
				}
			}
		}

		return true
	}

	if !check(p.name, v) {
		return false
	}

	for name, cv := range s.chosen {
		if name != p.name && !check(name, cv) {
			return false
		}
	}

	return true
}

// consistent reports whether every Depends of every installed version is met.
func (s *system) consistent() bool {
	for name, v := range s.chosen {
		for _, g := range v.deps {
			ok := false

			for _, alt := range g {
				ok = ok || s.metBy(alt)
			}

			if !ok {
				return false
			}
		}

		if !s.conflictFree(s.w.byN[name], v) {
			return false
		}
	}

	return true
}

func render(sb *strings.Builder, p *pkg, v *version, status string) {
	fmt.Fprintf(sb, "Package: %s\n", p.name)

	if status != "" {
		fmt.Fprintf(sb, "Status: %s\n", status)
	}

	fmt.Fprintf(sb, "Version: %s\nArchitecture: amd64\nMaintainer: Test <test@example.org>\n", v.ver)

	if p.essential {
		sb.WriteString("Essential: yes\n")
	}

	fmt.Fprintf(sb, "Priority: %s\nSection: %s\n", v.prio, v.section)

	join := func(field string, groups [][]string) {
		if len(groups) == 0 {
			return
		}

		parts := make([]string, len(groups))
		for i, g := range groups {
			parts[i] = strings.Join(g, " | ")
		}

		fmt.Fprintf(sb, "%s: %s\n", field, strings.Join(parts, ", "))
	}

	join("Depends", v.deps)
	join("Recommends", v.recs)
	join("Suggests", v.sugs)

	flat := func(field string, rels []string) {
		if len(rels) > 0 {
			fmt.Fprintf(sb, "%s: %s\n", field, strings.Join(rels, ", "))
		}
	}

	flat("Conflicts", v.conf)
	flat("Breaks", v.brk)
	flat("Provides", v.prov)

	fmt.Fprintf(sb, "Description: %s test package\n\n", p.name)
}

func (w *world) write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// A consistent installed system.
	var s *system

	for {
		s = &system{w: w, chosen: map[string]*version{}}

		for attempts := 0; len(s.roots) < rootCount && attempts < 400; attempts++ {
			p := w.pkgs[w.pick(packageCount)]
			if _, ok := s.chosen[p.name]; ok {
				continue
			}

			snapshot := map[string]*version{}
			for k, v := range s.chosen {
				snapshot[k] = v
			}

			if s.add(p, 0) {
				s.roots = append(s.roots, p.name)
			} else {
				s.chosen = snapshot
			}
		}

		if len(s.roots) > 0 && s.consistent() {
			break
		}

		s.roots = nil
	}

	var repo, status, auto strings.Builder

	for _, p := range w.pkgs {
		for _, v := range p.versions {
			render(&repo, p, v, "")
		}
	}

	names := make([]string, 0, len(s.chosen))
	for n := range s.chosen {
		names = append(names, n)
	}

	sort.Strings(names)

	held := ""
	if w.chance(0.3) {
		held = names[w.pick(len(names))]
	}

	isRoot := map[string]bool{}
	for _, r := range s.roots {
		isRoot[r] = true
	}

	for _, n := range names {
		st := "install ok installed"
		if n == held {
			st = "hold ok installed"
		}

		render(&status, w.byN[n], s.chosen[n], st)

		if (!isRoot[n] && w.chance(0.9)) || (isRoot[n] && w.chance(0.1)) {
			fmt.Fprintf(&auto, "Package: %s\nArchitecture: amd64\nAuto-Installed: 1\n\n", n)
		}
	}

	var sc strings.Builder

	sc.WriteString("# id\tapt-get arguments\n")

	flags := []string{"", " --install-recommends", " --install-recommends --install-suggests", " --install-suggests"}
	pickp := func() string { return pname(w.pick(packageCount)) }
	picki := func() string { return names[w.pick(len(names))] }

	for i := 1; i <= scenarios; i++ {
		id := fmt.Sprintf("x%02d", i)

		var cmd string

		switch k := w.pick(20); {
		case k < 7:
			cmd = "install " + pickp() + flags[w.pick(len(flags))]
		case k < 9:
			cmd = "install " + pickp() + " " + pickp() + flags[w.pick(len(flags))]
		case k < 11:
			cmd = "install " + picki() + flags[w.pick(len(flags))]
		case k < 13:
			cmd = "remove " + picki()
		case k < 15:
			cmd = "remove " + picki() + " --auto-remove"
		case k < 16:
			cmd = "autoremove"
		case k < 17:
			cmd = "autoremove -oAPT::AutoRemove::RecommendsImportant=false"
		case k < 18:
			cmd = "autoremove -oAPT::AutoRemove::SuggestsImportant=false"
		case k < 19:
			cmd = []string{"upgrade", "upgrade --with-new-pkgs", "dist-upgrade"}[w.pick(3)] + flags[w.pick(len(flags))]
		default:
			cmd = "install " + pickp() + " --auto-remove" + flags[w.pick(len(flags))]
		}

		fmt.Fprintf(&sc, "%s\t%s\n", id, cmd)
	}

	files := map[string]string{
		"Packages":        strings.TrimSuffix(repo.String(), "\n"),
		"status":          strings.TrimSuffix(status.String(), "\n"),
		"extended_states": auto.String(),
		"scenarios.txt":   sc.String(),
	}

	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text+"\n"), 0o644); err != nil {
			return err
		}
	}

	return nil
}
