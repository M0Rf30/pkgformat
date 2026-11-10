// Command trim cuts the Packages indexes of a distribution down to what the
// differential test needs: every version of every package in the dependency
// closure of the targets, following all alternatives and every provider of a
// virtual package, plus the packages those declare a Conflicts or Breaks on
// and the packages that declare one on them. The stanzas are copied verbatim.
//
// It is run by generate.sh, not by the tests.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
)

type stanza struct {
	deb.Stanza

	file      string
	depends   []string // every name a Depends or Pre-Depends mentions
	negations []string // every name a Conflicts or Breaks mentions
	provides  []string
}

func main() {
	listsDir := flag.String("lists", "", "directory with the plain Packages indexes")
	statusFile := flag.String("status", "", "dpkg status file")
	targetsFile := flag.String("targets", "", "file with one target per line")
	outDir := flag.String("out", "", "directory to write the trimmed indexes to")
	flag.Parse()

	if err := run(*listsDir, *statusFile, *targetsFile, *outDir); err != nil {
		fmt.Fprintln(os.Stderr, "trim:", err)
		os.Exit(1)
	}
}

func run(listsDir, statusFile, targetsFile, outDir string) error {
	targets, err := readLines(targetsFile)
	if err != nil {
		return err
	}

	files, err := filepath.Glob(filepath.Join(listsDir, "*_Packages"))
	if err != nil {
		return err
	}

	slices.Sort(files)

	var all []*stanza

	byName := map[string][]*stanza{}
	byProvide := map[string][]*stanza{}

	for _, file := range files {
		if err := scan(file, func(s *stanza) {
			all = append(all, s)
			byName[s.Package] = append(byName[s.Package], s)

			for _, name := range s.provides {
				byProvide[name] = append(byProvide[name], s)
			}
		}); err != nil {
			return err
		}
	}

	keep := map[*stanza]bool{}

	var queue []string

	seenName := map[string]bool{}
	want := func(name string) {
		if !seenName[name] {
			seenName[name] = true

			queue = append(queue, name)
		}
	}

	for _, t := range targets {
		if len(byName[t]) == 0 {
			return fmt.Errorf("target %q is not in the index", t)
		}

		want(t)
	}

	// Follow dependencies: all versions of the name, all providers of it.
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]

		for _, s := range slices.Concat(byName[name], byProvide[name]) {
			if keep[s] {
				continue
			}

			keep[s] = true

			for _, dep := range s.depends {
				want(dep)
			}
		}
	}

	// Conflicts and Breaks: the packages they name, without their closure, and
	// the packages that name something kept.
	names := map[string]bool{}

	for s := range keep {
		names[s.Package] = true

		for _, p := range s.provides {
			names[p] = true
		}
	}

	for s := range keep {
		for _, neg := range s.negations {
			for _, other := range slices.Concat(byName[neg], byProvide[neg]) {
				keep[other] = true
			}
		}
	}

	for _, s := range all {
		if keep[s] {
			continue
		}

		if slices.ContainsFunc(s.negations, func(n string) bool { return names[n] }) {
			keep[s] = true
		}
	}

	return write(outDir, files, all, keep, statusFile)
}

func scan(file string, add func(*stanza)) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()

	return deb.ScanPackages(f, func(raw deb.Stanza) error {
		cf, err := deb.ParseControlFile(strings.NewReader(raw.Text))
		if err != nil {
			return fmt.Errorf("%s: %s: %w", file, raw.Package, err)
		}

		s := &stanza{Stanza: raw, file: file}

		for _, field := range []string{"Depends", "Pre-Depends"} {
			groups, err := deb.ParseRelations(cf.Get(field))
			if err != nil {
				return fmt.Errorf("%s: %s: %s: %w", file, raw.Package, field, err)
			}

			for _, alts := range groups {
				for _, rel := range alts {
					s.depends = append(s.depends, rel.Name)
				}
			}
		}

		for _, field := range []string{"Conflicts", "Breaks"} {
			groups, err := deb.ParseRelations(cf.Get(field))
			if err != nil {
				return fmt.Errorf("%s: %s: %s: %w", file, raw.Package, field, err)
			}

			for _, alts := range groups {
				for _, rel := range alts {
					s.negations = append(s.negations, rel.Name)
				}
			}
		}

		groups, err := deb.ParseRelations(cf.Get("Provides"))
		if err != nil {
			return fmt.Errorf("%s: %s: Provides: %w", file, raw.Package, err)
		}

		for _, alts := range groups {
			for _, rel := range alts {
				s.provides = append(s.provides, rel.Name)
			}
		}

		add(s)

		return nil
	})
}

func write(outDir string, files []string, all []*stanza, keep map[*stanza]bool, statusFile string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	total := 0

	for _, file := range files {
		var sb strings.Builder

		for _, s := range all {
			if s.file == file && keep[s] {
				sb.WriteString(s.Text)

				total++
			}
		}

		if sb.Len() == 0 {
			continue
		}

		if err := os.WriteFile(filepath.Join(outDir, filepath.Base(file)), []byte(sb.String()), 0o644); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stderr, "trim: kept %d of %d stanzas (status: %s)\n", total, len(all), statusFile)

	return nil
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var out []string

	for line := range strings.SplitSeq(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}

	return out, nil
}
