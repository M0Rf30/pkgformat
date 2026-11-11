package apk

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// ErrInvalidWorld is wrapped by the errors of [ParseWorld] and [WorldAdd].
var ErrInvalidWorld = errors.New("apk: invalid world")

// Limits of ParseWorld.
const (
	maxWorldBytes   = 1 << 20
	maxWorldEntries = 100_000
)

// ParseWorld reads the world file of an apk system (/etc/apk/world): the
// dependencies the user asked for, separated by white space or newlines, each
// "name", "name@tag", "name>=1.2", "!name" and so on. Every entry is checked
// with [ParseDependency]. It reads at most 1 MiB and 100 000 entries.
func ParseWorld(r io.Reader) ([]string, error) {
	sc := bufio.NewScanner(io.LimitReader(r, maxWorldBytes+1))
	sc.Buffer(make([]byte, 0, 4096), maxWorldBytes+1)
	sc.Split(bufio.ScanWords)

	var (
		out  []string
		read int
	)

	for sc.Scan() {
		word := sc.Text()

		read += len(word) + 1
		if read > maxWorldBytes {
			return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidWorld, maxWorldBytes)
		}

		if _, err := ParseDependency(word); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidWorld, err)
		}

		if len(out) >= maxWorldEntries {
			return nil, fmt.Errorf("%w: more than %d entries", ErrInvalidWorld, maxWorldEntries)
		}

		out = append(out, word)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidWorld, err)
	}

	return out, nil
}

// worldKey is what identifies an entry: its name.
func worldKey(entry string) string {
	d, err := ParseDependency(entry)
	if err != nil {
		return entry
	}

	return d.Name
}

// WorldAdd returns world with the entries added the way "apk add" does: an
// entry replaces the one of the same package name, a conflict ("!name")
// included, and is added when there is none. The result is in the order of
// world, new entries last.
func WorldAdd(world []string, add ...string) ([]string, error) {
	out := slices.Clone(world)

	for _, e := range add {
		d, err := ParseDependency(e)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidWorld, err)
		}

		i := slices.IndexFunc(out, func(x string) bool { return worldKey(x) == d.Name })
		if i >= 0 {
			out[i] = e

			continue
		}

		out = append(out, e)
	}

	return out, nil
}

// WorldDel returns world without the entries for the given package names, as
// "apk del" does. A name may carry a version constraint or tag; only the name
// counts.
func WorldDel(world []string, names ...string) []string {
	drop := make(map[string]bool, len(names))

	for _, n := range names {
		drop[worldKey(n)] = true
	}

	var out []string

	for _, e := range world {
		if !drop[worldKey(e)] {
			out = append(out, e)
		}
	}

	return out
}

// RenderWorld renders the world file: one entry per line, sorted by name, as
// apk writes it.
func RenderWorld(world []string) []byte {
	sorted := slices.Clone(world)
	slices.SortStableFunc(sorted, func(a, b string) int { return strings.Compare(worldKey(a), worldKey(b)) })

	var b strings.Builder

	for _, e := range sorted {
		b.WriteString(e)
		b.WriteByte('\n')
	}

	return []byte(b.String())
}
