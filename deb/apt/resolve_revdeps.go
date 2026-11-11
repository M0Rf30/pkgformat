package apt

import (
	"slices"

	"github.com/M0Rf30/pkgformat/deb"
)

// apt lists the reverse dependencies of a package in an order that the order
// of unpacking and removal depends on (for two packages both to be removed,
// which of the two it removes first). The order is not "newest first" but
// falls out of how its cache generator links a new dependency record, which
// revIndex reproduces: it reads every version of the cache in the order the
// indexes gave them and links each dependency the way
// pkgCacheGenerator::NewDepends does.

// revRec is one dependency record of one version, in a reverse list.
type revRec struct {
	owner *pkg
	kind  depKind
	// gi is the place of the group among the groups of the version (the
	// critical ones for Pre-Depends, Depends, Conflicts and Breaks, the soft
	// ones for Recommends and Suggests); alt the alternative within it.
	gi, alt int32
	// next is the next record of the list, -1 at its end.
	next int32
}

// revData is what apt compares to tell two dependencies on a package alike:
// the version operand (as its place in the string pool), the type, the
// operator and whether another alternative follows.
type revData struct {
	rank int32
	kind depKind
	op   string
	or   bool
}

// revIndex holds the reverse dependency lists of a whole cache.
type revIndex struct {
	gen   int
	recs  []revRec
	heads map[string]int32
	chain map[string][]revData
}

// revIndex returns the reverse dependency index of the cache, building it
// when the versions changed since the last one. c.mu must be held for reading.
func (c *Cache) revIndex() *revIndex {
	c.revMu.Lock()
	defer c.revMu.Unlock()

	if c.rev != nil && c.rev.gen == c.gen {
		return c.rev
	}

	c.rev = c.buildRevIndex()

	return c.rev
}

func (c *Cache) buildRevIndex() *revIndex {
	var versions []*pkg

	for _, vs := range c.slots {
		versions = append(versions, vs...)
	}

	// The order the versions were read in.
	slices.SortFunc(versions, func(a, b *pkg) int { return a.seq - b.seq })

	idx := &revIndex{
		gen:   c.gen,
		heads: make(map[string]int32),
		chain: make(map[string][]revData),
	}

	rank := make(map[string]int32)
	rankOf := func(s string) int32 {
		if s == "" {
			return 0
		}

		r, ok := rank[s]
		if !ok {
			r = int32(len(rank)) + 1
			rank[s] = r
		}

		return r
	}

	link := func(owner *pkg, kind depKind, gi, alt int, rel *deb.Relation, or bool) {
		op := rel.Op

		switch op {
		case "<":
			op = "<="
		case ">":
			op = ">="
		}

		data := revData{rank: rankOf(rel.Version), kind: kind, op: op, or: or}
		key := c.relTarget(rel, ownerArchOf(owner, c.hostArch))

		idx.add(key, revRec{owner: owner, kind: kind, gi: int32(gi), alt: int32(alt), next: -1}, data)
	}

	for _, v := range versions {
		rankOf(v.Version)

		gi := 0

		each := func(kind depKind, alts []deb.Alternatives) {
			for _, a := range alts {
				for i := range a {
					link(v, kind, gi, i, &a[i], i < len(a)-1)
				}

				gi++
			}
		}

		each(kindPreDepends, v.PreDepends)
		each(kindDepends, v.Depends)

		for _, kind := range []depKind{kindConflicts, kindBreaks} {
			rels := v.Conflicts
			if kind == kindBreaks {
				rels = v.Breaks
			}

			for i := range rels {
				link(v, kind, gi, 0, &rels[i], false)

				gi++
			}
		}

		gi = 0

		each(kindRecommends, v.Recommends)
		each(kindSuggests, v.Suggests)
	}

	return idx
}

// ownerArchOf is the architecture a dependency of p is read for.
func ownerArchOf(p *pkg, native string) string {
	if p.Architecture == "" || p.Architecture == archAll {
		return native
	}

	return p.Architecture
}

// add links a record the way pkgCacheGenerator::NewDepends does: at the head
// of the list when its data sorts first in the chain of distinct data, else
// right after the head.
func (idx *revIndex) add(key string, r revRec, data revData) {
	chain := idx.chain[key]
	dup, prev := false, -1

	for i, c := range chain {
		if data.rank > c.rank {
			break
		}

		if c == data {
			dup = true

			break
		}

		prev = i
	}

	if !dup {
		idx.chain[key] = slices.Insert(chain, prev+1, data)
	}

	n := int32(len(idx.recs))
	head, ok := idx.heads[key]

	if ok && (dup || prev >= 0) {
		r.next = idx.recs[head].next
		idx.recs[head].next = n
	} else {
		r.next = -1
		if ok {
			r.next = head
		}

		idx.heads[key] = n
	}

	idx.recs = append(idx.recs, r)
}

// list returns the records of a package's list in order, those of installed
// versions only: the ordering never acts on the others.
func (idx *revIndex) list(key string, installed func(*pkg) bool, fn func(revRec)) {
	head, ok := idx.heads[key]
	if !ok {
		return
	}

	for i := head; i >= 0; i = idx.recs[i].next {
		if r := idx.recs[i]; installed(r.owner) {
			fn(r)
		}
	}
}
