package rpmdb_test

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/richdep"
	"github.com/M0Rf30/pkgformat/rpm/rpmdb"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// The rich fixture is built by testdata/rich/build.sh; testdata/README.md says
// what it holds. Its records are keyed by NEVRA.
const richFixture = "rich.sqlite"

// richPackage is what rpm printed for one package of the rich fixture.
type richPackage struct {
	epoch, version, release, arch, installTime string

	deps         map[string][][]string // record letter: name, flags, version
	files        [][]string
	states       map[string]string // path: file state
	scriptFlags  []string          // nine, in the order of the X record
	triggerFlags map[string][]string
	priorities   map[string][]string
}

func loadRich(t testing.TB) (order []string, pkgs map[string]*richPackage) {
	t.Helper()

	f, err := os.Open(filepath.Join("testdata", richFixture+".expected"))
	require.NoError(t, err)

	defer f.Close()

	pkgs = map[string]*richPackage{}
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)

	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		require.GreaterOrEqual(t, len(fields), 3, sc.Text())

		if fields[0] == "P" {
			require.Len(t, fields, 7)

			p := &richPackage{
				epoch: fields[2], version: fields[3], release: fields[4], arch: fields[5], installTime: fields[6],
				deps: map[string][][]string{}, states: map[string]string{},
				triggerFlags: map[string][]string{}, priorities: map[string][]string{},
			}
			pkgs[fields[1]] = p
			order = append(order, fields[1])

			continue
		}

		p := pkgs[fields[1]]
		require.NotNil(t, p, sc.Text())

		switch fields[0] {
		case "D", "Q", "C", "O", "W", "S", "U", "E":
			require.Len(t, fields, 5)
			p.deps[fields[0]] = append(p.deps[fields[0]], fields[2:])
		case "F":
			require.Len(t, fields, 11)
			p.files = append(p.files, fields[2:])
		case "N":
			require.Len(t, fields, 4)
			p.states[fields[2]] = fields[3]
		case "X":
			require.Len(t, fields, 11)
			p.scriptFlags = fields[2:]
		case "T":
			require.Len(t, fields, 5)
			p.triggerFlags[fields[2]] = append(p.triggerFlags[fields[2]], fields[3])
			p.priorities[fields[2]] = append(p.priorities[fields[2]], fields[4])
		default:
			t.Fatalf("unknown record %q", fields[0])
		}
	}

	require.NoError(t, sc.Err())

	return order, pkgs
}

// nevra writes a package like rpm's %{NEVRA}.
func nevra(p *rpm.Package) string {
	e := ""
	if p.Epoch != 0 {
		e = strconv.FormatUint(uint64(p.Epoch), 10) + ":"
	}

	return fmt.Sprintf("%s-%s%s-%s.%s", p.Name, e, p.Version, p.Release, p.Arch)
}

func nevras(pkgs []*rpm.Package) []string {
	out := make([]string, len(pkgs))
	for i, p := range pkgs {
		out[i] = nevra(p)
	}

	slices.Sort(out)

	return out
}

func openRich(t testing.TB, opts rpmdb.Options) *rpmdb.DB {
	t.Helper()

	db, err := rpmdb.Open(copyFixture(t, richFixture), opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	return db
}

func TestRichPackagesMatchRpm(t *testing.T) {
	order, want := loadRich(t)
	db := openRich(t, rpmdb.Options{})

	pkgs, err := db.InstalledPackages(t.Context())
	require.NoError(t, err)
	require.Len(t, pkgs, len(want))

	for _, p := range pkgs {
		key := nevra(p)
		exp := want[key]
		require.NotNil(t, exp, key)

		assert.Equal(t, exp.epoch, strconv.FormatUint(uint64(p.Epoch), 10), key)
		assert.Equal(t, exp.version, p.Version, key)
		assert.Equal(t, exp.release, p.Release, key)
		assert.Equal(t, exp.arch, p.Arch, key)
		assert.Equal(t, exp.installTime, strconv.FormatInt(p.InstallTime, 10), key)

		for letter, list := range map[string][]rpm.Dependency{
			"D": p.Provides, "Q": p.Requires, "C": p.Conflicts, "O": p.Obsoletes,
			"W": p.Recommends, "S": p.Suggests, "U": p.Supplements, "E": p.Enhances,
		} {
			assert.Equal(t, orNil(exp.deps[letter]), orNil(depStrings(list)), "%s %s", key, letter)
		}

		assert.Equal(t, orNil(exp.files), orNil(fileStrings(p.Files)), key)
	}

	// Sorted by name, then version, then architecture.
	names := nevras(pkgs)
	slices.Sort(order)
	assert.Equal(t, order, names)

	for i := 1; i < len(pkgs); i++ {
		assert.LessOrEqual(t, pkgs[i-1].Name, pkgs[i].Name)
	}

	// qdb-lib: 1.4 before 1.5, i686 before x86_64.
	var libs []string

	for _, p := range pkgs {
		if p.Name == "qdb-lib" {
			libs = append(libs, p.Version+"."+p.Arch)
		}
	}

	assert.Equal(t, []string{"1.4.x86_64", "1.5.i686", "1.5.x86_64"}, libs)

	// The slice is the caller's; the index is not touched by changing it.
	pkgs[0] = nil

	again, err := db.InstalledPackages(t.Context())
	require.NoError(t, err)
	assert.NotNil(t, again[0])
}

// scriptSections splits rich.sqlite.scripts by its "### NEVRA" headings.
func scriptSections(t *testing.T) map[string]string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", richFixture+".scripts"))
	require.NoError(t, err)

	sections := map[string]string{}

	var key string

	for _, line := range strings.SplitAfter(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "### "); ok {
			key = strings.TrimSpace(rest)
			sections[key] = ""

			continue
		}

		sections[key] += line
	}

	return sections
}

func flagStrings(s *rpmdb.Scripts) []string {
	var out []string

	for _, sc := range []*rpmdb.Scriptlet{
		s.PreTrans, s.PreIn, s.PostIn, s.PreUn, s.PostUn, s.PostTrans, s.PreUnTrans, s.PostUnTrans, s.Verify,
	} {
		if sc == nil || sc.Flags == 0 {
			out = append(out, "(none)")
		} else {
			out = append(out, strconv.FormatUint(uint64(sc.Flags), 10))
		}
	}

	return out
}

func TestScriptsMatchRpm(t *testing.T) {
	_, want := loadRich(t)
	sections := scriptSections(t)
	db := openRich(t, rpmdb.Options{})

	seen := 0

	for ps, err := range db.AllScripts(t.Context()) {
		require.NoError(t, err)

		seen++
		key := nevra(ps.Package)
		exp := want[key]
		require.NotNil(t, exp, key)

		// The text is what rpm -q --scripts --triggers --filetriggers prints.
		assert.Equal(t, sections[key], ps.Scripts.String(), key)

		// What the text does not show.
		assert.Equal(t, exp.scriptFlags, flagStrings(ps.Scripts), key)

		var flags, prios []string

		for _, tr := range ps.Scripts.Triggers {
			flags = append(flags, flagOf(tr.Script.Flags))
		}

		assert.Equal(t, zeroFlags(exp.triggerFlags["trigger"]), orNil(flags), key)

		for kind, list := range map[string][]rpmdb.FileTrigger{
			"filetrigger": ps.Scripts.FileTriggers, "transfiletrigger": ps.Scripts.TransFileTriggers,
		} {
			flags, prios = nil, nil

			for _, ft := range list {
				flags = append(flags, flagOf(ft.Script.Flags))
				prios = append(prios, strconv.Itoa(int(ft.Priority)))
			}

			assert.Equal(t, zeroFlags(exp.triggerFlags[kind]), orNil(flags), key+" "+kind)
			assert.Equal(t, orNil(exp.priorities[kind]), orNil(prios), key+" "+kind)
		}

		// Looking one up gives the same.
		one, err := db.Scripts(t.Context(), ps.Package)
		require.NoError(t, err)
		assert.Equal(t, ps.Scripts, one, key)
	}

	assert.Len(t, want, seen)
}

// zeroFlags reads rpm's "0" (a flags array that holds a zero) and "(none)" (no
// array) alike: a Scriptlet has the one value, 0, for both.
func zeroFlags(in []string) []string {
	var out []string

	for _, f := range in {
		if f == "0" {
			f = "(none)"
		}

		out = append(out, f)
	}

	return orNil(out)
}

func flagOf(f uint32) string {
	if f == 0 {
		return "(none)"
	}

	return strconv.FormatUint(uint64(f), 10)
}

func TestScriptsOfBase(t *testing.T) {
	db := openRich(t, rpmdb.Options{})

	pkgs, err := db.ByName(t.Context(), "qdb-base")
	require.NoError(t, err)
	require.Len(t, pkgs, 1)

	s, err := db.Scripts(t.Context(), pkgs[0])
	require.NoError(t, err)

	require.NotNil(t, s.PreTrans)
	assert.Contains(t, s.PreTrans.Body, `print("pretrans of qdb-base")`)
	assert.Equal(t, []string{"<lua>"}, s.PreTrans.Prog)
	assert.Zero(t, s.PreTrans.Flags)
	assert.Equal(t, []string{"/bin/sh"}, s.PreIn.Prog)
	assert.Equal(t, uint32(tag.RPMSCRIPT_FLAG_EXPAND), s.PostIn.Flags)
	assert.Equal(t, uint32(tag.RPMSCRIPT_FLAG_QFORMAT), s.PreUn.Flags)
	assert.Equal(t, uint32(tag.RPMSCRIPT_FLAG_EXPAND|tag.RPMSCRIPT_FLAG_QFORMAT), s.PostUnTrans.Flags)

	// A scriptlet that only names a program has no body.
	require.NotNil(t, s.PostUn)
	assert.Empty(t, s.PostUn.Body)
	assert.Equal(t, []string{"/sbin/ldconfig"}, s.PostUn.Prog)

	require.Len(t, s.Triggers, 4)

	kinds := []rpmdb.TriggerKind{rpmdb.TriggerPreIn, rpmdb.TriggerIn, rpmdb.TriggerUn, rpmdb.TriggerPostUn}
	for i, tr := range s.Triggers {
		assert.Equal(t, kinds[i], tr.Kind, i)
	}

	require.Len(t, s.Triggers[1].Conditions, 2)
	assert.Equal(t, "qdb-lib", s.Triggers[1].Conditions[0].Name)
	assert.Equal(t, "1.0", s.Triggers[1].Conditions[0].Version)
	assert.Equal(t, "qdb-x", s.Triggers[1].Conditions[1].Name)
	assert.Equal(t, "in", s.Triggers[1].Kind.String())

	require.Len(t, s.FileTriggers, 3)
	assert.Equal(t, []string{"/usr/lib/qdb", "/usr/share/qdb-extra"}, s.FileTriggers[1].Prefixes)
	assert.Equal(t, []string{"/bin/bash"}, s.FileTriggers[1].Script.Prog)
	assert.Equal(t, int32(100), s.FileTriggers[0].Priority)
	assert.Equal(t, rpmdb.TriggerPostUn, s.FileTriggers[2].Kind)

	require.Len(t, s.TransFileTriggers, 3)
	assert.Equal(t, int32(5000), s.TransFileTriggers[0].Priority)

	// A package without scripts has none.
	libs, err := db.ByName(t.Context(), "qdb-lib")
	require.NoError(t, err)

	none, err := db.Scripts(t.Context(), libs[0])
	require.NoError(t, err)
	assert.Equal(t, &rpmdb.Scripts{}, none)
	assert.Empty(t, none.String())
}

func TestScriptsErrors(t *testing.T) {
	db := openRich(t, rpmdb.Options{})

	_, err := db.Scripts(t.Context(), nil)
	require.ErrorIs(t, err, rpmdb.ErrInvalidQuery)

	_, err = db.Scripts(t.Context(), &rpm.Package{Name: "nosuch", Version: "1", Release: "1"})
	require.ErrorIs(t, err, rpmdb.ErrNotFound)

	// The same name and version at another install time is another package.
	pkgs, err := db.ByName(t.Context(), "qdb-old")
	require.NoError(t, err)

	other := *pkgs[0]
	other.InstallTime++

	_, err = db.Scripts(t.Context(), &other)
	require.ErrorIs(t, err, rpmdb.ErrNotFound)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = db.Scripts(ctx, pkgs[0])
	require.ErrorIs(t, err, context.Canceled)

	for _, err := range db.AllScripts(ctx) {
		require.ErrorIs(t, err, context.Canceled)
	}

	// A package over the limits of Options.Package is skipped, with its scripts.
	small := openRich(t, rpmdb.Options{Package: rpm.PackageLimits{MaxArrayEntries: 3}})

	for ps, err := range small.AllScripts(t.Context()) {
		require.NoError(t, err)
		assert.NotEqual(t, "qdb-base", ps.Package.Name)
	}

	// An early stop releases the iteration.
	for range db.AllScripts(t.Context()) {
		break
	}
}

// queryLine is one line of rich.sqlite.queries.
type queryLine struct{ kind, arg, result string }

func loadQueries(t testing.TB) []queryLine {
	t.Helper()

	f, err := os.Open(filepath.Join("testdata", richFixture+".queries"))
	require.NoError(t, err)

	defer f.Close()

	var out []queryLine

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.SplitN(sc.Text(), "\t", 3)
		require.Len(t, fields, 3, sc.Text())
		out = append(out, queryLine{fields[0], fields[1], fields[2]})
	}

	require.NoError(t, sc.Err())

	return out
}

// run answers a query line with the library.
func (q queryLine) run(ctx context.Context, t testing.TB, db *rpmdb.DB) []*rpm.Package {
	t.Helper()

	kind := strings.TrimPrefix(q.kind, "v:")

	var cap richdep.Atom

	if strings.HasPrefix(q.kind, "v:") {
		var err error

		cap, err = rpmdb.ParseCapability(q.arg)
		require.NoError(t, err, q.arg)
	} else {
		// What the command line gives rpm: a name as it is.
		cap = richdep.Atom{Name: q.arg}
	}

	var (
		pkgs []*rpm.Package
		err  error
	)

	switch kind {
	case "label":
		pkgs, err = db.ByLabel(ctx, q.arg)
	case "file":
		pkgs, err = db.FileOwners(ctx, q.arg)
	case "whatprovides", "provides":
		pkgs, err = db.WhatProvides(ctx, cap)
	case "whatrequires", "requires":
		pkgs, err = db.WhatRequires(ctx, cap)
	case "whatrecommends", "recommends":
		pkgs, err = db.WhatRecommends(ctx, cap)
	case "whatsuggests", "suggests":
		pkgs, err = db.WhatSuggests(ctx, cap)
	case "whatsupplements", "supplements":
		pkgs, err = db.WhatSupplements(ctx, cap)
	case "whatenhances", "enhances":
		pkgs, err = db.WhatEnhances(ctx, cap)
	case "whatconflicts", "conflicts":
		pkgs, err = db.WhatConflicts(ctx, cap)
	case "whatobsoletes", "obsoletes":
		pkgs, err = db.WhatObsoletes(ctx, cap)
	default:
		t.Fatalf("unknown query kind %q", q.kind)
	}

	require.NoError(t, err, "%s %s", q.kind, q.arg)

	return pkgs
}

func TestQueriesMatchRpm(t *testing.T) {
	db := openRich(t, rpmdb.Options{})
	queries := loadQueries(t)
	require.Greater(t, len(queries), 100)

	kinds := map[string]int{}

	for _, q := range queries {
		kinds[q.kind]++

		want := strings.Fields(q.result)
		slices.Sort(want)

		got := nevras(q.run(t.Context(), t, db))
		assert.Equal(t, orNil(want), orNil(got), "%s %s", q.kind, q.arg)
	}

	// Every kind of query is in the fixture.
	for _, k := range []string{
		"label", "file", "whatprovides", "whatrequires", "whatrecommends", "whatsuggests", "whatsupplements",
		"whatenhances", "whatconflicts", "whatobsoletes", "v:provides", "v:requires", "v:recommends",
		"v:enhances", "v:conflicts", "v:obsoletes",
	} {
		assert.Positive(t, kinds[k], k)
	}
}

func TestFileOwners(t *testing.T) {
	_, want := loadRich(t)
	db := openRich(t, rpmdb.Options{})

	owners := func(p string) []string {
		pkgs, err := db.FileOwners(t.Context(), p)
		require.NoError(t, err, p)

		return nevras(pkgs)
	}

	const base = "qdb-base-1:1.2.3-1.q1.noarch"

	// The path is cleaned: slashes, dots and a trailing slash, and a relative
	// path is taken from the root.
	for _, p := range []string{
		"/usr/share/qdb/a.txt", "/usr//share/qdb/a.txt", "/usr/share/qdb/./a.txt", "/usr/share/qdb/dir/../a.txt",
		"usr/share/qdb/a.txt", "/../usr/share/qdb/a.txt",
	} {
		assert.Equal(t, []string{base}, owners(p), p)
	}

	// Directories a package lists, its symbolic links and its ghosts.
	for _, p := range []string{"/usr/share/qdb/", "/usr/share/qdb/dir", "/usr/bin/qdb", "/var/lib/qdb/state"} {
		assert.Equal(t, []string{base}, owners(p), p)
	}

	assert.Empty(t, owners("/nonexistent"))
	assert.Empty(t, owners("/"))

	// Files in a state other than normal are not installed: qdb-x replaced
	// qdb-old's copy of one, which rpm -qf does not report for qdb-old.
	assert.Equal(t, "1", want["qdb-old-0.4-1.q1.noarch"].states["/usr/share/qdb/old.txt"])
	assert.Equal(t, []string{"qdb-x-3.1-1.q1.noarch"}, owners("/usr/share/qdb/old.txt"))

	all := openRich(t, rpmdb.Options{IncludeUninstalledFiles: true})

	pkgs, err := all.FileOwners(t.Context(), "/usr/share/qdb/old.txt")
	require.NoError(t, err)
	assert.Equal(t, []string{"qdb-old-0.4-1.q1.noarch", "qdb-x-3.1-1.q1.noarch"}, nevras(pkgs))

	for _, bad := range []string{"", "/a\x00b", strings.Repeat("a", 1<<17)} {
		_, err := db.FileOwners(t.Context(), bad)
		require.ErrorIs(t, err, rpmdb.ErrInvalidQuery)
	}
}

func TestByNameAndNEVRA(t *testing.T) {
	db := openRich(t, rpmdb.Options{})

	byName, err := db.ByName(t.Context(), "qdb-lib")
	require.NoError(t, err)
	assert.Equal(t, []string{"qdb-lib-1.4-1.q1.x86_64", "qdb-lib-1.5-2.q1.i686", "qdb-lib-1.5-2.q1.x86_64"}, nevras(byName))

	none, err := db.ByName(t.Context(), "qdb")
	require.NoError(t, err)
	assert.Empty(t, none)

	for _, tc := range []struct {
		n    rpm.NEVRA
		want []string
	}{
		{rpm.NEVRA{Name: "qdb-lib", Arch: "i686"}, []string{"qdb-lib-1.5-2.q1.i686"}},
		{rpm.NEVRA{Name: "qdb-lib", Version: "1.5"}, []string{"qdb-lib-1.5-2.q1.i686", "qdb-lib-1.5-2.q1.x86_64"}},
		{rpm.NEVRA{Name: "qdb-lib", Version: "1.5", Release: "2.q1", Arch: "x86_64"}, []string{"qdb-lib-1.5-2.q1.x86_64"}},
		{rpm.NEVRA{Name: "qdb-lib", Release: "1.q1"}, []string{"qdb-lib-1.4-1.q1.x86_64"}},
		{rpm.NEVRA{Name: "qdb-base", Epoch: "1"}, []string{"qdb-base-1:1.2.3-1.q1.noarch"}},
		{rpm.NEVRA{Name: "qdb-base", Epoch: "0"}, nil},
		{rpm.NEVRA{Name: "qdb-lib", Epoch: "0", Arch: "i686"}, []string{"qdb-lib-1.5-2.q1.i686"}},
		{rpm.NEVRA{Arch: "i686"}, []string{"qdb-lib-1.5-2.q1.i686"}},
		{rpm.NEVRA{Name: "nosuch"}, nil},
	} {
		got, err := db.ByNEVRA(t.Context(), tc.n)
		require.NoError(t, err, "%+v", tc.n)
		assert.Equal(t, orNil(tc.want), orNil(nevras(got)), "%+v", tc.n)
	}

	for _, bad := range []rpm.NEVRA{{Name: "a", Epoch: "x"}, {Name: "a\x00"}, {Version: strings.Repeat("v", 1<<17)}} {
		_, err := db.ByNEVRA(t.Context(), bad)
		require.ErrorIs(t, err, rpmdb.ErrInvalidQuery)
	}

	_, err = db.ByName(t.Context(), "")
	require.ErrorIs(t, err, rpmdb.ErrInvalidQuery)
}

func TestPackageRelations(t *testing.T) {
	db := openRich(t, rpmdb.Options{})

	one := func(name string) *rpm.Package {
		pkgs, err := db.ByName(t.Context(), name)
		require.NoError(t, err)
		require.NotEmpty(t, pkgs)

		return pkgs[0]
	}

	// qdb-base and qdb-old conflict, whichever way the entry is.
	got, err := db.ConflictsOf(t.Context(), one("qdb-old"))
	require.NoError(t, err)
	assert.Equal(t, []string{"qdb-base-1:1.2.3-1.q1.noarch"}, nevras(got))

	got, err = db.ConflictsOf(t.Context(), one("qdb-base"))
	require.NoError(t, err)
	assert.Equal(t, []string{"qdb-old-0.4-1.q1.noarch"}, nevras(got))

	got, err = db.ConflictsOf(t.Context(), one("qdb-x"))
	require.NoError(t, err)
	assert.Empty(t, got)

	// A package that is not installed, by what it provides and conflicts with.
	got, err = db.ConflictsOf(t.Context(), &rpm.Package{
		Name: "newcomer", Version: "1", Release: "1",
		Provides:  []rpm.Dependency{{Name: "qdb-clash", Flags: tag.RPMSENSE_EQUAL, Version: "9"}},
		Conflicts: []rpm.Dependency{{Name: "qdb-lib", Flags: tag.RPMSENSE_LESS, Version: "1.5"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"qdb-base-1:1.2.3-1.q1.noarch", "qdb-lib-1.4-1.q1.x86_64"}, nevras(got))

	// Obsoletes: by the name and version of the obsoleted package.
	got, err = db.ObsoletedBy(t.Context(), &rpm.Package{Name: "qdb-ancient", Version: "1.0", Release: "1"})
	require.NoError(t, err)
	assert.Equal(t, []string{"qdb-base-1:1.2.3-1.q1.noarch", "qdb-old-0.4-1.q1.noarch"}, nevras(got))

	got, err = db.ObsoletedBy(t.Context(), &rpm.Package{Name: "qdb-ancient", Version: "2.0", Release: "1"})
	require.NoError(t, err)
	assert.Equal(t, []string{"qdb-base-1:1.2.3-1.q1.noarch"}, nevras(got), "the entry of qdb-old stops at = 1.0")

	got, err = db.ObsoletedBy(t.Context(), one("qdb-base"))
	require.NoError(t, err)
	assert.Empty(t, got)

	got, err = db.ObsoletesOf(t.Context(), &rpm.Package{
		Name: "newcomer", Version: "1", Release: "1",
		Obsoletes: []rpm.Dependency{{Name: "qdb-lib", Flags: tag.RPMSENSE_LESS, Version: "1.5"}, {Name: "qdb-x"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"qdb-lib-1.4-1.q1.x86_64", "qdb-x-3.1-1.q1.noarch"}, nevras(got))

	// A package never obsoletes or conflicts with itself.
	got, err = db.ObsoletesOf(t.Context(), &rpm.Package{
		Name: "qdb-x", Version: "3.1", Release: "1.q1", Arch: "noarch", Obsoletes: []rpm.Dependency{{Name: "qdb-x"}},
	})
	require.NoError(t, err)
	assert.Empty(t, got)

	for _, fn := range []func(context.Context, *rpm.Package) ([]*rpm.Package, error){
		db.ConflictsOf, db.ObsoletedBy, db.ObsoletesOf,
	} {
		_, err := fn(t.Context(), nil)
		require.ErrorIs(t, err, rpmdb.ErrInvalidQuery)
	}
}

func TestVersionAwareProvides(t *testing.T) {
	db := openRich(t, rpmdb.Options{})

	for _, tc := range []struct {
		q    string
		want []string
	}{
		// qdb-base provides qdb-virt = 2.0-1 and qdb-multi = 1:3.0, the
		// others of qdb-virt are 1.0-1 (qdb-lib) and 0.4 (qdb-old).
		{"qdb-virt >= 1.5", []string{"qdb-base-1:1.2.3-1.q1.noarch"}},
		{"qdb-virt >= 2.0", []string{"qdb-base-1:1.2.3-1.q1.noarch"}},
		{"qdb-virt > 2.0-1", nil},
		{"qdb-virt < 1.0", []string{"qdb-old-0.4-1.q1.noarch"}},
		// A request without an epoch is met by a provide with a nonzero one,
		// which is the later, as in librpm.
		{"qdb-multi > 3.0", []string{"qdb-base-1:1.2.3-1.q1.noarch"}},
		{"qdb-multi > 1:3.0", nil},
		{"qdb-multi >= 1:3.0", []string{"qdb-base-1:1.2.3-1.q1.noarch"}},
		// The implicit provide of the name and version.
		{"qdb-base = 1:1.2.3-1.q1", []string{"qdb-base-1:1.2.3-1.q1.noarch"}},
		{"qdb-base >= 2:0", nil},
		{"qdb-lib == 1.5", []string{"qdb-lib-1.5-2.q1.i686", "qdb-lib-1.5-2.q1.x86_64"}},
		{"qdb-lib", []string{"qdb-lib-1.4-1.q1.x86_64", "qdb-lib-1.5-2.q1.i686", "qdb-lib-1.5-2.q1.x86_64"}},
	} {
		q, err := rpmdb.ParseCapability(tc.q)
		require.NoError(t, err, tc.q)

		got, err := db.WhatProvides(t.Context(), q)
		require.NoError(t, err, tc.q)
		assert.Equal(t, orNil(tc.want), orNil(nevras(got)), tc.q)
	}
}

func TestRichDependenciesAreIndexedLikeRpm(t *testing.T) {
	db := openRich(t, rpmdb.Options{})

	required := func(name string) []string {
		pkgs, err := db.WhatRequires(t.Context(), richdep.Atom{Name: name})
		require.NoError(t, err)

		return nevras(pkgs)
	}

	const base = "qdb-base-1:1.2.3-1.q1.noarch"

	// "(qdb-opt if qdb-x)" requires qdb-opt, and qdb-x only as a condition.
	assert.Equal(t, []string{base}, required("qdb-opt"))
	assert.Empty(t, required("qdb-x"))
	// Both branches of an or, and the text of the whole.
	assert.Equal(t, []string{base}, required("qdb-alt"))
	assert.Equal(t, []string{base}, required("qdb-other"))
	assert.Equal(t, []string{base}, required("(qdb-opt if qdb-x)"))

	// A version in the rich dependency is part of the match.
	// The atom is qdb-alt >= 2.0: a capability qdb-alt = 1.0 does not satisfy it.
	got, err := db.WhatRequires(t.Context(), richdep.Atom{Name: "qdb-alt", Cmp: richdep.Equal, Version: "1.0"})
	require.NoError(t, err)
	assert.Empty(t, got)

	got, err = db.WhatRequires(t.Context(), richdep.Atom{Name: "qdb-alt", Cmp: richdep.Equal, Version: "2.5"})
	require.NoError(t, err)
	assert.Equal(t, []string{base}, nevras(got))
}

func TestQueryIndexBoundsAndContext(t *testing.T) {
	db := openRich(t, rpmdb.Options{MaxIndexEntries: 10})

	_, err := db.InstalledPackages(t.Context())
	require.ErrorIs(t, err, rpmdb.ErrTooLarge)

	// A failed build leaves nothing behind: the next one tries again.
	_, err = db.ByName(t.Context(), "qdb-lib")
	require.ErrorIs(t, err, rpmdb.ErrTooLarge)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	ok := openRich(t, rpmdb.Options{})

	_, err = ok.InstalledPackages(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, ok.Refresh(ctx), context.Canceled)

	// And the database still answers with a live context.
	pkgs, err := ok.InstalledPackages(t.Context())
	require.NoError(t, err)
	assert.NotEmpty(t, pkgs)
}

func TestQueryIndexBuiltOnceUnderConcurrency(t *testing.T) {
	db := openRich(t, rpmdb.Options{})

	var (
		wg      sync.WaitGroup
		results [16][]*rpm.Package
	)

	for i := range results {
		wg.Add(1)

		go func() {
			defer wg.Done()

			switch i % 3 {
			case 0:
				results[i], _ = db.InstalledPackages(context.Background())
			case 1:
				results[i], _ = db.WhatRequires(context.Background(), richdep.Atom{Name: "/bin/sh"})
			default:
				results[i], _ = db.FileOwners(context.Background(), "/usr/bin/bash")
			}
		}()
	}

	wg.Wait()

	for i, r := range results {
		assert.NotEmpty(t, r, i)
	}

	// One index: the same packages come back to everyone.
	all := results[0]
	for i := 3; i < len(results); i += 3 {
		assert.Equal(t, all, results[i])
		assert.True(t, all[0] == results[i][0])
	}
}

func TestRefreshSeesNewPackages(t *testing.T) {
	path := copyFixture(t, richFixture)

	db, err := rpmdb.Open(path, rpmdb.Options{})
	require.NoError(t, err)

	defer db.Close()

	before, err := db.InstalledPackages(t.Context())
	require.NoError(t, err)

	w := writer(t, path)
	duplicateFirstPackage(t, w)

	// The index does not move on its own.
	still, err := db.InstalledPackages(t.Context())
	require.NoError(t, err)
	assert.Len(t, still, len(before))

	require.NoError(t, db.Refresh(t.Context()))

	after, err := db.InstalledPackages(t.Context())
	require.NoError(t, err)
	assert.Len(t, after, len(before)+1)
}

func TestParseCapability(t *testing.T) {
	for in, want := range map[string]richdep.Atom{
		"foo":                  {Name: "foo"},
		"foo >= 1.0":           {Name: "foo", Cmp: richdep.Greater | richdep.Equal, Version: "1.0"},
		"foo = 1:2.0-3":        {Name: "foo", Cmp: richdep.Equal, Version: "1:2.0-3"},
		"foo == 1":             {Name: "foo", Cmp: richdep.Equal, Version: "1"},
		"  foo   <  2  ":       {Name: "foo", Cmp: richdep.Less, Version: "2"},
		"/usr/bin/foo":         {Name: "/usr/bin/foo"},
		"libfoo.so.1()(64bit)": {Name: "libfoo.so.1()(64bit)"},
	} {
		got, err := rpmdb.ParseCapability(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	for _, bad := range []string{"", "  ", "foo >=", "(a and b)", "(a if b)", "a b c", "foo\x00", strings.Repeat("a", 1<<17)} {
		_, err := rpmdb.ParseCapability(bad)
		require.ErrorIs(t, err, rpmdb.ErrInvalidQuery, bad)
	}
}

func TestQueryArgumentsAreChecked(t *testing.T) {
	db := openRich(t, rpmdb.Options{})

	for _, q := range []richdep.Atom{{}, {Name: "a\x00"}, {Name: "a", Cmp: richdep.Equal, Version: strings.Repeat("1", 1<<17)}} {
		_, err := db.WhatProvides(t.Context(), q)
		require.ErrorIs(t, err, rpmdb.ErrInvalidQuery)
	}

	_, err := db.ByLabel(t.Context(), "")
	require.ErrorIs(t, err, rpmdb.ErrInvalidQuery)
}

func TestQueriesOnEveryFormat(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx.file, func(t *testing.T) {
			db, err := rpmdb.Open(copyFixture(t, fx.file), rpmdb.Options{})
			require.NoError(t, err)

			defer db.Close()

			list, err := db.List(t.Context())
			require.NoError(t, err)

			installed, err := db.InstalledPackages(t.Context())
			require.NoError(t, err)
			require.Len(t, installed, len(list))

			// Every package is found by its own name, label and files.
			for _, p := range installed {
				byName, err := db.ByName(t.Context(), p.Name)
				require.NoError(t, err)
				assert.Contains(t, byName, p)

				label := fmt.Sprintf("%s-%s-%s.%s", p.Name, p.Version, p.Release, p.Arch)
				if p.Arch == "" {
					label = fmt.Sprintf("%s-%s-%s", p.Name, p.Version, p.Release)
				}

				byLabel, err := db.ByLabel(t.Context(), label)
				require.NoError(t, err)
				assert.Contains(t, nevras(byLabel), nevra(p), label)

				prov, err := db.WhatProvides(t.Context(), richdep.Atom{Name: p.Name})
				require.NoError(t, err)
				assert.Contains(t, prov, p)

				for _, f := range p.Files[:min(len(p.Files), 3)] {
					owners, err := db.FileOwners(t.Context(), f.Path)
					require.NoError(t, err)
					assert.Contains(t, owners, p, f.Path)
				}
			}
		})
	}
}

func FuzzCapabilityQuery(f *testing.F) {
	db := openRich(f, rpmdb.Options{})

	for _, s := range []string{
		"qdb-virt >= 1.5", "qdb-lib", "qdb-base = 1:1.2.3-1.q1", "/usr/bin/bash", "foo < 1~rc1^git", "(a if b)",
		"x = :", "x = 1:", "x = :1", "x >= -", "x <= 1-", "y = 99999999999999999999:1-2", "", "libqdb.so.1()(64bit)",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		q, err := rpmdb.ParseCapability(s)
		if err != nil {
			require.ErrorIs(t, err, rpmdb.ErrInvalidQuery)

			return
		}

		ctx := context.Background()

		for _, fn := range []func(context.Context, richdep.Atom) ([]*rpm.Package, error){
			db.WhatProvides, db.WhatRequires, db.WhatRecommends, db.WhatSuggests,
			db.WhatSupplements, db.WhatEnhances, db.WhatConflicts, db.WhatObsoletes,
		} {
			pkgs, err := fn(ctx, q)
			if err != nil {
				require.ErrorIs(t, err, rpmdb.ErrInvalidQuery)

				continue
			}

			// Ordered, without repeats.
			for i := 1; i < len(pkgs); i++ {
				if pkgs[i-1] == pkgs[i] {
					t.Fatalf("%q: %s twice", s, nevra(pkgs[i]))
				}
			}
		}

		if _, err := db.ByLabel(ctx, s); err != nil {
			require.ErrorIs(t, err, rpmdb.ErrInvalidQuery)
		}

		if _, err := db.FileOwners(ctx, s); err != nil {
			require.ErrorIs(t, err, rpmdb.ErrInvalidQuery)
		}
	})
}
