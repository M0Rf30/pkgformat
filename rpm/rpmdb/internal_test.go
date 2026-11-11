package rpmdb

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/richdep"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

func TestTriggerKinds(t *testing.T) {
	for _, tc := range []struct {
		flags uint32
		kind  TriggerKind
		text  string
	}{
		{tag.RPMSENSE_TRIGGERIN | tag.RPMSENSE_GREATER, TriggerIn, "in"},
		{tag.RPMSENSE_TRIGGERUN, TriggerUn, "un"},
		{tag.RPMSENSE_TRIGGERPOSTUN | tag.RPMSENSE_EQUAL, TriggerPostUn, "postun"},
		{tag.RPMSENSE_TRIGGERPREIN, TriggerPreIn, "prein"},
		{tag.RPMSENSE_EQUAL, TriggerUnknown, ""},
		{0, TriggerUnknown, ""},
	} {
		assert.Equal(t, tc.kind, kindOf(tc.flags), tc.flags)
		assert.Equal(t, tc.text, tc.kind.String())
	}

	assert.Empty(t, TriggerKind(42).String())
}

// rich returns the capabilities walkRich reports for a dependency.
func rich(t *testing.T, text string) []string {
	t.Helper()

	n, err := richdep.Parse(text)
	require.NoError(t, err, text)

	var out []string

	walkRich(n, false, func(a richdep.Atom) { out = append(out, a.String()) })

	return out
}

func TestWalkRichFollowsRpm(t *testing.T) {
	for text, want := range map[string][]string{
		"(a and b)":                   {"a", "b"},
		"(a or b >= 1)":               {"a", "b >= 1"},
		"(a if b)":                    {"a"},
		"(a unless b)":                {"a"},
		"(a if b else c)":             {"a", "b", "c"},
		"(a unless b else c)":         {"a", "b", "c"},
		"((a or b) if (c and d))":     {"a", "b"},
		"(a with b)":                  {"a", "b"},
		"(a without b)":               {"a", "b"},
		"((a if b) and (c unless d))": {"a", "c"},
	} {
		// The atoms of a condition are left out, unless an else follows: rpm
		// indexes them negated and, for an else, once more as they are.
		assert.ElementsMatch(t, want, rich(t, text), text)
	}
}

func TestVersionMatches(t *testing.T) {
	p := &rpm.Package{Name: "x", Epoch: 2, Version: "1.5", Release: "3"}

	for _, tc := range []struct {
		version, release string
		want             bool
	}{
		{"", "", true},
		{"", "3", true},
		{"1.5", "", true},
		{"1.5", "3", true},
		{"1.5", "4", false},
		{"1.4", "", false},
		{"2:1.5", "", true},
		{"1:1.5", "", false},
		{"0:1.5", "", false},
		{"x:1.5", "", false},
		{"99999999999:1.5", "", false},
	} {
		assert.Equal(t, tc.want, versionMatches(p, tc.version, tc.release), "%s %s", tc.version, tc.release)
	}
}

func TestAppendOnce(t *testing.T) {
	assert.Equal(t, []int32{1, 2}, appendOnce(appendOnce([]int32{1}, 2), 2))
	assert.Equal(t, []int32{1, 2, 1}, appendOnce([]int32{1, 2}, 1))
}

func TestComparePackages(t *testing.T) {
	order := []*rpm.Package{
		{Name: "a", Version: "1", Release: "1", Arch: "x86_64"},
		{Name: "a", Version: "1", Release: "2", Arch: "i686"},
		{Name: "a", Version: "1", Release: "2", Arch: "x86_64"},
		{Name: "a", Version: "1.0", Release: "2", Arch: "x86_64"},
		{Name: "a", Version: "2", Release: "1", Arch: "i686"},
		{Name: "a", Epoch: 1, Version: "0.1", Release: "1", Arch: "i686"},
		{Name: "a", Epoch: 1, Version: "0.1", Release: "1", Arch: "i686", InstallTime: 5},
		{Name: "b", Version: "1", Release: "1"},
	}

	for i := range order {
		for j := range order {
			assert.Equal(t, fmt.Sprint(i < j), fmt.Sprint(comparePackages(order[i], order[j]) < 0), "%d %d", i, j)
		}
	}

	assert.Zero(t, comparePackages(order[0], order[0]))
}

func TestDepKindList(t *testing.T) {
	p := &rpm.Package{
		Provides: []rpm.Dependency{{Name: "p"}}, Requires: []rpm.Dependency{{Name: "r"}},
		Recommends: []rpm.Dependency{{Name: "w"}}, Suggests: []rpm.Dependency{{Name: "s"}},
		Supplements: []rpm.Dependency{{Name: "u"}}, Enhances: []rpm.Dependency{{Name: "e"}},
		Conflicts: []rpm.Dependency{{Name: "c"}}, Obsoletes: []rpm.Dependency{{Name: "o"}},
	}

	var names string

	for k := range numKinds {
		list := k.list(p)
		require.Len(t, list, 1)

		names += list[0].Name
	}

	assert.Equal(t, "prwsueco", names)
	assert.Nil(t, numKinds.list(p))
}

func TestSelfProvide(t *testing.T) {
	assert.Equal(t, richdep.Atom{Name: "a", Cmp: richdep.Equal, Version: "1-2"}, selfProvide(&rpm.Package{Name: "a", Version: "1", Release: "2"}))
	assert.Equal(t, richdep.Atom{Name: "a", Cmp: richdep.Equal, Version: "3:1-2"}, selfProvide(&rpm.Package{Name: "a", Epoch: 3, Version: "1", Release: "2"}))
	assert.Equal(t, richdep.Atom{Name: "a", Cmp: richdep.Equal, Version: "1"}, selfProvide(&rpm.Package{Name: "a", Version: "1"}))
}

func TestLabelMatchesOrder(t *testing.T) {
	ix := &queryIndex{byName: map[string][]int32{"a": {0}, "a-b": {1}}}
	ix.pkgs = []*rpm.Package{{Name: "a", Version: "b", Release: "c"}, {Name: "a-b", Version: "1", Release: "2"}}

	// The label as a whole name wins over its reading as name-version.
	assert.Equal(t, []*rpm.Package{ix.pkgs[1]}, ix.labelMatches("a-b", ""))
	assert.Equal(t, []*rpm.Package{ix.pkgs[0]}, ix.labelMatches("a-b-c", ""))
	assert.Equal(t, []*rpm.Package{ix.pkgs[1]}, ix.labelMatches("a-b-1-2", ""))
	assert.Nil(t, ix.labelMatches("-", ""))
	assert.Nil(t, ix.labelMatches("--", ""))
	assert.Nil(t, ix.labelMatches("a-b-1-2-3", ""))
	assert.Nil(t, ix.labelMatches("a-b-1-2", "i686"))
}

func TestSQLiteCodeOfForeignErrors(t *testing.T) {
	assert.Zero(t, sqliteCode(errors.New("plain")))
	assert.False(t, isLocked(errors.New("plain")))
	assert.False(t, needsFallback(errors.New("plain")))
	assert.NoError(t, wrapSQLite(nil))

	plain := errors.New("plain")
	assert.Equal(t, plain, wrapSQLite(plain))
}

func TestScriptsOfAHeaderAreBounded(t *testing.T) {
	db, err := Open("testdata/rich.sqlite", Options{SQLite: SQLiteImmutable})
	require.NoError(t, err)

	defer db.Close()

	var checked bool

	for rec, err := range db.records(t.Context()) {
		require.NoError(t, err)

		if rec.pkg.Name != "qdb-base" {
			continue
		}

		// Four trigger scripts, and more conditions than that.
		_, err := scriptsFromHeader(rec.hdr, 3)
		require.ErrorIs(t, err, ErrTooLarge)
		assert.Contains(t, err.Error(), "trigger scripts")

		_, err = scriptsFromHeader(rec.hdr, 4)
		require.ErrorIs(t, err, ErrTooLarge)
		assert.Contains(t, err.Error(), "trigger conditions")

		s, err := scriptsFromHeader(rec.hdr, 100)
		require.NoError(t, err)
		assert.Len(t, s.Triggers, 4)

		checked = true
	}

	assert.True(t, checked)
}
