package deb_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

func TestParseRelations(t *testing.T) {
	got, err := deb.ParseRelations("libc6 (>= 2.31), foo | bar (<< 3~) | baz:any, qux:native (= 1:1.0-1), plain")
	require.NoError(t, err)

	want := []deb.Alternatives{
		{{Name: "libc6", Op: ">=", Version: "2.31"}},
		{{Name: "foo"}, {Name: "bar", Op: "<<", Version: "3~"}, {Name: "baz", Arch: "any"}},
		{{Name: "qux", Arch: "native", Op: "=", Version: "1:1.0-1"}},
		{{Name: "plain"}},
	}
	assert.Equal(t, want, got)
}

func TestParseRelationsWhitespaceAndMultiline(t *testing.T) {
	got, err := deb.ParseRelations("  a  (  >=   1.0  )  ,\n b\n | c ,, ")
	require.NoError(t, err)
	assert.Equal(t, []deb.Alternatives{
		{{Name: "a", Op: ">=", Version: "1.0"}},
		{{Name: "b"}, {Name: "c"}},
	}, got)
}

func TestParseRelationsObsoleteAndCompactOperators(t *testing.T) {
	got, err := deb.ParseRelations("a (<1), b (>2), c (<=3), d (=4), e (>>5), f (<<6), g (>=7)")
	require.NoError(t, err)

	ops := make([]string, 0, len(got))
	vers := make([]string, 0, len(got))

	for _, alt := range got {
		ops = append(ops, alt[0].Op)
		vers = append(vers, alt[0].Version)
	}

	assert.Equal(t, []string{"<", ">", "<=", "=", ">>", "<<", ">="}, ops)
	assert.Equal(t, []string{"1", "2", "3", "4", "5", "6", "7"}, vers)
}

func TestParseRelationsKeepsRestrictions(t *testing.T) {
	got, err := deb.ParseRelations("a [amd64 i386], b (>= 1) [!arm64] <!nocheck> <cross>, c:any <!stage1 !cross>, d [linux-any any-arm64]")
	require.NoError(t, err)

	arch := func(terms ...string) []deb.Restriction {
		out := make([]deb.Restriction, len(terms))
		for i, s := range terms {
			out[i] = deb.Restriction{Name: strings.TrimPrefix(s, "!"), Negated: strings.HasPrefix(s, "!")}
		}

		return out
	}

	assert.Equal(t, []deb.Alternatives{
		{{Name: "a", ArchRestrictions: arch("amd64", "i386")}},
		{{Name: "b", Op: ">=", Version: "1", ArchRestrictions: arch("!arm64"), ProfileGroups: [][]deb.Restriction{arch("!nocheck"), arch("cross")}}},
		{{Name: "c", Arch: "any", ProfileGroups: [][]deb.Restriction{arch("!stage1", "!cross")}}},
		{{Name: "d", ArchRestrictions: arch("linux-any", "any-arm64")}},
	}, got)
}

func TestRelationCanonicalString(t *testing.T) {
	tests := []struct{ in, want string }{
		{"a", "a"},
		{"  a:any   (>=   1.0 ) ", "a:any (>= 1.0)"},
		{"a (>= 1)[amd64   !i386]<!nocheck><stage1  cross>", "a (>= 1) [amd64 !i386] <!nocheck> <stage1 cross>"},
		{"a:native [linux-any]", "a:native [linux-any]"},
		{"a:amd64 <cross>", "a:amd64 <cross>"},
		{"a | b:any (<< 2) [!hurd-any] | c <!nocheck>", "a | b:any (<< 2) [!hurd-any] | c <!nocheck>"},
	}

	for _, tt := range tests {
		got, err := deb.ParseRelations(tt.in)
		require.NoError(t, err, tt.in)
		require.Len(t, got, 1)
		assert.Equal(t, tt.want, got[0].String(), tt.in)

		back, err := deb.ParseRelations(deb.FormatRelations(got))
		require.NoError(t, err)
		assert.Equal(t, got, back, tt.in)
	}

	// Entries are joined with a comma and a space.
	got, err := deb.ParseRelations("a,b (= 1) [amd64] ,\n c|d")
	require.NoError(t, err)
	assert.Equal(t, "a, b (= 1) [amd64], c | d", deb.FormatRelations(got))
	assert.Empty(t, deb.FormatRelations(nil))
}

func TestParseRelationsEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", ",", " , ,\n,"} {
		got, err := deb.ParseRelations(in)
		require.NoError(t, err)
		assert.Empty(t, got, "%q", in)
	}
}

func TestParseRelationsMalformed(t *testing.T) {
	for _, in := range []string{
		"(>= 1)",
		"a (>= 1",
		"a (foo 1)",
		"a ()",
		"a (>=)",
		"a (1.0)",
		"a (>>> 1)",
		"a b",
		"a (>= 1) b",
		"a [amd64",
		"a <!nocheck",
		"a, | b",
		"a |",
		"a | | b",
		"a<b",
		"a=b",
		"a)",
		"a (= 1) (= 2)",
		"a ]",
		"a []",
		"a [ ]",
		"a [!]",
		"a [amd64] [i386]",
		"a <>",
		"a <!>",
		"a <nocheck> [amd64]",
		"a [am<d64]",
		"a <no:check>",
	} {
		t.Run(in, func(t *testing.T) {
			_, err := deb.ParseRelations(in)
			require.ErrorIs(t, err, deb.ErrInvalidControlFormat)
		})
	}
}

func TestParseRelationsTooMany(t *testing.T) {
	const limit = 1 << 16

	got, err := deb.ParseRelations(strings.Repeat("a,", limit))
	require.NoError(t, err)
	assert.Len(t, got, limit)

	_, err = deb.ParseRelations(strings.Repeat("a,", limit+1))
	require.ErrorIs(t, err, deb.ErrTooLarge)
}

func TestRelationString(t *testing.T) {
	assert.Equal(t, "a", deb.Relation{Name: "a"}.String())
	assert.Equal(t, "a:any", deb.Relation{Name: "a", Arch: "any"}.String())
	assert.Equal(t, "a (>= 1.0)", deb.Relation{Name: "a", Op: ">=", Version: "1.0"}.String())
	assert.Equal(t, "a:amd64 (<< 2)", deb.Relation{Name: "a", Arch: "amd64", Op: "<<", Version: "2"}.String())

	// What String renders parses back to the same relation.
	rel := deb.Relation{Name: "libfoo", Arch: "i386", Op: "=", Version: "1:2~rc1-3"}
	got, err := deb.ParseRelations(rel.String())
	require.NoError(t, err)
	assert.Equal(t, []deb.Alternatives{{rel}}, got)

	rel.ArchRestrictions = []deb.Restriction{{Name: "amd64"}, {Name: "i386", Negated: true}}
	rel.ProfileGroups = [][]deb.Restriction{{{Name: "nocheck", Negated: true}}, {{Name: "cross"}, {Name: "stage1"}}}
	assert.Equal(t, "libfoo:i386 (= 1:2~rc1-3) [amd64 !i386] <!nocheck> <cross stage1>", rel.String())

	got, err = deb.ParseRelations(rel.String())
	require.NoError(t, err)
	assert.Equal(t, []deb.Alternatives{{rel}}, got)
}

func TestRelationSatisfied(t *testing.T) {
	versions := []string{"1.0~rc1", "1.0", "1.0-1", "1.0+b1", "1.1", "1:0.5", "2.0"}
	ops := []string{"<<", "<", "<=", "=", ">=", ">>", ">"}

	for _, op := range ops {
		for _, bound := range versions {
			for _, v := range versions {
				c := deb.CompareVersions(v, bound)

				var want bool

				switch op {
				case "<<":
					want = c < 0
				case "<=", "<": // dpkg reads the obsolete "<" as "<="
					want = c <= 0
				case "=":
					want = c == 0
				case ">=", ">": // and ">" as ">="
					want = c >= 0
				case ">>":
					want = c > 0
				}

				rel := deb.Relation{Name: "p", Op: op, Version: bound}
				assert.Equal(t, want, rel.Satisfied(v), "%s %s %s", v, op, bound)
			}
		}
	}
}

func TestRelationSatisfiedEdges(t *testing.T) {
	assert.True(t, deb.Relation{Name: "p"}.Satisfied("anything"))
	assert.True(t, deb.Relation{Name: "p"}.Satisfied(""))
	assert.False(t, deb.Relation{Name: "p", Op: "~=", Version: "1"}.Satisfied("1"), "an unknown operator never matches")
	assert.True(t, deb.Relation{Name: "p", Op: ">=", Version: "1.0"}.Satisfied("1.0-0"))
	assert.True(t, deb.Relation{Name: "p", Op: "<<", Version: "2.0~"}.Satisfied("1.9"))
	assert.False(t, deb.Relation{Name: "p", Op: "<<", Version: "2.0~"}.Satisfied("2.0"))
}

func TestDependencyNames(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a, b (>= 1), c:any | d, e [amd64]", []string{"a", "b", "c", "e"}},
		{"libc6(>=2)", []string{"libc6"}},
		{"  ,a,, b ,", []string{"a", "b"}},
		{"x | y", []string{"x"}},
		{"a:amd64 (= 1)", []string{"a"}},
		{"a\n b", []string{"a"}},
		{"(>= 1)", nil},
		{" , , ", nil},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := deb.DependencyNames(tt.in)
			if len(tt.want) == 0 {
				assert.Empty(t, got)

				return
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeDependency(t *testing.T) {
	tests := []struct{ in, want string }{
		{"gcc>=11", "gcc (>= 11)"},
		{"gcc<=11", "gcc (<= 11)"},
		{"gcc=11", "gcc (= 11)"},
		{"libfoo>2.0", "libfoo (>> 2.0)"},
		{"libfoo<2.0", "libfoo (<< 2.0)"},
		{"foo>=1:2.0-3~rc1", "foo (>= 1:2.0-3~rc1)"},
		{"gcc (>= 11)", "gcc (>= 11)"},
		{"gcc (>> 11)", "gcc (>> 11)"},
		{"gcc (>= 11) [amd64]", "gcc (>= 11) [amd64]"},
		{"(>= 1)", "(>= 1)"},
		{"gcc", "gcc"},
		{"", ""},
		{"a>>1", "a>>1"},
		{"a<<1", "a<<1"},
		{"a=>1", "a=>1"},
		{"a>=1<2", "a>=1<2"},
		{"a==1", "a==1"},
		{"a>", "a (>> )"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, deb.NormalizeDependency(tt.in))
		})
	}
}

func TestNormalizeDependencyParses(t *testing.T) {
	for _, in := range []string{"gcc>=11", "a<2", "b>3", "c=4", "d<=5"} {
		got, err := deb.ParseRelations(deb.NormalizeDependency(in))
		require.NoError(t, err, in)
		require.Len(t, got, 1)
		assert.NotEmpty(t, got[0][0].Op, in)
	}
}

// FuzzParseRelations feeds arbitrary text to the relation parser.
func FuzzParseRelations(f *testing.F) {
	f.Add("libc6 (>= 2.31), foo | bar (<< 3~) [amd64] <!nocheck>, baz:any")
	f.Add("debhelper-compat (= 13), dh-golang <!nocheck>, libc6-dev [!hurd-any] <!stage1 !cross> <cross>, gcc:native [linux-any any-amd64]")
	f.Add("")
	f.Add("a (>= 1")
	f.Add(", | ,")
	f.Add("(>= 1)")

	f.Fuzz(func(t *testing.T, in string) {
		_ = deb.DependencyNames(in)
		_ = deb.NormalizeDependency(in)

		rels, err := deb.ParseRelations(in)
		if err != nil {
			return
		}

		for _, alts := range rels {
			require.NotEmpty(t, alts)

			for _, r := range alts {
				require.NotEmpty(t, r.Name)

				// What a relation renders as parses back to itself.
				back, err := deb.ParseRelations(r.String())
				require.NoError(t, err, r.String())
				require.Equal(t, []deb.Alternatives{{r}}, back)

				_ = r.Satisfied(strconv.Itoa(len(in)))
				_ = r.AppliesTo("amd64", []string{"nocheck", "cross"})
				_, _ = r.TargetArch("arm64", "amd64")
			}
		}

		// The whole field survives a render and a parse.
		again, err := deb.ParseRelations(deb.FormatRelations(rels))
		require.NoError(t, err)
		require.Equal(t, rels, again)

		for _, host := range []string{"amd64", "armhf", "hurd-i386", ""} {
			for _, alts := range deb.ActiveRelations(rels, host, []string{"nocheck"}) {
				require.NotEmpty(t, alts)

				for _, r := range alts {
					require.Empty(t, r.ArchRestrictions)
					require.Empty(t, r.ProfileGroups)
				}
			}
		}
	})
}
