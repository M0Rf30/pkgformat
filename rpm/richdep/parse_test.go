package richdep_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/rpm/richdep"
)

func atom(name string) richdep.Atom { return richdep.Atom{Name: name} }

func TestParseShapes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in   string
		want richdep.Node
		text string
	}{
		{"foo", atom("foo"), "foo"},
		{"  foo  >=  1.2-3 ", richdep.Atom{Name: "foo", Cmp: richdep.Greater | richdep.Equal, Version: "1.2-3"}, "foo >= 1.2-3"},
		{"foo == 1", richdep.Atom{Name: "foo", Cmp: richdep.Equal, Version: "1"}, "foo = 1"},
		{"foo =< 1", richdep.Atom{Name: "foo", Cmp: richdep.Less | richdep.Equal, Version: "1"}, "foo <= 1"},
		{"(a and b and c)", &richdep.Expr{Op: richdep.OpAnd, Args: []richdep.Node{atom("a"), atom("b"), atom("c")}},
			"(a and b and c)"},
		{"(a if b)", &richdep.Expr{Op: richdep.OpIf, Args: []richdep.Node{atom("a"), atom("b")}}, "(a if b)"},
		{"(a unless b else c)",
			&richdep.Expr{Op: richdep.OpUnless, Args: []richdep.Node{atom("a"), atom("b"), atom("c")}}, "(a unless b else c)"},
		{"((a))", atom("a"), "a"},
		{"( a ,b )", nil, ""},
		{"(libfoo.so.1()(64bit) or perl(Foo::Bar) >= 1.0)", &richdep.Expr{Op: richdep.OpOr, Args: []richdep.Node{
			atom("libfoo.so.1()(64bit)"),
			richdep.Atom{Name: "perl(Foo::Bar)", Cmp: richdep.Greater | richdep.Equal, Version: "1.0"},
		}}, "(libfoo.so.1()(64bit) or perl(Foo::Bar) >= 1.0)"},
		{"(a else b)", &richdep.Expr{Op: richdep.OpElse, Args: []richdep.Node{atom("a"), atom("b")}}, "(a else b)"},
	} {
		n, err := richdep.Parse(tc.in)
		if tc.want == nil {
			assert.Error(t, err, tc.in, "a comma is not an operator")

			continue
		}

		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.want, n, tc.in)
		assert.Equal(t, tc.text, n.String(), tc.in)
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()

	for _, in := range []string{
		"", " ", "()", "(a and)", "(and a)", "(a >=)", "(a >= 1 2)", "(a xor b)", "(a", "((a and b)", "(a and b))",
		"(a and b or c)", "(a if b and c)", "foo >=", "foo >= 1 junk", "(a with (b and c))",
	} {
		_, err := richdep.Parse(in)
		require.Error(t, err, in)
		assert.ErrorIs(t, err, richdep.ErrSyntax, in)
	}
}

func TestParseForContexts(t *testing.T) {
	t.Parallel()

	_, err := richdep.ParseFor("(a unless b)", richdep.KindRequire)
	require.Error(t, err, "librpm wants 'or' in a Requires")
	_, err = richdep.ParseFor("(a unless b)", richdep.KindConflict)
	require.NoError(t, err)
	_, err = richdep.ParseFor("(a if b)", richdep.KindConflict)
	require.Error(t, err, "librpm wants 'and' in a Conflicts")
	_, err = richdep.ParseFor("(a if b)", richdep.KindRequire)
	require.NoError(t, err)
	_, err = richdep.ParseFor("(a and b)", richdep.KindProvide)
	require.Error(t, err, "a Provides takes no rich dependency")
	_, err = richdep.ParseFor("a >= 1", richdep.KindProvide)
	require.NoError(t, err)
}

func TestParseDepthBound(t *testing.T) {
	t.Parallel()

	deep := strings.Repeat("(", 5000) + "a" + strings.Repeat(")", 5000)
	_, err := richdep.Parse(deep)
	require.Error(t, err)
	assert.True(t, errors.Is(err, richdep.ErrSyntax))

	ok := strings.Repeat("(a and ", 50) + "b" + strings.Repeat(")", 50)
	_, err = richdep.Parse(ok)
	require.NoError(t, err)
}

func TestAtoms(t *testing.T) {
	t.Parallel()

	n, err := richdep.Parse("((a >= 1 and b) or (c if d else e))")
	require.NoError(t, err)

	var names []string
	for _, a := range richdep.Atoms(n) {
		names = append(names, a.Name)
	}

	assert.Equal(t, []string{"a", "b", "c", "d", "e"}, names)
}

func TestCmpString(t *testing.T) {
	t.Parallel()

	for c, want := range map[richdep.Cmp]string{
		0: "", richdep.Less: "<", richdep.Less | richdep.Equal: "<=", richdep.Equal: "=",
		richdep.Greater | richdep.Equal: ">=", richdep.Greater: ">", richdep.Less | richdep.Greater: "",
	} {
		assert.Equal(t, want, c.String())
	}

	assert.Equal(t, richdep.Greater|richdep.Equal, richdep.FromFlags(uint32(0x4|0x8|1<<24)))
	assert.Empty(t, richdep.Op(0).String())
}

// provider builds an oracle from capability to packages.
func provider(m map[string][]string) richdep.Oracle {
	return richdep.OracleFunc(func(a richdep.Atom) []string { return m[a.Name] })
}

func TestEvalOperators(t *testing.T) {
	t.Parallel()

	o := provider(map[string][]string{
		"a": {"p1"}, "b": {"p1", "p2"}, "c": {"p2"}, "both": {"p1", "p2"},
	})

	for _, tc := range []struct {
		dep  string
		want bool
	}{
		{"(a and b)", true},
		{"(a and z)", false},
		{"(z or c)", true},
		{"(z or y)", false},
		{"(a if z)", true},
		{"(z if a)", false},
		{"(a unless z)", true},
		{"(a unless b)", false},
		{"(z if a else b)", false},
		{"(z if y else a)", true},
		{"(z unless a else c)", true},
		{"(a with b)", true},
		{"(a with c)", false},
		{"(b without a)", true},
		{"(a without b)", false},
		{"((a or c) with b)", true},
		{"(a else z)", true},
	} {
		n, err := richdep.Parse(tc.dep)
		require.NoError(t, err, tc.dep)
		assert.Equal(t, tc.want, richdep.Eval(n, o), tc.dep)
	}

	assert.Equal(t, []string{"p1", "p2"}, richdep.Set(mustParse(t, "(a or c)"), o))
	assert.Nil(t, richdep.Set(mustParse(t, "(a and b)"), o), "and is not a set operator")
}

func mustParse(t *testing.T, s string) richdep.Node {
	t.Helper()

	n, err := richdep.Parse(s)
	require.NoError(t, err)

	return n
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"foo", "foo >= 1:2.0-3", "(a and b)", "(a if b else c)", "((a or b) with c)", "(a unless (b and c))",
		"(a, b)", "", "(", ")", "(a >=", "perl(Foo::Bar)", "((((a))))", "(a without b)",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		n, err := richdep.Parse(s)
		if err != nil {
			require.ErrorIs(t, err, richdep.ErrSyntax)

			return
		}

		// The canonical form parses back to the same tree, unless a name has
		// a "(" that nothing closes: librpm accepts "(a( )" and reads the
		// ")" as part of the name, which text cannot say otherwise.
		for _, a := range richdep.Atoms(n) {
			if strings.Count(a.Name, "(") != strings.Count(a.Name, ")") {
				return
			}
		}

		text := n.String()

		m, err := richdep.Parse(text)
		require.NoErrorf(t, err, "canonical form %q of %q", text, s)
		require.Equal(t, text, m.String())

		// Evaluation terminates and is deterministic.
		o := provider(map[string][]string{"a": {"p"}, "b": {"p", "q"}})
		require.Equal(t, richdep.Eval(n, o), richdep.Eval(m, o))
		_ = richdep.Atoms(n)
	})
}
