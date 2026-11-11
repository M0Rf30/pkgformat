package apt

import (
	"bufio"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExpressionMatchesGlibc compares the expression matchers with glibc's
// fnmatch and regexec over the vectors of testdata/policy/matchvec.c.
func TestExpressionMatchesGlibc(t *testing.T) {
	t.Parallel()

	f, err := os.Open(policyDir("matchvec.tsv"))
	require.NoError(t, err)

	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)

	globs, regexes, invalid := 0, 0, 0
	bad := map[string]bool{}

	for sc.Scan() {
		cols := strings.Split(sc.Text(), "\t")
		require.Len(t, cols, 4, sc.Text())

		kind, pattern, str, want := cols[0], cols[1], cols[2], cols[3]

		var got bool

		switch kind {
		case "glob":
			// glibc counts the bytes of a multibyte character when a "*"
			// is next to a "?"; names in pins are ASCII, so that quirk is
			// not modelled.
			if !isASCII(str) && strings.Contains(pattern, "*") && strings.Contains(pattern, "?") {
				continue
			}

			got = fnmatch(pattern, str)
			globs++
		case "regex":
			got = newExpression("/" + pattern + "/").matches(str)
			regexes++

			if want == "invalid" {
				invalid++
				want = "0"
			}
		default:
			t.Fatalf("kind %q", kind)
		}

		if (want == "1") != got {
			bad[kind+" "+pattern+" ~ "+str+" want "+want] = true
		}
	}

	require.NoError(t, sc.Err())
	assert.Greater(t, globs, 4000)
	assert.Greater(t, regexes, 3000)
	assert.Greater(t, invalid, 100)

	for k := range bad {
		t.Error(k)
	}
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}

	return true
}

func TestTranslateERE(t *testing.T) {
	t.Parallel()

	rejected := []string{"(", "a)", `\`, "[a", "[[:alpha:", "[[.a", `\1`, `\d`, `\n`, "a{x}", "a{", "{1}", "a{,}", "a{1"}
	for _, src := range rejected {
		_, ok := translateERE(src)
		assert.False(t, ok, "%q", src)
	}

	cases := []struct {
		src, in string
		want    bool
	}{
		{"a**", "aaa", true},
		{"a+*", "", true},
		{"a?+", "b", true},
		{"a{,2}b", "aab", true},
		{"a{2,}", "a", false},
		{"*a", "*a", true},
		{"(*a)", "*a", true},
		{"(?i)a", "?ia", true},
		{"(?i)a", "a", false},
		{`\<lib`, "a libfoo", true},
		{`foo\>`, "foo bar", true},
		{"^a", "ba", false},
		{`\` + "`a", "ab", true},
		{`a\'`, "ba", true},
		{`\w+-\W`, "ab-.", true},
		{`[\]`, `\`, true},
		{`[[:alpha:]]+`, "é", true},
		{`[[:alnum:]]+$`, "é9", true},
		{`[[:digit:]]`, "x", false},
		{`[[=a=]b]`, "b", true},
		{`[[.-.]]`, "-", true},
		{`[^]a]`, "]", false},
		{`[]a]`, "]", true},
		{`a.c`, "a\nc", true},
		{`^$`, "", true},
		{`a|b|`, "zzz", true},
		{`\.`, "a.b", true},
		{`\/`, "/", true},
		{`\é`, "é", true},
		{"é+", "ÉÉ", true},
	}

	for _, c := range cases {
		got, ok := translateERE(c.src)
		require.True(t, ok, "%q", c.src)

		re, err := regexp.Compile(got)
		require.NoError(t, err, "%q -> %q", c.src, got)
		assert.Equal(t, c.want, re.MatchString(c.in), "%q ~ %q (%q)", c.src, c.in, got)
	}
}

func TestExpressionBounds(t *testing.T) {
	t.Parallel()

	assert.False(t, newExpression("/"+strings.Repeat("a", maxPatternLength)+"/").matches("a"))
	assert.True(t, newExpression("/^b$/").matches("B"))
	assert.False(t, newExpression("/(/").matches("("))
	assert.True(t, newExpression("/").matches("/"))
	assert.True(t, newExpression("//").matches("anything"))
	assert.False(t, newExpression("a*b").matches("abc"))
}

func TestFnmatchEdges(t *testing.T) {
	t.Parallel()

	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"a\\", "a\\", false},
		{"[a", "[a", true},
		{"[", "[", true},
		{"[!", "[!", true},
		{"a[]", "a[]", true},
		{"[[:foo:]]", "a", false},
		{"[[:alpha:]", "a", false},
		{"[a-]", "-", true},
		{"[z-a]", "m", false},
		{"[\\]]", "]", true},
		{"[[:blank:]]", "\t", true},
		{"[[:print:]]", "a", true},
		{"[[:graph:]]", " ", false},
		{"[[:cntrl:]]", "\x01", true},
		{"[[:punct:]]", "$", true},
		{"[[:xdigit:]]", "F", true},
		{"[[:space:]]", "\n", true},
		{"[[:upper:]]", "A", true},
		{"[[:lower:]]", "A", false},
		{"[[.x.]]", "x", true},
		{"[[=é=]]", "é", true},
		{"*", "", true},
		{"?", "", false},
		{"**a", "ba", true},
		{"É", "é", true},
	}

	for _, c := range cases {
		assert.Equal(t, c.want, fnmatch(c.pattern, c.s), "%q ~ %q", c.pattern, c.s)
	}
}

func TestTokSplit(t *testing.T) {
	t.Parallel()

	frags, ok := tokSplit("  a=1 ,, b=2,c=3 ", 19)
	assert.True(t, ok)
	assert.Equal(t, []string{"a=1", "b=2", "c=3"}, frags)

	frags, ok = tokSplit("", 19)
	assert.True(t, ok)
	assert.Empty(t, frags)

	_, ok = tokSplit(strings.Repeat("a,", 19), 19)
	assert.True(t, ok)

	_, ok = tokSplit(strings.Repeat("a,", 20), 19)
	assert.False(t, ok)
}

func TestPinSpecRelease(t *testing.T) {
	t.Parallel()

	rel := &ReleaseInfo{Origin: "Debian", Label: "Debian", Suite: "stable", Codename: "bookworm", Version: "12.5", Component: "main", Architecture: "amd64", Site: "deb.example.org"}
	bare := &ReleaseInfo{Site: "x"}

	cases := []struct {
		data  string
		rel   *ReleaseInfo
		match bool
	}{
		{"*", bare, true},
		{"a=stable", rel, true},
		{"A=STABLE", rel, true},
		{"a=stable", bare, false},
		{"n=bookworm", rel, true},
		{"n=trixie", rel, false},
		{"o=Debian,a=stable,n=bookworm,l=Debian,v=12.5,c=main,b=amd64", rel, true},
		{"o=Debian,a=stable,c=contrib", rel, false},
		{"b=arm64", rel, false},
		{"v=12", rel, false},
		{"v=12*", rel, true},
		{"v=12.5", rel, true},
		{"v=1?.5", rel, true},
		{"12.5", rel, true},
		{"12*", rel, true},
		{"stable", rel, true},
		{"bookworm", rel, true},
		{"unstable", rel, false},
		{"a=stable, n=bookworm", rel, true},
		{"o=*Deb*", rel, true},
		{"l=/^deb/", rel, true},
		{"", rel, false},
		{"x=y", rel, false},
		{"v=*", rel, false},
		{"a", rel, false},
		{"a=", rel, false},
	}

	for _, c := range cases {
		s := newPinSpec(PinRelease, c.data)
		assert.Equal(t, c.match, s.matchFile(pinFile{rel: c.rel}), "%q", c.data)
	}

	status := map[string]bool{
		"*": true, "a=now": true, "c=now": true, "a=stable": false, "o=Debian": false,
		"l=x": false, "v=1": false, "n=now": false, "b=amd64": false, "now": true, "a=now,c=now": true,
	}
	for data, want := range status {
		assert.Equal(t, want, newPinSpec(PinRelease, data).matchFile(pinFile{status: true}), "status %q", data)
	}

	assert.False(t, newPinSpec(PinRelease, strings.Repeat("a=x,", 25)).matchFile(pinFile{rel: rel}))
	assert.True(t, newPinSpec(PinRelease, strings.Repeat("a=x,", 25)).matchFile(pinFile{status: true}))
}

func TestPinSpecOrigin(t *testing.T) {
	t.Parallel()

	rel := &ReleaseInfo{Site: "deb.example.org"}

	for data, want := range map[string]bool{
		"deb.example.org": true, `"deb.example.org"`: true, "*.example.org": true, "": false,
		"other.example.org": false, `"deb.example.org`: false,
	} {
		assert.Equal(t, want, newPinSpec(PinOrigin, data).matchFile(pinFile{rel: rel}), "%q", data)
	}

	assert.True(t, newPinSpec(PinOrigin, "").matchFile(pinFile{rel: &ReleaseInfo{}}))
	assert.False(t, newPinSpec(PinOrigin, "").matchFile(pinFile{status: true}))
	assert.False(t, newPinSpec(PinVersion, "1").matchFile(pinFile{rel: rel}))
}

func TestPinSpecVersion(t *testing.T) {
	t.Parallel()

	v := &PackageInfo{Name: "foo", Version: "1:2.0-1", SourceName: "foosrc", SourceVersion: "2.0-1"}

	assert.True(t, newPinSpec(PinVersion, "1:2.0-1").matchVersion(v, nil))
	assert.True(t, newPinSpec(PinVersion, "1:2*").matchVersion(v, nil))
	assert.True(t, newPinSpec(PinVersion, "1:2.[0-1]-?").matchVersion(v, nil))
	assert.False(t, newPinSpec(PinVersion, "2.0-1").matchVersion(v, nil))
	assert.True(t, newPinSpec(PinSourceVersion, "2.0-1").matchVersion(v, nil))
	assert.False(t, newPinSpec(PinSourceVersion, "1:2.0-1").matchVersion(v, nil))
	assert.True(t, newPinSpec(PinSourceVersion, "2.*").matchVersion(&PackageInfo{Version: "2.5"}, nil))
	assert.False(t, newPinSpec(PinRelease, "a=x").matchVersion(v, nil))
	assert.False(t, newPinSpec(PinVersion, "").matchVersion(v, nil))
}

func TestNamePin(t *testing.T) {
	t.Parallel()

	v := &PackageInfo{Name: "libfoo1", Architecture: "amd64", SourceName: "foosrc"}
	all := &PackageInfo{Name: "docs", Architecture: "all"}
	i386 := &PackageInfo{Name: "libfoo1", Architecture: "i386"}

	cases := []struct {
		token string
		v     *PackageInfo
		want  bool
	}{
		{"libfoo1", v, true},
		{"LIBFOO1", v, false},
		{"libfoo1:amd64", v, true},
		{"libfoo1:i386", v, false},
		{"libfoo1:*", v, true},
		{"libfoo1:*", i386, true},
		{"libfoo1:any", i386, true},
		{"libfoo1:linux-any", v, true},
		{"libfoo1:linux-*", v, true},
		{"libfoo1:all", v, false},
		{"lib*", v, true},
		{"lib*:i386", v, false},
		{"lib*:i386", i386, true},
		{"libfoo?", v, true},
		{"libfoo1*", v, true},
		{"/^lib/", v, true},
		{"/^LIB/", v, true},
		{"/^foo/", v, false},
		{"/libfoo1/", v, true},
		{"src:foosrc", v, true},
		{"src:foo*", v, true},
		{"src:libfoo1", v, false},
		{"src:/^foo/", v, true},
		{"src:foosrc:i386", v, false},
		{"docs", all, true},
		{"docs:amd64", all, true},
		{"docs:i386", all, false},
		{"docs:all", all, false},
		{"*", v, true},
		{"[lm]ibfoo1", v, true},
	}

	for _, c := range cases {
		n := newNamePin(c.token)
		assert.Equal(t, c.want, n.matches(c.v, "amd64"), "%q", c.token)
	}

	assert.Equal(t, "libfoo1", sourceNameOf(&PackageInfo{Name: "libfoo1"}))
	assert.Equal(t, "foosrc", sourceNameOf(v))
	assert.Equal(t, "1.0", sourceVersionOf(&PackageInfo{Version: "1.0"}))
	assert.Equal(t, "2", sourceVersionOf(&PackageInfo{Version: "1.0", SourceVersion: "2"}))
	assert.Equal(t, "any-any-amd64", wildcardArch("*-*-amd64"))
	assert.Equal(t, "amd64", wildcardArch("amd64"))
	assert.Equal(t, `\p{L}`, regexpClass("alpha"))
	assert.Equal(t, `\p{L}\p{Nd}`, regexpClass("alnum"))
	assert.Equal(t, "[:digit:]", regexpClass("digit"))
}
