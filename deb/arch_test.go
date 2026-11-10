package deb_test

import (
	"bufio"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

// dataLines returns the non-comment lines of a testdata file.
func dataLines(t *testing.T, name string) []string {
	t.Helper()

	f, err := os.Open("testdata/" + name)
	require.NoError(t, err)

	defer func() { _ = f.Close() }()

	var lines []string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	require.NoError(t, sc.Err())

	return lines
}

// TestArchMatchesAgainstDpkg compares ArchMatches with the answers of
// dpkg-architecture -i, recorded in testdata/arch-matrix.txt.
func TestArchMatchesAgainstDpkg(t *testing.T) {
	t.Parallel()

	lines := dataLines(t, "arch-matrix.txt")
	require.Greater(t, len(lines), 1000)

	for _, line := range lines {
		f := strings.Fields(line)
		require.Len(t, f, 3, line)

		assert.Equal(t, f[2] == "true", deb.ArchMatches(f[0], f[1]), "%s matches %s", f[0], f[1])
	}
}

func TestArchMatchesEdges(t *testing.T) {
	t.Parallel()

	assert.True(t, deb.ArchMatches("amd64", "amd64"))
	assert.True(t, deb.ArchMatches("somethingnew", "somethingnew"), "an unknown architecture matches itself")
	assert.True(t, deb.ArchMatches("somethingnew", "any"))
	assert.False(t, deb.ArchMatches("somethingnew", "linux-any"))
	assert.False(t, deb.ArchMatches("amd64", "any-nonsense"))
	assert.False(t, deb.ArchMatches("amd64", "nonsense"))
	assert.False(t, deb.ArchMatches("", "linux-any"))
	assert.True(t, deb.ArchMatches("armhf", "any-arm"))
	assert.False(t, deb.ArchMatches("arm64", "any-arm"))
	assert.False(t, deb.ArchMatches("amd64", "all"), "all is no architecture to build for")
}

// TestArchMatchesLive repeats the comparison against the dpkg-architecture on
// the machine, when there is one.
func TestArchMatchesLive(t *testing.T) {
	t.Parallel()

	path, err := exec.LookPath("dpkg-architecture")
	if err != nil {
		t.Skip("dpkg-architecture is not installed")
	}

	archs := []string{"amd64", "i386", "arm64", "armhf", "armel", "mips64el", "x32", "ppc64el", "riscv64", "s390x", "hurd-i386", "musl-linux-arm64"}
	patterns := []string{"any", "linux-any", "any-amd64", "any-arm", "gnu-linux-any", "hurd-any", "musl-any", "eabihf-any-any-any", "armhf", "x32", "any-any-any-arm64"}

	for _, a := range archs {
		for _, p := range patterns {
			want := exec.Command(path, "-a"+a, "-i"+p).Run() == nil
			assert.Equal(t, want, deb.ArchMatches(a, p), "%s matches %s", a, p)
		}
	}
}

// restrictionRelations reads testdata/restriction-relations.txt: the relations
// "rNN <restrictions>" in force or not for each case.
func restrictionRelations(t *testing.T) (names []string, rels map[string]deb.Relation) {
	t.Helper()

	rels = map[string]deb.Relation{}

	for _, line := range dataLines(t, "restriction-relations.txt") {
		name, rest, _ := strings.Cut(line, " ")

		parsed, err := deb.ParseRelations("pkg " + rest)
		require.NoError(t, err, line)
		require.Len(t, parsed, 1)

		names = append(names, name)
		rels[name] = parsed[0][0]
	}

	return names, rels
}

// TestRelationAppliesToAgainstDpkg compares AppliesTo with the dependencies
// dpkg-checkbuilddeps reports for each host architecture and set of build
// profiles (testdata/restriction-cases.txt).
func TestRelationAppliesToAgainstDpkg(t *testing.T) {
	t.Parallel()

	names, rels := restrictionRelations(t)

	for _, line := range dataLines(t, "restriction-cases.txt") {
		parts := strings.Split(line, "|")
		require.Len(t, parts, 3, line)

		var profiles []string
		if parts[1] != "" {
			profiles = strings.Split(parts[1], ",")
		}

		inForce := map[string]bool{}
		for _, n := range strings.Fields(parts[2]) {
			inForce[n] = true
		}

		for _, n := range names {
			assert.Equal(t, inForce[n], rels[n].AppliesTo(parts[0], profiles), "%s %q on %s with profiles %v", n, rels[n], parts[0], profiles)
		}
	}
}

func TestRelationAppliesToLive(t *testing.T) {
	t.Parallel()

	path, err := exec.LookPath("dpkg-checkbuilddeps")
	if err != nil {
		t.Skip("dpkg-checkbuilddeps is not installed")
	}

	admin := t.TempDir()
	require.NoError(t, os.WriteFile(admin+"/status", nil, 0o600))

	names, rels := restrictionRelations(t)

	var parts []string

	for _, n := range names {
		parts = append(parts, strings.Replace(rels[n].String(), "pkg", n, 1))
	}

	field := strings.Join(parts, ", ")

	for _, arch := range []string{"amd64", "arm64", "armhf", "hurd-i386"} {
		for _, profiles := range []string{"", "nocheck", "cross,stage1"} {
			args := []string{"-a", arch, "-d", field, os.DevNull}
			if profiles != "" {
				args = append([]string{"-P", profiles}, args...)
			}

			cmd := exec.Command(path, args...)
			cmd.Env = append(os.Environ(), "DPKG_ADMINDIR="+admin)
			out, _ := cmd.CombinedOutput()

			inForce := map[string]bool{}

			for _, w := range strings.Fields(string(out)) {
				if _, ok := rels[w]; ok {
					inForce[w] = true
				}
			}

			var active []string
			if profiles != "" {
				active = strings.Split(profiles, ",")
			}

			for _, n := range names {
				assert.Equal(t, inForce[n], rels[n].AppliesTo(arch, active), "%s on %s with %q", n, arch, profiles)
			}
		}
	}
}

func TestActiveRelations(t *testing.T) {
	t.Parallel()

	rels, err := deb.ParseRelations(
		"debhelper-compat (= 13), dh-golang <!nocheck>, libgtk-3-dev [linux-any] | libgtk-dev [!linux-any], " +
			"libhurd-dev [hurd-any], gcc-for-host <cross>, tzdata:any (>= 2020) [amd64 arm64] <!stage1>")
	require.NoError(t, err)

	tests := []struct {
		arch     string
		profiles []string
		want     string
	}{
		{"amd64", nil, "debhelper-compat (= 13), dh-golang, libgtk-3-dev, tzdata:any (>= 2020)"},
		{"amd64", []string{"nocheck"}, "debhelper-compat (= 13), libgtk-3-dev, tzdata:any (>= 2020)"},
		{"hurd-i386", nil, "debhelper-compat (= 13), dh-golang, libgtk-dev, libhurd-dev"},
		{"armhf", []string{"cross", "stage1"}, "debhelper-compat (= 13), dh-golang, libgtk-3-dev, gcc-for-host"},
	}

	for _, tt := range tests {
		got := deb.ActiveRelations(rels, tt.arch, tt.profiles)
		assert.Equal(t, tt.want, deb.FormatRelations(got), "%s %v", tt.arch, tt.profiles)
	}

	// The input is not modified.
	assert.Contains(t, deb.FormatRelations(rels), "[linux-any]")
	assert.Empty(t, deb.ActiveRelations(nil, "amd64", nil))
}

func TestAlternativesActiveDropsEmptyGroup(t *testing.T) {
	t.Parallel()

	rels, err := deb.ParseRelations("a [i386] | b [arm64]")
	require.NoError(t, err)

	assert.Nil(t, rels[0].Active("amd64", nil))
	assert.Equal(t, "b", rels[0].Active("arm64", nil).String())
}

func TestRelationTargetArch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		rel     deb.Relation
		depends string
		native  string
		arch    string
		anyArch bool
	}{
		{deb.Relation{Name: "p"}, "arm64", "amd64", "arm64", false},
		{deb.Relation{Name: "p"}, "all", "amd64", "amd64", false},
		{deb.Relation{Name: "p"}, "", "amd64", "amd64", false},
		{deb.Relation{Name: "p", Arch: "native"}, "arm64", "amd64", "amd64", false},
		{deb.Relation{Name: "p", Arch: "any"}, "arm64", "amd64", "", true},
		{deb.Relation{Name: "p", Arch: "i386"}, "arm64", "amd64", "i386", false},
	}

	for _, tt := range tests {
		arch, anyArch := tt.rel.TargetArch(tt.depends, tt.native)
		assert.Equal(t, tt.arch, arch, "%v", tt.rel)
		assert.Equal(t, tt.anyArch, anyArch, "%v", tt.rel)
	}
}

func TestRestrictionEdges(t *testing.T) {
	t.Parallel()

	assert.True(t, deb.ArchRestrictionApplies("amd64", nil))
	assert.True(t, deb.ProfileRestrictionApplies(nil, nil))
	assert.True(t, deb.ArchRestrictionApplies("AMD64", []deb.Restriction{{Name: "amd64"}}))
	assert.Equal(t, "!nocheck", deb.Restriction{Name: "nocheck", Negated: true}.String())
	assert.Equal(t, "cross", deb.Restriction{Name: "cross"}.String())
}

// TestRealBuildDepends parses Build-Depends fields of Debian source packages,
// renders them back, and compares the relations in force with what
// dpkg-checkbuilddeps reported for several host architectures and build
// profile sets (testdata/build-depends-expected.txt).
func TestRealBuildDepends(t *testing.T) {
	t.Parallel()

	fields := map[string]string{}

	for _, line := range dataLines(t, "build-depends.tsv") {
		name, field, ok := strings.Cut(line, "\t")
		require.True(t, ok, line)

		fields[name] = field

		rels, err := deb.ParseRelations(field)
		require.NoError(t, err, name)

		back, err := deb.ParseRelations(deb.FormatRelations(rels))
		require.NoError(t, err, name)
		assert.Equal(t, rels, back, name)
	}

	require.Len(t, fields, 11)

	for _, line := range dataLines(t, "build-depends-expected.txt") {
		parts := strings.SplitN(line, "|", 4)
		require.Len(t, parts, 4, line)

		var profiles []string
		if parts[2] != "" {
			profiles = strings.Split(parts[2], ",")
		}

		rels, err := deb.ParseRelations(fields[parts[0]])
		require.NoError(t, err)

		assertUnmetMatches(t, parts[3], deb.ActiveRelations(rels, parts[1], profiles),
			"%s on %s with profiles %q", parts[0], parts[1], parts[2])
	}
}

// assertUnmetMatches compares the relations in force with the list
// dpkg-checkbuilddeps printed. dpkg also simplifies the list: an alternative
// group that another entry already implies ("x | bash-doc" next to "bash-doc")
// is not printed. So every printed entry has to be present, in order, and
// every entry that is not printed has to be such an implied group.
func assertUnmetMatches(t *testing.T, printed string, active []deb.Alternatives, msg ...any) {
	t.Helper()

	single := map[string]bool{}

	for _, alts := range active {
		if len(alts) == 1 {
			single[alts[0].Name] = true
		}
	}

	rest := printed

	for _, alts := range active {
		text := alts.String()

		if after, ok := strings.CutPrefix(rest, text); ok && (after == "" || after[0] == ' ') {
			rest = strings.TrimPrefix(after, " ")

			continue
		}

		implied := len(alts) > 1 && slices.ContainsFunc(alts, func(r deb.Relation) bool { return single[r.Name] })
		assert.True(t, implied, "%q is in force but dpkg did not print it (%v)", text, msg)
	}

	assert.Empty(t, rest, "dpkg printed entries that are not in force (%v)", msg)
}
