package apt

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// policyImages are the containers the policy fixtures were recorded in.
var policyImages = []string{"bookworm", "trixie", "unstable"}

func policyDir(parts ...string) string {
	return filepath.Join(append([]string{"testdata", "policy"}, parts...)...)
}

// scenario is one case of the policy fixtures: preferences files, a dpkg state
// and a default release, as recorded by the container run.
type scenario struct {
	name   string
	dir    string
	status string
	target string
}

func listScenarios(t *testing.T) []scenario {
	t.Helper()

	entries, err := os.ReadDir(policyDir("scenarios"))
	require.NoError(t, err)

	var out []scenario

	for _, e := range entries {
		dir := policyDir("scenarios", e.Name())
		s := scenario{name: e.Name(), dir: dir}

		data, err := os.ReadFile(filepath.Join(dir, "scenario"))
		require.NoError(t, err)

		for line := range strings.SplitSeq(string(data), "\n") {
			if v, ok := strings.CutPrefix(line, "status: "); ok {
				s.status = v
			}

			if v, ok := strings.CutPrefix(line, "default-release: "); ok {
				s.target = v
			}
		}

		require.NotEmpty(t, s.status, e.Name())

		out = append(out, s)
	}

	require.GreaterOrEqual(t, len(out), 100)

	return out
}

var (
	policyFileLine    = regexp.MustCompile(`^ (-?\d+) (\S+) (\S+)/(\S+) (\S+) Packages$`)
	policyStatusLine  = regexp.MustCompile(`^ (-?\d+) /var/lib/dpkg/status$`)
	policyPackageLine = regexp.MustCompile(`^(\S+):$`)
)

// checkFilePriorities compares the priority apt gave every package file with
// the Policy's.
func checkFilePriorities(t *testing.T, repo *fixtureRepo, p *Policy, files string) int {
	t.Helper()

	n := 0

	for line := range strings.SplitSeq(files, "\n") {
		if m := policyStatusLine.FindStringSubmatch(line); m != nil {
			want, _ := strconv.Atoi(m[1])
			assert.Equal(t, want, p.filePriority(pinFile{status: true}), "status file")

			n++

			continue
		}

		m := policyFileLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		site := strings.TrimPrefix(strings.TrimPrefix(m[2], "http://"), "https://")
		site, _, _ = strings.Cut(site, "/")

		if strings.HasPrefix(m[2], "file:") {
			site = ""
		}

		rel := repo.files[site+" "+m[3]+"/"+m[4]+" "+m[5]]
		require.NotNil(t, rel, line)

		want, _ := strconv.Atoi(m[1])
		assert.Equal(t, want, p.filePriority(pinFile{rel: rel}), "file %s", line)

		n++
	}

	return n
}

// slotKey maps the header of an apt-cache policy block to a fixture slot.
func slotKey(header string) string {
	if strings.Contains(header, ":") {
		return header
	}

	return header + ":amd64"
}

var policyVersionRow = regexp.MustCompile(`^(?: \*\*\*|    ) (\S+) (-?\d+)(?: \(phased (\d+)%\))?$`)

// checkPolicyOutput compares the version tables of `apt-cache policy`.
func checkPolicyOutput(t *testing.T, repo *fixtureRepo, p *Policy, out string) (versions int) {
	t.Helper()

	var (
		key   string
		want  = map[string]int{}
		cand  string
		have  bool
		flush = func() {
			if !have {
				return
			}

			slot := repo.slots[key]

			got := map[string]int{}
			for _, v := range slot {
				got[v.Version] = p.Priority(v)
			}

			assert.Equal(t, want, got, "priorities of %s", key)

			c := p.Candidate(slot, repo.installed(key))
			if cand == "(none)" {
				assert.Nil(t, c, "candidate of %s", key)
			} else if assert.NotNil(t, c, "candidate of %s", key) {
				assert.Equal(t, cand, c.Version, "candidate of %s", key)
			}

			versions += len(want)
		}
	)

	for line := range strings.SplitSeq(out, "\n") {
		if m := policyPackageLine.FindStringSubmatch(line); m != nil && !strings.HasPrefix(line, " ") {
			flush()

			key, want, cand, have = slotKey(m[1]), map[string]int{}, "", true

			continue
		}

		if v, ok := strings.CutPrefix(line, "  Candidate: "); ok {
			cand = v

			continue
		}

		if m := policyVersionRow.FindStringSubmatch(line); m != nil && have {
			n, err := strconv.Atoi(m[2])
			require.NoError(t, err)

			want[m[1]] = n
		}
	}

	flush()

	return versions
}

// installResult is what the Policy predicts `apt-get -s install name` does.
func installResult(repo *fixtureRepo, p *Policy, key string) (kind, version string) {
	slot := repo.slots[key]
	inst := repo.installed(key)

	cand := p.Candidate(slot, inst)

	switch {
	case cand == nil:
		return "error", ""
	case inst != nil && inst.Version == cand.Version:
		return "same", cand.Version
	default:
		return "inst", cand.Version
	}
}

func checkInstall(t *testing.T, repo *fixtureRepo, p *Policy, tsv string) int {
	t.Helper()

	n := 0

	for line := range strings.SplitSeq(strings.TrimSuffix(tsv, "\n"), "\n") {
		spec, res, _ := strings.Cut(line, "\t")
		kind, version := installResult(repo, p, slotKey(spec))

		want := kind + "=" + version
		if kind == "error" {
			assert.True(t, strings.HasPrefix(res, "error="), "install %s: apt said %q, policy has no candidate", spec, res)
		} else {
			assert.Equal(t, res, want, "install %s", spec)
		}

		n++
	}

	return n
}

func checkUpgrade(t *testing.T, repo *fixtureRepo, p *Policy, tsv string) {
	t.Helper()

	var want []string

	// apt holds back Multi-Arch: same packages whose other architectures
	// would be left behind; the fixtures do not model that.
	skip := map[string]bool{}

	for _, key := range repo.keys {
		if inst := repo.installed(key); inst != nil && inst.MultiArchSame() {
			skip[strings.TrimSuffix(key, ":amd64")] = true
		}
	}

	for _, key := range repo.keys {
		inst := repo.installed(key)
		if inst == nil || skip[strings.TrimSuffix(key, ":amd64")] {
			continue
		}

		// A candidate other than the installed version is installed over it:
		// newer, or older when a pin of 1000 or more asks for a downgrade.
		if cand := p.Candidate(repo.slots[key], inst); cand != nil && cand.Version != inst.Version {
			want = append(want, strings.TrimSuffix(key, ":amd64")+"="+cand.Version)
		}
	}

	slices.Sort(want)

	var got []string

	for _, f := range strings.Fields(tsv) {
		name, _, _ := strings.Cut(f, "=")
		if !skip[name] {
			got = append(got, f)
		}
	}

	assert.Equal(t, got, want, "upgrade")
}

// preferencesError maps the failure apt reported to the sentinel of the error
// ParsePreferences gives.
func preferencesError(stderr string) error {
	switch {
	case strings.Contains(stderr, "no Package header"):
		return ErrNoPackageHeader
	case strings.Contains(stderr, "'Pin-Priority: never' can only be used"):
		return ErrNeverPin
	case strings.Contains(stderr, "No priority (or zero) specified for pin"), strings.Contains(stderr, "outside the range of valid pin priorities"):
		return ErrPinPriority
	}

	return nil
}

func TestPolicyMatchesAptScenarios(t *testing.T) {
	t.Parallel()

	scenarios := listScenarios(t)

	for _, image := range policyImages {
		t.Run(image, func(t *testing.T) {
			t.Parallel()

			base := policyDir("results", image)

			manifest, err := os.ReadFile(filepath.Join(base, "MANIFEST"))
			require.NoError(t, err)
			assert.Contains(t, string(manifest), "apt ")

			var totalFiles, totalVersions, totalInstalls int

			for _, s := range scenarios {
				t.Run(s.name, func(t *testing.T) {
					res := filepath.Join(base, "scenarios", s.name)
					read := func(name string) string {
						data, err := os.ReadFile(filepath.Join(res, name))
						require.NoError(t, err, s.name)

						return string(data)
					}

					prefs, prefErr := LoadPreferences(filepath.Join(s.dir, "preferences"), filepath.Join(s.dir, "preferences.d"))
					stderr := read("stderr")

					want := preferencesError(stderr)
					if want != nil {
						require.ErrorIs(t, prefErr, want, "scenario %s: apt said %q", s.name, stderr)
					} else {
						require.NoError(t, prefErr, "scenario %s", s.name)
					}

					repo := loadFixtureRepo(t, policyDir("lists"), policyDir("status", s.status), "amd64")
					p := NewPolicy(prefs, PolicyOptions{DefaultRelease: s.target, NativeArch: "amd64", IgnoreSourceVersionPins: image == "bookworm"})

					t.Logf("%s: apt rc=%s", s.name, strings.TrimSpace(read("rc")))

					totalFiles += checkFilePriorities(t, repo, p, read("files"))
					totalVersions += checkPolicyOutput(t, repo, p, read("policy"))

					// apt plans nothing with a preferences error, but still
					// prints the policy of the pins it read before it.
					if want == nil && !strings.Contains(read("install.tsv"), "invalid for APT::Default-Release") {
						totalInstalls += checkInstall(t, repo, p, read("install.tsv"))
						checkUpgrade(t, repo, p, read("upgrade.tsv"))
					}
				})
			}

			assert.Greater(t, totalFiles, 1000)
			assert.Greater(t, totalVersions, 1000)
			assert.Greater(t, totalInstalls, 1000)
		})
	}
}

func handVersion(name, version string, rels ...*ReleaseInfo) *PackageInfo {
	return &PackageInfo{Name: name, Architecture: "amd64", Version: version, Releases: rels}
}

func TestPolicyPriorityHandBuilt(t *testing.T) {
	t.Parallel()

	stable := &ReleaseInfo{Suite: "stable", Codename: "bookworm", Origin: "Debian", Site: "deb.example.org"}
	backports := &ReleaseInfo{Suite: "bookworm-backports", NotAutomatic: true, ButAutomaticUpgrades: true, Site: "deb.example.org"}
	experimental := &ReleaseInfo{Suite: "experimental", NotAutomatic: true, Site: "deb.example.org"}

	plain := NewPolicy(nil, PolicyOptions{NativeArch: "amd64"})
	assert.Equal(t, 0, plain.Priority(nil))
	assert.Equal(t, PriorityDefault, plain.Priority(handVersion("a", "1")), "no index at all counts as one archive")
	assert.Equal(t, PriorityDefault, plain.Priority(handVersion("a", "1", stable)))
	assert.Equal(t, PriorityInstalled, plain.Priority(handVersion("a", "1", backports)))
	assert.Equal(t, PriorityNotAutomatic, plain.Priority(handVersion("a", "1", experimental)))
	assert.Equal(t, PriorityDefault, plain.Priority(handVersion("a", "1", nil, stable)), "a nil release is skipped")

	installedOnly := &PackageInfo{Name: "a", Version: "1", Installed: true}
	assert.Equal(t, PriorityInstalled, plain.Priority(installedOnly), "only the status file")
	assert.Equal(t, PriorityDefault, plain.Priority(&PackageInfo{Name: "a", Version: "1", Installed: true, Releases: []*ReleaseInfo{stable}}),
		"the best of the status file and the index")

	target := NewPolicy(nil, PolicyOptions{NativeArch: "amd64", DefaultRelease: "bookworm"})
	assert.Equal(t, PriorityTarget, target.Priority(handVersion("a", "1", stable)))
	assert.Equal(t, PriorityDefault, target.Priority(handVersion("a", "1", &ReleaseInfo{Suite: "unstable", Codename: "sid"})))
	assert.Equal(t, PriorityTarget, NewPolicy(nil, PolicyOptions{NativeArch: "amd64", DefaultRelease: "a=stable"}).Priority(handVersion("a", "1", stable)))

	prefs, err := ParsePreferences(`Package: *
Pin: release a=experimental
Pin-Priority: 600

Package: pinned
Pin: version 2*
Pin-Priority: 1001

Package: pinned
Pin: release a=stable
Pin-Priority: 300

Package: banned
Pin: release *
Pin-Priority: -1

Package: *
Pin: origin deb.example.org
Pin-Priority: 400
`)
	require.NoError(t, err)

	p := NewPolicy(prefs, PolicyOptions{NativeArch: "amd64", DefaultRelease: "stable"})
	assert.Equal(t, PriorityTarget, p.Priority(handVersion("x", "1", stable)), "the default release pin comes first")
	assert.Equal(t, 600, p.Priority(handVersion("x", "1", experimental)))
	assert.Equal(t, 1001, p.Priority(handVersion("pinned", "2.1", stable)))
	assert.Equal(t, 300, p.Priority(handVersion("pinned", "1.1", stable)))
	assert.Equal(t, -1, p.Priority(handVersion("banned", "1", stable)))
	assert.Equal(t, 400, p.Priority(handVersion("x", "1", backports)))

	never, err := ParsePreferences("Package: *\nPin: release a=stable\nPin-Priority: never\n")
	require.NoError(t, err)

	np := NewPolicy(never, PolicyOptions{NativeArch: "amd64"})
	assert.Equal(t, PriorityNever, np.Priority(handVersion("x", "1", stable)))
	assert.Equal(t, PriorityDefault, np.Priority(handVersion("x", "1", stable, &ReleaseInfo{Suite: "testing"})), "one live file keeps it")
}

func TestPolicyPriorityPhasePolicy(t *testing.T) {
	t.Parallel()

	pct := 30
	v := &PackageInfo{Name: "a", Architecture: "amd64", Version: "2", PhasedUpdatePercentage: &pct, Releases: []*ReleaseInfo{{Suite: "stable"}}}

	held, free := "", ""

	for i := range 200 {
		id := strconv.Itoa(i)
		if PhasedDraw("a", "2", id, PhasedCurrent) >= pct {
			held = id
		} else {
			free = id
		}
	}

	require.NotEmpty(t, held)
	require.NotEmpty(t, free)

	assert.Equal(t, 1, NewPolicy(nil, PolicyOptions{NativeArch: "amd64", MachineID: held, PhasePolicy: true}).Priority(v))
	assert.Equal(t, PriorityDefault, NewPolicy(nil, PolicyOptions{NativeArch: "amd64", MachineID: free, PhasePolicy: true}).Priority(v))
	assert.Equal(t, PriorityDefault, NewPolicy(nil, PolicyOptions{NativeArch: "amd64", MachineID: held}).Priority(v), "without Phase-Policy the pin priority is unchanged")

	prefs, err := ParsePreferences("Package: a\nPin: release a=stable\nPin-Priority: 1200\n")
	require.NoError(t, err)
	assert.Equal(t, 1, NewPolicy(prefs, PolicyOptions{NativeArch: "amd64", MachineID: held, PhasePolicy: true}).Priority(v), "the ceiling applies to pins")
}

func TestPolicyCandidateHandBuilt(t *testing.T) {
	t.Parallel()

	stable := &ReleaseInfo{Suite: "stable"}
	experimental := &ReleaseInfo{Suite: "experimental", NotAutomatic: true}

	v3 := handVersion("a", "3", experimental)
	v2 := handVersion("a", "2", stable)
	v1 := handVersion("a", "1", stable)
	versions := []*PackageInfo{v3, v2, v1}

	p := NewPolicy(nil, PolicyOptions{NativeArch: "amd64"})

	assert.Nil(t, p.Candidate(nil, nil))
	assert.Same(t, v2, p.Candidate(versions, nil))
	assert.Same(t, v2, p.Candidate(versions, v1))
	assert.Same(t, v2, p.Candidate([]*PackageInfo{nil, v2, v1}, nil))

	// Never a downgrade below priority 1000: the installed version wins over
	// an older, equally ranked one.
	installed := &PackageInfo{Name: "a", Architecture: "amd64", Version: "4", Installed: true}
	assert.Same(t, installed, p.Candidate(append([]*PackageInfo{installed}, versions...), nil), "the installed version flagged in the list")

	prefs, err := ParsePreferences("Package: a\nPin: version 1\nPin-Priority: 1000\n")
	require.NoError(t, err)

	down := NewPolicy(prefs, PolicyOptions{NativeArch: "amd64"})
	assert.Same(t, v1, down.Candidate(versions, installed), "a pin of 1000 downgrades")
	assert.Same(t, v1, down.Candidate(versions, nil))

	zero := NewPolicy(mustPrefs(t, "Package: a\nPin: release *\nPin-Priority: -10\n"), PolicyOptions{NativeArch: "amd64"})
	assert.Nil(t, zero.Candidate(versions, nil))
	assert.Equal(t, -10, zero.Priority(v2))
}

func mustPrefs(t *testing.T, content string) *Preferences {
	t.Helper()

	prefs, err := ParsePreferences(content)
	require.NoError(t, err)

	return prefs
}

func TestPolicyIgnoresSourceVersionPinsLikeOldApt(t *testing.T) {
	t.Parallel()

	prefs := mustPrefs(t, "Package: a\nPin: source-version 2\nPin-Priority: 900\n")
	v := &PackageInfo{Name: "a", Version: "2", Architecture: "amd64", Releases: []*ReleaseInfo{{Suite: "stable"}}}

	assert.Equal(t, 900, NewPolicy(prefs, PolicyOptions{NativeArch: "amd64"}).Priority(v))
	assert.Equal(t, PriorityDefault, NewPolicy(prefs, PolicyOptions{NativeArch: "amd64", IgnoreSourceVersionPins: true}).Priority(v))
}

func TestNewPolicyNativeArchDefault(t *testing.T) {
	t.Parallel()

	assert.NotEmpty(t, NewPolicy(nil, PolicyOptions{}).native)
	assert.Equal(t, "abc", NewPolicy(nil, PolicyOptions{MachineID: "abc\r\nrest"}).machineID)
}
