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

// phasedImages are the containers the phased fixtures were recorded in, with
// the apt version they ran and the model that reproduces it.
var phasedImages = []struct {
	label string
	apt   string
	model PhasedModel
}{
	{"bookworm", "apt 2.6.", PhasedPre2711},
	{"trixie", "apt 3.0.", PhasedPre33},
	{"unstable", "apt 3.3.", PhasedCurrent},
}

func phasedDir(parts ...string) string {
	return filepath.Join(append([]string{"testdata", "phased"}, parts...)...)
}

func phasedRepo(t *testing.T) *fixtureRepo {
	t.Helper()

	return loadFixtureRepo(t, phasedDir("repo"), phasedDir("repo", "status"), "amd64")
}

// readTSV reads a two column tab separated file into rows.
func readTSV(t *testing.T, path string) [][2]string {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var rows [][2]string

	for line := range strings.SplitSeq(strings.TrimSuffix(string(data), "\n"), "\n") {
		a, b, _ := strings.Cut(line, "\t")
		rows = append(rows, [2]string{a, b})
	}

	return rows
}

// upgradeOffer is the sorted names a Policy would have `apt-get upgrade`
// install.
func upgradeOffer(repo *fixtureRepo, p *Policy) string {
	var names []string

	for _, key := range repo.keys {
		versions := repo.slots[key]

		inst := repo.installed(key)
		if inst == nil {
			continue
		}

		cand := p.Candidate(versions, inst)
		if cand == nil || cand.Version == inst.Version || p.PhasedIn(versions, cand, inst) {
			continue
		}

		names = append(names, strings.TrimSuffix(key, ":amd64"))
	}

	slices.Sort(names)

	return strings.Join(names, " ")
}

func TestPhasedSweepMatchesApt(t *testing.T) {
	t.Parallel()

	repo := phasedRepo(t)

	for _, img := range phasedImages {
		t.Run(img.label, func(t *testing.T) {
			t.Parallel()

			manifest, err := os.ReadFile(phasedDir("results", img.label, "MANIFEST"))
			require.NoError(t, err)
			require.Contains(t, string(manifest), img.apt)
			require.Contains(t, string(manifest), "not a chroot")

			rows := readTSV(t, phasedDir("results", img.label, "sweep.tsv"))
			require.GreaterOrEqual(t, len(rows), 300)

			held, offered := 0, 0

			for _, row := range rows {
				p := NewPolicy(nil, PolicyOptions{MachineID: row[0], PhasedBehavior: img.model})
				assert.Equal(t, row[1], upgradeOffer(repo, p), "machine id %s", row[0])

				offered += len(strings.Fields(row[1]))
				held += 23 - len(strings.Fields(row[1]))
			}

			// The sweep is only meaningful if both outcomes occur for many.
			assert.Greater(t, held, 1000)
			assert.Greater(t, offered, 1000)
		})
	}
}

func TestPhasedPhasePolicySweepMatchesApt(t *testing.T) {
	t.Parallel()

	repo := phasedRepo(t)

	for _, img := range phasedImages {
		t.Run(img.label, func(t *testing.T) {
			t.Parallel()

			rows := readTSV(t, phasedDir("results", img.label, "sweep-phase-policy.tsv"))
			require.Len(t, rows, 100)

			for _, row := range rows {
				p := NewPolicy(nil, PolicyOptions{MachineID: row[0], PhasedBehavior: img.model, PhasePolicy: true})
				assert.Equal(t, row[1], upgradeOffer(repo, p), "machine id %s", row[0])
			}
		})
	}
}

func TestPhasedOptionsMatchApt(t *testing.T) {
	t.Parallel()

	repo := phasedRepo(t)

	for _, img := range phasedImages {
		t.Run(img.label, func(t *testing.T) {
			t.Parallel()

			first := readTSV(t, phasedDir("results", img.label, "sweep.tsv"))[0][0]

			opts := map[string]PolicyOptions{
				"never":               {MachineID: first, NeverIncludePhased: true},
				"always":              {MachineID: first, AlwaysIncludePhased: true},
				"no-machine-id":       {},
				"never-no-machine-id": {NeverIncludePhased: true},
				"always-and-never":    {MachineID: first, AlwaysIncludePhased: true, NeverIncludePhased: true},
			}

			rows := readTSV(t, phasedDir("results", img.label, "options.tsv"))
			require.Len(t, rows, len(opts))

			for _, row := range rows {
				o, ok := opts[row[0]]
				require.True(t, ok, row[0])

				o.PhasedBehavior = img.model
				assert.Equal(t, row[1], upgradeOffer(repo, NewPolicy(nil, o)), row[0])
			}
		})
	}
}

// installPlan reads the "name=version" plan of an install sweep.
func TestPhasedInstallIgnoresPhasing(t *testing.T) {
	t.Parallel()

	repo := phasedRepo(t)

	for _, img := range phasedImages {
		t.Run(img.label, func(t *testing.T) {
			t.Parallel()

			rows := readTSV(t, phasedDir("results", img.label, "install.tsv"))
			require.Len(t, rows, 5)

			for _, row := range rows {
				p := NewPolicy(nil, PolicyOptions{MachineID: row[0], PhasedBehavior: img.model})

				var want []string

				for _, key := range repo.keys {
					cand := p.Candidate(repo.slots[key], repo.installed(key))
					if inst := repo.installed(key); cand == nil || inst != nil && inst.Version == cand.Version {
						continue
					}

					want = append(want, strings.TrimSuffix(key, ":amd64")+"="+cand.Version)
				}

				slices.Sort(want)
				assert.Equal(t, row[1], strings.Join(want, " "), "machine id %s", row[0])
			}
		})
	}
}

var (
	policyVersionLine = regexp.MustCompile(`^( \*\*\*|     ) (\S+) (-?\d+)(?: \(phased (\d+)%\))?$`)
	policyHeaderLine  = regexp.MustCompile(`^(\S+):$`)
)

func TestPhasedPolicyOutputMatchesApt(t *testing.T) {
	t.Parallel()

	repo := phasedRepo(t)

	for _, img := range phasedImages {
		t.Run(img.label, func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(phasedDir("results", img.label, "policy-phase-policy.txt"))
			require.NoError(t, err)

			var (
				p       *Policy
				name    string
				checked int
			)

			for line := range strings.SplitSeq(string(data), "\n") {
				if id, ok := strings.CutPrefix(line, "### machine-id "); ok {
					p = NewPolicy(nil, PolicyOptions{MachineID: id, PhasedBehavior: img.model, PhasePolicy: true})

					continue
				}

				if m := policyHeaderLine.FindStringSubmatch(line); m != nil {
					name = m[1]

					continue
				}

				if cand, ok := strings.CutPrefix(strings.TrimSpace(line), "Candidate: "); ok {
					key := name + ":amd64"
					got := p.Candidate(repo.slots[key], repo.installed(key))
					require.NotNil(t, got, name)
					assert.Equal(t, cand, got.Version, "candidate of %s", name)

					checked++

					continue
				}

				if m := policyVersionLine.FindStringSubmatch(line); m != nil {
					want, err := strconv.Atoi(m[3])
					require.NoError(t, err)

					var found *PackageInfo

					for _, v := range repo.slots[name+":amd64"] {
						if v.Version == m[2] {
							found = v
						}
					}

					require.NotNil(t, found, "%s %s", name, m[2])
					assert.Equal(t, want, p.Priority(found), "priority of %s %s", name, m[2])

					checked++
				}
			}

			assert.Greater(t, checked, 100)
		})
	}
}

// phasedIDs finds machine identifiers a package version is held back for and
// let through.
func phasedIDs(t *testing.T, src, srcVer string, pct int, model PhasedModel) (held, free string) {
	t.Helper()

	for i := range 500 {
		id := "machine-" + strconv.Itoa(i)

		draw := PhasedDraw(src, srcVer, id, model)
		if model.heldBack(draw, pct) {
			held = id
		} else {
			free = id
		}
	}

	require.NotEmpty(t, held)
	require.NotEmpty(t, free)

	return held, free
}

func TestPhasedHandBuilt(t *testing.T) {
	t.Parallel()

	pct := 50
	phased := &PackageInfo{Name: "a", Version: "2", Architecture: "amd64", PhasedUpdatePercentage: &pct, Releases: []*ReleaseInfo{{Suite: "stable-updates"}}}
	installed := &PackageInfo{Name: "a", Version: "1", Architecture: "amd64", Installed: true}
	held, free := phasedIDs(t, "a", "2", pct, PhasedCurrent)

	opts := func(o PolicyOptions) *Policy {
		o.NativeArch = "amd64"

		return NewPolicy(nil, o)
	}

	assert.True(t, opts(PolicyOptions{MachineID: held}).Phased(phased, installed))
	assert.False(t, opts(PolicyOptions{MachineID: free}).Phased(phased, installed))
	assert.False(t, opts(PolicyOptions{MachineID: held + "\n"}).Phased(phased, nil), "a new installation is never phased")
	assert.True(t, opts(PolicyOptions{MachineID: held + "\r\nignored"}).Phased(phased, installed), "only the first line counts")
	assert.False(t, opts(PolicyOptions{MachineID: held}).Phased(nil, installed))
	assert.False(t, opts(PolicyOptions{MachineID: held}).Phased(phased, phased), "the installed version itself")
	assert.False(t, opts(PolicyOptions{MachineID: held}).Phased(phased, &PackageInfo{Name: "a", Version: "2", Installed: true}))
	assert.False(t, opts(PolicyOptions{}).Phased(phased, installed), "no machine id turns phasing off")
	assert.False(t, opts(PolicyOptions{MachineID: held, InChroot: true}).Phased(phased, installed))
	assert.False(t, opts(PolicyOptions{MachineID: held, AlwaysIncludePhased: true}).Phased(phased, installed))
	assert.True(t, opts(PolicyOptions{NeverIncludePhased: true}).Phased(phased, installed))
	assert.False(t, opts(PolicyOptions{NeverIncludePhased: true, AlwaysIncludePhased: true}).Phased(phased, installed), "always wins")

	for _, v := range []*int{nil, new(100), new(101), new(-1)} {
		other := *phased
		other.PhasedUpdatePercentage = v

		assert.False(t, opts(PolicyOptions{NeverIncludePhased: true}).Phased(&other, installed), "percentage %v is not phasing", v)
	}

	zero := *phased
	zero.PhasedUpdatePercentage = new(0)
	assert.True(t, opts(PolicyOptions{MachineID: held}).Phased(&zero, installed))
	assert.True(t, opts(PolicyOptions{MachineID: free}).Phased(&zero, installed), "0% holds back every machine")

	// Another source name and version change the draw.
	split := *phased
	split.SourceName, split.SourceVersion = "other", "9"
	assert.Equal(t, PhasedDraw("other", "9", held, PhasedCurrent) >= pct, opts(PolicyOptions{MachineID: held}).Phased(&split, installed))
}

func TestPhasedSecuritySuites(t *testing.T) {
	t.Parallel()

	pct := 0
	mk := func(version string, suite string) *PackageInfo {
		return &PackageInfo{Name: "a", Version: version, Architecture: "amd64", PhasedUpdatePercentage: &pct, Releases: []*ReleaseInfo{{Suite: suite}}}
	}

	installed := &PackageInfo{Name: "a", Version: "1", Architecture: "amd64", Installed: true}
	v3, v2 := mk("3", "stable-updates"), mk("2", "stable-security")
	versions := []*PackageInfo{v3, v2, installed}

	cur := NewPolicy(nil, PolicyOptions{NativeArch: "amd64", MachineID: "id", PhasedBehavior: PhasedCurrent})
	assert.True(t, cur.Phased(v3, installed), "alone, v3 is not a security update")
	assert.False(t, cur.PhasedIn(versions, v3, installed), "an intermediate security version lifts the hold")
	assert.False(t, cur.Phased(v2, installed), "a security version itself")
	assert.True(t, cur.PhasedIn([]*PackageInfo{v3, installed}, v3, installed))
	assert.True(t, cur.PhasedIn([]*PackageInfo{v2, installed, v3}, v3, installed), "v3 is not in the list in order")
	assert.True(t, cur.PhasedIn([]*PackageInfo{v3, nil, v2}, v3, installed), "a nil entry ends the scan")

	older := NewPolicy(nil, PolicyOptions{NativeArch: "amd64", MachineID: "id", PhasedBehavior: PhasedPre2711})
	assert.True(t, older.Phased(v2, installed), "apt before 2.7.11 does not look at the candidate itself")
	assert.False(t, older.PhasedIn(versions, v3, installed))
}

func TestPhasedPolicyOptionAnswersForAnyVersion(t *testing.T) {
	t.Parallel()

	pct := 40
	v := &PackageInfo{Name: "a", Version: "2", PhasedUpdatePercentage: &pct}
	held, free := phasedIDs(t, "a", "2", pct, PhasedCurrent)

	assert.True(t, NewPolicy(nil, PolicyOptions{MachineID: held, PhasePolicy: true}).Phased(v, nil))
	assert.False(t, NewPolicy(nil, PolicyOptions{MachineID: free, PhasePolicy: true}).Phased(v, nil))
}

func TestPhasedModels(t *testing.T) {
	t.Parallel()

	assert.Equal(t, uint64(100), PhasedCurrent.draws())
	assert.Equal(t, uint64(101), PhasedPre33.draws())
	assert.Equal(t, uint64(101), PhasedPre2711.draws())

	assert.True(t, PhasedCurrent.heldBack(50, 50))
	assert.False(t, PhasedPre33.heldBack(50, 50))
	assert.True(t, PhasedPre33.heldBack(51, 50))

	for _, m := range []PhasedModel{PhasedCurrent, PhasedPre33, PhasedPre2711} {
		draw := PhasedDraw("src", "1.0", "id", m)
		assert.GreaterOrEqual(t, draw, 0)
		assert.Less(t, draw, int(m.draws()))
		assert.Equal(t, draw, PhasedDraw("src", "1.0", "id", m), "deterministic")
	}

	seen := map[int]bool{}
	for i := range 200 {
		seen[PhasedDraw("a", "1", "id"+strconv.Itoa(i), PhasedCurrent)] = true
	}

	assert.Greater(t, len(seen), 50, "draws spread over the range")
}
