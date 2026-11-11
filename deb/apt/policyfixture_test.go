package apt

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

// fixtureRepo is the package universe of a policy fixture: the lists apt read
// (a hand-authored repository, or the one a container used) and the dpkg
// status, as the Policy sees them.
type fixtureRepo struct {
	native string
	// slots maps "name:arch" to its versions, highest first. Architecture all
	// versions live in the slot of the native architecture.
	slots map[string][]*PackageInfo
	keys  []string
	// files maps "site dist/component arch" to the Release of that index.
	files map[string]*ReleaseInfo
}

// fixtureRelease reads the Release file of the index at path and the index
// name's component and architecture, the way apt derives them.
func fixtureRelease(t *testing.T, dir, index string) (*ReleaseInfo, string) {
	t.Helper()

	dists := strings.Index(index, "_dists_")
	require.GreaterOrEqual(t, dists, 0, index)

	hostPath := index[:dists]
	rest := strings.TrimSuffix(index[dists+len("_dists_"):], "_Packages")
	binary := strings.LastIndex(rest, "_binary-")
	require.GreaterOrEqual(t, binary, 0, index)

	arch := rest[binary+len("_binary-"):]
	suiteComp := rest[:binary]
	suite, comp, ok := strings.Cut(suiteComp, "_")
	require.True(t, ok, index)

	rel := &ReleaseInfo{Component: comp, Architecture: arch}
	rel.Site, _, _ = strings.Cut(hostPath, "_")

	data, err := os.ReadFile(filepath.Join(dir, hostPath+"_dists_"+suite+"_Release"))
	require.NoError(t, err)

	cf, err := deb.ParseControlFile(strings.NewReader(string(data)))
	require.NoError(t, err)

	rel.Origin, rel.Label, rel.Suite = cf.Get("Origin"), cf.Get("Label"), cf.Get("Suite")
	rel.Codename, rel.Version = cf.Get("Codename"), cf.Get("Version")
	rel.NotAutomatic = strings.EqualFold(cf.Get("NotAutomatic"), "yes")
	rel.ButAutomaticUpgrades = strings.EqualFold(cf.Get("ButAutomaticUpgrades"), "yes")

	return rel, rel.Site + " " + suite + "/" + comp + " " + arch
}

// fixturePackage builds a PackageInfo from a paragraph the way a loader would,
// with the source package and phasing fields filled.
func fixturePackage(t *testing.T, cf *deb.ControlFile) *PackageInfo {
	t.Helper()

	info, err := packageInfoOf(cf, "")
	require.NoError(t, err)

	info.SourceName, info.SourceVersion = info.Name, info.Version

	if src := cf.Get("Source"); src != "" {
		name, ver, hasVer := strings.Cut(src, " (")
		info.SourceName = strings.TrimSpace(name)

		if hasVer {
			info.SourceVersion = strings.TrimSuffix(strings.TrimSpace(ver), ")")
		}
	}

	if text := cf.Get("Phased-Update-Percentage"); text != "" {
		if n, err := strconv.ParseUint(strings.TrimSpace(text), 10, 32); err == nil {
			pct := int(n)
			info.PhasedUpdatePercentage = &pct
		}
	}

	return info
}

// loadFixtureRepo reads every *_Packages index of listsDir and the dpkg status
// at status ("" for none).
func loadFixtureRepo(t *testing.T, listsDir, status, native string) *fixtureRepo {
	t.Helper()

	repo := &fixtureRepo{native: native, slots: map[string][]*PackageInfo{}, files: map[string]*ReleaseInfo{}}

	entries, err := os.ReadDir(listsDir)
	require.NoError(t, err)

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_Packages") {
			continue
		}

		rel, key := fixtureRelease(t, listsDir, e.Name())
		repo.files[key] = rel

		data, err := os.ReadFile(filepath.Join(listsDir, e.Name()))
		require.NoError(t, err)

		require.NoError(t, deb.ScanControl(strings.NewReader(string(data)), func(cf *deb.ControlFile) error {
			info := fixturePackage(t, cf)
			info.HasCandidate = true
			info.Releases = []*ReleaseInfo{rel}
			repo.add(info)

			return nil
		}))
	}

	if status != "" {
		data, err := os.ReadFile(status)
		require.NoError(t, err)

		require.NoError(t, deb.ScanControl(strings.NewReader(string(data)), func(cf *deb.ControlFile) error {
			if !strings.HasSuffix(cf.Get("Status"), " installed") || strings.HasSuffix(cf.Get("Status"), "not-installed") {
				return nil
			}

			info := fixturePackage(t, cf)
			info.Installed = true
			repo.add(info)

			return nil
		}))
	}

	for key, versions := range repo.slots {
		slices.SortStableFunc(versions, func(a, b *PackageInfo) int { return deb.CompareVersions(b.Version, a.Version) })
		repo.keys = append(repo.keys, key)
	}

	slices.Sort(repo.keys)

	return repo
}

// add merges info into the version of its slot with the same version string.
func (r *fixtureRepo) add(info *PackageInfo) {
	arch := info.Architecture
	if arch == archAll {
		arch = r.native
	}

	key := info.Name + ":" + arch

	for _, have := range r.slots[key] {
		if have.Version == info.Version {
			have.Installed = have.Installed || info.Installed
			have.HasCandidate = have.HasCandidate || info.HasCandidate
			have.Releases = append(have.Releases, info.Releases...)

			return
		}
	}

	r.slots[key] = append(r.slots[key], info)
}

// installed returns the installed version of a slot, or nil.
func (r *fixtureRepo) installed(key string) *PackageInfo {
	for _, v := range r.slots[key] {
		if v.Installed {
			return v
		}
	}

	return nil
}
