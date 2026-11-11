package deb_test

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

// byHashDist writes two indexes into a dists directory and returns it with the
// Release that lists them.
func byHashDist(t *testing.T, contents map[string]string) (string, *deb.Release) {
	t.Helper()

	dir := t.TempDir()
	rel := &deb.Release{Suite: "s", AcquireByHash: true}

	for p, c := range contents {
		full := filepath.Join(dir, filepath.FromSlash(p))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(c), 0o600))
		rel.AddFile(deb.HashBytes(p, []byte(c)))
	}

	return dir, rel
}

func sha256Of(rel *deb.Release, p string) string { return rel.Files[p].SHA256 }

func TestWriteByHashModes(t *testing.T) {
	const idx = "main/binary-amd64/Packages"

	for name, mode := range map[string]deb.ByHashMode{"copy": deb.ByHashCopy, "hardlink": deb.ByHashHardlink, "symlink": deb.ByHashSymlink} {
		t.Run(name, func(t *testing.T) {
			dir, rel := byHashDist(t, map[string]string{idx: "Package: a\n", "Contents-amd64": "x y\n"})

			stamp := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
			require.NoError(t, os.Chtimes(filepath.Join(dir, idx), stamp, stamp))

			got, err := deb.WriteByHash(dir, rel, deb.ByHashOptions{Mode: mode})
			require.NoError(t, err)

			want := []string{
				"by-hash/SHA256/" + sha256Of(rel, "Contents-amd64"),
				"by-hash/SHA512/" + rel.Files["Contents-amd64"].SHA512,
				"main/binary-amd64/by-hash/SHA256/" + sha256Of(rel, idx),
				"main/binary-amd64/by-hash/SHA512/" + rel.Files[idx].SHA512,
			}
			assert.ElementsMatch(t, want, got)
			assert.IsIncreasing(t, got)

			for _, p := range got {
				full := filepath.Join(dir, filepath.FromSlash(p))

				data, err := os.ReadFile(full)
				require.NoError(t, err)
				assert.NotEmpty(t, data)

				li, err := os.Lstat(full)
				require.NoError(t, err)

				switch mode {
				case deb.ByHashSymlink:
					assert.NotZero(t, li.Mode()&fs.ModeSymlink, p)
				case deb.ByHashHardlink:
					orig, err := os.Stat(filepath.Join(dir, filepath.FromSlash(servedIndex(p))))
					require.NoError(t, err)
					assert.True(t, os.SameFile(orig, li), "same inode: %s", p)
				default:
					assert.Equal(t, fs.FileMode(0o644), li.Mode().Perm(), p)
					assert.Equal(t, uint64(1), li.Sys().(*syscall.Stat_t).Nlink)
				}
			}

			di, err := os.Stat(filepath.Join(dir, "main/binary-amd64/by-hash/SHA256"))
			require.NoError(t, err)
			assert.Equal(t, fs.FileMode(0o755), di.Mode().Perm())

			if mode == deb.ByHashCopy {
				fi, err := os.Stat(filepath.Join(dir, "main/binary-amd64/by-hash/SHA256", sha256Of(rel, idx)))
				require.NoError(t, err)
				assert.True(t, fi.ModTime().Equal(stamp), "the copy keeps the index time")
			}

			// The Release's own by-hash references resolve.
			for _, ref := range rel.ByHashRefs(idx) {
				if ref.Algorithm != deb.ByHashSHA256 && ref.Algorithm != deb.ByHashSHA512 {
					continue
				}

				_, err := os.Stat(filepath.Join(dir, filepath.FromSlash(ref.Path)))
				assert.NoError(t, err, ref.Path)
			}
		})
	}
}

// servedIndex returns the index file a by-hash path of TestWriteByHashModes
// serves: Contents-amd64 at the root, Packages under main/binary-amd64.
func servedIndex(p string) string {
	if strings.HasPrefix(p, "main/binary-amd64/") {
		return "main/binary-amd64/Packages"
	}

	return "Contents-amd64"
}

func TestWriteByHashIdempotentAndRepairs(t *testing.T) {
	const idx = "a/Packages"

	dir, rel := byHashDist(t, map[string]string{idx: "Package: a\n"})
	opts := deb.ByHashOptions{Algorithms: []deb.ByHashAlgorithm{deb.ByHashSHA256}}

	first, err := deb.WriteByHash(dir, rel, opts)
	require.NoError(t, err)
	require.Len(t, first, 1)

	target := filepath.Join(dir, filepath.FromSlash(first[0]))
	before, err := os.Stat(target)
	require.NoError(t, err)

	// The file is left alone the second time.
	past := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(target, past, past))

	second, err := deb.WriteByHash(dir, rel, opts)
	require.NoError(t, err)
	assert.Equal(t, first, second)

	after, err := os.Stat(target)
	require.NoError(t, err)
	assert.WithinDuration(t, past, after.ModTime(), time.Second, "an existing file is not rewritten")
	assert.Equal(t, before.Size(), after.Size())

	// A torn file (wrong size) is replaced.
	require.NoError(t, os.WriteFile(target, []byte("torn"), 0o644))

	_, err = deb.WriteByHash(dir, rel, opts)
	require.NoError(t, err)

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "Package: a\n", string(data))

	// No temporary files are left behind.
	entries, err := os.ReadDir(filepath.Dir(target))
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestWriteByHashErrors(t *testing.T) {
	const idx = "a/Packages"

	t.Run("content differs in size", func(t *testing.T) {
		dir, rel := byHashDist(t, map[string]string{idx: "Package: a\n"})
		require.NoError(t, os.WriteFile(filepath.Join(dir, idx), []byte("longer than listed\n"), 0o644))

		_, err := deb.WriteByHash(dir, rel, deb.ByHashOptions{})
		require.ErrorIs(t, err, deb.ErrByHashMismatch)
		assert.NoDirExists(t, filepath.Join(dir, "a/by-hash"))
	})

	t.Run("content differs with the same size", func(t *testing.T) {
		dir, rel := byHashDist(t, map[string]string{idx: "Package: a\n"})
		require.NoError(t, os.WriteFile(filepath.Join(dir, idx), []byte("Package: b\n"), 0o644))

		_, err := deb.WriteByHash(dir, rel, deb.ByHashOptions{})
		require.ErrorIs(t, err, deb.ErrByHashMismatch)
		assert.NoDirExists(t, filepath.Join(dir, "a/by-hash"))
	})

	t.Run("missing and by-hash entries are skipped", func(t *testing.T) {
		dir, rel := byHashDist(t, map[string]string{idx: "Package: a\n"})
		rel.AddFile(deb.FileInfo{Path: "a/Packages.xz", Size: 5, SHA256: strings.Repeat("a", 64)})

		got, err := deb.WriteByHash(dir, rel, deb.ByHashOptions{Algorithms: []deb.ByHashAlgorithm{deb.ByHashSHA256}})
		require.NoError(t, err)
		assert.Len(t, got, 1)

		// Writing again with the by-hash file listed itself is not recursive.
		rel.AddFile(deb.HashBytes(got[0], []byte("Package: a\n")))

		again, err := deb.WriteByHash(dir, rel, deb.ByHashOptions{Algorithms: []deb.ByHashAlgorithm{deb.ByHashSHA256}})
		require.NoError(t, err)
		assert.Equal(t, got, again)
	})

	t.Run("algorithm without a listed digest", func(t *testing.T) {
		dir, rel := byHashDist(t, map[string]string{idx: "Package: a\n"})
		fi := rel.Files[idx]
		fi.MD5sum = ""
		rel.AddFile(fi)

		got, err := deb.WriteByHash(dir, rel, deb.ByHashOptions{Algorithms: []deb.ByHashAlgorithm{deb.ByHashMD5, deb.ByHashSHA1}})
		require.NoError(t, err)
		assert.Len(t, got, 1, "only SHA1 is listed")
	})

	t.Run("unwritable destination", func(t *testing.T) {
		dir, rel := byHashDist(t, map[string]string{idx: "Package: a\n"})
		require.NoError(t, os.WriteFile(filepath.Join(dir, "a/by-hash"), nil, 0o644))

		_, err := deb.WriteByHash(dir, rel, deb.ByHashOptions{})
		require.Error(t, err)
	})
}

func TestWriteByHashFS(t *testing.T) {
	content := "Package: a\n"
	rel := &deb.Release{}
	rel.AddFile(deb.HashBytes("main/binary-all/Packages", []byte(content)))

	src := fstest.MapFS{"main/binary-all/Packages": {Data: []byte(content), ModTime: time.Date(2023, 5, 6, 7, 8, 9, 0, time.UTC)}}
	dest := t.TempDir()

	got, err := deb.WriteByHashFS(src, dest, rel, deb.ByHashOptions{Mode: deb.ByHashSymlink, FileMode: 0o640, DirMode: 0o750})
	require.NoError(t, err)
	require.Len(t, got, 2)

	for _, p := range got {
		fi, err := os.Lstat(filepath.Join(dest, filepath.FromSlash(p)))
		require.NoError(t, err)
		assert.True(t, fi.Mode().IsRegular(), "a file system source is always copied")
		assert.Equal(t, fs.FileMode(0o640), fi.Mode().Perm())
		assert.True(t, fi.ModTime().Equal(time.Date(2023, 5, 6, 7, 8, 9, 0, time.UTC)))
	}

	di, err := os.Stat(filepath.Join(dest, "main/binary-all/by-hash"))
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o750), di.Mode().Perm())

	// Wrong content fails.
	bad := fstest.MapFS{"main/binary-all/Packages": {Data: []byte("Package: b\n")}}
	_, err = deb.WriteByHashFS(bad, t.TempDir(), rel, deb.ByHashOptions{})
	require.ErrorIs(t, err, deb.ErrByHashMismatch)

	// An unreadable listing entry (a directory) is skipped.
	dirs := fstest.MapFS{"main/binary-all/Packages/x": {Data: []byte("x")}}
	skipped, err := deb.WriteByHashFS(dirs, t.TempDir(), rel, deb.ByHashOptions{})
	require.NoError(t, err)
	assert.Empty(t, skipped)
}

// apt-ftparchive release with DoByHash writes a by-hash tree; WriteByHash
// writes the same one: same paths, same bytes, same permissions.
func TestWriteByHashMatchesAptFTPArchive(t *testing.T) {
	ftp, err := exec.LookPath("apt-ftparchive")
	if err != nil {
		t.Skip("apt-ftparchive not installed")
	}

	copyTree := func() string {
		dst := t.TempDir()
		require.NoError(t, os.CopyFS(dst, os.DirFS(filepath.Join("testdata", "repo", "ftparchive", "dists", "x"))))

		return dst
	}

	listTree := func(root string) map[string]string {
		out := map[string]string{}

		require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			rel, _ := filepath.Rel(root, p)
			if !strings.Contains(rel+"/", "by-hash/") || rel == "." {
				return nil
			}

			info, err := d.Info()
			require.NoError(t, err)

			if d.IsDir() {
				out[rel] = "dir " + info.Mode().Perm().String()

				return nil
			}

			data, err := os.ReadFile(p)
			require.NoError(t, err)

			out[rel] = "file " + info.Mode().Perm().String() + " " + deb.HashBytes(rel, data).SHA256

			return nil
		}))

		return out
	}

	aptDir := copyTree()
	cmd := exec.Command(ftp, "-o", "APT::FTPArchive::DoByHash=true", "release", ".")
	cmd.Dir = aptDir
	out, err := cmd.Output()
	require.NoError(t, err)

	rel, err := deb.ParseRelease(out)
	require.NoError(t, err)

	ourDir := copyTree()
	_, err = deb.WriteByHash(ourDir, rel, deb.ByHashOptions{})
	require.NoError(t, err)

	aptTree, ourTree := listTree(aptDir), listTree(ourDir)
	require.NotEmpty(t, aptTree)
	assert.Equal(t, aptTree, ourTree)

	// Nothing of the apt-written tree is stale for the Release that wrote it.
	plan, err := deb.PlanByHashPrune(aptDir, rel, deb.ByHashRetention{})
	require.NoError(t, err)
	assert.Empty(t, plan.Remove)
	assert.Empty(t, plan.Keep)
}

// setTimes sets the modification time of files.
func setTimes(t *testing.T, dir string, files map[string]time.Time) {
	t.Helper()

	for p, ts := range files {
		require.NoError(t, os.Chtimes(filepath.Join(dir, filepath.FromSlash(p)), ts, ts))
	}
}

func hexN(c byte, n int) string { return strings.Repeat(string(c), n) }

func TestByHashRetention(t *testing.T) {
	dir, rel := byHashDist(t, map[string]string{"main/binary-amd64/Packages": "Package: now\n"})

	opts := deb.ByHashOptions{Algorithms: []deb.ByHashAlgorithm{deb.ByHashSHA256}}
	_, err := deb.WriteByHash(dir, rel, opts)
	require.NoError(t, err)

	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	hash := "main/binary-amd64/by-hash/SHA256/"
	cur := hash + sha256Of(rel, "main/binary-amd64/Packages")

	// Generations: g1 at now-1h (a Packages and a Packages.gz written seconds
	// apart), g2 at now-26h, g3 at now-3 days. The current files are from now-10m.
	old := map[string]time.Time{
		hash + hexN('1', 64): now.Add(-time.Hour),
		hash + hexN('2', 64): now.Add(-time.Hour - 20*time.Second),
		hash + hexN('3', 64): now.Add(-26 * time.Hour),
		hash + hexN('4', 64): now.Add(-72 * time.Hour),
	}

	for p := range old {
		require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(p)), []byte("old"), 0o644))
	}

	setTimes(t, dir, old)
	setTimes(t, dir, map[string]time.Time{cur: now.Add(-10 * time.Minute)})

	// Entries that are not ours.
	require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(hash+"README")), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(hash+hexN('a', 63))), []byte("x"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "by-hash/NOTANALGO"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "by-hash/NOTANALGO", hexN('b', 64)), []byte("x"), 0o644))

	stale := hash + ".by-hash-1-2"
	fresh := hash + ".by-hash-3-4"

	require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(stale)), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(fresh)), []byte("x"), 0o644))
	setTimes(t, dir, map[string]time.Time{stale: now.Add(-2 * time.Hour), fresh: now.Add(-time.Minute)})

	g := func(i byte) string { return hash + hexN(i, 64) }

	type retentionCase struct {
		name       string
		pol        deb.ByHashRetention
		wantRemove []string
		wantKeep   []string
	}

	// Age counts from when a generation was superseded: g1 by the current
	// file (10 minutes ago), g2's generation by g1... that is, g3 by the
	// files at -1h (1h ago) and g4 by those at -26h (26h ago).
	tests := []retentionCase{
		{"nothing kept", deb.ByHashRetention{}, []string{g('1'), g('2'), g('3'), g('4'), stale}, nil},
		{"one generation", deb.ByHashRetention{KeepGenerations: 1}, []string{g('3'), g('4'), stale}, []string{g('1'), g('2')}},
		{"two generations", deb.ByHashRetention{KeepGenerations: 2}, []string{g('4'), stale}, []string{g('1'), g('2'), g('3')}},
		{"all generations", deb.ByHashRetention{KeepGenerations: 9}, []string{stale}, []string{g('1'), g('2'), g('3'), g('4')}},
		{"max age 5m", deb.ByHashRetention{MaxAge: 5 * time.Minute}, []string{g('1'), g('2'), g('3'), g('4'), stale}, nil},
		{"max age 30m", deb.ByHashRetention{MaxAge: 30 * time.Minute}, []string{g('3'), g('4'), stale}, []string{g('1'), g('2')}},
		{"max age 2h", deb.ByHashRetention{MaxAge: 2 * time.Hour}, []string{g('4'), stale}, []string{g('1'), g('2'), g('3')}},
		{"keep and age are a union", deb.ByHashRetention{KeepGenerations: 1, MaxAge: 2 * time.Hour}, []string{g('4'), stale}, []string{g('1'), g('2'), g('3')}},
		{"narrow gap splits generations", deb.ByHashRetention{KeepGenerations: 1, GenerationGap: 5 * time.Second}, []string{g('2'), g('3'), g('4'), stale}, []string{g('1')}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.pol.Now = now

			plan, err := deb.PlanByHashPrune(dir, rel, tc.pol)
			require.NoError(t, err)

			assert.ElementsMatch(t, tc.wantRemove, plan.Paths())

			var kept []string
			for _, f := range plan.Keep {
				kept = append(kept, f.Path)
				assert.NotEmpty(t, f.Reason)
				assert.NotZero(t, f.Generation)
			}

			assert.ElementsMatch(t, tc.wantKeep, kept)
			assert.IsIncreasing(t, plan.Paths())

			for _, f := range plan.Remove {
				assert.NotEmpty(t, f.Reason)
			}

			// Planning touches nothing.
			assert.FileExists(t, filepath.Join(dir, filepath.FromSlash(cur)))
			assert.FileExists(t, filepath.Join(dir, filepath.FromSlash(g('4'))))
		})
	}

	t.Run("generation numbers", func(t *testing.T) {
		plan, err := deb.PlanByHashPrune(dir, rel, deb.ByHashRetention{KeepGenerations: 9, Now: now})
		require.NoError(t, err)

		gens := map[string]int{}
		for _, f := range plan.Keep {
			gens[f.Path] = f.Generation
		}

		assert.Equal(t, map[string]int{g('1'): 1, g('2'): 1, g('3'): 2, g('4'): 3}, gens)
	})

	t.Run("prune applies the plan", func(t *testing.T) {
		removed, err := deb.PruneByHash(dir, rel, deb.ByHashRetention{KeepGenerations: 1, Now: now})
		require.NoError(t, err)
		assert.Equal(t, []string{stale, g('3'), g('4')}, removed)

		for _, p := range []string{cur, g('1'), g('2'), fresh, hash + "README", hash + hexN('a', 63), "by-hash/NOTANALGO/" + hexN('b', 64)} {
			assert.FileExists(t, filepath.Join(dir, filepath.FromSlash(p)), p)
		}

		for _, p := range []string{g('3'), g('4'), stale} {
			assert.NoFileExists(t, filepath.Join(dir, filepath.FromSlash(p)), p)
		}

		// Applying again is fine.
		plan, err := deb.PlanByHashPrune(dir, rel, deb.ByHashRetention{KeepGenerations: 1, Now: now})
		require.NoError(t, err)
		assert.Empty(t, plan.Remove)
	})

	t.Run("empty directories are dropped", func(t *testing.T) {
		d2, r2 := byHashDist(t, map[string]string{"x/Packages": "new\n"})
		other := filepath.Join(d2, "gone/by-hash/SHA256")
		require.NoError(t, os.MkdirAll(other, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(other, hexN('c', 64)), []byte("x"), 0o644))

		removed, err := deb.PruneByHash(d2, r2, deb.ByHashRetention{Now: time.Now().Add(24 * time.Hour)})
		require.NoError(t, err)
		assert.Len(t, removed, 1)
		assert.NoDirExists(t, filepath.Join(d2, "gone"+"/by-hash"))
		assert.DirExists(t, filepath.Join(d2, "gone"))
	})
}

func TestByHashPlanApplyMissingFile(t *testing.T) {
	dir := t.TempDir()
	plan := &deb.ByHashPlan{Remove: []deb.ByHashFile{{Path: "by-hash/SHA256/" + hexN('d', 64)}}}

	removed, err := plan.Apply(dir)
	require.NoError(t, err)
	assert.Len(t, removed, 1)
}

func TestPlanByHashPruneMissingDirectory(t *testing.T) {
	_, err := deb.PlanByHashPrune(filepath.Join(t.TempDir(), "nope"), &deb.Release{}, deb.ByHashRetention{})
	require.Error(t, err)
}

// A tree written for several Releases is pruned to the ones still wanted.
func TestByHashAccumulatesAcrossReleases(t *testing.T) {
	dir, rel1 := byHashDist(t, map[string]string{"a/Packages": "one\n"})
	opts := deb.ByHashOptions{Algorithms: []deb.ByHashAlgorithm{deb.ByHashSHA256}}

	_, err := deb.WriteByHash(dir, rel1, opts)
	require.NoError(t, err)

	old := time.Now().Add(-5 * time.Hour)
	setTimes(t, dir, map[string]time.Time{"a/by-hash/SHA256/" + sha256Of(rel1, "a/Packages"): old})

	require.NoError(t, os.WriteFile(filepath.Join(dir, "a/Packages"), []byte("two\n"), 0o644))
	setTimes(t, dir, map[string]time.Time{"a/Packages": time.Now().Add(-3 * time.Hour)})

	rel2 := &deb.Release{}
	rel2.AddFile(deb.HashBytes("a/Packages", []byte("two\n")))

	_, err = deb.WriteByHash(dir, rel2, opts)
	require.NoError(t, err)

	assert.FileExists(t, filepath.Join(dir, "a/by-hash/SHA256", sha256Of(rel1, "a/Packages")), "the older Release is still served")

	plan, err := deb.PlanByHashPrune(dir, rel2, deb.ByHashRetention{KeepGenerations: 1})
	require.NoError(t, err)
	assert.Empty(t, plan.Remove)
	require.Len(t, plan.Keep, 1)
	assert.Equal(t, 1, plan.Keep[0].Generation)

	plan, err = deb.PlanByHashPrune(dir, rel2, deb.ByHashRetention{MaxAge: time.Hour})
	require.NoError(t, err)
	assert.Len(t, plan.Remove, 1, "age is measured from when the new file appeared (3h ago)")
}
