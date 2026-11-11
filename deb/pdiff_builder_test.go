package deb_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"math/rand/v2"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"

	"github.com/M0Rf30/pkgformat/deb"
)

// pdiffVersions makes n successive versions of a Packages-like file.
func pdiffVersions(seed uint64, n int) []string {
	r := rand.New(rand.NewPCG(seed, 99))
	v := []string{pdiffRandomFile(r, 60, 40)}

	for range n - 1 {
		v = append(v, pdiffMutate(r, v[len(v)-1], 1+r.IntN(4), 40))
	}

	return v
}

func pdiffXZ(tb testing.TB, data []byte) []byte {
	tb.Helper()

	var buf bytes.Buffer

	w, err := xz.NewWriter(&buf)
	require.NoError(tb, err)
	_, err = w.Write(data)
	require.NoError(tb, err)
	require.NoError(tb, w.Close())

	return buf.Bytes()
}

func pdiffGunzip(tb testing.TB, data []byte) []byte {
	tb.Helper()

	r, err := gzip.NewReader(bytes.NewReader(data))
	require.NoError(tb, err)

	out, err := io.ReadAll(r)
	require.NoError(tb, err)

	return out
}

var pdiffEpoch = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// pdiffFSFetcher serves the patch downloads a builder published.
func pdiffFSFetcher(fsys deb.PDiffFS, dir string) deb.PDiffFetcher {
	return func(p deb.PDiffPatch) ([]byte, error) {
		return fsys.ReadFile(dir + "/" + p.DownloadName())
	}
}

// pdiffCatchUp checks that a client holding version `from` reaches `to` over
// the published Index, the way apt does.
func pdiffCatchUp(t *testing.T, fsys deb.PDiffFS, from, to string) []deb.PDiffPatch {
	t.Helper()

	data, err := fsys.ReadFile("Packages.diff/Index")
	require.NoError(t, err)

	idx, err := deb.ParsePDiffIndex(data)
	require.NoError(t, err)
	require.Equal(t, deb.PDiffSHA256([]byte(to)), idx.Current.SHA256)

	chain, err := idx.Chain(deb.PDiffSHA256([]byte(from)))
	require.NoError(t, err)

	got, err := deb.ApplyPDiffChain([]byte(from), chain, pdiffFSFetcher(fsys, "Packages.diff"), deb.PDiffApplyOptions{})
	require.NoError(t, err)
	require.Equal(t, to, string(got))

	return chain
}

func TestPDiffBuilderHistory(t *testing.T) {
	fsys := deb.NewPDiffMemFS()
	b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{MaxPatches: 4})
	require.NoError(t, err)

	vs := pdiffVersions(1, 9)

	// Publishing the first version has nothing to diff from.
	require.NoError(t, fsys.WriteFile("Packages", []byte(vs[0])))

	res, err := b.Update([]byte(vs[0]), pdiffEpoch)
	require.NoError(t, err)
	require.False(t, res.Changed)
	require.Nil(t, res.Index)
	require.Equal(t, []string{"Packages"}, fsys.Names())

	for i := 1; i < len(vs); i++ {
		now := pdiffEpoch.Add(time.Duration(i) * time.Hour)

		res, err = b.Update([]byte(vs[i]), now)
		require.NoError(t, err)
		require.True(t, res.Changed)
		require.Equal(t, now.Format("2006-01-02-1504.05"), res.Patch.Name)
		require.Equal(t, deb.PDiffSHA256([]byte(vs[i-1])), res.Patch.From.SHA256)
		require.Equal(t, res.IndexData, mustRead(t, fsys, "Packages.diff/Index"))
		require.NoError(t, fsys.WriteFile("Packages", []byte(vs[i])))

		// Every version still in the window reaches the current one.
		for j := max(0, i-4); j < i; j++ {
			chain := pdiffCatchUp(t, fsys, vs[j], vs[i])
			require.Len(t, chain, i-j)
		}

		// Only the window's files remain.
		want := min(i, 4)
		patches := 0

		for _, n := range fsys.Names() {
			if strings.HasSuffix(n, ".gz") {
				patches++
			}
		}

		require.Equal(t, want, patches, "%v", fsys.Names())
	}

	// A version that fell out of the window gets no chain.
	data := mustRead(t, fsys, "Packages.diff/Index")
	idx, err := deb.ParsePDiffIndex(data)
	require.NoError(t, err)

	_, err = idx.Chain(deb.PDiffSHA256([]byte(vs[0])))
	require.ErrorIs(t, err, deb.ErrPDiffNoPath)
	require.Len(t, res.Removed, 1)
}

func mustRead(t *testing.T, fsys deb.PDiffFS, name string) []byte {
	t.Helper()

	data, err := fsys.ReadFile(name)
	require.NoError(t, err)

	return data
}

func TestPDiffBuilderIndexRoundTrip(t *testing.T) {
	fsys := deb.NewPDiffMemFS()
	b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{SHA1: true, XZ: true, MaxPatches: 3})
	require.NoError(t, err)

	vs := pdiffVersions(2, 5)

	for i := 1; i < len(vs); i++ {
		res, err := b.UpdateFrom([]byte(vs[i-1]), []byte(vs[i]), pdiffEpoch.Add(time.Duration(i)*time.Minute))
		require.NoError(t, err)

		data := mustRead(t, fsys, "Packages.diff/Index")
		idx, err := deb.ParsePDiffIndex(data)
		require.NoError(t, err)
		require.Equal(t, res.IndexData, idx.Marshal(), "the builder writes what Marshal makes of what Parse reads")
		require.Equal(t, res.Index, idx)

		for _, p := range idx.Patches {
			require.NotEmpty(t, p.Download.SHA1)
			require.NotEmpty(t, p.DownloadXZ.SHA256)

			xzData := mustRead(t, fsys, "Packages.diff/"+p.Name+".xz")
			require.Equal(t, p.DownloadXZ.Size, int64(len(xzData)))

			r, err := deb.OpenIndex(bytes.NewReader(xzData), p.Name+".xz")
			require.NoError(t, err)

			plain := new(bytes.Buffer)
			_, err = plain.ReadFrom(r)
			require.NoError(t, err)
			require.Equal(t, p.Patch.Size, int64(plain.Len()))
		}
	}

	// The builder's own view equals the published one.
	require.Equal(t, mustParse(t, mustRead(t, fsys, "Packages.diff/Index")), b.Index())
}

func mustParse(t *testing.T, data []byte) *deb.PDiffIndex {
	t.Helper()

	idx, err := deb.ParsePDiffIndex(data)
	require.NoError(t, err)

	return idx
}

func TestPDiffBuilderMerged(t *testing.T) {
	fsys := deb.NewPDiffMemFS()
	b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{Merge: true, MaxPatches: 5})
	require.NoError(t, err)

	vs := pdiffVersions(3, 9)

	for i := 1; i < len(vs); i++ {
		now := pdiffEpoch.Add(time.Duration(i) * time.Hour)
		_, err := b.UpdateFrom([]byte(vs[i-1]), []byte(vs[i]), now)
		require.NoError(t, err)

		idx := mustParse(t, mustRead(t, fsys, "Packages.diff/Index"))
		require.True(t, idx.Merged)
		require.Len(t, idx.Patches, min(i, 5))
		require.Len(t, idx.Unmerged, min(i, 5))
		require.LessOrEqual(t, len(idx.OlderPatches), 3)
		require.Equal(t, now.Format("2006-01-02-1504.05"), idx.OlderPatches[len(idx.OlderPatches)-1])

		for j := max(0, i-5); j < i; j++ {
			chain := pdiffCatchUp(t, fsys, vs[j], vs[i])
			require.Len(t, chain, 1, "a merged series needs a single patch")
			require.True(t, strings.HasPrefix(chain[0].Name, "T-"+now.Format("2006-01-02-1504.05")+"-F-"))
		}

		// The one-step patches chain too, from the unmerged list.
		for j := max(0, i-5); j < i; j++ {
			var cur = []byte(vs[j])

			for _, u := range idx.Unmerged {
				if u.From.SHA256 != deb.PDiffSHA256(cur) {
					continue
				}

				cur, err = deb.ApplyPDiffChain(cur, []deb.PDiffPatch{u}, pdiffFSFetcher(fsys, "Packages.diff"), deb.PDiffApplyOptions{})
				require.NoError(t, err)
			}

			require.Equal(t, vs[i], string(cur))
		}
	}

	// The merged files of the previous two updates are still served.
	var olderFiles int

	for _, n := range fsys.Names() {
		if strings.HasPrefix(n, "Packages.diff/T-") && !strings.Contains(n, "T-"+pdiffEpoch.Add(8*time.Hour).Format("2006-01-02-1504.05")+"-F-") {
			olderFiles++
		}
	}

	require.Positive(t, olderFiles)
}

func TestPDiffBuilderMergeConversion(t *testing.T) {
	vs := pdiffVersions(4, 8)
	fsys := deb.NewPDiffMemFS()

	step := func(merge bool, i int) {
		t.Helper()

		b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{Merge: merge})
		require.NoError(t, err)

		_, err = b.UpdateFrom([]byte(vs[i-1]), []byte(vs[i]), pdiffEpoch.Add(time.Duration(i)*time.Hour))
		require.NoError(t, err)

		for j := range i {
			pdiffCatchUp(t, fsys, vs[j], vs[i])
		}
	}

	step(false, 1)
	step(false, 2)
	step(true, 3) // unmerged to merged
	step(true, 4)
	step(false, 5) // and back
	step(true, 6)

	// Back to unmerged leaves no merged files behind.
	step(false, 7)

	for _, n := range fsys.Names() {
		require.NotContains(t, n, "/T-")
	}
}

func TestPDiffBuilderNoopAndSecondCollision(t *testing.T) {
	fsys := deb.NewPDiffMemFS()
	b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{})
	require.NoError(t, err)

	vs := pdiffVersions(5, 4)

	res, err := b.UpdateFrom([]byte(vs[0]), []byte(vs[1]), pdiffEpoch)
	require.NoError(t, err)
	require.True(t, res.Changed)

	written := fsys.Names()

	// The same file again changes nothing.
	res, err = b.UpdateFrom([]byte(vs[1]), []byte(vs[1]), pdiffEpoch.Add(time.Hour))
	require.NoError(t, err)
	require.False(t, res.Changed)
	require.False(t, res.Reset)
	require.NotNil(t, res.Index)
	require.Equal(t, written, fsys.Names())

	// Two updates within the same second get distinct names.
	r2, err := b.UpdateFrom([]byte(vs[1]), []byte(vs[2]), pdiffEpoch.Add(500*time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, "2026-03-01-1200.01", r2.Patch.Name)

	r3, err := b.UpdateFrom([]byte(vs[2]), []byte(vs[3]), pdiffEpoch)
	require.NoError(t, err)
	require.Equal(t, "2026-03-01-1200.02", r3.Patch.Name)

	pdiffCatchUp(t, fsys, vs[0], vs[3])
}

func TestPDiffBuilderResets(t *testing.T) {
	vs := pdiffVersions(6, 6)

	build := func() (*deb.PDiffMemFS, *deb.PDiffIndexBuilder) {
		fsys := deb.NewPDiffMemFS()
		b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{})
		require.NoError(t, err)

		for i := 1; i <= 3; i++ {
			_, err = b.UpdateFrom([]byte(vs[i-1]), []byte(vs[i]), pdiffEpoch.Add(time.Duration(i)*time.Hour))
			require.NoError(t, err)
		}

		return fsys, b
	}

	t.Run("diffing from a file the history does not end at", func(t *testing.T) {
		fsys, b := build()

		res, err := b.UpdateFrom([]byte(vs[0]), []byte(vs[4]), pdiffEpoch.Add(10*time.Hour))
		require.NoError(t, err)
		require.True(t, res.Reset)
		require.True(t, res.Changed)
		require.Len(t, res.Index.Patches, 1)
		require.Len(t, res.Removed, 3)
		pdiffCatchUp(t, fsys, vs[0], vs[4])
	})

	t.Run("damaged patch file", func(t *testing.T) {
		fsys, b := build()
		idx := b.Index()

		require.NoError(t, fsys.WriteFile("Packages.diff/"+idx.Patches[1].DownloadName(), []byte("damaged")))

		res, err := b.UpdateFrom([]byte(vs[3]), []byte(vs[4]), pdiffEpoch.Add(10*time.Hour))
		require.NoError(t, err)
		require.True(t, res.Reset)
		require.Len(t, res.Index.Patches, 1)
		pdiffCatchUp(t, fsys, vs[3], vs[4])
	})

	t.Run("missing patch file", func(t *testing.T) {
		fsys, b := build()
		require.NoError(t, fsys.Remove("Packages.diff/"+b.Index().Patches[0].DownloadName()))

		res, err := b.UpdateFrom([]byte(vs[3]), []byte(vs[4]), pdiffEpoch.Add(10*time.Hour))
		require.NoError(t, err)
		require.True(t, res.Reset)
	})

	t.Run("patch file with the right download hash but a script of the wrong hash", func(t *testing.T) {
		fsys, b := build()
		p := b.Index().Patches[0]

		// Same compressed content in an index that claims another script size.
		data := mustRead(t, fsys, "Packages.diff/Index")
		bad := strings.Replace(string(data), "SHA256-Patches:\n "+p.Patch.SHA256, "SHA256-Patches:\n "+strings.Repeat("0", 64), 1)
		require.NoError(t, fsys.WriteFile("Packages.diff/Index", []byte(bad)))

		b2, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{})
		require.NoError(t, err)

		res, err := b2.UpdateFrom([]byte(vs[3]), []byte(vs[4]), pdiffEpoch.Add(10*time.Hour))
		require.NoError(t, err)
		require.True(t, res.Reset)
	})

	t.Run("corrupt index file", func(t *testing.T) {
		fsys, _ := build()
		require.NoError(t, fsys.WriteFile("Packages.diff/Index", []byte("not an index")))

		b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{})
		require.NoError(t, err)
		require.Nil(t, b.Index())

		res, err := b.UpdateFrom([]byte(vs[3]), []byte(vs[4]), pdiffEpoch.Add(10*time.Hour))
		require.NoError(t, err)
		require.True(t, res.Changed)
		require.Len(t, res.Index.Patches, 1)
		// Old patch files are gone.
		require.Len(t, fsys.Names(), 2, "%v", fsys.Names())
	})

	t.Run("no old file, history leads elsewhere", func(t *testing.T) {
		fsys, b := build()

		res, err := b.Update([]byte(vs[5]), pdiffEpoch)
		require.NoError(t, err)
		require.True(t, res.Reset)
		require.False(t, res.Changed)
		require.Nil(t, res.Index)
		require.Empty(t, fsys.Names())
	})

	t.Run("no old file, history leads to the new content", func(t *testing.T) {
		_, b := build()

		res, err := b.Update([]byte(vs[3]), pdiffEpoch)
		require.NoError(t, err)
		require.False(t, res.Reset)
		require.Len(t, res.Index.Patches, 3)
	})
}

func TestPDiffBuilderSkippedChange(t *testing.T) {
	fsys := deb.NewPDiffMemFS()
	b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{})
	require.NoError(t, err)

	_, err = b.UpdateFrom([]byte("a\n"), []byte("b\n"), pdiffEpoch)
	require.NoError(t, err)
	require.NotEmpty(t, fsys.Names())

	// A change that cannot be a patch drops the history; clients refetch.
	res, err := b.UpdateFrom([]byte("b\n"), []byte("b\n.\nc\n"), pdiffEpoch.Add(time.Hour))
	require.NoError(t, err)
	require.ErrorIs(t, res.Skipped, deb.ErrPDiffUnrepresentable)
	require.True(t, res.Reset)
	require.False(t, res.Changed)
	require.Empty(t, fsys.Names())

	// The generator's limits do the same.
	b, err = deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{Generate: deb.PDiffGenerateOptions{MaxLines: 2}})
	require.NoError(t, err)

	res, err = b.UpdateFrom([]byte("a\n"), []byte("a\nb\nc\n"), pdiffEpoch)
	require.NoError(t, err)
	require.ErrorIs(t, res.Skipped, deb.ErrPDiffLimit)
}

func TestPDiffBuilderReadsCompressedOldFile(t *testing.T) {
	vs := pdiffVersions(7, 3)

	for _, ext := range []string{"", ".gz", ".xz"} {
		t.Run("Packages"+ext, func(t *testing.T) {
			fsys := deb.NewPDiffMemFS()
			content := []byte(vs[0])

			switch ext {
			case ".gz":
				content = pdiffGzip(t, content)
			case ".xz":
				content = pdiffXZ(t, content)
			}

			require.NoError(t, fsys.WriteFile("Packages"+ext, content))

			b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{})
			require.NoError(t, err)

			res, err := b.Update([]byte(vs[1]), pdiffEpoch)
			require.NoError(t, err)
			require.True(t, res.Changed)
			require.Equal(t, deb.PDiffSHA256([]byte(vs[0])), res.Patch.From.SHA256)
		})
	}

	// A damaged compressed old file is an error, not a silent reset.
	fsys := deb.NewPDiffMemFS()
	require.NoError(t, fsys.WriteFile("Packages.gz", []byte("junk")))

	b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{})
	require.NoError(t, err)

	_, err = b.Update([]byte(vs[1]), pdiffEpoch)
	require.Error(t, err)
}

func TestPDiffBuilderIndexName(t *testing.T) {
	fsys := deb.NewPDiffMemFS()
	b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{IndexName: "Sources"})
	require.NoError(t, err)

	res, err := b.UpdateFrom([]byte("a\n"), []byte("b\n"), pdiffEpoch)
	require.NoError(t, err)
	require.Contains(t, res.Written, "Sources.diff/Index")

	for _, bad := range []string{"a/b", "..", "/x", "."} {
		_, err = deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{IndexName: bad})
		require.Error(t, err, bad)
	}
}

func TestPDiffBuilderDeterministic(t *testing.T) {
	vs := pdiffVersions(8, 4)

	run := func() map[string][]byte {
		fsys := deb.NewPDiffMemFS()
		b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{Merge: true, XZ: true, SHA1: true})
		require.NoError(t, err)

		for i := 1; i < len(vs); i++ {
			_, err = b.UpdateFrom([]byte(vs[i-1]), []byte(vs[i]), pdiffEpoch.Add(time.Duration(i)*time.Hour))
			require.NoError(t, err)
		}

		out := map[string][]byte{}
		for _, n := range fsys.Names() {
			out[n] = mustRead(t, fsys, n)
		}

		return out
	}

	require.Equal(t, run(), run())
}

func TestPDiffBuilderPatchesAreGzipOfThePatch(t *testing.T) {
	fsys := deb.NewPDiffMemFS()
	b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{})
	require.NoError(t, err)

	vs := pdiffVersions(9, 2)
	res, err := b.UpdateFrom([]byte(vs[0]), []byte(vs[1]), pdiffEpoch)
	require.NoError(t, err)

	want, err := deb.GeneratePDiff([]byte(vs[0]), []byte(vs[1]))
	require.NoError(t, err)

	gz := mustRead(t, fsys, "Packages.diff/"+res.Patch.DownloadName())
	require.Equal(t, want, pdiffGunzip(t, gz))
	require.Equal(t, int64(len(gz)), res.Patch.Download.Size)
	require.Equal(t, int64(len(want)), res.Patch.Patch.Size)
}

type failFS struct {
	deb.PDiffFS

	failWrite, failRead, failRemove, failList string
}

func (f failFS) ReadFile(name string) ([]byte, error) {
	if f.failRead != "" && name == f.failRead {
		return nil, errors.New("read failure")
	}

	return f.PDiffFS.ReadFile(name)
}

func (f failFS) WriteFile(name string, data []byte) error {
	if f.failWrite != "" && strings.Contains(name, f.failWrite) {
		return errors.New("write failure")
	}

	return f.PDiffFS.WriteFile(name, data)
}

func (f failFS) Remove(name string) error {
	if f.failRemove != "" && strings.Contains(name, f.failRemove) {
		return errors.New("remove failure")
	}

	return f.PDiffFS.Remove(name)
}

func (f failFS) ReadDir(dir string) ([]string, error) {
	if f.failList != "" {
		return nil, errors.New("list failure")
	}

	return f.PDiffFS.ReadDir(dir)
}

func TestPDiffBuilderStorageFailures(t *testing.T) {
	vs := pdiffVersions(10, 4)

	prepare := func() (*deb.PDiffMemFS, *deb.PDiffIndexBuilder) {
		mem := deb.NewPDiffMemFS()
		b, err := deb.NewPDiffIndexBuilder(mem, deb.PDiffBuilderOptions{})
		require.NoError(t, err)

		_, err = b.UpdateFrom([]byte(vs[0]), []byte(vs[1]), pdiffEpoch)
		require.NoError(t, err)

		return mem, b
	}

	t.Run("index unreadable on open", func(t *testing.T) {
		mem := deb.NewPDiffMemFS()
		_, err := deb.NewPDiffIndexBuilder(failFS{PDiffFS: mem, failRead: "Packages.diff/Index"}, deb.PDiffBuilderOptions{})
		require.Error(t, err)
	})

	t.Run("patch write failure keeps the old index", func(t *testing.T) {
		mem, _ := prepare()
		before := mustRead(t, mem, "Packages.diff/Index")

		b, err := deb.NewPDiffIndexBuilder(failFS{PDiffFS: mem, failWrite: ".gz"}, deb.PDiffBuilderOptions{})
		require.NoError(t, err)

		_, err = b.UpdateFrom([]byte(vs[1]), []byte(vs[2]), pdiffEpoch.Add(time.Hour))
		require.Error(t, err)
		require.Equal(t, before, mustRead(t, mem, "Packages.diff/Index"))
		require.Equal(t, mustParse(t, before), b.Index(), "the builder went back to the published state")
	})

	t.Run("index write failure", func(t *testing.T) {
		mem, _ := prepare()

		b, err := deb.NewPDiffIndexBuilder(failFS{PDiffFS: mem, failWrite: "Index"}, deb.PDiffBuilderOptions{})
		require.NoError(t, err)

		_, err = b.UpdateFrom([]byte(vs[1]), []byte(vs[2]), pdiffEpoch.Add(time.Hour))
		require.Error(t, err)
	})

	t.Run("xz write failure", func(t *testing.T) {
		mem, _ := prepare()

		b, err := deb.NewPDiffIndexBuilder(failFS{PDiffFS: mem, failWrite: ".xz"}, deb.PDiffBuilderOptions{XZ: true})
		require.NoError(t, err)

		_, err = b.UpdateFrom([]byte(vs[1]), []byte(vs[2]), pdiffEpoch.Add(time.Hour))
		require.Error(t, err)
	})

	t.Run("prune failures", func(t *testing.T) {
		mem, _ := prepare()

		b, err := deb.NewPDiffIndexBuilder(failFS{PDiffFS: mem, failList: "x"}, deb.PDiffBuilderOptions{})
		require.NoError(t, err)

		_, err = b.UpdateFrom([]byte(vs[1]), []byte(vs[2]), pdiffEpoch.Add(time.Hour))
		require.Error(t, err)

		mem, _ = prepare()
		require.NoError(t, mem.WriteFile("Packages.diff/stale.gz", []byte("x")))

		b, err = deb.NewPDiffIndexBuilder(failFS{PDiffFS: mem, failRemove: "stale"}, deb.PDiffBuilderOptions{})
		require.NoError(t, err)

		_, err = b.UpdateFrom([]byte(vs[1]), []byte(vs[2]), pdiffEpoch.Add(time.Hour))
		require.Error(t, err)
	})

	t.Run("clear failures", func(t *testing.T) {
		mem, _ := prepare()

		b, err := deb.NewPDiffIndexBuilder(failFS{PDiffFS: mem, failRemove: "Index"}, deb.PDiffBuilderOptions{})
		require.NoError(t, err)

		_, err = b.Update([]byte(vs[3]), pdiffEpoch)
		require.Error(t, err)

		mem, _ = prepare()

		b, err = deb.NewPDiffIndexBuilder(failFS{PDiffFS: mem, failList: "x"}, deb.PDiffBuilderOptions{})
		require.NoError(t, err)

		_, err = b.Update([]byte(vs[3]), pdiffEpoch)
		require.Error(t, err)
	})

	t.Run("old file unreadable", func(t *testing.T) {
		mem, _ := prepare()
		require.NoError(t, mem.WriteFile("Packages", []byte(vs[1])))

		b, err := deb.NewPDiffIndexBuilder(failFS{PDiffFS: mem, failRead: "Packages"}, deb.PDiffBuilderOptions{})
		require.NoError(t, err)

		_, err = b.Update([]byte(vs[2]), pdiffEpoch)
		require.Error(t, err)
	})
}

func TestPDiffBuilderMergeErrorsOnLimits(t *testing.T) {
	vs := pdiffVersions(11, 4)
	fsys := deb.NewPDiffMemFS()
	b, err := deb.NewPDiffIndexBuilder(fsys, deb.PDiffBuilderOptions{Merge: true, Apply: deb.PDiffApplyOptions{MaxCommands: 1}})
	require.NoError(t, err)

	var failed bool

	for i := 1; i < len(vs) && !failed; i++ {
		_, err = b.UpdateFrom([]byte(vs[i-1]), []byte(vs[i]), pdiffEpoch.Add(time.Duration(i)*time.Hour))
		if err != nil {
			require.ErrorIs(t, err, deb.ErrPDiffLimit)

			failed = true
		}
	}

	require.True(t, failed, "merging more commands than the limit allows is refused")
}

func TestPDiffMemFS(t *testing.T) {
	m := deb.NewPDiffMemFS()

	_, err := m.ReadFile("nope")
	require.ErrorIs(t, err, fs.ErrNotExist)

	require.Error(t, m.WriteFile("../x", nil))
	require.Error(t, m.WriteFile("/x", nil))
	require.Error(t, m.WriteFile(".", nil))

	require.NoError(t, m.WriteFile("d/a", []byte("1")))
	require.NoError(t, m.WriteFile("d/b", []byte("2")))
	require.NoError(t, m.WriteFile("e/c", []byte("3")))

	names, err := m.ReadDir("d")
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, names)

	data, _ := m.ReadFile("d/a")
	data[0] = 'X'

	again, _ := m.ReadFile("d/a")
	require.Equal(t, "1", string(again), "reads are copies")

	require.NoError(t, m.Remove("d/a"))
	require.NoError(t, m.Remove("d/a"))
	require.Equal(t, []string{"d/b", "e/c"}, m.Names())
}

func TestPDiffDirFS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dists", "x")

	d, err := deb.NewPDiffDirFS(dir)
	require.NoError(t, err)

	defer d.Close()

	_, err = d.ReadFile("Packages.diff/Index")
	require.ErrorIs(t, err, fs.ErrNotExist)

	names, err := d.ReadDir("Packages.diff")
	require.NoError(t, err)
	require.Empty(t, names)

	require.NoError(t, d.WriteFile("Packages.diff/Index", []byte("v1")))
	require.NoError(t, d.WriteFile("Packages.diff/Index", []byte("v2")))
	require.NoError(t, d.WriteFile("Packages.diff/a.gz", []byte("z")))

	data, err := d.ReadFile("Packages.diff/Index")
	require.NoError(t, err)
	require.Equal(t, "v2", string(data))

	names, err = d.ReadDir("Packages.diff")
	require.NoError(t, err)
	require.Equal(t, []string{"Index", "a.gz"}, names, "no temporary file stays")

	require.NoError(t, d.Remove("Packages.diff/a.gz"))
	require.NoError(t, d.Remove("Packages.diff/a.gz"))

	// Names cannot leave the directory.
	require.Error(t, d.WriteFile("../escape", []byte("x")))
	require.Error(t, d.WriteFile("/abs", []byte("x")))
	require.Error(t, d.WriteFile(".", []byte("x")))

	_, err = d.ReadFile("../escape")
	require.Error(t, err)
	require.Error(t, d.Remove("../escape"))

	// Reading a regular file as a directory fails.
	_, err = d.ReadDir("Packages.diff/Index")
	require.Error(t, err)

	// A whole builder cycle on the real file system.
	b, err := deb.NewPDiffIndexBuilder(d, deb.PDiffBuilderOptions{})
	require.NoError(t, err)

	vs := pdiffVersions(12, 3)

	for i := 1; i < len(vs); i++ {
		require.NoError(t, d.WriteFile("Packages", []byte(vs[i-1])))

		_, err = b.Update([]byte(vs[i]), pdiffEpoch.Add(time.Duration(i)*time.Hour))
		require.NoError(t, err)
	}

	require.NoError(t, d.WriteFile("Packages", []byte(vs[2])))
	pdiffCatchUp(t, d, vs[0], vs[2])
	require.NoError(t, d.Close())

	_, err = deb.NewPDiffDirFS(filepath.Join(dir, "Packages", "x"))
	require.Error(t, err, "a path below a regular file cannot be a directory")

	require.True(t, slices.IsSorted(names))
}
