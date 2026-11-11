package deb_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

const pdiffTestdata = "testdata/repo-pdiff"

// pdiffReadFile reads a fixture and decompresses it by its extension.
func pdiffReadFile(tb testing.TB, parts ...string) []byte {
	tb.Helper()

	name := filepath.Join(append([]string{pdiffTestdata}, parts...)...)

	f, err := os.Open(name)
	require.NoError(tb, err)

	defer f.Close()

	r, err := deb.OpenIndex(f, name)
	require.NoError(tb, err)

	data, err := io.ReadAll(r)
	require.NoError(tb, err)

	return data
}

func pdiffRawFile(tb testing.TB, parts ...string) []byte {
	tb.Helper()

	data, err := os.ReadFile(filepath.Join(append([]string{pdiffTestdata}, parts...)...))
	require.NoError(tb, err)

	return data
}

// pdiffDirFetcher serves the patches of a fixture directory.
func pdiffDirFetcher(tb testing.TB, dir string) deb.PDiffFetcher {
	tb.Helper()

	return func(p deb.PDiffPatch) ([]byte, error) {
		return os.ReadFile(filepath.Join(pdiffTestdata, dir, p.DownloadName()))
	}
}

// TestPDiffRealMergedIndex applies the merged patches of the trixie-updates
// index (real files published by the Debian archive) to every base file the
// history lists: each one reaches the current file in a single step.
func TestPDiffRealMergedIndex(t *testing.T) {
	raw := pdiffRawFile(t, "trixie-updates", "Index")

	idx, err := deb.ParsePDiffIndex(raw)
	require.NoError(t, err)
	require.Equal(t, string(raw), string(idx.Marshal()), "the writer reproduces the merged Index too")

	require.True(t, idx.Merged)
	require.Len(t, idx.Patches, 7)
	require.Len(t, idx.Unmerged, 7)
	require.Equal(t, []string{"2026-10-22-2004.53", "2026-10-30-1402.07", "2026-11-05-1401.10"}, idx.OlderPatches)
	require.Equal(t, int64(2351), idx.Current.Size)
	require.Equal(t, "7f1dd99bbd1a0416d39499892ec12ff38d80637029114d234c38972bba8ae041", idx.Current.SHA256)
	require.Equal(t, "50f4dfe00c44971c36f4355baaf28dc42c2c3385", idx.Current.SHA1)

	current := pdiffReadFile(t, "trixie-updates", "Packages.xz")
	require.Equal(t, idx.Current.SHA256, deb.PDiffSHA256(current))

	bases, err := filepath.Glob(filepath.Join(pdiffTestdata, "trixie-updates", "base-*.xz"))
	require.NoError(t, err)
	require.Len(t, bases, 6)

	for _, b := range bases {
		base := pdiffReadFile(t, "trixie-updates", filepath.Base(b))

		chain, err := idx.Chain(deb.PDiffSHA256(base))
		require.NoError(t, err, b)
		require.Len(t, chain, 1, "a merged index reaches the current file in one step")
		require.Equal(t, idx.Current, chain[0].To)
		require.True(t, strings.HasPrefix(chain[0].Name, "T-2026-11-05-1401.10-F-"))

		got, err := deb.ApplyPDiffChain(base, chain, pdiffDirFetcher(t, "trixie-updates"), deb.PDiffApplyOptions{})

		if strings.Contains(b, "base-20261022T210000Z") {
			// The archive published a merged patch for this base that does not
			// lead to the current file (rred produces the same wrong output,
			// see README.md). Verification must refuse it.
			var he *deb.PDiffHashError

			require.ErrorAs(t, err, &he, b)
			require.Equal(t, "result", he.What)

			continue
		}

		require.NoError(t, err, b)
		require.Equal(t, string(current), string(got), b)
	}

	// The unmerged series of the same index is the one-step patches.
	require.Equal(t, "2025-08-09-2057.10", idx.Unmerged[0].Name)
	require.Equal(t, idx.Patches[0].From, idx.Unmerged[0].From)
}

// TestPDiffRealUnmergedIndex walks the three one-step patches of the
// buster-updates index, which start from an empty file.
func TestPDiffRealUnmergedIndex(t *testing.T) {
	raw := pdiffRawFile(t, "buster-updates", "Index")

	idx, err := deb.ParsePDiffIndex(raw)
	require.NoError(t, err)
	require.False(t, idx.Merged)
	require.Len(t, idx.Patches, 3)
	require.Equal(t, "2019-08-14-2019.27", idx.Patches[0].Name)
	require.Equal(t, "2019-08-14-2019.27.gz", idx.Patches[0].DownloadName())
	require.Equal(t, int64(811), idx.Patches[0].Download.Size)
	require.Equal(t, int64(1503), idx.Patches[0].Patch.Size)
	require.Equal(t, "da39a3ee5e6b4b0d3255bfef95601890afd80709", idx.Patches[0].From.SHA1)

	// The writer reproduces the document dak wrote, byte for byte.
	require.Equal(t, string(raw), string(idx.Marshal()))

	current := pdiffReadFile(t, "buster-updates", "Packages.xz")

	chain, err := idx.Chain(deb.PDiffSHA256(nil))
	require.NoError(t, err)
	require.Len(t, chain, 3)
	require.Equal(t, idx.Patches[1].From, chain[0].To, "an intermediate patch leads to the next one's file")
	require.Equal(t, idx.Patches[2].From, chain[1].To)
	require.Equal(t, idx.Current, chain[2].To)

	got, err := deb.ApplyPDiffChain(nil, chain, pdiffDirFetcher(t, "buster-updates"), deb.PDiffApplyOptions{})
	require.NoError(t, err)
	require.Equal(t, string(current), string(got))

	// Starting in the middle of the series applies only the rest.
	mid, err := deb.ApplyPDiffChain(nil, chain[:1], pdiffDirFetcher(t, "buster-updates"), deb.PDiffApplyOptions{})
	require.NoError(t, err)

	chain2, err := idx.Chain(deb.PDiffSHA256(mid))
	require.NoError(t, err)
	require.Len(t, chain2, 2)

	got, err = deb.ApplyPDiffChain(mid, chain2, pdiffDirFetcher(t, "buster-updates"), deb.PDiffApplyOptions{})
	require.NoError(t, err)
	require.Equal(t, string(current), string(got))
}

func TestPDiffChainEdges(t *testing.T) {
	idx, err := deb.ParsePDiffIndex(pdiffRawFile(t, "buster-updates", "Index"))
	require.NoError(t, err)

	current := pdiffReadFile(t, "buster-updates", "Packages.xz")

	chain, err := idx.Chain(deb.PDiffSHA256(current))
	require.NoError(t, err)
	require.Empty(t, chain, "the current file needs no patch")

	chain, err = idx.Chain(strings.ToUpper(deb.PDiffSHA256(current)))
	require.NoError(t, err)
	require.Empty(t, chain, "digests compare case-insensitively")

	_, err = idx.Chain(deb.PDiffSHA256([]byte("something else")))
	require.ErrorIs(t, err, deb.ErrPDiffNoPath)

	_, err = idx.Chain("")
	require.ErrorIs(t, err, deb.ErrPDiffNoPath)
}

func TestPDiffChainPrefersNewestMatch(t *testing.T) {
	const h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	const idx = `SHA256-Current: ` + h + ` 0
SHA256-History:
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 10 p1
 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 10 p2
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 10 p3
SHA256-Patches:
 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc 1 p1
 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc 1 p2
 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc 1 p3
SHA256-Download:
 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd 1 p1.gz
 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd 1 p2.gz
 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd 1 p3.gz
`

	parsed, err := deb.ParsePDiffIndex([]byte(idx))
	require.NoError(t, err)

	chain, err := parsed.Chain(strings.Repeat("a", 64))
	require.NoError(t, err)
	require.Len(t, chain, 1)
	require.Equal(t, "p3", chain[0].Name, "the shortest chain wins")
}

func TestPDiffChainUnusableDigests(t *testing.T) {
	const idx = `SHA1-Current: da39a3ee5e6b4b0d3255bfef95601890afd80709 0
SHA256-Current: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0
SHA256-History:
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 10 p1
`

	parsed, err := deb.ParsePDiffIndex([]byte(idx))
	require.NoError(t, err)

	_, err = parsed.Chain(strings.Repeat("a", 64))
	require.ErrorIs(t, err, deb.ErrPDiffIndex, "a patch with no patch or download digest cannot be used")
}

func TestPDiffParseErrors(t *testing.T) {
	const (
		h64 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		h40 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	)

	cases := map[string]string{
		"empty":                "",
		"no current":           "SHA256-History:\n " + h64 + " 1 p\n",
		"bad current":          "SHA256-Current: " + h64 + "\n",
		"bad hash":             "SHA256-Current: zz 1\n",
		"short hash":           "SHA256-Current: abcd 1\n",
		"negative size":        "SHA256-Current: " + h64 + " -1\n",
		"size mismatch":        "SHA256-Current: " + h64 + " 1\nSHA1-Current: " + h40 + " 2\n",
		"history not triples":  "SHA256-Current: " + h64 + " 1\nSHA256-History:\n " + h64 + " 1\n",
		"unsafe name":          "SHA256-Current: " + h64 + " 1\nSHA256-History:\n " + h64 + " 1 ../x\n",
		"name Index":           "SHA256-Current: " + h64 + " 1\nSHA256-History:\n " + h64 + " 1 Index\n",
		"continuation first":   " " + h64 + "\n",
		"line without a colon": "SHA256-Current " + h64 + " 1\n",
	}

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := deb.ParsePDiffIndex([]byte(in))
			require.ErrorIs(t, err, deb.ErrPDiffIndex)
		})
	}

	_, err := deb.ParsePDiffIndex(bytes.Repeat([]byte("x"), deb.MaxPDiffIndexBytes+1))
	require.ErrorIs(t, err, deb.ErrPDiffIndex)
}

func TestPDiffParseIgnoresUnknownNamesAndExtras(t *testing.T) {
	const h64 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	in := "Canonical-Path: dists/x/Packages.diff/Index\n" +
		"SHA256-Current: " + h64 + " 5\n" +
		"SHA256-History:\n " + h64 + " 5 p1\n" +
		"SHA256-Patches:\n " + h64 + " 5 p1\n " + h64 + " 5 ghost\n" +
		"SHA256-Download:\n " + h64 + " 5 p1.gz\n " + h64 + " 5 p1.xz\n " + h64 + " 5 p1.bz2\n" +
		"SHA512-Current: whatever 5\n" +
		"X-Custom: yes\n" +
		"\nSHA256-Current: ignored 1\n"

	idx, err := deb.ParsePDiffIndex([]byte(in))
	require.NoError(t, err)
	require.Equal(t, "dists/x/Packages.diff/Index", idx.CanonicalPath)
	require.Len(t, idx.Patches, 1, "names that are not in the history are ignored")
	require.Equal(t, int64(5), idx.Patches[0].DownloadXZ.Size)
	require.Equal(t, map[string]string{"SHA512-Current": "whatever 5", "X-Custom": "yes"}, idx.Extra)

	again, err := deb.ParsePDiffIndex(idx.Marshal())
	require.NoError(t, err)
	require.Equal(t, idx, again)
}

func TestPDiffApplyChainDetectsTampering(t *testing.T) {
	idx, err := deb.ParsePDiffIndex(pdiffRawFile(t, "buster-updates", "Index"))
	require.NoError(t, err)

	chain, err := idx.Chain(deb.PDiffSHA256(nil))
	require.NoError(t, err)

	fetch := pdiffDirFetcher(t, "buster-updates")

	var he *deb.PDiffHashError

	// A corrupted download is caught by its digest before it is decompressed.
	bad := func(p deb.PDiffPatch) ([]byte, error) {
		b, err := fetch(p)
		if err == nil {
			b = append([]byte(nil), b...)
			b[len(b)/2] ^= 0xff
		}

		return b, err
	}

	_, err = deb.ApplyPDiffChain(nil, chain, bad, deb.PDiffApplyOptions{})
	require.ErrorIs(t, err, deb.ErrPDiffHash)
	require.ErrorAs(t, err, &he)
	require.Equal(t, "download", he.What)

	// The base must be the file the first patch applies to.
	_, err = deb.ApplyPDiffChain([]byte("x\n"), chain, fetch, deb.PDiffApplyOptions{})
	require.ErrorAs(t, err, &he)
	require.Equal(t, "base", he.What)

	// A well-formed patch the Index does not list gives a wrong result, which
	// is caught as well: forge a download whose digests we fix up.
	forged := append([]deb.PDiffPatch(nil), chain...)
	forged[0].To.SHA256 = strings.Repeat("0", 64)

	_, err = deb.ApplyPDiffChain(nil, forged, fetch, deb.PDiffApplyOptions{})
	require.ErrorAs(t, err, &he)
	require.Equal(t, "result", he.What)

	// A script that does not match the listed digest.
	forged = append([]deb.PDiffPatch(nil), chain...)
	forged[0].Patch.SHA256 = strings.Repeat("0", 64)
	forged[0].Patch.Size = 0

	_, err = deb.ApplyPDiffChain(nil, forged, fetch, deb.PDiffApplyOptions{})
	require.ErrorAs(t, err, &he)
	require.Equal(t, "patch", he.What)

	// A fetch failure is passed up.
	boom := errors.New("boom")
	_, err = deb.ApplyPDiffChain(nil, chain, func(deb.PDiffPatch) ([]byte, error) { return nil, boom }, deb.PDiffApplyOptions{})
	require.ErrorIs(t, err, boom)

	// A download that is not gzip.
	forged = append([]deb.PDiffPatch(nil), chain...)
	notGz := []byte("not gzip")
	forged[0].Download = deb.PDiffHash{Size: int64(len(notGz)), SHA256: deb.PDiffSHA256(notGz)}

	_, err = deb.ApplyPDiffChain(nil, forged, func(deb.PDiffPatch) ([]byte, error) { return notGz, nil }, deb.PDiffApplyOptions{})
	require.Error(t, err)

	// A gzip that decompresses over the limit.
	_, err = deb.ApplyPDiffChain(nil, chain, fetch, deb.PDiffApplyOptions{MaxPatchSize: 10})

	var pe *deb.PDiffError

	require.ErrorAs(t, err, &pe)
	require.ErrorIs(t, err, deb.ErrPDiffLimit)

	// An empty chain is the base itself.
	got, err := deb.ApplyPDiffChain([]byte("same"), nil, fetch, deb.PDiffApplyOptions{})
	require.NoError(t, err)
	require.Equal(t, "same", string(got))
}

func pdiffGzip(tb testing.TB, data []byte) []byte {
	tb.Helper()

	var buf bytes.Buffer

	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(data)
	require.NoError(tb, err)
	require.NoError(tb, zw.Close())

	return buf.Bytes()
}
