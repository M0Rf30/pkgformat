package deb_test

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

func hexOf(h interface{ Sum([]byte) []byte }) string { return hex.EncodeToString(h.Sum(nil)) }

func TestHashBytes(t *testing.T) {
	fi := deb.HashBytes("main/binary-amd64/Packages", []byte("abc"))

	assert.Equal(t, "main/binary-amd64/Packages", fi.Path)
	assert.Equal(t, int64(3), fi.Size)
	assert.Equal(t, "900150983cd24fb0d6963f7d28e17f72", fi.MD5sum)
	assert.Equal(t, "a9993e364706816aba3e25717850c26c9cd0d89d", fi.SHA1)
	assert.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", fi.SHA256)
	assert.Equal(t, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", fi.SHA512)
	assert.True(t, fi.Complete())

	empty := deb.HashBytes("e", nil)
	assert.Zero(t, empty.Size)
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", empty.SHA256)
}

func TestHashReader(t *testing.T) {
	data := []byte(strings.Repeat("0123456789", 100000))

	want := deb.HashBytes("p", data)

	got, err := deb.HashReader("p", iotest.OneByteReader(strings.NewReader(string(data[:1000]))))
	require.NoError(t, err)
	assert.Equal(t, deb.HashBytes("p", data[:1000]), got)

	got, err = deb.HashReader("p", strings.NewReader(string(data)))
	require.NoError(t, err)
	assert.Equal(t, want, got)

	m, s1, s2, s5 := md5.New(), sha1.New(), sha256.New(), sha512.New()
	_, _ = io.MultiWriter(m, s1, s2, s5).Write(data)
	assert.Equal(t, hexOf(m), got.MD5sum)
	assert.Equal(t, hexOf(s1), got.SHA1)
	assert.Equal(t, hexOf(s2), got.SHA256)
	assert.Equal(t, hexOf(s5), got.SHA512)

	_, err = deb.HashReader("p", failingReader{})
	require.ErrorIs(t, err, errBroken)
}

func TestFileInfoComplete(t *testing.T) {
	assert.False(t, deb.FileInfo{}.Complete())
	assert.False(t, deb.FileInfo{MD5sum: "a", SHA1: "b"}.Complete())
	assert.True(t, deb.FileInfo{MD5sum: "a", SHA1: "b", SHA256: "c"}.Complete())
}

func sampleRelease() *deb.Release {
	rel := &deb.Release{
		Origin: "Example", Label: "Ex", Suite: "stable", Version: "1.2", Codename: "bookworm",
		Date: time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC), ValidUntil: time.Date(2025, 4, 4, 5, 6, 7, 0, time.UTC),
		Architectures: []string{"amd64", "arm64"}, Components: []string{"main", "contrib"},
		Description: "Example repo\nsecond line",
	}

	for _, p := range []string{"main/binary-amd64/Packages.xz", "main/binary-amd64/Packages", "contrib/binary-arm64/Packages.gz"} {
		rel.AddFile(deb.HashBytes(p, []byte("content of "+p)))
	}

	return rel
}

func TestReleaseMarshalLayout(t *testing.T) {
	rel := &deb.Release{
		Origin: "O", Suite: "s", Codename: "c", Date: time.Date(2025, 3, 4, 5, 6, 7, 0, time.FixedZone("X", 3600)),
		Architectures: []string{"amd64"}, Components: []string{"main"},
	}
	rel.AddFile(deb.FileInfo{Path: "b/Packages", Size: 12, SHA256: strings.Repeat("b", 64)})
	rel.AddFile(deb.FileInfo{Path: "a/Packages", Size: 1234567890123, MD5sum: strings.Repeat("a", 32), SHA256: strings.Repeat("c", 64)})

	assert.Equal(t, "Origin: O\n"+
		"Suite: s\n"+
		"Codename: c\n"+
		"Date: Tue, 04 Mar 2025 04:06:07 UTC\n"+
		"Architectures: amd64\n"+
		"Components: main\n"+
		"MD5Sum:\n"+
		" "+strings.Repeat("a", 32)+" 1234567890123 a/Packages\n"+
		"SHA256:\n"+
		" "+strings.Repeat("c", 64)+" 1234567890123 a/Packages\n"+
		" "+strings.Repeat("b", 64)+"       12 b/Packages\n", string(rel.Marshal()))

	assert.Empty(t, (&deb.Release{}).Marshal())
}

func TestReleaseRoundTrip(t *testing.T) {
	rel := sampleRelease()

	got, err := deb.ParseRelease(rel.Marshal())
	require.NoError(t, err)

	assert.Equal(t, rel.Origin, got.Origin)
	assert.Equal(t, rel.Label, got.Label)
	assert.Equal(t, rel.Suite, got.Suite)
	assert.Equal(t, rel.Version, got.Version)
	assert.Equal(t, rel.Codename, got.Codename)
	assert.True(t, rel.Date.Equal(got.Date), got.Date)
	assert.True(t, rel.ValidUntil.Equal(got.ValidUntil), got.ValidUntil)
	assert.Equal(t, rel.Architectures, got.Architectures)
	assert.Equal(t, rel.Components, got.Components)
	assert.Equal(t, rel.Description, got.Description)
	assert.Equal(t, rel.Files, got.Files)

	// Marshal(Parse(x)) is stable.
	assert.Equal(t, string(rel.Marshal()), string(got.Marshal()))
}

func TestParseReleaseFixture(t *testing.T) {
	const doc = "Origin: Test\nSuite: jammy\nCodename: jammy\nDate: Thu, 21 Apr 2022 17:16:08 UTC\n" +
		"Architectures: amd64 arm64\nComponents: main universe\nDescription: Test Release\n" +
		"MD5Sum:\n d41d8cd98f00b204e9800998ecf8427e 0 main/binary-amd64/Packages\n d41d8cd98f00b204e9800998ecf8427e 0 main/binary-amd64/Packages.gz\n" +
		"SHA256:\n e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages\n" +
		" E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 0 main/binary-amd64/Packages.gz\n" +
		" not enough fields\n" +
		" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 notanumber main/skipped\n" +
		"SHA512:\n"

	rel, err := deb.ParseRelease([]byte(doc))
	require.NoError(t, err)

	assert.Equal(t, "jammy", rel.Suite)
	assert.Equal(t, []string{"amd64", "arm64"}, rel.Architectures)
	assert.Equal(t, []string{"main", "universe"}, rel.Components)
	assert.Equal(t, time.Date(2022, 4, 21, 17, 16, 8, 0, time.UTC), rel.Date.UTC())

	require.Len(t, rel.Files, 2)

	gz := rel.Files["main/binary-amd64/Packages.gz"]
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", gz.SHA256, "digests are lower-cased")
	assert.True(t, gz.MD5sum != "" && gz.SHA1 == "")
	assert.False(t, gz.Complete(), "SHA1 is missing")

	assert.True(t, rel.HasIndex("main", "amd64"))
	assert.False(t, rel.HasIndex("main", "arm64"))
	assert.False(t, rel.HasIndex("universe", "amd64"))
	assert.Equal(t, []string{"main/binary-amd64/Packages.gz", "main/binary-amd64/Packages"}, rel.PackagesVariants("main", "amd64"))
	assert.Empty(t, rel.PackagesVariants("main", "arm64"))
}

func TestReleasePackagesVariantsOrder(t *testing.T) {
	rel := &deb.Release{}
	base := "c/binary-a/Packages"

	for _, ext := range []string{"", ".lz4", ".bz2", ".gz", ".zst", ".xz"} {
		rel.AddFile(deb.FileInfo{Path: base + ext, Size: 1})
	}

	rel.AddFile(deb.FileInfo{Path: "c/binary-b/Packages.xz.diff", Size: 1})

	assert.Equal(t, []string{base + ".xz", base + ".zst", base + ".gz", base + ".bz2", base + ".lz4", base}, rel.PackagesVariants("c", "a"))
	assert.Equal(t, rel.PackagesVariants("c", "a"), rel.PackagesCandidates("c", "a"))

	// A Release without the index lists the usual guesses.
	assert.Equal(t, []string{"c/binary-b/Packages.xz", "c/binary-b/Packages.gz", "c/binary-b/Packages"}, rel.PackagesCandidates("c", "b"))
	assert.False(t, rel.HasIndex("c", "b"))
}

func TestParseReleaseClearsigned(t *testing.T) {
	const doc = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" +
		"Suite: jammy\nCodename: jammy\nDescription: has a dash\n" +
		"SHA256:\n e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages\n" +
		"-----BEGIN PGP SIGNATURE-----\n\nwsBcBAEBCgAGBQJ...\n-----END PGP SIGNATURE-----\n"

	rel, err := deb.ParseRelease([]byte(doc))
	require.NoError(t, err)

	assert.Equal(t, "jammy", rel.Suite)
	assert.Equal(t, "jammy", rel.Codename)
	require.Len(t, rel.Files, 1)

	// Leading blank lines and CRLF line ends are fine.
	crlf := "\r\n" + strings.ReplaceAll(doc, "\n", "\r\n")
	rel2, err := deb.ParseRelease([]byte(crlf))
	require.NoError(t, err)
	assert.Equal(t, "jammy", rel2.Suite)
	assert.Equal(t, rel.Files, rel2.Files)
}

func TestParseReleaseErrors(t *testing.T) {
	h := func(n int) string { return strings.Repeat("a", n) }

	tests := map[string]string{
		"short md5":          "MD5Sum:\n " + h(31) + " 1 a/Packages\n",
		"long sha256":        "SHA256:\n " + h(65) + " 1 a/Packages\n",
		"non hex sha1":       "SHA1:\n " + strings.Repeat("g", 40) + " 1 a/Packages\n",
		"sha512 with sha256": "SHA512:\n " + h(64) + " 1 a/Packages\n",
		"parent path":        "SHA256:\n " + h(64) + " 1 ../etc/passwd\n",
		"inner parent":       "SHA256:\n " + h(64) + " 1 a/../b\n",
		"absolute path":      "SHA256:\n " + h(64) + " 1 /etc/passwd\n",
		"empty segment":      "SHA256:\n " + h(64) + " 1 a//b\n",
		"dot segment":        "SHA256:\n " + h(64) + " 1 ./a\n",
		"backslash":          "SHA256:\n " + h(64) + " 1 a\\b\n",
		"size conflict":      "MD5Sum:\n " + h(32) + " 10 a/Packages\nSHA256:\n " + h(64) + " 11 a/Packages\n",
		"size conflict same": "SHA256:\n " + h(64) + " 10 a/Packages\n " + h(64) + " 11 a/Packages\n",
	}

	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := deb.ParseRelease([]byte(doc))
			require.ErrorIs(t, err, deb.ErrInvalidRelease)
		})
	}

	t.Run("duplicate with the same size is accepted", func(t *testing.T) {
		rel, err := deb.ParseRelease([]byte("SHA256:\n " + h(64) + " 10 a/Packages\nMD5Sum:\n " + h(32) + " 10 a/Packages\n"))
		require.NoError(t, err)
		assert.Equal(t, int64(10), rel.Files["a/Packages"].Size)
	})
}

func TestParseReleaseTooLarge(t *testing.T) {
	doc := []byte(strings.Repeat("# filler\n", deb.MaxReleaseBytes/9+1))[:deb.MaxReleaseBytes+1]

	_, err := deb.ParseRelease(doc)
	require.ErrorIs(t, err, deb.ErrTooLarge)

	_, err = deb.ParseRelease(doc[:deb.MaxReleaseBytes])
	assert.NotErrorIs(t, err, deb.ErrTooLarge)
}

func TestParseReleaseGarbage(t *testing.T) {
	rel, err := deb.ParseRelease(nil)
	require.NoError(t, err)
	assert.Empty(t, rel.Files)

	rel, err = deb.ParseRelease([]byte("this is\nnot a release\x00\xff"))
	require.NoError(t, err)
	assert.Empty(t, rel.Files)
}

func TestReleaseCheckValidity(t *testing.T) {
	until := time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)

	rel := &deb.Release{ValidUntil: until}
	require.NoError(t, rel.CheckValidity(until.Add(-time.Hour)))
	require.NoError(t, rel.CheckValidity(until), "the instant itself is still valid")
	require.ErrorIs(t, rel.CheckValidity(until.Add(time.Second)), deb.ErrReleaseExpired)

	require.NoError(t, (&deb.Release{}).CheckValidity(time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)), "no Valid-Until never expires")
}

func TestReleaseDateLayouts(t *testing.T) {
	want := time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	plus1 := time.Date(2027, 12, 31, 23, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		in   string
		want time.Time
	}{
		{"Sat, 01 Jan 2028 00:00:00 UTC", want},
		{"Sat, 01 Jan 2028 00:00:00 GMT", want},
		{"Sat, 1 Jan 2028 00:00:00 UTC", want},
		{"Sat, 01 Jan 2028 00:00:00 +0000", want},
		{"Sat, 1 Jan 2028 00:00:00 +0000", want},
		{"Sat, 01 Jan 2028 00:00:00 +0100", plus1},
		{"Sat, 1 Jan 2028 00:00:00 +0100", plus1},
		{"Sat, 01 Jan 2028 00:00:00 -0000", want},
	} {
		rel, err := deb.ParseRelease([]byte("Valid-Until: " + tc.in + "\nDate: " + tc.in + "\n"))
		require.NoError(t, err, tc.in)
		assert.True(t, rel.ValidUntil.Equal(tc.want), "%s: %v", tc.in, rel.ValidUntil)
		assert.True(t, rel.Date.Equal(tc.want), "%s: %v", tc.in, rel.Date)
		require.ErrorIs(t, rel.CheckValidity(tc.want.Add(time.Minute)), deb.ErrReleaseExpired, tc.in)
	}

	// An unreadable date is treated as absent.
	for _, bad := range []string{"", "tomorrow", "2028-01-01", "Sat, 32 Jan 2028 00:00:00 UTC"} {
		rel, err := deb.ParseRelease([]byte("Valid-Until: " + bad + "\n"))
		require.NoError(t, err)
		assert.True(t, rel.ValidUntil.IsZero(), "%q", bad)
	}
}

func TestStripClearsign(t *testing.T) {
	const begin, sig = "-----BEGIN PGP SIGNED MESSAGE-----", "-----BEGIN PGP SIGNATURE-----"

	tests := map[string]struct{ in, want string }{
		"plain text is unchanged":     {"Suite: jammy\n", "Suite: jammy\n"},
		"empty":                       {"", ""},
		"signed":                      {begin + "\nHash: SHA512\n\nSuite: jammy\nCodename: jammy\n" + sig + "\nxx\n", "Suite: jammy\nCodename: jammy"},
		"crlf":                        {begin + "\r\nHash: SHA512\r\n\r\nSuite: jammy\r\n" + sig + "\r\n", "Suite: jammy"},
		"several armor headers":       {begin + "\nHash: SHA256\nHash: SHA512\n\nSuite: jammy\n" + sig, "Suite: jammy"},
		"no armor header":             {begin + "\n\nSuite: jammy\n" + sig, "Suite: jammy"},
		"dash escaped":                {begin + "\n\n- -foo\n- - bar\n" + sig, "-foo\n- bar"},
		"escaped signature marker":    {begin + "\n\nA\n- " + sig + "\nB\n" + sig, "A\n" + sig + "\nB"},
		"marker in the middle":        {begin + "\n\nA " + sig + " B\n" + sig, "A " + sig + " B"},
		"blank lines kept":            {begin + "\n\nA\n\nB\n" + sig, "A\n\nB"},
		"leading whitespace":          {"\r\n \n" + begin + "\n\nA\n" + sig, "A"},
		"no signature block":          {begin + "\n\nA\nB\n", "A\nB\n"},
		"headers never end":           {begin + "\nHash: SHA512\nSuite: x\n", ""},
		"text after the begin marker": {"x\n" + begin + "\n\nA\n" + sig, "x\n" + begin + "\n\nA\n" + sig},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, string(deb.StripClearsign([]byte(tc.in))))
		})
	}
}

func FuzzStripClearsign(f *testing.F) {
	f.Add([]byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nSuite: x\n- -----BEGIN PGP SIGNATURE-----\n-----BEGIN PGP SIGNATURE-----\n"))
	f.Add([]byte("Suite: plain\n"))
	f.Add([]byte(""))
	f.Add([]byte("\r\n-----BEGIN PGP SIGNED MESSAGE-----\r\n\r\n- - x\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		out := deb.StripClearsign(data)

		if !strings.HasPrefix(strings.TrimLeft(string(data), "\r\n "), "-----BEGIN PGP SIGNED MESSAGE-----") {
			assert.Equal(t, data, out)

			return
		}

		assert.LessOrEqual(t, len(out), len(data))
	})
}

func FuzzParseRelease(f *testing.F) {
	f.Add(sampleRelease().Marshal())
	f.Add([]byte("SHA256:\n " + strings.Repeat("a", 64) + " 1 a/Packages\nMD5Sum:\n " + strings.Repeat("b", 32) + " 2 a/Packages\n"))
	f.Add([]byte("-----BEGIN PGP SIGNED MESSAGE-----\n\nSuite: x\nValid-Until: Sat, 1 Jan 2028 00:00:00 +0100\n-----BEGIN PGP SIGNATURE-----\n"))
	f.Add([]byte("Date: Sat, 01 Jan 2028 00:00:00 UTC\nDescription: a\n b\n .\n c\n"))
	f.Add([]byte("SHA256:\n " + strings.Repeat("a", 64) + " 1 ../x\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		rel, err := deb.ParseRelease(data)
		if err != nil {
			return
		}

		for p, fi := range rel.Files {
			assert.Equal(t, p, fi.Path)

			for seg := range strings.SplitSeq(p, "/") {
				assert.False(t, seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, "\\\x00"), "unsafe path %q", p)
			}

			assert.GreaterOrEqual(t, fi.Size, int64(0))
		}

		// What is rendered reads back with the same file listing.
		again, err := deb.ParseRelease(rel.Marshal())
		require.NoError(t, err)
		assert.Equal(t, rel.Files, again.Files)
	})
}
