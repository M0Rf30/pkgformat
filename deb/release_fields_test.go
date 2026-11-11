package deb_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

func readFixture(t testing.TB, elem ...string) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, elem...)...))
	require.NoError(t, err)

	return b
}

// fullRelease sets every field the type models.
func fullRelease() *deb.Release {
	rel := &deb.Release{
		Origin: "Example", Label: "Ex", Suite: "stable", Version: "1.2", Codename: "bookworm",
		Changelogs: "https://example.org/@CHANGEPATH@_changelog", Snapshots: "https://snap.example.org/@TIMESTAMP@/",
		Date: time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC), ValidUntil: time.Date(2025, 4, 4, 5, 6, 7, 0, time.UTC),
		NotAutomatic: true, ButAutomaticUpgrades: true, AcquireByHash: true,
		SignedBy:                    "0123456789ABCDEF0123456789ABCDEF01234567,\nFEDCBA9876543210FEDCBA9876543210FEDCBA98",
		NoSupportForArchitectureAll: "Packages",
		Architectures:               []string{"all", "amd64"}, Components: []string{"main", "contrib"},
		Description: "Example repo\nsecond line\n\nafter blank",
		Extra:       map[string]string{"X-Custom": "yes", "Z-Multi": "a\nb"},
	}

	for _, p := range []string{"main/binary-amd64/Packages.xz", "main/binary-amd64/Packages", "contrib/Contents-amd64.gz"} {
		fi := deb.HashBytes(p, []byte("content of "+p))
		rel.AddFile(fi)
	}

	return rel
}

func TestReleaseEveryFieldRoundTrips(t *testing.T) {
	rel := fullRelease()

	for _, style := range []deb.ReleaseStyle{deb.ReleaseStyleDebian, deb.ReleaseStyleAptFTPArchive} {
		got, err := deb.ParseRelease(rel.MarshalStyle(style))
		require.NoError(t, err)

		assert.Equal(t, rel, got, "style %d", style)
		assert.Equal(t, string(rel.MarshalStyle(style)), string(got.MarshalStyle(style)))
	}

	t.Run("debian field order", func(t *testing.T) {
		var names []string

		for line := range strings.SplitSeq(string(rel.Marshal()), "\n") {
			if line != "" && line[0] != ' ' {
				names = append(names, strings.TrimSuffix(strings.SplitN(line, ":", 2)[0], ":"))
			}
		}

		assert.Equal(t, []string{
			"Origin", "Label", "Suite", "Version", "Codename", "Changelogs", "Snapshots", "Date", "Valid-Until",
			"NotAutomatic", "ButAutomaticUpgrades", "Acquire-By-Hash", "Signed-By", "No-Support-for-Architecture-all",
			"Architectures", "Components", "Description", "X-Custom", "Z-Multi",
			"MD5Sum", "SHA1", "SHA256", "SHA512",
		}, names)
	})

	t.Run("multi-line values are continuation lines", func(t *testing.T) {
		out := string(rel.Marshal())
		assert.Contains(t, out, "Signed-By: 0123456789ABCDEF0123456789ABCDEF01234567,\n FEDCBA9876543210FEDCBA9876543210FEDCBA98\n")
		assert.Contains(t, out, "Description: Example repo\n second line\n .\n after blank\n")
	})
}

func TestReleaseFieldNameCaseAndAliases(t *testing.T) {
	doc := "origin: O\nLABEL: L\nsuite: s\nCODENAME: c\nacquire-by-hash: Yes\nnotautomatic: true\nbutautomaticupgrades: 1\n" +
		"signed-by: AB\nno-support-for-architecture-all: Packages\nchangelogs: no\nsnapshots: https://s/\n" +
		"architectures: amd64\ncomponents: main\nx-unknown: kept\nmd5sum:\n " + strings.Repeat("a", 32) + " 3 a/Packages\n"

	rel, err := deb.ParseRelease([]byte(doc))
	require.NoError(t, err)

	assert.Equal(t, "O", rel.Origin)
	assert.Equal(t, "L", rel.Label)
	assert.Equal(t, "s", rel.Suite)
	assert.True(t, rel.AcquireByHash)
	assert.True(t, rel.NotAutomatic)
	assert.True(t, rel.ButAutomaticUpgrades)
	assert.Equal(t, "AB", rel.SignedBy)
	assert.Equal(t, "Packages", rel.NoSupportForArchitectureAll)
	assert.Equal(t, "no", rel.Changelogs)
	assert.Equal(t, "https://s/", rel.Snapshots)
	assert.Equal(t, map[string]string{"x-unknown": "kept"}, rel.Extra, "unknown fields keep their spelling")
	assert.Equal(t, int64(3), rel.Files["a/Packages"].Size)

	// An unknown field written in any case of a known one is not duplicated.
	again, err := deb.ParseRelease(rel.Marshal())
	require.NoError(t, err)
	assert.Equal(t, rel.Extra, again.Extra)
	assert.Equal(t, 1, strings.Count(strings.ToLower(string(rel.Marshal())), "notautomatic"))

	// The older spelling Not-Automatic is read, not rendered.
	old, err := deb.ParseRelease([]byte("Not-Automatic: yes\n"))
	require.NoError(t, err)
	assert.True(t, old.NotAutomatic)
	assert.Empty(t, old.Extra)
}

func TestParseBool(t *testing.T) {
	for _, s := range []string{"yes", "YES", "true", "with", "on", "enable", "1", " yes "} {
		v, ok := deb.ParseBool(s)
		assert.True(t, v && ok, s)
	}

	for _, s := range []string{"no", "false", "without", "off", "disable", "0"} {
		v, ok := deb.ParseBool(s)
		assert.True(t, !v && ok, s)
	}

	for _, s := range []string{"", "maybe", "2"} {
		_, ok := deb.ParseBool(s)
		assert.False(t, ok, s)
	}

	rel, err := deb.ParseRelease([]byte("Acquire-By-Hash: no\nNotAutomatic: whatever\n"))
	require.NoError(t, err)
	assert.False(t, rel.AcquireByHash)
	assert.False(t, rel.NotAutomatic)
}

func TestReleaseOmitsEmptyAndFalse(t *testing.T) {
	assert.Equal(t, "Suite: s\n", string((&deb.Release{Suite: "s", Extra: map[string]string{"Empty": "", "Suite": "dup"}}).Marshal()),
		"empty extras and a known field in Extra are not rendered")
}

// The Debian archive's Release is reproduced byte for byte.
func TestReleaseMatchesDebianArchive(t *testing.T) {
	for _, name := range []string{"debian-stable.Release", "debian-backports.Release"} {
		t.Run(name, func(t *testing.T) {
			real := readFixture(t, "repo", name)

			rel, err := deb.ParseRelease(real)
			require.NoError(t, err)

			assert.Equal(t, string(real), string(rel.Marshal()))
		})
	}

	rel, err := deb.ParseRelease(readFixture(t, "repo", "debian-stable.Release"))
	require.NoError(t, err)

	assert.Equal(t, "Debian", rel.Origin)
	assert.Equal(t, "stable", rel.Suite)
	assert.Equal(t, "trixie", rel.Codename)
	assert.Equal(t, "13.7", rel.Version)
	assert.True(t, rel.AcquireByHash)
	assert.Equal(t, "Packages", rel.NoSupportForArchitectureAll)
	assert.Contains(t, rel.Changelogs, "@CHANGEPATH@")
	assert.Equal(t, time.Date(2026, 9, 12, 7, 55, 41, 0, time.UTC), rel.Date)
	assert.Equal(t, []string{"all", "amd64", "arm64", "armel", "armhf", "i386", "ppc64el", "riscv64", "s390x"}, rel.Architectures)
	assert.Equal(t, []string{"main", "contrib", "non-free-firmware", "non-free"}, rel.Components)
	assert.Empty(t, rel.Extra)

	fi := rel.Files["main/binary-amd64/Packages.xz"]
	assert.Equal(t, int64(9678380), fi.Size)
	assert.Equal(t, "2d47057a46b268c5f031facecf74b20a", fi.MD5sum)
	assert.Equal(t, "7778d3e3f303b7ddb8ce0fe7c8d57473a076c6bf2e8f241f75421d2396352498", fi.SHA256)
	assert.Empty(t, fi.SHA1, "Debian lists no SHA1")

	bp, err := deb.ParseRelease(readFixture(t, "repo", "debian-backports.Release"))
	require.NoError(t, err)

	assert.True(t, bp.NotAutomatic && bp.ButAutomaticUpgrades && bp.AcquireByHash)
	assert.Equal(t, time.Date(2026, 11, 17, 20, 25, 11, 0, time.UTC), bp.ValidUntil)
	require.ErrorIs(t, bp.CheckValidity(time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)), deb.ErrReleaseExpired)
	require.NoError(t, bp.CheckValidity(time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)))
}

// Ubuntu's apt-ftparchive Release: other field order, 16 column sizes, the
// Acquire-By-Hash field after the checksums, a blank padded date.
func TestReleaseReadsUbuntuArchive(t *testing.T) {
	rel, err := deb.ParseRelease(readFixture(t, "repo", "ubuntu-jammy.Release"))
	require.NoError(t, err)

	assert.Equal(t, "Ubuntu", rel.Origin)
	assert.Equal(t, "jammy", rel.Codename)
	assert.Equal(t, []string{"amd64", "arm64", "armhf", "i386", "ppc64el", "riscv64", "s390x"}, rel.Architectures)
	assert.True(t, rel.AcquireByHash, "a field after the checksum sections is a field")
	assert.Equal(t, time.Date(2022, 4, 21, 17, 16, 8, 0, time.UTC), rel.Date)
	assert.Equal(t, int64(10116), rel.Files["main/i18n/Index"].Size)
	assert.True(t, rel.Files["main/i18n/Index"].Complete())

	assert.Equal(t, []string{"main/i18n/Translation-de.xz", "main/i18n/Translation-de.gz", "main/i18n/Translation-de"}, rel.IndexPaths("main", "", "Translation-de"))
	assert.Equal(t, []string{"de", "en"}, rel.TranslationLanguages("main"))

	bp, err := deb.ParseRelease(readFixture(t, "repo", "ubuntu-backports.Release"))
	require.NoError(t, err)

	assert.Equal(t, time.Date(2026, 11, 10, 7, 42, 48, 0, time.UTC), bp.Date, "a blank padded hour")
	assert.True(t, bp.NotAutomatic && bp.ButAutomaticUpgrades)
	assert.True(t, bp.AcquireByHash)
}

// apt-ftparchive release: field order and sizes are reproduced byte for byte,
// from the committed output and from a live run.
func TestReleaseMatchesAptFTPArchive(t *testing.T) {
	check := func(t *testing.T, out []byte) {
		t.Helper()

		rel, err := deb.ParseRelease(out)
		require.NoError(t, err)

		assert.Equal(t, string(out), string(rel.MarshalStyle(deb.ReleaseStyleAptFTPArchive)))
		assert.Equal(t, "Test", rel.Origin)
		assert.Equal(t, "testing", rel.Suite)
		assert.Equal(t, "1.5", rel.Version)
		assert.Equal(t, "A test archive", rel.Description)
		assert.True(t, rel.NotAutomatic && rel.ButAutomaticUpgrades && rel.AcquireByHash)
		assert.Equal(t, 30*24*time.Hour, rel.ValidUntil.Sub(rel.Date))
		assert.Len(t, rel.Files, 9)
		assert.Equal(t, []string{"main/i18n/Translation-en.bz2", "main/i18n/Translation-en"}, rel.IndexPaths("main", "", "Translation-en"))
	}

	t.Run("committed", func(t *testing.T) {
		check(t, readFixture(t, "repo", "ftparchive.Release"))
	})

	t.Run("live", func(t *testing.T) {
		ftp, err := exec.LookPath("apt-ftparchive")
		if err != nil {
			t.Skip("apt-ftparchive not installed")
		}

		cmd := exec.Command(ftp,
			"-o", "APT::FTPArchive::Release::Origin=Test", "-o", "APT::FTPArchive::Release::Suite=testing",
			"-o", "APT::FTPArchive::Release::Version=1.5", "-o", "APT::FTPArchive::Release::Description=A test archive",
			"-o", "APT::FTPArchive::Release::NotAutomatic=yes", "-o", "APT::FTPArchive::Release::ButAutomaticUpgrades=yes",
			"-o", "APT::FTPArchive::Release::Acquire-By-Hash=yes", "-o", "APT::FTPArchive::Release::ValidTime=2592000",
			"release", ".")
		cmd.Dir = filepath.Join("testdata", "repo", "ftparchive", "dists", "x")

		out, err := cmd.Output()
		require.NoError(t, err)

		rel, err := deb.ParseRelease(out)
		require.NoError(t, err)
		assert.Equal(t, string(out), string(rel.MarshalStyle(deb.ReleaseStyleAptFTPArchive)))

		// The committed listing has the digests of the committed tree.
		committed, err := deb.ParseRelease(readFixture(t, "repo", "ftparchive.Release"))
		require.NoError(t, err)
		assert.Equal(t, committed.Files, rel.Files)
	})
}

func TestReleaseStylesDiffer(t *testing.T) {
	rel := fullRelease()

	debian, ftp := string(rel.Marshal()), string(rel.MarshalStyle(deb.ReleaseStyleAptFTPArchive))
	assert.NotEqual(t, debian, ftp)
	assert.Contains(t, debian, "Date: Tue, 04 Mar 2025 05:06:07 UTC\n")
	assert.Contains(t, ftp, "Date: Tue, 04 Mar 2025 05:06:07 +0000\n")
	assert.True(t, strings.HasPrefix(ftp, "Acquire-By-Hash: yes\nArchitectures:"), ftp[:60])
	assert.Regexp(t, `\n [0-9a-f]{32} {1,15}\d+ `, ftp)
}

func TestReleaseSizeColumnWidths(t *testing.T) {
	rel := &deb.Release{}
	rel.AddFile(deb.FileInfo{Path: "p", Size: 7, SHA256: strings.Repeat("a", 64)})

	assert.Equal(t, "SHA256:\n "+strings.Repeat("a", 64)+"        7 p\n", string(rel.Marshal()))
	assert.Equal(t, "SHA256:\n "+strings.Repeat("a", 64)+"                7 p\n", string(rel.MarshalStyle(deb.ReleaseStyleAptFTPArchive)))
}

func TestIndexPaths(t *testing.T) {
	rel := &deb.Release{}

	add := func(p ...string) {
		for _, x := range p {
			rel.AddFile(deb.FileInfo{Path: x, Size: 1})
		}
	}

	add("main/binary-amd64/Packages.gz", "main/binary-amd64/Packages", "main/binary-amd64/Packages.zst",
		"main/debian-installer/binary-amd64/Packages.xz",
		"main/Contents-amd64.gz", "main/Contents-amd64", "Contents-amd64.xz", "Contents-amd64.gz",
		"main/Contents-udeb-amd64.gz", "Contents-udeb-amd64",
		"main/i18n/Translation-pt_BR.xz", "main/i18n/Translation-pt_BR.bz2", "main/i18n/Translation-en",
		"main/source/Sources.xz", "main/source/Sources.lz4", "main/source/Sources",
		"updates/main/binary-amd64/Packages.xz")

	tests := []struct {
		comp, arch, kind string
		want             []string
	}{
		{"main", "amd64", "Packages", []string{"main/binary-amd64/Packages.zst", "main/binary-amd64/Packages.gz", "main/binary-amd64/Packages"}},
		{"main", "amd64", "Packages-udeb", []string{"main/debian-installer/binary-amd64/Packages.xz"}},
		{"main", "amd64", "Contents", []string{"main/Contents-amd64.gz", "main/Contents-amd64"}},
		{"", "amd64", "Contents", []string{"Contents-amd64.xz", "Contents-amd64.gz"}},
		{"main", "amd64", "Contents-udeb", []string{"main/Contents-udeb-amd64.gz"}},
		{"", "amd64", "Contents-udeb", []string{"Contents-udeb-amd64"}},
		{"main", "", "Translation-pt_BR", []string{"main/i18n/Translation-pt_BR.xz", "main/i18n/Translation-pt_BR.bz2"}},
		{"main", "ignored", "Translation-en", []string{"main/i18n/Translation-en"}},
		{"main", "", "Sources", []string{"main/source/Sources.xz", "main/source/Sources.lz4", "main/source/Sources"}},
		{"updates/main", "amd64", "Packages", []string{"updates/main/binary-amd64/Packages.xz"}},
		{"main", "arm64", "Packages", nil},
		{"main", "amd64", "Nonsense", nil},
		{"main", "amd64", "Translation-", nil},
		{"main", "amd64", "Translation-../x", nil},
		{"..", "amd64", "Packages", nil},
		{"main", "../x", "Packages", nil},
		{"", "amd64", "Packages", nil},
		{"", "", "Contents", nil},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.want, rel.IndexPaths(tc.comp, tc.arch, tc.kind), "%q %q %q", tc.comp, tc.arch, tc.kind)
	}

	assert.Equal(t, "main/binary-amd64/Packages", deb.IndexPath("main", "amd64", deb.IndexPackages))
	assert.Equal(t, "main/debian-installer/binary-amd64/Packages", deb.IndexPath("main", "amd64", deb.IndexPackagesUdeb))
	assert.Equal(t, "main/source/Sources", deb.IndexPath("main", "", deb.IndexSources))
	assert.Equal(t, "Contents-udeb-amd64", deb.IndexPath("", "amd64", deb.IndexContentsUdeb))
	assert.Equal(t, "main/i18n/Translation-de", deb.IndexPath("main", "", deb.IndexTranslationPrefix+"de"))
	assert.Empty(t, deb.IndexPath("main", "amd64", "Translation-d e"))
}

func TestIndexVariants(t *testing.T) {
	rel := &deb.Release{}
	base := "main/binary-amd64/Packages"

	for i, ext := range []string{"", ".lz4", ".bz2", ".gz", ".zst", ".xz"} {
		rel.AddFile(deb.FileInfo{Path: base + ext, Size: int64(i + 1)})
	}

	vs := rel.IndexVariants(base)
	require.Len(t, vs, 6)

	var exts []string

	for _, v := range vs {
		exts = append(exts, v.Extension)
		assert.Equal(t, base+v.Extension, v.Path)
		assert.Equal(t, v.Path, v.Info.Path)
	}

	assert.Equal(t, []string{".xz", ".zst", ".gz", ".bz2", ".lz4", ""}, exts)
	assert.Equal(t, int64(6), vs[0].Info.Size)
	assert.Empty(t, rel.IndexVariants("nothing"))
}

// A Release that carries every extended field is signed, and verifies, as
// InRelease and as Release plus Release.gpg.
func TestExtendedReleaseSigningRoundTrip(t *testing.T) {
	signer := newSigner(t, "repo")
	rel := fullRelease()
	rel.SignedBy = signer.KeyFingerprint()

	signed, err := deb.SignRelease(signer, rel.Marshal())
	require.NoError(t, err)

	trust := deb.Trust{Keyring: keyringOf(t, signer)}

	body, err := trust.VerifyInRelease(signed.InRelease)
	require.NoError(t, err)

	fromIn, err := deb.ParseRelease(body)
	require.NoError(t, err)
	assert.Equal(t, rel, fromIn)

	body, err = trust.VerifyReleaseGPG(signed.Release, signed.ReleaseGPG, nil)
	require.NoError(t, err)

	fromGPG, err := deb.ParseRelease(body)
	require.NoError(t, err)
	assert.Equal(t, rel, fromGPG)

	// ParseRelease reads the clear-signed document directly too.
	direct, err := deb.ParseRelease(signed.InRelease)
	require.NoError(t, err)
	assert.Equal(t, rel, direct)

	// Tampering with a listed digest breaks both signatures.
	tampered := bytes.Replace(signed.Release, []byte("Suite: stable"), []byte("Suite: oldstab"), 1)
	_, err = trust.VerifyReleaseGPG(tampered, signed.ReleaseGPG, nil)
	require.Error(t, err)

	tamperedIn := bytes.Replace(signed.InRelease, []byte("Suite: stable"), []byte("Suite: oldstab"), 1)
	_, err = trust.VerifyInRelease(tamperedIn)
	require.Error(t, err)

	_, err = deb.SignRelease(nil, rel.Marshal())
	require.ErrorIs(t, err, deb.ErrNoSigner)
}

// gpg itself verifies what SignRelease writes for an extended Release.
func TestExtendedReleaseVerifiedByGPG(t *testing.T) {
	gpgBin, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not installed")
	}

	signer := newSigner(t, "repo")
	rel := fullRelease()

	signed, err := deb.SignRelease(signer, rel.Marshal())
	require.NoError(t, err)

	pub, err := signer.PublicKey()
	require.NoError(t, err)

	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	require.NoError(t, os.MkdirAll(home, 0o700))

	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, data, 0o644))

		return p
	}

	pubPath := write("pub.asc", pub)
	releasePath := write("Release", signed.Release)
	sigPath := write("Release.gpg", signed.ReleaseGPG)
	inPath := write("InRelease", signed.InRelease)

	run := func(args ...string) string {
		cmd := exec.Command(gpgBin, append([]string{"--homedir", home, "--batch", "--status-fd", "1"}, args...)...)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))

		return string(out)
	}

	run("--import", pubPath)
	assert.Contains(t, run("--verify", sigPath, releasePath), "GOODSIG")
	assert.Contains(t, run("--verify", inPath), "GOODSIG")

	// And gpg's own reading of the clear-signed text is our Release. gpg 2.2
	// prints one more line end than 2.4 after the last line, so trailing line
	// ends are not compared.
	plain, err := exec.Command(gpgBin, "--homedir", home, "--batch", "--decrypt", inPath).Output()
	require.NoError(t, err)
	assert.Equal(t, strings.TrimRight(string(signed.Release), "\n"), strings.TrimRight(string(plain), "\n"))
}
