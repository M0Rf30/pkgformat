package rpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// installedBlob builds the header image of an installed package: the encoded
// header without its magic and reserved words. A package without an
// architecture is what gpg-pubkey is.
func installedBlob(t testing.TB, withArch bool) []byte {
	t.Helper()

	h := rpmhdr.NewIndex(tag.RPMTAG_HEADERIMMUTABLE)
	h.Add(tag.NAME, rpmhdr.String("hello"))
	h.Add(tag.VERSION, rpmhdr.String("1.2"))
	h.Add(tag.RELEASE, rpmhdr.String("3"))
	h.Add(tag.EPOCH, rpmhdr.Integers([]uint32{4}))
	h.Add(tag.INSTALLTIME, rpmhdr.Integers([]uint32{1700000000}))
	h.Add(tag.PROVIDENAME, rpmhdr.Strings([]string{"hello", "greeting"}))
	h.Add(tag.PROVIDEFLAGS, rpmhdr.Integers([]uint32{8, 0}))
	h.Add(tag.PROVIDEVERSION, rpmhdr.Strings([]string{"4:1.2-3", ""}))
	h.Add(tag.DIRNAMES, rpmhdr.Strings([]string{"/usr/bin/"}))
	h.Add(tag.BASENAMES, rpmhdr.Strings([]string{"hello", "hi"}))
	h.Add(tag.DIRINDEXES, rpmhdr.Integers([]uint32{0, 0}))
	h.Add(tag.FILEMODES, rpmhdr.Integers([]uint16{0o100755, 0o120777}))
	h.Add(tag.FILESIZES, rpmhdr.Integers([]uint32{1234, 5}))
	h.Add(tag.FILEUSERNAME, rpmhdr.Strings([]string{"root", "bin"}))
	h.Add(tag.FILEGROUPNAME, rpmhdr.Strings([]string{"root", "wheel"}))
	h.Add(tag.FILELINKTOS, rpmhdr.Strings([]string{"", "hello"}))

	if withArch {
		h.Add(tag.ARCH, rpmhdr.String("noarch"))
	}

	b, err := h.Bytes()
	require.NoError(t, err)

	return b[8:]
}

func TestReadHeaderBlobInstalledPackage(t *testing.T) {
	hdr, err := ReadHeaderBlob(installedBlob(t, true), HeaderLimits{})
	require.NoError(t, err)

	pkg, err := hdr.InstalledPackage(PackageLimits{})
	require.NoError(t, err)

	assert.Equal(t, "hello", pkg.Name)
	assert.EqualValues(t, 4, pkg.Epoch)
	assert.Equal(t, "1.2", pkg.Version)
	assert.Equal(t, "3", pkg.Release)
	assert.Equal(t, "noarch", pkg.Arch)
	assert.EqualValues(t, 1700000000, pkg.InstallTime)
	assert.Equal(t, []Dependency{
		{Name: "hello", Flags: tag.RPMSENSE_EQUAL, Version: "1.2-3", Epoch: 4},
		{Name: "greeting"},
	}, pkg.Provides)

	require.Len(t, pkg.Files, 2)
	assert.Equal(t, FileEntry{
		Path: "/usr/bin/hello", Mode: 0o100755, Size: 1234, User: "root", Group: "root",
	}, pkg.Files[0])
	assert.Equal(t, FileEntry{
		Path: "/usr/bin/hi", Mode: 0o120777, Size: 5, User: "bin", Group: "wheel", LinkTo: "hello",
	}, pkg.Files[1])

	// The same header read as a package file keeps its identity rules.
	pkg, err = hdr.Package(PackageLimits{})
	require.NoError(t, err)
	assert.Equal(t, "hello", pkg.Name)
}

func TestInstalledPackageWithoutArch(t *testing.T) {
	hdr, err := ReadHeaderBlob(installedBlob(t, false), HeaderLimits{})
	require.NoError(t, err)

	pkg, err := hdr.InstalledPackage(PackageLimits{})
	require.NoError(t, err)
	assert.Empty(t, pkg.Arch)

	_, err = hdr.Package(PackageLimits{})
	require.ErrorIs(t, err, ErrInvalidHeader)
}

func TestReadHeaderBlobRejects(t *testing.T) {
	good := installedBlob(t, true)

	for name, blob := range map[string][]byte{
		"empty":       nil,
		"short":       good[:7],
		"truncated":   good[:len(good)-1],
		"index only":  good[:8+16],
		"huge counts": {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		_, err := ReadHeaderBlob(blob, HeaderLimits{})
		require.Error(t, err, name)
	}

	_, err := ReadHeaderBlob(good, HeaderLimits{MaxDataSize: 10})
	require.ErrorIs(t, err, ErrHeaderTooLarge)

	_, err = ReadHeaderBlob(good, HeaderLimits{MaxEntries: 2})
	require.ErrorIs(t, err, ErrHeaderTooLarge)
}

func TestFileEntryCostCountsOwners(t *testing.T) {
	hdr, err := ReadHeaderBlob(installedBlob(t, true), HeaderLimits{})
	require.NoError(t, err)

	pkg, err := hdr.InstalledPackage(PackageLimits{MaxFileListBytes: 1})
	require.NoError(t, err)
	assert.True(t, pkg.FilesTruncated)
	assert.Empty(t, pkg.Files)
}

// FuzzReadHeaderBlob runs the header image decoder, and the package built
// from it, over arbitrary bytes: an error or a package, never a panic or an
// allocation out of proportion.
func FuzzReadHeaderBlob(f *testing.F) {
	f.Add(installedBlob(f, true))
	f.Add(installedBlob(f, false))
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 4})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, blob []byte) {
		hdr, err := ReadHeaderBlob(blob, HeaderLimits{MaxDataSize: 1 << 20})
		if err != nil {
			return
		}

		_, _ = hdr.InstalledPackage(PackageLimits{MaxArrayEntries: 1000, MaxFileListBytes: 1 << 16})
		_, _ = hdr.GetStrings(tag.PROVIDENAME)
	})
}
