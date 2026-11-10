package rpm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/M0Rf30/pkgformat/rpm/tag"
	"github.com/stretchr/testify/require"
)

// validLead returns the lead of a binary package of format 4.
func validLead() []byte {
	buf := make([]byte, LeadSize)
	binary.BigEndian.PutUint32(buf[0:4], LeadMagic)
	buf[4] = 3
	binary.BigEndian.PutUint16(buf[8:10], 1)
	copy(buf[10:76], "test-package-1.0-1.x86_64.rpm")
	binary.BigEndian.PutUint16(buf[76:78], 1)
	binary.BigEndian.PutUint16(buf[78:80], 5)

	return buf
}

// craft assembles the general header of a package entry by entry.
type craft struct {
	tags []headerTag
	data bytes.Buffer
}

func (c *craft) align4() {
	for c.data.Len()%4 != 0 {
		c.data.WriteByte(0)
	}
}

func (c *craft) str(id int32, v string) {
	c.tags = append(c.tags, headerTag{Tag: id, DataType: tag.RPM_STRING_TYPE, Offset: int32(c.data.Len()), Count: 1})
	c.data.WriteString(v)
	c.data.WriteByte(0)
}

// strArray stores raw NUL terminated strings but declares count of them.
func (c *craft) strArray(id, count int32, raw []byte) {
	c.tags = append(c.tags, headerTag{Tag: id, DataType: tag.RPM_STRING_ARRAY_TYPE, Offset: int32(c.data.Len()), Count: count})
	c.data.Write(raw)
}

func (c *craft) int32s(id int32, vals ...uint32) {
	c.align4()
	c.tags = append(c.tags, headerTag{Tag: id, DataType: tag.RPM_INT32_TYPE, Offset: int32(c.data.Len()), Count: int32(len(vals))})

	for _, v := range vals {
		_ = binary.Write(&c.data, binary.BigEndian, v)
	}
}

func (c *craft) identity() {
	c.str(tag.NAME, "bomb")
	c.str(tag.VERSION, "1")
	c.str(tag.RELEASE, "1")
	c.str(tag.ARCH, "noarch")
}

// rpmBytes returns the lead, an empty signature header and the crafted
// general header.
func (c *craft) rpmBytes(t testing.TB) []byte {
	var buf bytes.Buffer

	buf.Write(validLead())

	sig := rawHeader(t, nil, nil)
	buf.Write(sig)
	buf.Write(make([]byte, (8-len(sig)%8)%8))
	buf.Write(rawHeader(t, c.tags, c.data.Bytes()))

	return buf.Bytes()
}

func rawHeader(t testing.TB, tags []headerTag, data []byte) []byte {
	t.Helper()

	var b bytes.Buffer

	require.NoError(t, binary.Write(&b, binary.BigEndian, headerIntro{Magic: 0x8eade801, Entries: uint32(len(tags)), Size: uint32(len(data))}))

	for i := range tags {
		require.NoError(t, binary.Write(&b, binary.BigEndian, &tags[i]))
	}

	b.Write(data)

	return b.Bytes()
}

// emptyStrings is n NUL bytes: n empty strings.
func emptyStrings(n int) []byte { return make([]byte, n) }

func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)

	return after.TotalAlloc - before.TotalAlloc
}

// fullPackage is a small package with a signature header, identity tags, an
// epoch, a build time and sizes.
func fullPackage(t testing.TB) []byte {
	var c craft

	c.str(tag.NAME, "test-pkg")
	c.str(tag.VERSION, "1.0")
	c.str(tag.RELEASE, "1.el9")
	c.str(tag.SUMMARY, "A test package")
	c.int32s(tag.EPOCH, 2)
	c.int32s(tag.BUILDTIME, 1700000000)
	c.int32s(tag.SIZE, 200000)
	c.str(tag.ARCH, "x86_64")

	var buf bytes.Buffer

	buf.Write(validLead())

	sig := rawHeader(t, []headerTag{{Tag: 1000, DataType: tag.RPM_STRING_TYPE, Count: 1}}, []byte("abcdef1234\x00"))
	buf.Write(sig)
	buf.Write(make([]byte, (8-len(sig)%8)%8))
	buf.Write(rawHeader(t, c.tags, c.data.Bytes()))

	return buf.Bytes()
}

func TestReadPackageFull(t *testing.T) {
	data := fullPackage(t)

	pkg, err := ReadPackage(bytes.NewReader(data))
	require.NoError(t, err)
	require.Equal(t, "test-pkg", pkg.Name)
	require.Equal(t, "1.0", pkg.Version)
	require.Equal(t, "1.el9", pkg.Release)
	require.Equal(t, "x86_64", pkg.Arch)
	require.Equal(t, "A test package", pkg.Summary)
	require.Equal(t, uint32(2), pkg.Epoch)
	require.EqualValues(t, 1700000000, pkg.BuildTime)
	require.EqualValues(t, 200000, pkg.InstalledSize)
	require.Zero(t, pkg.PackageSize)
	// the signature header is 43 bytes, padded to 48
	require.EqualValues(t, LeadSize+48, pkg.HeaderStart)
	require.Greater(t, pkg.HeaderEnd, pkg.HeaderStart)
}

func TestReadPackageHeaderRange(t *testing.T) {
	for _, fx := range []string{"testdata/weakdeps.rpm", "testdata/sizes-v4.rpm", "testdata/sizes-v6.rpm", "testdata/simple-1.0.1-1.i386.rpm"} {
		t.Run(fx, func(t *testing.T) {
			data, err := os.ReadFile(fx)
			require.NoError(t, err)

			pkg, err := ReadPackage(bytes.NewReader(data))
			require.NoError(t, err)

			hdr, err := ReadHeader(bytes.NewReader(data))
			require.NoError(t, err)

			r := hdr.GetRange()
			require.EqualValues(t, r.Start, pkg.HeaderStart)
			require.EqualValues(t, r.End, pkg.HeaderEnd)
		})
	}
}

func TestReadPackageRejectsBadInput(t *testing.T) {
	bad := make([]byte, LeadSize)
	binary.BigEndian.PutUint32(bad[0:4], 0xDEADBEEF)

	_, err := ReadPackage(bytes.NewReader(bad))
	require.ErrorIs(t, err, ErrNotRPM)

	_, err = ReadPackage(bytes.NewReader([]byte{0xED, 0xAB}))
	require.ErrorIs(t, err, ErrNotRPM)

	old := validLead()
	old[4] = 2
	_, err = ReadPackage(bytes.NewReader(old))
	require.ErrorIs(t, err, ErrUnsupportedVersion)

	var c craft
	c.identity()
	c.tags[0].Offset = 1 << 20

	_, err = ReadPackage(bytes.NewReader(c.rpmBytes(t)))
	require.ErrorIs(t, err, ErrInvalidHeader)
}

func TestParseLead(t *testing.T) {
	lead, err := ParseLead(bytes.NewReader(validLead()))
	require.NoError(t, err)
	require.Equal(t, uint8(3), lead.MajorVersion)
	require.Equal(t, uint8(0), lead.MinorVersion)
	require.Equal(t, uint16(1), lead.Arch)
	require.Equal(t, uint16(5), lead.SignatureType)
	require.Equal(t, "test-package-1.0-1.x86_64.rpm", lead.Name)

	v4 := validLead()
	v4[4] = 4
	lead, err = ParseLead(bytes.NewReader(v4))
	require.NoError(t, err)
	require.Equal(t, uint8(4), lead.MajorVersion)

	_, err = ParseLead(bytes.NewReader([]byte{0xED, 0xAB, 0xEE}))
	require.ErrorIs(t, err, ErrNotRPM)
}

func TestHeaderLead(t *testing.T) {
	hdr, err := ReadHeader(bytes.NewReader(fullPackage(t)))
	require.NoError(t, err)
	require.Equal(t, "test-package-1.0-1.x86_64.rpm", hdr.Lead().Name)
}

func TestIdentityValidation(t *testing.T) {
	ok := Package{Name: "foo", Version: "1.0", Release: "1.el9", Arch: "x86_64"}
	require.NoError(t, ok.validateIdentity())

	for _, bad := range []string{"", "..", ".", "a/b", "a\\b", "a\x00b", "a b", "a\tb"} {
		for field := range 4 {
			p := ok
			switch field {
			case 0:
				p.Name = bad
			case 1:
				p.Version = bad
			case 2:
				p.Release = bad
			case 3:
				p.Arch = bad
			}

			require.ErrorIs(t, p.validateIdentity(), ErrInvalidHeader, "field %d value %q", field, bad)
		}
	}
}

func TestPackageWeakDependencies(t *testing.T) {
	f, err := os.Open("testdata/weakdeps.rpm")
	require.NoError(t, err)

	defer f.Close()

	pkg, err := ReadPackage(f)
	require.NoError(t, err)

	byName := func(deps []Dependency, name string) (Dependency, bool) {
		for _, d := range deps {
			if d.Name == name {
				return d, true
			}
		}

		return Dependency{}, false
	}

	for name, deps := range map[string][]Dependency{
		"recommended-pkg":  pkg.Recommends,
		"suggested-pkg":    pkg.Suggests,
		"supplemented-pkg": pkg.Supplements,
		"enhanced-pkg":     pkg.Enhances,
	} {
		_, ok := byName(deps, name)
		require.True(t, ok, "dependency %q missing from %v", name, deps)
	}

	sug, _ := byName(pkg.Suggests, "suggested-pkg")
	require.Equal(t, "GE", SenseFlagsString(sug.Flags))
	require.Equal(t, "1.0", sug.Version)

	_, ok := byName(pkg.Conflicts, "conflicting-pkg")
	require.True(t, ok, "conflicts missing")

	_, ok = byName(pkg.Obsoletes, "old-pkg")
	require.True(t, ok, "obsoletes missing")
}

// Both fixtures are built from testdata/sizes.spec by rpmbuild 6.0.1, once as
// a format 4 package (sizes in the signature header) and once as format 6
// (sizes in the general header).
type sizeFixture struct {
	file          string
	wantInstalled int64
	wantArchive   int64
}

func sizeFixtures() []sizeFixture {
	return []sizeFixture{
		{"testdata/sizes-v4.rpm", 100012, 100704},
		{"testdata/sizes-v6.rpm", 100012, 100204},
	}
}

func TestReadPackageSizes(t *testing.T) {
	for _, fx := range sizeFixtures() {
		t.Run(fx.file, func(t *testing.T) {
			data, err := os.ReadFile(fx.file)
			require.NoError(t, err)

			pkg, err := ReadPackage(bytes.NewReader(data))
			require.NoError(t, err)
			require.Equal(t, fx.wantInstalled, pkg.InstalledSize)
			require.Equal(t, fx.wantArchive, pkg.ArchiveSize)
			// The file size is not a header tag: the caller sets it.
			require.Zero(t, pkg.PackageSize)
		})
	}
}

func rpmQuery(t *testing.T, rpmBin, file, format string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, rpmBin, "-qp", "--queryformat", format, file).CombinedOutput()
	require.NoError(t, err, string(out))

	return string(out)
}

// TestPackageMatchesRPMClient compares the reader with what the rpm client
// reports for the same files.
func TestPackageMatchesRPMClient(t *testing.T) {
	rpmBin, err := exec.LookPath("rpm")
	if err != nil {
		t.Skip("rpm not installed")
	}

	for _, fx := range sizeFixtures() {
		t.Run(fx.file, func(t *testing.T) {
			data, err := os.ReadFile(fx.file)
			require.NoError(t, err)

			pkg, err := ReadPackage(bytes.NewReader(data))
			require.NoError(t, err)

			installed, err := strconv.ParseInt(rpmQuery(t, rpmBin, fx.file, "%{LONGSIZE}"), 10, 64)
			require.NoError(t, err)
			require.Equal(t, installed, pkg.InstalledSize)

			// ARCHIVESIZE exists for format 4; rpm 6 packages expose the
			// uncompressed payload size as PAYLOADSIZEALT instead.
			archiveStr := rpmQuery(t, rpmBin, fx.file, "%{ARCHIVESIZE}")
			if strings.Contains(archiveStr, "none") {
				archiveStr = rpmQuery(t, rpmBin, fx.file, "%{PAYLOADSIZEALT}")
			}

			archive, err := strconv.ParseInt(archiveStr, 10, 64)
			if err != nil {
				t.Skipf("this rpm does not expose an archive size tag (%q)", archiveStr)
			}

			require.Equal(t, archive, pkg.ArchiveSize)

			files := strings.Fields(rpmQuery(t, rpmBin, fx.file, "[%{FILENAMES} ]"))
			require.Len(t, pkg.Files, len(files))

			for i, f := range pkg.Files {
				require.Equal(t, files[i], f.Path)
			}
		})
	}
}

func TestPackageFilesJoinDirAndBase(t *testing.T) {
	var c craft

	c.identity()
	c.strArray(tag.DIRNAMES, 1, []byte("/usr/bin/\x00"))
	c.strArray(tag.BASENAMES, 2, []byte("foo\x00bar\x00"))
	c.int32s(tag.DIRINDEXES, 0, 0)

	pkg, err := ReadPackage(bytes.NewReader(c.rpmBytes(t)))
	require.NoError(t, err)
	require.Len(t, pkg.Files, 2)
	require.Equal(t, "/usr/bin/foo", pkg.Files[0].Path)
	require.Equal(t, "/usr/bin/bar", pkg.Files[1].Path)
	require.False(t, pkg.FilesTruncated)
}

func TestPackageChangelog(t *testing.T) {
	var c craft

	c.identity()
	c.int32s(tag.CHANGELOGTIME, 1700000000, 1600000000)
	c.strArray(tag.CHANGELOGNAME, 1, []byte("someone <a@b>\x00"))
	c.strArray(tag.CHANGELOGTEXT, 2, []byte("- first\x00- second\x00"))

	pkg, err := ReadPackage(bytes.NewReader(c.rpmBytes(t)))
	require.NoError(t, err)
	require.Equal(t, []ChangelogEntry{
		{Time: 1700000000, Author: "someone <a@b>", Description: "- first"},
		{Time: 1600000000, Description: "- second"},
	}, pkg.Changelogs)
}

func TestTagConstantsMatchRPM(t *testing.T) {
	for name, v := range map[string][2]int{
		"REQUIREVERSION": {tag.REQUIREVERSION, 1050}, "CONFLICTVERSION": {tag.CONFLICTVERSION, 1055},
		"OBSOLETEFLAGS": {tag.OBSOLETEFLAGS, 1114}, "OBSOLETEVERSION": {tag.OBSOLETEVERSION, 1115},
		"FILEDIGESTS": {tag.FILEDIGESTS, 1035}, "BASENAMES": {tag.BASENAMES, 1117},
		"DIRNAMES": {tag.DIRNAMES, 1118}, "DIRINDEXES": {tag.DIRINDEXES, 1116},
		"SUGGESTNAME": {tag.SUGGESTNAME, 5049}, "SUPPLEMENTNAME": {tag.SUPPLEMENTNAME, 5052},
		"ENHANCENAME": {tag.ENHANCENAME, 5055}, "PROVIDENAME": {tag.PROVIDENAME, 1047},
	} {
		require.Equal(t, v[1], v[0], name)
	}
}

func TestNumbersPrefix(t *testing.T) {
	var c craft

	c.int32s(1, 0xFFFFFFFE)
	c.tags = append(c.tags, headerTag{Tag: 2, DataType: tag.RPM_INT64_TYPE, Offset: int32(c.data.Len()), Count: 1})
	c.data.Write([]byte{0, 0, 0, 1, 0, 0, 0, 0})

	hdr, err := readHeader(bytes.NewReader(rawHeader(t, c.tags, c.data.Bytes())), "", 0, false, false, HeaderLimits{})
	require.NoError(t, err)

	vals, n := hdr.numbersPrefix(1, 10)
	require.Equal(t, []uint64{0xFFFFFFFE}, vals)
	require.Equal(t, 1, n)

	vals, _ = hdr.numbersPrefix(2, 10)
	require.Equal(t, []uint64{1 << 32}, vals)

	vals, n = hdr.numbersPrefix(99, 10)
	require.Nil(t, vals)
	require.Zero(t, n)
}

// The documented limits, spelled out so a test run cannot pass by raising a
// constant.
func TestLimitConstants(t *testing.T) {
	require.Equal(t, 0xffff, MaxHeaderEntries)
	require.Equal(t, 100_000, MaxArrayEntries)
	require.Equal(t, 16<<20, MaxFileListBytes)
	require.Equal(t, 1<<24, MaxPackageHeaderDataSize)
	require.Equal(t, 0x0fffffff, MaxHeaderDataSize)
}

func TestReadHeaderLimitsRejectsExcessIndexEntries(t *testing.T) {
	// Only the intro is provided: the limit must trip before any entry is read.
	for _, lim := range []HeaderLimits{{}, {MaxEntries: MaxHeaderEntries}, {MaxEntries: 1 << 30}} {
		raw := append(validLead(), introOnly(MaxHeaderEntries+1, 0)...)
		_, err := ReadHeaderLimits(bytes.NewReader(raw), lim)
		require.ErrorIs(t, err, ErrHeaderTooLarge, "%+v", lim)
	}
}

func TestReadPackageDefaultsDataLimit(t *testing.T) {
	var buf bytes.Buffer

	buf.Write(validLead())

	sig := rawHeader(t, nil, nil)
	buf.Write(sig)
	buf.Write(make([]byte, (8-len(sig)%8)%8))
	buf.Write(introOnly(0, MaxPackageHeaderDataSize+1))

	_, err := ReadPackage(&buf)
	require.ErrorIs(t, err, ErrHeaderTooLarge)
}

func TestReadPackageBoundsHugeFileList(t *testing.T) {
	const declared = 1 << 21 // 2M one-byte entries in a 2 MiB store

	var c craft

	c.identity()
	c.strArray(tag.DIRNAMES, 1, []byte("/\x00"))
	c.strArray(tag.BASENAMES, declared, emptyStrings(declared))

	data := c.rpmBytes(t)

	var pkg *Package

	alloc := allocatedBy(func() {
		var err error

		pkg, err = ReadPackage(bytes.NewReader(data))
		require.NoError(t, err)
	})

	require.LessOrEqual(t, len(pkg.Files), MaxArrayEntries)
	require.True(t, pkg.FilesTruncated)
	require.Less(t, alloc, uint64(256<<20), "parsing a %d-byte package allocated %d MiB", len(data), alloc>>20)
}

// A header that fills the whole data store with empty basenames is the worst
// case: 16.7M entries, ~11 GB before the cap.
func TestReadPackageBoundsMaxSizedFileList(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a 16 MiB header")
	}

	var c craft

	c.identity()
	c.strArray(tag.DIRNAMES, 1, []byte("/\x00"))

	// The store must stay below the data limit once the identity strings are in.
	n := MaxPackageHeaderDataSize - 64 - c.data.Len()
	c.strArray(tag.BASENAMES, int32(n), emptyStrings(n))

	data := c.rpmBytes(t)

	alloc := allocatedBy(func() {
		pkg, err := ReadPackage(bytes.NewReader(data))
		require.NoError(t, err)
		require.Len(t, pkg.Files, MaxArrayEntries)
		require.True(t, pkg.FilesTruncated)
	})

	require.Less(t, alloc, uint64(512<<20), "allocated %d MiB", alloc>>20)
}

// Every file shares one huge dirname; the entry count alone would let
// len(files) * len(dirname) bytes be materialised.
func TestReadPackageBoundsExpandedPathBytes(t *testing.T) {
	const (
		dirLen = 256 << 10
		nFiles = 2000
	)

	dir := append(bytes.Repeat([]byte("d"), dirLen-1), '/', 0)

	var c craft

	c.identity()
	c.strArray(tag.DIRNAMES, 1, dir)
	c.strArray(tag.BASENAMES, nFiles, bytes.Repeat([]byte("f\x00"), nFiles))
	c.int32s(tag.DIRINDEXES, make([]uint32, nFiles)...)

	pkg, err := ReadPackage(bytes.NewReader(c.rpmBytes(t)))
	require.NoError(t, err)

	total := 0
	for _, f := range pkg.Files {
		total += len(f.Path)
	}

	require.LessOrEqual(t, total, MaxFileListBytes)
	require.Less(t, len(pkg.Files), nFiles)
	require.True(t, pkg.FilesTruncated)
}

// The same shape through the spliced OLDFILENAMES view of the generic reader.
func TestGetStringsOldFilenamesBoundsExpandedPathBytes(t *testing.T) {
	const (
		dirLen = 4 << 20
		nFiles = 100
	)

	dir := append(bytes.Repeat([]byte("d"), dirLen-1), '/', 0)

	var c craft

	c.strArray(tag.DIRNAMES, 1, dir)
	c.strArray(tag.BASENAMES, nFiles, bytes.Repeat([]byte("f\x00"), nFiles))
	c.int32s(tag.DIRINDEXES, make([]uint32, nFiles)...)

	hdr, err := readHeader(bytes.NewReader(rawHeader(t, c.tags, c.data.Bytes())), "", 0, false, false, HeaderLimits{})
	require.NoError(t, err)

	alloc := allocatedBy(func() {
		_, err = hdr.GetStrings(tag.OLDFILENAMES)
	})
	require.ErrorIs(t, err, ErrHeaderTooLarge)
	require.Less(t, alloc, uint64(1<<30))
}

func TestReadPackageRejectsOversizedDependencyList(t *testing.T) {
	const declared = MaxArrayEntries + 1

	var c craft

	c.identity()
	c.strArray(tag.REQUIRENAME, declared, emptyStrings(declared))

	_, err := ReadPackage(bytes.NewReader(c.rpmBytes(t)))
	require.ErrorIs(t, err, ErrHeaderTooLarge)
}

func TestReadPackageLimitsCustom(t *testing.T) {
	var c craft

	c.identity()
	c.strArray(tag.BASENAMES, 10, emptyStrings(10))
	c.strArray(tag.DIRNAMES, 1, []byte("/\x00"))
	c.int32s(tag.DIRINDEXES, make([]uint32, 10)...)

	pkg, err := ReadPackageLimits(bytes.NewReader(c.rpmBytes(t)), PackageLimits{MaxArrayEntries: 4})
	require.NoError(t, err)
	require.Len(t, pkg.Files, 4)
	require.True(t, pkg.FilesTruncated)

	var d craft

	d.identity()
	d.strArray(tag.REQUIRENAME, 5, []byte("a\x00b\x00c\x00d\x00e\x00"))

	_, err = ReadPackageLimits(bytes.NewReader(d.rpmBytes(t)), PackageLimits{MaxArrayEntries: 4})
	require.ErrorIs(t, err, ErrHeaderTooLarge)
}

func TestReadPackageRejectsExcessIndexEntries(t *testing.T) {
	var buf bytes.Buffer

	buf.Write(validLead())

	sig := rawHeader(t, nil, nil)
	buf.Write(sig)
	buf.Write(make([]byte, (8-len(sig)%8)%8))
	// The general header claims 1M index entries.
	buf.Write(introOnly(1<<20, 0))

	_, err := ReadPackage(&buf)
	require.ErrorIs(t, err, ErrHeaderTooLarge)
}

func TestSenseFlagsString(t *testing.T) {
	for _, tt := range []struct {
		flags uint32
		want  string
	}{
		{tag.RPMSENSE_EQUAL, "EQ"},
		{tag.RPMSENSE_LESS, "LT"},
		{tag.RPMSENSE_GREATER, "GT"},
		{tag.RPMSENSE_LESS | tag.RPMSENSE_EQUAL, "LE"},
		{tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL, "GE"},
		{tag.RPMSENSE_ANY, ""},
		{tag.RPMSENSE_LESS | tag.RPMSENSE_GREATER, ""},
		{tag.RPMSENSE_RPMLIB, ""},
	} {
		require.Equal(t, tt.want, SenseFlagsString(tt.flags), "%#x", tt.flags)
	}
}

func TestDependencyPredicates(t *testing.T) {
	require.True(t, Dependency{Flags: tag.RPMSENSE_RPMLIB}.IsRPMLib())
	require.True(t, Dependency{Flags: tag.RPMSENSE_SCRIPT_PRE}.IsPre())
	require.True(t, Dependency{Flags: tag.RPMSENSE_PREREQ}.IsPre())
	require.False(t, Dependency{Flags: tag.RPMSENSE_EQUAL}.IsPre())
	require.True(t, Dependency{Flags: tag.RPMSENSE_EQUAL}.Versioned())
	require.False(t, Dependency{}.Versioned())
}

func TestSplitVersionRelease(t *testing.T) {
	v, r := SplitVersionRelease("1.2-3.el9")
	require.Equal(t, "1.2", v)
	require.Equal(t, "3.el9", r)

	v, r = SplitVersionRelease("1.2")
	require.Equal(t, "1.2", v)
	require.Empty(t, r)
}

func TestHeaderDependencies(t *testing.T) {
	var c craft

	c.strArray(tag.REQUIRENAME, 2, []byte("libc\x00libssl\x00"))
	c.int32s(tag.REQUIREFLAGS, tag.RPMSENSE_GREATER|tag.RPMSENSE_EQUAL, tag.RPMSENSE_EQUAL)
	c.strArray(tag.REQUIREVERSION, 2, []byte("2.31\x001:1.1.1\x00"))

	hdr, err := ReadHeader(bytes.NewReader(append(append(validLead(), rawHeader(t, nil, nil)...), append(make([]byte, 0), rawHeader(t, c.tags, c.data.Bytes())...)...)))
	require.NoError(t, err)

	deps, err := hdr.Dependencies(tag.REQUIRENAME, tag.REQUIREFLAGS, tag.REQUIREVERSION)
	require.NoError(t, err)
	require.Equal(t, []Dependency{
		{Name: "libc", Flags: tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL, Version: "2.31"},
		{Name: "libssl", Flags: tag.RPMSENSE_EQUAL, Version: "1.1.1", Epoch: 1},
	}, deps)

	deps, err = hdr.Dependencies(tag.CONFLICTNAME, tag.CONFLICTFLAGS, tag.CONFLICTVERSION)
	require.NoError(t, err)
	require.Nil(t, deps)
}

func TestSplitEpoch(t *testing.T) {
	for _, tt := range []struct {
		in      string
		epoch   uint32
		version string
	}{
		{"1:1.2.3", 1, "1.2.3"},
		{"2:3.0.0", 2, "3.0.0"},
		{"1.0.0", 0, "1.0.0"},
		{"0:1.0", 0, "1.0"},
		{"x:1.0", 0, "x:1.0"},
	} {
		e, v := splitEpoch(tt.in)
		require.Equal(t, tt.epoch, e, tt.in)
		require.Equal(t, tt.version, v, tt.in)
	}
}

func TestReadPackageNeverPanicsOnGarbledHeaders(t *testing.T) {
	var c craft

	c.identity()
	c.strArray(tag.REQUIRENAME, 3, []byte("a\x00b\x00")) // fewer strings than declared
	c.tags = append(c.tags, headerTag{Tag: tag.REQUIREFLAGS, DataType: tag.RPM_STRING_TYPE, Offset: 0, Count: 1})

	require.NotPanics(t, func() {
		_, err := ReadPackage(bytes.NewReader(c.rpmBytes(t)))
		if err != nil && !errors.Is(err, ErrInvalidHeader) {
			t.Fatal(err)
		}
	})
}
