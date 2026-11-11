package rpm

import (
	"bytes"
	"os"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// FuzzReadPackage feeds arbitrary bytes to the package reader; it must return
// an error or a package, never panic or allocate without bound.
func FuzzReadPackage(f *testing.F) {
	full := fullPackage(f)

	f.Add(full)
	f.Add(full[:LeadSize])
	f.Add(full[:len(full)/2])
	f.Add(validLead())
	f.Add([]byte{})
	addSeedRPMs(f)

	// Amplification shapes: many declared array elements, an over-long
	// dependency list.
	var bomb craft

	bomb.identity()
	bomb.strArray(tag.DIRNAMES, 1, []byte("/\x00"))
	bomb.strArray(tag.BASENAMES, 1<<16, emptyStrings(1<<16))
	f.Add(bomb.rpmBytes(f))

	var deps craft

	deps.identity()
	deps.strArray(tag.REQUIRENAME, MaxArrayEntries+1, emptyStrings(MaxArrayEntries+1))
	f.Add(deps.rpmBytes(f))

	f.Fuzz(func(_ *testing.T, data []byte) {
		pkg, err := ReadPackageLimits(bytes.NewReader(data), PackageLimits{Header: HeaderLimits{MaxDataSize: 1 << 20}})
		if err != nil {
			return
		}

		_ = pkg.Name
	})
}

// FuzzReadRawHeader exercises the header index and data parser and its tag
// getters on a bare header.
func FuzzReadRawHeader(f *testing.F) {
	var c craft

	c.identity()
	c.strArray(tag.REQUIRENAME, 2, []byte("a\x00b\x00"))
	c.int32s(tag.REQUIREFLAGS, 8, 8)
	f.Add(rawHeader(f, c.tags, c.data.Bytes()))
	f.Add([]byte{0x8E, 0xAD, 0xE8, 0x01, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		h, err := readHeader(bytes.NewReader(data), "", 0, false, false, HeaderLimits{MaxDataSize: 1 << 16})
		if err != nil {
			return
		}

		for id := range h.entries {
			_, _ = h.GetStrings(id)
			_, _ = h.GetUint32s(id)
			_, _ = h.GetUint64s(id)
			_, _ = h.stringsPrefix(id, 8)
			_, _ = h.numbersPrefix(id, 8)
		}

		_, _ = h.dependencies(tag.REQUIRENAME, tag.REQUIREFLAGS, tag.REQUIREVERSION, 16)
		_, _ = h.files(PackageLimits{MaxArrayEntries: 16, MaxFileListBytes: 1 << 10}, h)
		_ = h.changelogs(16)
		_ = h.scripts()
		_, _ = h.triggers(16)
		_, _ = h.fileTriggers(16)
		_ = h.payloadDigests()
		_ = h.policies(16)
	})
}

func benchFixture(b *testing.B) []byte {
	b.Helper()

	data, err := os.ReadFile("testdata/weakdeps.rpm")
	if err != nil {
		b.Fatal(err)
	}

	return data
}

// BenchmarkReadPackage measures the lead, both headers and the Package
// construction from an in-memory RPM.
func BenchmarkReadPackage(b *testing.B) {
	data := benchFixture(b)

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))

	for b.Loop() {
		if _, err := ReadPackage(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReadHeader isolates the header parse of ReadPackage.
func BenchmarkReadHeader(b *testing.B) {
	data := benchFixture(b)

	b.ReportAllocs()

	for b.Loop() {
		if _, err := ReadHeader(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}
