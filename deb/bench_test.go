package deb_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/deb"
)

func benchDeb(b *testing.B) []byte {
	b.Helper()

	var buf bytes.Buffer

	spec := &deb.Spec{
		Name: "bench", Version: "1.0", Release: "1", Architecture: "amd64", Maintainer: "Bench <b@example.org>",
		Description: "Benchmark package\nwith a longer description", Depends: rels("libc6 (>= 2.31)", "bash"),
		Compression: "gzip",
	}

	if err := deb.Write(&buf, spec, []deb.Entry{{Path: "usr/bin/bench", Mode: 0o755, Data: bytes.Repeat([]byte("x"), 4096)}}, deb.WriteOptions{TempDir: b.TempDir()}); err != nil {
		b.Fatal(err)
	}

	return buf.Bytes()
}

const benchControl = "Package: bench\nVersion: 1:1.0-1\nArchitecture: amd64\nMaintainer: Bench <b@example.org>\nInstalled-Size: 120\n" +
	"Depends: libc6 (>= 2.31), libssl3 (>= 3.0), zlib1g\nSection: utils\nPriority: optional\nHomepage: https://example.org\n" +
	"Description: Benchmark package\n with a longer description\n .\n and a second paragraph\n"

func BenchmarkParseControlFile(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		if _, err := deb.ParseControlFile(strings.NewReader(benchControl)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParsePackage(b *testing.B) {
	cf, err := deb.ParseControlFile(strings.NewReader(benchControl))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := cf.ParsePackage(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseDebFile(b *testing.B) {
	raw := benchDeb(b)

	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))

	for b.Loop() {
		if _, err := deb.ParseDebFileAt(bytes.NewReader(raw), int64(len(raw))); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWrite(b *testing.B) {
	spec := testSpec()
	payload := testPayload()
	opts := deb.WriteOptions{TempDir: b.TempDir()}

	b.ReportAllocs()

	for b.Loop() {
		var buf bytes.Buffer

		if err := deb.Write(&buf, spec, payload, opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompareVersions(b *testing.B) {
	for b.Loop() {
		deb.CompareVersions("1:2.30.1-1ubuntu3~bpo20.04.1", "1:2.30.1-1ubuntu3~bpo20.04.2")
	}
}

func BenchmarkParseRelations(b *testing.B) {
	const in = "libc6 (>= 2.31), libssl3 (>= 3.0) | libssl1.1, zlib1g, python3:any (<< 3.12), bash"

	b.ReportAllocs()

	for b.Loop() {
		if _, err := deb.ParseRelations(in); err != nil {
			b.Fatal(err)
		}
	}
}

func benchEntry(i int) deb.IndexEntry {
	return deb.IndexEntry{
		Name: fmt.Sprintf("pkg%d", i), Version: "1.0-1", Arch: "amd64", Filename: deb.PoolPath("main", fmt.Sprintf("pkg%d", i), fmt.Sprintf("pkg%d_1.0-1_amd64.deb", i)),
		Size: 1024, InstalledSize: 4, SHA256: strings.Repeat("ab", 32),
		Control: map[string]string{"Depends": "libc6 (>= 2.31)", "Maintainer": "A <a@b>", "Description": "synopsis\nlong text"},
	}
}

func BenchmarkFormatPackagesEntry(b *testing.B) {
	e := benchEntry(1)

	b.ReportAllocs()

	for b.Loop() {
		_ = deb.FormatPackagesEntry(e)
	}
}

func BenchmarkIndexBytes(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		var ix deb.Index

		for i := range 1000 {
			ix.Add(benchEntry(i))
		}

		_ = ix.Bytes()
	}
}

func BenchmarkIndexCompressed(b *testing.B) {
	var ix deb.Index

	for i := range 1000 {
		ix.Add(benchEntry(i))
	}

	for _, c := range []deb.Compression{deb.CompressionGzip, deb.CompressionXZ, deb.CompressionZstd} {
		b.Run(c.Extension(), func(b *testing.B) {
			b.SetBytes(int64(len(ix.Bytes())))

			for b.Loop() {
				if _, err := ix.Compressed(c); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkScanPackages(b *testing.B) {
	var ix deb.Index

	for i := range 1000 {
		ix.Add(benchEntry(i))
	}

	raw := ix.Bytes()

	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))

	for b.Loop() {
		if err := deb.ScanPackages(bytes.NewReader(raw), func(deb.Stanza) error { return nil }); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReleaseMarshalParse(b *testing.B) {
	rel := sampleRelease()
	for i := range 200 {
		rel.AddFile(deb.HashBytes(fmt.Sprintf("main/binary-amd64/file%d", i), []byte{byte(i)}))
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := deb.ParseRelease(rel.Marshal()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashBytes(b *testing.B) {
	data := bytes.Repeat([]byte("x"), 1<<20)

	b.SetBytes(int64(len(data)))

	for b.Loop() {
		_ = deb.HashBytes("p", data)
	}
}
