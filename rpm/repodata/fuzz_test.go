package repodata

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

const fuzzPrimarySeed = `<?xml version="1.0"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">
<package type="rpm"><name>p</name><arch>noarch</arch><version epoch="1" ver="2" rel="3"/>
<checksum type="sha256" pkgid="YES">ab</checksum><location xml:base="http://x/" href="Packages/p.rpm"/>
<size package="1" installed="2" archive="3"/>
<format><rpm:license>MIT</rpm:license><rpm:requires><rpm:entry name="a" flags="GE" epoch="0" ver="1" rel="2" pre="1"/></rpm:requires>
<file type="dir">/etc/p</file></format></package></metadata>`

func FuzzReadPrimary(f *testing.F) {
	f.Add([]byte(fuzzPrimarySeed))
	f.Add([]byte("<metadata><package><name>x</name>"))
	f.Add([]byte(""))

	f.Fuzz(func(_ *testing.T, data []byte) {
		lim := PrimaryLimits{MaxDependencies: 50, MaxFiles: 50, MaxFileBytes: 1 << 12, MaxFieldBytes: 1 << 12}
		_ = ReadPrimary(bytes.NewReader(data), lim, func(*PrimaryPackage) error { return nil })
	})
}

func FuzzScanPackages(f *testing.F) {
	f.Add([]byte(fuzzPrimarySeed), true)
	f.Add([]byte("<metadata><package pkgid=\"a\" name=\"n\" arch=\"x\"><version ver=\"1\" rel=\"1\"/></package></metadata>"), false)
	f.Add([]byte("<package>"), true)

	f.Fuzz(func(_ *testing.T, data []byte, withElement bool) {
		_ = ScanPackages(bytes.NewReader(data), withElement, func(PackageInfo, []byte) error { return nil })
	})
}

func FuzzParseRepomd(f *testing.F) {
	doc, _ := GenerateRepomdXML("1", []RepomdData{{Type: "primary", Location: "repodata/p.xml.gz", Checksum: "ab", ChecksumType: "sha256", OpenChecksum: "cd", OpenChecksumType: "sha256", Size: 1}})
	f.Add(doc)
	f.Add([]byte("<repomd><data"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseRepomd(bytes.NewReader(data))
	})
}

func FuzzOpenMetadata(f *testing.F) {
	for _, c := range []Compression{Gzip, Zstd, XZ} {
		cm, err := CompressMetadataStream(c, func(w io.Writer) error {
			_, err := io.WriteString(w, fuzzPrimarySeed)

			return err
		})
		if err != nil {
			f.Fatal(err)
		}

		f.Add(cm.Data, "primary.xml"+c.Extension())
	}

	f.Add([]byte(fuzzPrimarySeed), "primary.xml")
	f.Add([]byte("BZh9"), "primary.xml.bz2")

	f.Fuzz(func(_ *testing.T, data []byte, name string) {
		rc, err := OpenMetadata(io.NopCloser(bytes.NewReader(data)), name, 1<<20)
		if err != nil {
			return
		}

		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
	})
}

func FuzzValidateCompsXML(f *testing.F) {
	var buf bytes.Buffer
	_ = WriteCompsXML(&buf, testComps())
	f.Add(buf.Bytes())
	f.Add([]byte("<comps>"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = ValidateCompsXML(data)
	})
}

func FuzzMergeModules(f *testing.F) {
	f.Add(moduleStreams, moduleDefaults)
	f.Add("---\n...\n", "---\ndocument: modulemd\n")

	f.Fuzz(func(_ *testing.T, a, b string) {
		_, _ = MergeModules(io.Discard, []io.Reader{strings.NewReader(a), strings.NewReader(b)})
	})
}

func FuzzModuleIndexAdd(f *testing.F) {
	f.Add(moduleStreams)
	f.Add(moduleDefaults)
	f.Add("a: &x [*x]\n")

	f.Fuzz(func(_ *testing.T, data string) {
		var idx ModuleIndex

		_ = idx.Add(strings.NewReader(data), 1<<20)
		_ = idx.Blocked("1.module+el9", "n-0:1-1.module+el9.noarch")
	})
}
