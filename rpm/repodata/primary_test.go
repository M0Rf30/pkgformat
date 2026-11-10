package repodata

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

func readPrimaryDoc(t *testing.T, doc string, lim PrimaryLimits) ([]PrimaryPackage, error) {
	t.Helper()

	var out []PrimaryPackage

	err := ReadPrimary(strings.NewReader(doc), lim, func(p *PrimaryPackage) error {
		out = append(out, *p)

		return nil
	})

	return out, err
}

func TestReadPrimaryRoundTripsWrittenPrimary(t *testing.T) {
	pkgs := []rpm.Package{{
		Name: "tool", Version: "2.1", Release: "3", Epoch: 4, Arch: "x86_64",
		Summary: "A & B <tool>", Description: "Long\ndescription", License: "MIT", URL: "https://example.invalid/",
		Vendor: "V", Group: "G", Packager: "P", SourceRPM: "tool-2.1-3.src.rpm", BuildHost: "h",
		BuildTime: 1700000000, FileTime: 1700000100, PackageSize: 10, InstalledSize: 20, ArchiveSize: 30,
		SHA256: "abc123", HeaderStart: 100, HeaderEnd: 900,
		Provides: []rpm.Dependency{{Name: "tool", Flags: tag.RPMSENSE_EQUAL, Version: "2.1-3", Epoch: 4}},
		Requires: []rpm.Dependency{
			{Name: "libfoo", Flags: tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL, Version: "1.5", Epoch: 2},
			{Name: "shadow-utils", Flags: tag.RPMSENSE_PREREQ},
			{Name: "/bin/sh"},
		},
		Conflicts:   []rpm.Dependency{{Name: "old", Flags: tag.RPMSENSE_LESS, Version: "2.0-1"}},
		Obsoletes:   []rpm.Dependency{{Name: "older"}},
		Recommends:  []rpm.Dependency{{Name: "nice"}},
		Suggests:    []rpm.Dependency{{Name: "maybe"}},
		Supplements: []rpm.Dependency{{Name: "extra"}},
		Enhances:    []rpm.Dependency{{Name: "more"}},
		Files:       []rpm.FileEntry{{Path: "/usr/bin/tool"}, {Path: "/etc/tool", Flags: tag.RPMFILE_GHOST}, {Path: "/opt/not-primary"}},
	}}

	var doc bytes.Buffer
	if err := WritePrimaryXML(&doc, pkgs); err != nil {
		t.Fatal(err)
	}

	got, err := readPrimaryDoc(t, doc.String(), PrimaryLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 {
		t.Fatalf("got %d packages", len(got))
	}

	want := pkgs[0]
	// primary.xml lists only some files, and without their flags.
	want.Files = []rpm.FileEntry{{Path: "/usr/bin/tool"}, {Path: "/etc/tool"}}
	// The rpmlib flag and the sense bits are all the reader can restore.
	g := got[0]

	if g.Location != "Packages/tool-2.1-3.x86_64.rpm" || g.ChecksumType != "sha256" || g.Checksum != "abc123" {
		t.Errorf("location/checksum = %q %q %q", g.Location, g.ChecksumType, g.Checksum)
	}

	if !reflect.DeepEqual(g.Package, want) {
		t.Errorf("package differs\n got: %+v\nwant: %+v", g.Package, want)
	}
}

func TestReadPrimaryReadsRealMetadata(t *testing.T) {
	const doc = `<?xml version="1.0"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="2">
<package type="rpm">
  <name>glibc</name><arch>x86_64</arch>
  <version epoch="0" ver="2.34" rel="1.el9"/>
  <checksum type="sha512" pkgid="YES">dead</checksum>
  <location xml:base="http://other.invalid/" href="Packages/g/glibc.rpm"/>
  <format>
    <rpm:requires><rpm:entry name="rpmlib(PayloadIsZstd)" flags="LE" epoch="0" ver="5.4.18" rel="1"/></rpm:requires>
  </format>
</package>
<package type="rpm"><name>glibc</name><arch>src</arch></package>
</metadata>`

	got, err := readPrimaryDoc(t, doc, PrimaryLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 {
		t.Fatalf("got %d packages, want 2 (source packages are the caller's to skip)", len(got))
	}

	g := got[0]
	if g.Base != "http://other.invalid/" || g.Location != "Packages/g/glibc.rpm" || g.SHA256 != "" || g.Checksum != "dead" {
		t.Errorf("g = %+v", g)
	}

	req := g.Requires[0]
	if !req.IsRPMLib() || req.Version != "5.4.18-1" || req.Flags&tag.RPMSENSE_LESS == 0 {
		t.Errorf("requirement = %+v", req)
	}
}

func TestReadPrimarySkipsIncompletePackages(t *testing.T) {
	const doc = `<metadata>
<package><name></name><arch>noarch</arch></package>
<package><name>noarch-less</name></package>
<package><name>bad-epoch</name><arch>noarch</arch><version epoch="x" ver="1" rel="1"/></package>
<package><name>bad-size</name><arch>noarch</arch><size package="-1"/></package>
<package><name>good</name><arch>noarch</arch></package>
</metadata>`

	got, err := readPrimaryDoc(t, doc, PrimaryLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 || got[0].Name != "good" {
		t.Errorf("got %+v, want only good", got)
	}
}

func TestReadPrimaryLimits(t *testing.T) {
	entries := func(n int) string {
		return strings.Repeat(`<rpm:entry name="x"/>`, n)
	}

	pkg := func(inner string) string {
		return `<metadata xmlns:rpm="http://linux.duke.edu/metadata/rpm"><package><name>p</name><arch>noarch</arch><format>` + inner + `</format></package></metadata>`
	}

	for name, tc := range map[string]struct {
		doc string
		lim PrimaryLimits
	}{
		"dependencies": {pkg("<rpm:requires>" + entries(4) + "</rpm:requires>"), PrimaryLimits{MaxDependencies: 3}},
		"files":        {pkg(strings.Repeat("<file>/etc/a</file>", 4)), PrimaryLimits{MaxFiles: 3}},
		"file bytes":   {pkg(strings.Repeat("<file>/etc/aaaa</file>", 4)), PrimaryLimits{MaxFileBytes: 20}},
		"field bytes":  {`<metadata><package><name>p</name><arch>a</arch><description>` + strings.Repeat("x", 100) + `</description></package></metadata>`, PrimaryLimits{MaxFieldBytes: 50}},
	} {
		if _, err := readPrimaryDoc(t, tc.doc, tc.lim); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: err = %v, want ErrTooLarge", name, err)
		}
	}

	if _, err := readPrimaryDoc(t, pkg("<rpm:requires>"+entries(3)+"</rpm:requires>"), PrimaryLimits{MaxDependencies: 3}); err != nil {
		t.Errorf("a list at the limit: %v", err)
	}
}

func TestReadPrimaryErrors(t *testing.T) {
	if _, err := readPrimaryDoc(t, "<metadata><package><name>p</name>", PrimaryLimits{}); err == nil {
		t.Error("a truncated document must fail")
	}

	stop := errors.New("stop")

	err := ReadPrimary(strings.NewReader(`<metadata><package><name>p</name><arch>a</arch></package></metadata>`), PrimaryLimits{},
		func(*PrimaryPackage) error { return stop })
	if !errors.Is(err, stop) {
		t.Errorf("the error of the callback must be returned: %v", err)
	}
}

func TestReadPrimaryCountsPackages(t *testing.T) {
	var doc strings.Builder

	doc.WriteString("<metadata>")

	for i := range 1000 {
		fmt.Fprintf(&doc, "<package><name>p%d</name><arch>noarch</arch></package>", i)
	}

	doc.WriteString("</metadata>")

	got, err := readPrimaryDoc(t, doc.String(), PrimaryLimits{})
	if err != nil || len(got) != 1000 {
		t.Fatalf("len=%d err=%v", len(got), err)
	}
}

func TestRepomdRoundTrip(t *testing.T) {
	in := []RepomdData{
		{Type: "primary", Location: "repodata/p.xml.zst", Checksum: "aa", ChecksumType: "sha256",
			OpenChecksum: "bb", OpenChecksumType: "sha256", Timestamp: 5, Size: 10, OpenSize: 20},
		{Type: "group", Location: "repodata/g.xml", Checksum: "cc", ChecksumType: "sha256", Timestamp: 6, Size: 7},
	}

	doc, err := GenerateRepomdXML("42", in)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ParseRepomd(bytes.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}

	if got.Revision != "42" || !reflect.DeepEqual(got.Data, in) {
		t.Errorf("got %+v", got)
	}

	if _, ok := got.Find("nope"); ok {
		t.Error("Find must report a missing type")
	}

	if bytes.Contains(doc, []byte("open-checksum></data>")) || strings.Count(string(doc), "<open-checksum") != 1 {
		t.Errorf("open-checksum must appear only for the entry that has one:\n%s", doc)
	}
}

func TestParseRepomdLimits(t *testing.T) {
	big := "<repomd>" + strings.Repeat("<data type=\"x\"><location href=\"a\"/></data>", maxRepomdEntries+1) + "</repomd>"
	if _, err := ParseRepomd(strings.NewReader(big)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("too many entries: %v", err)
	}

	huge := io.MultiReader(strings.NewReader("<repomd><revision>"), strings.NewReader(strings.Repeat("1", maxRepomdSize+10)))
	if _, err := ParseRepomd(huge); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized document: %v", err)
	}
}

const moduleStreams = `---
document: modulemd
version: 2
data:
  name: nodejs
  stream: "18"
  artifacts:
    rpms:
    - nodejs-1:18.1.0-1.module+el9.1.0+1+aaaa.x86_64
---
document: modulemd
version: 2
data:
  name: nodejs
  stream: "20"
  artifacts:
    rpms:
    - nodejs-1:20.1.0-1.module+el9.1.0+2+bbbb.x86_64
---
document: modulemd
version: 2
data:
  name: other
  stream: "1"
  artifacts:
    rpms:
    - other-0:1-1.module+el9+3+cccc.noarch
---
this: is: not valid: [
`

const moduleDefaults = `---
document: modulemd-defaults
version: 1
data:
  module: nodejs
  stream: "18"
`

func TestModuleIndex(t *testing.T) {
	var idx ModuleIndex

	// An empty index blocks nothing.
	if idx.Blocked("1.module+el9", "x-0:1-1.module+el9.noarch") {
		t.Error("an empty index must not block")
	}

	// Streams and defaults may come from different files.
	if err := idx.Add(strings.NewReader(moduleStreams), 0); err != nil {
		t.Fatal(err)
	}

	if err := idx.Add(strings.NewReader(moduleDefaults), 0); err != nil {
		t.Fatal(err)
	}

	if s, ok := idx.DefaultStream("nodejs"); !ok || s != "18" || idx.Defaults() != 1 {
		t.Errorf("default = %q %v (%d)", s, ok, idx.Defaults())
	}

	for _, tc := range []struct {
		name, epoch, version, release, arch string
		blocked                             bool
	}{
		{"nodejs", "1", "20.1.0", "1.module+el9.1.0+2+bbbb", "x86_64", true},
		{"nodejs", "1", "18.1.0", "1.module+el9.1.0+1+aaaa", "x86_64", false},
		{"other", "", "1", "1.module+el9+3+cccc", "noarch", false}, // no default: not filtered
		{"plain", "", "1", "1.el9", "noarch", false},
	} {
		nevra := PackageNEVRA(tc.name, tc.epoch, tc.version, tc.release, tc.arch)
		if got := idx.Blocked(tc.release, nevra); got != tc.blocked {
			t.Errorf("Blocked(%s) = %v, want %v", nevra, got, tc.blocked)
		}
	}
}

func TestModuleIndexLimit(t *testing.T) {
	var idx ModuleIndex

	if err := idx.Add(strings.NewReader(moduleStreams), 20); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized modules.yaml: %v", err)
	}
}

func TestPackageNEVRAAndModular(t *testing.T) {
	if got := PackageNEVRA("a", "", "1", "2", "noarch"); got != "a-0:1-2.noarch" {
		t.Errorf("PackageNEVRA = %q", got)
	}

	if !IsModularPackage("1.module+el8.0.0+1+ab") || IsModularPackage("1.el8") {
		t.Error("IsModularPackage")
	}
}
