package repodata_test

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

// Register an AppStream catalog in a repository, the way modifyrepo_c does:
// the helper returns the record and the bytes of the file to store next to
// repomd.xml, and AddRecord puts the record in its place.
func ExampleAppStreamRecords() {
	repomd := &repodata.Repomd{Revision: "1", Data: []repodata.RepomdData{
		{Type: "primary", Location: "repodata/primary.xml.gz"},
	}}

	catalog := []byte("<components version=\"0.16\"><component type=\"desktop-application\"><id>org.example.Demo</id></component></components>")

	files, err := repodata.AppStreamRecords(repodata.AppStream{Components: catalog}, repodata.RecordOptions{
		Compression: repodata.Gzip, Timestamp: 1700000000,
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		repodata.AddRecord(repomd, f.Record)
		fmt.Println(strings.Replace(f.Record.Location, f.Record.Checksum, "<checksum>", 1), f.Record.OpenSize)
	}

	for _, d := range repomd.Data {
		fmt.Println(d.Type)
	}
	// Output:
	// repodata/<checksum>-appstream.xml.gz 115
	// primary
	// appstream
}

// An arbitrary document becomes a record of any type; RemoveRecord undoes it.
func ExampleNewOpaqueRecord() {
	repomd := &repodata.Repomd{}

	rec, file, err := repodata.NewOpaqueRecord("custom", "custom.xml", []byte("<custom/>"), repodata.Zstd, 1700000000)
	if err != nil {
		log.Fatal(err)
	}

	repodata.AddRecord(repomd, rec)
	fmt.Println(rec.Type, rec.OpenSize, strings.HasSuffix(rec.Location, "-custom.xml.zst"), len(file) > 0)

	removed := repodata.RemoveRecord(repomd, "custom")
	fmt.Println(len(removed), len(repomd.Data))
	// Output:
	// custom 9 true true
	// 1 0
}

// Write and read the delta rpm index of a repository.
func ExampleWriteDeltaInfoXML() {
	info := &repodata.DeltaInfo{NewPackages: []repodata.DeltaPackage{{
		Name: "hello", Epoch: 0, Version: "1.1", Release: "1", Arch: "x86_64",
		Deltas: []repodata.Delta{{
			Version: "1.0", Release: "1",
			Filename: "drpms/hello-1.0-1_1.1-1.x86_64.drpm",
			Sequence: "hello-1.0-1-0123456789abcdef",
			Size:     2048,
			Checksum: repodata.DeltaChecksum{Type: "sha256", Value: "ab12"},
		}},
	}}}

	var buf bytes.Buffer
	if err := repodata.WriteDeltaInfoXML(&buf, info); err != nil {
		log.Fatal(err)
	}

	fmt.Println(buf.String())

	err := repodata.ReadDeltaInfo(&buf, repodata.DeltaInfoLimits{}, func(p *repodata.DeltaPackage) error {
		fmt.Println(p.Name, p.Version, "from", p.Deltas[0].Version, p.Deltas[0].Size)

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <prestodelta>
	//   <newpackage name="hello" epoch="0" version="1.1" release="1" arch="x86_64">
	//     <delta oldepoch="0" oldversion="1.0" oldrelease="1">
	//       <filename>drpms/hello-1.0-1_1.1-1.x86_64.drpm</filename>
	//       <sequence>hello-1.0-1-0123456789abcdef</sequence>
	//       <size>2048</size>
	//       <checksum type="sha256">ab12</checksum>
	//     </delta>
	//   </newpackage>
	// </prestodelta>
	// hello 1.1 from 1.0 2048
}

// Read a filelists-ext document: the paths of each package with their types,
// as `createrepo_c --filelists-ext` writes them.
func ExampleReadFilelistsExt() {
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<filelists-ext xmlns="http://linux.duke.edu/metadata/filelists-ext" packages="1">
<package pkgid="abc" name="hello" arch="x86_64">
  <version epoch="0" ver="1.0" rel="1"/>
  <file>/usr/bin/hello</file>
  <file type="dir">/usr/share/hello</file>
  <file type="ghost">/var/log/hello.log</file>
</package>
</filelists-ext>`

	err := repodata.ReadFilelistsExt(strings.NewReader(doc), repodata.FilelistsLimits{}, func(p *repodata.FilelistsExtPackage) error {
		fmt.Println(p.Name, p.Version, p.PkgID)

		for _, f := range p.Files {
			fmt.Printf("%q %s\n", f.Type, f.Path)
		}

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	// Output:
	// hello 1.0 abc
	// "" /usr/bin/hello
	// "dir" /usr/share/hello
	// "ghost" /var/log/hello.log
}
