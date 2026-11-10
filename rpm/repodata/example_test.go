package repodata_test

import (
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

// Write the metadata of a one-package repository, then read it back the way a
// client does: repomd.xml names the primary document, which is decompressed
// and decoded.
func Example() {
	pkgs := []rpm.Package{{
		Name: "hello", Version: "1.0", Release: "1", Arch: "noarch",
		Summary: "A greeting", SHA256: "0123", PackageSize: 4096,
		Requires: []rpm.Dependency{{Name: "bash"}},
	}}

	primary, err := repodata.CompressMetadataStream(repodata.Zstd, func(w io.Writer) error {
		return repodata.WritePrimaryXML(w, pkgs)
	})
	if err != nil {
		log.Fatal(err)
	}

	name := "repodata/" + primary.SHA256 + "-primary.xml" + repodata.Zstd.Extension()

	repomd, err := repodata.GenerateRepomdXML("1", []repodata.RepomdData{{
		Type: "primary", Location: name, Checksum: primary.SHA256, ChecksumType: "sha256",
		OpenChecksum: primary.OpenSHA256, OpenChecksumType: "sha256",
		Timestamp: 1, Size: primary.Size, OpenSize: primary.OpenSize,
	}})
	if err != nil {
		log.Fatal(err)
	}

	// Client side.
	index, err := repodata.ParseRepomd(bytes.NewReader(repomd))
	if err != nil {
		log.Fatal(err)
	}

	entry, _ := index.Find("primary")

	doc, err := repodata.OpenMetadata(io.NopCloser(bytes.NewReader(primary.Data)), entry.Location, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer doc.Close()

	err = repodata.ReadPrimary(doc, repodata.PrimaryLimits{}, func(p *repodata.PrimaryPackage) error {
		fmt.Println(p.Name, p.Version, p.Requires[0].Name, p.Location)

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	// Output: hello 1.0 bash Packages/hello-1.0-1.noarch.rpm
}
