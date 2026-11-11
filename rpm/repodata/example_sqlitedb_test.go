package repodata_test

import (
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

// Write the XML documents and the SQLite databases of a one-package
// repository, list them in repomd.xml, then read the primary database back the
// way a client does.
func ExampleCompressSQLite() {
	pkgs := []rpm.Package{{
		Name: "hello", Version: "1.0", Release: "1", Arch: "noarch",
		Summary: "A greeting", SHA256: "0123", PackageSize: 4096,
		Requires: []rpm.Dependency{{Name: "bash"}},
	}}

	var entries []repodata.RepomdData

	var primaryDB *repodata.CompressedMetadata

	for _, kind := range []repodata.DocKind{repodata.DocPrimary, repodata.DocFilelists, repodata.DocOther} {
		xml, err := repodata.CompressMetadataStream(repodata.Gzip, func(w io.Writer) error {
			d := repodata.NewDocWriter(w, kind, len(pkgs))
			for i := range pkgs {
				d.Package(&pkgs[i])
			}

			return d.Close()
		})
		if err != nil {
			log.Fatal(err)
		}

		// The database records the checksum of the XML it accompanies.
		db, err := repodata.CompressSQLite(repodata.Gzip, kind, pkgs, repodata.SQLiteOptions{XMLChecksum: xml.SHA256})
		if err != nil {
			log.Fatal(err)
		}

		name := repodata.DatabaseFileName(kind, repodata.Gzip)
		entries = append(entries, repodata.DatabaseEntry(db, kind, name, 1))

		if kind == repodata.DocPrimary {
			primaryDB = db
		}
	}

	repomd, err := repodata.GenerateRepomdXML("1", entries)
	if err != nil {
		log.Fatal(err)
	}

	index, err := repodata.ParseRepomd(bytes.NewReader(repomd))
	if err != nil {
		log.Fatal(err)
	}

	entry, _ := index.Find("primary_db")
	fmt.Println(entry.Location, entry.DatabaseVersion)

	// Client side.
	doc, err := repodata.OpenMetadata(io.NopCloser(bytes.NewReader(primaryDB.Data)), entry.Location, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer doc.Close()

	db, err := repodata.OpenSQLite(doc, repodata.SQLiteLimits{})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.Primary(func(p *repodata.PrimaryPackage) error {
		fmt.Println(p.Name, p.Version, p.Requires[0].Name, p.Location)

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	// Output:
	// repodata/primary.sqlite.gz 10
	// hello 1.0 bash Packages/hello-1.0-1.noarch.rpm
}
