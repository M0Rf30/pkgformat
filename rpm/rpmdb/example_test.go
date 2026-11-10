package rpmdb_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/M0Rf30/pkgformat/rpm/rpmdb"
)

// Read the packages installed under a root. The example copies a small
// database into a temporary root; on a host, Find("/") finds the real one.
func Example() {
	root, err := os.MkdirTemp("", "root")
	if err != nil {
		log.Fatal(err)
	}

	defer os.RemoveAll(root)

	data, err := os.ReadFile(filepath.Join("testdata", "Packages.ndb"))
	if err != nil {
		log.Fatal(err)
	}

	dir := filepath.Join(root, "var/lib/rpm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "Packages.db"), data, 0o600); err != nil {
		log.Fatal(err)
	}

	path, format, err := rpmdb.Find(root)
	if err != nil {
		log.Fatal(err)
	}

	db, err := rpmdb.Open(path, rpmdb.Options{})
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	fmt.Println("format:", format)

	for pkg, err := range db.Packages(context.Background()) {
		if err != nil {
			log.Fatal(err)
		}

		if pkg.Name == "system-user-root" {
			fmt.Printf("%s %s-%s.%s with %d files\n", pkg.Name, pkg.Version, pkg.Release, pkg.Arch, len(pkg.Files))
		}
	}

	names, err := db.InstalledNames(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(names)
	// Output:
	// format: ndb
	// system-user-root 20190513-2.20.noarch with 1 files
	// [aaa_base filesystem system-user-root]
}
