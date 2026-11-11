package rpmdb_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

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

// openRichExample copies the rich fixture (see testdata/README.md) to a temporary
// directory and opens it; a host would use Find("/") instead.
func openRichExample() (*rpmdb.DB, func()) {
	dir, err := os.MkdirTemp("", "rpmdb")
	if err != nil {
		log.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join("testdata", "rich.sqlite"))
	if err != nil {
		log.Fatal(err)
	}

	path := filepath.Join(dir, "rpmdb.sqlite")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		log.Fatal(err)
	}

	db, err := rpmdb.Open(path, rpmdb.Options{})
	if err != nil {
		log.Fatal(err)
	}

	return db, func() {
		_ = db.Close()
		_ = os.RemoveAll(dir)
	}
}

// A provide "foo = 1.2-3" satisfies the requirement "foo >= 1.0": the query
// is version aware, by the rules of librpm.
func ExampleDB_WhatProvides() {
	db, done := openRichExample()
	defer done()

	for _, capability := range []string{"qdb-virt >= 1.5", "qdb-virt < 1.0", "qdb-virt > 5"} {
		q, err := rpmdb.ParseCapability(capability)
		if err != nil {
			log.Fatal(err)
		}

		pkgs, err := db.WhatProvides(context.Background(), q)
		if err != nil {
			log.Fatal(err)
		}

		var names []string
		for _, p := range pkgs {
			names = append(names, p.Name+"-"+p.Version)
		}

		fmt.Printf("%s: %v\n", capability, names)
	}
	// Output:
	// qdb-virt >= 1.5: [qdb-base-1.2.3]
	// qdb-virt < 1.0: [qdb-old-0.4]
	// qdb-virt > 5: []
}

// FileOwners is rpm -qf, ByLabel is what rpm -q takes.
func ExampleDB_FileOwners() {
	db, done := openRichExample()
	defer done()

	owners, err := db.FileOwners(context.Background(), "/usr/share//qdb/a.txt")
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range owners {
		fmt.Println("owner:", p.Name)
	}

	pkgs, err := db.ByLabel(context.Background(), "qdb-lib-1.5.i686")
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range pkgs {
		fmt.Println("label:", p.Name, p.Version, p.Release, p.Arch)
	}
	// Output:
	// owner: qdb-base
	// label: qdb-lib 1.5 2.q1 i686
}

// Scripts reads the scriptlets and triggers of a package from its header.
func ExampleDB_Scripts() {
	db, done := openRichExample()
	defer done()

	pkgs, err := db.ByName(context.Background(), "qdb-base")
	if err != nil {
		log.Fatal(err)
	}

	s, err := db.Scripts(context.Background(), pkgs[0])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("post:", s.PostIn.Prog, s.PostIn.Flags)
	fmt.Println("postun program:", s.PostUn.Prog, s.PostUn.Body == "")

	for _, t := range s.Triggers {
		fmt.Printf("trigger %s on %d packages\n", t.Kind, len(t.Conditions))
	}

	for _, t := range s.FileTriggers {
		fmt.Printf("file trigger %s on %v, priority %d\n", t.Kind, t.Prefixes, t.Priority)
	}
	// Output:
	// post: [/bin/sh] 1
	// postun program: [/sbin/ldconfig] true
	// trigger prein on 1 packages
	// trigger in on 2 packages
	// trigger un on 1 packages
	// trigger postun on 1 packages
	// file trigger in on [/usr/share/qdb], priority 100
	// file trigger un on [/usr/lib/qdb /usr/share/qdb-extra], priority 1000000
	// file trigger postun on [/usr/share/qdb-alt], priority 1000000
}

// A database on read-only media with a write-ahead log is read from a private
// copy by default; Options.SQLite chooses another way, and a database that
// stays locked fails with an error that matches ErrLocked.
func ExampleOptions_sqlite() {
	db, err := rpmdb.Open(filepath.Join("testdata", "rpmdb.sqlite"), rpmdb.Options{
		SQLite:      rpmdb.SQLiteImmutable, // no lock, nothing created next to the file
		BusyTimeout: time.Second,
	})
	if errors.Is(err, rpmdb.ErrLocked) {
		fmt.Println("rpm is busy, try again later")

		return
	}

	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	pkgs, err := db.InstalledPackages(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(pkgs), "packages,", rpmdb.SQLiteImmutable)
	// Output:
	// 3 packages, immutable
}
