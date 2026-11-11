package pacman_test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"testing/fstest"
	"time"

	"github.com/M0Rf30/pkgformat/pacman"
)

func Example() {
	spec := &pacman.Spec{
		Info: pacman.PkgInfo{
			Name: "hello", Version: "1.0-1", Description: "A greeting", Arch: "x86_64",
			BuildDate: 1700000000, Depends: []string{"glibc"},
		},
		Scriptlets: &pacman.Scriptlets{PostInstall: "echo installed"},
		Files: []pacman.File{
			{Path: "usr/bin/hello", Mode: 0o755, Data: []byte("#!/bin/sh\necho hello\n"), ModTime: time.Unix(1700000000, 0)},
		},
	}

	// Write the package, reproducibly.
	var pkg bytes.Buffer
	if err := spec.Write(&pkg, pacman.WriteOptions{Compression: pacman.CompressionZstd, ClampMTime: true}); err != nil {
		fmt.Println(err)

		return
	}

	// Read it back.
	read, err := pacman.ReadPackage(bytes.NewReader(pkg.Bytes()))
	if err != nil {
		fmt.Println(err)

		return
	}

	fmt.Println(spec.FileName(pacman.CompressionZstd), read.Info.Depends, read.Files)

	// Put it in a database and resolve a dependency against it.
	entry, err := pacman.NewDBEntry(spec.FileName(pacman.CompressionZstd), bytes.NewReader(pkg.Bytes()), nil)
	if err != nil {
		fmt.Println(err)

		return
	}

	var db bytes.Buffer
	if err := pacman.WriteDB(&db, []pacman.DBEntry{*entry}, false); err != nil {
		fmt.Println(err)

		return
	}

	var index pacman.Index
	if err := index.AddDatabase("local", &db); err != nil {
		fmt.Println(err)

		return
	}

	dep, _ := pacman.ParseDependency("hello>=0.9")
	best, err := index.Resolve(dep)
	fmt.Println(best.Repo, best.Version, err, pacman.Vercmp("1.0-1", "1.0.1-1"))

	// A pacman.conf yields repositories whose server URLs expand per arch.
	cfg, _ := pacman.ParseConfig(strings.NewReader("[core]\nServer = https://mirror.example/$repo/os/$arch\n"), pacman.ParseOptions{})
	fmt.Println(pacman.ExpandServer(cfg.Repos[0].Servers[0], "core", "x86_64"))

	// Output:
	// hello-1.0-1-x86_64.pkg.tar.zst [glibc] [usr/ usr/bin/ usr/bin/hello]
	// local 1.0-1 <nil> -1
	// https://mirror.example/core/os/x86_64
}

// Read the packages a pacman system has installed. On a host, FindLocalDB("/")
// and OpenLocalDB give the real database.
func ExampleLocalDB() {
	fsys := fstest.MapFS{
		"ALPM_DB_VERSION":   {Data: []byte("9\n")},
		"acl-2.4.0-1/desc":  {Data: []byte("%NAME%\nacl\n\n%VERSION%\n2.4.0-1\n\n%REASON%\n1\n\n%PROVIDES%\nlibacl.so=1-64\n\n")},
		"acl-2.4.0-1/files": {Data: []byte("%FILES%\nusr/\nusr/bin/\nusr/bin/chacl\n")},
	}

	db := pacman.NewLocalDB(fsys, pacman.LocalDBOptions{})

	for pkg, err := range db.Packages(context.Background()) {
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(pkg.Name, pkg.Version, pkg.Reason == pacman.ReasonDependency, pkg.Files)
	}

	provides, _ := db.InstalledProvides(context.Background())
	fmt.Println(provides)
	// Output:
	// acl 2.4.0-1 true [usr/ usr/bin/ usr/bin/chacl]
	// [acl libacl.so]
}
