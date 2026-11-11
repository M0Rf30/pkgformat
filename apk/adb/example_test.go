package adb_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/M0Rf30/pkgformat/apk/adb"
)

func ExampleWritePackage() {
	key, err := adb.GenerateECKey(adbCurve())
	if err != nil {
		log.Fatal(err)
	}

	signer, err := adb.NewSigner(key)
	if err != nil {
		log.Fatal(err)
	}

	spec := &adb.Spec{
		Info: adb.Info{
			Name: "hello", Version: "1.0-r0", Arch: "x86_64",
			Description: "A greeting", Depends: []string{"musl", "busybox>=1.36"},
		},
		Files: []adb.File{
			adb.MemFile("usr/bin/hello", 0o755, []byte("#!/bin/sh\necho hello\n")),
			{Name: "usr/bin/hi", Mode: 0o777 | 1<<27, LinkTarget: "hello"},
		},
	}

	var pkg bytes.Buffer

	written, err := adb.WritePackage(&pkg, spec, adb.WriteOptions{Signers: []*adb.Signer{signer}})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(written.Info.Name, written.Info.Version, written.Info.Depends)

	ring := adb.NewKeyring()
	if err := ring.Add(key.Public()); err != nil {
		log.Fatal(err)
	}

	if _, _, err := adb.VerifyPackage(&pkg, ring, adb.ReadOptions{}); err != nil {
		log.Fatal(err)
	}

	fmt.Println("verified")
	// Output:
	// hello 1.0-r0 [busybox>=1.36 musl]
	// verified
}

func ExampleReader() {
	var pkg bytes.Buffer

	spec := &adb.Spec{
		Info:  adb.Info{Name: "hello", Version: "1.0-r0", Arch: "noarch"},
		Files: []adb.File{adb.MemFile("etc/motd", 0o644, []byte("welcome\n"))},
	}

	if _, err := adb.WritePackage(&pkg, spec, adb.WriteOptions{}); err != nil {
		log.Fatal(err)
	}

	rd, err := adb.NewReader(&pkg, adb.ReadOptions{})
	if err != nil {
		log.Fatal(err)
	}

	defer func() { _ = rd.Close() }()

	for {
		e, err := rd.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			log.Fatal(err)
		}

		data, err := io.ReadAll(rd)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%-9s %-4s %04o %q\n", e.Name, e.Kind, e.Mode.Perm(), data)
	}
	// Output:
	// etc       dir  0755 ""
	// etc/motd  file 0644 "welcome\n"
}

func ExampleExtract() {
	var pkg bytes.Buffer

	spec := &adb.Spec{
		Info:  adb.Info{Name: "hello", Version: "1.0-r0", Arch: "noarch"},
		Files: []adb.File{adb.MemFile("etc/motd", 0o644, []byte("welcome\n"))},
	}

	if _, err := adb.WritePackage(&pkg, spec, adb.WriteOptions{}); err != nil {
		log.Fatal(err)
	}

	dir, err := os.MkdirTemp("", "adb-example")
	if err != nil {
		log.Fatal(err)
	}

	defer func() { _ = os.RemoveAll(dir) }()

	// A package is unpacked only if it is signed by a trusted key, or if the
	// caller says an unsigned one will do.
	_, err = adb.Extract(bytes.NewReader(pkg.Bytes()), dir, adb.ExtractOptions{})
	fmt.Println(errors.Is(err, adb.ErrNoKeyring))

	info, err := adb.Extract(bytes.NewReader(pkg.Bytes()), dir, adb.ExtractOptions{AllowUntrusted: true})
	if err != nil {
		log.Fatal(err)
	}

	data, _ := os.ReadFile(dir + "/etc/motd")
	fmt.Printf("%s %q\n", info.Info.Name, data)
	// Output:
	// true
	// hello "welcome\n"
}

func ExampleBuildIndex() {
	var pkg bytes.Buffer

	spec := &adb.Spec{Info: adb.Info{Name: "hello", Version: "1.0-r0", Arch: "noarch"}}
	if _, err := adb.WritePackage(&pkg, spec, adb.WriteOptions{}); err != nil {
		log.Fatal(err)
	}

	size := pkg.Len()

	entry, err := adb.IndexEntry(&pkg, adb.ReadOptions{})
	if err != nil {
		log.Fatal(err)
	}

	var index bytes.Buffer

	idx := &adb.Index{Description: "example", PkgnameSpec: "${name}-${version}.apk", Packages: []adb.Info{entry}}
	if err := adb.BuildIndex(&index, idx, adb.WriteOptions{}); err != nil {
		log.Fatal(err)
	}

	back, err := adb.ParseIndex(&index, adb.ReadOptions{})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(back.Description, len(back.Packages), back.Packages[0].Name, back.Packages[0].FileSize == uint64(size))
	// Output: example 1 hello true
}

func ExampleCompareVersions() {
	fmt.Println(adb.CompareVersions("1.0_rc1", "1.0"), adb.CompareVersions("1.10", "1.9"), adb.CompareVersions("2.0-r1", "2.0-r1"))
	// Output: -1 1 0
}

func ExampleParseDependency() {
	d, err := adb.ParseDependency("!foo>=1.2")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(d.Name, d.Version, d.Match&adb.MatchConflict != 0, d)
	// Output: foo 1.2 true !foo>=1.2
}
