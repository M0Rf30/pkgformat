package deb_test

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
)

func ExampleWrite() {
	spec := &deb.Spec{
		Name:         "hello",
		Version:      "1.0",
		Release:      "1",
		Architecture: "amd64",
		Maintainer:   "Jane Doe <jane@example.org>",
		Description:  "Say hello\nA friendly greeter.",
		Depends:      []string{"libc6 (>= 2.31)"},
		ModTime:      time.Unix(1700000000, 0),
	}

	payload := []deb.Entry{
		{Path: "usr/bin/hello", Mode: 0o755, Data: []byte("#!/bin/sh\necho hello\n")},
	}

	var buf bytes.Buffer
	if err := deb.Write(&buf, spec, payload, deb.WriteOptions{}); err != nil {
		log.Fatal(err)
	}

	pkg, err := deb.ParseDebFileAt(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(pkg.Package.Package, pkg.Package.Version, pkg.Package.Architecture)
	fmt.Println(pkg.Package.Depends)
	fmt.Println(spec.FileName())
	// Output:
	// hello 1.0-1 amd64
	// libc6 (>= 2.31)
	// hello_1.0-1_amd64.deb
}

func ExampleCompareVersions() {
	fmt.Println(deb.CompareVersions("1.0~rc1", "1.0"))
	fmt.Println(deb.CompareVersions("1:0.9", "2.0"))
	fmt.Println(deb.CompareVersions("1.10", "1.9"))
	fmt.Println(deb.CompareVersions("2.0-1", "2.0-1"))
	// Output:
	// -1
	// 1
	// 1
	// 0
}

func ExampleParseRelations() {
	const field = "libc6 (>= 2.31), bash | dash"

	alternatives, err := deb.ParseRelations(field)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(alternatives), deb.DependencyNames(field))
	// Output:
	// 2 [libc6 bash]
}

func ExampleIndex() {
	var index deb.Index

	index.Add(deb.IndexEntry{
		Name: "hello", Version: "1.0-1", Arch: "amd64",
		Filename: deb.PoolPath("main", "hello", "hello_1.0-1_amd64.deb"),
		Size:     1234, SHA256: "abc123",
		Control: map[string]string{"Maintainer": "Jane Doe <jane@example.org>", "Description": "Say hello"},
	})

	fmt.Print(string(index.Bytes()))

	err := deb.ScanPackages(bytes.NewReader(index.Bytes()), func(s deb.Stanza) error {
		fmt.Println("scanned:", s.Package, s.Version, s.Filename)

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	// Output:
	// Package: hello
	// Version: 1.0-1
	// Architecture: amd64
	// Maintainer: Jane Doe <jane@example.org>
	// Filename: pool/main/h/hello/hello_1.0-1_amd64.deb
	// Size: 1234
	// SHA256: abc123
	// Description: Say hello
	//
	// scanned: hello 1.0-1 pool/main/h/hello/hello_1.0-1_amd64.deb
}

func ExampleParseRelease() {
	packages := []byte("Package: hello\nVersion: 1.0\nArchitecture: amd64\n\n")

	release := &deb.Release{
		Suite:         "stable",
		Codename:      "bookworm",
		Date:          time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC),
		Architectures: []string{"amd64"},
		Components:    []string{"main"},
	}
	release.AddFile(deb.HashBytes("main/binary-amd64/Packages", packages))

	parsed, err := deb.ParseRelease(release.Marshal())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(parsed.Codename, parsed.Date.Format(time.RFC3339))
	fmt.Println(parsed.HasIndex("main", "amd64"), parsed.HasIndex("main", "arm64"))
	fmt.Println(parsed.PackagesVariants("main", "amd64"))
	fmt.Println(parsed.Files["main/binary-amd64/Packages"].Size)
	// Output:
	// bookworm 2025-03-04T05:06:07Z
	// true false
	// [main/binary-amd64/Packages]
	// 49
}

func ExampleTrust_VerifyInRelease() {
	entity, err := gpg.GenerateEntity("Repo", "", "repo@example.org", gpg.AlgorithmED25519)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := gpg.NewLocalSignerFromEntity(entity)
	if err != nil {
		log.Fatal(err)
	}

	signed, err := deb.SignRelease(signer, []byte("Suite: stable\nCodename: bookworm\n"))
	if err != nil {
		log.Fatal(err)
	}

	keyring, err := signer.Keyring()
	if err != nil {
		log.Fatal(err)
	}

	trust := deb.Trust{Keyring: keyring}

	body, err := trust.VerifyInRelease(signed.InRelease)
	fmt.Printf("signed by the trusted key: %q %v\n", bytes.TrimSpace(body), err)

	// The same document with its content changed is rejected, even by a Trust
	// that accepts unverified repositories.
	forged := bytes.Replace(signed.InRelease, []byte("bookworm"), []byte("trixie"), 1)
	lenient := deb.Trust{Keyring: keyring, AllowUnverified: true}
	_, err = lenient.VerifyInRelease(forged)
	fmt.Println("forged:", err != nil)

	// Without a trust anchor, verification fails unless explicitly allowed.
	_, err = deb.Trust{}.VerifyInRelease(signed.InRelease)
	fmt.Println(err)
	// Output:
	// signed by the trusted key: "Suite: stable\nCodename: bookworm" <nil>
	// forged: true
	// deb: no usable trust anchor for source
}
