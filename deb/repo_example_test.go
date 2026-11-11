package deb_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/deb"
)

func ExampleRelease_MarshalStyle() {
	rel := &deb.Release{
		Origin:        "Example",
		Suite:         "stable",
		Codename:      "bookworm",
		Date:          time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC),
		AcquireByHash: true,
		Architectures: []string{"amd64"},
		Components:    []string{"main"},
	}

	// The layout of the Debian archive...
	fmt.Print(strings.Join(strings.Split(string(rel.Marshal()), "\n")[:5], "\n"), "\n")
	// ...and the one apt-ftparchive release writes: fields sorted by name, a
	// numeric time zone.
	fmt.Print(strings.Join(strings.Split(string(rel.MarshalStyle(deb.ReleaseStyleAptFTPArchive)), "\n")[:5], "\n"), "\n")
	// Output:
	// Origin: Example
	// Suite: stable
	// Codename: bookworm
	// Date: Tue, 04 Mar 2025 05:06:07 UTC
	// Acquire-By-Hash: yes
	// Acquire-By-Hash: yes
	// Architectures: amd64
	// Codename: bookworm
	// Components: main
	// Date: Tue, 04 Mar 2025 05:06:07 +0000
}

func ExampleRelease_IndexPaths() {
	rel := &deb.Release{}
	for _, p := range []string{
		"main/binary-amd64/Packages", "main/binary-amd64/Packages.gz", "main/binary-amd64/Packages.xz",
		"main/Contents-amd64.gz", "main/i18n/Translation-de.bz2", "main/i18n/Translation-en",
	} {
		rel.AddFile(deb.FileInfo{Path: p, Size: 1})
	}

	// Best compression first.
	fmt.Println(rel.IndexPaths("main", "amd64", deb.IndexPackages))
	fmt.Println(rel.IndexPaths("main", "amd64", deb.IndexContents))
	fmt.Println(rel.IndexPaths("main", "", deb.IndexTranslationPrefix+"de"))
	fmt.Println(rel.TranslationLanguages("main"))
	fmt.Println(deb.IndexPath("main", "arm64", deb.IndexContentsUdeb))
	// Output:
	// [main/binary-amd64/Packages.xz main/binary-amd64/Packages.gz main/binary-amd64/Packages]
	// [main/Contents-amd64.gz]
	// [main/i18n/Translation-de.bz2]
	// [de en]
	// main/Contents-udeb-arm64
}

func ExampleWriteByHash() {
	dist, err := os.MkdirTemp("", "dists")
	if err != nil {
		log.Fatal(err)
	}

	defer func() { _ = os.RemoveAll(dist) }()

	packages := []byte("Package: hello\n\n")
	if err := os.MkdirAll(filepath.Join(dist, "main", "binary-amd64"), 0o755); err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dist, "main", "binary-amd64", "Packages"), packages, 0o644); err != nil {
		log.Fatal(err)
	}

	rel := &deb.Release{AcquireByHash: true}
	rel.AddFile(deb.HashBytes("main/binary-amd64/Packages", packages))

	written, err := deb.WriteByHash(dist, rel, deb.ByHashOptions{Algorithms: []deb.ByHashAlgorithm{deb.ByHashSHA256}})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(written), strings.HasPrefix(written[0], "main/binary-amd64/by-hash/SHA256/"))

	// Later, once the Release lists other files, the old ones are pruned
	// after a day (a dry run first).
	next := &deb.Release{}
	plan, err := deb.PlanByHashPrune(dist, next, deb.ByHashRetention{MaxAge: 24 * time.Hour, Now: time.Now().Add(48 * time.Hour)})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(plan.Keep), len(plan.Remove))

	removed, err := plan.Apply(dist)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(removed))
	// Output:
	// 1 true
	// 0 1
	// 1
}

func ExampleContentsBuilder() {
	var b deb.ContentsBuilder

	_ = b.Add("utils/hello", "usr/bin/hello", "usr/share/doc/hello/copyright")
	_ = b.Add("utils/hello-extras", "usr/bin/hello")

	fmt.Print(strings.ReplaceAll(string(b.Bytes()), "\t", "~"))

	for e, err := range deb.ScanContents(strings.NewReader(string(b.Bytes()))) {
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(e.Path, e.Locations)
	}
	// Output:
	// usr/bin/hello~~~~~~    utils/hello,utils/hello-extras
	// usr/share/doc/hello/copyright~~~~    utils/hello
	// usr/bin/hello [utils/hello utils/hello-extras]
	// usr/share/doc/hello/copyright [utils/hello]
}

func ExampleTranslationBuilder() {
	en := deb.NewTranslationBuilder("en")
	_ = en.Add(deb.TranslationEntry{Package: "hello", Description: "friendly greeter\nPrints a greeting."})

	md5sum := deb.DescriptionMD5("friendly greeter\nPrints a greeting.")

	de := deb.NewTranslationBuilder("de")
	// A translation is filed under the md5 of the English description.
	_ = de.Add(deb.TranslationEntry{Package: "hello", DescriptionMD5: md5sum, Description: "freundlicher Gruesser\nGibt einen Gruss aus."})

	fmt.Print(string(de.Bytes()))

	stanza := deb.FormatPackagesEntryShort(deb.IndexEntry{
		Name: "hello", Version: "1.0", Arch: "all", Filename: "pool/main/h/hello/hello_1.0_all.deb", Size: 1,
		Control: map[string]string{"Description": "friendly greeter\nPrints a greeting."},
	})
	fmt.Println(strings.Contains(stanza, "Description: friendly greeter\nDescription-md5: "+md5sum))
	// Output:
	// Package: hello
	// Description-md5: 40d9ed3e151e7006a11742c09a08ffa0
	// Description-de: freundlicher Gruesser
	//  Gibt einen Gruss aus.
	//
	// true
}

func ExampleI18nIndex() {
	var ix deb.I18nIndex

	ix.AddFile(deb.FileInfo{Path: "Translation-en.xz", Size: 100, SHA1: strings.Repeat("a", 40)})
	ix.AddFile(deb.FileInfo{Path: "Translation-de", Size: 5, SHA1: strings.Repeat("b", 40)})

	fmt.Print(string(ix.Marshal()))
	fmt.Println(ix.Languages(), deb.I18nIndexName("main"))
	// Output:
	// SHA1:
	//  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb       5 Translation-de
	//  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa     100 Translation-en.xz
	// [de en] main/i18n/Index
}
