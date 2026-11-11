package deb_test

import (
	"bytes"
	"fmt"
	"time"

	"github.com/M0Rf30/pkgformat/deb"
)

func ExampleApplyPDiff() {
	base := []byte("Package: a\nPackage: b\nPackage: c\n")
	patch := []byte("3c\nPackage: C\n.\n1a\nPackage: a2\n.\n")

	out, err := deb.ApplyPDiff(base, patch)
	if err != nil {
		panic(err)
	}

	fmt.Print(string(out))
	// Output:
	// Package: a
	// Package: a2
	// Package: b
	// Package: C
}

func ExampleGeneratePDiff() {
	oldFile := []byte("a\nb\nc\nd\n")
	newFile := []byte("a\nB\nc\nd\ne\n")

	patch, err := deb.GeneratePDiff(oldFile, newFile)
	if err != nil {
		panic(err)
	}

	fmt.Print(string(patch))

	got, _ := deb.ApplyPDiff(oldFile, patch)
	fmt.Println(bytes.Equal(got, newFile))
	// Output:
	// 4a
	// e
	// .
	// 2c
	// B
	// .
	// true
}

func ExampleMergePDiffs() {
	v0 := []byte("1\n2\n3\n")
	v1 := []byte("1\nx\n3\n")
	v2 := []byte("0\n1\nx\n")

	p1, _ := deb.GeneratePDiff(v0, v1)
	p2, _ := deb.GeneratePDiff(v1, v2)

	merged, err := deb.MergePDiffs(p1, p2)
	if err != nil {
		panic(err)
	}

	got, _ := deb.ApplyPDiff(v0, merged)
	fmt.Printf("%q\n", got)
	// Output:
	// "0\n1\nx\n"
}

// A client that holds an old Packages file asks the Index for the patches
// that lead to the current one, fetches them and applies them, every file
// checked against the digests of the Index.
func ExampleParsePDiffIndex() {
	versions := [][]byte{[]byte("a\n"), []byte("a\nb\n"), []byte("a\nb\nc\n")}

	// The server side: an in-memory directory and a builder.
	dir := deb.NewPDiffMemFS()

	builder, err := deb.NewPDiffIndexBuilder(dir, deb.PDiffBuilderOptions{})
	if err != nil {
		panic(err)
	}

	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	for i := 1; i < len(versions); i++ {
		if _, err := builder.UpdateFrom(versions[i-1], versions[i], at.Add(time.Duration(i)*time.Hour)); err != nil {
			panic(err)
		}
	}

	// The client side.
	indexData, _ := dir.ReadFile("Packages.diff/Index")

	idx, err := deb.ParsePDiffIndex(indexData)
	if err != nil {
		panic(err)
	}

	chain, err := idx.Chain(deb.PDiffSHA256(versions[0]))
	if err != nil {
		panic(err)
	}

	fetch := func(p deb.PDiffPatch) ([]byte, error) { return dir.ReadFile("Packages.diff/" + p.DownloadName()) }

	got, err := deb.ApplyPDiffChain(versions[0], chain, fetch, deb.PDiffApplyOptions{})
	if err != nil {
		panic(err)
	}

	for _, p := range chain {
		fmt.Println(p.Name)
	}

	fmt.Printf("%q\n", got)
	// Output:
	// 2026-01-02-0404.05
	// 2026-01-02-0504.05
	// "a\nb\nc\n"
}

func ExamplePDiffIndexBuilder() {
	dir := deb.NewPDiffMemFS()

	builder, err := deb.NewPDiffIndexBuilder(dir, deb.PDiffBuilderOptions{MaxPatches: 2})
	if err != nil {
		panic(err)
	}

	now := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	content := []string{"a\n", "a\nb\n", "a\nb\nc\n", "a\nb\nc\nd\n"}

	// The publisher stores each new Packages file after the builder has seen
	// the one it replaces.
	_ = dir.WriteFile("Packages", []byte(content[0]))

	for i, c := range content[1:] {
		res, err := builder.Update([]byte(c), now.Add(time.Duration(i)*time.Minute))
		if err != nil {
			panic(err)
		}

		fmt.Println("added", res.Patch.Name, "removed", len(res.Removed))

		_ = dir.WriteFile("Packages", []byte(c))
	}

	fmt.Println(dir.Names())
	// Output:
	// added 2026-05-06-0708.09 removed 0
	// added 2026-05-06-0709.09 removed 0
	// added 2026-05-06-0710.09 removed 1
	// [Packages Packages.diff/2026-05-06-0709.09.gz Packages.diff/2026-05-06-0710.09.gz Packages.diff/Index]
}

func ExamplePDiffIndex_Chain() {
	idx, err := deb.ParsePDiffIndex([]byte(`SHA256-Current: ` + deb.PDiffSHA256([]byte("c\n")) + ` 2
SHA256-History:
 ` + deb.PDiffSHA256([]byte("a\n")) + ` 2 p1
 ` + deb.PDiffSHA256([]byte("b\n")) + ` 2 p2
SHA256-Patches:
 ` + deb.PDiffSHA256([]byte("1c\nb\n.\n")) + ` 7 p1
 ` + deb.PDiffSHA256([]byte("1c\nc\n.\n")) + ` 7 p2
SHA256-Download:
 ` + deb.PDiffSHA256(nil) + ` 20 p1.gz
 ` + deb.PDiffSHA256(nil) + ` 20 p2.gz
`))
	if err != nil {
		panic(err)
	}

	chain, _ := idx.Chain(deb.PDiffSHA256([]byte("a\n")))
	for _, p := range chain {
		fmt.Println(p.DownloadName())
	}

	_, err = idx.Chain(deb.PDiffSHA256([]byte("unknown\n")))
	fmt.Println(err != nil)
	// Output:
	// p1.gz
	// p2.gz
	// true
}
