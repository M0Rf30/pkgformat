package source_test

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/M0Rf30/pkgformat/deb/source"
)

func ExampleParseDSC() {
	data, err := os.ReadFile(filepath.Join("testdata", "packages", "hello", "hello_2.10-5.dsc"))
	if err != nil {
		log.Fatal(err)
	}

	d, err := source.ParseDSC(data)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(d.Source, d.Version, d.Format)

	for _, f := range d.Files {
		fmt.Println(f.Name, f.Size)
	}

	deps, _ := d.Relations("Build-Depends")
	fmt.Println(deps)
	// Output:
	// hello 2.10-5 3.0 (quilt)
	// hello_2.10.orig.tar.gz 725946
	// hello_2.10.orig.tar.gz.asc 819
	// hello_2.10-5.debian.tar.xz 13112
	// [debhelper-compat (= 13) texinfo]
}

func ExampleUnpack() {
	dir := filepath.Join("testdata", "packages", "sl")

	m, _ := filepath.Glob(filepath.Join(dir, "*.dsc"))

	data, err := os.ReadFile(m[0])
	if err != nil {
		log.Fatal(err)
	}

	d, err := source.ParseDSC(data)
	if err != nil {
		log.Fatal(err)
	}

	// Checksums are verified, the orig and debian tarballs extracted and the
	// quilt patches applied, as dpkg-source -x does.
	tmp, _ := os.MkdirTemp("", "unpack")
	defer os.RemoveAll(tmp)

	dest := filepath.Join(tmp, "sl")
	if err := source.Unpack(d, dir, dest, nil); err != nil {
		log.Fatal(err)
	}

	_, err = os.Stat(filepath.Join(dest, "debian", "control"))
	fmt.Println(err)
	// Output: <nil>
}

func ExampleIndexSources() {
	entries, err := source.IndexSources(filepath.Join("testdata", "packages", "sl"), &source.SourcesOptions{Directory: "pool/main/s/sl"})
	if err != nil {
		log.Fatal(err)
	}

	var buf bytes.Buffer
	if err := source.WriteSources(&buf, entries, "gzip"); err != nil {
		log.Fatal(err)
	}

	back, err := source.ReadSources(&buf, "Sources.gz")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(back[0].Source, back[0].Directory)
	// Output: sl pool/main/s/sl
}

func ExampleParseChanges() {
	data, err := os.ReadFile(filepath.Join("testdata", "changes", "full", "hello_2.10-5_amd64.changes"))
	if err != nil {
		log.Fatal(err)
	}

	c, err := source.ParseChanges(data)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(c.Source, c.Version, c.Architecture, c.Distribution, c.Closes)
	// Output: hello 2.10-5 [source amd64] unstable [1103293]
}

func ExampleParseBuildInfo() {
	data, err := os.ReadFile(filepath.Join("testdata", "changes", "binary", "hello_2.10-5_amd64.buildinfo"))
	if err != nil {
		log.Fatal(err)
	}

	b, err := source.ParseBuildInfo(data)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(b.Source, b.BuildArchitecture, b.InstalledBuildDepends[0], b.Environment[0].Name)
	// Output: hello amd64 autoconf (= 2.71-3) DEB_BUILD_OPTIONS
}
