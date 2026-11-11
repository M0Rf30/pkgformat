package repodata_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

const zchunkExampleDoc = `<?xml version="1.0"?>
<metadata packages="3">
<package><name>a</name></package>
<package><name>b</name></package>
<package><name>c</name></package>
</metadata>`

// Write a document as a zchunk file with a chunk per package, and read it
// back.
func ExampleZchunkWriter() {
	var file bytes.Buffer

	zw, err := repodata.NewZchunkWriter(&file, repodata.ZchunkOptions{Chunking: repodata.ZchunkXMLPackages})
	if err != nil {
		log.Fatal(err)
	}

	if _, err := io.WriteString(zw, zchunkExampleDoc); err != nil {
		log.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}

	zr, err := repodata.NewZchunkReader(bytes.NewReader(file.Bytes()), repodata.ZchunkReadOptions{})
	if err != nil {
		log.Fatal(err)
	}

	doc, err := io.ReadAll(zr)
	if err != nil {
		log.Fatal(err)
	}

	h := zr.Header()
	fmt.Println(len(h.Chunks), "chunks,", h.UncompressedSize() == int64(len(doc)), bytes.Equal(doc, []byte(zchunkExampleDoc)))
	// Output: 4 chunks, true true
}

// A client that has an older copy of a zchunk file fetches the header of the
// new one (the header-size bytes of repomd.xml), compares the chunk lists, and
// requests only the ranges of the chunks it lacks.
func ExampleZchunkHeader_MissingChunks() {
	build := func(doc string) *repodata.ZchunkHeader {
		var file bytes.Buffer

		zw, err := repodata.NewZchunkWriter(&file, repodata.ZchunkOptions{Chunking: repodata.ZchunkXMLPackages})
		if err != nil {
			log.Fatal(err)
		}

		_, _ = io.WriteString(zw, doc)

		if err := zw.Close(); err != nil {
			log.Fatal(err)
		}

		h, err := repodata.ReadZchunkHeader(&file, repodata.ZchunkReadOptions{})
		if err != nil {
			log.Fatal(err)
		}

		return h
	}

	oldH := build(zchunkExampleDoc)
	newH := build(strings.NewReplacer(`packages="3"`, `packages="4"`, "</metadata>", "<package><name>d</name></package>\n</metadata>").Replace(zchunkExampleDoc))

	missing := newH.MissingChunks(oldH)
	fmt.Println(len(missing), "of", len(newH.Chunks), "chunks to fetch in", len(repodata.ByteRanges(missing)), "ranges")
	// Output: 3 of 5 chunks to fetch in 2 ranges
}
