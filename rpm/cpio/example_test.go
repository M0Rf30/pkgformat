package cpio_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/M0Rf30/pkgformat/rpm/cpio"
)

func Example() {
	var buf bytes.Buffer
	w := cpio.NewWriter(&buf)
	content := []byte("hello\n")
	if err := w.WriteHeader(&cpio.Header{Name: "hello.txt", Mode: 0o644, Size: int64(len(content))}); err != nil {
		log.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil { // writes the trailer
		log.Fatal(err)
	}

	r := cpio.NewReader(&buf)
	for {
		h, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		body, err := io.ReadAll(r)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %q\n", h.Filename(), body)
	}
	// Output: hello.txt: "hello\n"
}
