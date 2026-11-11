//go:build ignore

// strip keeps the lead, signature header and general header of an rpm and
// drops its payload. The result is still a package every reader of metadata
// understands, and small enough to commit.
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/M0Rf30/pkgformat/rpm"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: strip in.rpm out.rpm")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	pkg, err := rpm.ReadPackage(bytes.NewReader(data))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := os.WriteFile(os.Args[2], data[:pkg.HeaderEnd], 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
