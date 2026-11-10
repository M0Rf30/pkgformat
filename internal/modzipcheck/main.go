// Command modzipcheck builds the module zip of the committed tree, as the Go
// module proxy would for a tag, and fails when any file breaks the module zip
// rules. Run it from the repository root.
package main

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/mod/module"
	"golang.org/x/mod/zip"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "modzipcheck:", err)
		os.Exit(1)
	}
}

func run() error {
	// The version only labels the zip; any valid one checks the same files.
	mod := module.Version{Path: "github.com/M0Rf30/pkgformat", Version: "v0.0.0-check"}

	if err := zip.CreateFromVCS(io.Discard, mod, ".", "HEAD", ""); err != nil {
		return err
	}

	fmt.Println("modzipcheck: module zip is valid")

	return nil
}
