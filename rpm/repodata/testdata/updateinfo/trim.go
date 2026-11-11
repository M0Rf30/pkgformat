//go:build ignore

// trim keeps some advisories of an updateinfo.xml, byte for byte, and drops the
// others:
//
//	go run trim.go updateinfo.xml ID... > sample.xml
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: trim updateinfo.xml ID...")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	doc := string(data)
	first := strings.Index(doc, "  <update ")
	if first < 0 {
		fmt.Fprintln(os.Stderr, "no <update> element")
		os.Exit(1)
	}

	blocks := regexp.MustCompile(`(?s)  <update .*?\n  </update>\n`).FindAllString(doc, -1)
	out := doc[:first]

	for _, id := range os.Args[2:] {
		found := false

		for _, b := range blocks {
			if strings.Contains(b, "<id>"+id+"</id>") {
				out += b
				found = true

				break
			}
		}

		if !found {
			fmt.Fprintln(os.Stderr, "advisory not found:", id)
			os.Exit(1)
		}
	}

	fmt.Print(out + "</updates>\n")
}
