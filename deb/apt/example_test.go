package apt_test

import (
	"fmt"

	"github.com/M0Rf30/pkgformat/deb/apt"
)

func ExampleParseSourcesList() {
	sources := apt.ParseSourcesList(`
# main archive
deb [arch=amd64] https://deb.debian.org/debian bookworm main contrib
deb-src https://deb.debian.org/debian bookworm main
`)

	for _, s := range sources {
		fmt.Println(s.URL, s.Suite, s.Components, s.Architectures)
	}
	// Output:
	// https://deb.debian.org/debian/ bookworm [main contrib] [amd64]
}

func ExampleCache_ResolveDeps() {
	c := apt.NewCache("amd64")

	for _, p := range []*apt.PackageInfo{
		{Name: "app", Architecture: "amd64", HasCandidate: true, Version: "1.0",
			Filename: "pool/main/a/app/app_1.0_amd64.deb", Depends: []string{"libfoo", "mta"}},
		{Name: "libfoo", Architecture: "amd64", HasCandidate: true, Version: "2.1",
			Filename: "pool/main/libf/libfoo/libfoo_2.1_amd64.deb"},
		{Name: "exim4", Architecture: "amd64", HasCandidate: true, Version: "4.96",
			Filename: "pool/main/e/exim4/exim4_4.96_amd64.deb"},
	} {
		c.AddEntry(p)
	}

	order, unresolved, err := c.ResolveDeps([]string{"app"})
	if err != nil {
		fmt.Println(err)

		return
	}

	for _, p := range order {
		fmt.Println(p.Name, p.Version)
	}

	fmt.Println("unresolved:", unresolved)
	// Output:
	// libfoo 2.1
	// app 1.0
	// unresolved: [mta]
}
