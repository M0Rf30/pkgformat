package apt_test

import (
	"errors"
	"fmt"

	"github.com/M0Rf30/pkgformat/deb/apt"
)

func ExampleParseSources822() {
	sources, err := apt.ParseSources822(`Types: deb deb-src
URIs: https://deb.debian.org/debian
Suites: bookworm bookworm-updates
Components: main contrib
Architectures-Add: i386
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: file:///srv/local
Suites: ./
Enabled: no
`)
	if err != nil {
		fmt.Println(err)

		return
	}

	for _, s := range sources {
		fmt.Println(s.Type, s.URL, s.Suite, s.EffectiveArchitectures("amd64"))
	}
	// Output:
	// deb https://deb.debian.org/debian/ bookworm [amd64 i386]
	// deb https://deb.debian.org/debian/ bookworm-updates [amd64 i386]
	// deb-src https://deb.debian.org/debian/ bookworm [amd64 i386]
	// deb-src https://deb.debian.org/debian/ bookworm-updates [amd64 i386]
}

func ExampleParseSourcesList_errors() {
	sources, err := apt.ParseSourcesList(`deb [trusted=perhaps] http://a.example/ stable main
deb http://b.example/ stable main
deb ftp://c.example/debian stable main
`)

	// The good lines are returned next to the error that describes the bad one.
	var se *apt.SourceError
	if errors.As(err, &se) {
		fmt.Println("line", se.Line, "option", se.Option, errors.Is(err, apt.ErrInvalidOption))
	}

	for _, s := range sources {
		fmt.Println(s.Scheme(), s.URL)
	}
	// Output:
	// line 1 option trusted true
	// http http://b.example/
	// ftp ftp://c.example/debian/
}

func ExampleSource_EffectiveTargets() {
	src := apt.Source{Type: apt.TypeDeb, TargetsAdd: []string{"Contents"}}

	fmt.Println(src.EffectiveTargets([]string{"none"}))
	fmt.Println(src.EffectiveTargets([]string{"en"}))
	// Output:
	// [Packages Contents]
	// [Packages Translations Contents]
}

func ExampleListFileNameFor() {
	src := apt.Source{URL: "https://user:secret@deb.example.org:8443/my_repo~1/", Suite: "stable"}

	fmt.Println(apt.ListFileNameFor(&src, "InRelease"))
	fmt.Println(apt.ListFileNameFor(&src, "main/binary-amd64/Packages.xz"))

	flat := apt.Source{URL: "http://deb.example.org/flat/", Suite: "./"}

	fmt.Println(apt.ListFileNameFor(&flat, "Packages"))
	// Output:
	// deb.example.org:8443_my%5frepo%7e1_dists_stable_InRelease
	// deb.example.org:8443_my%5frepo%7e1_dists_stable_main_binary-amd64_Packages.xz
	// deb.example.org_flat_._Packages
}

func ExampleLoadKeyring() {
	// Signed-By may hold fingerprints, keyring paths or an inline key; here a
	// fingerprint that no keyring holds.
	_, err := apt.LoadKeyring("0123456789ABCDEF0123456789ABCDEF01234567", nil)

	var nf *apt.KeyNotFoundError

	fmt.Println(errors.As(err, &nf))
	// Output: true
}
