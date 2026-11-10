package rpm_test

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/M0Rf30/pkgformat/rpm"
)

func ExampleReadPackage() {
	f, err := os.Open("testdata/weakdeps.rpm")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	pkg, err := rpm.ReadPackage(f)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s %d:%s-%s.%s\n", pkg.Name, pkg.Epoch, pkg.Version, pkg.Release, pkg.Arch)

	for _, d := range pkg.Requires {
		if d.IsRPMLib() {
			continue
		}

		fmt.Println("requires", strings.TrimSpace(d.Name+" "+rpm.SenseFlagsString(d.Flags)+" "+d.Version))
	}

	fmt.Println("recommends", pkg.Recommends[0].Name)
	// Output:
	// weakdep-test 1:1.0-1.noarch
	// requires required-pkg GE 1.5-3
	// requires shadow-utils
	// recommends recommended-pkg
}

func ExampleSign() {
	entity, err := gpg.GenerateEntity("Example", "", "example@example.invalid", gpg.AlgorithmED25519)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := gpg.NewLocalSignerFromEntity(entity)
	if err != nil {
		log.Fatal(err)
	}

	src, err := os.Open("testdata/hello.rpm")
	if err != nil {
		log.Fatal(err)
	}
	defer src.Close()

	var signed bytes.Buffer
	if err := rpm.Sign(src, &signed, signer); err != nil {
		log.Fatal(err)
	}

	_, sigs, err := rpm.Verify(bytes.NewReader(signed.Bytes()), openpgp.EntityList{entity})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(sigs) > 0)
	// Output: true
}
