package gpg_test

import (
	"fmt"
	"strings"

	"github.com/M0Rf30/pkgformat/gpg"
)

func Example() {
	entity, _ := gpg.GenerateEntity("Repo Signer", "", "repo@example.com", gpg.AlgorithmED25519)
	signer, _ := gpg.NewLocalSignerFromEntity(entity)

	release := "Suite: stable\nCodename: bookworm\n"

	// Sign: a detached signature, binary as a pacman .sig file holds it.
	sig, _ := signer.DetachedSignBinary(strings.NewReader(release))

	// Verify against the signer's public key.
	keyring, _ := signer.Keyring()

	v, err := gpg.VerifyDetached(keyring, strings.NewReader(release), sig)
	fmt.Println(v.Identity, err)

	_, err = gpg.VerifyDetached(keyring, strings.NewReader(release+"tampered"), sig)
	fmt.Println(err != nil)

	// Output:
	// Repo Signer <repo@example.com> <nil>
	// true
}
