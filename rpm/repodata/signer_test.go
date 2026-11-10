package repodata

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/M0Rf30/pkgformat/gpg"
)

func newTestSigner(t *testing.T) *gpg.LocalSigner {
	t.Helper()

	entity, err := gpg.GenerateEntity("Repo Test", "", "repo@example.invalid", gpg.AlgorithmED25519)
	if err != nil {
		t.Fatal(err)
	}

	s, err := gpg.NewLocalSignerFromEntity(entity)
	if err != nil {
		t.Fatal(err)
	}

	return s
}

func TestSignRepomdXML(t *testing.T) {
	signer := newTestSigner(t)
	repomd, err := GenerateRepomdXML("1", []RepomdData{{Type: "primary", Location: "repodata/p.xml.gz", Checksum: "ab", ChecksumType: "sha256"}})
	if err != nil {
		t.Fatal(err)
	}

	sig, err := SignRepomdXML(signer, repomd)
	if err != nil {
		t.Fatal(err)
	}

	kr, err := signer.Keyring()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := gpg.VerifyDetached(kr, bytes.NewReader(repomd), sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	if _, err := gpg.VerifyDetached(kr, bytes.NewReader(append(repomd, ' ')), sig); err == nil {
		t.Error("a changed repomd.xml must not verify")
	}
}

// TestSignRepomdXMLWithGnuPG checks the signature and the exported key with
// gpg itself, as a client with repo_gpgcheck does.
func TestSignRepomdXMLWithGnuPG(t *testing.T) {
	gpgBin, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg is not installed")
	}

	signer := newTestSigner(t)
	repomd := []byte("<repomd></repomd>\n")

	sig, err := SignRepomdXML(signer, repomd)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := PublicKey(signer)
	if err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	dir := t.TempDir()

	files := map[string][]byte{"repomd.xml": repomd, "repomd.xml.asc": sig, "key.asc": pub}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command(gpgBin, append([]string{"--homedir", home, "--batch", "--no-tty"}, args...)...)
		cmd.Dir = dir

		return cmd.CombinedOutput()
	}

	if out, err := run("--import", "key.asc"); err != nil {
		t.Fatalf("import: %v\n%s", err, out)
	}

	if out, err := run("--verify", "repomd.xml.asc", "repomd.xml"); err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
}

func TestSignRepomdXMLErrors(t *testing.T) {
	if _, err := SignRepomdXML(nil, []byte("x")); !errors.Is(err, ErrSignerNil) {
		t.Errorf("nil signer: %v", err)
	}

	if _, err := SignRepomdXML(newTestSigner(t), nil); !errors.Is(err, ErrEmptyRepomd) {
		t.Errorf("empty repomd: %v", err)
	}

	if _, err := PublicKey(nil); !errors.Is(err, ErrSignerNil) {
		t.Errorf("nil signer key: %v", err)
	}
}
