package rpm

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm/tag"
	"github.com/ProtonMail/go-crypto/openpgp"
)

// signing key of testdata/v6/ref-v6s.rpm, see testdata/v6/README.md
const v6KeyID = 0x1E66303A75B7A873

func readV6(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/v6/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func v6Keyring(t *testing.T) openpgp.EntityList {
	t.Helper()
	f, err := os.Open("testdata/v6/testkey.pub")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	kr, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func TestV6PayloadExtraction(t *testing.T) {
	rpm, err := ReadRpm(bytes.NewReader(readV6(t, "ref-v6.rpm")))
	if err != nil {
		t.Fatal(err)
	}
	if got := rpm.Header.Format(); got != 6 {
		t.Fatalf("Format() = %d, want 6", got)
	}
	pr, err := rpm.PayloadReaderExtended()
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{}
	modes := map[string]FileInfo{}
	for {
		fi, err := pr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading payload: %v", err)
		}
		data, err := io.ReadAll(pr)
		if err != nil {
			t.Fatal(err)
		}
		contents[fi.Name()] = string(data)
		modes[fi.Name()] = fi
	}
	if len(contents) != 3 {
		t.Fatalf("got %d entries, want 3: %q", len(contents), contents)
	}
	var sawFile, sawLink, sawDir bool
	for name, fi := range modes {
		switch {
		case strings.HasSuffix(name, "/a.txt"):
			sawFile = true
			if contents[name] != "hi\n" || fi.Size() != 3 {
				t.Errorf("%s: content %q size %d", name, contents[name], fi.Size())
			}
		case fi.Linkname() == "a.txt":
			sawLink = true
			if contents[name] != "a.txt" {
				t.Errorf("%s: symlink content %q", name, contents[name])
			}
		default:
			sawDir = true
			if contents[name] != "" {
				t.Errorf("%s: dir has content %q", name, contents[name])
			}
		}
	}
	if !sawFile || !sawLink || !sawDir {
		t.Errorf("missing entries: file=%v link=%v dir=%v: %q", sawFile, sawLink, sawDir, contents)
	}
}

func TestV6VerifyUnsigned(t *testing.T) {
	hdr, sigs, err := Verify(bytes.NewReader(readV6(t, "ref-v6.rpm")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 0 {
		t.Fatalf("got %d sigs, want 0", len(sigs))
	}
	if hdr.Format() != 6 {
		t.Fatalf("Format() = %d", hdr.Format())
	}
	if size, err := hdr.PayloadSize(); err != nil || size <= 0 {
		t.Fatalf("PayloadSize() = %d, %v", size, err)
	}
	files, err := hdr.GetFiles()
	if err != nil {
		t.Fatal(err)
	}
	var sizes int64
	for _, f := range files {
		if strings.HasSuffix(f.Name(), "/a.txt") {
			sizes = f.Size()
		}
	}
	if sizes != 3 {
		t.Fatalf("a.txt size = %d, want 3 (LONGFILESIZES)", sizes)
	}
}

func TestV6VerifySigned(t *testing.T) {
	kr := v6Keyring(t)
	_, sigs, err := Verify(bytes.NewReader(readV6(t, "ref-v6s.rpm")), kr)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 {
		t.Fatalf("got %d sigs, want 1", len(sigs))
	}
	if !sigs[0].HeaderOnly || sigs[0].KeyId != v6KeyID || sigs[0].Signer == nil {
		t.Fatalf("unexpected signature: %+v", sigs[0])
	}

	// no keys known: digests only, key ID still reported
	_, sigs, err = Verify(bytes.NewReader(readV6(t, "ref-v6s.rpm")), nil)
	if err != nil || len(sigs) != 1 || sigs[0].KeyId != v6KeyID {
		t.Fatalf("nil keyring: sigs=%v err=%v", sigs, err)
	}

	// empty keyring: key must not be found
	_, _, err = Verify(bytes.NewReader(readV6(t, "ref-v6s.rpm")), openpgp.EntityList{})
	var knf KeyNotFoundError
	if !errors.As(err, &knf) || knf.KeyID != v6KeyID {
		t.Fatalf("got %v, want KeyNotFoundError for %x", err, v6KeyID)
	}
}

func TestV6VerifyTampered(t *testing.T) {
	for _, name := range []string{"ref-v6.rpm", "ref-v6s.rpm"} {
		orig := readV6(t, name)
		hdr, err := ReadHeader(bytes.NewReader(orig))
		if err != nil {
			t.Fatal(err)
		}
		r := hdr.GetRange()
		kr := v6Keyring(t)

		payload := append([]byte(nil), orig...)
		payload[r.End+(len(orig)-r.End)/2] ^= 0xff
		_, _, err = Verify(bytes.NewReader(payload), kr)
		if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
			t.Errorf("%s: tampered payload: got %v, want digest mismatch", name, err)
		}

		header := append([]byte(nil), orig...)
		header[r.End-1] ^= 0x01
		_, _, err = Verify(bytes.NewReader(header), kr)
		if err == nil || !strings.Contains(err.Error(), "mismatch in signature header") {
			t.Errorf("%s: tampered header: got %v, want header digest mismatch", name, err)
		}
	}
}

// With header-only signatures, a tampered header whose digests have been
// stripped from the signature header must still not verify.
func TestV6SignedHeaderBadSignature(t *testing.T) {
	orig := readV6(t, "ref-v6s.rpm")
	hdr, err := ReadHeader(bytes.NewReader(orig))
	if err != nil {
		t.Fatal(err)
	}
	// drop the header digests so only the OpenPGP signature protects the header
	delete(hdr.sigHeader.entries, tag.SIG_SHA256)
	delete(hdr.sigHeader.entries, tag.SIG_SHA3_256)
	r := hdr.GetRange()
	sigblob, err := hdr.DumpSignatureHeader(false)
	if err != nil {
		t.Fatal(err)
	}
	rest := append([]byte(nil), orig[r.Start:]...)
	// control: the rewritten package without tampering verifies
	if _, sigs, err := Verify(bytes.NewReader(append(append([]byte(nil), sigblob...), rest...)), v6Keyring(t)); err != nil || len(sigs) != 1 {
		t.Fatalf("control failed: sigs=%v err=%v", sigs, err)
	}
	// flip the last byte of the main header
	rest[r.End-r.Start-1] ^= 0x01
	_, _, err = Verify(bytes.NewReader(append(sigblob, rest...)), v6Keyring(t))
	if err == nil {
		t.Fatal("tampered header verified")
	}
}
