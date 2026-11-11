package pack

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
)

// verifyFileSignatures checks every IMA and fs-verity signature of a package
// written by pack with the verifiers of the rpm package, against the test
// certificate, and that a changed digest is rejected.
func verifyFileSignatures(t *testing.T, raw []byte) {
	t.Helper()

	keys := loadSigningKeys(t)

	pkg, err := rpm.ReadPackage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	payload, err := rpm.ReadRpm(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	contents := map[string][]byte{}

	r, err := payload.PayloadReaderExtended()
	if err != nil {
		t.Fatal(err)
	}

	for {
		f, err := r.Next()
		if err != nil {
			break
		}

		if f.Mode()&0o170000 == 0o100000 {
			var b bytes.Buffer
			if _, err := b.ReadFrom(r); err != nil {
				t.Fatal(err)
			}

			contents["/"+strings.TrimPrefix(strings.TrimPrefix(f.Name(), "."), "/")] = b.Bytes()
		}
	}

	checked := 0

	for _, f := range pkg.Files {
		if f.IMASignature != "" {
			digest, err := hex.DecodeString(f.Digest)
			if err != nil {
				t.Fatal(err)
			}

			if err := rpm.VerifyIMASignature([]byte(f.IMASignature), digest, keys.IMAKey.Public()); err != nil {
				t.Errorf("%s: IMA: %v", f.Path, err)
			}

			digest[0] ^= 1
			if rpm.VerifyIMASignature([]byte(f.IMASignature), digest, keys.IMAKey.Public()) == nil {
				t.Errorf("%s: IMA signature accepted a wrong digest", f.Path)
			}

			checked++
		}

		if f.VeritySignature != "" {
			// entries without contents (directories, links, ghosts) are
			// signed over empty contents, as rpmsign does
			body := contents[f.Path]

			digest, err := rpm.FSVerityDigest(bytes.NewReader(body), pkg.VeritySignatureAlgorithm)
			if err != nil {
				t.Fatal(err)
			}

			certs := []*x509.Certificate{keys.VerityCert}
			if err := rpm.VerifyVeritySignature([]byte(f.VeritySignature), digest, pkg.VeritySignatureAlgorithm, certs); err != nil {
				t.Errorf("%s: fs-verity: %v", f.Path, err)
			}

			checked++
		}
	}

	if checked == 0 {
		t.Fatal("no file signature checked")
	}
}
