package apk

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func signedWith(t *testing.T, s *Signer) []byte {
	t.Helper()

	raw, _ := mustWrite(t, sampleSpec(), WriteOptions{Signer: s, TempDir: t.TempDir()})

	return raw
}

func signerFor(t *testing.T, alg SigAlgorithm) *Signer {
	t.Helper()

	s, err := NewSigner("pkgformat-test.rsa.pub", testKey(t), alg)
	if err != nil {
		t.Fatal(err)
	}

	return s
}

func TestVerifyPackage(t *testing.T) {
	sha1s, sha256s := signerFor(t, SigRSASHA1), signerFor(t, SigRSASHA256)
	ring := keyringOf(t, sha1s) // the same key under the same name for both

	other, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	otherSigner, err := NewSigner("pkgformat-test.rsa.pub", other, SigRSASHA256)
	if err != nil {
		t.Fatal(err)
	}

	renamed, err := NewSigner("someone-else.rsa.pub", testKey(t), SigRSASHA256)
	if err != nil {
		t.Fatal(err)
	}

	all := []SigAlgorithm{SigRSASHA1, SigRSASHA256}

	for _, tc := range []struct {
		name string
		raw  []byte
		opts VerifyOptions
		want error
	}{
		{"sha256", signedWith(t, sha256s), VerifyOptions{Keys: ring, Algorithms: all}, nil},
		{"sha1", signedWith(t, sha1s), VerifyOptions{Keys: ring, Algorithms: all}, nil},
		{"sha1 only accepted when listed", signedWith(t, sha1s), VerifyOptions{Keys: ring, Algorithms: []SigAlgorithm{SigRSASHA256}}, ErrUntrusted},
		{"sha256 not listed", signedWith(t, sha256s), VerifyOptions{Keys: ring, Algorithms: []SigAlgorithm{SigRSASHA1}}, ErrUntrusted},
		{"unsigned", func() []byte { r, _ := mustWrite(t, sampleSpec(), WriteOptions{TempDir: t.TempDir()}); return r }(), VerifyOptions{Keys: ring, Algorithms: all}, ErrUnsigned},
		{"wrong key under a trusted name", signedWith(t, otherSigner), VerifyOptions{Keys: ring, Algorithms: all}, ErrBadSignature},
		{"unknown key name", signedWith(t, renamed), VerifyOptions{Keys: ring, Algorithms: all}, ErrUntrusted},
		{"no keys", signedWith(t, sha256s), VerifyOptions{Algorithms: all}, ErrNoKeyring},
		{"no algorithms", signedWith(t, sha256s), VerifyOptions{Keys: ring}, ErrNoAlgorithm},
		{"zero algorithm", signedWith(t, sha256s), VerifyOptions{Keys: ring, Algorithms: []SigAlgorithm{0}}, ErrNoAlgorithm},
		{"garbage", []byte("not a package"), VerifyOptions{Keys: ring, Algorithms: all}, ErrInvalidPackage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := VerifyPackage(bytes.NewReader(tc.raw), int64(len(tc.raw)), tc.opts)
			if !errors.Is(err, tc.want) || (tc.want == nil && (p == nil || !p.Signed)) {
				t.Fatalf("got %v, %+v; want %v", err, p, tc.want)
			}
		})
	}
}

func TestVerifyPackage_tampered(t *testing.T) {
	s := signerFor(t, SigRSASHA256)
	raw := signedWith(t, s)
	opts := VerifyOptions{Keys: keyringOf(t, s), Algorithms: []SigAlgorithm{SigRSASHA256}}

	// Change the description inside the control segment: the signature no
	// longer covers it. The gzip is stored, so flip bytes via a rewritten
	// package with another description signed by the original signature.
	other := sampleSpec()
	other.Info.Description = "Prints something else"

	forged, _ := mustWrite(t, other, WriteOptions{TempDir: t.TempDir()})

	sigLen := len(raw) - len(rawFromUnsigned(t, sampleSpec()))
	forged = append(append([]byte{}, raw[:sigLen]...), forged...)

	if _, err := VerifyPackage(bytes.NewReader(forged), int64(len(forged)), opts); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func rawFromUnsigned(t *testing.T, spec *Spec) []byte {
	t.Helper()

	raw, _ := mustWrite(t, spec, WriteOptions{TempDir: t.TempDir()})

	return raw
}

func TestVerifyIndex(t *testing.T) {
	sha256s := signerFor(t, SigRSASHA256)
	ring := keyringOf(t, sha256s)
	opts := VerifyOptions{Keys: ring, Algorithms: []SigAlgorithm{SigRSASHA256}}

	signed, err := BuildIndex(samplePackages(), "d", sha256s)
	if err != nil {
		t.Fatal(err)
	}

	unsigned, err := BuildIndex(samplePackages(), "d", nil)
	if err != nil {
		t.Fatal(err)
	}

	pkgs, err := VerifyIndex(signed, opts)
	if err != nil || len(pkgs) != len(samplePackages()) {
		t.Fatalf("%d packages, %v", len(pkgs), err)
	}

	for name, tc := range map[string]struct {
		data []byte
		opts VerifyOptions
		want error
	}{
		"unsigned":      {unsigned, opts, ErrUnsigned},
		"plain text":    {RenderIndex(samplePackages()), opts, ErrUnsigned},
		"sha1 refused":  {signed, VerifyOptions{Keys: ring, Algorithms: []SigAlgorithm{SigRSASHA1}}, ErrUntrusted},
		"no keys":       {signed, VerifyOptions{Algorithms: []SigAlgorithm{SigRSASHA256}}, ErrNoKeyring},
		"no algorithms": {signed, VerifyOptions{Keys: ring}, ErrNoAlgorithm},
		"other key":     {signed, VerifyOptions{Keys: NewKeyring(), Algorithms: []SigAlgorithm{SigRSASHA256}}, ErrUntrusted},
		"garbage":       {[]byte("\x1f\x8bjunk"), opts, ErrInvalidIndex},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyIndex(tc.data, tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	// A different index under the original signature must not verify.
	forgedIndex, err := BuildIndex(samplePackages()[:1], "d", nil)
	if err != nil {
		t.Fatal(err)
	}

	sigPart := signed[:len(signed)-len(unsigned)]
	if _, err := VerifyIndex(append(append([]byte{}, sigPart...), forgedIndex...), opts); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("spliced index: %v", err)
	}
}

func TestKeyring(t *testing.T) {
	s := signerFor(t, SigRSASHA256)
	k := NewKeyring()

	if err := k.Add("a.rsa.pub", s.PublicKey()); err != nil {
		t.Fatal(err)
	}

	if err := k.Add("a/b.rsa.pub", s.PublicKey()); err == nil {
		t.Fatal("unsafe key name accepted")
	}

	if err := k.Add("c.rsa.pub", nil); err == nil {
		t.Fatal("nil key accepted")
	}

	if k.Len() != 1 {
		t.Fatalf("len %d", k.Len())
	}

	if _, ok := k.Lookup("a.rsa.pub"); !ok {
		t.Fatal("key not found")
	}

	if _, ok := k.Lookup("zz"); ok {
		t.Fatal("unknown key found")
	}
}

func TestLoadKeyring(t *testing.T) {
	s := signerFor(t, SigRSASHA256)

	pemKey, err := s.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	files := map[string][]byte{
		"good.rsa.pub":   pemKey,
		"other.txt":      []byte("ignored: not a .pub file"),
		"broken.rsa.pub": []byte("not pem"),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := LoadKeyring(dir); err == nil {
		t.Fatal("a broken key file must fail the load")
	}

	if err := os.Remove(filepath.Join(dir, "broken.rsa.pub")); err != nil {
		t.Fatal(err)
	}

	k, err := LoadKeyring(dir)
	if err != nil || k.Len() != 1 {
		t.Fatalf("%v, %d keys", err, k.Len())
	}

	if err := os.WriteFile(filepath.Join(dir, "huge.rsa.pub"), bytes.Repeat([]byte("A"), maxKeyFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadKeyring(dir); err == nil {
		t.Fatal("oversized key file accepted")
	}

	if _, err := LoadKeyring(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing directory accepted")
	}
}

func TestSigAlgorithm_string(t *testing.T) {
	for alg, want := range map[SigAlgorithm]string{SigRSASHA1: "RSA-SHA1", SigRSASHA256: "RSA-SHA256", 0: "invalid"} {
		if got := alg.String(); !strings.Contains(got, strings.Split(want, "-")[0]) {
			t.Errorf("%d: %q", alg, got)
		}
	}
}

func TestParsePackage_signatureEntries(t *testing.T) {
	fx := newFixture(t, "")
	name := ".SIGN.RSA256.pkgformat-test.rsa.pub"

	sigs := func(entries ...tarEntry) []byte { return gz(t, tarBytes(t, entries, false)) }

	many := make([]tarEntry, 0, maxSignatures+1)
	for i := range maxSignatures + 1 {
		many = append(many, tarEntry{name: name[:len(name)-1] + string(rune('a'+i)), body: "x"})
	}

	for label, sig := range map[string][]byte{
		"directory":     sigs(tarEntry{name: name, typ: tar.TypeDir}),
		"symlink":       sigs(tarEntry{name: name, typ: tar.TypeSymlink, link: "x"}),
		"oversized":     sigs(tarEntry{name: name, body: strings.Repeat("x", maxSignatureLen+1)}),
		"too many":      sigs(many...),
		"not signature": sigs(tarEntry{name: "README", body: "x"}),
	} {
		t.Run(label, func(t *testing.T) {
			raw := concat(sig, fx.control, fx.data)

			if _, err := ParsePackage(bytes.NewReader(raw), int64(len(raw))); !errors.Is(err, ErrInvalidPackage) {
				t.Fatalf("got %v, want ErrInvalidPackage", err)
			}
		})
	}

	// An unknown signature type parses but is never trusted.
	raw := concat(sigs(tarEntry{name: ".SIGN.DSA.k.pub", body: "x"}), fx.control, fx.data)

	p, err := ParsePackage(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || !p.Signed {
		t.Fatalf("%+v, %v", p, err)
	}

	s := signerFor(t, SigRSASHA256)

	_, err = VerifyPackage(bytes.NewReader(raw), int64(len(raw)), VerifyOptions{Keys: keyringOf(t, s), Algorithms: []SigAlgorithm{SigRSASHA256}})
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
}
