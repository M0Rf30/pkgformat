package apk

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// verifyErr reports whether err is one of the typed failures of verification.
func verifyErr(err error) bool {
	for _, target := range []error{
		ErrInvalidPackage, ErrInvalidIndex, ErrUnsigned, ErrUntrusted, ErrBadSignature,
	} {
		if errors.Is(err, target) {
			return true
		}
	}

	return false
}

func verifyOpts(tb fataler) VerifyOptions {
	s := testSigner(tb)
	ring := NewKeyring()

	if err := ring.Add(s.KeyName(), s.PublicKey()); err != nil {
		tb.Fatalf("%v", err)
	}

	return VerifyOptions{Keys: ring, Algorithms: []SigAlgorithm{SigRSASHA1, SigRSASHA256}}
}

func FuzzVerifyPackage(f *testing.F) {
	for _, kind := range []string{"", "sha256", "sha1"} {
		f.Add(newFixture(f, kind).bytes())
	}

	opts := verifyOpts(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := VerifyPackage(bytes.NewReader(data), int64(len(data)), opts)
		if err != nil {
			if !verifyErr(err) {
				t.Fatalf("untyped error: %v", err)
			}

			return
		}

		if !p.Signed {
			t.Fatalf("verified package is not signed: %+v", p)
		}
	})
}

func FuzzVerifyIndex(f *testing.F) {
	signed, err := BuildIndex(samplePackages(), "d", testSigner(f))
	if err != nil {
		f.Fatalf("%v", err)
	}

	unsigned, err := BuildIndex(samplePackages(), "d", nil)
	if err != nil {
		f.Fatalf("%v", err)
	}

	f.Add(signed)
	f.Add(unsigned)
	f.Add(RenderIndex(samplePackages()))

	opts := verifyOpts(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		pkgs, err := VerifyIndex(data, opts)
		if err != nil {
			if !verifyErr(err) {
				t.Fatalf("untyped error: %v", err)
			}

			return
		}

		sameIndex(t, pkgs)
	})
}

func FuzzParseRepositories(f *testing.F) {
	for _, s := range []string{
		"https://example.org/main\n", "@edge https://example.org/edge/\n# c\n\n", "@\n", "a b c\n", "\x00\xff", "@t",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		repos, err := ParseRepositories(strings.NewReader(s))
		if err != nil {
			if !errors.Is(err, ErrInvalidRepositories) {
				t.Fatalf("untyped error: %v", err)
			}

			return
		}

		for _, r := range repos {
			if r.URL == "" || strings.HasSuffix(r.URL, "/") || strings.ContainsAny(r.URL+r.Tag, " \t\r\n") {
				t.Fatalf("bad repository %+v", r)
			}
		}
	})
}

func FuzzParsePublicKeyPEM(f *testing.F) {
	pemKey, err := testSigner(f).PublicKeyPEM()
	if err != nil {
		f.Fatalf("%v", err)
	}

	f.Add(pemKey)
	f.Add([]byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"))
	f.Add([]byte("-----BEGIN RSA PUBLIC KEY-----\n-----END RSA PUBLIC KEY-----\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := ParsePublicKeyPEM(data)
		if err != nil {
			if !errors.Is(err, errKey) {
				t.Fatalf("untyped error: %v", err)
			}

			return
		}

		if key.N.BitLen() < 2048 {
			t.Fatalf("accepted a %d-bit key", key.N.BitLen())
		}
	})
}

func FuzzSolve(f *testing.F) {
	f.Add(RenderIndex(samplePackages()), "hello")
	f.Add([]byte("P:a\nV:1\nA:noarch\nD:b c>=1 !d\np:x=1\n\nP:b\nV:1\nA:noarch\nD:a\n"), "a")

	f.Fuzz(func(t *testing.T, data []byte, want string) {
		pkgs, err := ParseIndex(bytes.NewReader(data))
		if err != nil || len(pkgs) == 0 {
			return
		}

		idx := NewIndex()
		idx.Add(Repo{URL: "https://example.org"}, "x86_64", pkgs)

		seeds := []string{want}
		for i := range pkgs {
			seeds = append(seeds, pkgs[i].Name)
		}

		res, err := idx.Solve(SolveRequest{World: seeds})
		if err != nil {
			if !errors.Is(err, ErrUnsatisfiable) && !errors.Is(err, ErrSolveLimit) {
				t.Fatalf("untyped error: %v", err)
			}

			return
		}

		seen := map[string]bool{}

		for _, p := range res.Packages {
			if seen[p.Name] {
				t.Fatalf("%s listed twice", p.Name)
			}

			seen[p.Name] = true
		}
	})
}

// FuzzWritePackage checks that the writer and the parser agree: whatever the
// writer accepts, the parser reads back, and what it refuses is a typed error.
func FuzzWritePackage(f *testing.F) {
	f.Add("hello", "1.2.3-r0", "x86_64", "a greeting", "MIT", "dep>=1", "etc/conf", "data")
	f.Add("a b", "1:2", "", "x\ny", "", "", "../x", "")
	f.Add("lib-2", "2.0", "noarch", "", "", "so:libc.so.6", "/abs", "x")

	f.Fuzz(func(t *testing.T, name, version, arch, desc, license, dep, file, content string) {
		spec := &Spec{
			Info: Info{
				Name: name, Version: version, Arch: arch, Description: desc, License: license,
				Depends: []string{dep}, BuildDate: time.Unix(1700000000, 0),
			},
			Files: []File{MemFile(file, fs.FileMode(0o644), []byte(content))},
		}

		var buf bytes.Buffer

		pkg, err := WritePackage(&buf, spec, WriteOptions{TempDir: t.TempDir()})
		if err != nil {
			if !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("untyped error: %v", err)
			}

			return
		}

		got, err := ParsePackage(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatalf("written package does not parse: %v", err)
		}

		if got.Name != pkg.Name || got.Version != pkg.Version || got.Checksum != pkg.Checksum || got.DataHash != pkg.DataHash {
			t.Fatalf("parsed %+v\nwritten %+v", got, pkg)
		}
	})
}

// FuzzArchive checks that reading and extracting arbitrary bytes never
// panics, never writes outside the target directory and fails with an error
// or succeeds.
func FuzzArchive(f *testing.F) {
	for _, name := range []string{"fping-5.2-r0.apk", "iputils-ping-20240117-r0.apk", "interop-1.2.3-r4.apk"} {
		raw, err := os.ReadFile(filepath.Join("testdata", "extract", name))
		if err != nil {
			f.Fatal(err)
		}

		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := OpenArchive(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}

		_, _ = a.Files()

		root := t.TempDir()
		out := filepath.Join(root, "out")

		if err := os.Mkdir(out, 0o755); err != nil {
			t.Fatal(err)
		}

		_ = a.Extract(out, ExtractOptions{MaxBytes: 1 << 20, MaxEntries: 1000})

		// Nothing may appear next to the extraction directory.
		des, err := os.ReadDir(root)
		if err != nil || len(des) != 1 {
			t.Fatalf("extraction wrote outside its directory: %v %v", des, err)
		}
	})
}

// FuzzParseWorld checks that ParseWorld, WorldAdd and RenderWorld agree.
func FuzzParseWorld(f *testing.F) {
	f.Add("busybox libfoo@edge>=1.2 !bad\nalpine-base")
	f.Add("")

	f.Fuzz(func(t *testing.T, text string) {
		w, err := ParseWorld(strings.NewReader(text))
		if err != nil {
			if !errors.Is(err, ErrInvalidWorld) {
				t.Fatalf("untyped error: %v", err)
			}

			return
		}

		back, err := ParseWorld(bytes.NewReader(RenderWorld(w)))
		if err != nil || len(back) != len(w) {
			t.Fatalf("render does not parse back: %v", err)
		}

		if len(w) > 0 {
			if _, err := WorldAdd(w, w[0]); err != nil {
				t.Fatal(err)
			}
		}
	})
}
