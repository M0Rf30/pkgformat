package apk_test

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"

	"github.com/M0Rf30/pkgformat/apk"
)

// Compare versions the way "apk version -t" does.
func ExampleCompareVersions() {
	fmt.Println(apk.CompareVersions("1.2.3-r1", "1.2.3-r2"))
	fmt.Println(apk.CompareVersions("1.0_rc1", "1.0"))
	fmt.Println(apk.CompareVersions("1.0_p1", "1.0"))
	fmt.Println(apk.CompareVersions("2.0", "10.0"))
	// Output:
	// -1
	// -1
	// 1
	// -1
}

func ExampleParseDependency() {
	d, err := apk.ParseDependency("libfoo@edge>=1.2")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(d.Name, d.Tag, d.Op, d.MatchVersion("1.5-r0"), d.MatchVersion("1.1"))
	// Output: libfoo edge >= true false
}

// Read the files of a package without unpacking it, then unpack it into a
// directory. Every name is confined to the directory and every file is
// checked against the checksum the package records.
func ExampleArchive() {
	spec := &apk.Spec{
		Info: apk.Info{Name: "tool", Version: "1-r0", Arch: "noarch"},
		Files: []apk.File{
			apk.MemFile("usr/bin/tool", fs.ModeSetuid|0o755, []byte("#!/bin/sh\n")),
			{Name: "usr/bin/t", Mode: fs.ModeSymlink | 0o777, LinkTarget: "tool"},
			{
				Name: "usr/bin/cap", Mode: 0o755, Size: 1,
				Xattrs: map[string][]byte{"security.capability": make([]byte, 20)},
			},
		},
	}
	spec.Files[2].Open = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader([]byte("c"))), nil }

	var pkg bytes.Buffer
	if _, err := apk.WritePackage(&pkg, spec, apk.WriteOptions{}); err != nil {
		log.Fatal(err)
	}

	a, err := apk.OpenArchive(bytes.NewReader(pkg.Bytes()), int64(pkg.Len()))
	if err != nil {
		log.Fatal(err)
	}

	files, err := a.Files()
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		fmt.Println(f.Type, f.Name, f.Mode)
	}

	dir, err := os.MkdirTemp("", "extract")
	if err != nil {
		log.Fatal(err)
	}

	defer func() { _ = os.RemoveAll(dir) }()

	if err := a.Extract(dir, apk.ExtractOptions{}); err != nil {
		log.Fatal(err)
	}
	// Output:
	// dir usr -rwxr-xr-x
	// dir usr/bin -rwxr-xr-x
	// file usr/bin/tool urwxr-xr-x
	// symlink usr/bin/t -rwxrwxrwx
	// file usr/bin/cap -rwxr-xr-x
}

// Choose the packages for a world with apk's rules and see what changes.
func ExampleIndex_Solve() {
	idx := apk.NewIndex()
	idx.Add(apk.Repo{URL: "https://example.org/main"}, "x86_64", []apk.Package{
		{Name: "app", Version: "2-r0", Depends: []string{"libfoo>=1.2"}},
		{Name: "libfoo", Version: "1.1-r0"},
		{Name: "libfoo", Version: "1.5-r0"},
		{Name: "docs", Version: "1-r0", InstallIf: []string{"app"}},
	})

	sol, err := idx.Solve(apk.SolveRequest{
		World:     []string{"app"},
		Installed: []apk.Package{{Name: "libfoo", Version: "1.1-r0"}},
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, c := range sol.Changes {
		fmt.Println(c.Kind(), c.New.Name, c.New.Version)
	}
	// Output:
	// upgrade libfoo 1.5-r0
	// install app 2-r0
	// install docs 1-r0
}

func ExampleWorldAdd() {
	world, _ := apk.WorldAdd([]string{"busybox", "libfoo"}, "libfoo>=1.2", "curl")
	fmt.Print(string(apk.RenderWorld(world)))
	// Output:
	// busybox
	// curl
	// libfoo>=1.2
}

// Decide which of two packages that ship the same file keeps it.
func ExampleReplacesFile() {
	owner := &apk.Package{Name: "old", Version: "1"}
	incoming := &apk.Package{Name: "new", Version: "1", Replaces: []string{"old"}, ReplacesPriority: 1}
	fmt.Println(apk.ReplacesFile(owner, incoming))
	fmt.Println(apk.ReplacesFile(owner, &apk.Package{Name: "other", Version: "1"}))
	// Output:
	// yes
	// conflict
}

// hsm stands for a signing service: the private key never leaves it.
type hsm struct{ key *rsa.PrivateKey }

func (h hsm) Public() crypto.PublicKey { return h.key.Public() }

func (h hsm) Sign(r io.Reader, digest []byte, o crypto.SignerOpts) ([]byte, error) {
	return h.key.Sign(r, digest, o)
}

// Sign a package with a key that lives in an HSM or KMS: any crypto.Signer
// with an RSA public key works.
func ExampleNewSigner() {
	key, err := apk.GenerateKey(2048)
	if err != nil {
		log.Fatal(err)
	}

	name, err := apk.PublicKeyName("builder@example.org", &key.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := apk.NewSigner(name, hsm{key}, apk.SigRSASHA256)
	if err != nil {
		log.Fatal(err)
	}

	spec := &apk.Spec{Info: apk.Info{Name: "signed", Version: "1-r0", Arch: "noarch"}}
	if _, err := apk.WritePackage(io.Discard, spec, apk.WriteOptions{Signer: signer}); err != nil {
		log.Fatal(err)
	}

	fmt.Println(signer.EntryName() == ".SIGN.RSA256."+name)
	// Output: true
}
