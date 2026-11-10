package apk_test

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"log"
	"time"

	"github.com/M0Rf30/pkgformat/apk"
)

func Example() {
	// Describe the package.
	spec := &apk.Spec{
		Info: apk.Info{
			Name: "hello", Version: "1.0-r0", Arch: "x86_64",
			Description: "Prints a greeting", License: "MIT",
			BuildDate: time.Unix(1700000000, 0),
			Depends:   []string{"busybox"},
		},
		Scripts: apk.Scripts{PostInstall: "#!/bin/sh\necho installed\n"},
		Files: []apk.File{
			{Name: "usr", Mode: fs.ModeDir | 0o755, Uname: "root", Gname: "root"},
			{Name: "usr/bin", Mode: fs.ModeDir | 0o755, Uname: "root", Gname: "root"},
			apk.MemFile("usr/bin/hello", 0o755, []byte("#!/bin/sh\necho hello\n")),
		},
	}

	// Sign it with a key of your own.
	key, err := apk.GenerateKey(2048)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := apk.NewSigner("me@example.org-5f0a1b2c.rsa.pub", key, apk.SigRSASHA256)
	if err != nil {
		log.Fatal(err)
	}

	var out bytes.Buffer

	pkg, err := apk.WritePackage(&out, spec, apk.WriteOptions{Signer: signer})
	if err != nil {
		log.Fatal(err)
	}

	// Verify it against the keys you trust.
	keys := apk.NewKeyring()
	if err := keys.Add(signer.KeyName(), signer.PublicKey()); err != nil {
		log.Fatal(err)
	}

	verified, err := apk.VerifyPackage(bytes.NewReader(out.Bytes()), int64(out.Len()), apk.VerifyOptions{
		Keys: keys, Algorithms: []apk.SigAlgorithm{apk.SigRSASHA256},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Put it in a signed repository index.
	index, err := apk.BuildIndex([]apk.Package{*pkg}, "example repository", signer)
	if err != nil {
		log.Fatal(err)
	}

	entries, err := apk.VerifyIndex(index, apk.VerifyOptions{
		Keys: keys, Algorithms: []apk.SigAlgorithm{apk.SigRSASHA256},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(verified.FileName(), verified.Signed, len(entries), entries[0].Checksum == pkg.Checksum)
	// Output: hello-1.0-r0.apk true 1 true
}

func ExampleClient() {
	client, err := apk.NewClient(apk.ClientOptions{
		Repos:      []apk.Repo{{URL: "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"}},
		Arch:       "x86_64",
		KeysDir:    "/etc/apk/keys",
		Algorithms: []apk.SigAlgorithm{apk.SigRSASHA1}, // what Alpine's own repositories use
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	index, err := client.Update(ctx)
	if err != nil {
		log.Fatal(err)
	}

	res, err := index.ResolveDeps([]string{"curl"})
	if err != nil {
		log.Fatal(err)
	}

	paths, err := client.Download(ctx, "/var/cache/apk", res.Packages...)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(paths)
}
