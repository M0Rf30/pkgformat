package apk_test

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"log"
	"strings"
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

	res, err := index.Solve(apk.SolveRequest{World: []string{"curl"}})
	if err != nil {
		log.Fatal(err)
	}

	paths, err := client.Download(ctx, "/var/cache/apk", res.Packages...)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(paths)
}

// Read the packages an apk system has installed, with the files they own. On
// a host, FindInstalled("/") and OpenInstalled give the real database.
func ExampleInstalledDB() {
	const text = `C:Q1qvTGHdzF6KLavt4PO0gs2a6pQ00=
P:busybox
V:1.37.0-r31
A:x86_64
p:cmd:busybox=1.37.0-r31 /bin/sh
F:bin
R:busybox
a:0:0:755
Z:Q1y5VcgN7Y1x2d9E1Gp7BkG5mZYGM=

`

	db := apk.NewInstalledDB(strings.NewReader(text), int64(len(text)), apk.InstalledOptions{})

	for pkg, err := range db.Packages(context.Background()) {
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(pkg.Name, pkg.Version, pkg.FilePaths())
	}

	provides, _ := db.InstalledProvides(context.Background())
	fmt.Println(provides)
	// Output:
	// busybox 1.37.0-r31 [bin/busybox]
	// [/bin/sh busybox cmd:busybox]
}
