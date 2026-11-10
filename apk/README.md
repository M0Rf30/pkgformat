# apk

Part of [pkgformat](../README.md).

[![Go Reference](https://pkg.go.dev/badge/github.com/M0Rf30/pkgformat/apk.svg)](https://pkg.go.dev/github.com/M0Rf30/pkgformat/apk)

A Go library to build, read, verify and sign [Alpine Linux](https://alpinelinux.org)
packages (`.apk`, the v2 format of apk-tools) and repository indexes, and to
fetch them from repositories. It is pure Go: no `abuild`, no `apk` binary, no
fakeroot and no access to the file system to do its job, other than the paths
you pass in.

## Install

```sh
go get github.com/M0Rf30/pkgformat/apk
```

Requires Go 1.27 or later.

## What it does

| | |
| --- | --- |
| Write a package | `WritePackage` from a `Spec` of plain structs (`Info`, `Scripts`, `File`); `FilesFromDir` lists a staged tree. The output is deterministic. |
| Read a package | `ParsePackage` returns the metadata, the SHA-1 index checksum, the size and the data hash, under explicit limits. |
| Sign and verify | `SignPackage`, `WriteOptions.Signer`, `VerifyPackage`. RSA with PKCS#1 v1.5, SHA-1 (`.SIGN.RSA.`) or SHA-256 (`.SIGN.RSA256.`). |
| Indexes | `BuildIndex`, `RenderIndex`, `ParseIndex`, `VerifyIndex`. |
| Keys | `GenerateKey`, `ParsePrivateKeyPEM`, `ParsePublicKeyPEM`, `Keyring`, `LoadKeyring` for an apk keys directory. |
| Repositories | `ParseRepositories`; `Client` fetches and verifies the indexes and downloads packages; `Index` resolves names, capabilities and dependencies. |

A package written by `WritePackage` has, as abuild writes it: an optional
signature segment, a control segment (`.PKGINFO` first, then the install
scripts as `.pre-install`, `.post-install`, `.pre-upgrade`, `.post-upgrade`,
`.pre-deinstall`, `.post-deinstall` and `.trigger`) and a data segment in which
every regular file carries its SHA-1 in the `APK-TOOLS.checksum.SHA1` PAX
record. The `.PKGINFO` records the SHA-256 of the data segment (`datahash`)
and the installed size.

## Examples

The tested examples are on [pkg.go.dev](https://pkg.go.dev/github.com/M0Rf30/pkgformat/apk#pkg-examples)
([`example_test.go`](example_test.go)). In short:

Write, sign, verify and index a package:

```go
spec := &apk.Spec{
	Info: apk.Info{Name: "hello", Version: "1.0-r0", Arch: "x86_64", License: "MIT"},
	Files: []apk.File{
		{Name: "usr", Mode: fs.ModeDir | 0o755, Uname: "root", Gname: "root"},
		{Name: "usr/bin", Mode: fs.ModeDir | 0o755, Uname: "root", Gname: "root"},
		apk.MemFile("usr/bin/hello", 0o755, []byte("#!/bin/sh\necho hello\n")),
	},
}

key, _ := apk.GenerateKey(2048)
signer, _ := apk.NewSigner("me@example.org-5f0a1b2c.rsa.pub", key, apk.SigRSASHA256)

pkg, err := apk.WritePackage(out, spec, apk.WriteOptions{Signer: signer}) // out is an io.Writer
if err != nil {
	log.Fatal(err)
}

index, _ := apk.BuildIndex([]apk.Package{*pkg}, "my repository", signer)
```

Install from a repository:

```go
client, err := apk.NewClient(apk.ClientOptions{
	Repos:      []apk.Repo{{URL: "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"}},
	Arch:       "x86_64",
	KeysDir:    "/etc/apk/keys",
	Algorithms: []apk.SigAlgorithm{apk.SigRSASHA1},
})
index, err := client.Update(ctx)
res, err := index.ResolveDeps([]string{"curl"})
paths, err := client.Download(ctx, "/var/cache/apk", res.Packages...)
```

## Signature types

There is no default signature type. `NewSigner` takes the `SigAlgorithm`, and
`VerifyOptions.Algorithms` (and `ClientOptions.Algorithms`) list the types a
verifier accepts. Alpine's own repositories are signed with SHA-1
(`.SIGN.RSA.`); apk-tools 3 also reads SHA-256 (`.SIGN.RSA256.`). A caller who
accepts SHA-1 says so. Keys are RSA of 2048 to 16384 bits.

## The client

`Client` needs a trust decision: a `KeysDir` with `Algorithms`, or an explicit
`InsecureSkipVerify`. `Update` loads the repositories in parallel; one that
cannot be fetched or verified is left out and listed in `Failures`, and
`ErrNoIndex` is returned only when none loads. `Download` resumes partial
files and checks each package against its index entry (size, SHA-1 checksum,
name and version) before keeping it, as apk does: the signed index is the
trust anchor of the packages it lists. Package files are found next to the
index of their repository, whatever their own `arch` is (`noarch` packages
included).

The caller supplies everything that comes from the host: the repositories
(`ParseRepositories` reads text, it opens no file), the architecture and the
keys directory. Retry, backoff and timeouts come from the `httpclient.Client`
you pass in `ClientOptions.HTTP`.

The resolver is not a solver. `ResolveDeps` follows `depend` entries
depth-first, drops version constraints, skips `!conflicts` and `/path`
dependencies and picks the first package that provides a capability (the
highest `provider_priority` wins). It does not compare versions and has no
notion of `@tag` pinning; the tag of a repository is only carried along.

## Not covered

- Package versions have no epoch: Alpine's version syntax has none, and
  `WritePackage` refuses `1:2.0-r0`.
- `Info.License` is one string (abuild joins several licenses with a space).
- Entries of the data segment are directories, regular files, symbolic links
  and named pipes. Devices and hard links are refused.
- Installing packages, the apk database, version comparison and `@tag`
  repository pinning are out of scope.

## Security notes

Everything that reads untrusted bytes is bounded and returns typed errors,
wrapping `ErrInvalidPackage`, `ErrInvalidIndex`, `ErrInvalidRepositories`,
`ErrUnsigned`, `ErrUntrusted` or `ErrBadSignature`; none of it panics on
malformed input, and every parser has a fuzz target.

| Limit | Value |
| --- | --- |
| Package control segment, compressed / decompressed | 4 MiB / 8 MiB |
| `.PKGINFO` | 1 MiB |
| Control entries | 1000 |
| Data segment, decompressed / entries | 8 GiB / 1,000,000 |
| Index, decompressed / entries / line | 512 MiB / 2,000,000 / 1 MiB |
| Signature entry / signatures per package | 4096 bytes / 16 |
| Index download | 100 MiB |
| Package download | its index size, else 1 GiB |
| Repositories file | 1 MiB, 10,000 lines |

File names in a package are checked against `..` and absolute paths, and the
names the client builds from an index entry are checked before they touch the
file system.
