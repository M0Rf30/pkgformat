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
| Installed packages | `FindInstalled`, `OpenInstalled`, `(*InstalledDB)`: `Packages`, `List`, `InstalledNames`, `InstalledProvides`. Reads `/lib/apk/db/installed`, with the file lists. |
| Repositories | `ParseRepositories`; `Client` fetches and verifies the indexes and downloads packages; `Index` resolves names, capabilities and dependencies. |

### APKv3

`ParsePackage` reads the ADB packages of apk-tools 3 as well (the metadata comes
back in the same `Package`, with `Format` set to `FormatV3`). The sub-package
[`apk/adb`](adb/README.md) does the rest of v3: read, verify and extract
packages and indexes, write them the way `apk mkpkg` and `apk mkndx` do, and
sign with RSA and ECDSA keys. It is verified against apk-tools 3.0.9: the ADB
block it writes is identical to `apk mkpkg`'s, `apk verify` and `apk add`
accept its packages, and the packages and indexes apk makes read and verify in
it.

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
sol, err := index.Solve(apk.SolveRequest{World: []string{"curl"}})
paths, err := client.Download(ctx, "/var/cache/apk", sol.Packages...)
```

## The installed database

`OpenInstalled` (or `NewInstalledDB` over an `io.ReaderAt`) reads
`/lib/apk/db/installed`, read-only and in bounded memory: `FindInstalled("/")`
gives the path under a root. Each `InstalledPackage` has the fields of an index
entry (the same single-letter lines as an `APKINDEX`) plus `Replaces`,
`ReplacesPriority` and the `Files` the package owns: directories (`F:`) and
files (`R:`) with their checksum (`Z:`) and, from the `a:` and `M:` lines, owner
and mode. The files are read with apk 2 and apk 3 databases alike.

Unlike `ParseIndex` the reader is lenient: a record that is not valid (a
missing `P`, `V` or `A`, a repeated field, a path that climbs out of the root,
an ACL that is not `uid:gid:mode`) is skipped and logged at debug level, as a
database written by an installer is not an index a client rejects as a whole. A
name may start with a dot (`apk add --virtual .build-deps`) and a checksum may
be of any algorithm. `InstalledNames` and `InstalledProvides` list the names
and the capabilities (`so:libc.musl-x86_64.so.1`, `cmd:sh`), without versions
and with the package's own name; they do not keep the file lists.
`InstalledOptions` bounds the file size, the packages and the file records of
one package, and `SkipFiles` leaves the file lists out.

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

## Reading and extracting packages

`OpenArchive` reads a package for its contents. `Files` and `Walk` give each
`Entry`: type (file, directory, symbolic link, hard link, device, FIFO), mode
with setuid, setgid and sticky, owner, link target, device numbers, the SHA-1 the
package records and the extended attributes (`security.capability` among them).
`Walk` verifies the checksum of each file as it is read (`ErrChecksum`).
`Extract` unpacks into an existing directory with every path confined to it
(`ErrUnsafeEntry`; an absolute symbolic link target is read relative to the
directory, as in a chroot), limits on bytes and entries (`ErrExtractLimit`) and
opt-in `Owners`, `Devices` and `Xattrs`. The entries and the extracted trees
of real Alpine packages (busybox, ca-certificates, iputils, fping and
shadow-subids with file capabilities, bind-tools with hard links) are compared
with what `apk extract` makes: `testdata/extract`.

## Versions, dependencies and the solver

`CompareVersions` orders versions as `apk version -t` does, `ParseDependency`
reads `name`, `name>=1.2`, `name~1.2`, `name><checksum`, `!name` and
`name@tag`, and `Dependency.MatchVersion` tests a version. Both are tested
against the host `apk`: `testdata/version` holds 3000+ generated pairs.

`Index.Solve(SolveRequest{World, Installed, Upgrade})` chooses the packages
with apk's rules: constraints, conflicts, versioned and unversioned provides,
`provider_priority` (an unversioned virtual without priority is not chosen on
its own), `install_if`, `@tag` repository pinning, the installed version
preferred unless `Upgrade`, the highest version, then the first repository. It
backtracks when a choice leads to a conflict, within a step budget
(`ErrSolveLimit`); an unsatisfiable request is a `*SolveError` that wraps
`ErrUnsatisfiable` and lists the problems with who required them. The result
has the packages in dependency order and the `Changes` (install, upgrade,
downgrade, reinstall, remove) from the installed set. 59 synthetic cases and
15 targets against a real Alpine 3.24 index agree with `apk add --simulate`:
`testdata/resolve`. `ParseWorld`, `WorldAdd` (an entry replaces the one of the
same name), `WorldDel` and `RenderWorld` handle `/etc/apk/world`. `ReplacesFile`
decides which of two packages that ship the same file keeps it, from `replaces`
and `replaces_priority` (checked against `apk add`: `testdata/replaces`).

## Writing

`Spec.Files` may hold directories, files, symbolic links (with the SHA-1 of the
target recorded, as abuild does), hard links (`File.Hardlink`, a target earlier
in the package), FIFOs, character and block devices (`DevMajor`, `DevMinor`),
owners and `Xattrs` (`security.capability` as the kernel's binary value). The
parent directories of the entries are added as root-owned 0755 directories
unless `WriteOptions.NoParentDirs`. `Info` has `Licenses` (a list, joined with
a space as abuild does), `Origin`, `Commit`, `Maintainer`, `Triggers`,
`ReplacesPriority`, `ProviderPriority` and `InstallIf`. Alpine versions have no
epoch; `WritePackage` refuses `1:2.0-r0`.

Signing takes any `crypto.Signer` with an RSA public key (an HSM or KMS client
works): the signature is checked against the advertised key before it is used
and a signer that fails, returns an oversized signature or signs other data
gives `ErrSign`. `ParsePrivateKeyPEM` reads PKCS#1 and PKCS#8 keys,
`MarshalPrivateKeyPEM` (PKCS#8) and `MarshalPrivateKeyPKCS1PEM` write them,
`MarshalPublicKeyPEM` writes the keys-directory file and `PublicKeyName` its
name. `apk verify` accepts the packages written with an opaque signer
(`testdata/extract/listings/apk.verdicts`).

## Not covered

- Installing packages and writing the installed database are out of scope.
- Package versions have no epoch: Alpine's version syntax has none.
- Data segment entries other than those listed above (sockets) are refused.

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
