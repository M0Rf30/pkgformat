# rpm

Part of [pkgformat](../README.md).

[![Go Reference](https://pkg.go.dev/badge/github.com/M0Rf30/pkgformat/rpm.svg)](https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm)

A Go library to build, read, verify and sign [RPM](https://rpm.org) packages,
in the classic format 4 and in the format 6 of rpm 6.0, and to write, read and
use dnf/yum repositories. It needs no `rpmbuild`, no spec file, no `rpm` or
`dnf` binary and no access to the file system to do its job.

## Install

```sh
go get github.com/M0Rf30/pkgformat/rpm
```

Requires Go 1.27 or later. The library is pure Go; with cgo enabled it uses the
C zstd library to decompress payloads, otherwise a pure Go decoder.

## Packages

| Package | Purpose |
| --- | --- |
| [`github.com/M0Rf30/pkgformat/rpm`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm) | Read packages (`ReadPackage`: metadata, dependencies, files), verify and create OpenPGP signatures (`Sign`), compare versions, expand payloads |
| [`.../pack`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm/pack) | Write packages (`NewRPM`, `AddFile`, `Write`), optionally signed; build a package from a tar |
| [`.../tag`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm/tag) | Header tag numbers and entry types, as in `rpmtag.h` |
| [`.../cpio`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm/cpio) | Read, write and safely extract the cpio payload, including the stripped cpio of format 6 |
| [`.../repodata`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm/repodata) | Write repository metadata (primary, filelists, other, repomd.xml, comps), compress and sign it; read repomd.xml, primary.xml and modules.yaml; merge repositories |
| [`.../dnf`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm/dnf) | Repository client: `.repo` files, mirror failover, verified metadata cache, module filtering, dependency resolution, checked downloads |
| [`cmd/tar2rpm`](../cmd/tar2rpm) | Command that turns a tar archive into a package |
| [`cmd/rpmsample`](../cmd/rpmsample) | Command that writes a sample package, to test other rpm tools |

## Formats

| | Format 4 | Format 6 |
| --- | --- | --- |
| Build (`pack`) | yes | yes (`Format: pack.FormatV6`) |
| Read | yes | yes |
| Verify digests and signatures | yes | yes |
| Sign | yes | yes |

Payloads can be compressed with gzip, zstd, xz and lzma when writing; reading
also handles bzip2 and uncompressed payloads.

## Examples

The tested examples are on [pkg.go.dev](https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm#pkg-examples)
([`example_test.go`](example_test.go), [`pack/example_test.go`](pack/example_test.go),
[`cpio/example_test.go`](cpio/example_test.go)). In short:

Write a package:

```go
r, err := pack.NewRPM(pack.RPMMetaData{Name: "example", Version: "3", Release: "1"})
if err != nil {
	log.Fatal(err)
}
r.AddFile(pack.RPMFile{Name: "/usr/local/hello", Body: []byte("hello"), Mode: 0o644, Owner: "root", Group: "root"})
if err := r.Write(out); err != nil { // out is an io.Writer
	log.Fatal(err)
}
```

Read a package and expand its payload:

```go
pkg, err := rpm.ReadRpm(f)
if err != nil {
	log.Fatal(err)
}
nevra, _ := pkg.Header.GetNEVRA()
fmt.Println(nevra)
pkg.SetMaxPayloadSize(1 << 30) // see the security notes
if err := pkg.ExpandPayload(dir); err != nil {
	log.Fatal(err)
}
```

Verify a package against a keyring:

```go
_, sigs, err := rpm.Verify(f, keyring) // keyring is an openpgp.EntityList
if err != nil {
	log.Fatal(err)
}
if len(sigs) == 0 {
	log.Fatal("package is not signed")
}
```

Sign a package without rewriting it: `SignRpmStream` computes the signatures,
`DumpSignatureHeader` writes the new lead and signature header, and the rest of
the package is copied after the first `OriginalSignatureHeaderSize` bytes (see
`ExampleSignRpmStream`). `pack.RPM.SetPGPSigner` signs while writing.

Read the metadata of a package, without its payload:

```go
pkg, err := rpm.ReadPackage(f) // f is an io.Reader
if err != nil {
	log.Fatal(err)
}
fmt.Println(pkg.Name, pkg.Version, len(pkg.Requires), len(pkg.Files))
```

Sign a package into a new file with a key from `pkgformat/gpg`:

```go
signer, err := gpg.NewLocalSignerFromEntity(entity)
if err != nil {
	log.Fatal(err)
}
if err := rpm.Sign(src, dst, signer); err != nil { // src is an io.ReadSeeker
	log.Fatal(err)
}
```

Publish a repository and consume it (see the examples of `repodata` and `dnf`):
`repodata.WritePrimaryXML`, `WriteFilelistsXML` and `WriteOtherXML` produce the
metadata that `createrepo_c` writes, `GenerateRepomdXML` indexes it and
`SignRepomdXML` signs the index. On the client side `dnf.New(dnf.Options{...})`
gives `Update` (fetch and verify), `Load` (index), `Resolve` and `Download`;
nothing about the host is assumed, the repository, cache and variable
directories and the installed-package list are all options.

Command line:

```sh
go install github.com/M0Rf30/pkgformat/cmd/tar2rpm@latest
tar2rpm -name example -version 1.0 -release 1 -file example.rpm < example.tar
```

## Security notes

Packages and archives are often untrusted input.

- **Bound decompression.** A few KiB of compressed payload can expand to many
  GiB, and the sizes declared in the header are attacker controlled. Call
  `Rpm.SetMaxPayloadSize` before `ExpandPayload`, `PayloadReader` or
  `PayloadReaderExtended`. The default is no limit.
- **Check that a package is signed.** `Verify` returns an empty list of
  signatures, and no error, for a package that carries none. A caller that
  requires a signature must check `len(sigs)`, and that the signatures it got are
  made by a key it trusts (they are `Signature` values with the key ID and
  whether they cover the header only).
- **Extraction is confined.** `cpio.Extract` and `ExpandPayload` write below the
  destination only, never follow links out of it, and create files without
  setuid and setgid bits.
- **Repository metadata is untrusted.** The `dnf` client confines every
  location to the repository and the destination, caps what it downloads and
  decompresses, verifies SHA-256 and SHA-512 checksums, refuses a package it
  cannot verify, and keeps a repository id from leaving the cache directory. It
  does not check the signature of `repomd.xml`: its checksums catch a corrupt or
  mismatched mirror, not a repository that lies. Dependencies are matched by
  name, without comparing versions.
- **OpenPGP v3 signatures** (found in some very old packages) are not supported.
- Parsers enforce limits on header sizes and counts, and are fuzzed
  (`go test -fuzz`).

## License

Apache License 2.0, see [LICENSE](../LICENSE).
