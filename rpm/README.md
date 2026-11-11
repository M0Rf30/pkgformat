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
| [`.../rpmdb`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm/rpmdb) | Read the installed-package database of a system, read only: SQLite (rpm 4.16 and later), ndb (`Packages.db`) and BerkeleyDB hash (`Packages`, rpm 4.15 and earlier) ([README](rpmdb/README.md)) |
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

`Package` also carries the scriptlets with their interpreters and flags
(`Scripts`), package triggers (`Triggers`), file and transaction file triggers
(`FileTriggers`), per-file capabilities, hard link counts, languages, verify
flags, SELinux contexts, IMA and fs-verity signatures (`Files[i]`), the
sources and patches of a source package, and the build metadata (modularity
label, dist tag, platform, cookie, policies, sysusers). The values match what
librpm reads (`testdata/meta/golden.py`). `VerifyIMASignature` and
`VerifyVeritySignature` check the per-file IMA and fs-verity signatures that
`rpmsign --signfiles` / `--signverity` add; `FSVerityDigest` computes the
fs-verity digest of file contents as `fsverity digest` does.

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
directories and the installed-package list are all options. The `.repo`
keys `gpgcheck`/`gpgkey`, `exclude`/`excludepkgs`, `priority` and `proxy` are
honoured, and a metalink's hashes are checked against `repomd.xml` (see the
security notes).

Command line:

```sh
go install github.com/M0Rf30/pkgformat/cmd/tar2rpm@latest
tar2rpm -name example -version 1.0 -release 1 -file example.rpm < example.tar
```

## Security notes

Packages and archives are often untrusted input.

- **Bound decompression.** A few KiB of compressed payload can expand to many
  GiB, and the sizes declared in the header are attacker controlled. The
  payload readers stop at `rpm.DefaultMaxPayloadSize` (4 GiB), or at twice the
  declared size when that is larger; `Rpm.SetMaxPayloadSize` sets a bound of
  your own (a negative value removes it). `Rpm.SetVerifyPayloadDigest` checks
  the compressed payload against the payload digest of the header, so a
  verified header proves the payload too.
- **Check that a package is signed.** `Verify` returns an empty list of
  signatures, and no error, for a package that carries none: it is intact, not
  authentic. A caller that requires a signature uses `VerifyWithOptions` with
  `RequireSigned` (an unsigned package then fails with `ErrUnsigned`), or checks
  `len(sigs)`; the signatures are checked against the keys it passes, so pass
  only keys it trusts.
- **Keys are checked for validity.** A signature counts only if its key is not
  revoked (primary key, subkey or primary user id), not expired, allowed to
  sign, and the signature itself is not expired or from the future. A key that
  fails is a `*SignatureError` wrapping `gpg.ErrKeyRevoked`, `gpg.ErrKeyExpired`,
  `gpg.ErrSignatureExpired` or `gpg.ErrKeyCannotSign`. Validity is judged at the
  time of the check (`VerifyOptions.Now` overrides the clock for tests), as GnuPG
  does, so a package signed by a key that has since expired no longer verifies.
- **Extraction is confined.** `cpio.Extract` and `ExpandPayload` write below the
  destination only and never follow links out of it. They apply the modes of the
  package, including the setuid, setgid and sticky bits, and its modification
  times, as rpm does; `ExpandOptions.Umask` (`07022` drops the special bits)
  masks them. Owners are applied only with `ExpandOptions.Chown`, and only when
  running as root. Device nodes, FIFOs and sockets are skipped, with a logged
  warning, unless `ExpandOptions.SpecialFiles` is set. `ExpandPayload` checks the
  contents of every regular file against `FILEDIGESTS` and fails with
  `*DigestMismatchError` (`errors.Is(err, rpm.ErrDigestMismatch)`) on a mismatch;
  `ExpandOptions.SkipDigests` turns that off. Both the cpio payload of format 4
  and the stripped payload of format 6 are extracted.
- **Repository metadata is untrusted.** The `dnf` client confines every
  location to the repository and the destination, caps what it downloads and
  decompresses, verifies SHA-256 and SHA-512 checksums, refuses a package it
  cannot verify, and keeps a repository id from leaving the cache directory. A
  repository with `gpgcheck=1` has the signature of each downloaded package
  checked with `rpm.VerifyWithOptions` (signatures required) against its
  `gpgkey` keys, fetched over the client's HTTP client or read from `file://`
  URLs; `gpgcheck=1` without a key fails (`dnf.ErrNoGPGKey`), `gpgcheck=0` and
  a missing `gpgcheck` check nothing. A repository whose mirror list is a
  metalink has its `repomd.xml` compared with the size and hashes the metalink
  publishes (`dnf.ErrMetalinkMismatch`); other repositories are protected by
  checksums only, which catch a corrupt or mismatched mirror, not a repository
  that lies: `repo_gpgcheck` (the signature of `repomd.xml`) is not checked.
  Dependencies are matched by name, without comparing versions; of several
  versions of a package the newest by epoch, version and release (`rpm.Vercmp`)
  is chosen, unless a repository with a lower `priority` number has the name.
- **Every OpenPGP signature version is verified**: version 3 packets (RSA and
  DSA, the packages of RHEL 7 and earlier), version 4, and the salted version 6
  of RFC 9580. `VerifyWithKeyring` takes the `gpg.Keyring` the other formats
  use.
- **Signing keys stay where they are.** `rpm.Sign` takes any `gpg.Signer`:
  `gpg.NewCryptoSigner` wraps an RSA or ECDSA `crypto.Signer` (HSM, KMS, smart
  card) and a signer that only implements `DetachedSign` (gpg-agent, a remote
  service) gets the header-only signature rpm 4.16 and later make.
- Parsers enforce limits on header sizes and counts, and are fuzzed
  (`go test -fuzz`).

## License

Apache License 2.0, see [LICENSE](../LICENSE).
