# apk/adb: Alpine packages and indexes in the v3 (ADB) format

`package adb` reads, verifies, writes and extracts the APKv3 format of
apk-tools 3: `.apk` packages and `APKINDEX.adb` repository indexes. The v2
format (tar streams) lives in the parent package, `apk`.

```go
import "github.com/M0Rf30/pkgformat/apk/adb"
```

## What is covered

| Capability | API |
| --- | --- |
| Read the metadata of a package | `ParsePackage`, `Reader.Package` |
| Walk the files, streaming their content | `NewReader`, `Reader.Next`, `Reader.Read` |
| Verify signatures and file digests | `VerifyPackage`, `VerifyIndex`, `Reader.Verify` |
| Extract with path containment | `Extract`, `ExtractOptions` |
| Write a package (`apk mkpkg`) | `WritePackage`, `Spec`, `File`, `FilesFromDir` |
| Write an index (`apk mkndx`) | `IndexEntry`, `BuildIndex`, `Index` |
| Read an index | `ParseIndex`, `Reader.Index` |
| Sign with RSA (2048 to 16384 bits) or ECDSA (P-256, P-384, P-521) | `Signer`, `NewSigner`, `WriteOptions.Signers` |
| Trust keys | `Keyring`, `LoadKeyring` (an `/etc/apk/keys` directory) |
| Compression: none, deflate, Zstandard | `WriteOptions.Compression` |
| Versions and dependencies in apk syntax | `CompareVersions`, `ValidVersion`, `ParseDependency` |

The ADB block of a package written here is identical, byte for byte, to what
`apk mkpkg` writes for the same input, including dependency lists, scripts,
triggers, extended attributes, hard links and every `--compat` level.

Ed25519 keys are not supported: apk-tools 3.0.9 cannot load them.

## Reading

```go
f, _ := os.Open("hello-1.0-r0.apk")
defer f.Close()

keys, _ := adb.LoadKeyring("/etc/apk/keys")

pkg, keyID, err := adb.VerifyPackage(f, keys, adb.ReadOptions{})
```

`NewReader` reads the ADB block (the metadata) and the signature blocks, and
hands out the files one by one; each file is checked against the digest in the
metadata when its content has been read to the end. Nothing is trusted until
`Verify` (or `VerifyPackage`, or `Extract` with a `Keyring`) has said so.

Reading is bounded: `Limits` caps the ADB block, the decompressed stream, the
number of list elements and the work a decode may take. The values of an ADB
block form a graph in which one value can be referenced many times, so a few
bytes can ask for an enormous decode; `ErrTooComplex` is what stops that.

## Extracting

`Extract` refuses a package that is not trusted (`ErrNoKeyring`, `ErrUnsigned`,
`ErrUntrusted`, `ErrBadSignature`) unless `AllowUntrusted` says an unsigned one
will do; a signature by a trusted key that does not verify is never accepted.
Every path is confined to the destination, links that leave it are refused
(`ErrUnsafeEntry`), devices and named pipes are skipped, owners are not applied
and the setuid, setgid and sticky bits are dropped.

## Writing

```go
spec := &adb.Spec{
    Info:  adb.Info{Name: "hello", Version: "1.0-r0", Arch: "x86_64"},
    Files: []adb.File{adb.MemFile("usr/bin/hello", 0o755, script)},
}

_, err := adb.WritePackage(out, spec, adb.WriteOptions{Signers: []*adb.Signer{signer}})
```

`FilesFromDir` lists a directory tree with the owner root and the epoch as
modification time, so a build does not depend on who ran it or when. Names are
recorded, not numeric ids: set `Uname` and `Gname` on a `File` to say otherwise.
An index is built from entries that `IndexEntry` makes out of the package
files, and `BuildIndex` sorts and signs them.

## Interoperability, proven against apk-tools 3.0.9

The tests drive the real tools (they skip when `apk` is absent):

* `apk mkpkg` and the writer make the same ADB block for 14 inputs: empty
  packages, every mode bit, links, extended attributes, full metadata, large
  scripts and the four compat levels.
* `apk verify` accepts every package and index the writer signs with RSA and
  EC keys, in all six compression variants, and refuses them under a wrong key.
* `apk add` installs a signed package in an Alpine container, runs its
  post-install script, and refuses it without the key.
* Packages and indexes that apk signs verify in this package, and extracting
  them gives the same tree as apk does.
* `apk mkndx` and `BuildIndex` give indexes that `apk adbdump` shows alike.
* `CompareVersions` agrees with `apk version -t` on over 270 pairs.

`testdata/` holds the fixtures that those runs produced, with `generate.sh`
and the `apk adbdump` of each; see `testdata/README.md`. Tests that do not need
the tools read the fixtures and check them against the writer.

## Fuzzing

`FuzzReader`, `FuzzExtract`, `FuzzParseDependency`, `FuzzCompareVersions` and
`FuzzWriteRead` run with `go test -run=^$ -fuzz=FuzzReader -fuzztime=15s`.

## Differences from apk worth knowing

* The writer names a hard link to a file in the root as `name`, where apk
  writes `./name`, which apk's own extractor then refuses. The reader accepts
  both.
* `apk mkpkg` hangs on a tree that contains a named pipe. The writer takes
  FIFOs and devices from `Spec.Files`.
* An index written here is not byte-identical to apk's: apk leaves 20 unused
  bytes in every index. Everything an index says is the same.
