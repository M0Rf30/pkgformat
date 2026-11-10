# pacman

Part of [pkgformat](../README.md).

[![Go Reference](https://pkg.go.dev/badge/github.com/M0Rf30/pkgformat/pacman.svg)](https://pkg.go.dev/github.com/M0Rf30/pkgformat/pacman)

A Go library to build, read, index and download [Arch Linux](https://archlinux.org)
packages and repositories, in pure Go. It needs no `makepkg`, no `pacman`, no
`repo-add` and no PKGBUILD: a package is described with plain Go structs.

## Install

```sh
go get github.com/M0Rf30/pkgformat/pacman
```

Requires Go 1.27 or later.

## What it does

| Area | API |
| --- | --- |
| Write `.pkg.tar.zst`, `.xz`, `.gz` | `Spec`, `PkgInfo`, `BuildInfo`, `Scriptlets`, `File`, `ScanDir`, `Spec.Write`, `Spec.WriteFile` |
| Read packages | `ReadPackage`, `ParsePkgInfo`, `ParseBuildInfo` |
| Sync databases | `ReadDB`, `ReadFileLists`, `WriteDB`, `NewDBEntry`, `DBEntry` |
| Versions and dependencies | `Vercmp`, `ParseDependency`, `Dependency.Allows` |
| Signatures | `SignDetached`, `NormalizeSignature`, verification through [`gpg`](../gpg/README.md) |
| `pacman.conf` and mirrorlists | `ParseConfig`, `ParseMirrorlist`, `ParseConfigFile`, `ExpandServer` |
| Repository client | `Client`: `FetchDB`, `SyncDB`, `Sync`, `DownloadPackage` |
| Search and resolution | `Index`: `Lookup`, `Providers`, `Resolve`, `ResolveDeps` |

The writer produces what makepkg does: `.PKGINFO`, `.BUILDINFO`, a gzipped
`.MTREE` with SHA-256 digests, `.INSTALL` with the six hooks, `.CHANGELOG`, and
a payload sorted by path with its parent directories. With
`WriteOptions.ClampMTime` the archive is reproducible from the build date.

## Examples

Build a package, read it back, publish it in a database and resolve against it:

```go
spec := &pacman.Spec{
	Info: pacman.PkgInfo{
		Name: "hello", Version: "1.0-1", Description: "A greeting", Arch: "x86_64",
		BuildDate: 1700000000, Depends: []string{"glibc"},
	},
	Scriptlets: &pacman.Scriptlets{PostInstall: "echo installed"},
	Files: []pacman.File{
		{Path: "usr/bin/hello", Mode: 0o755, Data: []byte("#!/bin/sh\necho hello\n")},
	},
}

var pkg bytes.Buffer
err := spec.Write(&pkg, pacman.WriteOptions{Compression: pacman.CompressionZstd, ClampMTime: true})

entry, err := pacman.NewDBEntry(spec.FileName(pacman.CompressionZstd), bytes.NewReader(pkg.Bytes()), nil)

var db bytes.Buffer
err = pacman.WriteDB(&db, []pacman.DBEntry{*entry}, false)

var index pacman.Index
err = index.AddDatabase("local", &db)

dep, _ := pacman.ParseDependency("hello>=0.9")
best, err := index.Resolve(dep)
```

Package a directory tree:

```go
files, err := pacman.ScanDir("pkgroot")
spec := &pacman.Spec{Info: info, Files: files}
err = spec.WriteFile("out/"+spec.FileName(pacman.CompressionZstd), pacman.WriteOptions{})
```

Sync databases from the mirrors of a `pacman.conf` and download a package,
verifying signatures against a keyring:

```go
keyring, err := gpg.LoadKeyringFile("archlinux.gpg")
client, err := pacman.NewClient(pacman.ClientOptions{
	Keyring:           keyring,
	DBSignatures:      pacman.VerifyRequired,
	PackageSignatures: pacman.VerifyRequired,
})

cfg, err := pacman.ParseConfigFile("pacman.conf")
n, err := client.Sync(ctx, cfg.Repos, "sync")

db, err := client.FetchDB(ctx, cfg.Repos[0])
entries, err := db.Entries()
path, err := client.DownloadPackage(ctx, cfg.Repos[0], &entries[0], "cache")
```

## Security notes

- Packages and databases are untrusted input. Decompressed size, entry count,
  path length, file-list size, and the zstd and xz windows all have explicit
  limits (`MaxUncompressedBytes`, `MaxFileEntries`, `MaxDBBytes`, ...); hitting
  one returns an error wrapping a sentinel such as `ErrPackageTooLarge`.
- Paths inside packages are validated; an unsafe one fails with
  `ErrUnsafeEntry`. `ScanDir` opens files below its root and does not follow
  links out of it.
- The writer rejects line breaks, NUL bytes and invalid UTF-8 in metadata
  fields, and paths that could clash with the metadata files, so a field value
  cannot inject another `.PKGINFO` line.
- The client checks a package against the size and SHA-256 (or MD5) of its
  database entry, and against its signature when `PackageSignatures` is set. A
  signature that cannot be fetched is an error, not "unsigned". A failed
  database or package is discarded and the next mirror is tried.
- The library never reads a host path on its own: configuration, keyrings and
  directories are passed in.
- `.MTREE` carries SHA-256 digests only.

## License

Apache License 2.0, see [LICENSE](../LICENSE).
