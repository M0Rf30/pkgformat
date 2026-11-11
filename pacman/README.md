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
| Write `.pkg.tar.zst`, `.xz`, `.gz` | `Spec`, `PkgInfo`, `BuildInfo`, `Scriptlets`, `File`, `ScanDir`, `ScanDirWith`, `Spec.Write`, `Spec.WriteFile`, `WriteOptions` |
| Read packages | `ReadPackage`, `ParsePkgInfo`, `ParseBuildInfo`, `ReadMetadata`, `ParseInstall`, `WalkPackage` |
| Extract and verify | `Extract`, `ExtractOptions`, `VerifyPackage`, `VerifyPackageWith`, `VerifyInstalled`, `VerifyOptions`, `MtreeError` |
| `.MTREE` | `ParseMtree`, `ReadMtree`, `Mtree`, `MtreeEntry`, `MtreeKeys`, `(*LocalDB).Mtree`, `(*LocalDB).VerifyInstalled` |
| Installed packages | `FindLocalDB`, `OpenLocalDB`, `NewLocalDB`, `(*LocalDB)`: `Packages`, `List`, `InstalledNames`, `InstalledProvides` |
| Sync databases | `ReadDB`, `ReadFileLists`, `WriteDB`, `NewDBEntry`, `DBEntry` |
| Versions and dependencies | `Vercmp`, `ParseDependency`, `Dependency.Allows` |
| Signatures | `SignDetached`, `NormalizeSignature`, verification through [`gpg`](../gpg/README.md) |
| `pacman.conf` and mirrorlists | `ParseConfig`, `ParseConfigFile`, `ParseConfigFS`, `ParseOptions`, `Config`, `Repo`, `SigLevel`, `ParseMirrorlist`, `ExpandServer`; `Config`: `IsHeld`, `IsIgnored`, `Arch`, `AllowedArchitectures`, `ResolveOptions`, `ApplyUsage`, `ReposFor` |
| Repository client | `Client`: `FetchDB`, `SyncDB`, `Sync`, `DownloadPackage`, `DownloadPackageFile`, `VerifyPackageFile` |
| Search and resolution | `Index`: `Lookup`, `Providers`, `Search`, `Group`, `Resolve`, `ResolveDeps`, `Install`, `Sysupgrade`, `OptionalDeps`, `SetUsage`; `ResolveOptions`, `Transaction`, `Upgrade`, `Replacement`, `ConflictError`, `BrokenDependencyError`, `OptionalDep`, `ParseOptionalDep` |

The writer produces what makepkg does: `.PKGINFO`, `.BUILDINFO`, a gzipped
`.MTREE` with SHA-256 digests, `.INSTALL` with the six hooks, `.CHANGELOG`, and
a payload sorted by path with its parent directories. With
`WriteOptions.ClampMTime` the archive is reproducible from the build date.

A `File` can also be a hard link (`Hardlink`), a pipe, a character or block
device (`DevMajor`, `DevMinor`), and carry an owner (`UID`, `GID`, `Uname`,
`Gname`) and extended attributes (`Xattrs`, stored as the `SCHILY.xattr.*` and
`LIBARCHIVE.xattr.*` PAX records bsdtar writes, `security.capability`
included). `ScanDir` finds hard links and pipes; `ScanDirWith` also reads
owners and xattrs. The `.MTREE` lists a hard link as the file it is, and
`WriteOptions.MtreeMD5` adds `md5digest` before `sha256digest`, in the order
bsdtar writes them (makepkg 7.1 writes `sha256digest` only).

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

cfg, err := pacman.ParseConfigFile("/etc/pacman.conf", pacman.ParseOptions{})
n, err := client.Sync(ctx, cfg.Repos, "sync")

db, err := client.FetchDB(ctx, cfg.Repos[0])
entries, err := db.Entries()
path, err := client.DownloadPackage(ctx, cfg.Repos[0], &entries[0], "cache")
```

## Resolution

An `Index` holds the sync databases (`AddDatabase`, `Add`) and plans what
`pacman -S` and `pacman -Su` would do, with libalpm's choices:

```go
local, err := localDB.List(ctx) // []*pacman.InstalledPackage
tx, err := index.Install([]string{"app", "base"}, pacman.ResolveOptions{Local: local})
tx, err = index.Sysupgrade(local, pacman.ResolveOptions{IgnorePkg: []string{"linux*"}})
// tx.Packages in dependency order; tx.Installs, tx.Upgrades, tx.Replacements, tx.Removals
```

- A dependency is looked up among the installed packages (`ResolveOptions.Local`,
  `ResolveOptions.Installed`) first, then in the repositories in the order they
  were added. A package of the exact name wins (the newest version of the first
  repository that has it), then a provider: an installed one, then the one of
  the earliest repository, then the lowest name. Pass `Index.SetUsage`
  (`Config.ApplyUsage` does it for every repository) to keep a repository out
  of resolution: libalpm uses one whose `Usage` has `Install` or `Upgrade`.
- Versions compare with `Vercmp`; `=`, `<`, `<=`, `>` and `>=` constrain a
  dependency, a conflict or a replacement. A provision without a version
  satisfies only a dependency without one.
- A root can be a dependency expression, a provider or a group name
  (`Index.Group`); a group stands for its members.
- Conflicts: two packages of the transaction that conflict, by name, version or
  provision, fail with `ErrConflict` (`ConflictError` names both), unless one
  provides the name of the other, which then takes its place. A conflict with an
  installed package that stays fails the same way. A package that stops
  satisfying a dependency of an installed package fails with
  `ErrBrokenDependency`. An unsatisfiable dependency fails with `ErrUnresolved`.
- `Sysupgrade` upgrades every installed package whose first repository holds a
  newer version, and applies `replaces` (the replacement is installed, the
  replaced package removed). `IgnorePkg` and `IgnoreGroup` (globs, as in
  pacman.conf; `Config.ResolveOptions` fills them) keep a package from being
  upgraded, replaced or picked as a dependency; a package asked for by name is
  installed anyway. Repositories without the `Upgrade` usage are skipped.
- Optional dependencies are listed (`IndexedPackage.OptionalDeps`,
  `Index.OptionalDeps`, parsed by `ParseOptionalDep`) and never installed unless
  `ResolveOptions.WithOptional` is set.

`testdata/resolver` holds the scenarios the tests replay against the output of
a real pacman (see its README).

## Reading pacman.conf

`ParseConfig`, `ParseConfigFile` and `ParseConfigFS` read every option of
`[options]` and the keys of the repository sections, with the semantics of
pacman 7: `Include` (recursive, with globs, in `[options]` and in
repositories, the current section carrying on after an include), list
options split on spaces, single-valued options, the root-relative defaults of
`DBPath` and `LogFile`, `ParallelDownloads`, `CleanMethod`, `DisableSandbox`
and the boolean flags. `ParseOptions.Include` decides how an `Include` is
resolved: `ParseConfigFile` reads the host, `ParseConfigFS` any `fs.FS`, and
with neither (`ParseConfig` and no resolver) the line is skipped. Directives
the parser does not know are kept in `Config.Unknown`, or fail with
`ErrUnknownDirective` under `ParseOptions.Strict`.

`SigLevel` is typed: `Config.SigLevel`, `LocalFileSigLevel`,
`RemoteFileSigLevel` and `Repo.SigLevel` hold a package and a database
`SigPolicy` (`SigNever`, `SigOptional`, `SigRequired`, plus `TrustedOnly` or
`TrustAll`), computed like pacman does: tokens apply left to right over the
global level, which each repository starts from. The `Client` enforces a
repository's `SigLevel` over `ClientOptions.DBSignatures` and
`PackageSignatures`, which remain the fallback when the repository has none.
The keyring has no trust levels, so `TrustedOnly` and `TrustAll` verify alike.

`Repo.Usage` limits what a repository is used for: `Client.Sync` skips those
without `UsageSync`, and `Config.ApplyUsage` passes the rest to an `Index`,
whose resolution then keeps to repositories with `UsageInstall`.
`Config.ResolveOptions` carries `IgnorePkg` and `IgnoreGroup`, `IsHeld` and
`IsIgnored` answer `HoldPkg` and `IgnorePkg` with pacman's glob matching, and
`Repo.CacheServers` (`CacheServer`) are tried before `Server` for packages,
never for databases. `DownloadPackageFile` and `VerifyPackageFile` apply a
`SigPolicy` to a package that is not in a database.

## Extracting and verifying packages

`ReadMetadata` returns `.PKGINFO`, `.BUILDINFO` (formats 1 and 2), `.INSTALL`
(with the hook functions it defines, `InstallScript.Has`), `.CHANGELOG` and the
parsed `.MTREE`. `ParseMtree` reads every keyword (`type`, `mode`, `uid`,
`gid`, `uname`, `gname`, `size`, `time` with fractions, `link`, `nlink`, the
md5, sha1, sha256, sha384, sha512 and rmd160 digests, `cksum`, `flags`,
`device`, `inode`, `contents`, `optional`), `/set` and `/unset`, the nested
form with `..`, continuation lines and `\ooo` escapes; the keywords of an
entry are `MtreeEntry.Keys`.

`Extract` unpacks below a directory: modes and mtimes, owners (`Chown`, which
needs privilege), hard links, symbolic links, pipes, device nodes
(`SpecialFiles`) and xattrs (`Xattrs`). Nothing is written outside the
directory: entry names are validated, and a symbolic link is resolved as a
chroot would, so `lib -> /usr/lib` works and `evil -> /` stays inside. Special
mode bits follow `ExtractOptions.Umask`, and `MaxBytes` and `MaxEntries` bound
the work. `Verify` checks the result against the `.MTREE`; so do
`VerifyPackage`, which checks the archive itself, and `VerifyInstalled`, which
checks a tree and reports a `*MtreeError` listing each `MtreeDiff`.

## The files database

`WriteDB(w, entries, true)` writes what repo-add writes into `<repo>.files`:
the `desc` and `files` members of each package, with the `%FILES%` list that
`NewDBEntry` reads out of the package, and `%PGPSIG%` when given a signature.
`ReadDB` reads it back, `ReadFileLists` reads the file lists of the wanted
packages only. The tests compare the members with those repo-add writes and
have `pacman -Fy`, `-Fl` and `-F` answer from a database written here.

## The local database

`OpenLocalDB` reads `/var/lib/pacman/local`, read-only and without locking:
`FindLocalDB("/")` gives the path under a root, and `NewLocalDB` reads any
`fs.FS`. Each `<name>-<version>` directory yields an `InstalledPackage` from
its `desc` (name, version, base, description, URL, architecture, packager,
build and install dates, installed size, install reason, licenses, groups,
validation, `xdata`, and the dependency, provides, conflicts and replaces
lists) and its `files` (`%FILES%` and `%BACKUP%`). `desc` is read with the
parser of the sync database. `LocalDB.Mtree` parses the `mtree` member, and
`LocalDB.VerifyInstalled` checks the installed files against it like
`pacman -Qkk`: directory times are left alone and the package's backup files
are not checked for content.

The name of a package is its `%NAME%`, never part of the directory name.
Symbolic links inside the database that point out of it are not followed. A
directory without a valid `desc`, with a malformed value, a path that climbs
out of the root, or over a limit is skipped and logged at debug level. An
`ALPM_DB_VERSION` other than 9 is `ErrUnsupportedLocalDB`. `InstalledNames`
and `InstalledProvides` do not read the `files` members: they list the names,
and the provides without version constraints and with each package's own name.
`LocalDBOptions` bounds the packages and the file records of one package, and
`SkipFiles` leaves the file lists out. pacman writes `(null)` as the checksum
of a `%BACKUP%` file it has none for; `BackupFile.MD5` keeps it.

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
- Configuration files are bounded: one file (`MaxConfigBytes`), all the files
  of a parse together (`MaxConfigTotalBytes`), repositories, servers and
  values (`MaxConfigRepos`, `MaxConfigServers`, `MaxConfigValues`), include
  depth (`DefaultMaxIncludeDepth`, ten as in pacman) and the number of
  included files (`DefaultMaxIncludeFiles`); hitting one wraps
  `ErrConfigLimit`. `ParseConfigFS` cannot leave its `fs.FS`. A repository
  that requires signatures with no keyring fails with `ErrNoKeyring` rather
  than skipping the check.
- `Extract` never follows a link out of its directory, refuses names with
  `..`, absolute names and control characters, and creates device nodes only on
  request; xattr counts and values are bounded (`MaxEntryXattrs`,
  `MaxXattrValueBytes`), and so are the `.MTREE` (`MaxMtreeBytes`,
  `MaxMtreeEntries`, `MaxMtreeLineBytes`) and the metadata files
  (`MaxMetadataBytes`, `MaxChangelogBytes`).
- `.MTREE` carries SHA-256 digests, and MD5 too under `WriteOptions.MtreeMD5`.

## License

Apache License 2.0, see [LICENSE](../LICENSE).
