# deb

Debian packages and apt repositories, in pure Go. No `dpkg`, `ar` or `apt` is needed.

```
github.com/M0Rf30/pkgformat/deb        packages, control files, versions, indexes, Release, signing
github.com/M0Rf30/pkgformat/deb/apt    apt client: update, load, resolve, download
```

## What it does

| Area | API |
| --- | --- |
| Write a `.deb` | `Write`, `WriteFile` with a plain `Spec` and `[]Entry` (or `FSEntries` over an `fs.FS`) |
| Read a `.deb` | `ParseDebFileAt`, `ParseDebFile`, `(*DebFile).Extract`, `OpenData`, `Conffiles`, `Triggers`, `Shlibs`, `Symbols`, `Signatures` |
| Sign a `.deb` | `SignPackage` (debsigs `_gpgorigin` for `debsig-verify`, dpkg-sig `_gpgbuilder` manifests), `(*DebFile).VerifySignatures`, `DebsigPolicy` (policy file for `debsig-verify`) |
| deb822 | `ParseControlFile` (strict, one paragraph), `ScanControl` (lenient, every paragraph), `ControlFile` |
| Versions | `CompareVersions` (the dpkg algorithm), `ValidVersion`, `StripEpoch` |
| Relations | `ParseRelations` (keeps `:any`/`:native` qualifiers, `[arch]` and `<profile>` restrictions), `FormatRelations`, `Relation.AppliesTo`, `ActiveRelations`, `ArchMatches` (architecture wildcards), `DependencyNames`, `NormalizeDependency` |
| Installed packages | `FindStatus`, `OpenStatus`, `(*StatusDB)`: `Entries`, `List`, `InstalledNames`, `InstalledProvides`; `ParseStatus`; `ReadInfoList` for `/var/lib/dpkg/info/*.list` |
| Repository indexes | `Index` (Packages writer, plain and compressed), `ScanPackages`, `OpenIndex` (gz, bz2, xz, lz4, zst) |
| Release | `Release`, `ParseRelease`, `SignRelease`, `Trust` (InRelease and Release.gpg verification policy) |
| apt client | `apt.Update`, `apt.Load`, `(*apt.Cache)`: `Lookup`, `ResolveVirtual`, `ResolveDeps`, `Download`, `DownloadClosure` |

Compression of written packages: `gzip`, `xz`, `zstd` (default) or none. Index decoders also read `bzip2` and `lz4`.

## Design

* **The writer takes plain structs.** `Spec` carries the control fields, scripts, conffiles, Multi-Arch, debconf and the compression. Nothing in the package knows any build recipe format.
* **Output is deterministic.** Entries are written in the order given, modification times come from `Spec.ModTime` and `Entry.ModTime`, owners are root:root, and a given input gives the same bytes. `dpkg-deb -I`, `-c`, `-x` and `md5sum -c` accept the result.
* **Untrusted input is bounded.** Package size, control archive, control file, lines, paragraphs, indexes (decompressed), Releases, extraction size and entry count each have a limit, exported as a constant. Hitting one gives a typed error (`ErrDebFileTooLarge`, `ErrTooLarge`, ...). Parsers do not panic; every entry point has a fuzz target.
* **Extraction cannot escape.** `Extract` resolves every path under the target directory, including symlink chains (see the `safepath` package).
* **Errors are values.** `fmt.Errorf("deb: ...: %w")` with exported sentinels; `errors.Is` works.
* **No globals, no host paths.** The apt client takes the lists directory, the dpkg status file, the keyring paths and the HTTP client as options. `*slog.Logger` is optional.

## The installed database

`OpenStatus` (or `NewStatusDB` over an `io.ReaderAt`) reads a dpkg `status` file
read-only, in bounded memory, one stanza at a time. `FindStatus("/")` gives the
path under a root. Each `StatusEntry` has the parsed `Package`, the `Status`
split into want, flag and state (`install ok installed`), and the `ControlFile`
with every field, which `ControlFile.String` writes back as dpkg wrote it
(a `Conffiles:` list included).

`Status.Installed()` is true only when the state is `installed`, as in apt's
and dpkg's own notion of an installed package: a package that is `unpacked`,
`half-configured`, `half-installed`, `triggers-awaited`, `triggers-pending` or
`config-files` (removed, configuration kept) is not. The want does not matter,
so a package on hold is installed. `InstalledNames` and `InstalledProvides`
count those only; the provides include the names of versioned provides
(`Provides: foo (= 1)` gives `foo`) and the name of the package itself, and
names carry no architecture qualifier. `ReadInfoList` reads the file list
`<name>:<arch>.list` (or `<name>.list`) from an `fs.FS` rooted at
`/var/lib/dpkg/info`. A stanza with no `Package` is skipped and logged at debug
level; the file size and the number of stanzas are limits
(`StatusOptions.MaxBytes`, `MaxEntries`).

## Verification policy

`Trust` implements what apt does, with one strict rule:

* a signature that exists and does not verify (altered data, expired or revoked key) is **always** an error, even with `AllowUnverified`;
* no keys, an unknown signer, or no signature at all are errors unless `AllowUnverified` is set, which accepts the document and logs a warning;
* `Valid-Until` is checked separately by `Release.CheckValidity`; `apt.Update` calls it with `UpdateOptions.Now`.

`apt.IsVerificationError` separates these trust failures from network ones in the joined error `Update` returns.

## Package signatures

`SignPackage` copies a package and appends one signature member; it takes any `gpg.Signer`, so the key can live in a KMS or an agent.

* `SchemeDebsigs` (default, role `origin`): `_gpgorigin` holds a detached signature of `debian-binary`, the control archive and the data archive concatenated. `DebsigPolicy.Marshal` renders the `.pol` file `debsig-verify` needs next to a keyring of the public key.
* `SchemeDpkgSig` (role `builder` by default): `_gpgbuilder` holds a clear-signed manifest with the size, MD5 and SHA-1 of each core member, as `dpkg-sig` writes it. Signing again picks the suffixes `0`-`9`, `A`-`Z` like dpkg-sig.

`(*DebFile).VerifySignatures(keyring)` checks every `_gpg*` member and returns one `PackageSignature` each. A member that does not verify fails with `ErrInvalidPackageSignature` (and `gpg.ErrUnknownSigner` for a key outside the keyring); no member at all is `ErrNoPackageSignature`. The caller decides which keys to trust.

`dpkg-sig` and `debsig-verify` reject what they cannot read: `dpkg-sig --verify` knows only `gzip`, `xz` and `bzip2` members, and `debsig-verify` rejects SHA-1 signatures, which `gpg.Signer` implementations here do not make. `testdata/sign` holds packages signed by the reference tools and `generate.sh` rebuilds them in a Debian container; the tests also hand packages signed by this module to `debsig-verify` and `dpkg-sig` there.

## Behaviour to know

* deb822 values are *logical*: the continuation marker is removed and a `" ."` line is an empty line. `ControlFile.String` and the Packages writer re-encode them.
* The writer rejects field values containing a newline (it would inject fields).
* Control files and tar entries use `./` prefixes, as dpkg-deb does. `Installed-Size` is computed from the payload.
* Package names must match `^[a-z0-9][a-z0-9+.-]+$`.
* `Release.PackagesVariants` lists the variants a Release declares, best compression first (`.xz`, `.zst`, `.gz`, `.bz2`, `.lz4`, plain); `apt.Update` only fetches a variant whose SHA-256 the verified Release lists.
* The apt cache keys entries by `name:arch`; architecture `all` lives under the bare name. Every version the indexes carry is kept, the highest is the candidate (`Lookup`), `Versions` lists them all.
* `ResolveDeps` honours version constraints, alternatives, versioned and unversioned `Provides`, Pre-Depends, `Conflicts`/`Breaks` in both directions (`ConflictError`) and Multi-Arch (`foreign`, `allowed`, `same`, `:any`, `:native`, `:arch`). A dependency nothing satisfies is an `UnsatisfiedError`. Installed packages are never removed (apt would remove one a candidate conflicts with); `apt/testdata/diff` compares the result with `apt-get install -s` for a set of real packages.
* A plain-http transfer that fails transiently is retried once over https.

## Not included

Writing the dpkg status database and running maintainer scripts are the installer's job and live outside this module. The status reader is read only.
