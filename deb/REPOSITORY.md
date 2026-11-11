# Repository indexes: Release, by-hash, Contents, Translation

This page covers the index side of a Debian repository in package `deb`:
the `Release` file, the `by-hash` tree, `Contents-<arch>`, `Translation-<lang>`
and `i18n/Index`. Every format here is checked against real files from the
Debian and Ubuntu archives and against the real tools (`apt-ftparchive`,
`apt-file`, `apt`, `gpg`); the fixtures and the scripts that make them are in
`testdata/repo`, `testdata/repo-contents` and `testdata/repo-translation`, each
with a README.

## Release

`Release` models every field apt reads: Origin, Label, Suite, Version,
Codename, Date, Valid-Until, Architectures, Components, Description,
NotAutomatic, ButAutomaticUpgrades, Acquire-By-Hash, Signed-By (several lines),
Changelogs, Snapshots, No-Support-for-Architecture-all, the MD5Sum/SHA1/SHA256/
SHA512 listings, and `Extra` for any other field (kept with its spelling,
written after the known ones, sorted). `ParseRelease` is case-insensitive for
field names, reads the `Not-Automatic` spelling, accepts a clear-signed
`InRelease`, and normalizes times to UTC (also a blank padded hour such as
`Tue, 10 Nov 2026  7:42:48 UTC`).

Two tools write a Release, and they differ. `Marshal` and `MarshalStyle` pick
the layout:

| | `ReleaseStyleDebian` (default of `Marshal`) | `ReleaseStyleAptFTPArchive` |
| --- | --- | --- |
| Header field order | Origin, Label, Suite, Version, Codename, Changelogs, Snapshots, Date, Valid-Until, NotAutomatic, ButAutomaticUpgrades, Acquire-By-Hash, Signed-By, No-Support-for-Architecture-all, Architectures, Components, Description, then the extras | sorted by name |
| Date | `Thu, 12 Sep 2026 07:55:41 UTC` | `Wed, 11 Nov 2026 02:48:58 +0000` |
| Size column | 8 | 16 |
| Reproduced byte for byte from | Debian stable and bookworm-backports Release | `apt-ftparchive release` (apt 2.6.2) |

`apt-ftparchive release` supports only Origin, Label, Suite, Version,
Codename, Date, NotAutomatic, ButAutomaticUpgrades, Acquire-By-Hash, Valid-Until,
Architectures, Components and Description (its man page); the other fields exist
only in the Debian-style layout. Ubuntu's own files put `Acquire-By-Hash` after
the checksum sections; the parser is order-agnostic.

`SignRelease` signs the extended Release: `InRelease`, `Release` + `Release.gpg`
verify with `Trust` and with the real `gpg` (`TestExtendedReleaseSigningRoundTrip`,
`TestExtendedReleaseVerifiedByGPG`), and real apt accepts them
(`TestTranslationRepoWithApt/signed`).

### Finding index files

`IndexPath(component, arch, kind)` names an index without a compression
suffix; `Release.IndexPaths` returns the variants the Release lists, best
compression first (`.xz`, `.zst`, `.gz`, `.bz2`, `.lz4`, plain);
`Release.IndexVariants(base)` returns them with their `FileInfo`. Kinds:

| Kind | Path |
| --- | --- |
| `IndexPackages` | `<comp>/binary-<arch>/Packages` |
| `IndexPackagesUdeb` | `<comp>/debian-installer/binary-<arch>/Packages` |
| `IndexSources` | `<comp>/source/Sources` |
| `IndexContents`, `IndexContentsUdeb` | `<comp>/Contents-<arch>`, `<comp>/Contents-udeb-<arch>`; an empty component gives the top-level `Contents-<arch>` |
| `IndexTranslationPrefix + lang` | `<comp>/i18n/Translation-<lang>` (`pt_BR`, `zh-Hans` are fine) |

A component may contain a slash (`updates/main`); a component, architecture or
language with `..`, a blank or another unsafe character gives no path.
`Release.TranslationLanguages(comp)` lists the languages a component has.

## by-hash

With `Acquire-By-Hash: yes` a client fetches `<dir>/by-hash/<ALG>/<hex>`
instead of the index name, so an index and its Release can never disagree.
`WriteByHash(distDir, release, opts)` (a directory) and `WriteByHashFS`
(any `fs.FS`, copies) lay the tree out for every file the Release lists:

* `ByHashOptions.Algorithms`: default SHA256 and SHA512, as apt-ftparchive;
* `Mode`: `ByHashCopy` (zero value, what apt-ftparchive does and the only
  safe choice when an index may be rewritten in place), `ByHashHardlink`
  (falls back to a copy), `ByHashSymlink`;
* atomic (temporary file renamed over the name), idempotent (an existing file
  of the right size is kept, a torn one is replaced), copies keep the index
  modification time, mode 0644 in 0755 directories;
* size and digest of every index are verified first (`ErrByHashMismatch`).

Tree comparison with `apt-ftparchive release -o APT::FTPArchive::DoByHash=true`
(apt 3.3.5): same directories (`by-hash/SHA256`, `by-hash/SHA512` next to each
index, also for the top-level Contents and for the uncompressed index), same
bytes, copies (link count 1) with mode 0644 in 0755 directories
(`TestWriteByHashMatchesAptFTPArchive`).

### Retention

Clients that fetched an older Release still need the older files, so they are
kept for a while. `ByHashRetention{KeepGenerations, MaxAge, GenerationGap, Now}`
decides: the unlisted files of each `by-hash/<ALG>` directory are grouped into
generations by modification time (files within `GenerationGap`, default one
minute, are one publication); generation 1 is the newest the current Release
does not list. A generation is kept when it is among the newest
`KeepGenerations`, or when it was superseded less than `MaxAge` ago, which is
measured from the moment the next generation (or the current file) appeared,
not from the file's own time. Files that are not a digest of the algorithm are
ignored; leftover temporary files of an interrupted write older than an hour
are removed. `PlanByHashPrune` is the dry run (`ByHashPlan.Keep`/`Remove` with a
reason for each file), `ByHashPlan.Apply` and `PruneByHash` do it; listed files
are never touched and directories left empty are removed.

apt-ftparchive keeps files differently: `APT::FTPArchive::By-Hash-Keep` (default
3) counts files per directory by age, not generations. In an experiment with
seven runs that each changed `Packages` (apt 3.3.5), `By-Hash-Keep=2` left two
`Packages` hashes, `3` left four, `5` left all seven, and `1` or `0` also
removed the file the current Release lists. Generations are the more useful unit
(a publication changes several files at once) and a listed file is never
removed here.

## Contents

`ContentsBuilder` collects `Add(location, paths...)`, `AddDeb`/`AddDebAs` (the
files of a `.deb`, `DebContentsFiles`), `AddReader` (merge an existing index),
and renders `Bytes`, `Compressed(c)`, streaming `WriteTo(w, c)`: one line per
file, sorted by path, packages sorted and comma separated, so the same input
gives the same bytes. `ScanContents` is an `iter.Seq2[ContentsEntry, error]`
(streaming, line length bounded by `MaxLineBytes`, at most
`MaxContentsLocations` packages per file); `ParseContents` builds a
`ContentsIndex` for lookups (`Locations`, `Find`, `Entries`, at most
`MaxContentsFiles` files). `ContentsFileName` and `IndexContents` give the
names (`Contents-amd64`, `Contents-udeb-amd64`, top-level or per component).

Tool differences found against the real thing:

* padding: `apt-ftparchive` pads the path with tabs to column 56 and then four
  blanks; a path of 56 columns or more gets blanks up to column 60 and at least
  one. dak and Ubuntu's generator use blanks (dak) or tabs; none writes the
  `FILE LOCATION` header apt-ftparchive documents, but the parser skips it;
* names: `apt-ftparchive contents pool` writes the bare package name,
  `apt-ftparchive generate` writes `Section/name` (a package without a Section
  stays bare). `ContentsLocation` follows `generate`; use `AddDebAs` with the
  bare name for the `contents` form;
* members: apt-ftparchive lists every non-directory member (symbolic and hard
  links included); dak also lists usr-merge entries such as `bin`;
* a path may contain blanks; the package column is the last blank-separated
  word.

`contents.expected` and `generate.expected` are reproduced byte for byte and
against live runs; the three real heads parse; `apt-file` (Debian bookworm)
reads the index `ContentsBuilder` writes (`TestContentsReadByAptFile`; apt only
fetches a Contents index whose uncompressed form the Release lists too).

## Translation

`DescriptionMD5(description)` is the key of a translation: the MD5 of the
description as written in `Packages` (short line, then each extended line with
its leading blank). It equals the `Description-md5` of every entry of Debian
stable's `Translation-en` fixture. `FormatPackagesEntryShort` writes the stanza
a repository with translations publishes (short `Description` plus
`Description-md5`), checked against
`apt-ftparchive -o APT::FTPArchive::LongDescription=false packages`.

`TranslationBuilder` (`NewTranslationBuilder(lang)`, `Add`, `AddIndexEntry`,
`Bytes`, `Compressed`, `WriteTo`) writes `Translation-<lang>`, one paragraph per
distinct description, sorted by package name then md5 (Debian orders by its own
package order; `MarshalTranslation` writes entries in the order given and
reproduces the archive's files byte for byte). A translation is filed under the
md5 of the **English** description. `ScanTranslation` is an iterator,
`ParseTranslation` returns a map from md5.

`I18nIndex` (`AddFile`, `Marshal`, `Languages`, `Variants`, `ParseI18nIndex`,
`I18nIndexName`) is `<comp>/i18n/Index`: the checksum sections of a Release for
the Translation files, size column 7 and SHA1 only as in Ubuntu's file (read
and written back byte for byte). Debian itself publishes none.

### End to end

`TestTranslationRepoWithApt` (`PKGFORMAT_E2E=1`, podman) builds a repository
with this package only (`.deb`s, short `Packages`, `Translation-en/de`,
`i18n/Index`, by-hash, Release, optionally signed) and runs
`apt-get update -o Acquire::Languages=de` plus `apt-cache show` in a Debian
bookworm container; the output has `Description-de` with the German text and is
compared with `testdata/repo-translation/expected-*.txt`. Without the variable
(or without podman) the committed repository is only checked against the
builder.
