# rpm/rpmdb

Part of [pkgformat](../../README.md) and of the [rpm](../README.md) packages.

[![Go Reference](https://pkg.go.dev/badge/github.com/M0Rf30/pkgformat/rpm/rpmdb.svg)](https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm/rpmdb)

A read-only reader of the installed-package database of an rpm system, in the
three formats rpm has used, with one interface and no `rpm` binary or C library:

| Format | File | Used by |
| --- | --- | --- |
| SQLite | `rpmdb.sqlite` | rpm 4.16 and later (Fedora, RHEL 9, Arch Linux, …) |
| ndb | `Packages.db` | openSUSE and SLE (rpm 4.16 and later) |
| BerkeleyDB hash | `Packages` | rpm 4.15 and earlier (RHEL 8, CentOS 7, …) |

The format is recognised from the content of the file, not its name. Each
package is decoded with the same bounded header parser as `rpm.ReadPackage`:
name, epoch, version, release, architecture, install time, provides, requires
and the file list with modes, sizes, digests, link targets, owners and times.

The package needs no host path: the caller gives the root (or the file) to
read. SQLite is the only format that needs a driver; it is
[modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite), which needs no cgo,
and only this package links it.

## Install

```sh
go get github.com/M0Rf30/pkgformat/rpm/rpmdb
```

## Use

```go
path, format, err := rpmdb.Find("/") // or the root of a container, a chroot, an image
if err != nil {
	log.Fatal(err) // rpmdb.ErrNotFound: no database under the root
}
db, err := rpmdb.Open(path, rpmdb.Options{})
if err != nil {
	log.Fatal(err)
}
defer db.Close()

for pkg, err := range db.Packages(ctx) {
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(pkg.Name, pkg.Version, pkg.Release, len(pkg.Files))
}
```

`List` returns the same packages as a slice. `InstalledNames` and
`InstalledProvides` return the sorted, distinct names of the installed packages
and of what they provide (a package provides its own name). `InstalledPackages`
returns the packages with their versioned dependencies, so `*DB` satisfies [`dnf.Installed`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm/dnf#Installed),
the installed-package list of the dnf client.

`Find` looks, under the root, at `var/lib/rpm` and `usr/lib/sysimage/rpm` for
`rpmdb.sqlite`, `Packages.db` and `Packages`, in that order, and returns the
first that holds a database. It resolves links inside the root, never outside.

## Queries

The first query method, like `InstalledPackages`, reads the whole database into
an index; the later ones answer from it. Building it is done once even when
many goroutines ask at the same time (a waiting caller leaves when its context
is done), is bounded by `Options.MaxIndexEntries`, and is repeated on demand by
`Refresh`. The results are shared with the index: do not modify them.

| Method | Finds |
| --- | --- |
| `InstalledPackages` | every package, by name, version and architecture |
| `ByName`, `ByNEVRA`, `ByLabel` | by name (all versions and architectures), by the set fields of an `rpm.NEVRA`, or by what `rpm -q` takes: `name`, `name-version`, `name-version-release`, an epoch before the version, `.arch` at the end |
| `WhatProvides` | providers of a capability, with version and comparison |
| `WhatRequires`, `WhatRecommends`, `WhatSuggests`, `WhatSupplements`, `WhatEnhances` | packages with such a dependency that overlaps the capability |
| `WhatConflicts`, `WhatObsoletes` | `rpm --whatconflicts`, `--whatobsoletes` |
| `ConflictsOf`, `ObsoletedBy`, `ObsoletesOf` | the conflicts and obsoletes of one package, in the direction that is asked |
| `FileOwners` | `rpm -qf` |

A capability is a `richdep.Atom`, which `ParseCapability("foo >= 1.0")`
builds. Matching follows librpm: a provide `foo = 1.2-3` satisfies the
requirement `foo >= 1.0`; the epoch counts when both sides have one, else a
nonzero epoch wins; the release is compared only when both sides have one; a
side with no comparison matches every version. A package also provides its own
name and version, and a path is provided by the packages that own the file.

`FileOwners` cleans the path (`path.Clean`; a relative path is taken from `/`)
and follows `rpm -qf`: ghost files and the directories a package lists are
owned, a file that a package lists but did not install (`--excludedocs`, or
replaced by another package, the `replaced` file state) is not, unless
`Options.IncludeUninstalledFiles` is set. Symbolic links are not followed: the
database knows paths, not the file system.

`WhatRequires` and the other dependency queries index the capabilities inside
rich dependencies as rpm does: `(foo if bar)` is found as a requirement of
`foo` and of the text `(foo if bar)`, but not of `bar`, which is only a
condition; with an `else`, the condition is found as well.

`ByLabel` compares versions, releases and architectures as written; the globs
and regular expressions of the rpm command line are not supported.

## Scripts and triggers

`Scripts(ctx, pkg)` and `AllScripts(ctx)` read the scriptlets (pretrans, pre,
post, preun, postun, posttrans, preuntrans, postuntrans, verify) with their
interpreter and flags, the triggers with their conditions and kind, and the file
triggers and transaction file triggers with their prefixes and priorities, from
the raw tags of the header. `Scripts.String()` prints them as
`rpm -q --scripts --triggers --filetriggers`; the tests compare the two byte for
byte on real packages. Headers are not kept in memory, so `Scripts` reads the
database to find the package; use `AllScripts` for many packages.

## Read only, and while rpm writes

A database is never written. The ndb and BerkeleyDB files are read with
positioned reads and no lock of their own; what is being written is read as of
the moment of the read.

SQLite is opened with `mode=ro` and `query_only`, so a live database is read
like `rpm -qa` does and a writer is not blocked. rpm keeps the database in WAL
mode; `Options.SQLite` chooses what to do when the file cannot be opened in
place:

| `Options.SQLite` | Behaviour |
| --- | --- |
| `SQLiteAuto` (default) | Open in place. If SQLite cannot (a read-only directory: it has no place for the `-shm` index), fall back: to `immutable=1` when there is no `-wal`/`-journal`, or an empty one; otherwise read a private copy of the database with its `-wal` and `-journal` (see below). Nothing is created next to the original. |
| `SQLiteInPlace` | Open in place only, and fail as SQLite does. SQLite itself creates `-shm` (and, in a writable directory, `-wal`) next to a WAL database it opens. |
| `SQLiteImmutable` | `immutable=1`: no lock, no side file, `-wal` and `-journal` ignored. For media that nothing writes; on a live database it may miss what rpm has not checkpointed. |
| `SQLiteSnapshot` | Always read a private copy. |

A snapshot is made in `Options.TempDir` (default `os.TempDir()`), is bounded by
`Options.MaxSnapshotBytes` (`ErrTooLarge`), is mode 0600, and is removed by
`Close`. It is copied again if a file changes while it is copied, up to
`Options.LockRetries` times, then `ErrLocked`. SQLite recovers the copied `-wal`
as it would the original's, so transactions a crashed writer committed are seen;
a database copied without its `-wal` shows what its main file holds, and a stale
or missing `-shm` is rebuilt from the `-wal`.

A writer that holds the database (an exclusive transaction of rpm) makes the
read wait for `Options.BusyTimeout` (default 5 s), and then repeat up to
`Options.LockRetries` times (default 2) with a growing pause. When it is still
locked the error matches `ErrLocked`, whether it came from `Open` or from a read;
it is never reported as `ErrCorrupt`. A cancelled context ends the waiting.

## Untrusted files

A database found in an image or a container is untrusted input.

- Every count and size is bounded: the number of records (`Options.MaxRecords`),
  the size of one record (`Options.MaxBlobBytes`), what one package may decode to
  (`Options.Package`), and the pages of a BerkeleyDB chain and the blocks of an
  ndb blob by the size of the file, so that a file cannot make the reader read
  more than it holds.
- A record that does not decode (rpm's own bookkeeping values, a damaged header,
  one over a limit) is skipped, and reported at debug level through
  `Options.Logger`; the other packages are still read.
- A damaged container, or a file that is not a database, returns an error that
  matches `ErrCorrupt`, `ErrFormat`, `ErrUnsupported` or `ErrTooLarge` with
  `errors.Is`. No input panics, and none can allocate beyond the limits.
- BerkeleyDB files that are encrypted or carry page checksums, and btree files,
  are `ErrUnsupported`: rpm does not write them.

The page, slot and header parsers are fuzzed (`go test -fuzz`).

## Test data

`testdata` holds a real database of each format, written by the rpm of Rocky
Linux 8, openSUSE Tumbleweed and Fedora, and the output of `rpm -qa` for each.
`rich.sqlite` (rpm 6.0.2, Fedora 43) adds packages with scriptlets, triggers,
file triggers, versioned and rich dependencies, and several versions and
architectures of one name, with what `rpm -q --scripts --triggers --filetriggers`,
`-qf`, `--whatprovides`, `--whatrequires` and the like print for them. See its
[README](testdata/README.md).

## License

Apache License 2.0, see [LICENSE](../../LICENSE).
