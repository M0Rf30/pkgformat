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
and of what they provide (a package provides its own name); `*DB` therefore
satisfies [`dnf.Installed`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm/dnf#Installed),
the installed-package list of the dnf client.

`Find` looks, under the root, at `var/lib/rpm` and `usr/lib/sysimage/rpm` for
`rpmdb.sqlite`, `Packages.db` and `Packages`, in that order, and returns the
first that holds a database. It resolves links inside the root, never outside.

## Read only

A database is never written. SQLite is opened with `mode=ro` and `query_only`,
so a live database is read like `rpm -qa` does and a writer is not blocked;
`Options.Immutable` also sets `immutable=1`, for a database on read-only media
or a snapshot that nobody changes. The other two formats are read with
positioned reads.

A database that is being written to is read as of the moment of the read; the
reader takes no lock of its own on ndb and BerkeleyDB files.

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
Linux 8, openSUSE Tumbleweed and Fedora, and the output of `rpm -qa` for each;
see its [README](testdata/README.md).

## License

Apache License 2.0, see [LICENSE](../../LICENSE).
