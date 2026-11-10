// Package rpmdb reads the database in which rpm records the packages
// installed on a host: SQLite (rpm 4.16 and later on Fedora, RHEL 9, Rocky 9,
// AlmaLinux 9, ...), the BerkeleyDB hash database of rpm 4.15 and earlier
// (RHEL 8 and its rebuilds, CentOS 7), and the "ndb" database of openSUSE and
// SUSE Linux Enterprise. It needs no rpm binary, no BerkeleyDB library and no
// cgo.
//
// # Opening
//
// [Find] looks for the database under a root directory the caller names, and
// [Open] opens a database file. The format is told from the leading bytes of
// the file, not from its name. The package assumes no host path: pass "/" to
// look at the running system, or the root of a container image or an install
// directory.
//
// The database is only ever read. SQLite is opened with mode=ro (or
// immutable=1, see [Options.Immutable]), the other two formats with a plain
// read-only file handle, so a database that rpm is using at the same time is
// not modified or locked for writing.
//
// # Reading
//
// [DB.Packages] iterates over the installed packages as [rpm.Package] values:
// name, epoch, version, release and architecture, the dependencies, the file
// list with modes, sizes, digests, link targets, owners and times, and the
// install time. [DB.List] collects them. [DB.InstalledNames] and
// [DB.InstalledProvides] answer the two questions a dependency resolver asks,
// and make a *DB usable as a [dnf.Installed].
//
// The records of the database are the header images of the packages (see
// [rpm.ReadHeaderBlob]); the three formats differ only in how they store them.
// A record that is not a package, such as the counters BerkeleyDB keeps next
// to them, or whose header does not decode, is skipped and reported at debug
// level to [Options.Logger]. A damaged container, such as a page that points
// outside the file, ends the read with [ErrCorrupt].
//
// # Untrusted input
//
// The readers are written for hostile files. Page and slot counts, overflow
// chains, record sizes and the number of records are bounded, the total amount
// read from a file cannot exceed the size of the file, and none of the readers
// panics on malformed input.
//
// [dnf.Installed]: https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm/dnf#Installed
package rpmdb
