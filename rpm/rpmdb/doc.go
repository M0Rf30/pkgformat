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
// The database is only ever read. SQLite is opened with mode=ro, the other two
// formats with a plain read-only file handle, so a database that rpm is using
// at the same time is not modified or locked for writing. [Options.SQLite]
// says what to do when SQLite cannot open a database in place, for example
// because it lies on read-only media with a write-ahead log (see [SQLiteMode]):
// the default falls back to an immutable read, or to a private copy when a log
// holds transactions the read has to see, and never creates a file next to the
// original in that case. A database that stays locked fails with [ErrLocked]
// after [Options.BusyTimeout] and [Options.LockRetries].
//
// # Reading
//
// [DB.Packages] iterates over the installed packages as [rpm.Package] values:
// name, epoch, version, release and architecture, the dependencies, the file
// list with modes, sizes, digests, link targets, owners and times, and the
// install time. [DB.List] collects them.
// [DB.InstalledPackages] returns them too, which makes a *DB usable as a
// [dnf.Installed].
//
// # Queries
//
// [DB.InstalledPackages] and the query methods answer from an index that the
// first of them builds from the whole database, once, safely for concurrent
// callers and within [Options.MaxIndexEntries]; [DB.Refresh] builds it again
// after rpm changed the database. The index follows rpm's own:
//
//   - [DB.ByName], [DB.ByNEVRA] and [DB.ByLabel] (what rpm -q takes: "bash",
//     "bash-5.2", "bash-5.2-1.fc40.x86_64");
//   - [DB.WhatProvides] with a capability that carries a version and a
//     comparison ([ParseCapability]): a provide "foo = 1.2-3" satisfies
//     "foo >= 1.0", by the overlap rules of librpm ([richdep.Atom.Overlaps]),
//     and a path is provided by the packages that own it;
//   - [DB.WhatRequires], [DB.WhatRecommends], [DB.WhatSuggests],
//     [DB.WhatSupplements], [DB.WhatEnhances], [DB.WhatConflicts] and
//     [DB.WhatObsoletes], which also find the capabilities inside rich
//     dependencies the way rpm does, and [DB.ConflictsOf], [DB.ObsoletedBy]
//     and [DB.ObsoletesOf] for the relations of one package;
//   - [DB.FileOwners]: rpm -qf, with the path cleaned, ghost files included
//     and files a package did not install left out.
//
// # Scripts
//
// [DB.Scripts] and [DB.AllScripts] return the [Scripts] of a package, read
// from the raw tags of its header: the scriptlets with their interpreter and
// flags, the triggers with their conditions, and the file triggers and
// transaction file triggers with their prefixes and priorities. [Scripts.String]
// prints them as rpm -q --scripts --triggers --filetriggers does.
//
// # Records
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
// [richdep.Atom.Overlaps]: https://pkg.go.dev/github.com/M0Rf30/pkgformat/rpm/richdep#Atom.Overlaps
package rpmdb
