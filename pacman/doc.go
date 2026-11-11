// Package pacman builds, reads and indexes Arch Linux packages and
// repositories in pure Go, without makepkg, pacman or repo-add.
//
// # Writing packages
//
// A Spec describes a package with plain Go values: the PkgInfo that becomes
// .PKGINFO, an optional BuildInfo for .BUILDINFO, Scriptlets for .INSTALL, a
// changelog and the File list. Spec.Write produces a .pkg.tar.zst, .xz or .gz,
// with .PKGINFO, .BUILDINFO, .MTREE, .INSTALL and .CHANGELOG in the order
// pacman expects and every directory entry the payload needs. With
// WriteOptions.ClampMTime the output is reproducible: file times never exceed
// PkgInfo.BuildDate, as makepkg does with SOURCE_DATE_EPOCH. ScanDir lists a
// directory tree as Files. A File can be a hard link, a pipe, a device node,
// and carry an owner and xattrs (ScanDirWith reads them); WriteOptions.MtreeMD5
// adds md5digest to the .MTREE.
//
// # Reading packages and databases
//
// ReadPackage returns the PkgInfo and the file list of a package, ParsePkgInfo
// and ParseBuildInfo parse the metadata files on their own, and ReadDB reads a
// sync database ("core.db") into DBEntry values. WriteDB writes one, the way
// repo-add does, from entries NewDBEntry builds out of package files.
// Vercmp compares versions like libalpm. The files database
// ("core.files") is the same format: WriteDB with withFiles, ReadDB and
// ReadFileLists.
//
// # Extracting and verifying
//
// ReadMetadata reads the metadata files of a package, ParseMtree the .MTREE.
// Extract unpacks a package into a directory without writing outside it,
// restoring modes, times, hard links, pipes, optionally owners, device nodes
// and xattrs. VerifyPackage, VerifyPackageWith and Extract with Verify check a
// package against its .MTREE; VerifyInstalled and LocalDB.VerifyInstalled do
// what pacman -Qkk does for installed files.
//
// # The local database
//
// OpenLocalDB, NewLocalDB and FindLocalDB read the installed packages of
// /var/lib/pacman/local, read-only: LocalDB.Packages yields an InstalledPackage
// for each package directory, from its desc and files members, named by its
// %NAME%. LocalDB.InstalledNames and LocalDB.InstalledProvides list the
// installed names and capabilities.
//
// # Repositories
//
// ParseConfig, ParseConfigFS and ParseConfigFile read pacman.conf, with its
// includes, into a Config of typed options and Repo values (SigLevel, Usage,
// Server, CacheServer); ParseMirrorlist reads a mirrorlist. They touch no file
// unless asked to (ParseConfigFile, ParseConfigFS), and no path is built in.
// A Client fetches databases from the servers of a Repo, with mirror failover,
// OpenPGP verification as the repository's SigLevel or ClientOptions say
// (VerifyMode) and atomic writes (SyncDB, Sync, which skips repositories whose
// Usage excludes it), and downloads packages checked against their database
// entry, from CacheServer addresses first (DownloadPackage), or from a URL
// (DownloadPackage).
//
// # Resolution
//
// An Index holds the entries of several databases. Index.Resolve and
// Index.ResolveDeps resolve dependencies and provisions; Index.Install plans
// what "pacman -S" does for targets that are packages, providers or groups
// (Index.Group), and Index.Sysupgrade what "pacman -Su" does, as a Transaction
// of installs, upgrades, replacements ("replaces") and removals. The plan
// follows libalpm: versioned dependencies, provisions and conflicts compare
// with Vercmp, a provision without a version satisfies only a dependency
// without one, a package of the exact name is preferred to a provider, ignored
// packages (ResolveOptions.IgnorePkg, IgnoreGroup) are not upgraded, and
// the Usage of a repository (Index.SetUsage) decides whether it is used.
// Conflicts and broken dependencies fail with ErrConflict and
// ErrBrokenDependency. Optional dependencies are exposed (OptionalDep) and not
// installed unless asked for.
//
// # Signatures
//
// SignDetached signs a package or database with a gpg.Signer and returns the
// binary signature pacman expects in a ".sig" file; NormalizeSignature accepts
// an armored one too.
//
// # Untrusted input
//
// Everything read is bounded: sizes, entry counts, path lengths and the zstd
// and xz windows have explicit limits, paths are validated, and failures are
// returned as errors wrapping the exported sentinels, never as panics. The
// writer rejects values that would corrupt a metadata file, such as a line
// break in a field.
package pacman
