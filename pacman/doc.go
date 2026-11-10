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
// directory tree as Files.
//
// # Reading packages and databases
//
// ReadPackage returns the PkgInfo and the file list of a package, ParsePkgInfo
// and ParseBuildInfo parse the metadata files on their own, and ReadDB reads a
// sync database ("core.db") into DBEntry values. WriteDB writes one, the way
// repo-add does, from entries NewDBEntry builds out of package files.
// Vercmp compares versions like libalpm.
//
// # Repositories
//
// ParseConfig and ParseMirrorlist read pacman.conf and mirrorlist text; they
// touch no file unless asked to (ParseConfigFile), and no path is built in. A
// Client fetches databases from the servers of a Repo, with mirror failover,
// optional OpenPGP verification (VerifyMode) and atomic writes (SyncDB, Sync),
// and downloads packages checked against their database entry
// (DownloadPackage). An Index holds the entries of several databases and
// resolves dependencies and provisions (Index.Resolve, Index.ResolveDeps).
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
