// Package deb reads, writes and indexes Debian binary packages and the
// metadata of apt repositories.
//
// # Writing packages
//
// A Spec describes the package (name, version, relationships, maintainer
// scripts, conffiles, copyright data) and a list of Entry values describes its
// payload. Write streams the package to an io.Writer and WriteFile replaces a
// file atomically. The payload is staged in a temporary file, so a package of
// any size is written in bounded memory; set WriteOptions.TempDir to choose
// where. Entries carry their content as bytes or as an Open function, and
// FSEntries lists an fs.FS as entries. Output is reproducible: nothing but the
// Spec, the entries and their modification times goes into the package, and
// Spec.ModTime overrides the time of entries that have none.
//
// # Reading packages
//
// ParseDebFileAt and ParseDebFile read the ar container and the control
// archive of a package given as an io.ReaderAt, in gzip, xz, zstd, bzip2 or
// uncompressed form, and return a DebFile with the parsed control file, the
// maintainer scripts and the md5sums. Reading is bounded: the size of the
// package, of the control archive and of its files are limited, and
// ParseOptions adjusts the limits. DebFile.OpenData streams the payload and
// DebFile.Extract unpacks it into a directory; Extract refuses entries that
// would be written outside the directory, whether by their name, by a link or
// by writing through a link it created earlier, and bounds the number of
// entries and the number of bytes.
//
// # Control files, versions and relations
//
// ControlFile is a parsed deb822 paragraph that keeps the order of its fields.
// ParseControlFile is strict and reads the first paragraph; ScanControl is
// lenient and visits every paragraph. Package extracts the common fields.
// CompareVersions orders versions as dpkg does, ValidVersion and StripEpoch
// help with their syntax, and ParseRelations reads a dependency field into
// alternatives with an optional version constraint, which Relation.Satisfied
// checks against a version. NormalizeDependency converts a "name>=version"
// dependency to control-file syntax.
//
// # Installed packages
//
// OpenStatus and NewStatusDB read a dpkg status file, bounded and read-only.
// StatusDB.Entries yields each stanza as a StatusEntry: the parsed Package, the
// Status (want, flag and state, as in "install ok installed") and the
// ControlFile with every field. Status.Installed is true only for the state
// "installed", so packages that are unpacked, half-configured or removed with
// their configuration kept are not installed. StatusDB.InstalledNames and
// StatusDB.InstalledProvides list the installed names and capabilities, and
// ReadInfoList reads a package's file list from /var/lib/dpkg/info.
//
// # Repository indexes and Release files
//
// Index builds a Packages file from IndexEntry values (EntryFromControl makes
// one from a control file and the file facts HashReader computes) or from
// ready-made stanzas, and renders it plain or compressed with gzip, xz or
// zstd. ScanPackages and OpenIndex read an index back in any of the formats
// apt uses, with the size of the decompressed data bounded. Release lists the
// files of a distribution with their digests; Marshal renders it and
// ParseRelease reads a Release or an InRelease document, rejecting digests of
// the wrong length, paths that are not plain relative paths and
// contradicting sizes. Release.CheckValidity applies Valid-Until. The path
// helpers (PoolPath, PackagesPath, ReleasePath, ...) give the conventional
// locations.
//
// # Signing and verification
//
// SignRelease signs a Release document with a gpg.Signer and returns the
// three files apt fetches: Release, InRelease and Release.gpg. Trust holds the
// policy for the other direction, VerifyInRelease and VerifyReleaseGPG:
//
//   - a signature that exists and does not verify is always an error, even
//     with AllowUnverified, because it points to tampering or a broken mirror;
//   - no keyring, a signature by a key outside the keyring, and no signature at
//     all are errors unless AllowUnverified is set, in which case the document
//     is accepted and a warning goes to Logger.
//
// Nothing in this package reads keys from the host: the caller supplies the
// gpg.Keyring and decides what to trust.
//
// The subpackage deb/apt resolves and downloads packages from such
// repositories.
package deb
