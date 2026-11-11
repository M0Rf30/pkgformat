// Package apk builds, reads, verifies and signs Alpine Linux packages (.apk,
// the v2 format of apk-tools) and repository indexes, and fetches them from
// repositories. It is pure Go and needs neither abuild nor apk.
//
// # Packages
//
// An .apk file is two or three concatenated gzip members: an optional
// signature segment (a tar whose entry is named .SIGN.RSA.<key> or
// .SIGN.RSA256.<key>), the control segment (a tar that starts with .PKGINFO,
// followed by the install scripts) and the data segment (the files, each
// regular file with its SHA-1 in a PAX record). abuild leaves the
// end-of-archive blocks off the signature and control tars so a client reads
// the three segments as one tar stream.
//
// [WritePackage] writes a package from a [Spec] of plain structs: the
// metadata ([Info]), the [Scripts] and the [File] entries; [FilesFromDir]
// lists a staged directory tree. A package may hold directories (parents are
// added automatically), files, symbolic links, hard links, FIFOs, device nodes,
// owners and extended attributes, and the metadata includes a license list,
// origin, commit, triggers, replaces_priority, provider_priority and
// install_if. [ParsePackage] reads one back under explicit
// limits, [SignPackage] adds a signature and [VerifyPackage] checks it.
//
// # APKv3
//
// [ParsePackage] also reads the ADB packages of apk-tools 3 and sets
// [Package.Format] to [FormatV3]. The sub-package [github.com/M0Rf30/pkgformat/apk/adb]
// reads, verifies and extracts v3 packages and indexes, writes them the way
// "apk mkpkg" and "apk mkndx" do, and signs with RSA and ECDSA keys; it is
// tested against apk-tools 3.0.9.
//
// # Signatures
//
// Alpine signs with RSA and PKCS#1 v1.5, either over a SHA-1 digest
// (.SIGN.RSA.) or a SHA-256 digest (.SIGN.RSA256.). The type is always an
// explicit choice: a [Signer] is made for one [SigAlgorithm], and
// [VerifyOptions] lists the types a verifier accepts, with the trusted keys in
// a [Keyring] ([LoadKeyring] reads an apk keys directory). Nothing defaults to
// SHA-1. A Signer wraps any [crypto.Signer] with an RSA key, so the key may live
// in an HSM or a KMS; the signature is checked against the advertised public
// key before it is used. [ParsePrivateKeyPEM] reads PKCS#1 and PKCS#8 keys and
// [PublicKeyName] gives a keys-directory file name.
//
// # The installed database
//
// OpenInstalled and NewInstalledDB read /lib/apk/db/installed, read-only: an
// [InstalledPackage] per record, with the index fields and the directories and
// files it owns, their checksums, owners and modes. A record that is not valid
// is skipped. [InstalledDB.InstalledNames] and [InstalledDB.InstalledProvides]
// list the installed names and capabilities.
//
// # Indexes
//
// [BuildIndex] and [RenderIndex] write an APKINDEX.tar.gz or its text,
// [ParseIndex] reads one and [VerifyIndex] checks its signature.
//
// # Repositories
//
// [ParseRepositories] reads a repositories file. A [Client] fetches the index
// of each repository, requires a valid signature by a trusted key (unless the
// caller opts out), and downloads packages, checking each against its index
// entry. The [Index] it returns resolves package names, provided
// capabilities, and [Index.Solve] chooses the packages for a world.
//
// # Reading packages
//
// [OpenArchive] reads a package for its contents: [Archive.Files] and
// [Archive.Walk] give every [Entry] (type, mode, owner, hard link and symbolic
// link targets, device numbers, the recorded SHA-1 and the extended attributes
// such as security.capability), and [Archive.Extract] unpacks the data segment
// into a directory with every path confined to it and every file checked
// against its checksum. Owners, device nodes and extended attributes are opt-in
// because they need privileges.
//
// # Versions and dependencies
//
// [CompareVersions] orders versions exactly as "apk version -t" does (it is
// tested against that tool on thousands of pairs); [ParseDependency] and
// [Dependency.MatchVersion] read and test "name>=1.2", "name~1.2", "!name",
// "name@tag" and "name><checksum". Alpine versions have no epoch: a version
// with a colon is refused.
//
// # Choosing packages
//
// [Index.Solve] follows apk's solver: constraints, conflicts, versioned and
// unversioned provides, provider_priority, install_if, @tag repositories, the
// preference for what is installed, and backtracking when a choice leads to a
// conflict. Its answers are tested against "apk add --simulate" on synthetic
// and real Alpine indexes. [ParseWorld], [WorldAdd], [WorldDel] and
// [RenderWorld] handle the world file, and [ReplacesFile] decides who owns a
// file that two packages ship, from replaces and replaces_priority.
//
// Everything that reads untrusted bytes has explicit size and entry limits and
// returns typed errors; none of it panics on malformed input.
package apk
