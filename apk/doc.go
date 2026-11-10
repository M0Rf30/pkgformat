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
// lists a staged directory tree. [ParsePackage] reads one back under explicit
// limits, [SignPackage] adds a signature and [VerifyPackage] checks it.
//
// # Signatures
//
// Alpine signs with RSA and PKCS#1 v1.5, either over a SHA-1 digest
// (.SIGN.RSA.) or a SHA-256 digest (.SIGN.RSA256.). The type is always an
// explicit choice: a [Signer] is made for one [SigAlgorithm], and
// [VerifyOptions] lists the types a verifier accepts, with the trusted keys in
// a [Keyring] ([LoadKeyring] reads an apk keys directory). Nothing defaults to
// SHA-1.
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
// capabilities and dependencies ([Index.ResolveDeps]).
//
// Everything that reads untrusted bytes has explicit size and entry limits and
// returns typed errors; none of it panics on malformed input.
package apk
