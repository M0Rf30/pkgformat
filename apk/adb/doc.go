// Package adb reads, verifies and writes APKv3 files: the packages and the
// repository indexes of apk-tools 3.
//
// # Format
//
// An APKv3 file is a stream that starts with the bytes "ADB." and a schema
// (SchemaPackage "pckg" or SchemaIndex "ndx."), followed by blocks. The ADB
// block holds the metadata as a tree of objects, arrays, integers and blobs
// that refer to each other by offset; blocks of signatures follow it, and for
// a package blocks of file content come last, each stamped with the position
// of the file in the tree. The whole stream may be compressed: "ADBd" is
// followed by a raw deflate stream, "ADBc" by two bytes naming the algorithm
// (deflate or zstd) and the level, and then the compressed stream.
//
// A signature covers the SHA-512 of the schema, the signature header and the
// digest of the ADB block, so one signature protects the file list, and the
// file list carries the digest of every file: nothing outside the ADB block
// needs signing. RSA (PKCS#1 v1.5) and ECDSA over P-256, P-384 and P-521 keys
// are supported, which are the keys apk-tools 3.0.9 handles; it rejects
// Ed25519 keys, so this package does too. A key is known by the first 16
// bytes of the SHA-512 of its public key.
//
// # Reading
//
// [ParsePackage] returns the metadata and the file list of a package;
// [VerifyPackage] additionally checks the signatures against a [Keyring] and
// the digest of every file; [Extract] unpacks into a directory with the paths
// confined to it. [Reader] is the streaming interface under all of them:
// [NewReader] reads the head of the file, [Reader.Next] and [Reader.Read]
// walk the entries. [ParseIndex] and [VerifyIndex] read a repository index.
//
// Everything read from a file is bounded: the size of the ADB block, of the
// decompressed stream, the number of entries and the work a hostile object
// graph can ask of the decoder are all limited, see [Limits].
//
// # Writing
//
// [WritePackage] writes a package from a [Spec], and [BuildIndex] an index of
// the [Info] entries that [IndexEntry] makes from packages. A [Signer]
// signs; several may sign the same file. The ADB block of a package comes out
// byte for byte the way apk mkpkg writes it, so tools that hash it get the
// same answer.
//
// # Compatibility
//
// The files interoperate with apk-tools 3.0.9: its apk verify accepts what
// this package signs, its apk add installs what it writes, and this package
// reads what apk mkpkg and apk mkndx write. [WriteOptions.Compat] chooses how
// much of the directory tree is written for older readers.
package adb
