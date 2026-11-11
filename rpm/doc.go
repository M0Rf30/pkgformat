// Package rpm reads, verifies and signs RPM packages. It handles both the
// classic format 4 and the format 6 written by rpm 6.0, and is written in pure
// Go; cgo, when enabled, only switches zstd decompression to the C library.
//
// # Reading
//
// ReadRpm parses the lead and the headers of a package and gives access to the
// tags (see the tag package for their numbers), the files, and the payload:
//
//	pkg, err := rpm.ReadRpm(f)
//	if err != nil { ... }
//	nevra, err := pkg.Header.GetNEVRA()
//	provides, err := pkg.Header.GetStrings(tag.PROVIDENAME)
//	pkg.SetMaxPayloadSize(1 << 30) // bound the expansion of untrusted input
//	err = pkg.ExpandPayload(dir)
//
// The payload of a package can also be read sequentially with
// Rpm.PayloadReader and Rpm.PayloadReaderExtended, which handle hard links and
// the stripped cpio archives of format 6. Package github.com/M0Rf30/pkgformat/rpm/cpio
// has the archive reader and the extraction.
//
// ExpandPayload applies the modes (including set-uid, set-gid and sticky bits)
// and modification times of the package and verifies every regular file against
// the digest in the header; ExpandPayloadWithOptions masks the modes, applies
// owners, creates device nodes and FIFOs, or skips the digests on request.
//
// ReadPackage returns the metadata of a package as a plain struct: identity,
// sizes, the dependency lists (requires, provides, conflicts, obsoletes and the
// weak dependencies, with their sense flags), the file list and the changelog.
// It reads the headers only, with explicit limits (PackageLimits), and is what
// the writers of repository metadata in package repodata consume.
//
// # Verifying
//
// Verify checks the digests of a stream and the OpenPGP signatures of the
// header and payload against a keyring. It returns the signatures it
// found. A package that carries no signature at all is not an error: Verify
// returns an empty list, so callers that require a signature use
// VerifyWithOptions with RequireSigned, or check len(sigs).
//
// A signature is accepted only if its key is not revoked, not expired and
// allowed to sign, and the signature is not expired; the failure is a
// *SignatureError wrapping the matching error of package
// github.com/M0Rf30/pkgformat/gpg. VerifyOptions.Now sets the time those
// checks are made at.
//
// # Signing
//
// SignRpmStream computes the signatures of a package and returns the header
// that DumpSignatureHeader turns into the new lead and signature header, which
// replace the first OriginalSignatureHeaderSize bytes of the package. SignRpmFile
// does the same on a file. The header and payload are not touched.
//
// # Versions
//
// Vercmp compares versions the way rpm does, and NEVRA holds the name, epoch,
// version, release and architecture of a package.
//
// # Untrusted input
//
// Headers are parsed with limits on the number of tags and on their size, and
// payload extraction is confined to the destination directory. Decompression is
// bounded by DefaultMaxPayloadSize unless the header declares a larger payload;
// set a policy-specific bound with Rpm.SetMaxPayloadSize for untrusted input,
// and Rpm.SetVerifyPayloadDigest to check the payload against the digest of the
// (signed) header.
//
// Packages are written by the pack package; repositories are written and read
// by the repodata package and used by the dnf package.
package rpm
