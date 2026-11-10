// Package repodata writes and reads the metadata of an RPM repository: the
// repomd.xml index and the primary.xml, filelists.xml, other.xml, comps.xml and
// modules.yaml documents that dnf and yum fetch.
//
// # Writing
//
// The writers take the [rpm.Package] values that rpm.ReadPackage returns, set
// the checksum and size of the file, and stream a document to an io.Writer
// with memory use independent of the size of the repository:
// [WritePrimaryXML], [WriteFilelistsXML], [WriteOtherXML], [WriteCompsXML]. A
// [DocWriter] writes a document package by package. [CompressMetadataStream]
// compresses a document (gzip, zstd or xz) and returns the checksums and sizes
// repomd.xml records; [GenerateRepomdXML] writes the index, and [SignRepomdXML]
// signs it for clients that check repo_gpgcheck.
//
// The output is accepted by createrepo_c's own tools and equals what it writes
// for the same packages, up to formatting and an explicit epoch of 0.
//
// # Reading
//
// [ParseRepomd] reads repomd.xml, [OpenMetadata] decompresses a document by the
// extension of its name with a bound on the decompressed size, and
// [ReadPrimary] decodes primary.xml package by package with limits on the
// dependency lists, file lists and text fields. [ScanPackages] walks the
// <package> elements of any of the three documents and can hand them back
// verbatim, which is how [MergeModules] and a repository merge are built.
// [ModuleIndex] interprets modules.yaml the way dnf does when no module stream
// is enabled.
//
// # Untrusted input
//
// Every reader bounds what it keeps or decompresses and fails with
// [ErrTooLarge] when a limit is exceeded; none of them panics on malformed
// input.
package repodata
