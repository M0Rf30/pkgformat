// Package source reads, verifies, unpacks, builds and indexes Debian source
// packages.
//
// A source package is a .dsc control file plus the files it lists: the
// pristine orig tarball(s) and a Debian diff (format "1.0"), a debian
// tarball whose debian/patches/series quilt patches are applied on unpack
// ("3.0 (quilt)"), or a single tarball ("3.0 (native)").
//
// The package covers the surrounding documents too: the .dsc itself
// ([ParseDSC], [DSC.Marshal], [DSC.Sign], [ParseSignedDSC]), a Sources index
// ([ReadSources], [WriteSources]), the .changes upload description
// ([ParseChanges], [Changes.Marshal]) and the .buildinfo build record
// ([ParseBuildInfo], [BuildInfo.Marshal]). Every one is deb822 and goes
// through [deb.ParseControlFile]; clear-signed wrappers are verified with a
// [gpg.Keyring] and created with a [gpg.Signer].
//
// [Unpack] verifies the files against the checksums of the .dsc, extracts the
// tarballs the way dpkg-source -x does and applies the patches with the
// same strictness (fuzz 0), writing only inside the target directory
// ([safepath]). [Build] is the opposite for formats "3.0 (native)" and
// "3.0 (quilt)": it packs a prepared tree and writes the .dsc.
//
// Format "3.0 (git)" is read and written as metadata but cannot be unpacked:
// that needs a git client, which this package never runs.
package source
