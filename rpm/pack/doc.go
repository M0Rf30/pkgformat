// Package pack writes rpm packages. It is pure Go and needs no rpmbuild.
//
// Describe the package with RPMMetaData, create it with NewRPM, add the files
// with RPM.AddFile (or RPM.AddFS) and the scripts with RPM.AddScriptlet,
// RPM.AddTrigger and RPM.AddFileTrigger, and write the result with RPM.Write:
//
//	r, err := pack.NewRPM(pack.RPMMetaData{Name: "example", Version: "3", Release: "1"})
//	if err != nil { ... }
//	r.AddFile(pack.RPMFile{Name: "/usr/local/hello", Body: []byte("hello"), Mode: 0o644})
//	err = r.Write(w)
//
// # Streaming
//
// The content of a file is a byte slice (Body), an io.Reader of a known Size, a
// function that opens it (Open) or a path of the file system. Write compresses the
// payload into a temporary file (RPMMetaData.TempDir), because the header of an
// rpm precedes the payload and needs its digests and sizes, so memory use does not
// depend on the size of the package.
//
// # What is written
//
//   - Scriptlets with interpreter arguments, flags (expand, qformat, critical) and
//     Lua; pretrans, posttrans, preuntrans, postuntrans and verify scripts.
//   - Package triggers, file triggers and transaction file triggers with
//     priorities, laid out as rpmbuild lays them out.
//   - Hard links (content is stored once, also in the v6 stripped cpio), devices,
//     fifos and sockets, file capabilities, verify flags, languages, classes,
//     file dependencies, ghost, config, doc, license, readme, artifact files.
//   - The file digest algorithms SHA-256, SHA-512, SHA3-256 and SHA3-512.
//   - Every kind of dependency, with its scope and the rich (boolean) syntax checked,
//     and the rpmlib() requirements that follow from the features used.
//   - Header metadata: prefixes, changelog, translations, sysusers, modularity
//     label, dist tag, vcs, bug url, source rpm, platform and more.
//   - Signatures of the package (SetPGPSigner) and of the files (SetFileSigning:
//     IMA and fs-verity).
//
// Set RPMMetaData.Format to FormatV6 to write the format of rpm 6.0 instead of
// the default FormatV4.
//
// FromTar builds a package from a tar archive; the tar2rpm command in
// github.com/M0Rf30/pkgformat/cmd/tar2rpm is a front end for it.
package pack
