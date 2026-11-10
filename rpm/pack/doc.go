// Package pack writes rpm packages. It is designed to be simple to use and
// deploy: it is pure Go, needs no rpmbuild and no access to the file system.
//
// Describe the package with RPMMetaData, create it with NewRPM, add the files
// with RPM.AddFile and the scripts with the Add* methods, and write the result
// with RPM.Write:
//
//	r, err := pack.NewRPM(pack.RPMMetaData{Name: "example", Version: "3", Release: "1"})
//	if err != nil { ... }
//	r.AddFile(pack.RPMFile{Name: "/usr/local/hello", Body: []byte("hello"), Mode: 0o644})
//	err = r.Write(w)
//
// Set RPMMetaData.Format to FormatV6 to write the format of rpm 6.0 instead of
// the default FormatV4. The package can be signed while writing with
// RPM.SetPGPSigner, or afterwards with the rpm package.
//
// FromTar builds a package from a tar archive; the tar2rpm command in
// github.com/M0Rf30/pkgformat/cmd/tar2rpm is a front end for it.
package pack
