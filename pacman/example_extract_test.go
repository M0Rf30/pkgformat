package pacman_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/pacman"
)

func examplePackage() []byte {
	built := time.Unix(1700000000, 0)

	spec := &pacman.Spec{
		Info: pacman.PkgInfo{Name: "shapes", Version: "1.0-1", Description: "Some shapes", Arch: "any", BuildDate: 1700000000},
		Scriptlets: &pacman.Scriptlets{
			PostInstall: "echo installed",
		},
		Files: []pacman.File{
			{Path: "usr/bin/shape", Mode: 0o755, ModTime: built, Data: []byte("#!/bin/sh\n")},
			{Path: "usr/bin/shape-hard", Hardlink: "usr/bin/shape", ModTime: built},
			{Path: "usr/bin/shape-link", Mode: fs.ModeSymlink | 0o777, Linkname: "shape", ModTime: built},
			{Path: "usr/share/shapes/data", Mode: 0o644, UID: 1234, GID: 5678, ModTime: built, Data: []byte("data\n")},
		},
	}

	var buf bytes.Buffer
	if err := spec.Write(&buf, pacman.WriteOptions{MtreeMD5: true}); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

// ReadMetadata returns the metadata files of a package: .PKGINFO, .BUILDINFO,
// .INSTALL, .CHANGELOG and the parsed .MTREE.
func ExampleReadMetadata() {
	md, err := pacman.ReadMetadata(bytes.NewReader(examplePackage()))
	if err != nil {
		fmt.Println(err)

		return
	}

	data, _ := md.Mtree.Lookup("usr/share/shapes/data")

	fmt.Println(md.Info.Name, md.Info.Version)
	fmt.Println("post_install:", md.Install.Has(pacman.HookPostInstall), "pre_remove:", md.Install.Has(pacman.HookPreRemove))
	fmt.Println(len(md.Mtree.Entries), "entries; data is", data.Size, "bytes owned by", data.UID, data.GID)
	// Output:
	// shapes 1.0-1
	// post_install: true pre_remove: false
	// 10 entries; data is 5 bytes owned by 1234 5678
}

// VerifyPackage checks the files of a package against its .MTREE.
func ExampleVerifyPackage() {
	pkg := examplePackage()

	fmt.Println(pacman.VerifyPackage(bytes.NewReader(pkg), pacman.VerifyOptions{}))
	// Output: <nil>
}

// Extract unpacks a package below a directory and checks it against its
// .MTREE. Nothing is written outside the directory.
func ExampleExtract() {
	dir, err := os.MkdirTemp("", "extract")
	if err != nil {
		fmt.Println(err)

		return
	}

	defer func() { _ = os.RemoveAll(dir) }()

	pkg, err := pacman.Extract(bytes.NewReader(examplePackage()), dir, pacman.ExtractOptions{
		Verify:        true,
		VerifyOptions: pacman.VerifyOptions{IgnoreOwner: true}, // the owners need root
	})
	if err != nil {
		fmt.Println(err)

		return
	}

	target, _ := os.Readlink(filepath.Join(dir, "usr/bin/shape-link"))
	a, _ := os.Stat(filepath.Join(dir, "usr/bin/shape"))
	b, _ := os.Stat(filepath.Join(dir, "usr/bin/shape-hard"))

	fmt.Println(pkg.Info.Name, len(pkg.Files), "files")
	fmt.Println("symlink to", target, "- hard link:", os.SameFile(a, b))
	// Output:
	// shapes 8 files
	// symlink to shape - hard link: true
}

// ParseMtree reads an .MTREE, applying /set and /unset.
func ExampleParseMtree() {
	mt, err := pacman.ParseMtree(strings.NewReader(`#mtree
/set type=file uid=0 gid=0 mode=644
./usr type=dir mode=755
./usr/bin type=dir mode=755
./usr/bin/tool mode=755 size=10 time=1700000000.0
`))
	if err != nil {
		fmt.Println(err)

		return
	}

	tool, _ := mt.Lookup("usr/bin/tool")
	fmt.Println(tool.Type, tool.FileMode(), tool.Size, tool.Time.Unix())
	// Output: file -rwxr-xr-x 10 1700000000
}
