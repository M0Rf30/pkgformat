package pack_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"strings"
	"testing/fstest"
	"time"

	"github.com/M0Rf30/pkgformat/rpm/pack"
)

// A minimal package with one file. Set Format: pack.FormatV6 to write the RPM v6
// format instead of v4.
func ExampleNewRPM() {
	r, err := pack.NewRPM(pack.RPMMetaData{Name: "example", Version: "3", Release: "1"})
	if err != nil {
		log.Fatal(err)
	}
	r.AddFile(pack.RPMFile{
		Name:  "/usr/local/hello",
		Body:  []byte("content of the file"),
		Mode:  0o644,
		Owner: "root",
		Group: "root",
	})

	var w bytes.Buffer // any io.Writer, for example an *os.File
	if err := r.Write(&w); err != nil {
		log.Fatal(err)
	}
	// Every rpm starts with the lead magic.
	fmt.Printf("% x\n", w.Bytes()[:4])
	// Output: ed ab ee db
}

func ExampleRPM_Write_invalidFile() {
	r, err := pack.NewRPM(pack.RPMMetaData{Name: "example", Version: "3"})
	if err != nil {
		log.Fatal(err)
	}
	// Names must be clean absolute paths.
	r.AddFile(pack.RPMFile{Name: "usr/../etc/passwd", Body: []byte("x")})
	err = r.Write(&bytes.Buffer{})
	fmt.Println(err)
	// Output: invalid rpm file: name "usr/../etc/passwd" is not a clean absolute path
}

// AddFS streams the files of an fs.FS (here an in-memory one; os.DirFS works the same) into the package: their
// content is never held in memory, and the compressed payload is spooled to a
// temporary file, so packages larger than memory can be written.
func ExampleRPM_AddFS() {
	r, err := pack.NewRPM(pack.RPMMetaData{Name: "tree", Version: "1", Release: "1", ImplicitDirs: true})
	if err != nil {
		log.Fatal(err)
	}
	fsys := fstest.MapFS{"bin/tool": {Data: []byte("#!/bin/sh\n"), Mode: 0o755}}
	if err := r.AddFS(fsys, pack.AddFSOptions{Prefix: "/opt/tree"}); err != nil {
		log.Fatal(err)
	}
	// A file can also come from any reader of a known size, or from a path.
	r.AddFile(pack.RPMFile{Name: "/opt/tree/big", Reader: strings.NewReader("streamed"), Size: 8})
	if err := r.Write(io.Discard); err != nil {
		log.Fatal(err)
	}
	fmt.Println("written")
	// Output: written
}

// Scriptlets run with an interpreter and arguments, and triggers fire on other
// packages or on files.
func ExampleRPM_AddTrigger() {
	r, err := pack.NewRPM(pack.RPMMetaData{Name: "hooks", Version: "1", Release: "1"})
	if err != nil {
		log.Fatal(err)
	}
	r.AddScriptlet(pack.ScriptPostin, pack.Scriptlet{
		Script:      "echo installed",
		Interpreter: []string{"/bin/sh", "-e"},
		Flags:       pack.ScriptExpand,
	})
	r.AddScriptlet(pack.ScriptPretrans, pack.Scriptlet{Script: `print("hello")`, Interpreter: []string{pack.LuaInterpreter}})
	dep, err := pack.NewRelation("openssl >= 3")
	if err != nil {
		log.Fatal(err)
	}
	r.AddTrigger(pack.Trigger{Kind: pack.TriggerIn, Conditions: pack.Relations{dep}, Script: pack.Scriptlet{Script: "ldconfig"}})
	r.AddFileTrigger(pack.FileTrigger{Kind: pack.FileTriggerIn, Prefixes: []string{"/usr/lib64"}, Priority: 100,
		Script: pack.Scriptlet{Script: "ldconfig"}})
	if err := r.Write(io.Discard); err != nil {
		log.Fatal(err)
	}
	fmt.Println("written")
	// Output: written
}

// Hard links share their content, which is stored once in the payload.
func ExampleRPMFile_hardlink() {
	r, err := pack.NewRPM(pack.RPMMetaData{Name: "links", Version: "1", Release: "1", Format: pack.FormatV6})
	if err != nil {
		log.Fatal(err)
	}
	r.AddFile(pack.RPMFile{Name: "/usr/bin/tool", Body: []byte("binary"), Mode: 0o755})
	r.AddFile(pack.RPMFile{Name: "/usr/bin/tool-alias", Hardlink: "/usr/bin/tool", Mode: 0o755})
	if err := r.Write(io.Discard); err != nil {
		log.Fatal(err)
	}
	fmt.Println("written")
	// Output: written
}

// A reproducible package: file times are clamped and the build time is fixed.
func ExampleRPMMetaData_reproducible() {
	epoch := time.Unix(1700000000, 0)
	build := func() []byte {
		r, err := pack.NewRPM(pack.RPMMetaData{Name: "repro", Version: "1", Release: "1", BuildTime: epoch, BuildHost: "builder", ClampTime: epoch})
		if err != nil {
			log.Fatal(err)
		}
		r.AddFile(pack.RPMFile{Name: "/f", Body: []byte("x"), MTime: uint32(time.Now().Unix())})
		var b bytes.Buffer
		if err := r.Write(&b); err != nil {
			log.Fatal(err)
		}
		return b.Bytes()
	}
	fmt.Println(bytes.Equal(build(), build()))
	// Output: true
}

// IMA and fs-verity signatures of the files are made while the package is
// written, as rpmsign --signfiles --signverity would do afterwards.
func ExampleRPM_SetFileSigning() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	r, err := pack.NewRPM(pack.RPMMetaData{Name: "signed", Version: "1", Release: "1"})
	if err != nil {
		log.Fatal(err)
	}
	r.AddFile(pack.RPMFile{Name: "/usr/bin/tool", Body: []byte("binary"), Mode: 0o755})
	r.SetFileSigning(pack.FileSigning{IMAKey: key})
	if err := r.Write(io.Discard); err != nil {
		log.Fatal(err)
	}
	fmt.Println("signed")
	// Output: signed
}
