package adb

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The fixtures of testdata/ are made by testdata/generate.sh with apk-tools
// 3.0.9. fixtureSpec mirrors that script.

const fixtureEpoch = 1700000000

func fixtureFile(name string, mode fs.FileMode, data string) File {
	f := MemFile(name, mode, []byte(data))
	f.ModTime = time.Unix(fixtureEpoch, 0)

	return f
}

func fixtureTreeFiles() []File {
	xattrs := []Xattr{{Name: "user.fixture", Value: []byte("v1")}}
	conf := fixtureFile("etc/app.conf", 0o644, "conf\n")
	conf.Xattrs = xattrs

	hard := conf
	hard.Name, hard.HardLink = "etc/app.conf.hard", "etc/app.conf"

	hi := File{
		Name: "usr/bin/hi", Mode: fs.ModeSymlink | 0o777, LinkTarget: "hello", ModTime: time.Unix(fixtureEpoch, 0),
	}

	return []File{
		fixtureFile("usr/bin/hello", 0o755, "#!/bin/sh\necho hello\n"),
		fixtureFile("usr/bin/su", fs.ModeSetuid|0o755, "su\n"),
		hi, conf, hard,
		fixtureFile("etc/empty", 0o600, ""),
		fixtureFile("usr/share/doc/tree/big", 0o644, strings.Repeat("x", 100000)),
		fixtureFile("README", 0o644, "readme\n"),
		{Name: "var/empty", Mode: fs.ModeDir | 0o700},
		{Name: "var/lib/app/state", Mode: fs.ModeDir | 0o755},
	}
}

func fixtureTreeInfo() Info {
	return Info{
		Name: "tree", Version: "1.0-r0", Arch: "x86_64", BuildTime: fixtureEpoch,
		Description: "Fixture with every kind of entry", License: "MIT",
	}
}

// fixtureSpec returns the spec and options a fixture is made from.
func fixtureSpec(name string) (*Spec, WriteOptions) {
	switch name {
	case "minimal":
		return &Spec{Info: Info{Name: "minimal", Version: "1.0-r0", Arch: "x86_64", BuildTime: fixtureEpoch}}, WriteOptions{}
	case "tree":
		return &Spec{Info: fixtureTreeInfo(), Files: fixtureTreeFiles()}, WriteOptions{}
	case "tree-none":
		return &Spec{Info: fixtureTreeInfo(), Files: fixtureTreeFiles()}, WriteOptions{Compression: NoCompression}
	case "tree-deflate9":
		return &Spec{Info: fixtureTreeInfo(), Files: fixtureTreeFiles()}, WriteOptions{Compression: Compression{Alg: CompDeflate, Level: 9}}
	case "tree-zstd3":
		return &Spec{Info: fixtureTreeInfo(), Files: fixtureTreeFiles()}, WriteOptions{Compression: Compression{Alg: CompZstd, Level: 3}}
	case "tree-compat-300pre3":
		return &Spec{Info: fixtureTreeInfo(), Files: fixtureTreeFiles()}, WriteOptions{Compat: "3.0.0_pre3"}
	case "tree-compat-300rc9":
		return &Spec{Info: fixtureTreeInfo(), Files: fixtureTreeFiles()}, WriteOptions{Compat: "3.0.0_rc9"}
	case "full":
		in := fullInfo()
		in.BuildTime = fixtureEpoch

		return &Spec{
			Info: in, ReplacesPriority: 5, Triggers: []string{"/usr/share/*", "/lib/x"},
			Scripts: Scripts{
				Trigger: "#!/bin/sh\necho trigger\n", PreInstall: "#!/bin/sh\necho pre-install\n",
				PostInstall: "#!/bin/sh\necho post-install\n", PreDeinstall: "#!/bin/sh\necho pre-deinstall\n",
				PostDeinstall: "#!/bin/sh\necho post-deinstall\n", PreUpgrade: "#!/bin/sh\necho pre-upgrade\n",
				PostUpgrade: "#!/bin/sh\necho post-upgrade\n",
			},
			Files: []File{fixtureFile("usr/bin/one", 0o755, "one\n")},
		}, WriteOptions{}
	case "signed-rsa", "signed-ec":
		return &Spec{
			Info:  Info{Name: "signed", Version: "1.0-r0", Arch: "x86_64", BuildTime: fixtureEpoch},
			Files: []File{fixtureFile("usr/bin/one", 0o755, "one\n")},
		}, WriteOptions{}
	}

	panic("no fixture " + name)
}

func readFixture(t testing.TB, name string) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}

	return b
}

var unsignedFixtures = []string{
	"minimal", "tree", "tree-none", "tree-deflate9", "tree-zstd3", "tree-compat-300pre3", "tree-compat-300rc9", "full",
}

// TestWriterReproducesFixtures: the ADB block the writer makes is the one apk
// mkpkg made.
func TestWriterReproducesFixtures(t *testing.T) {
	for _, name := range unsignedFixtures {
		t.Run(name, func(t *testing.T) {
			spec, opts := fixtureSpec(name)
			ref := readFixture(t, name+".apk")

			var out bytes.Buffer
			if _, err := WritePackage(&out, spec, opts); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(adbOf(t, out.Bytes()), adbOf(t, ref)) {
				t.Error("the ADB block differs from the fixture's")
			}

			// Stored files are the same all through.
			if opts.Compression == NoCompression && !bytes.Equal(out.Bytes(), ref) {
				t.Error("the whole file differs from the fixture's")
			}

			rd, err := NewReader(bytes.NewReader(ref), ReadOptions{})
			if err != nil {
				t.Fatal(err)
			}

			defer func() { _ = rd.Close() }()

			if got, want := rd.Compression().Alg, opts.Compression.Alg; got != want && (want != CompNone || opts.Compression.Level != 0) {
				t.Errorf("compression %v, want %v", got, want)
			}
		})
	}
}

// TestFixturesRead parses, walks and extracts every fixture.
func TestFixturesRead(t *testing.T) {
	for _, name := range append(unsignedFixtures, "signed-rsa", "signed-ec") {
		t.Run(name, func(t *testing.T) {
			ref := readFixture(t, name+".apk")

			spec, opts := fixtureSpec(name)

			pkg, err := ParsePackage(bytes.NewReader(ref), ReadOptions{})
			if err != nil {
				t.Fatal(err)
			}

			// What the writer makes of the spec, decoded, is what the
			// fixture must decode to.
			wrote, err := WritePackage(io.Discard, spec, opts)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(pkg, wrote) {
				t.Errorf("package\n got %+v\nwant %+v", pkg, wrote)
			}

			if pkg.Scripts != spec.Scripts || !reflect.DeepEqual(pkg.Triggers, spec.Triggers) || pkg.ReplacesPriority != spec.ReplacesPriority {
				t.Errorf("scripts/triggers: %+v %v %d", pkg.Scripts, pkg.Triggers, pkg.ReplacesPriority)
			}

			dest := t.TempDir()
			if _, err := Extract(bytes.NewReader(ref), dest, ExtractOptions{AllowUntrusted: true}); err != nil {
				t.Fatal(err)
			}

			for _, f := range spec.Files {
				p := filepath.Join(dest, filepath.FromSlash(f.Name))

				fi, err := os.Lstat(p)
				if err != nil {
					t.Errorf("%s: %v", f.Name, err)

					continue
				}

				switch {
				case f.Mode&fs.ModeSymlink != 0:
					if got, _ := os.Readlink(p); got != f.LinkTarget {
						t.Errorf("%s -> %q, want %q", f.Name, got, f.LinkTarget)
					}
				case f.Mode.IsRegular():
					data, _ := os.ReadFile(p)

					rc, _ := f.Open()
					want, _ := io.ReadAll(rc)
					_ = rc.Close()

					if !bytes.Equal(data, want) {
						t.Errorf("%s: content differs", f.Name)
					}

					if fi.Mode().Perm() != f.Mode.Perm() {
						t.Errorf("%s: mode %v, want %v", f.Name, fi.Mode().Perm(), f.Mode.Perm())
					}
				case f.Mode.IsDir():
					if !fi.IsDir() {
						t.Errorf("%s is not a directory", f.Name)
					}
				}
			}
		})
	}
}

func normalizeInfo(in Info) Info {
	for _, l := range []*[]string{&in.Provides, &in.Replaces, &in.InstallIf, &in.Recommends} {
		if len(*l) == 0 {
			*l = nil
		}
	}

	return in
}

func TestFixtureSignatures(t *testing.T) {
	rsaPub, err := os.ReadFile(filepath.Join("testdata", "rsa.pub"))
	if err != nil {
		t.Fatal(err)
	}

	ecPub, err := os.ReadFile(filepath.Join("testdata", "ec.pub"))
	if err != nil {
		t.Fatal(err)
	}

	ring := func(pems ...[]byte) *Keyring {
		kr := NewKeyring()

		for _, p := range pems {
			pub, err := ParsePublicKeyPEM(p)
			if err != nil {
				t.Fatal(err)
			}

			if err := kr.Add(pub); err != nil {
				t.Fatal(err)
			}
		}

		return kr
	}

	for _, c := range []struct {
		file string
		kr   *Keyring
		want error
	}{
		{"signed-rsa", ring(rsaPub), nil},
		{"signed-rsa", ring(rsaPub, ecPub), nil},
		{"signed-rsa", ring(ecPub), ErrUntrusted},
		{"signed-ec", ring(ecPub), nil},
		{"signed-ec", ring(rsaPub), ErrUntrusted},
		{"signed-ec", NewKeyring(), ErrNoKeyring},
		{"tree", ring(rsaPub), ErrUnsigned},
	} {
		_, _, err := VerifyPackage(bytes.NewReader(readFixture(t, c.file+".apk")), c.kr, ReadOptions{})
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.file, err, c.want)
		}
	}

	// The trust gate of Extract.
	for _, c := range []struct {
		file string
		opts ExtractOptions
		want error
	}{
		{"signed-rsa", ExtractOptions{Keyring: ring(rsaPub)}, nil},
		{"signed-rsa", ExtractOptions{Keyring: ring(ecPub)}, ErrUntrusted},
		{"signed-rsa", ExtractOptions{Keyring: ring(ecPub), AllowUntrusted: true}, nil},
		{"signed-rsa", ExtractOptions{}, ErrNoKeyring},
		{"tree", ExtractOptions{Keyring: ring(rsaPub)}, ErrUnsigned},
		{"tree", ExtractOptions{Keyring: ring(rsaPub), AllowUntrusted: true}, nil},
	} {
		_, err := Extract(bytes.NewReader(readFixture(t, c.file+".apk")), t.TempDir(), c.opts)
		if !errors.Is(err, c.want) {
			t.Errorf("extract %s: %v, want %v", c.file, err, c.want)
		}
	}

	// Verify checks keys by id, so the id of the key is in the signature.
	pub, _ := ParsePublicKeyPEM(rsaPub)

	id, err := KeyIDOf(pub)
	if err != nil {
		t.Fatal(err)
	}

	rd, err := NewReader(bytes.NewReader(readFixture(t, "signed-rsa.apk")), ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = rd.Close() }()

	sigs := rd.Signatures()
	if len(sigs) != 1 || sigs[0].KeyID != id || sigs[0].Digest != DigestSHA512 || sigs[0].Version != 0 {
		t.Errorf("signatures %+v, key id %x", sigs, id)
	}
}

func TestFixtureIndexes(t *testing.T) {
	rsaPub, _ := os.ReadFile(filepath.Join("testdata", "rsa.pub"))

	pub, err := ParsePublicKeyPEM(rsaPub)
	if err != nil {
		t.Fatal(err)
	}

	kr := NewKeyring()
	if err := kr.Add(pub); err != nil {
		t.Fatal(err)
	}

	idx, err := ParseIndex(bytes.NewReader(readFixture(t, "index.adb")), ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if idx.Description != "fixture index" || idx.PkgnameSpec != "${name}-${version}.apk" || len(idx.Packages) != 3 {
		t.Fatalf("index %+v", idx)
	}

	var names []string

	for i, name := range []string{"full", "minimal", "tree"} {
		f, err := os.Open(filepath.Join("testdata", name+".apk"))
		if err != nil {
			t.Fatal(err)
		}

		want, err := IndexEntry(f, ReadOptions{})
		_ = f.Close()

		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(idx.Packages[i], normalizeInfo(want)) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, idx.Packages[i], want)
		}

		names = append(names, idx.Packages[i].Name)
	}

	if !reflect.DeepEqual(names, []string{"full", "minimal", "tree"}) {
		t.Errorf("order %v", names)
	}

	signed, id, err := VerifyIndex(bytes.NewReader(readFixture(t, "index-signed.adb")), kr, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if want, _ := KeyIDOf(pub); id != want || !reflect.DeepEqual(signed, idx) {
		t.Errorf("signed index: id %x, equal %v", id, reflect.DeepEqual(signed, idx))
	}

	if _, _, err := VerifyIndex(bytes.NewReader(readFixture(t, "index.adb")), kr, ReadOptions{}); !errors.Is(err, ErrUnsigned) {
		t.Errorf("unsigned index: %v", err)
	}

	// Rebuilding an index from its entries gives the same content.
	var out bytes.Buffer
	if err := BuildIndex(&out, idx, WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	again, err := ParseIndex(&out, ReadOptions{})
	if err != nil || !reflect.DeepEqual(again, idx) {
		t.Errorf("rebuilt index differs: %v", err)
	}
}
