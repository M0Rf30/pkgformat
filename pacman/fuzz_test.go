package pacman

import (
	"bytes"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

// FuzzReadPackage feeds arbitrary bytes to the package reader.
func FuzzReadPackage(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00})
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00})
	f.Add([]byte{0xfd, '7', 'z', 'X', 'Z', 0x00})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ReadPackage(bytes.NewReader(data))
	})
}

// FuzzParsePkgInfo feeds arbitrary text to the .PKGINFO parser.
func FuzzParsePkgInfo(f *testing.F) {
	f.Add(samplePkgInfo)
	f.Add("pkgname = a\npkgver = 1-1\narch = any\n")
	f.Add("pkgname=a\npkgver=1:2-3\narch=x86_64\nsize=99999999999999999999\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, in string) {
		info, err := ParsePkgInfo(strings.NewReader(in))
		if err != nil {
			return
		}

		if !ValidName(info.Name) || !ValidVersion(info.Version) || !ValidArch(info.Arch) {
			t.Fatalf("accepted an invalid identity: %+v", info)
		}
	})
}

// FuzzVercmp checks that the comparison is antisymmetric.
func FuzzVercmp(f *testing.F) {
	f.Add("1.0-1", "1.0-2")
	f.Add("1:1.0", "2.0")
	f.Add("1.0a", "1.0")
	f.Add("", "x")

	f.Fuzz(func(t *testing.T, a, b string) {
		if Vercmp(a, b) != -Vercmp(b, a) {
			t.Fatalf("Vercmp(%q, %q) is not antisymmetric", a, b)
		}
	})
}

// FuzzNormalizeSignature feeds arbitrary bytes to the signature check.
func FuzzNormalizeSignature(f *testing.F) {
	f.Add([]byte("-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEE\n-----END PGP SIGNATURE-----\n"))
	f.Add([]byte{0x89, 0x01, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = NormalizeSignature(data)
	})
}

// FuzzReadDB feeds arbitrary bytes to the database reader and checks that what
// it keeps has a usable identity.
func FuzzReadDB(f *testing.F) {
	var plain bytes.Buffer

	e := DBEntry{
		Filename: "a-1-1-any.pkg.tar.zst", Name: "a", Version: "1-1", Arch: "any",
		Depends: []string{"glibc"}, Files: []string{"usr/bin/a"},
	}
	_ = WriteDB(&plain, []DBEntry{e}, true)

	f.Add(plain.Bytes())
	f.Add([]byte{})
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00})
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := ReadDB(bytes.NewReader(data))
		if err != nil {
			return
		}

		for _, e := range entries {
			if !e.usable() {
				t.Fatalf("kept an unusable entry: %+v", e)
			}
		}
	})
}

// FuzzParseBuildInfo feeds arbitrary text to the .BUILDINFO parser; whatever
// it accepts and can render must parse again.
func FuzzParseBuildInfo(f *testing.F) {
	f.Add("format = 2\npkgname = a\npkgver = 1-1\npkgarch = any\nbuilddate = 1700000000\ninstalled = x-1-1-any\n")
	f.Add("builddate = 99999999999999999999\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, in string) {
		bi, err := ParseBuildInfo(strings.NewReader(in))
		if err != nil {
			return
		}

		out, err := bi.Render()
		if err != nil {
			return
		}

		if _, err := ParseBuildInfo(bytes.NewReader(out)); err != nil {
			t.Fatalf("rendered .BUILDINFO does not parse: %v\n%s", err, out)
		}
	})
}

// FuzzParseConfig feeds arbitrary text to the pacman.conf and mirrorlist
// parsers.
func FuzzParseConfig(f *testing.F) {
	f.Add(sampleConf)
	f.Add("[core]\nServer = https://x/$repo\n")
	f.Add("[")
	f.Add("[]")
	f.Add("")

	f.Fuzz(func(t *testing.T, in string) {
		cfg, err := ParseConfig(strings.NewReader(in), func(inc string) ([]string, error) {
			return []string{inc}, nil
		})
		if err == nil {
			for _, r := range cfg.Repos {
				if r.Name == "" || r.Name == "options" {
					t.Fatalf("bad repository name %q", r.Name)
				}
			}
		}

		servers, err := ParseMirrorlist(strings.NewReader(in))
		if err == nil {
			for _, s := range servers {
				if strings.ContainsAny(s, "\r\n") {
					t.Fatalf("server with a line break: %q", s)
				}
			}
		}
	})
}

// FuzzParseDependency checks that accepted dependencies round-trip.
func FuzzParseDependency(f *testing.F) {
	for _, s := range []string{"glibc", "sh>=5", "a=1:2-3", "lib++<2", "", ">=", "a<=", "a=>b"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		d, err := ParseDependency(in)
		if err != nil {
			return
		}

		if d.String() != in {
			t.Fatalf("round trip: %q -> %q", in, d.String())
		}

		_ = d.Allows("1:2-3")
		_ = (&IndexedPackage{DBEntry: DBEntry{Name: d.Name, Version: "1-1"}}).Satisfies(d)
	})
}

// FuzzWriteSpec feeds arbitrary names and paths to the package writer; a
// package it writes must read back with the same identity and path.
func FuzzWriteSpec(f *testing.F) {
	f.Add("hello", "1.0-1", "usr/bin/hello", "data")
	f.Add("a", "1:2-3", "dir/", "")
	f.Add("x", "1-1", ".PKGINFO", "")
	f.Add("x", "1-1", "a//b", "")
	f.Add("bad\nname", "1-1", "p", "")

	f.Fuzz(func(t *testing.T, name, version, path, data string) {
		s := &Spec{
			Info:  PkgInfo{Name: name, Version: version, Arch: "any", Description: "d", BuildDate: 1},
			Files: []File{{Path: path, Mode: 0o644, Data: []byte(data)}},
		}
		if strings.HasSuffix(path, "/") {
			s.Files[0].Mode = fs.ModeDir | 0o755
			s.Files[0].Data = nil
		}

		var buf bytes.Buffer
		if err := s.Write(&buf, WriteOptions{Compression: CompressionGzip}); err != nil {
			return
		}

		pkg, err := ReadPackage(&buf)
		if err != nil {
			t.Fatalf("written package does not read back: %v", err)
		}

		if pkg.Info.Name != name || pkg.Info.Version != version {
			t.Fatalf("identity changed: %+v", pkg.Info)
		}

		if !slices.Contains(pkg.Files, path) && !strings.HasPrefix(path, ".") {
			t.Fatalf("path %q missing from %v", path, pkg.Files)
		}
	})
}
