package adb

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

var fuzzLimits = ReadOptions{Limits: Limits{
	MaxADB: 1 << 20, MaxStream: 1 << 24, MaxEntries: 1 << 14, MaxNodes: 1 << 18, MaxDecodedBytes: 1 << 26,
}}

// FuzzReader reads arbitrary bytes as a package and as an index: neither may
// panic or run away, and what reads once reads the same again.
func FuzzReader(f *testing.F) {
	seeds, _ := filepath.Glob(filepath.Join("testdata", "*.apk"))

	index, _ := filepath.Glob(filepath.Join("testdata", "*.adb"))

	for _, p := range append(seeds, index...) {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}

	f.Add(signedBase(f))
	f.Add([]byte("ADB."))
	f.Add([]byte("ADBd"))
	f.Add([]byte("ADBc\x02\x03"))

	f.Fuzz(func(t *testing.T, data []byte) {
		pkg, err := ParsePackage(bytes.NewReader(data), fuzzLimitsOpts())
		if err == nil {
			again, err := ParsePackage(bytes.NewReader(data), fuzzLimitsOpts())
			if err != nil || !reflect.DeepEqual(pkg, again) {
				t.Fatalf("reading twice gives different results: %v", err)
			}

			_, _ = IndexEntry(bytes.NewReader(data), fuzzLimitsOpts())
			_, _, _ = readAll(t, data, fuzzLimitsOpts())
		}

		_, _ = ParseIndex(bytes.NewReader(data), fuzzLimitsOpts())

		if rd, err := NewReader(bytes.NewReader(data), fuzzLimitsOpts()); err == nil {
			_, _ = io.Copy(io.Discard, rd)

			_ = rd.Close()
		}
	})
}

func fuzzLimitsOpts() ReadOptions { return fuzzLimits }

// FuzzExtract extracts arbitrary packages; nothing may land outside the
// directory.
func FuzzExtract(f *testing.F) {
	seeds, _ := filepath.Glob(filepath.Join("testdata", "*.apk"))
	for _, p := range seeds {
		// The stored fixture holds 100 kB of one letter, which only slows
		// the mutations down.
		if b, err := os.ReadFile(p); err == nil && len(b) < 8<<10 {
			f.Add(b)
		}
	}

	f.Add(signedBase(f))

	f.Fuzz(func(t *testing.T, data []byte) {
		parent := t.TempDir()
		root := filepath.Join(parent, "root")

		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}

		_, _ = Extract(bytes.NewReader(data), root, ExtractOptions{
			AllowUntrusted: true, MaxBytes: 1 << 24, MaxEntries: 1 << 12, Read: fuzzLimits,
		})

		if entries, _ := os.ReadDir(parent); len(entries) != 1 {
			t.Fatalf("something was created beside the root: %v", entries)
		}
	})
}

// FuzzParseDependency: what parses prints in a form that parses to the same.
func FuzzParseDependency(f *testing.F) {
	for _, s := range []string{"foo", "!foo", "foo>=1.0", "foo~1.2", "foo><abc123", "so:libc.so.6", "a=1_rc2-r3", "x<", "", "!", ">="} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDependency(s)
		if err != nil {
			return
		}

		again, err := ParseDependency(d.String())
		if err != nil {
			t.Fatalf("%q parsed but %q, its own form, does not: %v", s, d.String(), err)
		}

		if again != d {
			t.Fatalf("%q: %+v, then %+v", s, d, again)
		}
	})
}

// FuzzCompareVersions: the order is a total order on valid versions.
func FuzzCompareVersions(f *testing.F) {
	for _, p := range versionPairs {
		f.Add(p.a, p.b, "1.0")
	}

	f.Fuzz(func(t *testing.T, a, b, c string) {
		if !ValidVersion(a) || !ValidVersion(b) || !ValidVersion(c) {
			return
		}

		if CompareVersions(a, a) != 0 {
			t.Fatalf("%q != itself", a)
		}

		ab, ba := CompareVersions(a, b), CompareVersions(b, a)
		if ab != -ba {
			t.Fatalf("%q vs %q: %d and %d", a, b, ab, ba)
		}

		if ab <= 0 && CompareVersions(b, c) <= 0 && CompareVersions(a, c) > 0 {
			t.Fatalf("not transitive: %q <= %q <= %q", a, b, c)
		}
	})
}

// FuzzWriteRead writes a package out of arbitrary names and content: either
// the spec is refused or the package reads back as written.
func FuzzWriteRead(f *testing.F) {
	f.Add("usr/bin/tool", "content", "target", uint32(0o755))
	f.Add("a/b/c", "", "", uint32(fs.ModeSymlink|0o777))
	f.Add("../x", "y", "z", uint32(0o644))

	f.Fuzz(func(t *testing.T, name, content, target string, mode uint32) {
		spec := &Spec{
			Info:  Info{Name: "fz", Version: "1", Arch: "noarch"},
			Files: []File{MemFile(name, 0o644, []byte(content))},
		}

		spec.Files[0].Mode = fs.FileMode(mode)
		spec.Files[0].LinkTarget = target

		var out bytes.Buffer

		wrote, err := WritePackage(&out, spec, WriteOptions{})
		if err != nil {
			return
		}

		got, err := ParsePackage(bytes.NewReader(out.Bytes()), ReadOptions{})
		if err != nil {
			t.Fatalf("a package it wrote does not read: %v", err)
		}

		if !reflect.DeepEqual(got, wrote) {
			t.Fatalf("read back differs:\n%+v\n%+v", got, wrote)
		}

		if err := drain(mustReader(t, out.Bytes())); err != nil {
			t.Fatalf("a package it wrote does not drain: %v", err)
		}
	})
}

func mustReader(t *testing.T, data []byte) *Reader {
	t.Helper()

	rd, err := NewReader(bytes.NewReader(data), ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = rd.Close() })

	return rd
}
