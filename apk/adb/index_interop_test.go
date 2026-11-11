package adb

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
)

// indexPackages makes a few packages with apk mkpkg and returns their files.
func indexPackages(t *testing.T) []string {
	t.Helper()

	dir := t.TempDir()

	var paths []string

	for _, in := range []Info{
		{Name: "foo", Version: "1.0-r0", Arch: "x86_64", Depends: []string{"musl", "bar>=1"}, BuildTime: 1700000000},
		{Name: "foo", Version: "1.0-r1", Arch: "x86_64", Depends: []string{"musl"}, BuildTime: 1700000001},
		{Name: "foo", Version: "1.0_rc1-r0", Arch: "x86_64", BuildTime: 1700000002},
		fullInfo(),
		{Name: "bar", Version: "2.0-r0", Arch: "noarch", Description: "bar package", Provides: []string{"cmd:bar=2.0-r0"}, BuildTime: 1700000000},
	} {
		tr := newTree(t)
		tr.File("usr/bin/"+in.Name, 0o755, []byte(in.Name+in.Version))

		p := filepath.Join(dir, fmt.Sprintf("%s-%s.apk", in.Name, in.Version))
		if err := os.WriteFile(p, tr.mkpkg(&Spec{Info: in}), 0o600); err != nil {
			t.Fatal(err)
		}

		paths = append(paths, p)
	}

	return paths
}

func entriesOf(t *testing.T, paths []string) []Info {
	t.Helper()

	var out []Info

	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}

		in, err := IndexEntry(f, ReadOptions{})
		_ = f.Close()

		if err != nil {
			t.Fatal(err)
		}

		out = append(out, in)
	}

	return out
}

// TestIndexMatchesMkndx builds an index from the same packages with apk mkndx
// and with BuildIndex, and compares what apk adbdump says of both and what
// ParseIndex reads from both.
func TestIndexMatchesMkndx(t *testing.T) {
	needApk(t)

	paths := indexPackages(t)
	spec := "${name}-${version}.apk"

	ref := filepath.Join(t.TempDir(), "ref.adb")
	runApk(t, append([]string{"--allow-untrusted", "mkndx", "--description", "test repo", "--pkgname-spec", spec, "--output", ref}, paths...)...)

	refData, err := os.ReadFile(ref)
	if err != nil {
		t.Fatal(err)
	}

	idx := &Index{Description: "test repo", PkgnameSpec: spec, Packages: entriesOf(t, paths)}

	var out bytes.Buffer
	if err := BuildIndex(&out, idx, WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	// apk keeps a 20-byte leftover of its own in every index, so the blocks
	// differ in size; nothing else may.
	sizeLine := regexp.MustCompile(`(?m)^# ADB block, size: \d+.*\n`)
	strip := func(s string) string { return sizeLine.ReplaceAllString(s, "") }

	if got, want := strip(dumpOf(t, out.Bytes())), strip(dumpOf(t, refData)); got != want {
		t.Errorf("adbdump differs\n--- ours\n%s\n--- apk\n%s", got, want)
	}

	ours, err := ParseIndex(bytes.NewReader(out.Bytes()), ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	theirs, err := ParseIndex(bytes.NewReader(refData), ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(ours, theirs) {
		t.Errorf("ParseIndex differs:\n%+v\n%+v", ours, theirs)
	}

	if len(theirs.Packages) != 5 || theirs.Packages[0].Name != "bar" || theirs.Packages[1].Name != "foo" {
		t.Errorf("packages not sorted: %+v", theirs.Packages)
	}
}

// TestIndexSignatures has each side check what the other signs.
func TestIndexSignatures(t *testing.T) {
	needApk(t)

	paths := indexPackages(t)

	for _, k := range keysOf(t) {
		t.Run(k.name, func(t *testing.T) {
			ref := filepath.Join(t.TempDir(), "ref.adb")
			runApk(t, append([]string{"--allow-untrusted", "mkndx", "--sign-key", k.priv, "--output", ref}, paths...)...)

			refData, err := os.ReadFile(ref)
			if err != nil {
				t.Fatal(err)
			}

			idx, id, err := VerifyIndex(bytes.NewReader(refData), keyringOf(t, k), ReadOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if id != k.signer.KeyID() || len(idx.Packages) != 5 {
				t.Errorf("id %x, %d packages", id, len(idx.Packages))
			}

			var out bytes.Buffer
			if err := BuildIndex(&out, idx, WriteOptions{Signers: []*Signer{k.signer}}); err != nil {
				t.Fatal(err)
			}

			p := save(t, "ours.adb", out.Bytes())
			runApk(t, "--keys-dir", k.keysDir, "verify", p)

			if _, _, err := VerifyIndex(bytes.NewReader(out.Bytes()), keyringOf(t, k), ReadOptions{}); err != nil {
				t.Fatal(err)
			}

			for _, other := range keysOf(t) {
				if other.name != k.name {
					if _, _, err := VerifyIndex(bytes.NewReader(out.Bytes()), keyringOf(t, other), ReadOptions{}); !errors.Is(err, ErrUntrusted) {
						t.Errorf("verified with the wrong key: %v", err)
					}
				}
			}
		})
	}
}
