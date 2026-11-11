package pacman

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// FuzzParseMtree feeds arbitrary text to the .MTREE parser: whatever it
// accepts is a relative, clean path with a known type.
func FuzzParseMtree(f *testing.F) {
	for _, seed := range []string{
		"#mtree\n/set type=file uid=0 gid=0 mode=644\n./a time=1.0 size=1 sha256digest=" + strings.Repeat("0", 64) + "\n",
		"/set type=file mode=644\n. type=dir\n    usr type=dir\n        a\\040b size=1\n    ..\n..\n",
		"./a type=link link=b\\\\x \\\n  mode=777\n/unset all\n",
		"./a type=file md5digest=" + strings.Repeat("a", 32) + " cksum=1 flags=x device=a,1 optional\n",
		"",
	} {
		f.Add([]byte(seed))
	}

	if raw, err := os.ReadFile("testdata/makepkg/mtree.expected"); err == nil {
		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		mt, err := ParseMtree(bytes.NewReader(data))
		if err != nil {
			return
		}

		for i := range mt.Entries {
			e := &mt.Entries[i]
			if !e.Type.valid() || e.Path == "" || filepath.IsAbs(e.Path) || e.Path != pathClean(e.Path) {
				t.Fatalf("accepted entry %+v", e)
			}
		}
	})
}

func pathClean(p string) string { return filepath.ToSlash(filepath.Clean(p)) }

// FuzzParseInstall feeds arbitrary text to the .INSTALL reader.
func FuzzParseInstall(f *testing.F) {
	f.Add("pre_install() {\n:\n}\nfunction post_remove {\n:\n}\n")
	f.Add("post_upgrade ()\n{\n}\r\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, in string) {
		s, err := ParseInstall(strings.NewReader(in))
		if err != nil {
			return
		}

		if string(s.Raw) != in {
			t.Fatal("the script was altered")
		}

		for _, h := range s.Hooks {
			if !s.Has(h) || !slices.Contains(hookNames, h) {
				t.Fatalf("hook %q", h)
			}
		}
	})
}

func seedPackages(f *testing.F) {
	f.Helper()

	f.Add([]byte{})

	if raw, err := os.ReadFile(makepkgFixture); err == nil {
		f.Add(raw)
	}
}

// FuzzReadMetadata feeds arbitrary bytes to the metadata reader.
func FuzzReadMetadata(f *testing.F) {
	seedPackages(f)

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ReadMetadata(bytes.NewReader(data))
		_ = VerifyPackage(bytes.NewReader(data), VerifyOptions{})
	})
}

// FuzzWalkPackage feeds arbitrary bytes to the member walker.
func FuzzWalkPackage(f *testing.F) {
	seedPackages(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = WalkPackage(bytes.NewReader(data), func(e *Entry, body io.Reader) error {
			if e.Path == "" || filepath.IsAbs(e.Path) || slices.Contains(strings.Split(e.Path, "/"), "..") {
				t.Fatalf("unsafe path %q", e.Path)
			}

			_, err := io.Copy(io.Discard, body)

			return err
		})
	})
}

// FuzzExtract extracts arbitrary bytes into a directory and checks that
// nothing appears beside it.
func FuzzExtract(f *testing.F) {
	seedPackages(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		base := t.TempDir()
		root := filepath.Join(base, "root")

		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}

		_, _ = Extract(bytes.NewReader(data), root, ExtractOptions{
			SpecialFiles: true, Xattrs: true, Metadata: true, MaxBytes: 1 << 20, MaxEntries: 1000,
		})

		entries, err := os.ReadDir(base)
		if err != nil {
			t.Fatal(err)
		}

		if len(entries) != 1 {
			t.Fatalf("something was written beside the root: %v", entries)
		}
	})
}
