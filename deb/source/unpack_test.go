package source_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/deb/source"
)

func TestUnpackMatchesDpkgSourceManifest(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			d, _ := fixtureDSC(t, fx.name)
			if d.Format != fx.format {
				t.Fatalf("format %q, want %q", d.Format, fx.format)
			}

			dest := filepath.Join(t.TempDir(), fx.name)
			if err := source.Unpack(d, fixtureDir(fx.name), dest, nil); err != nil {
				t.Fatalf("Unpack: %v", err)
			}

			want := readLines(t, filepath.Join("testdata", "expected", fx.name+".manifest"))
			got := manifest(t, dest)

			diffLines(t, want, got)
		})
	}
}

func diffLines(t *testing.T, want, got []string) {
	t.Helper()

	set := map[string]bool{}
	for _, l := range want {
		set[l] = true
	}

	gotSet := map[string]bool{}

	for _, l := range got {
		gotSet[l] = true
		if !set[l] {
			t.Errorf("unexpected: %s", l)
		}
	}

	for _, l := range want {
		if !gotSet[l] {
			t.Errorf("missing:    %s", l)
		}
	}
}

func TestUnpackMatchesDpkgSource(t *testing.T) {
	if _, err := exec.LookPath("dpkg-source"); err != nil {
		t.Skip("dpkg-source not installed")
	}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			d, dsc := fixtureDSC(t, fx.name)

			ref := filepath.Join(t.TempDir(), "ref")

			cmd := exec.Command("dpkg-source", "--no-check", "-x", filepath.Base(dsc), ref)
			cmd.Dir = fixtureDir(fx.name)

			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("dpkg-source -x: %v\n%s", err, out)
			}

			dest := filepath.Join(t.TempDir(), "ours")
			if err := source.Unpack(d, fixtureDir(fx.name), dest, nil); err != nil {
				t.Fatalf("Unpack: %v", err)
			}

			diffLines(t, manifest(t, ref), manifest(t, dest))
		})
	}
}

func TestUnpackErrors(t *testing.T) {
	d, _ := fixtureDSC(t, "sl")
	src := fixtureDir("sl")

	t.Run("checksum", func(t *testing.T) {
		dir := copyDir(t, src)
		corrupt(t, filepath.Join(dir, "sl_5.02.orig.tar.gz"))

		err := source.Unpack(d, dir, filepath.Join(t.TempDir(), "x"), nil)
		if !errors.Is(err, source.ErrChecksum) {
			t.Fatalf("got %v, want ErrChecksum", err)
		}
	})

	t.Run("missing", func(t *testing.T) {
		dir := copyDir(t, src)
		_ = os.Remove(filepath.Join(dir, "sl_5.02-1.debian.tar.xz"))

		err := source.Unpack(d, dir, filepath.Join(t.TempDir(), "x"), nil)
		if !errors.Is(err, source.ErrMissingFile) {
			t.Fatalf("got %v, want ErrMissingFile", err)
		}
	})

	t.Run("dest not empty", func(t *testing.T) {
		dest := t.TempDir()
		_ = os.WriteFile(filepath.Join(dest, "f"), nil, 0o644)

		err := source.Unpack(d, src, dest, nil)
		if !errors.Is(err, source.ErrDestExists) {
			t.Fatalf("got %v, want ErrDestExists", err)
		}

		if err := source.Unpack(d, src, dest, &source.UnpackOptions{Replace: true}); err != nil {
			t.Fatalf("Replace: %v", err)
		}
	})

	t.Run("git format", func(t *testing.T) {
		g := *d
		g.Format = source.FormatGit

		err := source.Unpack(&g, src, filepath.Join(t.TempDir(), "x"), nil)
		if !errors.Is(err, source.ErrUnsupportedFormat) {
			t.Fatalf("got %v, want ErrUnsupportedFormat", err)
		}
	})

	t.Run("unexpected file", func(t *testing.T) {
		g := *d
		g.Files = append(append([]source.FileRef(nil), d.Files...), source.FileRef{Name: "stray.txt", Size: 1, MD5: strings.Repeat("0", 32)})

		err := source.Unpack(&g, src, filepath.Join(t.TempDir(), "x"), nil)
		if !errors.Is(err, source.ErrUnexpectedFile) {
			t.Fatalf("got %v, want ErrUnexpectedFile", err)
		}
	})

	t.Run("limits", func(t *testing.T) {
		err := source.Unpack(d, src, filepath.Join(t.TempDir(), "x"), &source.UnpackOptions{MaxEntries: 3})
		if !errors.Is(err, source.ErrTooLarge) {
			t.Fatalf("entries: got %v, want ErrTooLarge", err)
		}

		err = source.Unpack(d, src, filepath.Join(t.TempDir(), "x"), &source.UnpackOptions{MaxBytes: 10})
		if !errors.Is(err, source.ErrTooLarge) {
			t.Fatalf("bytes: got %v, want ErrTooLarge", err)
		}
	})
}

func TestUnpackSkipOptions(t *testing.T) {
	d, _ := fixtureDSC(t, "sl")
	src := fixtureDir("sl")

	skipPatches := filepath.Join(t.TempDir(), "p")
	if err := source.Unpack(d, src, skipPatches, &source.UnpackOptions{SkipPatches: true}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(skipPatches, ".pc")); err == nil {
		t.Error("SkipPatches created .pc")
	}

	if _, err := os.Stat(filepath.Join(skipPatches, "debian", "patches", "series")); err != nil {
		t.Error("SkipPatches lost debian/patches/series")
	}

	orig := filepath.Join(t.TempDir(), "o")
	if err := source.Unpack(d, src, orig, &source.UnpackOptions{SkipDebianization: true}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(orig, "debian")); err == nil {
		t.Error("SkipDebianization extracted debian/")
	}
}

func copyDir(t *testing.T, src string) string {
	t.Helper()

	dst := t.TempDir()

	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}

	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return dst
}

func corrupt(t *testing.T, p string) {
	t.Helper()

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}

	data[len(data)/2] ^= 0xff

	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
