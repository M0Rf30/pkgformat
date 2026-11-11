package pacman

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func notRoot(t *testing.T) {
	t.Helper()

	if os.Geteuid() == 0 {
		t.Skip("root is allowed what these cases need to be refused")
	}
}

func TestExtractFailsOnWhatIsInTheWay(t *testing.T) {
	t.Parallel()

	// A directory that is not empty cannot be replaced by a file, a link or a
	// pipe; a file cannot be the parent of one.
	for name, member := range map[string]tm{
		"file":     {hdr: tar.Header{Name: "f", Mode: 0o644}, body: "x"},
		"symlink":  {hdr: tar.Header{Name: "f", Typeflag: tar.TypeSymlink, Linkname: "g"}},
		"hardlink": {hdr: tar.Header{Name: "f", Typeflag: tar.TypeLink, Linkname: "g"}},
		"fifo":     {hdr: tar.Header{Name: "f", Typeflag: tar.TypeFifo, Mode: 0o644}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "f", "inner"), 0o755); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(filepath.Join(dir, "g"), nil, 0o600); err != nil {
				t.Fatal(err)
			}

			raw := rawPackage(t, member)
			if _, err := Extract(bytes.NewReader(raw), dir, ExtractOptions{SpecialFiles: true}); err == nil {
				t.Error("extraction succeeded")
			}
		})
	}

	t.Run("file as parent", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "d"), nil, 0o600); err != nil {
			t.Fatal(err)
		}

		raw := rawPackage(t, tm{hdr: tar.Header{Name: "d/x", Mode: 0o644}, body: "x"})
		if _, err := Extract(bytes.NewReader(raw), dir, ExtractOptions{}); err == nil {
			t.Error("extraction succeeded")
		}
	})

	t.Run("directory over file", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "d"), nil, 0o600); err != nil {
			t.Fatal(err)
		}

		raw := rawPackage(t, tm{hdr: tar.Header{Name: "d", Typeflag: tar.TypeDir, Mode: 0o755}})
		if _, err := Extract(bytes.NewReader(raw), dir, ExtractOptions{}); err == nil {
			t.Error("extraction succeeded")
		}
	})
}

func TestExtractHardlinkToMissingFile(t *testing.T) {
	t.Parallel()

	raw := rawPackage(t, tm{hdr: tar.Header{Name: "l", Typeflag: tar.TypeLink, Linkname: "missing"}})
	if _, err := Extract(bytes.NewReader(raw), t.TempDir(), ExtractOptions{}); err == nil {
		t.Error("a link to nothing was created")
	}

	// Nor can a link name leave the directory.
	raw = rawPackage(t, tm{hdr: tar.Header{Name: "l", Typeflag: tar.TypeLink, Linkname: "../outside"}})
	if _, err := Extract(bytes.NewReader(raw), t.TempDir(), ExtractOptions{}); !errors.Is(err, ErrUnsafeEntry) {
		t.Errorf("link out of the directory: %v", err)
	}
}

func TestExtractPrivilegedOperationsFailWithoutPrivilege(t *testing.T) {
	notRoot(t)
	t.Parallel()

	other := os.Getuid() + 1

	for name, tc := range map[string]struct {
		member tm
		opts   ExtractOptions
	}{
		"device": {
			member: tm{hdr: tar.Header{Name: "dev", Typeflag: tar.TypeChar, Mode: 0o600, Devmajor: 1, Devminor: 3}},
			opts:   ExtractOptions{SpecialFiles: true},
		},
		"chown file": {
			member: tm{hdr: tar.Header{Name: "f", Mode: 0o644, Uid: other}, body: "x"},
			opts:   ExtractOptions{Chown: true},
		},
		"chown directory": {
			member: tm{hdr: tar.Header{Name: "d", Typeflag: tar.TypeDir, Mode: 0o755, Uid: other}},
			opts:   ExtractOptions{Chown: true},
		},
		"chown symlink": {
			member: tm{hdr: tar.Header{Name: "s", Typeflag: tar.TypeSymlink, Linkname: "f", Uid: other}},
			opts:   ExtractOptions{Chown: true},
		},
		"trusted xattr on a file": {
			member: tm{hdr: tar.Header{Name: "f", Mode: 0o644, PAXRecords: map[string]string{"SCHILY.xattr.trusted.pkgformat": "v"}}, body: "x"},
			opts:   ExtractOptions{Xattrs: true},
		},
		"trusted xattr on a directory": {
			member: tm{hdr: tar.Header{Name: "d", Typeflag: tar.TypeDir, Mode: 0o755, PAXRecords: map[string]string{"SCHILY.xattr.trusted.pkgformat": "v"}}},
			opts:   ExtractOptions{Xattrs: true},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw := rawPackage(t, tc.member)
			if _, err := Extract(bytes.NewReader(raw), t.TempDir(), tc.opts); err == nil {
				t.Error("extraction succeeded")
			}
		})
	}
}

func TestExtractVerifyRejectsBadMtree(t *testing.T) {
	t.Parallel()

	raw := rawPackage(t,
		tm{hdr: tar.Header{Name: ".MTREE", Mode: 0o644}, body: string(gzipped(t, "#mtree\n/bogus x\n"))},
		tm{hdr: tar.Header{Name: "f", Mode: 0o644}, body: "x"},
	)

	_, err := Extract(bytes.NewReader(raw), t.TempDir(), ExtractOptions{Verify: true})
	if !errors.Is(err, ErrInvalidMtree) {
		t.Errorf("err = %v", err)
	}
}

func gzipped(t *testing.T, text string) []byte {
	t.Helper()

	out, err := gzipBytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}

	return out
}
