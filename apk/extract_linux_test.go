package apk

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestExtract_userXattr(t *testing.T) {
	raw, _ := mustWrite(t, &Spec{
		Info: Info{Name: "x", Version: "1-r0", Arch: "noarch"},
		Files: []File{{
			Name: "f", Mode: 0o644, Xattrs: map[string][]byte{"user.pkgformat": []byte("v"), "user.a": nil},
		}},
	}, WriteOptions{TempDir: t.TempDir()})

	out := t.TempDir()

	err := openArchiveBytes(t, raw).Extract(out, ExtractOptions{Xattrs: true})
	if errors.Is(err, unix.ENOTSUP) {
		t.Skip("filesystem without user xattrs")
	}

	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 16)

	n, err := unix.Lgetxattr(filepath.Join(out, "f"), "user.pkgformat", buf)
	if err != nil || string(buf[:n]) != "v" {
		t.Fatalf("%q %v", buf[:n], err)
	}
}

func TestExtract_deviceUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can create devices")
	}

	raw, _ := mustWrite(t, deviceSpec(), WriteOptions{TempDir: t.TempDir()})

	err := openArchiveBytes(t, raw).Extract(t.TempDir(), ExtractOptions{Devices: true})
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("got %v, want EPERM", err)
	}
}
