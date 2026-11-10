//go:build unix

package apk

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestFilesFromDir_fifo(t *testing.T) {
	dir := t.TempDir()

	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}

	files, err := FilesFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) != 1 || files[0].Name != "pipe" {
		t.Fatalf("files %+v", files)
	}

	if _, err := WritePackage(discard{}, &Spec{Info: sampleSpec().Info, Files: files}, WriteOptions{TempDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
