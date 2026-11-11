//go:build linux

package pacman

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// getXattr returns the value of an extended attribute of path.
func getXattr(path, name string) (string, error) {
	buf := make([]byte, 256)

	n, err := unix.Lgetxattr(path, name, buf)
	if err != nil {
		return "", err
	}

	return string(buf[:n]), nil
}

func TestListXattrsErrors(t *testing.T) {
	t.Parallel()

	if _, err := listXattrs(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file has xattrs")
	}

	if _, err := listXattrs(t.TempDir()); err != nil {
		t.Errorf("a directory without xattrs: %v", err)
	}
}
