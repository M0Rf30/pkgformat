//go:build linux

package pacman

import (
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

// listXattrs returns the extended attributes of path, a symbolic link not
// followed. A file system without extended attributes yields none.
func listXattrs(path string) (map[string][]byte, error) {
	size, err := unix.Llistxattr(path, nil)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENODATA) {
			return nil, nil
		}

		return nil, err
	}

	if size == 0 {
		return nil, nil
	}

	buf := make([]byte, size)

	size, err = unix.Llistxattr(path, buf)
	if err != nil {
		return nil, err
	}

	out := map[string][]byte{}

	for name := range strings.SplitSeq(string(buf[:size]), "\x00") {
		if name == "" {
			continue
		}

		vsize, err := unix.Lgetxattr(path, name, nil)
		if err != nil {
			return nil, err
		}

		val := make([]byte, vsize)

		if vsize > 0 {
			vsize, err = unix.Lgetxattr(path, name, val)
			if err != nil {
				return nil, err
			}
		}

		out[name] = val[:vsize]
	}

	return out, nil
}

// setXattr sets one extended attribute of path, a symbolic link not followed.
func setXattr(path, name string, value []byte) error {
	return unix.Lsetxattr(path, name, value, 0)
}
