package apk

import (
	"golang.org/x/sys/unix"
)

func mkfifo(path string, mode uint32) error { return unix.Mkfifo(path, mode) }

func mknod(path string, char bool, mode uint32, major, minor int64) error {
	kind := uint32(unix.S_IFBLK)
	if char {
		kind = unix.S_IFCHR
	}

	return unix.Mknod(path, kind|mode, int(unix.Mkdev(uint32(major), uint32(minor))))
}

func lchown(path string, uid, gid int) error { return unix.Lchown(path, uid, gid) }

func lsetxattr(path, name string, value []byte) error { return unix.Lsetxattr(path, name, value, 0) }
