package adb

import (
	"io/fs"
	"syscall"
)

func setxattr(path, key string, value []byte) error {
	return syscall.Setxattr(path, key, value, 0)
}

func mkfifo(path string, perm fs.FileMode) error {
	return syscall.Mkfifo(path, uint32(perm.Perm()))
}
