//go:build unix

package rpm_test

import (
	"io/fs"
	"syscall"
)

func statUID(fi fs.FileInfo) uint32 { return fi.Sys().(*syscall.Stat_t).Uid }
