//go:build !(linux || darwin || freebsd)

package pacman

import (
	"errors"
	"io/fs"
	"os"
	"time"
)

type statInfo struct {
	uid, gid  int
	dev, ino  uint64
	nlink     uint64
	rdevMajor uint32
	rdevMinor uint32
}

func sysStat(fs.FileInfo) (statInfo, bool) { return statInfo{}, false }

func mknod(string, fs.FileMode, int64, int64) error { return errors.ErrUnsupported }

func setLinkTimes(path string, mtime time.Time) error { return os.Chtimes(path, mtime, mtime) }
