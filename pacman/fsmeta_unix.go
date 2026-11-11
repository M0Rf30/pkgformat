//go:build linux || darwin || freebsd

package pacman

import (
	"fmt"
	"io/fs"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// statInfo is what the file system keeps of a file beyond what io/fs shows.
type statInfo struct {
	uid, gid  int
	dev, ino  uint64
	nlink     uint64
	rdevMajor uint32
	rdevMinor uint32
}

// sysStat extracts the owner, the inode and the device number from the result
// of a stat call; ok is false when the platform value is not there.
func sysStat(fi fs.FileInfo) (statInfo, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return statInfo{}, false
	}

	return statInfo{
		uid: int(st.Uid), gid: int(st.Gid),
		dev: uint64(st.Dev), ino: uint64(st.Ino), nlink: uint64(st.Nlink), //nolint:unconvert // the types differ between platforms
		rdevMajor: unix.Major(uint64(st.Rdev)), rdevMinor: unix.Minor(uint64(st.Rdev)), //nolint:unconvert // see above
	}, true
}

// mknod creates a FIFO or a device node at path.
func mknod(path string, mode fs.FileMode, major, minor int64) error {
	perm := posixMode(mode)

	var kind uint32

	switch {
	case mode&fs.ModeNamedPipe != 0:
		kind = unix.S_IFIFO
	case mode&fs.ModeCharDevice != 0:
		kind = unix.S_IFCHR
	case mode&fs.ModeDevice != 0:
		kind = unix.S_IFBLK
	default:
		return fmt.Errorf("pacman: mknod: %v is not a special file", mode)
	}

	if err := unix.Mknod(path, kind|perm, int(unix.Mkdev(uint32(major), uint32(minor)))); err != nil {
		return err
	}

	return nil
}

// setLinkTimes sets the modification time of path itself, not of what a
// symbolic link points at.
func setLinkTimes(path string, mtime time.Time) error {
	ts := []unix.Timespec{unix.NsecToTimespec(mtime.UnixNano()), unix.NsecToTimespec(mtime.UnixNano())}

	return unix.UtimesNanoAt(unix.AT_FDCWD, path, ts, unix.AT_SYMLINK_NOFOLLOW)
}
