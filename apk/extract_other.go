//go:build !linux

package apk

func mkfifo(string, uint32) error { return ErrUnsupported }

func mknod(string, bool, uint32, int64, int64) error { return ErrUnsupported }

func lchown(string, int, int) error { return ErrUnsupported }

func lsetxattr(string, string, []byte) error { return ErrUnsupported }
