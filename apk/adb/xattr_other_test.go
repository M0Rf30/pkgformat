//go:build !linux

package adb

import (
	"errors"
	"io/fs"
)

func setxattr(string, string, []byte) error { return errors.New("not supported on this system") }

func mkfifo(string, fs.FileMode) error { return errors.New("not supported on this system") }
