//go:build !linux

package pacman

import "errors"

func getXattr(string, string) (string, error) { return "", errors.ErrUnsupported }
