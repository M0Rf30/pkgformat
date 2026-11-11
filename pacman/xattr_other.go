//go:build !linux

package pacman

import "errors"

func listXattrs(string) (map[string][]byte, error) { return nil, nil }

func setXattr(string, string, []byte) error { return errors.ErrUnsupported }
