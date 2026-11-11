package pacman

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ParseConfigFS parses the pacman.conf named name inside fsys. Includes are
// read from the same file system unless opts.Include says otherwise: a value
// such as "/etc/pacman.d/mirrorlist" names "etc/pacman.d/mirrorlist" in fsys,
// and globs are expanded with fs.Glob. No host path is built in.
func ParseConfigFS(fsys fs.FS, name string, opts ParseOptions) (*Config, error) {
	rel, err := fsPath(name)
	if err != nil {
		return nil, err
	}

	f, err := fsys.Open(rel)
	if err != nil {
		return nil, fmt.Errorf("pacman: opening configuration: %w", err)
	}

	defer func() { _ = f.Close() }()

	if opts.Include == nil {
		opts.Include = FSIncludeResolver(fsys)
	}

	return parseConfig(name, f, opts)
}

// ParseConfigFile reads the pacman.conf at name in the host file system.
// Include values are paths too (relative ones to the working directory, as in
// pacman), with globs expanded, unless opts.Include says otherwise. The path is
// the caller's: no location is built in.
func ParseConfigFile(name string, opts ParseOptions) (*Config, error) {
	f, err := os.Open(filepath.Clean(name))
	if err != nil {
		return nil, fmt.Errorf("pacman: opening configuration: %w", err)
	}

	defer func() { _ = f.Close() }()

	if opts.Include == nil {
		opts.Include = OSIncludeResolver
	}

	return parseConfig(name, f, opts)
}

// OSIncludeResolver resolves an include to host files: the value is a path, or
// a glob pattern that expands to the matching files in sorted order. A value
// that matches no file fails with an error wrapping fs.ErrNotExist, as in
// pacman.
func OSIncludeResolver(include string) ([]IncludeFile, error) {
	paths := []string{include}

	if strings.ContainsAny(include, "*?[") {
		var err error

		if paths, err = filepath.Glob(include); err != nil {
			return nil, fmt.Errorf("%w: Include pattern %q: %w", ErrInvalidConfig, include, err)
		}

		if len(paths) == 0 {
			return nil, fmt.Errorf("pacman: Include %q: %w", include, fs.ErrNotExist)
		}
	}

	files := make([]IncludeFile, len(paths))

	for i, p := range paths {
		files[i] = IncludeFile{Name: p, Open: func() (io.ReadCloser, error) { return os.Open(filepath.Clean(p)) }}
	}

	return files, nil
}

// FSIncludeResolver returns an IncludeResolver reading from fsys. A leading
// "/" of the include value is dropped, and a value that would climb out of
// fsys is an ErrInvalidConfig.
func FSIncludeResolver(fsys fs.FS) IncludeResolver {
	return func(include string) ([]IncludeFile, error) {
		pattern, err := fsPath(include)
		if err != nil {
			return nil, err
		}

		matches := []string{pattern}

		if strings.ContainsAny(pattern, "*?[") {
			if matches, err = fs.Glob(fsys, pattern); err != nil {
				return nil, fmt.Errorf("%w: Include pattern %q: %w", ErrInvalidConfig, include, err)
			}

			if len(matches) == 0 {
				return nil, fmt.Errorf("pacman: Include %q: %w", include, fs.ErrNotExist)
			}
		}

		files := make([]IncludeFile, len(matches))

		for i, m := range matches {
			files[i] = IncludeFile{Name: m, Open: func() (io.ReadCloser, error) { return fsys.Open(m) }}
		}

		return files, nil
	}
}

// fsPath turns an absolute or relative configuration path into an fs.FS path.
func fsPath(p string) (string, error) {
	rel := path.Clean(strings.TrimLeft(p, "/"))

	if !fs.ValidPath(rel) {
		return "", fmt.Errorf("%w: path %q is outside the file system", ErrInvalidConfig, p)
	}

	return rel, nil
}
