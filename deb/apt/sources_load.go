package apt

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// LoadSources reads the configured sources. listFile is a sources.list style
// file and listDir a directory of *.list (one-line) and *.sources (deb822)
// files, read in name order, as apt reads /etc/apt/sources.list and
// sources.list.d. Either may be empty, and either may be missing: apt
// tolerates that, and so does LoadSources.
//
// In the directory only regular files (or links to them) count, named with
// letters, digits, "_", "-" and "." and not starting with a dot or ending with
// one, as apt's run-parts style rule has it; other names are ignored.
//
// A file that exists but cannot be read, or is larger than
// MaxSourcesFileBytes, is skipped and reported in the returned error, next to
// the sources that did load; so is every entry that did not parse, as a
// *SourceError carrying the file name and line. The error is an errors.Join
// of them, empty when all went well.
func LoadSources(listFile, listDir string) ([]Source, error) {
	var (
		out  []Source
		errs []error
	)

	read := func(path string) {
		data, err := readSourcesFile(path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}

			return
		}

		var (
			got  []Source
			perr error
		)

		if strings.HasSuffix(path, ".sources") {
			got, perr = parseSources822(path, data)
		} else {
			got, perr = parseSourcesList(path, data)
		}

		out = append(out, got...)

		if perr != nil {
			errs = append(errs, perr)
		}
	}

	if listFile != "" {
		read(listFile)
	}

	if listDir != "" {
		entries, err := os.ReadDir(listDir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("apt: read sources directory: %w", err))
		}

		for _, e := range entries {
			name := e.Name()
			if !sourcesFileName(name) {
				continue
			}

			path := filepath.Join(listDir, name)

			if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
				continue
			}

			read(path)
		}
	}

	return out, errors.Join(errs...)
}

// sourcesFileName reports whether name is one apt reads from sources.list.d:
// an extension of list or sources, only [A-Za-z0-9_.-], not hidden, and not
// ending with a period.
func sourcesFileName(name string) bool {
	if name == "" || name[0] == '.' || strings.HasSuffix(name, ".") {
		return false
	}

	if !strings.HasSuffix(name, ".list") && !strings.HasSuffix(name, ".sources") {
		return false
	}

	for i := range len(name) {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return false
		}
	}

	return true
}

func readSourcesFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("apt: open sources file: %w", err)
	}

	defer func() { _ = f.Close() }()

	data, err := limitio.ReadAll(f, MaxSourcesFileBytes, ErrTooLarge)
	if err != nil {
		return "", fmt.Errorf("apt: read sources file %s: %w", filepath.Base(path), err)
	}

	return string(data), nil
}
