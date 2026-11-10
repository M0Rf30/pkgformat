package deb

import (
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"
	"time"
)

// RemoveScriptHeader is prepended to the prerm and postrm scripts: it makes
// them return at once unless dpkg runs them for a removal, a purge or an
// aborted installation.
const RemoveScriptHeader = `#!/bin/bash
case $1 in
    purge|remove|abort-install) ;;
    *) exit;;
esac
`

// Scripts holds the maintainer scripts and debconf files of a package. An
// empty field is not written. The scripts are written as given, except that
// RemoveScriptHeader is put in front of Prerm and Postrm.
type Scripts struct {
	Preinst  string
	Postinst string
	Prerm    string
	Postrm   string
	// Config is the debconf config script and Templates the debconf templates.
	Config    string
	Templates string
}

// Spec describes a binary package to write. It carries everything the control
// file, the control archive and the metadata files are made of; the payload
// goes with it to Write as a list of Entry values.
type Spec struct {
	// Name is the package name. Required.
	Name string
	// Epoch, Version and Release make the version "[epoch:]version[-release]".
	// Epoch and Release are optional; Version is required.
	Epoch   string
	Version string
	Release string

	// Architecture is the Architecture field ("amd64", "all", ...). Required.
	Architecture string
	// MultiArch is the Multi-Arch field. When empty and Architecture is "all" it
	// is "foreign".
	MultiArch string

	Section  string
	Priority string

	Maintainer string
	// SourcePkg is the Source field.
	SourcePkg string
	// URL is the Homepage field.
	URL  string
	Bugs string
	// Description is the synopsis on its first line, the long description on the
	// following ones. A blank line in it is encoded as " .".
	Description string

	// InstalledSize is the Installed-Size field in KiB. When zero it is computed
	// from the payload.
	InstalledSize int64

	// Relationship fields. Entries are in control-file syntax (see
	// NormalizeDependency to convert PKGBUILD syntax) and are joined with ", ".
	Provides   []string
	PreDepends []string
	Depends    []string
	Conflicts  []string
	Breaks     []string
	Replaces   []string
	Recommends []string
	Suggests   []string
	Enhances   []string
	BuiltUsing []string

	// Conffiles lists the configuration files; a leading "/" is added when
	// missing.
	Conffiles []string

	// Licenses and Copyrights fill the copyright file of the control archive. The
	// file is written when Licenses is not empty.
	Licenses   []string
	Copyrights []string

	Scripts Scripts

	// Changelog, when not empty, is stored gzip-compressed as
	// usr/share/doc/<name>/changelog.Debian.gz.
	Changelog []byte

	// Compression is the compression of the control and data archives: "zstd"
	// (the default when empty), "gzip", "xz" or "none".
	Compression string

	// ModTime is the modification time of the ar members, of the control
	// archive entries and of the generated changelog; zero is the Unix epoch.
	// Set it from SOURCE_DATE_EPOCH for reproducible output.
	ModTime time.Time
}

var (
	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	// archPattern is an architecture, possibly a "linux-amd64" style tuple.
	archPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
)

// FullVersion returns the version as the Version field spells it.
func (s *Spec) FullVersion() string {
	v := s.Version
	if s.Epoch != "" {
		v = s.Epoch + ":" + v
	}

	if s.Release != "" {
		v += "-" + s.Release
	}

	return v
}

// FileName is the conventional file name of the package, name_version_arch.deb.
func (s *Spec) FileName() string {
	return FileName(s.Name, s.FullVersion(), s.Architecture)
}

func invalidSpec(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpec, fmt.Sprintf(format, args...))
}

// Validate checks the spec and returns an error wrapping ErrInvalidSpec for
// a name, version or architecture dpkg would reject, or for a one-line field
// that holds a line break.
func (s *Spec) Validate() error {
	if !namePattern.MatchString(s.Name) {
		return invalidSpec("package name %q must be at least two characters of a-z, 0-9, + - .", s.Name)
	}

	if s.Epoch != "" && !isDigits(s.Epoch) {
		return invalidSpec("epoch %q is not a number", s.Epoch)
	}

	if !ValidVersion(s.FullVersion()) || strings.Contains(s.Version, ":") {
		return invalidSpec("version %q is not a valid Debian version", s.FullVersion())
	}

	if !archPattern.MatchString(s.Architecture) {
		return invalidSpec("architecture %q is not valid", s.Architecture)
	}

	if _, err := ParseCompression(s.Compression); err != nil {
		return err
	}

	single := map[string]string{
		"MultiArch": s.MultiArch, "Section": s.Section, "Priority": s.Priority,
		"Maintainer": s.Maintainer, "SourcePkg": s.SourcePkg, "URL": s.URL, "Bugs": s.Bugs,
	}

	for name, v := range single {
		if strings.ContainsAny(v, "\r\n") {
			return invalidSpec("%s holds a line break", name)
		}
	}

	lists := map[string][]string{
		"Provides": s.Provides, "PreDepends": s.PreDepends, "Depends": s.Depends,
		"Conflicts": s.Conflicts, "Breaks": s.Breaks, "Replaces": s.Replaces,
		"Recommends": s.Recommends, "Suggests": s.Suggests, "Enhances": s.Enhances,
		"BuiltUsing": s.BuiltUsing, "Conffiles": s.Conffiles, "Licenses": s.Licenses,
	}

	for name, list := range lists {
		for _, v := range list {
			if strings.ContainsAny(v, "\r\n") {
				return invalidSpec("%s entry %q holds a line break", name, v)
			}
		}
	}

	return nil
}

// Entry is one member of the data archive of a package.
type Entry struct {
	// Path is the slash-separated path inside the package, relative to the
	// root: "usr/bin/tool". A leading "./" or "/" is ignored.
	Path string
	// Mode holds the permission bits and the type: fs.ModeDir for a
	// directory, fs.ModeSymlink for a symlink; any other type is rejected.
	Mode fs.FileMode
	// Linkname is the target of a symlink.
	Linkname string
	// ModTime is the modification time; zero means the Spec's ModTime.
	ModTime time.Time
	// Data is the content of a regular file. When nil, Open provides it.
	Data []byte
	// Open returns the content of a regular file that is not in Data. It may
	// be called once. Size must be set with it.
	Open func() (io.ReadCloser, error)
	// Size is the length of the content Open returns.
	Size int64
}
