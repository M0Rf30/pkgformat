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

	// Modes are the permissions of the members; zero selects 0755 for the
	// scripts and Config and 0644 for Templates. dpkg refuses a maintainer
	// script (Preinst, Postinst, Prerm, Postrm) whose mode is not between 0555
	// and 0775 with no special bits, which Validate checks.
	Modes ScriptModes
}

// ScriptModes holds the permission bits of the script members of the control
// archive. See Scripts.Modes.
type ScriptModes struct {
	Preinst   fs.FileMode
	Postinst  fs.FileMode
	Prerm     fs.FileMode
	Postrm    fs.FileMode
	Config    fs.FileMode
	Templates fs.FileMode
}

// ControlMember is a file of the control archive that Spec has no member for.
type ControlMember struct {
	// Name is the file name in the control archive: one path element made of
	// letters, digits and ". _ + -".
	Name string
	// Mode holds the permission bits; zero means 0644.
	Mode fs.FileMode
	// Data is the content, at most MaxControlFileSize bytes.
	Data []byte
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

	// Essential and Protected set the fields of that name to "yes".
	Essential bool
	Protected bool

	// Relationship fields, typed as ParseRelations returns them (see
	// ParseRelationList to build them from control-file syntax and
	// NormalizeDependency to convert PKGBUILD syntax). A binary package may not
	// carry architecture or profile restrictions, Provides and Built-Using
	// take only "=", and only Depends, Pre-Depends, Recommends, Suggests and
	// Enhances take alternatives; Validate enforces it.
	Provides   []Alternatives
	PreDepends []Alternatives
	Depends    []Alternatives
	Conflicts  []Alternatives
	Breaks     []Alternatives
	Replaces   []Alternatives
	Recommends []Alternatives
	Suggests   []Alternatives
	Enhances   []Alternatives
	BuiltUsing []Alternatives
	// StaticBuiltUsing is the Static-Built-Using field: like BuiltUsing, for
	// the sources of what a statically linked binary embeds.
	StaticBuiltUsing []Alternatives

	// Fields are further control fields, written in their order after the
	// fields above and before Description: Rules-Requires-Root, Important,
	// Build-Essential, Origin, Original-Maintainer, Tag, Description-md5,
	// Vcs-*, X-* and any other well-formed name. The fields the members of
	// Spec write are rejected here. Fields with a defined syntax are checked.
	Fields []Field

	// Conffiles lists the configuration files; a leading "/" is added when
	// missing.
	Conffiles []string

	// Triggers, Shlibs and Symbols fill the triggers, shlibs and symbols
	// members of the control archive; a member is written when its list is
	// not empty.
	Triggers []Trigger
	Shlibs   []Shlib
	Symbols  []SymbolsLibrary

	// ExtraControl holds further members of the control archive, in order.
	ExtraControl []ControlMember

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
	// CompressionLevel is the level of the data archive compression: 1 is the
	// fastest, MaxGzipLevel, MaxXZLevel and MaxZstdLevel the smallest output;
	// zero is the default of the method. "none" takes only zero.
	CompressionLevel int

	// ControlCompression and ControlCompressionLevel choose the compression of
	// the control archive on its own. An empty ControlCompression is
	// Compression, and the level is then CompressionLevel; set a level only
	// together with a method.
	ControlCompression      string
	ControlCompressionLevel int

	// ModTime is the modification time of the ar members, of the control
	// archive entries and of the generated changelog; zero is the Unix epoch.
	// Set it from SOURCE_DATE_EPOCH (see SourceDateEpoch) for reproducible
	// output.
	ModTime time.Time
	// ClampMTime limits the modification time of every data entry to ModTime,
	// as "dpkg-deb --clamp-mtime" does: an entry that is older keeps its time,
	// a newer one gets ModTime. It is what makes a build from a source tree
	// reproducible when files are newer than SOURCE_DATE_EPOCH.
	ClampMTime bool
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

	if s.ClampMTime && s.ModTime.IsZero() {
		return invalidSpec("ClampMTime needs ModTime, the time to clamp to")
	}

	if err := s.validateFields(); err != nil {
		return err
	}

	if err := s.validateRelations(); err != nil {
		return err
	}

	if err := s.validateControlMembers(); err != nil {
		return err
	}

	return s.validateCompression()
}

func (s *Spec) validateFields() error {
	for _, f := range [...]struct{ name, v string }{
		{"MultiArch", s.MultiArch}, {"Section", s.Section}, {"Priority", s.Priority},
		{"Maintainer", s.Maintainer}, {"SourcePkg", s.SourcePkg}, {"URL", s.URL}, {"Bugs", s.Bugs},
	} {
		if err := checkSingleLine(f.name, f.v); err != nil {
			return err
		}
	}

	for _, list := range [...]struct {
		name   string
		values []string
	}{{"Conffiles", s.Conffiles}, {"Licenses", s.Licenses}} {
		for _, v := range list.values {
			if strings.ContainsAny(v, "\r\n") {
				return invalidSpec("%s entry %q holds a line break", list.name, v)
			}
		}
	}

	return validateFields(s.Fields)
}

func (s *Spec) validateRelations() error {
	for _, r := range [...]struct {
		name  string
		list  []Alternatives
		rules relationRules
	}{
		{"Provides", s.Provides, provideRules},
		{"Pre-Depends", s.PreDepends, depRules},
		{"Depends", s.Depends, depRules},
		{"Recommends", s.Recommends, depRules},
		{"Suggests", s.Suggests, depRules},
		{"Enhances", s.Enhances, depRules},
		{"Conflicts", s.Conflicts, conflictRules},
		{"Breaks", s.Breaks, conflictRules},
		{"Replaces", s.Replaces, replaceRules},
		{"Built-Using", s.BuiltUsing, builtRules},
		{"Static-Built-Using", s.StaticBuiltUsing, builtRules},
	} {
		if err := validateRelations(r.name, r.list, r.rules); err != nil {
			return err
		}
	}

	return nil
}

// Entry is one member of the data archive of a package.
type Entry struct {
	// Path is the slash-separated path inside the package, relative to the
	// root: "usr/bin/tool". A leading "./" or "/" is ignored.
	Path string
	// Mode holds the permission bits, with fs.ModeSetuid, fs.ModeSetgid and
	// fs.ModeSticky, and the type: fs.ModeDir for a directory, fs.ModeSymlink
	// for a symlink, fs.ModeNamedPipe for a FIFO, fs.ModeDevice for a block
	// device and fs.ModeDevice|fs.ModeCharDevice for a character device; no
	// type is a regular file. A socket cannot be stored in a tar archive and
	// fails with ErrUnsupportedEntryType, as does any other type.
	Mode fs.FileMode
	// Linkname is the target of a symlink: stored as given.
	Linkname string
	// Hardlink, when not empty, makes the entry a hard link to the regular
	// file of that path, which must be an earlier entry of the payload (or
	// itself a hard link to one). The entry has no content of its own; Mode is
	// recorded as given and should repeat the mode of the target, which is what
	// dpkg applies.
	Hardlink string
	// DevMajor and DevMinor are the device numbers of a device node.
	DevMajor int64
	DevMinor int64

	// UID and GID are the numeric owner and group, zero (root) by default.
	// User and Group are their names; when empty they are "root" for id zero
	// and absent otherwise. dpkg installs by name when the system knows it and
	// falls back to the numbers.
	UID, GID    int
	User, Group string

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
