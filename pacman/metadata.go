package pacman

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// MaxChangelogBytes bounds the .CHANGELOG of a package.
const MaxChangelogBytes = 16 << 20

// maxMtreeMemberBytes bounds the compressed .MTREE member of a package.
const maxMtreeMemberBytes = 256 << 20

// ErrMetadataTooLarge reports a metadata file over its limit.
var ErrMetadataTooLarge = errors.New("pacman: metadata file too large")

// Hook names pacman runs from a package's .INSTALL file.
const (
	HookPreInstall  = "pre_install"
	HookPostInstall = "post_install"
	HookPreUpgrade  = "pre_upgrade"
	HookPostUpgrade = "post_upgrade"
	HookPreRemove   = "pre_remove"
	HookPostRemove  = "post_remove"
)

var hookNames = []string{HookPreInstall, HookPostInstall, HookPreUpgrade, HookPostUpgrade, HookPreRemove, HookPostRemove}

// InstallScript is the .INSTALL file of a package, as read back.
type InstallScript struct {
	// Raw is the whole text of the file.
	Raw []byte
	// Hooks lists the hook functions the file defines, in the order of
	// pacman's run (pre_install first), once each.
	Hooks []string
}

// Has reports whether the script defines the hook (HookPostInstall, ...).
func (s *InstallScript) Has(hook string) bool {
	return s != nil && slices.Contains(s.Hooks, hook)
}

// hookDef matches the definition of a hook function the way a shell reads
// one: "name() {", "name ()" with the brace on the next line, "function name"
// or "function name()". A line starting with "#" is a comment and does not
// match.
var hookDef = regexp.MustCompile(`^[ \t]*(?:(function)[ \t]+)?(` + strings.Join(hookNames, "|") + `)[ \t]*(\([ \t]*\))?[ \t]*(?:\{.*)?$`)

// ParseInstall reads the text of a .INSTALL file and finds which of the six
// hook functions it defines. The text is not run or otherwise interpreted: a
// definition is recognized by the line that opens it, so a function defined
// inside an "eval" or a here-document is not seen. A file over MaxInstallBytes
// fails with ErrMetadataTooLarge.
func ParseInstall(r io.Reader) (*InstallScript, error) {
	data, err := limitio.ReadAll(r, MaxInstallBytes, ErrMetadataTooLarge)
	if err != nil {
		return nil, fmt.Errorf("pacman: reading .INSTALL: %w", err)
	}

	found := map[string]bool{}

	for line := range strings.Lines(string(data)) {
		m := hookDef.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
		if m == nil {
			continue
		}

		// Without the "function" keyword the parentheses are required.
		if m[1] == "" && m[3] == "" {
			continue
		}

		found[m[2]] = true
	}

	s := &InstallScript{Raw: data}

	for _, h := range hookNames {
		if found[h] {
			s.Hooks = append(s.Hooks, h)
		}
	}

	return s, nil
}

// Metadata is everything a package says about itself outside its payload.
type Metadata struct {
	// Info is the .PKGINFO.
	Info *PkgInfo
	// BuildInfo is the .BUILDINFO, nil when the package has none (a package
	// built before makepkg 5.1).
	BuildInfo *BuildInfo
	// Install is the .INSTALL, nil when the package has none.
	Install *InstallScript
	// Changelog is the .CHANGELOG, nil when the package has none.
	Changelog []byte
	// Mtree is the .MTREE, nil when the package has none.
	Mtree *Mtree
}

// ReadMetadata reads the metadata files of a package: .PKGINFO, .BUILDINFO
// (format 1 or 2), .INSTALL, .CHANGELOG and .MTREE. It reads the whole archive,
// because the format does not fix the position of the metadata members, and
// ignores the payload. A package without .PKGINFO fails with ErrNoPkgInfo.
func ReadMetadata(r io.Reader) (*Metadata, error) {
	md := &Metadata{}

	err := WalkPackage(r, func(e *Entry, body io.Reader) error {
		if !e.IsMetadata() || !e.IsRegular() {
			return nil
		}

		var err error

		switch e.Path {
		case FilePkgInfo:
			if md.Info != nil {
				return fmt.Errorf("%w: duplicate .PKGINFO", ErrInvalidField)
			}

			md.Info, err = ParsePkgInfo(body)
		case FileBuildInfo:
			md.BuildInfo, err = ParseBuildInfo(body)
		case FileInstall:
			md.Install, err = ParseInstall(body)
		case FileChangelog:
			md.Changelog, err = limitio.ReadAll(body, MaxChangelogBytes, ErrMetadataTooLarge)
		case FileMtree:
			md.Mtree, err = ParseMtree(limitio.Capped(body, maxMtreeMemberBytes, ErrMetadataTooLarge))
		}

		return err
	})
	if err != nil {
		return nil, err
	}

	if md.Info == nil {
		return nil, ErrNoPkgInfo
	}

	return md, nil
}
