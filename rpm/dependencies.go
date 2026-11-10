package rpm

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// senseCompareMask selects the comparison bits of the sense flags.
const senseCompareMask = tag.RPMSENSE_LESS | tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL

// Dependency is one entry of a dependency list of a package: a provide, a
// requirement, a conflict, an obsolete or a weak dependency.
type Dependency struct {
	Name string `json:"name"`
	// Flags holds the sense bits, the tag.RPMSENSE_* values.
	Flags   uint32 `json:"flags,omitempty"`
	Version string `json:"version,omitempty"`
	// Epoch is the epoch part of the version, when it is written "epoch:version".
	Epoch uint32 `json:"epoch,omitempty"`
}

// SenseFlagsString renders the comparison bits of flags as the flags attribute
// of repodata: "LT", "GT", "EQ", "LE" or "GE". An unversioned dependency
// yields "".
func SenseFlagsString(flags uint32) string {
	switch flags & senseCompareMask {
	case tag.RPMSENSE_LESS:
		return "LT"
	case tag.RPMSENSE_GREATER:
		return "GT"
	case tag.RPMSENSE_EQUAL:
		return "EQ"
	case tag.RPMSENSE_LESS | tag.RPMSENSE_EQUAL:
		return "LE"
	case tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL:
		return "GE"
	default:
		return ""
	}
}

// IsPre reports whether the requirement must be met before the scriptlets of
// the package run.
func (d Dependency) IsPre() bool {
	return d.Flags&(tag.RPMSENSE_PREREQ|tag.RPMSENSE_SCRIPT_PRE|tag.RPMSENSE_SCRIPT_POST) != 0
}

// IsRPMLib reports whether the dependency is an rpmlib(...) feature
// requirement.
func (d Dependency) IsRPMLib() bool {
	return d.Flags&tag.RPMSENSE_RPMLIB != 0
}

// Versioned reports whether the dependency carries a version comparison.
func (d Dependency) Versioned() bool {
	return d.Flags&senseCompareMask != 0
}

// SplitVersionRelease splits a dependency version "ver[-rel]" at the last dash.
func SplitVersionRelease(v string) (version, release string) {
	if i := strings.LastIndexByte(v, '-'); i >= 0 { //nolint:modernize // CutLast is not in every supported toolchain
		return v[:i], v[i+1:]
	}

	return v, ""
}

// Dependencies decodes a dependency list from the parallel name, flags and
// version tags of the header, for example tag.REQUIRENAME, tag.REQUIREFLAGS
// and tag.REQUIREVERSION. A list that is absent yields nil. A flags or
// version tag of 0 is ignored.
func (hdr *RpmHeader) Dependencies(nameTag, flagsTag, versionTag int) ([]Dependency, error) {
	_, n := hdr.genHeader.stringsPrefix(nameTag, 0)

	return hdr.genHeader.dependencies(nameTag, flagsTag, versionTag, n)
}

// dependencies decodes at most limit entries of a dependency list.
func (hdr *rpmHeader) dependencies(nameTag, flagsTag, versionTag, limit int) ([]Dependency, error) {
	names, declared := hdr.stringsPrefix(nameTag, limit)
	if declared > 0 && names == nil {
		return nil, fmt.Errorf("%w: tag %d is malformed", ErrInvalidHeader, nameTag)
	}

	if len(names) == 0 {
		return nil, nil
	}

	var flags []uint64
	if flagsTag != 0 {
		flags, _ = hdr.numbersPrefix(flagsTag, len(names))
	}

	var versions []string
	if versionTag != 0 {
		versions, _ = hdr.stringsPrefix(versionTag, len(names))
	}

	deps := make([]Dependency, len(names))
	for i, name := range names {
		deps[i].Name = name

		if i < len(flags) {
			deps[i].Flags = uint32(flags[i])
		}

		if i < len(versions) {
			deps[i].Epoch, deps[i].Version = splitEpoch(versions[i])
		}
	}

	return deps, nil
}

// splitEpoch splits "epoch:version"; a version without a numeric epoch is
// returned unchanged.
func splitEpoch(ver string) (epoch uint32, version string) {
	if before, after, ok := strings.Cut(ver, ":"); ok {
		if e, err := strconv.ParseUint(before, 10, 32); err == nil {
			return uint32(e), after
		}
	}

	return 0, ver
}
