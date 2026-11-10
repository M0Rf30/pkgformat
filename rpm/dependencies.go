package rpm

import (
	"fmt"
	"strconv"
	"strings"
)

// Dependency is one entry of a dependency list of a package: a provide, a
// requirement, a conflict, an obsolete or a weak dependency.
type Dependency struct {
	Name string `json:"name"`
	// Flags holds the sense bits, the tag.RPMSENSE_* values: the comparison
	// and the roles of the dependency. The predicates below (IsPre, IsPost,
	// IsRPMLib, ...) read them.
	Flags   Sense  `json:"flags,omitempty"`
	Version string `json:"version,omitempty"`
	// Epoch is the epoch part of the version, when it is written "epoch:version".
	Epoch uint32 `json:"epoch,omitempty"`
}

// IsPre reports whether the requirement is needed before the package is
// installed: Requires(pre), Requires(post) or a legacy PreReq; the pre
// attribute of repodata. See [Sense.IsPre].
func (d Dependency) IsPre() bool { return d.Flags.IsPre() }

// IsPost reports a Requires(post) dependency.
func (d Dependency) IsPost() bool { return d.Flags.IsPost() }

// IsPreun reports a Requires(preun) dependency.
func (d Dependency) IsPreun() bool { return d.Flags.IsPreun() }

// IsPostun reports a Requires(postun) dependency.
func (d Dependency) IsPostun() bool { return d.Flags.IsPostun() }

// IsPretrans reports a Requires(pretrans) dependency.
func (d Dependency) IsPretrans() bool { return d.Flags.IsPretrans() }

// IsPosttrans reports a Requires(posttrans) dependency.
func (d Dependency) IsPosttrans() bool { return d.Flags.IsPosttrans() }

// IsUntrans reports a Requires(preuntrans) or Requires(postuntrans)
// dependency.
func (d Dependency) IsUntrans() bool { return d.Flags.IsUntrans() }

// IsMissingOK reports a dependency that need not be satisfied.
func (d Dependency) IsMissingOK() bool { return d.Flags.IsMissingOK() }

// IsKeyring reports a requirement on a key of the rpm keyring.
func (d Dependency) IsKeyring() bool { return d.Flags.IsKeyring() }

// IsConfig reports the implicit config(name) dependency of a package that
// ships configuration files.
func (d Dependency) IsConfig() bool { return d.Flags.IsConfig() }

// IsRich reports a rich (boolean) dependency such as "(a if b)". Packages do
// not store the rich marker of the sense flags, so it is recognised by the
// parenthesis that opens the name. Package richdep parses and evaluates them.
func (d Dependency) IsRich() bool { return d.Flags.IsRich() || IsRichName(d.Name) }

// IsRPMLib reports an rpmlib(...) feature requirement.
func (d Dependency) IsRPMLib() bool { return d.Flags.IsRPMLib() }

// IsPrereq reports a legacy PreReq dependency.
func (d Dependency) IsPrereq() bool { return d.Flags.IsPrereq() }

// IsInterp reports the dependency on the interpreter of a scriptlet.
func (d Dependency) IsInterp() bool { return d.Flags.IsInterp() }

// IsScriptVerify reports a Requires(verify) dependency.
func (d Dependency) IsScriptVerify() bool { return d.Flags.IsScriptVerify() }

// Versioned reports whether the dependency carries a version comparison.
func (d Dependency) Versioned() bool { return d.Flags.Versioned() }

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
			deps[i].Flags = Sense(flags[i])
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
