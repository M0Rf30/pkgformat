package richdep

import (
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm"
)

// evr is a parsed "[epoch:]version[-release]".
type evr struct {
	epoch, version, release string
	hasEpoch, hasRelease    bool
}

// parseEVR splits like librpm's parseEVR: the epoch is the leading digits
// before a colon (an empty one is 0), the release follows the last dash.
func parseEVR(s string) evr {
	var e evr

	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}

	rest := s
	if i < len(s) && s[i] == ':' {
		e.epoch, e.hasEpoch = s[:i], true
		if e.epoch == "" {
			e.epoch = "0"
		}

		rest = s[i+1:]
	}

	if j := strings.LastIndexByte(rest, '-'); j >= 0 { //nolint:modernize // CutLast is not in every supported toolchain
		e.version, e.release, e.hasRelease = rest[:j], rest[j+1:], true
	} else {
		e.version = rest
	}

	return e
}

// epochValue is atol of an epoch: the leading digits, 0 for none.
func epochValue(s string) int64 {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}

	n, _ := strconv.ParseInt(s[:end], 10, 64)

	return n
}

// Overlaps reports whether the ranges of two capabilities with the same name
// have a version in common, as librpm decides whether a provide satisfies a
// requirement: different names never overlap; if either side has no version
// comparison, they do; otherwise the versions are compared (epoch only when
// both sides have one, else a nonzero epoch wins; the release only when both
// have one) and the ranges are intersected.
func (a Atom) Overlaps(b Atom) bool {
	if a.Name != b.Name {
		return false
	}

	f1, f2 := a.Cmp&cmpMask, b.Cmp&cmpMask
	if f1 == 0 || f2 == 0 || a.Version == "" || b.Version == "" {
		return true
	}

	v1, v2 := parseEVR(a.Version), parseEVR(b.Version)

	var sense int

	switch {
	case v1.hasEpoch && v1.epoch != "" && v2.hasEpoch && v2.epoch != "":
		sense = rpm.Vercmp(v1.epoch, v2.epoch)
	case v1.hasEpoch && epochValue(v1.epoch) > 0:
		sense = 1
	case v2.hasEpoch && epochValue(v2.epoch) > 0:
		sense = -1
	}

	if sense == 0 {
		sense = rpm.Vercmp(v1.version, v2.version)
		if sense == 0 {
			if v1.hasRelease && v1.release != "" && v2.hasRelease && v2.release != "" {
				sense = rpm.Vercmp(v1.release, v2.release)
			} else if (v1.hasRelease && v1.release != "" && f2&Equal != 0) ||
				(v2.hasRelease && v2.release != "" && f1&Equal != 0) {
				return true
			}
		}
	}

	switch {
	case sense < 0:
		return f1&Greater != 0 || f2&Less != 0
	case sense > 0:
		return f1&Less != 0 || f2&Greater != 0
	default:
		return (f1&Equal != 0 && f2&Equal != 0) ||
			(f1&Less != 0 && f2&Less != 0) ||
			(f1&Greater != 0 && f2&Greater != 0)
	}
}

// AtomOf returns the capability a dependency entry of a package states: its
// name and, when it carries a comparison, "[epoch:]version[-release]". An
// epoch of 0 is left out, as repository metadata and rpm headers do not tell
// it from no epoch at all.
func AtomOf(d rpm.Dependency) Atom {
	a := Atom{Name: d.Name, Cmp: FromFlags(d.Flags)}
	if a.Cmp == 0 {
		return a
	}

	a.Version = d.Version
	if d.Epoch != 0 {
		a.Version = strconv.FormatUint(uint64(d.Epoch), 10) + ":" + d.Version
	}

	return a
}
