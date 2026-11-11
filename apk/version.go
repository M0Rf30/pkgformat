package apk

import "github.com/M0Rf30/pkgformat/internal/apkver"

// An Alpine version is a number, any number of ".number" components, an
// optional lowercase letter, any number of "_suffix[number]" groups, an
// optional "~hexdigits" commit hash and an optional "-rN" release:
//
//	1.2.3b_rc2_p4~9fceb02-r5

// ValidVersion reports whether v is a version in the syntax apk accepts:
// digits, ".digits", a letter, "_suffix[digits]" groups, "~hash" and "-rN", in
// that order. "1.2.3-r0", "2.0_rc1" and "20240101_git~1a2b3c-r2" are valid;
// "", "1.", "1.0-1" and "1.0_foo" are not.
func ValidVersion(v string) bool {
	return apkver.Valid(v)
}

// CompareVersions compares two versions as apk does and returns -1, 0 or +1.
// Both versions are expected to be valid; for a string that is not (see
// [ValidVersion]) the result is defined but not meaningful.
//
// The release ("-r1") counts: "1.0-r1" is older than "1.0-r2", and "1.0" is
// older than "1.0-r1". Pre-release suffixes (_alpha, _beta, _pre, _rc) are
// older than the version without them and post-release ones (_cvs, _svn, _git,
// _hg, _p) are newer. "1.0" is older than "1.0.1" and than "1.0a" but newer
// than "1.0_rc1".
func CompareVersions(a, b string) int {
	return apkver.Compare(a, b)
}
