package repodata

import (
	"strings"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// isPre reports whether a requirement is needed before or while the scriptlets
// of the package run, which primary.xml marks pre="1": the prerequisite, the
// pre/post and transaction scriptlet requirements.
func isPre(d rpm.Dependency) bool {
	return d.Flags&(tag.RPMSENSE_POSTTRANS|tag.RPMSENSE_PREREQ|tag.RPMSENSE_PRETRANS|
		tag.RPMSENSE_SCRIPT_PRE|tag.RPMSENSE_SCRIPT_POST) != 0
}

type depKey struct {
	name, flags, ver string
	epoch            uint32
}

func keyOf(d rpm.Dependency) depKey {
	return depKey{d.Name, rpm.SenseFlagsString(d.Flags), d.Version, d.Epoch}
}

// lastRequire is the last requirement kept under a name: the next one with
// the same name is dropped when it only repeats it.
type lastRequire struct {
	key depKey
	pre bool
}

// requiresFilter applies the filtering createrepo_c puts on the requirements
// of a package and keeps its scratch maps and slices between packages, so
// repeated use (one filter per metadata run) does not allocate per package.
// The slice returned by filter is only valid until the next call.
//
// A requirement is dropped when it is an rpmlib(...) feature, a primary file
// of the package, something the package provides with the same comparison, or
// a repeat of the previous requirement of that name. All the libc.so.6
// requirements collapse into the one with the highest symbol version, which is
// listed last.
type requiresFilter struct {
	provides map[depKey]struct{}
	files    map[string]struct{}
	last     map[string]lastRequire
	out      []rpm.Dependency
}

func newRequiresFilter() *requiresFilter {
	return &requiresFilter{
		provides: make(map[depKey]struct{}),
		files:    make(map[string]struct{}),
		last:     make(map[string]lastRequire),
	}
}

func (f *requiresFilter) filter(pkg *rpm.Package) []rpm.Dependency {
	clear(f.provides)
	clear(f.files)
	clear(f.last)

	for _, d := range pkg.Provides {
		f.provides[keyOf(d)] = struct{}{}
	}

	for i := range pkg.Files {
		f.files[pkg.Files[i].Path] = struct{}{}
	}

	f.out = f.out[:0]

	var libc *rpm.Dependency

	for i := range pkg.Requires {
		d := &pkg.Requires[i]

		if d.IsRPMLib() || strings.HasPrefix(d.Name, "rpmlib(") {
			continue
		}

		if strings.HasPrefix(d.Name, "/") && isPrimaryFile(d.Name) {
			if _, ok := f.files[d.Name]; ok {
				continue
			}
		}

		k := keyOf(*d)
		if _, ok := f.provides[k]; ok {
			continue
		}

		pre := isPre(*d)
		if l, ok := f.last[d.Name]; ok && l.key == k && l.pre == pre {
			continue
		}

		if strings.HasPrefix(d.Name, "libc.so.6") {
			if libc == nil || compareLibcDependency(libc.Name, d.Name) == 2 {
				libc = d
			}

			continue
		}

		f.last[d.Name] = lastRequire{k, pre}
		f.out = append(f.out, *d)
	}

	if libc != nil {
		f.out = append(f.out, *libc)
	}

	return f.out
}

// compareLibcDependency compares two requirement names of one library by the
// version in their first parentheses, as createrepo_c does: 0 when the same,
// 1 when the first is higher, 2 when the second is. An empty pair of
// parentheses ranks lowest, so does a name without a digit in them; the
// version starts at the first digit.
func compareLibcDependency(a, b string) int {
	va, okA := symbolVersion(a)
	vb, okB := symbolVersion(b)

	switch {
	case !okA && !okB:
		return 0
	case !okA:
		return 2
	case !okB:
		return 1
	}

	switch r := rpm.Vercmp(va, vb); {
	case r < 0:
		return 2
	case r > 0:
		return 1
	}

	return 0
}

// symbolVersion returns the text from the first digit to the closing
// parenthesis of the first parenthesised group of name; false when there is
// no group, it is empty or holds no digit.
func symbolVersion(name string) (string, bool) {
	_, rest, ok := strings.Cut(name, "(")
	if !ok {
		return "", false
	}

	group, _, ok := strings.Cut(rest, ")")
	if !ok {
		return "", false
	}

	i := strings.IndexAny(group, "0123456789")
	if i < 0 {
		return "", false
	}

	return group[i:], true
}
