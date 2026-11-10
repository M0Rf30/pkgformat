package deb

import "strings"

// FileName is the file name of a binary package, name_version_arch.deb. The
// epoch is not part of it: "1:2.0-1" is written "2.0-1".
func FileName(name, version, arch string) string {
	return name + "_" + StripEpoch(version) + "_" + arch + ".deb"
}

// PoolPath renders the pool location of a package file inside a repository:
// pool/<component>/<prefix>/<package>/<filename>. The prefix is the first
// letter of the package name, or "lib" plus the fourth letter for lib* names
// (the layout apt expects). It is "" for an empty package name.
func PoolPath(component, packageName, filename string) string {
	if packageName == "" {
		return ""
	}

	prefix := string(packageName[0])
	if len(packageName) > 3 && strings.HasPrefix(packageName, "lib") {
		prefix = "lib" + string(packageName[3])
	}

	return "pool/" + component + "/" + prefix + "/" + packageName + "/" + filename
}

// PackagesPath is the location of a Packages index relative to the
// repository root: dists/<dist>/<component>/binary-<arch>/Packages<ext>, where
// ext is "", ".gz", ".xz", ...
func PackagesPath(dist, component, arch, ext string) string {
	return "dists/" + dist + "/" + component + "/binary-" + arch + "/Packages" + ext
}

// ReleasePath is the location of the Release file of a distribution relative
// to the repository root.
func ReleasePath(dist string) string { return "dists/" + dist + "/Release" }

// InReleasePath is the location of the clear-signed InRelease file.
func InReleasePath(dist string) string { return "dists/" + dist + "/InRelease" }

// ReleaseGPGPath is the location of the detached Release signature.
func ReleaseGPGPath(dist string) string { return "dists/" + dist + "/Release.gpg" }
