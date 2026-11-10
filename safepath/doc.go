// Package safepath holds the path-containment checks an archive or package
// extractor needs: it defends against zip-slip path traversal and
// symlink-escape attacks (deb data.tar, RPM CPIO payloads, APK tarballs,
// container rootfs layers, source archives).
//
// All joins use filepath.Rel-based containment. That is immune to the
// prefix-aliasing flaw of naive strings.HasPrefix checks (root "/tmp/foo"
// must not admit "/tmp/foobar/evil") and still meaningful when root is "/",
// where every absolute path trivially passes a prefix check.
//
// A rejected path wraps ErrEscapesRoot.
package safepath
