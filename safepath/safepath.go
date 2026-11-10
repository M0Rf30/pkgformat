package safepath

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
)

// ErrEscapesRoot is returned, wrapped, when a path or symlink target resolves
// outside the root it is confined to.
var ErrEscapesRoot = errors.New("safepath: path escapes root")

// ResolveInRoot resolves unsafePath (absolute or relative; always treated as
// relative to root) component by component, following any symlinks that
// already exist on disk with chroot semantics: absolute link targets are
// reinterpreted relative to root and ".." is clamped at root. The returned
// host path is cleaned and is guaranteed to be lexically AND physically
// inside root. The final component (and any intermediate components) need
// not exist.
//
// Use it before creating files/directories/links during extraction so that a
// symlink planted earlier by the archive (e.g. link -> /etc, or the usrmerge
// lib -> usr/lib) cannot redirect a later write outside root.
//
// Security note: this is TOCTOU-safe only against archive content, i.e. the
// symlink layout produced by the extraction itself. It does NOT defend
// against a concurrent attacker on the host who can mutate the tree between
// resolution and use.
func ResolveInRoot(root, unsafePath string) (string, error) {
	resolved, err := securejoin.SecureJoin(root, unsafePath)
	if err != nil {
		return "", fmt.Errorf("safepath: resolve %q within %q: %w", unsafePath, root, err)
	}

	resolved = filepath.Clean(resolved)

	// Defense-in-depth: re-verify containment lexically.
	rel, err := filepath.Rel(filepath.Clean(root), resolved)
	if err != nil || escapes(rel) {
		return "", escapeError(root, unsafePath, rel)
	}

	return resolved, nil
}

// Join joins root and an archive entry name and verifies the result stays
// inside root. Absolute entry names are reinterpreted as root-relative
// (tar/cpio writers disagree on leading slashes). Entries that resolve to
// root itself (e.g. tar's "./" directory entry) are allowed; use
// JoinStrict to reject them.
func Join(root, name string) (string, error) {
	cleaned, rel, err := relativize(root, name)
	if err != nil {
		return "", err
	}

	if escapes(rel) {
		return "", escapeError(root, name, rel)
	}

	return cleaned, nil
}

// JoinStrict is Join but additionally rejects entries that resolve to the
// root itself ("", ".", "/"). CPIO/RPM extraction uses this: a payload
// entry must always name something *inside* the install root.
func JoinStrict(root, name string) (string, error) {
	cleaned, rel, err := relativize(root, name)
	if err != nil {
		return "", err
	}

	if rel == "." || rel == "" || rel == "/" || escapes(rel) {
		return "", escapeError(root, name, rel)
	}

	return cleaned, nil
}

// SymlinkTarget validates the target of a symlink being created at
// linkPath (an on-disk path under root, as returned by Join/JoinStrict).
//
// Absolute targets are accepted: real packages routinely ship absolute
// symlinks (e.g. /usr/lib64/libfoo.so.1 → /usr/lib/libfoo.so.1) and
// dpkg/rpm/apk accept them — they only resolve at runtime, when the
// package content lives at /.
//
// Relative targets are resolved against the symlink's own parent
// directory and must stay inside root. This is defense-in-depth against
// symlink+write attacks where a malicious archive first plants a symlink
// pointing outside the root and then writes a regular file through it.
func SymlinkTarget(root, linkPath, target string) error {
	if target == "" || filepath.IsAbs(target) {
		return nil
	}

	resolved := filepath.Clean(filepath.Join(filepath.Dir(linkPath), target))

	rel, err := filepath.Rel(filepath.Clean(root), resolved)
	if err != nil {
		return fmt.Errorf("safepath: symlink %q target %q against %q: %w", linkPath, target, root, err)
	}

	if escapes(rel) {
		return fmt.Errorf("%w: symlink %q target %q leaves %q", ErrEscapesRoot, linkPath, target, root)
	}

	return nil
}

// EntrySymlinkTarget validates a symlink target for an archive entry whose
// paths are still archive-relative (no on-disk root yet). The target is
// resolved against the entry's parent directory inside the archive; an
// escape manifests as a leading "..".
//
// Absolute targets are accepted for the same reason as SymlinkTarget.
func EntrySymlinkTarget(entryName, target string) error {
	if target == "" || filepath.IsAbs(target) || strings.HasPrefix(target, "/") {
		return nil
	}

	parent := filepath.ToSlash(filepath.Dir(filepath.ToSlash(entryName)))
	if parent == "." || parent == "/" {
		parent = ""
	}

	joined := filepath.ToSlash(filepath.Join(parent, filepath.ToSlash(target)))

	if joined == ".." || strings.HasPrefix(joined, "../") {
		return fmt.Errorf("%w: symlink %q target %q resolves to %q", ErrEscapesRoot, entryName, target, joined)
	}

	return nil
}

// relativize joins root+name (treating absolute names as root-relative)
// and returns the cleaned join plus its path relative to root.
//
// Names that lexically climb above the root ("../x", "a/../../x") are
// rejected by inspecting the cleaned NAME, not just the join result: when
// root is "/" filepath.Clean clamps ".." at the root ("/../etc" → "/etc"),
// which would silently normalize a hostile entry instead of rejecting it.
func relativize(root, name string) (cleaned, rel string, err error) {
	if filepath.IsAbs(name) {
		name = strings.TrimPrefix(name, "/")
	}

	if cleanName := filepath.Clean(name); escapes(cleanName) {
		return "", "", fmt.Errorf("%w: entry %q climbs above %q", ErrEscapesRoot, name, root)
	}

	cleanRoot := filepath.Clean(root)
	cleaned = filepath.Clean(filepath.Join(cleanRoot, name))

	rel, err = filepath.Rel(cleanRoot, cleaned)
	if err != nil {
		return "", "", fmt.Errorf("safepath: entry %q against %q: %w", name, root, err)
	}

	return cleaned, rel, nil
}

// escapes reports whether a root-relative path points outside the root.
func escapes(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// escapeError builds the standard traversal rejection error.
func escapeError(root, name, rel string) error {
	return fmt.Errorf("%w: entry %q resolves to %q relative to %q", ErrEscapesRoot, name, rel, root)
}
