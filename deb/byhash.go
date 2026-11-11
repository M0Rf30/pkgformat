package deb

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ByHashAlgorithm names a digest of the by-hash tree of a repository: the name
// is the directory under by-hash/ ("SHA256") and the name of the Release
// section that lists it.
type ByHashAlgorithm string

// The digests a by-hash tree is laid out by, strongest first, the order a
// client prefers.
const (
	ByHashSHA512 ByHashAlgorithm = "SHA512"
	ByHashSHA256 ByHashAlgorithm = "SHA256"
	ByHashSHA1   ByHashAlgorithm = "SHA1"
	ByHashMD5    ByHashAlgorithm = "MD5Sum"
)

// ByHashAlgorithms lists every ByHashAlgorithm, strongest first.
func ByHashAlgorithms() []ByHashAlgorithm {
	return []ByHashAlgorithm{ByHashSHA512, ByHashSHA256, ByHashSHA1, ByHashMD5}
}

// Digest returns the hex digest of f for the algorithm, or "" when f has none.
func (a ByHashAlgorithm) Digest(f FileInfo) string {
	switch a {
	case ByHashSHA512:
		return f.SHA512
	case ByHashSHA256:
		return f.SHA256
	case ByHashSHA1:
		return f.SHA1
	case ByHashMD5:
		return f.MD5sum
	}

	return ""
}

// ByHashPath returns where the by-hash copy of an index lives: next to the
// index, under by-hash/<algorithm>/<digest>. indexPath is relative to a
// dists/<dist> directory ("main/binary-amd64/Packages.xz"), and so is the
// result ("main/binary-amd64/by-hash/SHA256/<digest>"). digest is lowercased.
func ByHashPath(indexPath string, alg ByHashAlgorithm, digest string) string {
	dir := path.Dir(indexPath)
	name := "by-hash/" + string(alg) + "/" + strings.ToLower(digest)

	if dir == "." {
		return name
	}

	return dir + "/" + name
}

// IsByHashPath reports whether p is a path inside a by-hash tree.
func IsByHashPath(p string) bool {
	return strings.HasPrefix(p, "by-hash/") || strings.Contains(p, "/by-hash/")
}

// ByHashRef is one way to fetch an index by its digest.
type ByHashRef struct {
	// Algorithm and Digest identify the file.
	Algorithm ByHashAlgorithm
	Digest    string
	// Path is the by-hash path, relative to dists/<dist>.
	Path string
}

// ByHashRefs lists the by-hash paths of a file the Release lists, strongest
// digest first. A Release lists the digests of an index in its checksum
// sections; one without any digest of the file yields nothing.
func (r *Release) ByHashRefs(indexPath string) []ByHashRef {
	fi, ok := r.Files[indexPath]
	if !ok {
		return nil
	}

	var out []ByHashRef

	for _, alg := range ByHashAlgorithms() {
		if d := alg.Digest(fi); d != "" {
			out = append(out, ByHashRef{Algorithm: alg, Digest: d, Path: ByHashPath(indexPath, alg, d)})
		}
	}

	return out
}

// ByHashOptions configures WriteByHash.
type ByHashOptions struct {
	// Algorithms are the digests to lay the tree out by. Empty selects
	// SHA256 and SHA512, which is what apt-ftparchive does: MD5 and SHA1 are
	// obsolete and clients prefer the stronger ones.
	Algorithms []ByHashAlgorithm
	// Copy copies files instead of hard-linking them into the tree. A hard link
	// costs no disk space; WriteByHash falls back to a copy when the file
	// system refuses one.
	Copy bool
}

// ErrByHashMismatch is returned by WriteByHash for an index whose content does
// not match the digest the Release lists for it: publishing it would put a
// file under a hash it does not have.
var ErrByHashMismatch = errors.New("deb: by-hash file does not match its listed digest")

// WriteByHash lays out the by-hash tree for the indexes of a Release stored in
// distDir (the dists/<dist> directory): for every file the Release lists, it
// makes the file available as by-hash/<algorithm>/<digest> next to itself, for
// each algorithm. Existing by-hash files are left alone (their name is their
// content), so repeated runs and runs for several Releases accumulate the
// tree that clients fetching an older Release still need; see PruneByHash.
//
// Files the Release lists but that are not in distDir are skipped (a Release
// lists the uncompressed index of a repository that only keeps the compressed
// ones), as are by-hash entries themselves. A file whose size or digest is not
// the listed one fails with ErrByHashMismatch before anything is published for
// it. It returns the by-hash paths now present for the Release, relative to
// distDir. Set Release.AcquireByHash when publishing the Release itself.
func WriteByHash(distDir string, rel *Release, opts ByHashOptions) ([]string, error) {
	algs := opts.Algorithms
	if len(algs) == 0 {
		algs = []ByHashAlgorithm{ByHashSHA256, ByHashSHA512}
	}

	paths := make([]string, 0, len(rel.Files))
	for p := range rel.Files {
		paths = append(paths, p)
	}

	sort.Strings(paths)

	var out []string

	for _, p := range paths {
		if IsByHashPath(p) {
			continue
		}

		src := filepath.Join(distDir, filepath.FromSlash(p))

		if _, err := os.Stat(src); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}

			return out, fmt.Errorf("deb: by-hash %s: %w", p, err)
		}

		fi, err := hashFile(p, src)
		if err != nil {
			return out, err
		}

		listed := rel.Files[p]
		if fi.Size != listed.Size {
			return out, fmt.Errorf("%w: %s is %d bytes, the Release lists %d", ErrByHashMismatch, p, fi.Size, listed.Size)
		}

		for _, alg := range algs {
			want := strings.ToLower(alg.Digest(listed))
			if want == "" {
				continue
			}

			if !strings.EqualFold(alg.Digest(fi), want) {
				return out, fmt.Errorf("%w: %s %s", ErrByHashMismatch, alg, p)
			}

			dest := ByHashPath(p, alg, want)

			if err := placeByHash(src, filepath.Join(distDir, filepath.FromSlash(dest)), opts.Copy); err != nil {
				return out, err
			}

			out = append(out, dest)
		}
	}

	return out, nil
}

// hashFile computes the FileInfo of a file.
func hashFile(rel, name string) (FileInfo, error) {
	f, err := os.Open(name)
	if err != nil {
		return FileInfo{}, fmt.Errorf("deb: %w", err)
	}

	defer func() { _ = f.Close() }()

	return HashReader(rel, f)
}

// placeByHash makes src appear as dest unless dest exists.
func placeByHash(src, dest string, copyFile bool) error {
	if _, err := os.Lstat(dest); err == nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil { //nolint:gosec // a repository is world readable
		return fmt.Errorf("deb: by-hash: %w", err)
	}

	if !copyFile {
		if err := os.Link(src, dest); err == nil || errors.Is(err, fs.ErrExist) {
			return nil
		}
	}

	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("deb: by-hash: %w", err)
	}

	defer func() { _ = in.Close() }()

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".by-hash-*")
	if err != nil {
		return fmt.Errorf("deb: by-hash: %w", err)
	}

	_, err = io.Copy(tmp, in)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}

	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644) //nolint:gosec // a repository is world readable
	}

	if err == nil {
		err = os.Rename(tmp.Name(), dest)
	}

	if err != nil {
		_ = os.Remove(tmp.Name())

		return fmt.Errorf("deb: by-hash: %w", err)
	}

	return nil
}

// ByHashRetention is the policy of PruneByHash for files no current Release
// lists any more. A client that started from an older Release may still be
// downloading them, so they are kept for a while.
type ByHashRetention struct {
	// MaxAge is how long a by-hash file that the current Release does not list
	// stays after it was published (its modification time). Zero removes them
	// at once, subject to Keep.
	MaxAge time.Duration
	// Keep is the number of newest unlisted files kept in each by-hash
	// directory (that is, for each index and algorithm) regardless of their
	// age, so that the previous generation of an index always survives.
	Keep int
	// Now is the reference of MaxAge; the zero value is time.Now().
	Now time.Time
}

// PruneByHash removes the by-hash files under distDir that the current Release
// does not list and that the retention policy does not keep. current must be
// the Release being published; a file it lists is never removed. It returns
// the removed paths, relative to distDir. Empty by-hash directories are
// removed as well.
func PruneByHash(distDir string, current *Release, pol ByHashRetention) ([]string, error) {
	now := pol.Now
	if now.IsZero() {
		now = time.Now()
	}

	listed := make(map[string]bool)

	for p := range current.Files {
		for _, ref := range current.ByHashRefs(p) {
			listed[ref.Path] = true
		}
	}

	type stale struct {
		rel     string
		modTime time.Time
	}

	byDir := make(map[string][]stale)

	err := filepath.WalkDir(distDir, func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		rel, err := filepath.Rel(distDir, name)
		if err != nil {
			return fmt.Errorf("deb: by-hash: %w", err)
		}

		rel = filepath.ToSlash(rel)
		if !IsByHashPath(rel) || listed[rel] {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("deb: by-hash: %w", err)
		}

		dir := path.Dir(rel)
		byDir[dir] = append(byDir[dir], stale{rel: rel, modTime: info.ModTime()})

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("deb: by-hash: %w", err)
	}

	var removed []string

	for dir, files := range byDir {
		sort.Slice(files, func(i, j int) bool {
			if !files[i].modTime.Equal(files[j].modTime) {
				return files[i].modTime.After(files[j].modTime)
			}

			return files[i].rel < files[j].rel
		})

		for i, f := range files {
			if i < pol.Keep || now.Sub(f.modTime) < pol.MaxAge {
				continue
			}

			if err := os.Remove(filepath.Join(distDir, filepath.FromSlash(f.rel))); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return removed, fmt.Errorf("deb: by-hash: %w", err)
			}

			removed = append(removed, f.rel)
		}

		// Drop a directory this emptied; failure means it is not empty.
		_ = os.Remove(filepath.Join(distDir, filepath.FromSlash(dir)))
	}

	sort.Strings(removed)

	return removed, nil
}
