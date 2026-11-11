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

// hexLen is the length of a hex digest of the algorithm, 0 for an unknown one.
func (a ByHashAlgorithm) hexLen() int {
	switch a {
	case ByHashSHA512:
		return 128
	case ByHashSHA256:
		return 64
	case ByHashSHA1:
		return 40
	case ByHashMD5:
		return 32
	}

	return 0
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

// ByHashMode is how WriteByHash makes a file available under its digest.
type ByHashMode int

const (
	// ByHashCopy copies the file, atomically (a temporary file renamed into
	// place), keeping its modification time. This is the zero value and what
	// apt-ftparchive does: the copy is safe even when the index is later
	// rewritten in place.
	ByHashCopy ByHashMode = iota
	// ByHashHardlink hard-links the by-hash name to the index: no disk space,
	// and the name keeps the content it had as long as the index is replaced
	// by a new file (a new inode) rather than rewritten in place. It falls
	// back to a copy when the file system refuses a link.
	ByHashHardlink
	// ByHashSymlink writes a relative symbolic link to the index. The link
	// follows the index, not its content: when the index is replaced in place
	// the link serves the new content under the old digest. Use it only when
	// indexes are published once and not rewritten.
	ByHashSymlink
)

// ByHashOptions configures WriteByHash and WriteByHashFS.
type ByHashOptions struct {
	// Algorithms are the digests to lay the tree out by. Empty selects
	// SHA256 and SHA512: MD5 and SHA1 are obsolete and clients prefer the
	// stronger ones, which every Release written by this package lists.
	Algorithms []ByHashAlgorithm
	// Mode selects how the files are made available; the zero value is
	// ByHashCopy. WriteByHashFS can only copy and ignores it.
	Mode ByHashMode
	// FileMode is the permission of copied files; zero means 0644, a
	// repository is world readable.
	FileMode fs.FileMode
	// DirMode is the permission of the directories created; zero means 0755.
	DirMode fs.FileMode
}

func (o ByHashOptions) algorithms() []ByHashAlgorithm {
	if len(o.Algorithms) == 0 {
		return []ByHashAlgorithm{ByHashSHA256, ByHashSHA512}
	}

	return o.Algorithms
}

func (o ByHashOptions) fileMode() fs.FileMode {
	if o.FileMode == 0 {
		return 0o644
	}

	return o.FileMode.Perm()
}

func (o ByHashOptions) dirMode() fs.FileMode {
	if o.DirMode == 0 {
		return 0o755
	}

	return o.DirMode.Perm()
}

// ErrByHashMismatch is returned by WriteByHash for an index whose content does
// not match the digest the Release lists for it: publishing it would put a
// file under a hash it does not have.
var ErrByHashMismatch = errors.New("deb: by-hash file does not match its listed digest")

// WriteByHash lays out the by-hash tree for the indexes of a Release stored in
// distDir (the dists/<dist> directory): for every file the Release lists, it
// makes the file available as by-hash/<algorithm>/<digest> next to itself, for
// each algorithm, in the way opts.Mode says. Existing by-hash files of the
// right size are left alone (their name is their content), so repeated runs
// are no-ops and runs for several Releases accumulate the tree that clients
// fetching an older Release still need; see PruneByHash. A by-hash file of the
// wrong size (a torn write of an older tool) is replaced.
//
// Every file is published atomically: a client never sees a partial by-hash
// file. Directories are created with opts.DirMode (0755) and copies get
// opts.FileMode (0644). The tree is the one apt-ftparchive release writes with
// APT::FTPArchive::DoByHash=true (same paths, same SHA256 and SHA512 set,
// copies with mode 0644 in 0755 directories); set Release.AcquireByHash when
// publishing the Release itself, after the tree is laid out.
//
// Files the Release lists but that are not in distDir are skipped (a Release
// lists the uncompressed index of a repository that only keeps the compressed
// ones), as are by-hash entries themselves. A file whose size or digest is not
// the listed one fails with ErrByHashMismatch before anything is published for
// it. It returns the by-hash paths now present for the Release, sorted,
// relative to distDir.
func WriteByHash(distDir string, rel *Release, opts ByHashOptions) ([]string, error) {
	return writeByHash(os.DirFS(distDir), distDir, distDir, rel, opts)
}

// WriteByHashFS is WriteByHash for an index tree that is not a directory:
// src holds the dists/<dist> tree (an embedded or in-memory file system, an
// archive) and the by-hash files are written, as copies, under the directory
// dest. dest may be the directory the Release is published from.
func WriteByHashFS(src fs.FS, dest string, rel *Release, opts ByHashOptions) ([]string, error) {
	opts.Mode = ByHashCopy

	return writeByHash(src, "", dest, rel, opts)
}

// writeByHash does the work of both entry points; srcDir is the directory src
// is rooted at, "" when it is not one.
func writeByHash(src fs.FS, srcDir, dest string, rel *Release, opts ByHashOptions) ([]string, error) {
	paths := make([]string, 0, len(rel.Files))
	for p := range rel.Files {
		if !IsByHashPath(p) {
			paths = append(paths, p)
		}
	}

	sort.Strings(paths)

	var out []string

	for _, p := range paths {
		listed := rel.Files[p]

		info, err := fs.Stat(src, p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}

			return out, fmt.Errorf("deb: by-hash %s: %w", p, err)
		}

		if !info.Mode().IsRegular() {
			continue
		}

		if info.Size() != listed.Size {
			return out, fmt.Errorf("%w: %s is %d bytes, the Release lists %d", ErrByHashMismatch, p, info.Size(), listed.Size)
		}

		fi, err := hashFS(src, p)
		if err != nil {
			return out, err
		}

		for _, alg := range opts.algorithms() {
			want := strings.ToLower(alg.Digest(listed))
			if want == "" {
				continue
			}

			if !strings.EqualFold(alg.Digest(fi), want) {
				return out, fmt.Errorf("%w: %s %s", ErrByHashMismatch, alg, p)
			}

			byHash := ByHashPath(p, alg, want)

			err := placeByHash(src, srcDir, p, info, filepath.Join(dest, filepath.FromSlash(byHash)), opts)
			if err != nil {
				return out, err
			}

			out = append(out, byHash)
		}
	}

	sort.Strings(out)

	return out, nil
}

// hashFS computes the FileInfo of a file of a file system.
func hashFS(fsys fs.FS, name string) (FileInfo, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return FileInfo{}, fmt.Errorf("deb: by-hash: %w", err)
	}

	defer func() { _ = f.Close() }()

	return HashReader(name, f)
}

// placeByHash makes the file srcRel of src appear as dest, unless a file of
// its size is already there.
func placeByHash(src fs.FS, srcDir, srcRel string, info fs.FileInfo, dest string, opts ByHashOptions) error {
	if cur, err := os.Stat(dest); err == nil && cur.Mode().IsRegular() && cur.Size() == info.Size() {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dest), opts.dirMode()); err != nil {
		return fmt.Errorf("deb: by-hash: %w", err)
	}

	srcPath := ""
	if srcDir != "" {
		srcPath = filepath.Join(srcDir, filepath.FromSlash(srcRel))
	}

	switch {
	case opts.Mode == ByHashSymlink && srcPath != "":
		target, err := filepath.Rel(filepath.Dir(dest), srcPath)
		if err != nil {
			return fmt.Errorf("deb: by-hash: %w", err)
		}

		return publishTemp(dest, func(tmp string) error { return os.Symlink(target, tmp) })
	case opts.Mode == ByHashHardlink && srcPath != "":
		err := publishTemp(dest, func(tmp string) error { return os.Link(srcPath, tmp) })
		if err == nil {
			return nil
		}
		// A file system without hard links, or another device: copy.
	}

	return copyByHash(src, srcRel, info, dest, opts.fileMode())
}

// publishTemp creates the file dest atomically: create writes it under a
// fresh temporary name next to dest, which is then renamed over dest.
func publishTemp(dest string, create func(tmp string) error) error {
	dir := filepath.Dir(dest)

	for range 8 {
		tmp := filepath.Join(dir, fmt.Sprintf(".by-hash-%d-%d", os.Getpid(), time.Now().UnixNano()))

		err := create(tmp)
		if errors.Is(err, fs.ErrExist) {
			continue
		}

		if err != nil {
			return fmt.Errorf("deb: by-hash: %w", err)
		}

		if err := os.Rename(tmp, dest); err != nil {
			_ = os.Remove(tmp)

			return fmt.Errorf("deb: by-hash: %w", err)
		}

		return nil
	}

	return fmt.Errorf("deb: by-hash: no free temporary name in %s", dir)
}

// copyByHash copies a file of src to dest atomically, keeping its
// modification time.
func copyByHash(src fs.FS, srcRel string, info fs.FileInfo, dest string, mode fs.FileMode) error {
	in, err := src.Open(srcRel)
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
		err = os.Chmod(tmp.Name(), mode)
	}

	if err == nil {
		err = os.Chtimes(tmp.Name(), info.ModTime(), info.ModTime())
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

// ByHashRetention is the policy of PruneByHash for the by-hash files the
// current Release no longer lists. A client that fetched an older Release may
// still be downloading them, so they stay for a while.
//
// The files of a by-hash directory (one per index directory and algorithm)
// are grouped into generations by their modification time: the files of one
// publication share one (a hard link or a copy keeps the time of the index it
// was made from), and files whose times lie within GenerationGap of each other
// are one generation. Generation 1 is the newest the Release does not list.
// A generation is superseded when the next one appeared: the modification
// time of the newest file of that next generation, or, for generation 1, of
// the files the current Release lists in the same directory.
type ByHashRetention struct {
	// KeepGenerations is the number of unlisted generations kept in each
	// directory regardless of their age. Zero keeps none (subject to MaxAge).
	KeepGenerations int
	// MaxAge keeps a generation for that long after it was superseded. Zero
	// removes it at once (subject to KeepGenerations).
	MaxAge time.Duration
	// GenerationGap separates generations: files whose modification times are
	// further apart belong to different ones. Zero means one minute.
	GenerationGap time.Duration
	// Now is the reference of MaxAge; the zero value is time.Now().
	Now time.Time
}

func (p ByHashRetention) gap() time.Duration {
	if p.GenerationGap <= 0 {
		return time.Minute
	}

	return p.GenerationGap
}

// ByHashFile is one by-hash file the prune plan decides on.
type ByHashFile struct {
	// Path is relative to the dists/<dist> directory.
	Path string
	// ModTime is the modification time of the file.
	ModTime time.Time
	// Generation is 1 for the newest generation the current Release does not
	// list, 2 for the one before, and so on; 0 for a leftover temporary file.
	Generation int
	// Reason says why the file is kept or removed.
	Reason string
}

// ByHashPlan is what PruneByHash would do: the files it keeps although the
// current Release does not list them and the files it removes.
type ByHashPlan struct {
	// Keep lists the unlisted files the retention policy keeps, sorted by path.
	Keep []ByHashFile
	// Remove lists the files to remove, sorted by path.
	Remove []ByHashFile
}

// Paths returns the paths to remove.
func (p *ByHashPlan) Paths() []string {
	out := make([]string, len(p.Remove))
	for i, f := range p.Remove {
		out[i] = f.Path
	}

	return out
}

// staleTempAge is how old a leftover temporary file of an interrupted
// WriteByHash must be before the plan removes it.
const staleTempAge = time.Hour

// PlanByHashPrune decides what PruneByHash would do, without touching
// anything. current must be the Release being published; a file it lists is
// never in the plan. Files in a by-hash directory that do not look like a
// digest of their algorithm are left alone, except leftover temporary files of
// an interrupted write older than an hour.
func PlanByHashPrune(distDir string, current *Release, pol ByHashRetention) (*ByHashPlan, error) {
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

	type member struct {
		rel     string
		modTime time.Time
	}

	plan := &ByHashPlan{}
	stale := make(map[string][]member)       // by-hash/<alg> directory -> unlisted files
	currentMod := make(map[string]time.Time) // by-hash/<alg> directory -> newest listed file

	err := filepath.WalkDir(distDir, func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		rel, err := filepath.Rel(distDir, name)
		if err != nil {
			return fmt.Errorf("deb: by-hash: %w", err)
		}

		rel = filepath.ToSlash(rel)
		if !IsByHashPath(rel) {
			return nil
		}

		dir, base := path.Split(rel)
		dir = strings.TrimSuffix(dir, "/")

		alg := ByHashAlgorithm(path.Base(dir))
		if path.Base(path.Dir(dir)) != "by-hash" || alg.hexLen() == 0 {
			return nil // not the layout of a by-hash tree: not ours
		}

		info, err := os.Lstat(name)
		if err != nil {
			return fmt.Errorf("deb: by-hash: %w", err)
		}

		if info.Mode()&fs.ModeSymlink == 0 {
			if info, err = os.Stat(name); err != nil {
				return fmt.Errorf("deb: by-hash: %w", err)
			}
		}

		switch {
		case strings.HasPrefix(base, ".by-hash-"):
			if now.Sub(info.ModTime()) >= staleTempAge {
				plan.Remove = append(plan.Remove, ByHashFile{Path: rel, ModTime: info.ModTime(), Reason: "leftover of an interrupted write"})
			}
		case !isHexOfLen(base, alg.hexLen()):
			// Not a digest: leave it.
		case listed[rel]:
			if info.ModTime().After(currentMod[dir]) {
				currentMod[dir] = info.ModTime()
			}
		default:
			stale[dir] = append(stale[dir], member{rel: rel, modTime: info.ModTime()})
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("deb: by-hash: %w", err)
	}

	for dir, files := range stale {
		sort.Slice(files, func(i, j int) bool {
			if !files[i].modTime.Equal(files[j].modTime) {
				return files[i].modTime.After(files[j].modTime)
			}

			return files[i].rel < files[j].rel
		})

		gen, superseded := 1, currentMod[dir]
		newest := files[0].modTime

		if superseded.IsZero() {
			superseded = newest // nothing current here: the newest file is the last of its kind
		}

		prev := files[0].modTime

		for _, f := range files {
			if prev.Sub(f.modTime) > pol.gap() {
				gen++
				superseded, newest = newest, f.modTime
			}

			prev = f.modTime

			file := ByHashFile{Path: f.rel, ModTime: f.modTime, Generation: gen}

			switch {
			case gen <= pol.KeepGenerations:
				file.Reason = fmt.Sprintf("generation %d is within the %d kept", gen, pol.KeepGenerations)
				plan.Keep = append(plan.Keep, file)
			case now.Sub(superseded) < pol.MaxAge:
				file.Reason = fmt.Sprintf("superseded %s ago, younger than %s", now.Sub(superseded).Round(time.Second), pol.MaxAge)
				plan.Keep = append(plan.Keep, file)
			default:
				file.Reason = fmt.Sprintf("generation %d, superseded %s ago", gen, now.Sub(superseded).Round(time.Second))
				plan.Remove = append(plan.Remove, file)
			}
		}
	}

	byPath := func(s []ByHashFile) {
		sort.Slice(s, func(i, j int) bool { return s[i].Path < s[j].Path })
	}

	byPath(plan.Keep)
	byPath(plan.Remove)

	return plan, nil
}

func isHexOfLen(s string, n int) bool {
	if len(s) != n {
		return false
	}

	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}

	return true
}

// Apply removes the files of the plan under distDir, then the by-hash
// directories that this leaves empty. It returns the removed paths. A file
// that is already gone is not an error.
func (p *ByHashPlan) Apply(distDir string) ([]string, error) {
	var removed []string

	dirs := make(map[string]bool)

	for _, f := range p.Remove {
		if err := os.Remove(filepath.Join(distDir, filepath.FromSlash(f.Path))); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return removed, fmt.Errorf("deb: by-hash: %w", err)
		}

		removed = append(removed, f.Path)
		dirs[path.Dir(f.Path)] = true
	}

	for dir := range dirs {
		// Drop the directories this emptied; failure means one is not empty.
		for _, d := range []string{dir, path.Dir(dir)} {
			if os.Remove(filepath.Join(distDir, filepath.FromSlash(d))) != nil {
				break
			}
		}
	}

	return removed, nil
}

// PruneByHash removes the by-hash files under distDir that the current Release
// does not list and that the retention policy does not keep, see
// PlanByHashPrune for the decision and ByHashRetention for the policy. current
// must be the Release being published. It returns the removed paths, relative
// to distDir, sorted.
func PruneByHash(distDir string, current *Release, pol ByHashRetention) ([]string, error) {
	plan, err := PlanByHashPrune(distDir, current, pol)
	if err != nil {
		return nil, err
	}

	return plan.Apply(distDir)
}
