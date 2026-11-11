package deb

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1" //nolint:gosec // SHA1 is a field of the legacy pdiff Index format, not a security control
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"
)

// Defaults of PDiffBuilderOptions.
const (
	// DefaultPDiffMaxPatches is how many patches dak keeps in a series.
	DefaultPDiffMaxPatches = 56
	// pdiffOlderKept is how many merged series (current one included) keep
	// their patch files, for clients that hold an older Index.
	pdiffOlderKept = 3
	// pdiffNameLayout is the patch name scheme: UTC date, then hour and minute,
	// a dot and the second, as dak names them: 2024-05-01-1234.56.
	pdiffNameLayout = "2006-01-02-1504.05"
)

// PDiffBuilderOptions configures a PDiffIndexBuilder. The zero value maintains
// the Packages.diff of a "Packages" file with unmerged patches, SHA-256 only,
// 56 patches deep.
type PDiffBuilderOptions struct {
	// IndexName is the file the patches lead to, relative to the PDiffFS root:
	// "Packages", "Sources", "Contents-amd64", "Translation-en". The patches
	// live in the directory IndexName+".diff". Default "Packages".
	IndexName string
	// MaxPatches bounds the history; older patches are pruned and their files
	// removed. DefaultPDiffMaxPatches when zero.
	MaxPatches int
	// Merge publishes merged patches (X-Patch-Precedence: merged): every patch
	// of the history leads to the current file in one step, so a client fetches
	// one file however far behind it is. The cost is that all patches are
	// rewritten on each update. The one-step patches are kept in the
	// X-Unmerged-* lists, and the merged files of the two previous updates are
	// kept for clients that read an older Index.
	Merge bool
	// SHA1 also lists the legacy SHA1 digests, as dak does. Digests of
	// entries that were published without them stay missing.
	SHA1 bool
	// XZ also publishes each patch as <name>.xz next to the gzip file and lists
	// it in the Download section. apt reads gzip patches only; the xz files are
	// for other clients.
	XZ bool
	// Generate limits the patch generator.
	Generate PDiffGenerateOptions
	// Apply limits the merging and the verification of existing patches.
	Apply PDiffApplyOptions
}

// PDiffUpdate is the outcome of PDiffIndexBuilder.Update.
type PDiffUpdate struct {
	// Changed reports that a patch was added to the history. It is false when
	// the new file is the file already published or when no patch could be made.
	Changed bool
	// Reset reports that the existing history was discarded: the file the
	// builder diffed from was not the one the old Index describes, the old
	// patches were unreadable, or no patch could be made.
	Reset bool
	// Skipped is why no patch was made for a change (ErrPDiffUnrepresentable or
	// ErrPDiffLimit); the history is then discarded and clients fetch the whole
	// file. It is nil otherwise.
	Skipped error
	// Patch is the one-step patch added, nil unless Changed.
	Patch *PDiffPatch
	// Index is the Index now published; nil when the directory holds no patches.
	Index *PDiffIndex
	// IndexData is the content written to Packages.diff/Index, for the hashes
	// of the Release; nil with Index.
	IndexData []byte
	// Written and Removed list the files (relative to the PDiffFS root) the
	// update created or replaced and deleted.
	Written, Removed []string
}

// PDiffIndexBuilder maintains the Packages.diff directory of one index file of
// a repository, as dak's generate-index-diffs does: on each publication it
// diffs the file being replaced against the new one, adds the patch to the
// history, prunes it, rewrites the Index and removes the patch files that fell
// out of it.
//
// Call Update before the new index files replace the old ones, since it reads
// the old one from the same PDiffFS; or call UpdateFrom with the old content.
// A builder is not safe for concurrent use, and neither is two builders on one
// directory.
type PDiffIndexBuilder struct {
	fsys PDiffFS
	opts PDiffBuilderOptions
	dir  string

	// unmerged is the series of one-step patches, oldest first; main is what the
	// Index lists as its History (the same series, or the merged one). Both are
	// nil when there is no history.
	unmerged, main []PDiffPatch
	merged         bool
	older          []string
	current        PDiffHash
}

// NewPDiffIndexBuilder returns the builder of the directory in fsys, picking
// up the history of the Index published there. A missing or unparsable Index
// starts an empty history: the first Update then rebuilds the directory, and
// clients that are behind fetch the whole file once.
func NewPDiffIndexBuilder(fsys PDiffFS, opts PDiffBuilderOptions) (*PDiffIndexBuilder, error) {
	if opts.IndexName == "" {
		opts.IndexName = "Packages"
	}

	if opts.MaxPatches <= 0 {
		opts.MaxPatches = DefaultPDiffMaxPatches
	}

	if !fs.ValidPath(opts.IndexName) || opts.IndexName == "." || strings.Contains(opts.IndexName, "/") {
		return nil, fmt.Errorf("deb: invalid pdiff index name %q", opts.IndexName)
	}

	b := &PDiffIndexBuilder{fsys: fsys, opts: opts, dir: opts.IndexName + ".diff"}

	data, err := fsys.ReadFile(b.dir + "/Index")

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return b, nil
	case err != nil:
		return nil, fmt.Errorf("deb: reading pdiff index: %w", err)
	}

	if idx, err := ParsePDiffIndex(data); err == nil {
		b.adopt(idx)
	}

	return b, nil
}

// adopt takes the history of a parsed Index.
func (b *PDiffIndexBuilder) adopt(idx *PDiffIndex) {
	b.current = idx.Current
	b.merged = idx.Merged
	b.main = idx.Patches
	b.unmerged = idx.Patches

	if idx.Merged {
		b.unmerged = idx.Unmerged
		b.older = idx.OlderPatches
	}
}

// Index returns the Index the builder currently describes, nil when there is
// no history.
func (b *PDiffIndexBuilder) Index() *PDiffIndex {
	if len(b.main) == 0 {
		return nil
	}

	idx := &PDiffIndex{Current: b.current, Patches: slices.Clone(b.main), Merged: b.merged}
	if b.merged {
		idx.Unmerged = slices.Clone(b.unmerged)
		idx.OlderPatches = slices.Clone(b.older)
	}

	return idx
}

// Update adds the change from the index file now in the PDiffFS to
// newPackages (the uncompressed content of the file that is about to replace
// it) to the history. The old file is read as IndexName or with a .gz, .xz,
// .zst, .bz2 or .lz4 suffix. now names the patch (see UpdateFrom).
//
// When there is no old file, nothing can be diffed: Update only discards a
// history that does not lead to newPackages.
func (b *PDiffIndexBuilder) Update(newPackages []byte, now time.Time) (*PDiffUpdate, error) {
	old, found, err := b.readOld()
	if err != nil {
		return nil, err
	}

	if !found {
		return b.settle(newPackages)
	}

	return b.UpdateFrom(old, newPackages, now)
}

// readOld reads the file the Index leads to, decompressing it.
func (b *PDiffIndexBuilder) readOld() ([]byte, bool, error) {
	for _, ext := range []string{"", ".xz", ".gz", ".zst", ".bz2", ".lz4"} {
		name := b.opts.IndexName + ext

		data, err := b.fsys.ReadFile(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}

		if err != nil {
			return nil, false, fmt.Errorf("deb: reading %s: %w", name, err)
		}

		if ext == "" {
			return data, true, nil
		}

		r, err := OpenIndex(bytes.NewReader(data), name)
		if err != nil {
			return nil, false, err
		}

		out, err := readAllIndex(r)
		if err != nil {
			return nil, false, fmt.Errorf("deb: reading %s: %w", name, err)
		}

		return out, true, nil
	}

	return nil, false, nil
}

func readAllIndex(r interface {
	Read([]byte) (int, error)
	Close() error
},
) ([]byte, error) {
	defer r.Close()

	var buf bytes.Buffer

	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// settle handles an update without an old file: the history stays only when it
// already leads to the new content.
func (b *PDiffIndexBuilder) settle(newPackages []byte) (*PDiffUpdate, error) {
	if len(b.main) > 0 && b.current.SHA256 == PDiffSHA256(newPackages) {
		idx := b.Index()

		return &PDiffUpdate{Index: idx, IndexData: idx.Marshal()}, nil
	}

	res := &PDiffUpdate{Reset: len(b.main) > 0}

	if err := b.clear(res); err != nil {
		return nil, err
	}

	return res, nil
}

// UpdateFrom is Update with the content of the old file given. now names the
// new patch, "2006-01-02-1504.05" in UTC (2024-05-01-1234.56); where that name
// is taken by an earlier patch, the next free second is used.
//
// Nothing is written when the two files are the same. A history that does not
// end at oldPackages, or whose patch files cannot be read back and verified,
// is discarded and started over with the new patch. A change a patch cannot
// express, or one over the generator's limits, discards the history and
// publishes no patch (PDiffUpdate.Skipped), which is always safe: clients that
// find no patch fetch the whole file.
func (b *PDiffIndexBuilder) UpdateFrom(oldPackages, newPackages []byte, now time.Time) (*PDiffUpdate, error) {
	oldSum, newSum := PDiffSHA256(oldPackages), PDiffSHA256(newPackages)

	if oldSum == newSum {
		return b.settle(newPackages)
	}

	res := &PDiffUpdate{}

	scripts, ok := b.loadHistory(oldSum)
	if !ok {
		res.Reset = len(b.main) > 0 || len(b.unmerged) > 0
		b.unmerged, b.main, b.older, b.merged = nil, nil, nil, false
		scripts = nil
	}

	patch, err := GeneratePDiffWith(oldPackages, newPackages, b.opts.Generate)
	if err != nil {
		if errors.Is(err, ErrPDiffUnrepresentable) || errors.Is(err, ErrPDiffLimit) {
			res.Reset, res.Skipped = true, err

			if cerr := b.clear(res); cerr != nil {
				return nil, cerr
			}

			return res, nil
		}

		return nil, err
	}

	name := b.freshName(now)

	gz, err := gzipPDiff(patch)
	if err != nil {
		return nil, err
	}

	one := PDiffPatch{
		Name:     name,
		From:     b.hashOf(oldPackages),
		Patch:    b.hashOf(patch),
		Download: b.hashOf(gz),
	}

	b.current = b.hashOf(newPackages)
	b.unmerged = append(b.unmerged, one)
	scripts = append(scripts, patch)

	// Prune the one-step series; the merged one is derived from what is left.
	if extra := len(b.unmerged) - b.opts.MaxPatches; extra > 0 {
		b.unmerged = b.unmerged[extra:]
		scripts = scripts[extra:]
	}

	files := map[string][]byte{name: gz}

	if err := b.arrange(scripts, name, files); err != nil {
		b.reload()

		return nil, err
	}

	if err := b.publish(files, res); err != nil {
		b.reload()

		return nil, err
	}

	res.Changed = true
	res.Patch = &one

	return res, nil
}

// arrange builds the Index's own list (History) out of the one-step series,
// and the extra files a merged list needs.
func (b *PDiffIndexBuilder) arrange(scripts [][]byte, target string, files map[string][]byte) error {
	b.merged = b.opts.Merge

	if !b.opts.Merge {
		b.main = slices.Clone(b.unmerged)
		b.older = nil

		return nil
	}

	// The merged patch of entry i is the patch i applied, then the merged patch
	// of entry i+1; the newest one is its own merged patch. Going from the
	// newest back gives every merged patch in one merge each.
	n := len(b.unmerged)
	b.main = make([]PDiffPatch, n)
	next := scripts[n-1]

	for i := n - 1; i >= 0; i-- {
		script := next
		if i < n-1 {
			var err error

			if script, err = MergePDiffsWith(b.opts.Apply, scripts[i], next); err != nil {
				return fmt.Errorf("deb: merging pdiff %s: %w", b.unmerged[i].Name, err)
			}
		}

		gz, err := gzipPDiff(script)
		if err != nil {
			return err
		}

		name := "T-" + target + "-F-" + b.unmerged[i].Name
		files[name] = gz
		b.main[i] = PDiffPatch{
			Name:     name,
			From:     b.unmerged[i].From,
			Patch:    b.hashOf(script),
			Download: b.hashOf(gz),
		}
		next = script
	}

	b.older = append(slices.DeleteFunc(slices.Clone(b.older), func(s string) bool { return s == target }), target)
	if extra := len(b.older) - pdiffOlderKept; extra > 0 {
		b.older = b.older[extra:]
	}

	return nil
}

// reload drops the in-memory history for what the Index in the directory says,
// after an update failed half way.
func (b *PDiffIndexBuilder) reload() {
	b.unmerged, b.main, b.older, b.merged = nil, nil, nil, false
	b.current = PDiffHash{}

	data, err := b.fsys.ReadFile(b.dir + "/Index")
	if err != nil {
		return
	}

	if idx, err := ParsePDiffIndex(data); err == nil {
		b.adopt(idx)
	}
}

// loadHistory reads back the scripts of the one-step series and verifies them
// against the Index. It reports false, and the series is to be discarded,
// when there is no history ending at the file with digest oldSum or when a
// patch is missing or damaged.
func (b *PDiffIndexBuilder) loadHistory(oldSum string) ([][]byte, bool) {
	if len(b.unmerged) == 0 || b.current.SHA256 != oldSum {
		return nil, false
	}

	opts := b.opts.Apply.withDefaults()
	scripts := make([][]byte, len(b.unmerged))

	for i, p := range b.unmerged {
		gz, err := b.fsys.ReadFile(b.dir + "/" + p.DownloadName())
		if err != nil || checkPDiffHash(p.Name, "download", gz, p.Download) != nil {
			return nil, false
		}

		script, err := gunzipPDiff(gz, opts.MaxPatchSize)
		if err != nil || checkPDiffHash(p.Name, "patch", script, p.Patch) != nil {
			return nil, false
		}

		scripts[i] = script
	}

	return scripts, true
}

// freshName returns the patch name for now, moved forward to a second no patch
// of the series has.
func (b *PDiffIndexBuilder) freshName(now time.Time) string {
	now = now.UTC().Truncate(time.Second)

	for {
		name := now.Format(pdiffNameLayout)

		if !slices.ContainsFunc(b.unmerged, func(p PDiffPatch) bool { return p.Name == name }) {
			return name
		}

		now = now.Add(time.Second)
	}
}

// hashOf computes the digests an Index lists for data; SHA1 only when asked.
func (b *PDiffIndexBuilder) hashOf(data []byte) PDiffHash {
	h := PDiffHash{Size: int64(len(data)), SHA256: PDiffSHA256(data)}

	if b.opts.SHA1 {
		sum := sha1.Sum(data) //nolint:gosec // see above
		h.SHA1 = hex.EncodeToString(sum[:])
	}

	return h
}

// publish writes the patch files, then the Index, then removes the files the
// Index no longer needs, so a client reading at any moment finds an Index
// whose patches exist.
func (b *PDiffIndexBuilder) publish(files map[string][]byte, res *PDiffUpdate) error {
	var xzFiles map[string][]byte

	if b.opts.XZ {
		xzFiles = map[string][]byte{}

		for name, gz := range files {
			xzData, err := xzPDiff(gz, b.opts.Apply.withDefaults().MaxPatchSize)
			if err != nil {
				return err
			}

			xzFiles[name] = xzData
		}

		b.attachXZ(xzFiles)
	}

	// Write in a stable order so a failure leaves a reproducible state.
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}

	slices.Sort(names)

	for _, n := range names {
		if err := b.write(res, n+".gz", files[n]); err != nil {
			return err
		}

		if b.opts.XZ {
			if err := b.write(res, n+".xz", xzFiles[n]); err != nil {
				return err
			}
		}
	}

	idx := b.Index()
	res.Index = idx
	res.IndexData = idx.Marshal()

	if err := b.write(res, "Index", res.IndexData); err != nil {
		return err
	}

	return b.prune(res)
}

// attachXZ records the xz downloads on the entries of both lists.
func (b *PDiffIndexBuilder) attachXZ(xzFiles map[string][]byte) {
	for _, list := range [][]PDiffPatch{b.unmerged, b.main} {
		for i := range list {
			if data, ok := xzFiles[list[i].Name]; ok {
				list[i].DownloadXZ = b.hashOf(data)
			}
		}
	}
}

func (b *PDiffIndexBuilder) write(res *PDiffUpdate, name string, data []byte) error {
	full := b.dir + "/" + name
	if err := b.fsys.WriteFile(full, data); err != nil {
		return fmt.Errorf("deb: writing %s: %w", full, err)
	}

	res.Written = append(res.Written, full)

	return nil
}

// prune removes the files of the directory the Index does not list: patches
// that left the history, the xz and gzip files of both, and leftovers of
// earlier failures. Merged patch files of the last series stay.
func (b *PDiffIndexBuilder) prune(res *PDiffUpdate) error {
	keep := map[string]bool{"Index": true}

	for _, list := range [][]PDiffPatch{b.main, b.unmerged} {
		for _, p := range list {
			keep[p.Name+".gz"], keep[p.Name+".xz"] = true, true
		}
	}

	var prefixes []string

	for _, t := range b.older {
		prefixes = append(prefixes, "T-"+t+"-F-")
	}

	names, err := b.fsys.ReadDir(b.dir)
	if err != nil {
		return fmt.Errorf("deb: listing %s: %w", b.dir, err)
	}

	for _, n := range names {
		if keep[n] || slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(n, p) }) {
			continue
		}

		if err := b.fsys.Remove(b.dir + "/" + n); err != nil {
			return fmt.Errorf("deb: removing %s: %w", n, err)
		}

		res.Removed = append(res.Removed, b.dir+"/"+n)
	}

	return nil
}

// clear discards the history and removes the whole Packages.diff directory
// content.
func (b *PDiffIndexBuilder) clear(res *PDiffUpdate) error {
	b.unmerged, b.main, b.older, b.merged = nil, nil, nil, false
	b.current = PDiffHash{}

	names, err := b.fsys.ReadDir(b.dir)
	if err != nil {
		return fmt.Errorf("deb: listing %s: %w", b.dir, err)
	}

	// The Index goes first, so that nobody finds one that names missing patches.
	slices.SortFunc(names, func(x, y string) int {
		switch {
		case x == "Index" && y != "Index":
			return -1
		case y == "Index" && x != "Index":
			return 1
		}

		return strings.Compare(x, y)
	})

	for _, n := range names {
		if err := b.fsys.Remove(b.dir + "/" + n); err != nil {
			return fmt.Errorf("deb: removing %s: %w", n, err)
		}

		res.Removed = append(res.Removed, b.dir+"/"+n)
	}

	return nil
}

// gzipPDiff compresses a patch the way dak does: best compression, no name and
// no time in the header, so equal patches give equal files.
func gzipPDiff(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("deb: gzip: %w", err)
	}

	if _, err := zw.Write(data); err != nil {
		return nil, fmt.Errorf("deb: gzip: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("deb: gzip: %w", err)
	}

	return buf.Bytes(), nil
}

// xzPDiff recompresses a gzip patch as xz.
func xzPDiff(gz []byte, limit int64) ([]byte, error) {
	script, err := gunzipPDiff(gz, limit)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	w, err := compressWriter(&buf, CompressionXZ)
	if err != nil {
		return nil, err
	}

	if _, err := w.Write(script); err != nil {
		return nil, fmt.Errorf("deb: xz: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("deb: xz: %w", err)
	}

	return buf.Bytes(), nil
}
