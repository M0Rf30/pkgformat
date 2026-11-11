package source

import (
	"crypto/md5"  //nolint:gosec // the Files field of a .dsc is an MD5 list
	"crypto/sha1" //nolint:gosec // the Checksums-Sha1 field
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/M0Rf30/pkgformat/safepath"
)

// UnpackOptions tunes [Unpack]. The zero value is valid.
type UnpackOptions struct {
	// Replace allows the target directory to exist and not be empty; it is
	// then removed first, as dpkg-source -x does by default. Without it a
	// target that exists must be an empty directory.
	Replace bool
	// SkipPatches leaves the quilt patches of a "3.0 (quilt)" package
	// unapplied and writes no .pc directory (dpkg-source --skip-patches).
	SkipPatches bool
	// SkipDebianization extracts only the orig tarballs and skips the debian
	// tarball or the .diff.gz (dpkg-source --skip-debianization).
	SkipDebianization bool
	// MaxEntries bounds the archive entries extracted; default
	// [DefaultMaxEntries].
	MaxEntries int
	// MaxBytes bounds the file bytes extracted; default [DefaultMaxBytes].
	MaxBytes int64
}

const tarExt = `(?:gz|bz2|xz|zst)`

// layout is the role of every file of a source package.
type layout struct {
	// tar is the orig tarball, or the one tarball of a native package.
	tar     string
	tarSig  string
	addons  map[string]string // component name -> orig-COMP tarball
	addSigs map[string]string
	debian  string // debian.tar.EXT (3.0 quilt)
	diff    string // diff.gz (1.0)
	native  bool
}

// versionParts returns the upstream version and the full version, both without
// epoch.
func versionParts(version string) (upstream, full string) {
	full = version
	if i := strings.IndexByte(full, ':'); i >= 0 {
		full = full[i+1:]
	}

	upstream = full
	if i := strings.LastIndexByte(full, '-'); i >= 0 {
		upstream = full[:i]
	}

	return upstream, full
}

func classify(d *DSC) (*layout, error) {
	up, full := versionParts(d.Version)
	base := regexp.QuoteMeta(d.Source + "_" + up)
	baseRev := regexp.QuoteMeta(d.Source + "_" + full)

	l := &layout{addons: map[string]string{}, addSigs: map[string]string{}}

	switch d.Format {
	case Format10:
		return l, l.classify10(d, base, baseRev)
	case FormatQuilt:
		return l, l.classifyQuilt(d, base, baseRev)
	case FormatNative:
		return l, l.classifyNative(d, baseRev)
	}

	return nil, fmt.Errorf("%w: %q", ErrUnsupportedFormat, string(d.Format))
}

func unexpected(f Format, name string) error {
	return fmt.Errorf("%w: %q in a %s source package", ErrUnexpectedFile, name, string(f))
}

func (l *layout) classify10(d *DSC, base, baseRev string) error {
	tarRE := regexp.MustCompile(`^(?:` + base + `\.orig|` + baseRev + `)\.tar\.gz$`)
	sigRE := regexp.MustCompile(`^` + base + `\.orig\.tar\.gz\.asc$`)
	diffRE := regexp.MustCompile(`^` + baseRev + `\.diff\.gz$`)

	for _, f := range d.Files {
		switch {
		case tarRE.MatchString(f.Name):
			if l.tar != "" {
				return fmt.Errorf("%w: several tarballs in a 1.0 source package", ErrUnexpectedFile)
			}

			l.tar = f.Name
		case sigRE.MatchString(f.Name):
			l.tarSig = f.Name
		case diffRE.MatchString(f.Name):
			l.diff = f.Name
		default:
			return unexpected(d.Format, f.Name)
		}
	}

	if l.tar == "" {
		return fmt.Errorf("%w: no tarball", ErrMissingFile)
	}

	l.native = l.diff == "" && !strings.Contains(l.tar, ".orig.tar.")

	return nil
}

func (l *layout) classifyQuilt(d *DSC, base, baseRev string) error {
	origRE := regexp.MustCompile(`^` + base + `\.orig\.tar\.` + tarExt + `$`)
	origSigRE := regexp.MustCompile(`^` + base + `\.orig\.tar\.` + tarExt + `\.asc$`)
	addRE := regexp.MustCompile(`^` + base + `\.orig-([[:alnum:]-]+)\.tar\.` + tarExt + `$`)
	addSigRE := regexp.MustCompile(`^` + base + `\.orig-([[:alnum:]-]+)\.tar\.` + tarExt + `\.asc$`)
	debRE := regexp.MustCompile(`^` + baseRev + `\.debian\.tar\.` + tarExt + `$`)

	for _, f := range d.Files {
		switch {
		case origRE.MatchString(f.Name):
			l.tar = f.Name
		case origSigRE.MatchString(f.Name):
			l.tarSig = f.Name
		case addRE.MatchString(f.Name):
			l.addons[addRE.FindStringSubmatch(f.Name)[1]] = f.Name
		case addSigRE.MatchString(f.Name):
			l.addSigs[addSigRE.FindStringSubmatch(f.Name)[1]] = f.Name
		case debRE.MatchString(f.Name):
			l.debian = f.Name
		default:
			return unexpected(d.Format, f.Name)
		}
	}

	if l.tar == "" || l.debian == "" {
		return fmt.Errorf("%w: a 3.0 (quilt) package needs an orig tarball and a debian tarball", ErrMissingFile)
	}

	if l.tarSig != "" && l.tarSig != l.tar+".asc" {
		return unexpected(d.Format, l.tarSig)
	}

	for comp, sig := range l.addSigs {
		if l.addons[comp] == "" || sig != l.addons[comp]+".asc" {
			return unexpected(d.Format, sig)
		}
	}

	return nil
}

func (l *layout) classifyNative(d *DSC, baseRev string) error {
	tarRE := regexp.MustCompile(`^` + baseRev + `\.tar\.` + tarExt + `$`)
	sigRE := regexp.MustCompile(`^` + baseRev + `\.tar\.` + tarExt + `\.asc$`)

	for _, f := range d.Files {
		switch {
		case tarRE.MatchString(f.Name):
			l.tar = f.Name
		case sigRE.MatchString(f.Name):
			l.tarSig = f.Name
		default:
			return unexpected(d.Format, f.Name)
		}
	}

	if l.tar == "" {
		return fmt.Errorf("%w: no tarball", ErrMissingFile)
	}

	if l.tarSig != "" && l.tarSig != l.tar+".asc" {
		return unexpected(d.Format, l.tarSig)
	}

	l.native = true

	return nil
}

// VerifyFiles checks every file of a .dsc, .changes or .buildinfo file list,
// found in dir by name, against the size and every digest the list carries for
// it. A missing file fails with [ErrMissingFile], a difference with
// [ErrChecksum].
func VerifyFiles(files []FileRef, dir string) error {
	for i := range files {
		if err := verifyFile(&files[i], filepath.Join(dir, files[i].Name)); err != nil {
			return err
		}
	}

	return nil
}

func newHashes(f *FileRef) (map[int]hash.Hash, []io.Writer) {
	hs := map[int]hash.Hash{}

	var ws []io.Writer

	add := func(kind int, h hash.Hash) {
		if f.get(kind) != "" {
			hs[kind] = h
			ws = append(ws, h)
		}
	}

	add(hashMD5, md5.New())   //nolint:gosec // matches the Files field
	add(hashSHA1, sha1.New()) //nolint:gosec // matches the Checksums-Sha1 field
	add(hashSHA256, sha256.New())
	add(hashSHA512, sha512.New())

	return hs, ws
}

func verifyFile(f *FileRef, p string) error {
	if f.MD5 == "" && f.SHA1 == "" && f.SHA256 == "" && f.SHA512 == "" {
		return fmt.Errorf("%w: the .dsc lists no digest for %s", ErrInvalid, f.Name)
	}

	file, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrMissingFile, f.Name)
	}

	if err != nil {
		return err
	}

	defer file.Close()

	hs, ws := newHashes(f)

	n, err := io.Copy(io.MultiWriter(ws...), file)
	if err != nil {
		return err
	}

	if n != f.Size {
		return fmt.Errorf("%w: %s is %d bytes, the .dsc lists %d", ErrChecksum, f.Name, n, f.Size)
	}

	for kind, h := range hs {
		if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, f.get(kind)) {
			return fmt.Errorf("%w: %s %s is %s, the .dsc lists %s", ErrChecksum, f.Name, checksumFields[kind], got, f.get(kind))
		}
	}

	return nil
}

func prepareDest(dest string, replace bool) error {
	st, err := os.Lstat(dest)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return os.MkdirAll(filepath.Dir(dest), fixedDirMode)
	case err != nil:
		return err
	case replace:
		return nil
	case !st.IsDir():
		return fmt.Errorf("%w: %s", ErrDestExists, dest)
	}

	entries, err := os.ReadDir(dest)
	if err != nil {
		return err
	}

	if len(entries) > 0 {
		return fmt.Errorf("%w: %s is not empty", ErrDestExists, dest)
	}

	return nil
}

// Unpack extracts the source package that d describes, whose files are in
// srcDir, to the directory dest, and gives the same tree as dpkg-source -x:
// the files are first verified against the checksums of the .dsc; then the orig
// tarball (its single top-level directory becomes dest), the component
// tarballs, and the debian tarball or the .diff.gz are extracted, and the
// patches of debian/patches/series of a "3.0 (quilt)" package are applied with
// fuzz 0, leaving the .pc directory quilt expects.
//
// Entries and patches only ever write inside dest, never through a symlink,
// and special files are refused with [ErrUnsafe]. Formats "3.0 (git)" and
// "3.0 (custom)" fail with [ErrUnsupportedFormat].
func Unpack(d *DSC, srcDir, dest string, opts *UnpackOptions) error {
	if opts == nil {
		opts = &UnpackOptions{}
	}

	l, err := classify(d)
	if err != nil {
		return err
	}

	if err := VerifyFiles(d.Files, srcDir); err != nil {
		return err
	}

	if err := prepareDest(dest, opts.Replace); err != nil {
		return err
	}

	b := &budget{maxEntries: opts.MaxEntries, maxBytes: opts.MaxBytes}
	if b.maxEntries <= 0 {
		b.maxEntries = DefaultMaxEntries
	}

	if b.maxBytes <= 0 {
		b.maxBytes = DefaultMaxBytes
	}

	file := func(name string) string { return filepath.Join(srcDir, name) }

	var skip func(string) bool
	if d.Format == FormatQuilt {
		skip = skipQuiltDir
	}

	if err := extractReplacing(file(l.tar), dest, skip, b); err != nil {
		return err
	}

	if opts.SkipDebianization {
		return nil
	}

	switch d.Format {
	case FormatQuilt:
		return unpackQuilt(l, file, dest, opts, b)
	case Format10:
		if l.diff != "" {
			return applyDiff10(file(l.diff), dest)
		}
	}

	return nil
}

// skipQuiltDir drops a .pc directory of an orig tarball, at the top or just
// below the top directory.
func skipQuiltDir(name string) bool {
	parts := strings.Split(name, "/")

	return parts[0] == ".pc" || (len(parts) > 1 && parts[1] == ".pc")
}

// extractComponents extracts the component tarballs of l below dest, in name
// order.
func extractComponents(l *layout, file func(string) string, dest string, b *budget) error {
	comps := make([]string, 0, len(l.addons))
	for c := range l.addons {
		comps = append(comps, c)
	}

	sort.Strings(comps)

	for _, c := range comps {
		sub := filepath.Join(dest, c)
		// An empty directory (a git submodule placeholder) is silently replaced.
		_ = os.Remove(sub)

		if err := extractReplacing(file(l.addons[c]), sub, nil, b); err != nil {
			return err
		}
	}

	return nil
}

func unpackQuilt(l *layout, file func(string) string, dest string, opts *UnpackOptions, b *budget) error {
	if err := extractComponents(l, file, dest, b); err != nil {
		return err
	}

	if err := os.RemoveAll(filepath.Join(dest, "debian")); err != nil {
		return err
	}

	if err := extractTar(file(l.debian), dest, nil, b); err != nil {
		return err
	}

	if opts.SkipPatches {
		return nil
	}

	return applyQuiltSeries(dest)
}

func applyDiff10(diff, dest string) error {
	f, err := os.Open(diff)
	if err != nil {
		return err
	}

	defer f.Close()

	r, err := openCompressed(f, diff)
	if err != nil {
		return err
	}

	defer r.Close()

	if _, err := ApplyPatch(dest, r, PatchOptions{Strip: 1}); err != nil {
		return err
	}

	// A diff cannot carry the executable bit: dpkg-source makes debian/rules
	// executable.
	rules := filepath.Join(dest, "debian", "rules")
	if st, err := os.Lstat(rules); err == nil && st.Mode().IsRegular() {
		return os.Chmod(rules, st.Mode().Perm()|0o111)
	}

	return nil
}

var insecureSeriesRE = regexp.MustCompile(`(^|/)\.\./`)

// readSeries returns the patch names of a quilt series file.
func readSeries(data []byte) ([]string, error) {
	var out []string

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)

		if i := strings.Index(line, "#"); i == 0 || (i > 0 && (line[i-1] == ' ' || line[i-1] == '\t')) {
			line = strings.TrimSpace(line[:i])
		}

		if line == "" {
			continue
		}

		name := strings.Fields(line)[0]
		if insecureSeriesRE.MatchString(name) || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/..") {
			return nil, fmt.Errorf("%w: series names the insecure path %q", ErrUnsafe, name)
		}

		out = append(out, name)
	}

	return out, nil
}

// applyQuiltSeries creates the quilt database and applies debian/patches/series
// as dpkg-source does after unpacking.
func applyQuiltSeries(dest string) error {
	pc := filepath.Join(dest, ".pc")
	if err := os.MkdirAll(pc, fixedDirMode); err != nil {
		return err
	}

	for name, content := range map[string]string{
		".version": "2\n", ".quilt_patches": "debian/patches\n", ".quilt_series": "series\n",
	} {
		if err := writeIfMissing(filepath.Join(pc, name), content); err != nil {
			return err
		}
	}

	applied := filepath.Join(pc, "applied-patches")
	if err := os.WriteFile(applied, nil, fixedFileMode); err != nil {
		return err
	}

	seriesFile, err := safepath.ResolveInRoot(dest, "debian/patches/series")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafe, err)
	}

	data, err := os.ReadFile(seriesFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return err
	}

	series, err := readSeries(data)
	if err != nil {
		return err
	}

	var done strings.Builder

	for _, name := range series {
		if err := applyQuiltPatch(dest, name); err != nil {
			return err
		}

		done.WriteString(name + "\n")

		if err := os.WriteFile(applied, []byte(done.String()), fixedFileMode); err != nil {
			return err
		}
	}

	return nil
}

func writeIfMissing(p, content string) error {
	if _, err := os.Lstat(p); err == nil {
		return nil
	}

	return os.WriteFile(p, []byte(content), fixedFileMode)
}

func applyQuiltPatch(dest, name string) error {
	p, err := safepath.ResolveInRoot(dest, path.Join("debian/patches", name))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafe, err)
	}

	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: patch %s of the series", ErrMissingFile, name)
	}

	if err != nil {
		return err
	}

	defer f.Close()

	r, err := openCompressed(f, name)
	if err != nil {
		return err
	}

	defer r.Close()

	backup := filepath.Join(dest, ".pc", filepath.FromSlash(name))
	if err := os.MkdirAll(backup, fixedDirMode); err != nil {
		return err
	}

	_, err = ApplyPatch(dest, r, PatchOptions{Strip: 1, BackupDir: backup})
	if err != nil {
		return fmt.Errorf("patch %s: %w", name, err)
	}

	return nil
}
