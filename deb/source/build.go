package source

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
)

// BuildOptions tunes [Build]. The zero value is valid.
type BuildOptions struct {
	// OrigDir holds the orig tarballs of a "3.0 (quilt)" package. The default
	// is the parent directory of the tree, where dpkg-source looks.
	OrigDir string
	// OutDir receives the .dsc, the debian tarball and a copy of the orig
	// tarballs. The default is the parent directory of the tree.
	OutDir string
	// Compression is the compression of the tarball that is created: "xz"
	// (the default), "gzip" or "zstd": the compressions dpkg-source reads.
	Compression string
	// ModTime is the modification time of every archive entry that is not
	// older. The default is the date of the latest debian/changelog entry, so
	// that a build is reproducible.
	ModTime time.Time
	// Signer, when set, clear-signs the .dsc.
	Signer gpg.Signer
	// IgnorePatterns are tar exclude patterns added to the defaults that
	// dpkg-source uses (".git", "*.o", ...).
	IgnorePatterns []string
}

// BuildResult describes what [Build] wrote.
type BuildResult struct {
	// DSC is the description written to DSCPath, without a signature.
	DSC *DSC
	// DSCPath is the path of the .dsc file.
	DSCPath string
	// Files lists every file of the source package in OutDir, the .dsc
	// included.
	Files []string
}

// defaultTarIgnore are the exclude patterns of dpkg-source.
var defaultTarIgnore = []string{
	"*.a", "*.la", "*.o", "*.so", ".*.sw?", "*/*~", ",,*", ".[#~]*", ".arch-ids", ".arch-inventory", ".be",
	".bzr", ".bzr.backup", ".bzr.tags", ".bzrignore", ".cvsignore", ".deps", ".git", ".gitattributes",
	".gitignore", ".gitmodules", ".gitreview", ".hg", ".hgignore", ".hgsigs", ".hgtags", ".mailmap",
	".mtn-ignore", ".shelf", ".svn", "CVS", "DEADJOE", "RCS", "_MTN", "_darcs", "{arch}",
	"debian/source/local-options", "debian/source/local-patch-header", "debian/files", "debian/files.new",
}

// ignoreSet matches paths against tar --exclude patterns: a pattern matches
// the whole path or any tail of it that starts at a component, and "*" also
// matches "/".
type ignoreSet []*regexp.Regexp

func newIgnoreSet(patterns []string) (ignoreSet, error) {
	set := make(ignoreSet, 0, len(patterns))

	for _, p := range patterns {
		re, err := globRegexp(p)
		if err != nil {
			return nil, fmt.Errorf("%w: ignore pattern %q: %w", ErrInvalid, p, err)
		}

		set = append(set, re)
	}

	return set, nil
}

func globRegexp(p string) (*regexp.Regexp, error) {
	var sb strings.Builder

	sb.WriteString(`^(?:.*/)?`)

	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '*':
			sb.WriteString(`.*`)
		case '?':
			sb.WriteString(`.`)
		case '[':
			j := strings.IndexByte(p[i:], ']')
			if j < 0 {
				return nil, errors.New("unterminated [")
			}

			class := p[i+1 : i+j]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}

			sb.WriteString("[" + class + "]")
			i += j
		case '\\':
			if i+1 < len(p) {
				i++
				sb.WriteString(regexp.QuoteMeta(string(p[i])))
			}
		default:
			sb.WriteString(regexp.QuoteMeta(string(c)))
		}
	}

	sb.WriteString(`$`)

	return regexp.Compile(sb.String())
}

func (s ignoreSet) match(name string) bool {
	for _, re := range s {
		if re.MatchString(name) {
			return true
		}
	}

	return false
}

type changelogHead struct {
	source, version string
	date            time.Time
}

var (
	changelogHeadRE    = regexp.MustCompile(`^(\S+) \(([^)\s]+)\) [^;]*;`)
	changelogTrailerRE = regexp.MustCompile(`^ -- .*?  (.+?)\s*$`)
)

var changelogDateLayouts = []string{
	"Mon, 2 Jan 2006 15:04:05 -0700", "2 Jan 2006 15:04:05 -0700",
	"Mon, 2 Jan 2006 15:04:05 MST", "Mon, 2 Jan 2006 15:04 -0700",
}

// parseChangelogHead reads the first entry of a debian/changelog.
func parseChangelogHead(data []byte) (changelogHead, error) {
	var h changelogHead

	lines := strings.Split(string(data), "\n")

	i := 0
	for i < len(lines) && strings.TrimSpace(lines[i]) == "" {
		i++
	}

	if i >= len(lines) {
		return h, fmt.Errorf("%w: debian/changelog is empty", ErrInvalid)
	}

	m := changelogHeadRE.FindStringSubmatch(lines[i])
	if m == nil {
		return h, fmt.Errorf("%w: debian/changelog starts with %q", ErrInvalid, truncate(lines[i]))
	}

	h.source, h.version = m[1], m[2]

	for _, line := range lines[i+1:] {
		if t := changelogTrailerRE.FindStringSubmatch(line); t != nil {
			for _, layout := range changelogDateLayouts {
				if d, err := time.Parse(layout, t[1]); err == nil {
					h.date = d

					break
				}
			}

			break
		}

		if changelogHeadRE.MatchString(line) {
			break
		}
	}

	return h, nil
}

type controlStanzas struct {
	src  *deb.ControlFile
	bins []*deb.ControlFile
}

func readControl(tree string) (*controlStanzas, error) {
	data, err := os.ReadFile(filepath.Join(tree, "debian", "control"))
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}

	if len(data) > MaxDocumentBytes {
		return nil, fmt.Errorf("%w: debian/control of %d bytes", ErrTooLarge, len(data))
	}

	var cs controlStanzas

	err = deb.ScanControl(bytes.NewReader(data), func(cf *deb.ControlFile) error {
		if _, ok := cf.Lookup("Source"); ok && cs.src == nil {
			cs.src = cf

			return nil
		}

		if _, ok := cf.Lookup("Package"); ok {
			cs.bins = append(cs.bins, cf)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: debian/control: %w", ErrInvalid, err)
	}

	if cs.src == nil {
		return nil, fmt.Errorf("%w: debian/control has no source stanza", ErrInvalid)
	}

	if len(cs.bins) == 0 {
		return nil, fmt.Errorf("%w: debian/control lists no binary package", ErrInvalid)
	}

	return &cs, nil
}

// srcFields are the fields of the source stanza that go to the .dsc as they are.
var srcFieldsKnown = nameSet(
	"Source", "Maintainer", "Uploaders", "Homepage", "Standards-Version", "Origin",
	"Testsuite", "Testsuite-Triggers",
	"Build-Depends", "Build-Depends-Arch", "Build-Depends-Indep",
	"Build-Conflicts", "Build-Conflicts-Arch", "Build-Conflicts-Indep",
	"Vcs-Browser", "Vcs-Arch", "Vcs-Bzr", "Vcs-Cvs", "Vcs-Darcs", "Vcs-Git", "Vcs-Hg", "Vcs-Mtn", "Vcs-Svn",
)

var xFieldRE = regexp.MustCompile(`(?i)^X([SBC]*)-(.+)$`)

func normalizeRelations(v string) (string, error) {
	rels, err := deb.ParseRelations(v)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	return deb.FormatRelations(rels), nil
}

// dscFromControl builds the description of the source package of tree, without
// its files.
func describeTree(tree string, head changelogHead, cs *controlStanzas) (*DSC, error) {
	d := &DSC{Source: head.source, Version: head.version}

	if cs.src.Get("Source") != head.source {
		return nil, fmt.Errorf("%w: debian/control names source %q, debian/changelog %q",
			ErrInvalid, cs.src.Get("Source"), head.source)
	}

	d.Maintainer = strings.TrimSpace(cs.src.Get("Maintainer"))
	d.Uploaders = normalizeUploaders(cs.src.Get("Uploaders"))
	d.Homepage = strings.TrimSpace(cs.src.Get("Homepage"))
	d.StandardsVersion = strings.TrimSpace(cs.src.Get("Standards-Version"))
	d.Origin = strings.TrimSpace(cs.src.Get("Origin"))
	d.Testsuite = strings.TrimSpace(cs.src.Get("Testsuite"))
	d.TestsuiteTriggers = strings.TrimSpace(cs.src.Get("Testsuite-Triggers"))

	for _, name := range vcsFields {
		if v, ok := cs.src.Lookup(name); ok {
			if d.Vcs == nil {
				d.Vcs = map[string]string{}
			}

			d.Vcs[name] = strings.TrimSpace(v)
		}
	}

	for _, f := range []struct {
		dst  *string
		name string
	}{
		{&d.BuildDepends, "Build-Depends"}, {&d.BuildDependsArch, "Build-Depends-Arch"},
		{&d.BuildDependsIndep, "Build-Depends-Indep"}, {&d.BuildConflicts, "Build-Conflicts"},
		{&d.BuildConflictsArch, "Build-Conflicts-Arch"}, {&d.BuildConflictsIndep, "Build-Conflicts-Indep"},
	} {
		v, ok := cs.src.Lookup(f.name)
		if !ok {
			continue
		}

		n, err := normalizeRelations(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}

		*f.dst = n
	}

	for _, name := range cs.src.Order {
		if srcFieldsKnown[strings.ToLower(name)] {
			continue
		}

		if m := xFieldRE.FindStringSubmatch(name); m != nil && strings.ContainsAny(strings.ToUpper(m[1]), "S") {
			d.Extra = append(d.Extra, Field{Name: m[2], Value: cs.src.Fields[name]})
		}
	}

	if err := describeBinaries(tree, d, cs); err != nil {
		return nil, err
	}

	return d, nil
}

func describeBinaries(tree string, d *DSC, cs *controlStanzas) error {
	var (
		archs  []string
		seen   = map[string]bool{}
		listed []string
	)

	for _, b := range cs.bins {
		name := strings.TrimSpace(b.Get("Package"))
		if name == "" {
			return fmt.Errorf("%w: a binary stanza has no Package field", ErrInvalid)
		}

		d.Binary = append(d.Binary, name)

		entry := PackageListEntry{Name: name, Type: "deb"}
		if v := firstNonEmpty(b.Get("Package-Type"), b.Get("XC-Package-Type")); v != "" {
			entry.Type = v
		}

		entry.Section = firstNonEmpty(b.Get("Section"), cs.src.Get("Section"), "unknown")
		entry.Priority = firstNonEmpty(b.Get("Priority"), cs.src.Get("Priority"), "optional")

		arch := strings.Join(strings.Fields(b.Get("Architecture")), ",")
		if arch == "" {
			return fmt.Errorf("%w: binary package %s has no Architecture", ErrInvalid, name)
		}

		entry.Options = append(entry.Options, "arch="+arch)

		for _, a := range strings.Fields(b.Get("Architecture")) {
			if !seen[a] {
				seen[a] = true

				archs = append(archs, a)
			}
		}

		if v := b.Get("Build-Profiles"); v != "" {
			v0, v1 := profileProperties(v)
			entry.Options = append(entry.Options, "profile="+v0, "profile:v1="+v1)
		}

		for _, f := range []string{"Protected", "Essential"} {
			if b.Get(f) == "yes" {
				entry.Options = append(entry.Options, strings.ToLower(f)+"=yes")
			}
		}

		listed = append(listed, entry.String())
	}

	sort.Strings(listed)

	for _, l := range listed {
		w := strings.Fields(l)
		d.PackageList = append(d.PackageList, PackageListEntry{Name: w[0], Type: w[1], Section: w[2], Priority: w[3], Options: w[4:]})
	}

	d.Architecture = minimalArchitectures(archs)

	return setTestsuite(tree, d)
}

// normalizeUploaders joins the entries of an Uploaders field on one line,
// separated by ", ", without empty entries; a comma inside "<>" or quotes is
// part of an entry.
func normalizeUploaders(v string) string {
	var (
		parts    []string
		cur      strings.Builder
		inAngle  bool
		inQuotes bool
	)

	flush := func() {
		if s := strings.Join(strings.Fields(cur.String()), " "); s != "" {
			parts = append(parts, s)
		}

		cur.Reset()
	}

	for _, r := range v {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case r == '<' && !inQuotes:
			inAngle = true
		case r == '>' && !inQuotes:
			inAngle = false
		case r == ',' && !inAngle && !inQuotes:
			flush()

			continue
		}

		cur.WriteRune(r)
	}

	flush()

	return strings.Join(parts, ", ")
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}

	return ""
}

// profileProperties renders a Build-Profiles formula ("<!nocheck> <a b>") as
// the profile (v0) and profile:v1 properties of Package-List.
func profileProperties(formula string) (v0, v1 string) {
	var or0, or1 []string

	for _, g := range strings.Split(formula, ">") {
		g = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(g), "<"))
		if g == "" {
			continue
		}

		words := strings.Fields(g)
		or0 = append(or0, strings.Join(words, ","))
		or1 = append(or1, strings.Join(words, "&"))
	}

	return strings.Join(or0, "+"), strings.Join(or1, "|")
}

// minimalArchitectures merges the architectures of the binary packages: "any"
// swallows everything but "all", and an architecture a wildcard covers is
// dropped.
func minimalArchitectures(archs []string) []string {
	has := func(a string) bool {
		for _, x := range archs {
			if x == a {
				return true
			}
		}

		return false
	}

	if has("any") {
		if has("all") {
			return []string{"any", "all"}
		}

		return []string{"any"}
	}

	var wild, out []string

	for _, a := range archs {
		if strings.Contains(a, "any") {
			wild = append(wild, a)
		}
	}

	out = append(out, wild...)

	for _, a := range archs {
		covered := false

		for _, w := range wild {
			if a != w && deb.ArchMatches(a, w) {
				covered = true
			}
		}

		if !strings.Contains(a, "any") && !covered {
			out = append(out, a)
		}
	}

	return out
}

// setTestsuite fills Testsuite and Testsuite-Triggers from debian/tests/control.
func setTestsuite(tree string, d *DSC) error {
	suites := map[string]bool{}

	for _, s := range splitList(d.Testsuite) {
		suites[s] = true
	}

	data, err := os.ReadFile(filepath.Join(tree, "debian", "tests", "control"))

	switch {
	case err == nil:
		suites["autopkgtest"] = true

		if d.TestsuiteTriggers == "" {
			d.TestsuiteTriggers = testTriggers(data, d.Binary)
		}
	case errors.Is(err, fs.ErrNotExist):
		delete(suites, "autopkgtest")
	default:
		return fmt.Errorf("source: %w", err)
	}

	names := make([]string, 0, len(suites))
	for s := range suites {
		names = append(names, s)
	}

	sort.Strings(names)

	d.Testsuite = strings.Join(names, ", ")

	return nil
}

// testTriggers collects the package names of the Depends fields of an
// autopkgtest control file, without the binaries of the source itself.
func testTriggers(data []byte, binaries []string) string {
	deps := map[string]bool{}

	_ = deb.ScanControl(bytes.NewReader(data), func(cf *deb.ControlFile) error {
		for _, name := range deb.DependencyNames(cf.Get("Depends")) {
			deps[name] = true
		}

		return nil
	})

	delete(deps, "@")

	for _, b := range binaries {
		delete(deps, b)
	}

	names := make([]string, 0, len(deps))
	for n := range deps {
		names = append(names, n)
	}

	sort.Strings(names)

	return strings.Join(names, ", ")
}

// compression selects the writer for a tarball.
type compression struct {
	ext   string
	write func(io.Writer) (io.WriteCloser, error)
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func parseWriteCompression(name string) (compression, error) {
	switch strings.ToLower(name) {
	case "none":
		return compression{"", func(w io.Writer) (io.WriteCloser, error) { return nopCloser{w}, nil }}, nil
	case "", "xz":
		return compression{".xz", func(w io.Writer) (io.WriteCloser, error) { return xz.NewWriter(w) }}, nil
	case "gz", "gzip":
		return compression{".gz", func(w io.Writer) (io.WriteCloser, error) { return gzip.NewWriter(w), nil }}, nil
	case "zst", "zstd":
		return compression{".zst", func(w io.Writer) (io.WriteCloser, error) { return zstd.NewWriter(w) }}, nil
	}

	return compression{}, fmt.Errorf("%w: compression %q", deb.ErrUnsupportedCompression, name)
}

// writeTar writes the entries below tree/sub (all of tree when sub is empty)
// as the tar archive out. With no sub, the entries sit below the top directory
// named top; with a sub they keep their name relative to tree. Entries are in
// name order with root ownership and clamped times, like dpkg-source.
func writeTar(out io.Writer, tree, sub, top string, ignore ignoreSet, mod time.Time) error {
	tw := tar.NewWriter(out)
	start := tree

	if sub != "" {
		start = filepath.Join(tree, sub)
	}

	err := filepath.WalkDir(start, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(tree, p)
		if err != nil {
			return err
		}

		rel = filepath.ToSlash(rel)
		if rel != "." && ignore.match(rel) {
			if de.IsDir() {
				return filepath.SkipDir
			}

			return nil
		}

		name := rel
		if sub == "" {
			name = path.Join(top, rel)
		}

		return addTarEntry(tw, p, name, mod)
	})
	if err != nil {
		return err
	}

	return tw.Close()
}

func addTarEntry(tw *tar.Writer, p, name string, mod time.Time) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}

	hdr := &tar.Header{Name: name, Mode: int64(st.Mode().Perm()), Format: tar.FormatGNU, ModTime: st.ModTime()}
	if hdr.ModTime.After(mod) {
		hdr.ModTime = mod
	}

	hdr.ModTime = hdr.ModTime.Truncate(time.Second)

	switch {
	case st.IsDir():
		hdr.Typeflag = tar.TypeDir
		hdr.Name += "/"
	case st.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(p)
		if err != nil {
			return err
		}

		hdr.Typeflag, hdr.Linkname = tar.TypeSymlink, target
	case st.Mode().IsRegular():
		hdr.Typeflag, hdr.Size = tar.TypeReg, st.Size()
	default:
		return fmt.Errorf("%w: %s is a special file", ErrUnsafe, p)
	}

	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}

	if hdr.Typeflag != tar.TypeReg {
		return nil
	}

	f, err := os.Open(p)
	if err != nil {
		return err
	}

	defer f.Close()

	_, err = io.Copy(tw, f)

	return err
}

func createTarball(dst string, c compression, fill func(io.Writer) error) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}

	w, err := c.write(f)
	if err != nil {
		_ = f.Close()

		return err
	}

	if err := fill(w); err != nil {
		_ = w.Close()
		_ = f.Close()

		return err
	}

	if err := w.Close(); err != nil {
		_ = f.Close()

		return err
	}

	return f.Close()
}

// digestFile returns the FileRef of the file p with the MD5, SHA-1 and SHA-256
// digests dpkg-source writes.
func digestFile(p, name string) (FileRef, error) {
	f, err := hashFile(p, name)
	if err != nil {
		return FileRef{}, err
	}

	f.SHA512 = ""

	return f, nil
}

func copyFile(src, dst string) error {
	if filepath.Clean(src) == filepath.Clean(dst) {
		return nil
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}

	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()

		return err
	}

	return out.Close()
}

// Build packs the prepared source tree into a source package, the way
// dpkg-source -b does for the formats "3.0 (native)" and "3.0 (quilt)": the
// format comes from debian/source/format, the description from
// debian/changelog and debian/control.
//
// A native package becomes one tarball of the whole tree. A quilt package
// needs its orig tarballs in [BuildOptions.OrigDir]; they are copied to the
// output next to a debian tarball of debian/, and the tree must equal the
// orig tarballs plus the patches debian/patches/series lists as applied by
// .pc/applied-patches, or Build fails with [ErrLocalChanges] (it never writes
// an automatic patch). The result is accepted by dpkg-source -x.
func Build(tree string, opts *BuildOptions) (*BuildResult, error) {
	if opts == nil {
		opts = &BuildOptions{}
	}

	tree = filepath.Clean(tree)

	b, err := newBuilder(tree, opts)
	if err != nil {
		return nil, err
	}

	switch b.format {
	case FormatNative:
		err = b.buildNative()
	case FormatQuilt:
		err = b.buildQuilt()
	default:
		return nil, fmt.Errorf("%w: cannot build format %q", ErrUnsupportedFormat, string(b.format))
	}

	if err != nil {
		return nil, err
	}

	return b.finish()
}

type builder struct {
	tree, outDir, origDir string
	opts                  *BuildOptions
	format                Format
	comp                  compression
	ignore                ignoreSet
	head                  changelogHead
	mod                   time.Time
	dsc                   *DSC
	up, full              string
	files                 []string // base names in dsc order
}

func newBuilder(tree string, opts *BuildOptions) (*builder, error) {
	b := &builder{tree: tree, opts: opts}

	if st, err := os.Stat(tree); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("source: %s is not a directory", tree)
	}

	parent := filepath.Dir(tree)

	b.outDir, b.origDir = opts.OutDir, opts.OrigDir
	if b.outDir == "" {
		b.outDir = parent
	}

	if b.origDir == "" {
		b.origDir = parent
	}

	var err error

	if b.comp, err = parseWriteCompression(opts.Compression); err != nil {
		return nil, err
	}

	if b.comp.ext == "" {
		return nil, fmt.Errorf("%w: dpkg-source reads no uncompressed tarball", deb.ErrUnsupportedCompression)
	}

	if b.ignore, err = newIgnoreSet(append(append([]string(nil), defaultTarIgnore...), opts.IgnorePatterns...)); err != nil {
		return nil, err
	}

	format, err := os.ReadFile(filepath.Join(tree, "debian", "source", "format"))
	if err != nil {
		return nil, fmt.Errorf("%w: debian/source/format: %w", ErrUnsupportedFormat, err)
	}

	b.format = Format(strings.TrimSpace(string(format)))

	changelog, err := os.ReadFile(filepath.Join(tree, "debian", "changelog"))
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}

	if b.head, err = parseChangelogHead(changelog); err != nil {
		return nil, err
	}

	if !deb.ValidVersion(b.head.version) {
		return nil, fmt.Errorf("%w: version %q", ErrInvalid, b.head.version)
	}

	b.mod = opts.ModTime
	if b.mod.IsZero() {
		b.mod = b.head.date
	}

	if b.mod.IsZero() {
		b.mod = time.Unix(0, 0)
	}

	cs, err := readControl(tree)
	if err != nil {
		return nil, err
	}

	if b.dsc, err = describeTree(tree, b.head, cs); err != nil {
		return nil, err
	}

	b.dsc.Format = b.format
	b.up, b.full = versionParts(b.head.version)

	if err := os.MkdirAll(b.outDir, fixedDirMode); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *builder) buildNative() error {
	name := fmt.Sprintf("%s_%s.tar%s", b.head.source, b.full, b.comp.ext)

	err := createTarball(filepath.Join(b.outDir, name), b.comp, func(w io.Writer) error {
		return writeTar(w, b.tree, "", b.head.source+"-"+b.full, b.ignore, b.mod)
	})
	if err != nil {
		return err
	}

	b.files = append(b.files, name)

	return nil
}

var origNameRE = regexp.MustCompile(`^(.*)\.orig(?:-([[:alnum:]-]+))?\.tar\.(gz|bz2|xz|zst)(\.asc)?$`)

// findOrigs returns the orig tarballs (and signatures) of the package in dir,
// as a layout.
func (b *builder) findOrigs() (*layout, error) {
	entries, err := os.ReadDir(b.origDir)
	if err != nil {
		return nil, err
	}

	l := &layout{addons: map[string]string{}, addSigs: map[string]string{}}
	prefix := b.head.source + "_" + b.up

	for _, e := range entries {
		m := origNameRE.FindStringSubmatch(e.Name())
		if m == nil || m[1] != prefix {
			continue
		}

		switch {
		case m[2] == "" && m[4] == "":
			if l.tar != "" {
				return nil, fmt.Errorf("%w: several orig tarballs (%s, %s)", ErrUnexpectedFile, l.tar, e.Name())
			}

			l.tar = e.Name()
		case m[2] == "":
			l.tarSig = e.Name()
		case m[4] == "":
			if _, dup := l.addons[m[2]]; dup {
				return nil, fmt.Errorf("%w: several orig tarballs for component %s", ErrUnexpectedFile, m[2])
			}

			l.addons[m[2]] = e.Name()
		default:
			l.addSigs[m[2]] = e.Name()
		}
	}

	if l.tar == "" {
		return nil, fmt.Errorf("%w: %s.orig.tar.* in %s", ErrMissingFile, prefix, b.origDir)
	}

	return l, nil
}

func (b *builder) buildQuilt() error {
	l, err := b.findOrigs()
	if err != nil {
		return err
	}

	if err := b.checkTree(l); err != nil {
		return err
	}

	tarballs := []string{l.tar}
	sigs := map[string]string{l.tar: l.tarSig}

	for c, n := range l.addons {
		tarballs = append(tarballs, n)
		sigs[n] = l.addSigs[c]
	}

	// dpkg-source lists the tarballs in name order, each followed by its signature.
	sort.Strings(tarballs)

	var names []string

	for _, n := range tarballs {
		names = append(names, n)
		if sigs[n] != "" {
			names = append(names, sigs[n])
		}
	}

	for _, n := range names {
		if err := copyFile(filepath.Join(b.origDir, n), filepath.Join(b.outDir, n)); err != nil {
			return err
		}
	}

	debName := fmt.Sprintf("%s_%s.debian.tar%s", b.head.source, b.full, b.comp.ext)

	err = createTarball(filepath.Join(b.outDir, debName), b.comp, func(w io.Writer) error {
		return writeTar(w, b.tree, "debian", "debian", b.ignore, b.mod)
	})
	if err != nil {
		return err
	}

	b.files = append(names, debName)

	return nil
}

// finish writes the .dsc.
func (b *builder) finish() (*BuildResult, error) {
	for _, n := range b.files {
		f, err := digestFile(filepath.Join(b.outDir, n), n)
		if err != nil {
			return nil, err
		}

		b.dsc.Files = append(b.dsc.Files, f)
	}

	var (
		body []byte
		err  error
	)

	if b.opts.Signer != nil {
		body, err = b.dsc.Sign(b.opts.Signer)
	} else {
		body, err = b.dsc.Marshal()
	}

	if err != nil {
		return nil, err
	}

	dscName := fmt.Sprintf("%s_%s.dsc", b.head.source, b.full)
	dscPath := filepath.Join(b.outDir, dscName)

	if err := os.WriteFile(dscPath, body, fixedFileMode); err != nil {
		return nil, err
	}

	res := &BuildResult{DSC: b.dsc, DSCPath: dscPath, Files: []string{dscPath}}
	for _, n := range b.files {
		res.Files = append(res.Files, filepath.Join(b.outDir, n))
	}

	return res, nil
}

// treeEntry is what compare keeps of a file: enough to tell two trees apart.
type treeEntry struct {
	kind   byte // 'f' or 'l'
	exec   bool
	digest string // content or link target
}

// scanTree lists the files and links of root, relative, leaving out what ignore
// matches and the debian and .pc directories at the top.
func scanTree(root string, ignore ignoreSet) (map[string]treeEntry, error) {
	out := map[string]treeEntry{}

	err := filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)

		if rel == "." {
			return nil
		}

		if rel == "debian" || rel == ".pc" || ignore.match(rel) {
			if de.IsDir() {
				return filepath.SkipDir
			}

			return nil
		}

		if de.IsDir() {
			return nil
		}

		st, err := os.Lstat(p)
		if err != nil {
			return err
		}

		switch {
		case st.Mode()&fs.ModeSymlink != 0:
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}

			out[rel] = treeEntry{kind: 'l', digest: t}
		case st.Mode().IsRegular():
			f, err := digestFile(p, rel)
			if err != nil {
				return err
			}

			out[rel] = treeEntry{kind: 'f', exec: st.Mode().Perm()&0o111 != 0, digest: f.SHA256}
		default:
			return fmt.Errorf("%w: %s is a special file", ErrUnsafe, rel)
		}

		return nil
	})

	return out, err
}

// checkTree verifies that tree equals the orig tarballs plus the patches that
// .pc/applied-patches lists, outside debian/.
func (b *builder) checkTree(l *layout) error {
	tmp, err := os.MkdirTemp(b.outDir, ".check-*")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tmp)

	ref := filepath.Join(tmp, "ref")
	budget := &budget{maxEntries: DefaultMaxEntries, maxBytes: DefaultMaxBytes}
	file := func(n string) string { return filepath.Join(b.origDir, n) }

	if err := extractReplacing(file(l.tar), ref, skipQuiltDir, budget); err != nil {
		return err
	}

	if err := extractComponents(l, file, ref, budget); err != nil {
		return err
	}

	if err := b.replaySeries(ref); err != nil {
		return err
	}

	want, err := scanTree(ref, b.ignore)
	if err != nil {
		return err
	}

	got, err := scanTree(b.tree, b.ignore)
	if err != nil {
		return err
	}

	var diff []string

	for n, e := range got {
		if w, ok := want[n]; !ok || w != e {
			diff = append(diff, n)
		}
	}

	for n := range want {
		if _, ok := got[n]; !ok {
			diff = append(diff, n)
		}
	}

	if len(diff) > 0 {
		sort.Strings(diff)

		if len(diff) > 5 {
			diff = append(diff[:5], "...")
		}

		return fmt.Errorf("%w: %s", ErrLocalChanges, strings.Join(diff, ", "))
	}

	return nil
}

// replaySeries applies to ref the leading patches of the series that
// the tree records as applied.
func (b *builder) replaySeries(ref string) error {
	var series []string

	if data, err := os.ReadFile(filepath.Join(b.tree, "debian", "patches", "series")); err == nil {
		if series, err = readSeries(data); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	var applied []string

	if data, err := os.ReadFile(filepath.Join(b.tree, ".pc", "applied-patches")); err == nil {
		if applied, err = readSeries(data); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	if len(applied) > len(series) {
		return fmt.Errorf("%w: .pc/applied-patches is longer than the series", ErrLocalChanges)
	}

	for i, name := range applied {
		if series[i] != name {
			return fmt.Errorf("%w: applied patch %q is not %q of the series", ErrLocalChanges, name, series[i])
		}

		p := filepath.Join(b.tree, "debian", "patches", filepath.FromSlash(name))

		f, err := os.Open(p)
		if err != nil {
			return fmt.Errorf("%w: patch %s of the series", ErrMissingFile, name)
		}

		r, err := openCompressed(f, name)
		if err != nil {
			_ = f.Close()

			return err
		}

		_, err = ApplyPatch(ref, r, PatchOptions{Strip: 1})
		_ = r.Close()

		if err != nil {
			return fmt.Errorf("patch %s: %w", name, err)
		}
	}

	return nil
}
