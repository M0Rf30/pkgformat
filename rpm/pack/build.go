package pack

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"

	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// payloadResult is the outcome of writing the payload.
type payloadResult struct {
	spool          *spool
	compressedSize int64
	rawSize        int64
	// digests of the compressed payload and of the cpio archive, as hex. v4
	// packages only have SHA-256; v6 packages have SHA-256, SHA-512 and SHA3-256.
	compressed, raw []string
	installed       uint64
}

// hashSet is the digests rpm records of a payload.
type hashSet []hash.Hash

func newHashSet(v6 bool) hashSet {
	if v6 {
		return hashSet{sha256.New(), sha512.New(), sha3.New256()}
	}
	return hashSet{sha256.New()}
}

func (s hashSet) writers() []io.Writer {
	w := make([]io.Writer, len(s))
	for i, h := range s {
		w[i] = h
	}
	return w
}

func (s hashSet) sums() []string {
	out := make([]string, len(s))
	for i, h := range s {
		out[i] = hex.EncodeToString(h.Sum(nil))
	}
	return out
}

// sniffer keeps the first bytes of a stream to classify it.
type sniffer struct{ buf []byte }

func (s *sniffer) Write(p []byte) (int, error) {
	if room := 512 - len(s.buf); room > 0 {
		s.buf = append(s.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// buildPayload writes the cpio archive of the files through the compressor into a
// spool file, hashing the compressed and the uncompressed stream on the way and
// reading every file content once.
func (r *RPM) buildPayload(entries []*fileEntry) (res *payloadResult, err error) {
	sp, err := newSpool(r.TempDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			sp.close()
		}
	}()
	v6 := r.Format == FormatV6
	cHashes, rHashes := newHashSet(v6), newHashSet(v6)
	comp := &countWriter{w: io.MultiWriter(append([]io.Writer{sp.f}, cHashes.writers()...)...)}
	cw, err := r.comp.open(comp)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s writer: %w", r.Compressor, err)
	}
	raw := &countWriter{w: io.MultiWriter(append([]io.Writer{cw}, rHashes.writers()...)...)}
	ar := &archive{w: raw, stripped: v6}
	buf := make([]byte, 256<<10)
	for _, e := range payloadOrder(entries) {
		h := entryHeader{name: e.Name, index: e.index, ino: e.ino, mode: uint32(e.Mode), nlink: e.nlink, mtime: e.MTime,
			rmaj: e.Major, rmin: e.Minor}
		switch {
		case e.isLink():
			h.size = e.size
		case e.isReg() && e.carrier:
			h.size = e.c.size
		}
		ar.begin(h)
		switch {
		case e.isLink():
			_, _ = ar.Write(e.Body)
		case e.isReg() && e.carrier:
			if err := r.streamContent(e, ar, buf); err != nil {
				_ = cw.Close()
				return nil, err
			}
		}
		ar.end()
		if ar.err != nil {
			_ = cw.Close()
			return nil, fmt.Errorf("failed to write payload entry %q: %w", e.Name, ar.err)
		}
	}
	if err := ar.close(); err != nil {
		_ = cw.Close()
		return nil, fmt.Errorf("failed to close cpio payload: %w", err)
	}
	if err := cw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close %s payload: %w", r.Compressor, err)
	}
	return &payloadResult{
		spool: sp, compressedSize: comp.n, rawSize: raw.n,
		compressed: cHashes.sums(), raw: rHashes.sums(), installed: installedSize(entries),
	}, nil
}

// openSource opens the content of a file.
func (c *content) openSource() (io.Reader, func(), error) {
	switch {
	case c.path != "":
		f, err := os.Open(c.path)
		if err != nil {
			return nil, nil, err
		}
		return f, func() { _ = f.Close() }, nil
	case c.open != nil:
		rc, err := c.open()
		if err != nil {
			return nil, nil, err
		}
		return rc, func() { _ = rc.Close() }, nil
	case c.reader != nil:
		return c.reader, func() {}, nil
	}
	return strings.NewReader(string(c.body)), func() {}, nil
}

// streamContent copies the content of a file into the archive and records its
// digests.
func (r *RPM) streamContent(e *fileEntry, ar *archive, buf []byte) error {
	c := e.c
	src, closeSrc, err := c.openSource()
	if err != nil {
		return fmt.Errorf("%w: %q: open content: %w", ErrInvalidFile, e.Name, err)
	}
	defer closeSrc()
	fh, err := newFileHash(r.FileDigestAlgo)
	if err != nil {
		return err
	}
	sn := &sniffer{}
	ws := []io.Writer{ar, fh, sn}
	var vh *verityHasher
	if r.fileSigning != nil && r.fileSigning.VerityKey != nil {
		vh = newVerityHasher()
		ws = append(ws, vh)
	}
	n, err := io.CopyBuffer(io.MultiWriter(ws...), io.LimitReader(src, c.size), buf)
	if err != nil {
		return fmt.Errorf("failed to copy the content of %q: %w", e.Name, err)
	}
	var one [1]byte
	if k, _ := src.Read(one[:]); n != c.size || k > 0 {
		return invalidFile(e.RPMFile, "the content is not the declared %d bytes long", c.size)
	}
	c.digest = hex.EncodeToString(fh.Sum(nil))
	if vh != nil {
		c.verity = vh.Sum()
	}
	c.mime = "inode/x-empty"
	if c.size > 0 {
		c.mime, _, _ = strings.Cut(http.DetectContentType(sn.buf), ";")
	}
	return nil
}

func rpmlibDep(name, version string) *Relation {
	return &Relation{Name: name, Version: version, Sense: SenseRPMLIB | SenseLess | SenseEqual}
}

// fileDeps flags the dependencies of a file the way rpmbuild's dependency
// generators mark them.
func fileDeps(rels Relations, flag Sense) Relations {
	out := make(Relations, len(rels))
	for i, rel := range rels {
		out[i] = &Relation{Name: rel.Name, Version: rel.Version, Sense: rel.Sense | flag}
	}
	return out
}

// sysusersNames returns the users and groups the sysusers lines create.
func sysusersNames(lines []string) (users, groups []string) {
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "u", "u!":
			users = append(users, f[1])
			groups = append(groups, f[1])
		case "g":
			groups = append(groups, f[1])
		}
	}
	return users, groups
}

// finalRelations returns the provides and requires of the package: those of the
// caller plus the ones rpmbuild derives: interpreters of scriptlets, rpmlib features,
// config files, sysusers, file owners and the dependencies of files.
func (r *RPM) finalRelations(entries []*fileEntry, installed uint64) (prov, req Relations) {
	prov, req = slices.Clone(r.Provides), slices.Clone(r.Requires)
	for _, d := range r.scriptDeps() {
		req.addIfMissing(d)
	}
	for _, e := range entries {
		if e.Type&ConfigFile != 0 {
			cfg := func() *Relation {
				return &Relation{Name: "config(" + r.Name + ")", Version: r.evr(), Sense: SenseConfig | SenseEqual}
			}
			prov.addIfMissing(cfg())
			req.addIfMissing(cfg())
			break
		}
	}
	users, groups := sysusersNames(r.Sysusers)
	for _, u := range users {
		prov.addIfMissing(&Relation{Name: "user(" + u + ")"})
	}
	for _, g := range groups {
		prov.addIfMissing(&Relation{Name: "group(" + g + ")"})
	}
	if r.OwnerDeps {
		for _, e := range entries {
			if e.Owner != "root" {
				req.addIfMissing(&Relation{Name: "user(" + e.Owner + ")", Sense: SenseScriptPre | SenseScriptPostun})
			}
			if e.Group != "root" {
				req.addIfMissing(&Relation{Name: "group(" + e.Group + ")", Sense: SenseScriptPre | SenseScriptPostun})
			}
		}
	}
	for _, e := range entries {
		for _, p := range fileDeps(e.Provides, tag.RPMSENSE_FIND_PROVIDES) {
			prov.addIfMissing(p)
		}
		for _, q := range fileDeps(e.Requires, tag.RPMSENSE_FIND_REQUIRES) {
			req.addIfMissing(q)
		}
	}
	for _, d := range r.rpmlibDeps(entries, installed, append(slices.Clone(prov), req...)) {
		req.addIfMissing(d)
	}
	return prov.sorted(), req.sorted()
}

// rpmlibDeps returns the rpmlib(...) requirements of the features the package uses.
func (r *RPM) rpmlibDeps(entries []*fileEntry, installed uint64, rels Relations) Relations {
	var deps Relations
	add := func(name, version string) { deps.addIfMissing(rpmlibDep(name, version)) }
	if r.Format == FormatV4 {
		add("rpmlib(CompressedFileNames)", "3.0.4-1")
		add("rpmlib(FileDigests)", "4.6.0-1")
		add("rpmlib(PayloadFilesHavePrefix)", "4.0-1")
		if installed > maxV4FileSize {
			add("rpmlib(LargeFiles)", "4.12.0-1")
		}
	} else if len(entries) > 0 {
		add("rpmlib(LargeFiles)", "4.12.0-1")
	}
	switch r.Compressor {
	case "zstd":
		add("rpmlib(PayloadIsZstd)", "5.4.18-1")
	case "xz":
		add("rpmlib(PayloadIsXz)", "5.2-1")
	case "lzma":
		add("rpmlib(PayloadIsLzma)", "4.4.6-1")
	}
	for _, e := range entries {
		if e.nlink > 1 && e.isReg() && r.Format == FormatV4 {
			add("rpmlib(PartialHardlinkSets)", "4.0.4-1")
		}
		if e.Caps != "" {
			add("rpmlib(FileCaps)", "4.6.1-1")
		}
	}
	for _, s := range r.scripts {
		r.scriptFeatures(s, add)
	}
	for _, t := range r.triggers {
		r.scriptFeatures(t.Script, add)
		rels = append(rels, t.Conditions...)
	}
	for _, t := range r.fileTriggers {
		r.scriptFeatures(t.Script, add)
	}
	rels = append(rels, r.Obsoletes...)
	rels = append(rels, r.Suggests...)
	rels = append(rels, r.Recommends...)
	rels = append(rels, r.Conflicts...)
	rels = append(rels, r.Enhances...)
	rels = append(rels, r.Supplements...)
	rels = append(rels, r.OrderWithRequires...)
	versions := []string{r.Version, r.Release}
	for _, rel := range rels {
		if isRich(rel.Name) {
			add("rpmlib(RichDependencies)", "4.12.0-1")
		}
		versions = append(versions, rel.Version)
	}
	for _, v := range versions {
		if strings.Contains(v, "~") {
			add("rpmlib(TildeInVersions)", "4.10.0-1")
		}
		if strings.Contains(v, "^") {
			add("rpmlib(CaretInVersions)", "4.15.0-1")
		}
	}
	return deps
}

func (r *RPM) scriptFeatures(s Scriptlet, add func(name, version string)) {
	if !s.isSet() {
		return
	}
	if s.isLua() {
		add("rpmlib(BuiltinLuaScripts)", "4.2.2-1")
	}
	if len(s.Interpreter) > 1 {
		add("rpmlib(ScriptletInterpreterArgs)", "4.0.3-1")
	}
	if s.Flags&(ScriptExpand|ScriptQFormat) != 0 {
		add("rpmlib(ScriptletExpansion)", "4.9.0-1")
	}
}

// i18nEntry builds a RPM_I18NSTRING_TYPE entry: one string per language.
func i18nEntry(values []string) IndexEntry {
	var data []byte
	for _, v := range values {
		data = append(append(data, v...), 0)
	}
	return IndexEntry{Type: tag.RPM_I18NSTRING_TYPE, Count: len(values), Data: data}
}

// buildHeader assembles the main header.
func (r *RPM) buildHeader(entries []*fileEntry, pl *payloadResult) (*rpmhdr.Index, error) {
	h := rpmhdr.NewIndex(tag.RPMTAG_HEADERIMMUTABLE)
	prov, req := r.finalRelations(entries, pl.installed)
	r.writeGenIndexes(h, pl, len(entries))
	// do not write file indexes if there are no files (meta package)
	// doing so will result in an invalid package
	if len(entries) > 0 {
		r.writeFileIndexes(h, entries, prov, req)
	}
	rels := []struct {
		rels                     Relations
		name, version, flagsName int
	}{
		{prov, tag.PROVIDENAME, tag.PROVIDEVERSION, tag.PROVIDEFLAGS},
		{r.Obsoletes, tag.OBSOLETENAME, tag.OBSOLETEVERSION, tag.OBSOLETEFLAGS},
		{r.Suggests, tag.SUGGESTNAME, tag.SUGGESTVERSION, tag.SUGGESTFLAGS},
		{r.Recommends, tag.RECOMMENDNAME, tag.RECOMMENDVERSION, tag.RECOMMENDFLAGS},
		{req, tag.REQUIRENAME, tag.REQUIREVERSION, tag.REQUIREFLAGS},
		{r.Conflicts, tag.CONFLICTNAME, tag.CONFLICTVERSION, tag.CONFLICTFLAGS},
		{r.Enhances, tag.ENHANCENAME, tag.ENHANCEVERSION, tag.ENHANCEFLAGS},
		{r.Supplements, tag.SUPPLEMENTNAME, tag.SUPPLEMENTVERSION, tag.SUPPLEMENTFLAGS},
		{r.OrderWithRequires, tag.ORDERNAME, tag.ORDERVERSION, tag.ORDERFLAGS},
	}
	for _, x := range rels {
		if err := x.rels.AddToIndex(h, x.name, x.version, x.flagsName); err != nil {
			return nil, fmt.Errorf("failed to add relations: %w", err)
		}
	}
	r.addScriptlets(h)
	r.addTriggers(h)
	r.addFileTriggers(h)
	// CustomTags must be the last to be added, because they can overwrite values.
	h.AddEntries(r.customTags)
	return h, nil
}

func (r *RPM) writeGenIndexes(h *rpmhdr.Index, pl *payloadResult, nfiles int) {
	langs := make([]string, 0, len(r.Translations))
	for l := range r.Translations {
		langs = append(langs, l)
	}
	slices.Sort(langs)
	h.Add(tag.HEADERI18NTABLE, EntryStringSlice(append([]string{"C"}, langs...)))
	i18n := func(base string, pick func(Translation) string) IndexEntry {
		// languages without a translation fall back to the default, and the list
		// ends with the last translation, as rpmbuild writes it
		v := []string{base}
		for _, l := range langs {
			t := pick(r.Translations[l])
			if t == "" {
				t = base
			}
			v = append(v, t)
		}
		for len(v) > 1 && v[len(v)-1] == base {
			v = v[:len(v)-1]
		}
		return i18nEntry(v)
	}
	if r.Format == FormatV4 {
		addInstalledSize(h, pl.installed)
	}
	h.Add(tag.NAME, EntryString(r.Name))
	h.Add(tag.VERSION, EntryString(r.Version))
	if r.Epoch != NoEpoch {
		h.Add(tag.EPOCH, EntryUint32([]uint32{r.Epoch}))
	}
	h.Add(tag.SUMMARY, i18n(r.Summary, func(t Translation) string { return t.Summary }))
	h.Add(tag.DESCRIPTION, i18n(r.Description, func(t Translation) string { return t.Description }))
	h.Add(tag.BUILDHOST, EntryString(r.BuildHost))
	if !r.BuildTime.IsZero() {
		// time.Time zero value is confusing, avoid if not supplied
		// a zero time would be written as a date in 1754 or 1970
		bt := r.BuildTime
		if !r.ClampTime.IsZero() && bt.After(r.ClampTime) {
			bt = r.ClampTime
		}
		h.Add(tag.BUILDTIME, EntryUint32([]uint32{uint32(bt.Unix())})) // range checked by validateMetadata
	}
	if len(r.Prefixes) != 0 {
		h.Add(tag.PREFIXES, EntryStringSlice(r.Prefixes))
	}
	h.Add(tag.RELEASE, EntryString(r.Release))
	h.Add(tag.ENCODING, EntryString("utf-8"))
	h.Add(tag.PAYLOADFORMAT, EntryString("cpio"))
	h.Add(tag.PAYLOADCOMPRESSOR, EntryString(r.Compressor))
	h.Add(tag.PAYLOADFLAGS, EntryString(r.comp.level))
	h.Add(tag.ARCH, EntryString(r.Arch))
	h.Add(tag.OS, EntryString(r.OS))
	optional := []struct {
		tag   int
		value string
	}{
		{tag.VENDOR, r.Vendor}, {tag.PACKAGER, r.Packager}, {tag.URL, r.URL},
		{tag.DISTRIBUTION, r.Distribution}, {tag.BUGURL, r.BugURL}, {tag.VCS, r.VCS},
		{tag.DISTTAG, r.DistTag}, {tag.DISTURL, r.DistURL}, {tag.PLATFORM, r.Platform},
		{tag.OPTFLAGS, r.OptFlags}, {tag.COOKIE, r.Cookie}, {tag.MODULARITYLABEL, r.ModularityLabel},
		{tag.TRANSLATIONURL, r.TranslationURL},
	}
	for _, o := range optional {
		if o.value != "" {
			h.Add(o.tag, EntryString(o.value))
		}
	}
	h.Add(tag.LICENSE, EntryString(r.Licence))
	if r.Group != "" {
		h.Add(tag.GROUP, i18n(r.Group, func(t Translation) string { return t.Group }))
	}
	if len(r.BuildArchs) > 0 {
		h.Add(tag.BUILDARCHS, EntryStringSlice(r.BuildArchs))
	}
	if len(r.Sysusers) > 0 {
		h.Add(tag.SYSUSERS, EntryStringSlice(r.Sysusers))
	}
	if len(r.Changelog) > 0 {
		times := make([]uint32, len(r.Changelog))
		names := make([]string, len(r.Changelog))
		texts := make([]string, len(r.Changelog))
		for i, e := range r.Changelog {
			times[i] = uint32(e.Time.Unix()) // range checked by validateMetadata
			names[i] = e.Author
			texts[i] = e.Text
		}
		h.Add(tag.CHANGELOGTIME, EntryUint32(times))
		h.Add(tag.CHANGELOGNAME, EntryStringSlice(names))
		h.Add(tag.CHANGELOGTEXT, EntryStringSlice(texts))
	}
	h.Add(tag.PAYLOADDIGEST, EntryStringSlice([]string{pl.compressed[0]}))
	if r.Format == FormatV4 {
		h.Add(tag.PAYLOADDIGESTALGO, EntryInt32([]int32{tag.HASH_SHA256}))
		h.Add(tag.PAYLOADSHA256ALT, EntryStringSlice([]string{pl.raw[0]}))
	} else {
		r.writeV6Indexes(h, pl)
	}
	sourceRPM := r.SourceRPM
	if sourceRPM == "" {
		// rpm utilities look for the sourcerpm tag to deduce if this is not a source rpm
		// (if it has a sourcerpm, it is NOT a source rpm).
		sourceRPM = fmt.Sprintf("%s-%s.src.rpm", r.Name, r.FullVersion())
	}
	h.Add(tag.SOURCERPM, EntryString(sourceRPM))
	_ = nfiles
}

// writeV6Indexes adds the main header tags that only exist in v6 packages.
func (r *RPM) writeV6Indexes(h *rpmhdr.Index, pl *payloadResult) {
	h.Add(tag.RPMFORMAT, EntryInt32([]int32{FormatV6}))
	nevr := r.Name + "-" + r.FullVersion()
	if r.Epoch != NoEpoch {
		nevr = fmt.Sprintf("%s-%d:%s", r.Name, r.Epoch, r.FullVersion())
	}
	h.Add(tag.SOURCENEVR, EntryString(nevr))
	// Digests of the compressed payload, then of the uncompressed one (ALT).
	h.Add(tag.PAYLOADSHA256ALT, EntryStringSlice([]string{pl.raw[0]}))
	h.Add(tag.PAYLOADSHA512, EntryString(pl.compressed[1]))
	h.Add(tag.PAYLOADSHA512ALT, EntryString(pl.raw[1]))
	h.Add(tag.PAYLOADSHA3_256, EntryString(pl.compressed[2]))
	h.Add(tag.PAYLOADSHA3_256ALT, EntryString(pl.raw[2]))
	h.Add(tag.PAYLOADSIZE, EntryInt64([]int64{pl.compressedSize}))
	h.Add(tag.PAYLOADSIZEALT, EntryInt64([]int64{pl.rawSize}))
	h.Add(tag.LONGSIZE, EntryUint64([]uint64{pl.installed}))
}

// verifyDefault is what rpm does not verify of a ghost file.
const verifyDefault = VerifyDigest | VerifySize | VerifyLinkTo | VerifyMTime

// writeFileIndexes writes the file related tags.
func (r *RPM) writeFileIndexes(h *rpmhdr.Index, entries []*fileEntry, prov, req Relations) {
	n := len(entries)
	var (
		basenames   = make([]string, n)
		dirindexes  = make([]uint32, n)
		sizes       = make([]uint32, n)
		longsizes   = make([]uint64, n)
		modes       = make([]uint16, n)
		owners      = make([]string, n)
		groups      = make([]string, n)
		mtimes      = make([]uint32, n)
		digests     = make([]string, n)
		linktos     = make([]string, n)
		flags       = make([]uint32, n)
		inodes      = make([]int32, n)
		devices     = make([]int32, n)
		verify      = make([]int32, n)
		rdevs       = make([]int16, n)
		langs       = make([]string, n)
		colors      = make([]uint32, n)
		caps        = make([]string, n)
		classIdx    = make([]uint32, n)
		classDict   []string
		classLookup = map[string]uint32{}
		mimeIdx     = make([]uint32, n)
		mimeDict    []string
		mimeLookup  = map[string]uint32{}
		depX        = make([]uint32, n)
		depN        = make([]uint32, n)
		depDict     []uint32
		anyCaps     bool
		anyClass    bool
		anyDeps     bool
		di          = newDirIndex()
	)
	sortedProv, sortedReq := prov, req
	for i, e := range entries {
		dirindexes[i] = di.Get(e.dir)
		basenames[i] = e.base
		owners[i], groups[i], mtimes[i] = e.Owner, e.Group, e.MTime
		flags[i] = uint32(e.Type)
		inodes[i] = int32(e.ino)
		devices[i] = 1
		if e.ghost() {
			devices[i] = 0
		}
		modes[i] = uint16(e.Mode) // range checked by validateFile
		rdevs[i] = int16(e.Major<<8 | e.Minor)
		langs[i] = e.Lang
		colors[i] = e.Color
		caps[i] = e.Caps
		anyCaps = anyCaps || e.Caps != ""
		excl := e.VerifyExclude
		if e.ghost() && excl == 0 {
			excl = verifyDefault
		}
		verify[i] = int32(^uint32(excl))

		mime := ""
		switch {
		case e.isDir():
			mime = "inode/directory"
		case e.isLink():
			sizes[i], longsizes[i] = uint32(e.size), uint64(e.size)
			linktos[i] = string(e.Body)
			mime = "inode/symlink"
		case e.isReg():
			sizes[i], longsizes[i] = uint32(min(e.size, maxV4FileSize)), uint64(e.size)
			if !e.ghost() {
				digests[i] = e.c.digest
				mime = e.c.mime
			}
		case modeIs(e.Mode, ModeFifo):
			mime = "inode/fifo"
		case modeIs(e.Mode, ModeSocket):
			mime = "inode/socket"
		case modeIs(e.Mode, ModeChar):
			mime = "inode/chardevice"
		case modeIs(e.Mode, ModeBlock):
			mime = "inode/blockdevice"
		}
		if e.isDir() {
			longsizes[i] = 0
		}
		idx, ok := mimeLookup[mime]
		if !ok {
			idx = uint32(len(mimeDict))
			mimeDict = append(mimeDict, mime)
			mimeLookup[mime] = idx
		}
		mimeIdx[i] = idx

		ci, ok := classLookup[e.Class]
		if !ok {
			ci = uint32(len(classDict))
			classDict = append(classDict, e.Class)
			classLookup[e.Class] = ci
		}
		classIdx[i] = ci
		anyClass = anyClass || e.Class != ""
		depX[i] = uint32(len(depDict))
		for _, p := range fileDeps(e.Provides, tag.RPMSENSE_FIND_PROVIDES) {
			depDict = append(depDict, 'P'<<24|uint32(sortedProv.index(p)))
		}
		for _, q := range fileDeps(e.Requires, tag.RPMSENSE_FIND_REQUIRES) {
			depDict = append(depDict, 'R'<<24|uint32(sortedReq.index(q)))
		}
		depN[i] = uint32(len(depDict)) - depX[i]
		anyDeps = anyDeps || depN[i] > 0
	}
	h.Add(tag.BASENAMES, EntryStringSlice(basenames))
	h.Add(tag.DIRINDEXES, EntryUint32(dirindexes))
	h.Add(tag.DIRNAMES, EntryStringSlice(di.AllDirs()))
	if r.Format == FormatV4 {
		h.Add(tag.FILESIZES, EntryUint32(sizes))
	} else {
		h.Add(tag.LONGFILESIZES, EntryUint64(longsizes))
		h.Add(tag.FILEMIMEINDEX, EntryUint32(mimeIdx))
		h.Add(tag.MIMEDICT, EntryStringSlice(mimeDict))
	}
	h.Add(tag.FILEMODES, EntryUint16(modes))
	h.Add(tag.FILEUSERNAME, EntryStringSlice(owners))
	h.Add(tag.FILEGROUPNAME, EntryStringSlice(groups))
	h.Add(tag.FILEMTIMES, EntryUint32(mtimes))
	h.Add(tag.FILEDIGESTS, EntryStringSlice(digests))
	h.Add(tag.FILELINKTOS, EntryStringSlice(linktos))
	h.Add(tag.FILEFLAGS, EntryUint32(flags))
	h.Add(tag.FILEINODES, EntryInt32(inodes))
	h.Add(tag.FILEDEVICES, EntryInt32(devices))
	h.Add(tag.FILEDIGESTALGO, EntryInt32([]int32{int32(r.FileDigestAlgo)}))
	h.Add(tag.FILEVERIFYFLAGS, EntryInt32(verify))
	h.Add(tag.FILERDEVS, EntryInt16(rdevs))
	h.Add(tag.FILELANGS, EntryStringSlice(langs))
	h.Add(tag.FILECOLORS, EntryUint32(colors))
	if anyCaps {
		h.Add(tag.FILECAPS, EntryStringSlice(caps))
	}
	if r.Format == FormatV4 && anyClass {
		h.Add(tag.FILECLASS, EntryUint32(classIdx))
		h.Add(tag.CLASSDICT, EntryStringSlice(classDict))
	}
	if anyDeps {
		h.Add(tag.FILEDEPENDSX, EntryUint32(depX))
		h.Add(tag.FILEDEPENDSN, EntryUint32(depN))
		h.Add(tag.DEPENDSDICT, EntryUint32(depDict))
	}
}

// signatureHeaderV6 builds the (8-byte padded) v6 signature header for the main
// header hb. It holds the SHA256 and SHA3-256 digests of the header, an OpenPGP
// signature of the header when a signer is set, the file signatures and reserved space.
func (r *RPM) signatureHeaderV6(hb []byte, files []*fileEntry, _ *payloadResult) ([]byte, error) {
	s := rpmhdr.NewIndex(tag.RPMTAG_HEADERSIGNATURES)
	s.Add(tag.SIG_SHA256, EntryString(fmt.Sprintf("%x", sha256.Sum256(hb))))
	s.Add(tag.SIG_SHA3_256, EntryString(fmt.Sprintf("%x", sha3.Sum256(hb))))
	// The reserved space is sized so that the total signature header length
	// is the one of an unsigned package, as rpm does.
	base, err := s.Bytes()
	if err != nil {
		return nil, err
	}
	total := len(base) + rpmhdr.IndexEntrySize + v6SigReserved

	if r.pgpSigner != nil {
		sig, err := r.pgpSigner(strings.NewReader(string(hb)))
		if err != nil {
			return nil, fmt.Errorf("call to signer failed: %w", err)
		}
		s.Add(tag.SIG_OPENPGP, EntryStringSlice([]string{base64.StdEncoding.EncodeToString(sig)}))
	}
	if err := r.addFileSignatures(s, files); err != nil {
		return nil, err
	}
	s.AddEntries(r.customSigs)

	if err := s.Reserve(tag.SIG_RESERVED, total); err != nil {
		return nil, err
	}
	sb, err := s.Bytes()
	if err != nil {
		return nil, err
	}
	// Signatures are padded to 8-byte boundaries
	return append(sb, make([]byte, rpmhdr.Pad8(len(sb)))...), nil
}

// The signature header tags of file signatures.
const (
	sigFileSignatures      = tag.SIG_BASE + 18
	sigFileSignatureLength = tag.SIG_BASE + 19
)

// addFileSignatures adds the IMA and fs-verity signatures of the files to a signature header.
func (r *RPM) addFileSignatures(s *rpmhdr.Index, files []*fileEntry) error {
	fs := r.fileSigning
	if fs == nil || len(files) == 0 {
		return nil
	}
	if fs.IMAKey != nil {
		sigs := make([]string, len(files))
		var length int32
		for i, e := range files {
			if !e.isReg() || e.ghost() {
				continue
			}
			digest, err := hex.DecodeString(e.c.digest)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrFileSigning, err)
			}
			sig, err := imaSignature(fs.IMAKey, r.FileDigestAlgo, digest)
			if err != nil {
				return err
			}
			sigs[i] = hex.EncodeToString(sig)
			length = int32(len(sig))
		}
		s.Add(sigFileSignatures, EntryStringSlice(sigs))
		s.Add(sigFileSignatureLength, EntryInt32([]int32{length}))
	}
	if fs.VerityKey != nil {
		empty := newVerityHasher().Sum()
		sigs := make([]string, len(files))
		cache := map[[32]byte]string{}
		for i, e := range files {
			d := empty
			if e.isReg() && !e.ghost() {
				d = e.c.verity
			}
			sig, ok := cache[d]
			if !ok {
				var err error
				if sig, err = veritySignature(fs.VerityKey, fs.VerityCert, d); err != nil {
					return err
				}
				cache[d] = sig
			}
			sigs[i] = sig
		}
		s.Add(tag.SIG_VERITYSIGNATURES, EntryStringSlice(sigs))
		s.Add(tag.SIG_VERITYSIGNATUREALGO, EntryInt32([]int32{1}))
	}
	return nil
}
