package deb

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Limits of the Packages.diff/Index parser.
const (
	// MaxPDiffIndexBytes bounds the size of a Packages.diff/Index document. Real
	// ones are tens of kilobytes.
	MaxPDiffIndexBytes = 8 << 20
	// maxPDiffEntries bounds the patches one Index lists (dak keeps 56).
	maxPDiffEntries = 1 << 14
)

// Errors of the pdiff (Packages.diff) support. Malformed edit scripts are
// reported as a *PDiffError that wraps ErrPDiffScript or ErrPDiffLimit.
var (
	// ErrPDiffIndex is wrapped by every error ParsePDiffIndex returns, and by
	// PDiffIndex methods that find the Index unusable.
	ErrPDiffIndex = errors.New("deb: invalid pdiff index")
	// ErrPDiffNoPath is returned by PDiffIndex.Chain for a file that is neither
	// the current one nor listed in the history: no patch series leads from it
	// to the current file, and the full index must be fetched instead.
	ErrPDiffNoPath = errors.New("deb: no pdiff path from the local file to the current one")
	// ErrPDiffScript is wrapped by the *PDiffError of a malformed edit script
	// or of one that does not fit the file it is applied to.
	ErrPDiffScript = errors.New("deb: invalid pdiff edit script")
	// ErrPDiffLimit is wrapped by the *PDiffError of a script or result that
	// exceeds a limit of PDiffApplyOptions.
	ErrPDiffLimit = errors.New("deb: pdiff limit exceeded")
	// ErrPDiffHash is returned when a patch, a patched file or a downloaded
	// patch does not have the digest the Index lists for it.
	ErrPDiffHash = errors.New("deb: pdiff digest mismatch")
	// ErrPDiffUnrepresentable is returned by GeneratePDiff for a change an
	// ed-script patch cannot express: new text with a line that is just "." or
	// without a final newline.
	ErrPDiffUnrepresentable = errors.New("deb: change cannot be expressed as a pdiff")
)

// PDiffHash is a size and the digests of one file an Index lists. SHA1 is
// legacy and may be empty; SHA256 is what clients verify.
type PDiffHash struct {
	Size   int64
	SHA256 string
	SHA1   string
}

// IsZero reports whether h carries no digest and no size.
func (h PDiffHash) IsZero() bool { return h == PDiffHash{} }

// usable reports whether h has the digest clients verify.
func (h PDiffHash) usable() bool { return h.SHA256 != "" }

// PDiffPatch is one patch of a Packages.diff series.
//
// The patch is fetched as Packages.diff/<Name>.gz (see DownloadName), which is
// Download.Size bytes with the digest Download.SHA256; decompressed it is the
// ed script of Patch. Applying it to the file with digest From.SHA256 gives
// the file with digest To.SHA256.
type PDiffPatch struct {
	// Name is the name of the patch without extension, such as
	// "2024-05-01-1234.56" or "T-2024-05-01-1234.56-F-2024-04-30-0801.12".
	Name string
	// From describes the file the patch applies to (the Index History entry).
	From PDiffHash
	// To describes the file the patch yields. PDiffIndex.Chain fills it in; it
	// is the Current file for a merged patch and the next patch's From
	// otherwise. It is zero in PDiffIndex.Patches.
	To PDiffHash
	// Patch describes the decompressed ed script.
	Patch PDiffHash
	// Download describes the gzip file Packages.diff/<Name>.gz.
	Download PDiffHash
	// DownloadXZ describes the optional xz file Packages.diff/<Name>.xz; it is
	// zero when the Index lists none. Clients that only know gzip ignore it.
	DownloadXZ PDiffHash
}

// DownloadName is the file name of the gzip download, relative to the
// Packages.diff directory.
func (p PDiffPatch) DownloadName() string { return p.Name + ".gz" }

// PDiffIndex is a parsed Packages.diff/Index: the digest of the current file
// and the series of patches that lead to it.
type PDiffIndex struct {
	// Current describes the file the patches lead to.
	Current PDiffHash
	// Patches is the History in the order of the Index, oldest first. Each
	// patch's From is the file it applies to. For a Merged index each patch
	// leads to Current by itself; otherwise patch i leads to patch i+1's file
	// and the last one to Current.
	Patches []PDiffPatch
	// Merged reports "X-Patch-Precedence: merged": the server merged the
	// patches, so every entry of Patches reaches Current in one step.
	Merged bool
	// Unmerged lists, for a Merged index, the one-step patches the merged ones
	// were built from (the X-Unmerged-* sections); empty otherwise.
	Unmerged []PDiffPatch
	// OlderPatches is X-DAK-Older-Patches: the targets of earlier merged
	// series whose patch files are kept for clients holding an older Index.
	OlderPatches []string
	// CanonicalPath is Canonical-Path, when present.
	CanonicalPath string
	// Extra holds the fields the parser does not interpret, by name.
	Extra map[string]string
}

// pdiffHashKinds are the digest algorithms of an Index, in the order the
// writer emits them.
var pdiffHashKinds = []string{"SHA1", "SHA256"}

// pdiffSection is one History, Patches or Download list of an Index.
type pdiffSection int

const (
	pdiffHistory pdiffSection = iota
	pdiffPatches
	pdiffDownload
)

func (s pdiffSection) String() string {
	switch s {
	case pdiffHistory:
		return "History"
	case pdiffPatches:
		return "Patches"
	default:
		return "Download"
	}
}

// pdiffField is a field of the Index paragraph, in file order.
type pdiffField struct{ name, value string }

// ParsePDiffIndex parses the Packages.diff/Index of an apt repository. It
// reads the SHA256 and SHA1 variants of the Current, History, Patches and
// Download fields (and their X-Unmerged-* counterparts), X-Patch-Precedence,
// X-DAK-Older-Patches and Canonical-Path; other fields are kept in Extra. The
// history order of the first digest present (SHA256, else SHA1) is
// authoritative: entries of other lists that are not in it are ignored, as apt
// does. Documents over MaxPDiffIndexBytes and series over 16384 patches are
// refused. A hash or size that is malformed fails the parse; an Index without
// any Current digest or history is an error as well.
func ParsePDiffIndex(data []byte) (*PDiffIndex, error) {
	if len(data) > MaxPDiffIndexBytes {
		return nil, fmt.Errorf("%w: document exceeds %d bytes", ErrPDiffIndex, MaxPDiffIndexBytes)
	}

	fields, err := pdiffParagraph(string(data))
	if err != nil {
		return nil, err
	}

	idx := &PDiffIndex{}
	main := newPDiffSeries()
	unmerged := newPDiffSeries()

	// The SHA256 histories fix the order of their series, so read them first.
	sort.SliceStable(fields, func(i, j int) bool {
		return strings.HasSuffix(fields[i].name, "SHA256-History") && !strings.HasSuffix(fields[j].name, "SHA256-History")
	})

	for _, f := range fields {
		if err := idx.addField(f, main, unmerged); err != nil {
			return nil, err
		}
	}

	if idx.Current.SHA256 == "" && idx.Current.SHA1 == "" {
		return nil, fmt.Errorf("%w: no Current digest", ErrPDiffIndex)
	}

	idx.Patches = main.patches()
	idx.Unmerged = unmerged.patches()

	return idx, nil
}

// addField interprets one field of the Index.
func (idx *PDiffIndex) addField(f pdiffField, main, unmerged *pdiffSeries) error {
	name := f.name

	switch name {
	case "X-Patch-Precedence":
		idx.Merged = strings.TrimSpace(f.value) == "merged"

		return nil
	case "X-DAK-Older-Patches":
		idx.OlderPatches = strings.Fields(f.value)

		return nil
	case "Canonical-Path":
		idx.CanonicalPath = strings.TrimSpace(f.value)

		return nil
	}

	series := main

	if rest, ok := strings.CutPrefix(name, "X-Unmerged-"); ok {
		series, name = unmerged, rest
	}

	for _, kind := range pdiffHashKinds {
		rest, ok := strings.CutPrefix(name, kind+"-")
		if !ok {
			continue
		}

		if rest == "Current" && series == main {
			h, err := parsePDiffCurrent(f.value)
			if err != nil {
				return fmt.Errorf("%w: %s: %w", ErrPDiffIndex, f.name, err)
			}

			return idx.setCurrent(kind, h, f.name)
		}

		for _, sec := range []pdiffSection{pdiffHistory, pdiffPatches, pdiffDownload} {
			if rest == sec.String() {
				if err := series.add(kind, sec, f.value); err != nil {
					return fmt.Errorf("%w: %s: %w", ErrPDiffIndex, f.name, err)
				}

				return nil
			}
		}
	}

	if idx.Extra == nil {
		idx.Extra = map[string]string{}
	}

	idx.Extra[f.name] = strings.TrimSpace(f.value)

	return nil
}

// setCurrent records one Current digest; digests of one Index must agree on
// the size.
func (idx *PDiffIndex) setCurrent(kind string, h pdiffEntry, field string) error {
	if idx.Current.SHA256 != "" || idx.Current.SHA1 != "" {
		if idx.Current.Size != h.size {
			return fmt.Errorf("%w: %s: size %d disagrees with %d", ErrPDiffIndex, field, h.size, idx.Current.Size)
		}
	}

	idx.Current.Size = h.size

	if kind == "SHA256" {
		idx.Current.SHA256 = h.hash
	} else {
		idx.Current.SHA1 = h.hash
	}

	return nil
}

// pdiffEntry is one "hash size [name]" line.
type pdiffEntry struct {
	hash string
	size int64
	name string
}

func parsePDiffCurrent(v string) (pdiffEntry, error) {
	f := strings.Fields(v)
	if len(f) != 2 {
		return pdiffEntry{}, fmt.Errorf("want \"<hash> <size>\", got %q", strings.TrimSpace(v))
	}

	return newPDiffEntry(f[0], f[1], "")
}

func newPDiffEntry(hash, size, name string) (pdiffEntry, error) {
	n, err := strconv.ParseInt(size, 10, 64)
	if err != nil || n < 0 {
		return pdiffEntry{}, fmt.Errorf("bad size %q", size)
	}

	if !validPDiffHex(hash) {
		return pdiffEntry{}, fmt.Errorf("bad digest %q", hash)
	}

	return pdiffEntry{hash: strings.ToLower(hash), size: n, name: name}, nil
}

// validPDiffHex reports whether s is a hex SHA1 or SHA256 digest.
func validPDiffHex(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}

	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}

	return true
}

// pdiffSeries accumulates the three lists of a patch series.
type pdiffSeries struct {
	order   []string
	byName  map[string]*PDiffPatch
	primary string // the digest kind whose History fixed the order
}

func newPDiffSeries() *pdiffSeries { return &pdiffSeries{byName: map[string]*PDiffPatch{}} }

// add reads one list. The first History read fixes the order and the set of
// names; everything else only fills in digests of names that are known.
func (s *pdiffSeries) add(kind string, sec pdiffSection, value string) error {
	lines := strings.Fields(value)
	if len(lines)%3 != 0 {
		return errors.New("lines are not \"<hash> <size> <name>\"")
	}

	if len(lines)/3 > maxPDiffEntries {
		return fmt.Errorf("more than %d entries", maxPDiffEntries)
	}

	for i := 0; i < len(lines); i += 3 {
		e, err := newPDiffEntry(lines[i], lines[i+1], lines[i+2])
		if err != nil {
			return err
		}

		name, xz := e.name, false

		if sec == pdiffDownload {
			switch {
			case strings.HasSuffix(name, ".gz"):
				name = strings.TrimSuffix(name, ".gz")
			case strings.HasSuffix(name, ".xz"):
				name, xz = strings.TrimSuffix(name, ".xz"), true
			default:
				continue // apt only knows gzip patches
			}
		}

		if !validPDiffName(name) {
			return fmt.Errorf("unsafe patch name %q", e.name)
		}

		p := s.byName[name]

		if p == nil {
			if sec != pdiffHistory || (s.primary != "" && s.primary != kind) {
				continue
			}

			s.primary = kind
			p = &PDiffPatch{Name: name}
			s.byName[name] = p
			s.order = append(s.order, name)
		}

		set := func(h *PDiffHash) {
			h.Size = e.size
			if kind == "SHA256" {
				h.SHA256 = e.hash
			} else {
				h.SHA1 = e.hash
			}
		}

		switch {
		case sec == pdiffHistory:
			set(&p.From)
		case sec == pdiffPatches:
			set(&p.Patch)
		case xz:
			set(&p.DownloadXZ)
		default:
			set(&p.Download)
		}
	}

	return nil
}

func (s *pdiffSeries) patches() []PDiffPatch {
	if len(s.order) == 0 {
		return nil
	}

	out := make([]PDiffPatch, len(s.order))
	for i, n := range s.order {
		out[i] = *s.byName[n]
	}

	return out
}

// validPDiffName reports whether name is a safe patch file name: non-empty and
// made of characters of Debian version and date strings, so it cannot name a
// path outside the Packages.diff directory.
func validPDiffName(name string) bool {
	if name == "" || len(name) > 255 || name == "Index" || name[0] == '.' {
		return false
	}

	for i := range len(name) {
		c := name[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			c != '-' && c != '.' && c != '_' && c != '+' && c != '~' {
			return false
		}
	}

	return true
}

// pdiffParagraph splits the first paragraph of an Index into fields; the
// continuation lines of a field are joined with newlines.
func pdiffParagraph(text string) ([]pdiffField, error) {
	var (
		fields []pdiffField
		cur    *pdiffField
	)

	for line := range strings.Lines(text) {
		line = strings.TrimRight(line, "\r\n")

		switch {
		case strings.TrimSpace(line) == "":
			if len(fields) > 0 {
				return fields, nil
			}
		case line[0] == '#':
		case line[0] == ' ' || line[0] == '\t':
			if cur == nil {
				return nil, fmt.Errorf("%w: continuation line without a field", ErrPDiffIndex)
			}

			cur.value += "\n" + line
		default:
			name, value, ok := strings.Cut(line, ":")
			if !ok || name == "" || strings.ContainsAny(name, " \t") {
				return nil, fmt.Errorf("%w: malformed line %q", ErrPDiffIndex, truncatePDiff(line))
			}

			fields = append(fields, pdiffField{name: name, value: value})
			cur = &fields[len(fields)-1]
		}
	}

	return fields, nil
}

func truncatePDiff(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}

	return s
}

// Chain returns the patches to fetch and apply, in order, to turn a local
// file with the SHA-256 fromSHA256 into the current file.
//
// A local file that already is the current one needs no patch: Chain returns
// an empty chain and no error. A file that is not in the history yields
// ErrPDiffNoPath: the caller fetches the whole index. A history entry matches
// by digest; where several do, the newest wins, which is the shortest chain.
// For a Merged index the chain is the single merged patch of the entry.
//
// The chain's patches have To filled in. A patch without a usable digest of
// itself, of its download or of its source makes the Index unusable for the
// chain (ErrPDiffIndex).
func (idx *PDiffIndex) Chain(fromSHA256 string) ([]PDiffPatch, error) {
	from := strings.ToLower(strings.TrimSpace(fromSHA256))
	if from == "" {
		return nil, fmt.Errorf("%w: empty digest", ErrPDiffNoPath)
	}

	if from == idx.Current.SHA256 {
		return nil, nil
	}

	start := -1

	for i := len(idx.Patches) - 1; i >= 0; i-- {
		if idx.Patches[i].From.SHA256 == from {
			start = i

			break
		}
	}

	if start < 0 {
		return nil, fmt.Errorf("%w: %s is not in the history", ErrPDiffNoPath, from)
	}

	end := len(idx.Patches)
	if idx.Merged {
		end = start + 1
	}

	chain := make([]PDiffPatch, 0, end-start)

	for i := start; i < end; i++ {
		p := idx.Patches[i]
		p.To = idx.Current

		if !idx.Merged && i+1 < len(idx.Patches) {
			p.To = idx.Patches[i+1].From
		}

		if !p.From.usable() || !p.Patch.usable() || !p.Download.usable() || !p.To.usable() {
			return nil, fmt.Errorf("%w: patch %s has no usable SHA256 digests", ErrPDiffIndex, p.Name)
		}

		chain = append(chain, p)
	}

	return chain, nil
}

// Marshal renders the Index in the layout dak writes: the Current digests,
// the History, Patches and Download lists with SHA1 before SHA256 (a digest
// kind no patch carries is left out), the X-Unmerged-* lists of a Merged
// index, X-Patch-Precedence, X-DAK-Older-Patches, and the Extra fields sorted
// by name. ParsePDiffIndex reads the result back.
func (idx *PDiffIndex) Marshal() []byte {
	var sb strings.Builder

	if idx.CanonicalPath != "" {
		sb.WriteString("Canonical-Path: " + idx.CanonicalPath + "\n")
	}

	for _, kind := range pdiffHashKinds {
		if h := pdiffDigest(idx.Current, kind); h != "" {
			fmt.Fprintf(&sb, "%s-Current: %s %7d\n", kind, h, idx.Current.Size)
		}
	}

	writePDiffLists(&sb, "", idx.Patches)

	if idx.Merged {
		writePDiffLists(&sb, "X-Unmerged-", idx.Unmerged)
		sb.WriteString("X-Patch-Precedence: merged\n")

		if len(idx.OlderPatches) > 0 {
			sb.WriteString("X-DAK-Older-Patches: " + strings.Join(idx.OlderPatches, " ") + "\n")
		}
	}

	keys := make([]string, 0, len(idx.Extra))
	for k := range idx.Extra {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		sb.WriteString(k + ": " + idx.Extra[k] + "\n")
	}

	return []byte(sb.String())
}

func pdiffDigest(h PDiffHash, kind string) string {
	if kind == "SHA256" {
		return h.SHA256
	}

	return h.SHA1
}

// writePDiffLists writes the History, Patches and Download lists of a series
// under the field prefix, SHA1 before SHA256 within each; a digest kind no patch
// carries is left out. The xz downloads share the Download field with the gzip
// ones.
func writePDiffLists(sb *strings.Builder, prefix string, patches []PDiffPatch) {
	for _, sec := range []pdiffSection{pdiffHistory, pdiffPatches, pdiffDownload} {
		for _, kind := range pdiffHashKinds {
			var lines []string

			add := func(h PDiffHash, name string) {
				if d := pdiffDigest(h, kind); d != "" {
					lines = append(lines, fmt.Sprintf(" %s %7d %s\n", d, h.Size, name))
				}
			}

			for _, p := range patches {
				switch sec {
				case pdiffHistory:
					add(p.From, p.Name)
				case pdiffPatches:
					add(p.Patch, p.Name)
				default:
					add(p.Download, p.Name+".gz")
				}
			}

			if sec == pdiffDownload {
				for _, p := range patches {
					add(p.DownloadXZ, p.Name+".xz")
				}
			}

			if len(lines) == 0 {
				continue
			}

			sb.WriteString(prefix + kind + "-" + sec.String() + ":\n")

			for _, l := range lines {
				sb.WriteString(l)
			}
		}
	}
}
