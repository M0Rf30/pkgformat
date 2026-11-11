package apt

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/deb"
)

// ParseSourcesList parses the one-line format of /etc/apt/sources.list and
// *.list files after sources.list(5):
//
//	deb [arch=amd64 signed-by=/usr/share/keyrings/k.gpg] https://archive.ubuntu.com/ubuntu/ jammy main universe
//	deb-src [arch+=i386 lang=de,fr target-=Contents-deb] http://deb.example.org/ stable main
//
// Both types (deb, deb-src) and every URI scheme are returned; filter with
// Source.IsSource and Source.Scheme. A line gives one Source holding all the
// components. Options sit between brackets, separated by blanks; values of
// list options are separated by commas, and "+=" and "-=" add to or remove
// from the default instead of replacing it (arch, lang and target). Words may
// be quoted with double quotes and carry %xx escapes, and a "#" starts a
// comment unless it is inside the brackets.
//
// A suite that ends in a slash is an exact path and takes no component.
//
// The parser is as strict as apt about the shape of a line, and stricter about
// option values, which apt silently reads as false or 0: an entry that is not
// well formed (unknown type, no URI, no suite or component, a URI without a
// scheme, an option that is not key=value) or whose known option has an
// invalid value is skipped and reported as a *SourceError, all of them joined
// into the returned error next to the sources that did parse. Options this
// package does not know are kept in Source.Options.
//
// Input over MaxSourcesFileBytes is refused with ErrTooLarge.
func ParseSourcesList(content string) ([]Source, error) {
	return parseSourcesList("", content)
}

// ParseSources822 parses the deb822 format of *.sources files after
// sources.list(5). A stanza gives one Source per Types, URIs and Suites value
// (all with the stanza's Components); the capitalised option names are
// Architectures, Architectures-Add, Architectures-Remove, Languages,
// Languages-Add, Languages-Remove, Targets, Targets-Add, Targets-Remove,
// Trusted, Signed-By (a list of fingerprints, keyring paths, or an inline
// armored key block whose empty lines are written " ."), Check-Valid-Until,
// Valid-Until-Min, Valid-Until-Max (seconds), Check-Date, Date-Max-Future
// (seconds), By-Hash (yes, no or force), PDiffs, Snapshot, Allow-Insecure,
// Allow-Weak and Allow-Downgrade-To-Insecure, matched case-insensitively.
// List values are separated by blanks and newlines. Other fields are kept in
// Source.Options under their name as written.
//
// A stanza with "Enabled: no" (or another false spelling) is skipped. Errors
// are reported as in ParseSourcesList: a bad stanza is skipped and described
// by a *SourceError whose Line is its first line.
//
// Input over MaxSourcesFileBytes is refused with ErrTooLarge.
func ParseSources822(content string) ([]Source, error) {
	return parseSources822("", content)
}

// sourceFile accumulates the sources and errors of one file.
type sourceFile struct {
	path    string
	sources []Source
	errs    []error
}

func (f *sourceFile) fail(line int, option string, err error) {
	f.errs = append(f.errs, &SourceError{Path: f.path, Line: line, Option: option, Err: err})
}

// full reports whether the file reached MaxSourcesPerFile sources, and
// records it once.
func (f *sourceFile) full(line int) bool {
	if len(f.sources) < MaxSourcesPerFile {
		return false
	}

	f.fail(line, "", fmt.Errorf("%w: more than %d sources", ErrTooLarge, MaxSourcesPerFile))

	return true
}

func malformed(what string) error { return fmt.Errorf("%w: %s", ErrMalformedSource, what) }

func tooLargeInput() error {
	return fmt.Errorf("%w: sources text over %d bytes", ErrTooLarge, MaxSourcesFileBytes)
}

// parseSourcesList is ParseSourcesList with the file name for its errors.
func parseSourcesList(path, content string) ([]Source, error) {
	if len(content) > MaxSourcesFileBytes {
		return nil, tooLargeInput()
	}

	f := &sourceFile{path: path}

	for i, line := range strings.Split(content, "\n") {
		if f.full(i + 1) {
			break
		}

		f.parseListLine(i+1, line)
	}

	return f.sources, errors.Join(f.errs...)
}

// stripListComment removes a trailing comment and the blanks around line. A
// "#" inside an unclosed "[" belongs to an option, as in apt.
func stripListComment(line string) string {
	for pos := 0; ; {
		i := strings.IndexByte(line[pos:], '#')
		if i < 0 {
			break
		}

		i += pos

		if strings.Count(line[:i], "[") > strings.Count(line[:i], "]") {
			pos = i + 1

			continue
		}

		line = line[:i]

		break
	}

	return strings.Trim(line, " \t\r")
}

// parseListLine handles one line of a one-line file.
func (f *sourceFile) parseListLine(lineNo int, raw string) {
	line := stripListComment(raw)
	if line == "" {
		return
	}

	typ := line
	if i := strings.IndexAny(line, " \t\v"); i >= 0 {
		typ = line[:i]
	}

	if typ == line {
		f.fail(lineNo, "", malformed("line has no type, URI and suite"))

		return
	}

	st := SourceType(typ)
	if st != TypeDeb && st != TypeDebSrc {
		f.fail(lineNo, "", malformed(fmt.Sprintf("unknown type %q", typ)))

		return
	}

	rest := strings.TrimLeft(line[len(typ):], " \t\v\f\r")

	var opts []rawOption

	if strings.HasPrefix(rest, "[") {
		var (
			err  error
			what string
		)

		opts, rest, what, err = parseListOptions(rest)
		if err != nil {
			f.fail(lineNo, what, err)

			return
		}
	}

	src, err := parseListEntry(st, rest)
	if err != nil {
		f.fail(lineNo, "", err)

		return
	}

	if name, err := applyOptions(&src, opts, ','); err != nil {
		f.fail(lineNo, name, err)

		return
	}

	f.sources = append(f.sources, src)
}

// parseListEntry reads "URI suite [component...]" after the options.
func parseListEntry(typ SourceType, rest string) (Source, error) {
	uri, rest, ok := quoteWord(rest)
	if !ok {
		return Source{}, malformed("missing URI")
	}

	suite, rest, ok := quoteWord(rest)
	if !ok {
		return Source{}, malformed("missing suite")
	}

	url, err := fixupURI(uri)
	if err != nil {
		return Source{}, err
	}

	src := Source{Type: typ, URL: url, Suite: suite}

	if strings.HasSuffix(suite, "/") {
		if _, _, more := quoteWord(rest); more {
			return Source{}, malformed("an exact path suite takes no component")
		}

		return src, nil
	}

	for {
		var comp string

		comp, rest, ok = quoteWord(rest)
		if !ok {
			break
		}

		if len(src.Components) >= MaxSourceListValues {
			return Source{}, fmt.Errorf("%w: more than %d components", ErrTooLarge, MaxSourceListValues)
		}

		src.Components = append(src.Components, comp)
	}

	if len(src.Components) == 0 {
		return Source{}, malformed("missing component")
	}

	return src, nil
}

// fixupURI checks that uri has a scheme and ends it with a slash.
func fixupURI(uri string) (string, error) {
	if !strings.Contains(uri, ":") {
		return "", malformed(fmt.Sprintf("URI %q has no scheme", uri))
	}

	return withSlash(uri), nil
}

// isSpace is C isspace for ASCII.
func isSpace(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r')
}

// quoteWord is apt's ParseQuoteWord: the next blank-separated word of s, in
// which a double-quoted run and a bracketed run may contain blanks, with %xx
// escapes decoded and the quotes removed. rest starts at the next word. It
// reports false when there is no word or a quote or bracket is not closed.
func quoteWord(s string) (word, rest string, ok bool) {
	start := 0
	for start < len(s) && isSpace(s[start]) {
		start++
	}

	if start == len(s) {
		return "", "", false
	}

	end := start

	for end < len(s) && !isSpace(s[end]) {
		if s[end] == '"' {
			j := strings.IndexByte(s[end+1:], '"')
			if j < 0 {
				return "", "", false
			}

			end += 1 + j
		}

		if s[end] == '[' {
			j := strings.IndexByte(s[end+1:], ']')
			if j < 0 {
				return "", "", false
			}

			end += 1 + j
		}

		end++
	}

	var sb strings.Builder

	seg := s[start:end]

	for i := 0; i < len(seg); i++ {
		if seg[i] == '%' && i+2 < len(seg) {
			if hi, ok := unhex(seg[i+1]); ok {
				if lo, ok := unhex(seg[i+2]); ok {
					sb.WriteByte(hi<<4 | lo)

					i += 2

					continue
				}
			}
		}

		if seg[i] != '"' {
			sb.WriteByte(seg[i])
		}
	}

	rest = s[end:]
	for len(rest) > 0 && isSpace(rest[0]) {
		rest = rest[1:]
	}

	return sb.String(), rest, true
}

// rawOption is one option as written: its apt key ("arch", "arch+", "arch-",
// "signed-by"), its name as written and its value.
type rawOption struct {
	key, name, value string
}

// parseListOptions reads the "[key=value key+=value ...]" block that s starts
// with and returns the options and what follows the closing bracket. what
// names the offending option in an error.
func parseListOptions(s string) (opts []rawOption, rest, what string, err error) {
	s = strings.TrimLeft(s[1:], " \t\v\f\r")

	for {
		if s == "" {
			return nil, "", "", malformed("[option] unparsable")
		}

		if s[0] == ']' {
			break
		}

		word, after, ok := quoteWord(s)
		if !ok {
			return nil, "", "", malformed("[option] unparsable")
		}

		if len(word) < 3 {
			return nil, "", word, malformed("[option] too short")
		}

		// The last option may touch the closing bracket.
		if strings.HasSuffix(word, "]") {
			consumed := s[:len(s)-len(after)]
			after = s[strings.LastIndexByte(consumed, ']'):]
			word = word[:len(word)-1]
		}

		key, value, found := strings.Cut(word, "=")

		switch {
		case !found:
			return nil, "", word, malformed("[option] not an assignment")
		case key == "":
			return nil, "", word, malformed("[option] no key")
		case value == "":
			return nil, "", key, malformed("[option] no value")
		}

		if len(opts) >= MaxSourceListValues {
			return nil, "", "", fmt.Errorf("%w: more than %d options", ErrTooLarge, MaxSourceListValues)
		}

		opts = append(opts, rawOption{key: key, name: key, value: value})
		s = after
	}

	return opts, strings.TrimLeft(s[1:], " \t\v\f\r"), "", nil
}

// deb822Options maps the lower-cased deb822 field names to the option keys.
var deb822Options = map[string]string{
	"architectures":               "arch",
	"architectures-add":           "arch+",
	"architectures-remove":        "arch-",
	"languages":                   "lang",
	"languages-add":               "lang+",
	"languages-remove":            "lang-",
	"targets":                     "target",
	"targets-add":                 "target+",
	"targets-remove":              "target-",
	"trusted":                     "trusted",
	"check-valid-until":           "check-valid-until",
	"valid-until-min":             "valid-until-min",
	"valid-until-max":             "valid-until-max",
	"check-date":                  "check-date",
	"date-max-future":             "date-max-future",
	"snapshot":                    "snapshot",
	"signed-by":                   "signed-by",
	"pdiffs":                      "pdiffs",
	"by-hash":                     "by-hash",
	"allow-insecure":              "allow-insecure",
	"allow-weak":                  "allow-weak",
	"allow-downgrade-to-insecure": "allow-downgrade-to-insecure",
}

// parseSources822 is ParseSources822 with the file name for its errors.
func parseSources822(path, content string) ([]Source, error) {
	if len(content) > MaxSourcesFileBytes {
		return nil, tooLargeInput()
	}

	f := &sourceFile{path: path}

	var (
		para      []string
		paraStart int
		inPara    bool
	)

	flush := func() {
		if len(para) > 0 {
			f.parseStanza(paraStart, strings.Join(para, "\n"))
		}

		para = para[:0]
		inPara = false
	}

	for i, line := range strings.Split(content, "\n") {
		if f.full(i + 1) {
			break
		}

		line = strings.TrimRight(line, "\r")

		if strings.TrimSpace(line) == "" {
			flush()

			continue
		}

		if line[0] == '#' {
			continue
		}

		if !inPara {
			paraStart = i + 1
			inPara = true
		}

		para = append(para, line)
	}

	flush()

	return f.sources, errors.Join(f.errs...)
}

// parseStanza handles the text of one deb822 paragraph.
func (f *sourceFile) parseStanza(line int, text string) {
	var cf *deb.ControlFile

	// The scanner is lenient, and a reader over a string cannot fail.
	_ = deb.ScanControl(strings.NewReader(text), func(c *deb.ControlFile) error {
		cf = c

		return nil
	})

	if cf == nil {
		return
	}

	if v, ok := cf.Lookup("Enabled"); ok {
		on, valid := parseSwitch(v)
		if !valid {
			f.fail(line, "Enabled", fmt.Errorf("%w: %q", ErrInvalidOption, v))

			return
		}

		if on == SwitchNo {
			return
		}
	}

	typesValue, ok := cf.Lookup("Types")
	if !ok {
		f.fail(line, "", malformed("stanza has no Types"))

		return
	}

	types, err := splitWords("Types", typesValue)
	if err != nil {
		f.fail(line, "Types", err)

		return
	}

	for _, t := range types {
		if st := SourceType(t); st != TypeDeb && st != TypeDebSrc {
			f.fail(line, "Types", malformed(fmt.Sprintf("unknown type %q", t)))

			return
		}
	}

	uris, err1 := splitWords("URIs", cf.Get("URIs"))
	suites, err2 := splitWords("Suites", cf.Get("Suites"))
	comps, err3 := splitWords("Components", cf.Get("Components"))

	if err := errors.Join(err1, err2, err3); err != nil {
		f.fail(line, "", err)

		return
	}

	switch {
	case len(types) == 0:
		f.fail(line, "Types", malformed("no type"))

		return
	case len(uris) == 0:
		f.fail(line, "URIs", malformed("missing URI"))

		return
	case len(suites) == 0:
		f.fail(line, "Suites", malformed("missing suite"))

		return
	}

	if len(types)*len(uris)*len(suites) > MaxStanzaSources {
		f.fail(line, "", fmt.Errorf("%w: stanza expands to more than %d sources", ErrTooLarge, MaxStanzaSources))

		return
	}

	// The shape of every suite is checked before any source is built, so that
	// a stanza is taken or skipped as a whole.
	for _, s := range suites {
		switch {
		case strings.HasSuffix(s, "/") && len(comps) > 0:
			f.fail(line, "Components", malformed("an exact path suite takes no component"))

			return
		case !strings.HasSuffix(s, "/") && len(comps) == 0:
			f.fail(line, "Components", malformed("missing component"))

			return
		}
	}

	urls := make([]string, len(uris))

	for i, u := range uris {
		if urls[i], err = fixupURI(u); err != nil {
			f.fail(line, "URIs", err)

			return
		}
	}

	proto := Source{}

	var opts []rawOption

	for _, name := range cf.Order {
		low := strings.ToLower(name)

		switch low {
		case "types", "uris", "suites", "components", "enabled":
			continue
		}

		key := deb822Options[low]
		if key == "" {
			key = name
		}

		opts = append(opts, rawOption{key: key, name: name, value: cf.Fields[name]})
	}

	if name, err := applyOptions(&proto, opts, ' '); err != nil {
		f.fail(line, name, err)

		return
	}

	for _, t := range types {
		for _, u := range urls {
			for _, s := range suites {
				src := proto.clone()
				src.Type = SourceType(t)
				src.URL = u
				src.Suite = s
				src.Components = slices.Clone(comps)

				f.sources = append(f.sources, src)
			}
		}
	}
}

// splitWords splits a deb822 list value at blanks and newlines.
func splitWords(name, v string) ([]string, error) {
	words := strings.Fields(v)
	if len(words) == 0 {
		return nil, nil
	}

	if len(words) > MaxSourceListValues {
		return nil, fmt.Errorf("%w: %s lists more than %d values", ErrTooLarge, name, MaxSourceListValues)
	}

	return words, nil
}

// clone copies the slices and the map of s, so that sources expanded from one
// stanza do not share memory.
func (s Source) clone() Source {
	s.Components = slices.Clone(s.Components)
	s.Architectures = slices.Clone(s.Architectures)
	s.ArchitecturesAdd = slices.Clone(s.ArchitecturesAdd)
	s.ArchitecturesRemove = slices.Clone(s.ArchitecturesRemove)
	s.Languages = slices.Clone(s.Languages)
	s.LanguagesAdd = slices.Clone(s.LanguagesAdd)
	s.LanguagesRemove = slices.Clone(s.LanguagesRemove)
	s.Targets = slices.Clone(s.Targets)
	s.TargetsAdd = slices.Clone(s.TargetsAdd)
	s.TargetsRemove = slices.Clone(s.TargetsRemove)
	s.Options = maps.Clone(s.Options)

	return s
}

// applyOptions sets the options on src. sep is ',' for the one-line format and
// ' ' for deb822: how list values are separated. It stops at the first
// invalid value and returns the option's name with the error.
func applyOptions(src *Source, opts []rawOption, sep byte) (string, error) {
	for _, o := range opts {
		if err := applyOption(src, o, sep); err != nil {
			return o.name, err
		}
	}

	return "", nil
}

func applyOption(src *Source, o rawOption, sep byte) error {
	invalid := func(err error) error {
		if errors.Is(err, ErrInvalidOption) || errors.Is(err, ErrInvalidSignedBy) || errors.Is(err, ErrTooLarge) {
			return err
		}

		return fmt.Errorf("%w: %q", ErrInvalidOption, o.value)
	}

	list := func() ([]string, error) { return splitValues(o.value, sep) }

	var err error

	switch o.key {
	case "arch":
		src.Architectures, err = list()
	case "arch+":
		src.ArchitecturesAdd, err = list()
	case "arch-":
		src.ArchitecturesRemove, err = list()
	case "lang":
		src.Languages, err = list()
	case "lang+":
		src.LanguagesAdd, err = list()
	case "lang-":
		src.LanguagesRemove, err = list()
	case "target":
		src.Targets, err = list()
	case "target+":
		src.TargetsAdd, err = list()
	case "target-":
		src.TargetsRemove, err = list()
	case "trusted":
		err = setSwitch(&src.Trusted, o.value)
	case "allow-insecure":
		err = setSwitch(&src.AllowInsecure, o.value)
	case "allow-weak":
		err = setSwitch(&src.AllowWeak, o.value)
	case "allow-downgrade-to-insecure":
		err = setSwitch(&src.AllowDowngradeToInsecure, o.value)
	case "check-valid-until":
		err = setSwitch(&src.CheckValidUntil, o.value)
	case "check-date":
		err = setSwitch(&src.CheckDate, o.value)
	case "pdiffs":
		err = setSwitch(&src.PDiffs, o.value)
	case "valid-until-min":
		src.ValidUntilMin, err = parseSeconds(o.value)
	case "valid-until-max":
		src.ValidUntilMax, err = parseSeconds(o.value)
	case "date-max-future":
		src.DateMaxFuture, err = parseSeconds(o.value)
	case "by-hash":
		src.ByHash, err = parseByHash(o.value)
	case "snapshot":
		src.Snapshot = strings.TrimSpace(o.value)
	case "signed-by":
		src.SignedBy = strings.TrimSpace(o.value)
		if src.SignedBy != "" {
			_, err = parseSignedBy(src.SignedBy)
		}
	default:
		if src.Options == nil {
			src.Options = make(map[string]string)
		}

		src.Options[o.name] = o.value
	}

	if err != nil {
		return invalid(err)
	}

	return nil
}

// splitValues splits a list option at commas (one-line) or blanks (deb822),
// dropping empty values.
func splitValues(v string, sep byte) ([]string, error) {
	var out []string

	if sep == ',' {
		for part := range strings.SplitSeq(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	} else {
		out = strings.Fields(v)
	}

	if len(out) > MaxSourceListValues {
		return nil, fmt.Errorf("%w: more than %d values", ErrTooLarge, MaxSourceListValues)
	}

	return out, nil
}

// parseSwitch reads a boolean as apt's StringToBool does: 0 and 1, and the
// words yes, no, true, false, with, without, on, off, enable and disable in
// any case. valid is false for anything else.
func parseSwitch(v string) (s Switch, valid bool) {
	v = strings.TrimSpace(v)

	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		switch n {
		case 0:
			return SwitchNo, true
		case 1:
			return SwitchYes, true
		}

		return SwitchDefault, false
	}

	for _, w := range []string{"no", "false", "without", "off", "disable"} {
		if strings.EqualFold(v, w) {
			return SwitchNo, true
		}
	}

	for _, w := range []string{"yes", "true", "with", "on", "enable"} {
		if strings.EqualFold(v, w) {
			return SwitchYes, true
		}
	}

	return SwitchDefault, false
}

func setSwitch(dst *Switch, v string) error {
	s, ok := parseSwitch(v)
	if !ok {
		return ErrInvalidOption
	}

	*dst = s

	return nil
}

// parseByHash reads the By-Hash option: yes, no or force, or another boolean
// spelling.
func parseByHash(v string) (ByHashMode, error) {
	if strings.EqualFold(strings.TrimSpace(v), "force") {
		return ByHashForce, nil
	}

	switch s, ok := parseSwitch(v); {
	case !ok:
		return ByHashDefault, ErrInvalidOption
	case s == SwitchYes:
		return ByHashYes, nil
	default:
		return ByHashNo, nil
	}
}

// maxOptionSeconds keeps a seconds option a valid time.Duration.
const maxOptionSeconds = int64(time.Duration(1<<63-1) / time.Second)

// parseSeconds reads a non-negative whole number of seconds.
func parseSeconds(v string) (time.Duration, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 || n > maxOptionSeconds {
		return 0, ErrInvalidOption
	}

	return time.Duration(n) * time.Second, nil
}
