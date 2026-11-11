package apt

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/M0Rf30/pkgformat/deb"
)

// maxReleasePinSpec is the longest release pin apt reads; it copies the
// expression into a 300 byte buffer.
const maxReleasePinSpec = 299

// maxReleasePinFragments is the most comma separated terms of a release pin;
// apt refuses a longer one, and the pin then matches nothing.
const maxReleasePinFragments = 19

// maxPatternLength bounds a package-name pattern or regular expression.
const maxPatternLength = 4096

// statusArchive is the archive apt gives the dpkg status file.
const statusArchive = "now"

// pinFile is a package file of a version as pins see it: one index of a
// Release file, or the dpkg status database.
type pinFile struct {
	rel    *ReleaseInfo
	status bool
}

// fnmatch is fnmatch(3) with FNM_CASEFOLD, as apt matches pin expressions:
// "*", "?", bracket expressions with ranges, classes and negation ("!" or
// "^"), and a backslash that quotes. Nothing is special about "/" or ".".
func fnmatch(pattern, s string) bool {
	var (
		p, i         int
		starP, starI = -1, 0
	)

	for i < len(s) {
		r, w := utf8.DecodeRuneInString(s[i:])

		if p < len(pattern) {
			switch pattern[p] {
			case '*':
				starP, starI = p, i
				p++

				continue
			case '?':
				p++
				i += w

				continue
			case '[':
				if ok, next, valid := matchBracket(pattern, p, r); valid {
					if ok {
						p, i = next, i+w

						continue
					}
				} else if foldRune('[') == foldRune(r) {
					p++
					i += w

					continue
				}
			case '\\':
				if p+1 >= len(pattern) {
					return false
				}

				pr, pw := utf8.DecodeRuneInString(pattern[p+1:])
				if foldRune(pr) == foldRune(r) {
					p += 1 + pw
					i += w

					continue
				}
			default:
				pr, pw := utf8.DecodeRuneInString(pattern[p:])
				if foldRune(pr) == foldRune(r) {
					p += pw
					i += w

					continue
				}
			}
		}

		if starP < 0 {
			return false
		}

		_, sw := utf8.DecodeRuneInString(s[starI:])
		starI += sw
		i = starI
		p = starP + 1
	}

	for p < len(pattern) && pattern[p] == '*' {
		p++
	}

	return p == len(pattern)
}

// foldRune is the case folding fnmatch applies to both sides.
func foldRune(r rune) rune { return unicode.ToLower(r) }

// matchBracket matches r against the bracket expression that starts at
// pattern[p] == '['. valid is false when the expression is not closed, in
// which case the '[' is an ordinary character.
func matchBracket(pattern string, p int, r rune) (matched bool, next int, valid bool) {
	i := p + 1
	negate := false

	if i < len(pattern) && (pattern[i] == '!' || pattern[i] == '^') {
		negate = true
		i++
	}

	first := true
	fr := foldRune(r)

	for {
		if i >= len(pattern) {
			return false, 0, false
		}

		c := pattern[i]
		if c == ']' && !first {
			return matched != negate, i + 1, true
		}

		first = false

		if c == '[' && i+1 < len(pattern) && pattern[i+1] == ':' {
			if end := strings.Index(pattern[i+2:], ":]"); end >= 0 {
				if classMatches(pattern[i+2:i+2+end], r) {
					matched = true
				}

				i += 2 + end + 2

				continue
			}
		}

		lo, w, symbol := bracketRune(pattern, i)
		i += w

		rangeStart := i+1 < len(pattern) && pattern[i] == '-' && pattern[i+1] != ']'
		if symbol && !rangeStart {
			// A collating symbol or equivalence class alone compares the
			// character as it is, without case folding.
			if lo == r {
				matched = true
			}

			continue
		}

		hi := lo

		if rangeStart {
			var hw int

			hi, hw, _ = bracketRune(pattern, i+1)
			i += 1 + hw
		}

		if foldRune(lo) <= fr && fr <= foldRune(hi) {
			matched = true
		}
	}
}

// bracketRune reads one element of a bracket expression at pattern[i], which
// may be a character quoted with a backslash, a collating symbol "[.c.]" or an
// equivalence class "[=c=]" (symbol), and returns it with its width.
func bracketRune(pattern string, i int) (r rune, width int, symbol bool) {
	if pattern[i] == '\\' && i+1 < len(pattern) {
		r, w := utf8.DecodeRuneInString(pattern[i+1:])

		return r, 1 + w, false
	}

	if pattern[i] == '[' && i+1 < len(pattern) && (pattern[i+1] == '.' || pattern[i+1] == '=') {
		closer := pattern[i+1:i+2] + "]"
		if end := strings.Index(pattern[i+2:], closer); end > 0 {
			sym, n := utf8.DecodeRuneInString(pattern[i+2 : i+2+end])
			if n == end {
				return sym, 2 + end + 2, true
			}
		}
	}

	r, width = utf8.DecodeRuneInString(pattern[i:])

	return r, width, false
}

// classMatches reports whether r is in the POSIX character class name. The
// class sees the character as it is: FNM_CASEFOLD does not make upper match
// lower case letters.
func classMatches(name string, r rune) bool {
	switch name {
	case "alpha":
		return unicode.IsLetter(r)
	case "digit":
		return r >= '0' && r <= '9'
	case "alnum":
		return unicode.IsLetter(r) || unicode.IsDigit(r)
	case "upper":
		return unicode.IsUpper(r)
	case "lower":
		return unicode.IsLower(r)
	case "space":
		return r == ' ' || (r >= '\t' && r <= '\r')
	case "blank":
		return r == ' ' || r == '\t'
	case "punct":
		return r < 0x80 && unicode.IsPunct(r) || r < 0x80 && unicode.IsSymbol(r)
	case "print":
		return unicode.IsPrint(r)
	case "graph":
		return unicode.IsGraphic(r) && !unicode.IsSpace(r)
	case "cntrl":
		return unicode.IsControl(r)
	case "xdigit":
		return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
	default:
		return false
	}
}

// expression is a pin expression apt matches with ExpressionMatches: a
// regular expression between slashes, else an fnmatch glob.
type expression struct {
	pattern string
	re      *regexp.Regexp // non-nil for /regex/
	isRegex bool
}

// newExpression compiles a pin expression. An invalid regular expression
// matches nothing, as apt warns about it and does not match.
func newExpression(pattern string) expression {
	e := expression{pattern: pattern}

	if len(pattern) >= 2 && pattern[0] == '/' && pattern[len(pattern)-1] == '/' {
		e.isRegex = true

		if len(pattern) <= maxPatternLength {
			if translated, ok := translateERE(pattern[1 : len(pattern)-1]); ok {
				if re, err := regexp.Compile(translated); err == nil {
					e.re = re
				}
			}
		}
	}

	return e
}

// translateERE rewrites a POSIX extended regular expression as glibc reads it
// (apt compiles pin regular expressions with REG_EXTENDED | REG_ICASE) into
// the syntax of package regexp, which differs in a few places: stacked
// repetitions, "{,n}" intervals, repetition operators with nothing to repeat,
// "\<" and "\>" word anchors, a backslash before an ordinary letter, "(?"
// groups, and a backslash inside a bracket expression. It reports false for
// expressions glibc rejects.
func translateERE(src string) (string, bool) {
	t := ereTranslator{src: src}
	t.out.WriteString("(?is)")

	for t.pos < len(t.src) {
		if !t.step() {
			return "", false
		}
	}

	if t.depth != 0 {
		return "", false
	}

	t.flush()

	return t.out.String(), true
}

type ereTranslator struct {
	src     string
	pos     int
	out     strings.Builder
	atom    bool // an operand precedes, so a repetition operator applies to it
	pending byte // a repetition operator read but not yet written
	depth   int
}

// flush writes the pending repetition operator.
func (t *ereTranslator) flush() {
	if t.pending != 0 {
		t.out.WriteByte(t.pending)
		t.pending = 0
	}
}

// operand writes a complete operand.
func (t *ereTranslator) operand(s string) {
	t.flush()
	t.out.WriteString(s)
	t.atom = true
}

// step translates one token.
func (t *ereTranslator) step() bool {
	r, w := utf8.DecodeRuneInString(t.src[t.pos:])
	t.pos += w

	switch r {
	case '\\':
		return t.escape()
	case '[':
		return t.bracket()
	case '(':
		t.flush()
		t.depth++
		t.out.WriteByte('(')

		if strings.HasPrefix(t.src[t.pos:], "?") {
			t.out.WriteString(`\?`)
			t.pos++
		}

		t.atom = false
	case ')':
		if t.depth == 0 {
			return false
		}

		t.depth--
		t.flush()
		t.out.WriteByte(')')
		t.atom = true
	case '|':
		t.flush()
		t.out.WriteByte('|')

		t.atom = false
	case '*', '+', '?':
		if !t.atom {
			t.operand(`\` + string(r))

			return true
		}

		switch {
		case t.pending == 0:
			t.pending = byte(r)
		case t.pending != byte(r):
			t.pending = '*'
		}
	case '{':
		return t.interval()
	case '^':
		t.flush()
		t.out.WriteByte('^')

		t.atom = false
	case '$':
		t.flush()
		t.out.WriteByte('$')

		t.atom = false
	case '.':
		t.operand(".")
	default:
		t.operand(regexp.QuoteMeta(string(r)))
	}

	return true
}

// interval translates "{m}", "{m,}", "{m,n}" and glibc's "{,n}".
func (t *ereTranslator) interval() bool {
	end := strings.IndexByte(t.src[t.pos:], '}')
	if end < 0 || !t.atom {
		return false
	}

	body := t.src[t.pos : t.pos+end]
	lo, hi, comma := body, "", false

	if i := strings.IndexByte(body, ','); i >= 0 {
		lo, hi, comma = body[:i], body[i+1:], true
	}

	if !allDigits(lo) || !allDigits(hi) || lo == "" && (!comma || hi == "") {
		return false
	}

	if lo == "" {
		lo = "0"
	}

	t.flush()
	t.out.WriteString("{" + lo)

	if comma {
		t.out.WriteString("," + hi)
	}

	t.out.WriteByte('}')

	t.pos += end + 1

	return true
}

func allDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}

// escape translates a backslash sequence.
func (t *ereTranslator) escape() bool {
	if t.pos >= len(t.src) {
		return false
	}

	r, w := utf8.DecodeRuneInString(t.src[t.pos:])
	t.pos += w

	switch {
	case r == '<' || r == '>':
		t.flush()
		t.out.WriteString(`\b`)

		t.atom = false
	case r == '`':
		t.flush()
		t.out.WriteString(`\A`)

		t.atom = false
	case r == '\'':
		t.flush()
		t.out.WriteString(`\z`)

		t.atom = false
	case r == 'w':
		t.operand(`[\p{L}\p{Nd}_]`)
	case r == 'W':
		t.operand(`[^\p{L}\p{Nd}_]`)
	case r == 's' || r == 'S' || r == 'b' || r == 'B':
		t.operand(`\` + string(r))
	case r >= '1' && r <= '9':
		// A back-reference: not expressible, so never matching.
		return false
	case r >= 'a' && r <= 'z':
		// glibc reads a backslash before any other lower-case letter as an
		// escape that never matches.
		return false
	default:
		t.operand(regexp.QuoteMeta(string(r)))
	}

	return true
}

// bracket translates a bracket expression; the opening "[" is consumed.
func (t *ereTranslator) bracket() bool {
	var b strings.Builder

	b.WriteByte('[')

	if strings.HasPrefix(t.src[t.pos:], "^") {
		b.WriteByte('^')

		t.pos++
	}

	first := true

	for t.pos < len(t.src) {
		rest := t.src[t.pos:]

		switch {
		case rest[0] == ']' && !first:
			t.pos++
			b.WriteByte(']')
			t.operand(b.String())

			return true
		case strings.HasPrefix(rest, "[:"):
			end := strings.Index(rest, ":]")
			if end < 0 {
				return false
			}

			b.WriteString(regexpClass(rest[2:end]))
			t.pos += end + 2
		case strings.HasPrefix(rest, "[.") || strings.HasPrefix(rest, "[="):
			closer := string(rest[1]) + "]"

			end := strings.Index(rest[2:], closer)
			if end < 0 {
				return false
			}

			b.WriteString(regexp.QuoteMeta(rest[2 : 2+end]))
			t.pos += 2 + end + 2
		default:
			r, w := utf8.DecodeRuneInString(rest)
			t.pos += w

			switch r {
			case '\\', '[', ']':
				b.WriteByte('\\')
				b.WriteRune(r)
			default:
				b.WriteRune(r)
			}
		}

		first = false
	}

	return false
}

// matches reports whether s satisfies the expression.
func (e expression) matches(s string) bool {
	if e.isRegex {
		return e.re != nil && e.re.MatchString(s)
	}

	return fnmatch(e.pattern, s)
}

// rejects reports whether s fails the expression; a field the Release file
// does not have (empty) always fails.
func (e expression) rejects(s string) bool {
	return s == "" || !e.matches(s)
}

// matchVer is apt's MatchVer: b equals a, ignoring case, or with prefix is a
// prefix of it.
func matchVer(a, b string, prefix bool) bool {
	if len(a) != len(b) && !prefix || len(a) < len(b) {
		return false
	}

	return strings.EqualFold(a[:len(b)], b)
}

// pinTerms records which terms a release pin gave.
type pinTerms struct{ ver, origin, archive, codename, label, component, arch, release bool }

// any reports whether at least one term is present.
func (t pinTerms) any() bool {
	return t.ver || t.origin || t.archive || t.codename || t.label || t.release || t.component || t.arch
}

// pinSpec is the compiled Data of a pin.
type pinSpec struct {
	kind PinType

	// PinVersion, PinSourceVersion: the version string, glob-chopped.
	ver       expression
	verPrefix bool

	// PinRelease.
	matchAll  bool
	relVer    expression
	relPrefix bool
	// the terms of a release pin; "" means the term is absent.
	origin, archive, codename, label, component, arch, release expression
	has                                                        pinTerms

	// PinOrigin: the site.
	site expression
}

// newPinSpec compiles the Data of a pin of the given type, following apt's
// pkgVersionMatch constructor.
func newPinSpec(kind PinType, data string) *pinSpec {
	s := &pinSpec{kind: kind}

	if data == "" {
		return s
	}

	switch kind {
	case PinVersion, PinSourceVersion:
		if strings.HasSuffix(data, "*") {
			s.verPrefix = true
			data = data[:len(data)-1]
		}

		s.ver = newExpression(data)
	case PinOrigin:
		if len(data) >= 2 && data[0] == '"' && data[len(data)-1] == '"' {
			data = data[1 : len(data)-1]
		}

		s.site = newExpression(data)
	case PinRelease:
		s.parseRelease(data)
	}

	return s
}

// parseRelease reads a release pin: "*", a bare archive, codename or version,
// or comma separated "v=", "o=", "a=", "n=", "l=", "c=" and "b=" terms.
func (s *pinSpec) parseRelease(data string) {
	if data == "*" {
		s.matchAll = true

		return
	}

	if !strings.Contains(data, "=") {
		if data[0] >= '0' && data[0] <= '9' {
			s.setRelVer(data)
		} else {
			s.release, s.has.release = newExpression(data), true
		}

		return
	}

	if len(data) > maxReleasePinSpec {
		data = data[:maxReleasePinSpec]
	}

	// More fragments than fit makes apt give up, leaving a pin without any
	// term: it matches no Release file, but the dpkg status file (apt sets
	// the "no match" marker on a shadowed copy of its type).
	frags, ok := tokSplit(data, maxReleasePinFragments)
	if !ok {
		return
	}

	for _, f := range frags {
		if len(f) < 3 {
			continue
		}

		val := f[2:]

		switch strings.ToLower(f[:2]) {
		case "v=":
			s.relVer, s.relPrefix, s.has.ver = expression{}, false, false
			s.setRelVer(val)
		case "o=":
			s.origin, s.has.origin = newExpression(val), true
		case "a=":
			s.archive, s.has.archive = newExpression(val), true
		case "n=":
			s.codename, s.has.codename = newExpression(val), true
		case "l=":
			s.label, s.has.label = newExpression(val), true
		case "c=":
			s.component, s.has.component = newExpression(val), true
		case "b=":
			s.arch, s.has.arch = newExpression(val), true
		}
	}
}

// setRelVer records the version term of a release pin; a trailing "*" makes
// it a prefix.
func (s *pinSpec) setRelVer(v string) {
	if strings.HasSuffix(v, "*") {
		s.relPrefix = true
		v = v[:len(v)-1]
	}

	s.relVer, s.has.ver = newExpression(v), v != ""
}

// tokSplit is apt's TokSplitString for ',': fragments are separated by runs
// of commas and white space, which are also trimmed from their ends. It
// reports false for more than max fragments.
func tokSplit(s string, maxFrags int) ([]string, bool) {
	s = strings.TrimLeftFunc(s, isSpaceRune)

	var frags []string

	pos, start := 0, 0

	for pos != len(s) {
		for pos != len(s) && s[pos] != ',' {
			pos++
		}

		end := pos
		for end > start && (s[end-1] == ',' || isSpaceByte(s[end-1])) {
			end--
		}

		frags = append(frags, s[start:end])
		if len(frags) > maxFrags {
			return nil, false
		}

		for pos != len(s) && (s[pos] == ',' || isSpaceByte(s[pos])) {
			pos++
		}

		start = pos
	}

	return frags, true
}

// matchRelease is the Release-file half of FileMatch.
func (s *pinSpec) matchRelease(r *ReleaseInfo) bool {
	if s.matchAll {
		return true
	}

	if !s.has.any() {
		return false
	}

	if s.has.ver && (r.Version == "" || !s.matchRelVer(r.Version)) {
		return false
	}

	if s.has.origin && s.origin.rejects(r.Origin) {
		return false
	}

	if s.has.archive && s.archive.rejects(r.Suite) {
		return false
	}

	if s.has.codename && s.codename.rejects(r.Codename) {
		return false
	}

	if s.has.release &&
		s.release.rejects(r.Suite) && s.release.rejects(r.Codename) {
		return false
	}

	if s.has.label && s.label.rejects(r.Label) {
		return false
	}

	return true
}

// matchRelVer applies the version term of a release pin to a Release Version.
func (s *pinSpec) matchRelVer(v string) bool {
	return matchVer(v, s.relVer.pattern, s.relPrefix) || s.relVer.matches(v)
}

// matchFile is pkgVersionMatch::FileMatch for a package file.
func (s *pinSpec) matchFile(f pinFile) bool {
	switch s.kind {
	case PinRelease:
		if f.status {
			return s.matchStatus()
		}

		if !s.matchRelease(f.rel) {
			return false
		}

		if s.matchAll {
			return true
		}

		if s.has.component && s.component.rejects(f.rel.Component) {
			return false
		}

		if s.has.arch && s.arch.rejects(f.rel.Architecture) {
			return false
		}

		return true
	case PinOrigin:
		if f.status {
			return false
		}

		return s.site.matches(f.rel.Site)
	default:
		return false
	}
}

// matchStatus matches a release pin against the dpkg status file, which has
// no Release file: apt files it under the archive and component "now".
func (s *pinSpec) matchStatus() bool {
	if s.has.archive && !s.archive.matches(statusArchive) {
		return false
	}

	if s.has.release && !s.release.matches(statusArchive) {
		return false
	}

	if s.has.origin || s.has.label || s.has.ver || s.has.codename {
		return false
	}

	if s.matchAll {
		return true
	}

	if s.has.component && !s.component.matches(statusArchive) {
		return false
	}

	return !s.has.arch
}

// matchVersion is pkgVersionMatch::VersionMatches: a version string pin
// compares strings, the others ask whether any package file of the version
// matches.
func (s *pinSpec) matchVersion(v *PackageInfo, files []pinFile) bool {
	switch s.kind {
	case PinVersion:
		return s.matchVersionString(v.Version)
	case PinSourceVersion:
		return s.matchVersionString(sourceVersionOf(v))
	default:
		for _, f := range files {
			if s.matchFile(f) {
				return true
			}
		}

		return false
	}
}

func (s *pinSpec) matchVersionString(v string) bool {
	return matchVer(v, s.ver.pattern, s.verPrefix) || s.ver.matches(v)
}

// sourceNameOf is the name of the source package of v.
func sourceNameOf(v *PackageInfo) string {
	if v.SourceName != "" {
		return v.SourceName
	}

	return v.Name
}

// sourceVersionOf is the version of the source package of v.
func sourceVersionOf(v *PackageInfo) string {
	if v.SourceVersion != "" {
		return v.SourceVersion
	}

	return v.Version
}

// namePin is one name of a Package field.
type namePin struct {
	source   bool
	arch     string
	name     string
	wildcard bool
	expr     expression
}

// newNamePin parses one token of a Package field the way apt's CreatePin does:
// a "src:" prefix, an architecture after the last colon, and a glob or
// regular expression when it has a wildcard character or is written between
// slashes.
func newNamePin(token string) namePin {
	n := namePin{}

	if rest, ok := strings.CutPrefix(token, "src:"); ok {
		n.source = true
		token = rest
	}

	if i := strings.LastIndexByte(token, ':'); i >= 0 {
		n.arch = token[i+1:]
		token = token[:i]
	}

	n.name = token
	n.wildcard = len(token) >= 2 && token[0] == '/' && token[len(token)-1] == '/' ||
		strings.ContainsAny(token, "*[?")

	if n.wildcard {
		n.expr = newExpression(token)
	}

	return n
}

// matches reports whether the pin names the package of v, on the architecture
// the pin selects (the native one by default).
func (n *namePin) matches(v *PackageInfo, native string) bool {
	name := v.Name
	if n.source {
		name = sourceNameOf(v)
	}

	if n.wildcard {
		if name == n.name || !n.expr.matches(name) {
			return false
		}
	} else if name != n.name {
		return false
	}

	spec := n.arch
	if spec == "" {
		spec = native
	}

	return archSelected(v.Architecture, spec, native)
}

// archSelected reports whether a version of the given architecture is on the
// architecture spec of a pin. A version of architecture all belongs to the
// package of the native architecture, so only a spec selecting that one
// reaches it.
func archSelected(arch, spec, native string) bool {
	if strings.EqualFold(arch, archAll) {
		arch = native
	}

	return deb.ArchMatches(arch, wildcardArch(spec))
}

// wildcardArch spells the "*" parts of an architecture pattern as "any", the
// wildcard the architecture matcher knows.
func wildcardArch(spec string) string {
	if !strings.Contains(spec, "*") {
		return spec
	}

	parts := strings.Split(spec, "-")
	for i, p := range parts {
		if p == "*" {
			parts[i] = deb.ArchAny
		}
	}

	return strings.Join(parts, "-")
}

// regexpClass is a POSIX character class name as package regexp writes it
// inside a bracket expression. Under REG_ICASE the upper and lower classes
// accept any letter, and classes are not restricted to ASCII.
func regexpClass(name string) string {
	switch name {
	case "alpha", "upper", "lower":
		return `\p{L}`
	case "alnum":
		return `\p{L}\p{Nd}`
	default:
		return "[:" + name + ":]"
	}
}
