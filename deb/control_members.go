package deb

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
)

// maxMemberLines bounds the lines read from one control member (triggers,
// shlibs, symbols); a control file is limited to MaxControlFileSize bytes,
// this keeps a file of empty lines from costing more than it should.
const maxMemberLines = 1 << 18

// ---------------------------------------------------------------------------
// triggers

// TriggerAwait tells whether the package that activates a trigger waits for
// the triggered package, or whether a package that is interested in a trigger
// makes the activating one wait.
type TriggerAwait int

// The values of TriggerAwait. The zero value writes no suffix: dpkg treats it
// as "await".
const (
	AwaitDefault TriggerAwait = iota
	AwaitYes
	AwaitNo
)

// Trigger is one line of the triggers control file, deb-triggers(5): a package
// declares an interest in a trigger name or activates one.
type Trigger struct {
	// Activate is true for "activate" lines and false for "interest" lines.
	Activate bool
	// Await is the "-await" or "-noawait" suffix of the directive, if any.
	Await TriggerAwait
	// Name is the trigger name: an absolute path for a file trigger, any
	// other word for an explicit trigger.
	Name string
}

// String renders the trigger as one line of the triggers file, without the
// final newline.
func (t Trigger) String() string {
	d := "interest"
	if t.Activate {
		d = "activate"
	}

	switch t.Await {
	case AwaitYes:
		d += "-await"
	case AwaitNo:
		d += "-noawait"
	case AwaitDefault:
	}

	return d + " " + t.Name
}

// validTriggerName follows dpkg: a trigger name is not empty and holds no
// blank or control character.
func validTriggerName(name string) bool {
	if name == "" {
		return false
	}

	for _, r := range name {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}

	return true
}

func parseTriggerDirective(d string) (activate bool, await TriggerAwait, ok bool) {
	base, suffix, hasSuffix := strings.Cut(d, "-")

	switch base {
	case "interest":
	case "activate":
		activate = true
	default:
		return false, AwaitDefault, false
	}

	if !hasSuffix {
		return activate, AwaitDefault, true
	}

	switch suffix {
	case "await":
		return activate, AwaitYes, true
	case "noawait":
		return activate, AwaitNo, true
	}

	return false, AwaitDefault, false
}

// ParseTriggers parses a triggers control file. Blank lines and lines starting
// with "#" are skipped. A malformed line fails with ErrInvalidControlFormat.
func ParseTriggers(r io.Reader) ([]Trigger, error) {
	var out []Trigger

	err := scanMemberLines(r, func(n int, line string) error {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return fmt.Errorf("%w: triggers line %d: want \"directive name\"", ErrInvalidControlFormat, n)
		}

		activate, await, ok := parseTriggerDirective(fields[0])
		if !ok {
			return fmt.Errorf("%w: triggers line %d: unknown directive %q", ErrInvalidControlFormat, n, fields[0])
		}

		if !validTriggerName(fields[1]) {
			return fmt.Errorf("%w: triggers line %d: invalid trigger name %q", ErrInvalidControlFormat, n, fields[1])
		}

		out = append(out, Trigger{Activate: activate, Await: await, Name: fields[1]})

		return nil
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// FormatTriggers renders triggers as the content of a triggers control file.
func FormatTriggers(triggers []Trigger) string {
	var sb strings.Builder

	for _, t := range triggers {
		sb.WriteString(t.String())
		sb.WriteByte('\n')
	}

	return sb.String()
}

func (t Trigger) validate() error {
	if !validTriggerName(t.Name) {
		return invalidSpec("trigger name %q is empty or holds a blank", t.Name)
	}

	if t.Await < AwaitDefault || t.Await > AwaitNo {
		return invalidSpec("trigger %q has an unknown await value %d", t.Name, int(t.Await))
	}

	return nil
}

// ---------------------------------------------------------------------------
// shlibs

// Shlib is one line of the shlibs control file, deb-shlibs(5): the shared
// library the package provides and the dependency a package linking with it
// needs.
type Shlib struct {
	// Type is the package type the line is for: "" for a deb, "udeb" for
	// udebs ("udeb: libfoo 1 libfoo-udeb").
	Type string
	// Library is the name of the library as in its soname without ".so.N":
	// "libfoo" for libfoo.so.1.
	Library string
	// Version is the soname version, "1" for libfoo.so.1.
	Version string
	// Dependencies is the dependency a package linking with the library gets:
	// "libfoo1 (>= 1.2)".
	Dependencies []Alternatives
}

// String renders the line of the shlibs file, without the final newline.
func (s Shlib) String() string {
	line := s.Library + " " + s.Version + " " + FormatRelations(s.Dependencies)
	if s.Type != "" {
		line = s.Type + ": " + line
	}

	return line
}

func (s Shlib) validate() error {
	if s.Type != "" && s.Type != "udeb" && s.Type != "deb" {
		return invalidSpec("shlibs type %q is not deb or udeb", s.Type)
	}

	if s.Library == "" || strings.ContainsFunc(s.Library, unicode.IsSpace) || strings.Contains(s.Library, ":") {
		return invalidSpec("shlibs library name %q is empty or holds a blank or colon", s.Library)
	}

	if s.Version == "" || strings.ContainsFunc(s.Version, unicode.IsSpace) {
		return invalidSpec("shlibs version %q is empty or holds a blank", s.Version)
	}

	if len(s.Dependencies) == 0 {
		return invalidSpec("shlibs line for %s %s has no dependency", s.Library, s.Version)
	}

	return validateRelations("shlibs dependency", s.Dependencies, relationRules{alternatives: true, archQualifier: true})
}

// ParseShlibs parses a shlibs control file. Blank lines and "#" comments are
// skipped. A malformed line fails with ErrInvalidControlFormat.
func ParseShlibs(r io.Reader) ([]Shlib, error) {
	var out []Shlib

	err := scanMemberLines(r, func(n int, line string) error {
		var s Shlib

		if typ, rest, ok := strings.Cut(line, ":"); ok && !strings.ContainsFunc(typ, unicode.IsSpace) {
			s.Type, line = typ, strings.TrimSpace(rest)
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			return fmt.Errorf("%w: shlibs line %d: want \"library version dependencies\"", ErrInvalidControlFormat, n)
		}

		s.Library, s.Version = fields[0], fields[1]

		// The dependencies are what follows the version, kept as written.
		rest := strings.TrimSpace(line[strings.Index(line, fields[1])+len(fields[1]):])

		deps, err := ParseRelations(rest)
		if err != nil {
			return fmt.Errorf("shlibs line %d: %w", n, err)
		}

		s.Dependencies = deps
		out = append(out, s)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// FormatShlibs renders shlibs as the content of a shlibs control file.
func FormatShlibs(shlibs []Shlib) string {
	var sb strings.Builder

	for _, s := range shlibs {
		sb.WriteString(s.String())
		sb.WriteByte('\n')
	}

	return sb.String()
}

// ---------------------------------------------------------------------------
// symbols

// Symbol is one symbol line of a symbols file.
type Symbol struct {
	// Name is the symbol as written, with its tags and quotes when it has
	// them: "foo@Base", `(c++|optional)"bar(int)@Base"`.
	Name string
	// MinVersion is the version of the library that introduced the symbol.
	MinVersion string
	// Template is the index of the alternative dependency template the symbol
	// refers to, or -1 for the main one (no third column).
	Template int
}

func (s Symbol) String() string {
	line := " " + s.Name + " " + s.MinVersion
	if s.Template >= 0 {
		line += " " + strconv.Itoa(s.Template)
	}

	return line
}

// SymbolsLibrary is one library block of a symbols file, deb-symbols(5).
type SymbolsLibrary struct {
	// SOName is the soname of the library: "libfoo.so.1".
	SOName string
	// Dependency is the main dependency template: "libfoo1 #MINVER#".
	Dependency string
	// Alternatives are the alternative dependency templates, the "| ..."
	// lines.
	Alternatives []string
	// Fields are the "* Field: value" lines, such as Build-Depends-Package.
	Fields []Field
	// Symbols are the symbols the library exports.
	Symbols []Symbol
}

func (l SymbolsLibrary) validate() error {
	if l.SOName == "" || strings.ContainsFunc(l.SOName, unicode.IsSpace) {
		return invalidSpec("symbols soname %q is empty or holds a blank", l.SOName)
	}

	oneLine := func(what, v string) error {
		if v == "" || strings.ContainsAny(v, "\r\n") || strings.TrimSpace(v) != v {
			return invalidSpec("symbols %s %q is empty, padded or holds a line break", what, v)
		}

		return nil
	}

	if err := oneLine("dependency template", l.Dependency); err != nil {
		return err
	}

	for _, a := range l.Alternatives {
		if err := oneLine("alternative template", a); err != nil {
			return err
		}
	}

	for _, f := range l.Fields {
		if err := validFieldName(f.Name); err != nil {
			return err
		}

		if err := oneLine("field value", f.Value); err != nil {
			return err
		}
	}

	for _, s := range l.Symbols {
		if err := oneLine("symbol", s.Name); err != nil {
			return err
		}

		if err := oneLine("symbol version", s.MinVersion); err != nil {
			return err
		}

		if strings.ContainsFunc(s.MinVersion, unicode.IsSpace) {
			return invalidSpec("symbol version %q holds a blank", s.MinVersion)
		}

		if s.Template < -1 || s.Template > len(l.Alternatives) {
			return invalidSpec("symbol %q refers to template %d of %d", s.Name, s.Template, len(l.Alternatives)+1)
		}

		if !validSymbolName(s.Name) {
			return invalidSpec("symbol name %q is not a plain or quoted symbol", s.Name)
		}
	}

	return nil
}

// validSymbolName accepts a plain word, or [(tags)]"quoted name" where the
// quoted part may hold blanks.
func validSymbolName(name string) bool {
	_, _, ok := splitSymbolName(name)

	return ok
}

// splitSymbolName cuts the symbol name off the front of s and returns it and
// the remaining text.
func splitSymbolName(s string) (name, rest string, ok bool) {
	i := 0

	if strings.HasPrefix(s, "(") {
		end := strings.IndexByte(s, ')')
		if end < 0 {
			return "", "", false
		}

		i = end + 1
	}

	if i < len(s) && s[i] == '"' {
		end := strings.IndexByte(s[i+1:], '"')
		if end < 0 {
			return "", "", false
		}

		i += end + 2

		return s[:i], strings.TrimLeft(s[i:], " \t"), i == len(s) || s[i] == ' ' || s[i] == '\t'
	}

	end := strings.IndexAny(s[i:], " \t")
	if end < 0 {
		return s, "", s != ""
	}

	return s[:i+end], strings.TrimLeft(s[i+end:], " \t"), i+end > 0
}

// FormatSymbols renders libraries as the content of a symbols control file.
func FormatSymbols(libs []SymbolsLibrary) string {
	var sb strings.Builder

	for _, l := range libs {
		sb.WriteString(l.SOName + " " + l.Dependency + "\n")

		for _, a := range l.Alternatives {
			sb.WriteString("| " + a + "\n")
		}

		for _, f := range l.Fields {
			sb.WriteString("* " + f.Name + ": " + f.Value + "\n")
		}

		for _, s := range l.Symbols {
			sb.WriteString(s.String() + "\n")
		}
	}

	return sb.String()
}

// ParseSymbols parses a symbols control file. Blank lines and "#" comments
// are skipped. A malformed line fails with ErrInvalidControlFormat.
func ParseSymbols(r io.Reader) ([]SymbolsLibrary, error) {
	var (
		out []SymbolsLibrary
		cur *SymbolsLibrary
	)

	err := scanMemberLines(r, func(n int, raw string) error {
		line := strings.TrimRight(raw, " \t")

		switch {
		case raw[0] == ' ' || raw[0] == '\t':
			if cur == nil {
				return fmt.Errorf("%w: symbols line %d: symbol before any library", ErrInvalidControlFormat, n)
			}

			name, rest, ok := splitSymbolName(strings.TrimLeft(line, " \t"))
			if !ok {
				return fmt.Errorf("%w: symbols line %d: bad symbol name", ErrInvalidControlFormat, n)
			}

			cols := strings.Fields(rest)
			if len(cols) < 1 || len(cols) > 2 {
				return fmt.Errorf("%w: symbols line %d: want \"symbol version [template]\"", ErrInvalidControlFormat, n)
			}

			sym := Symbol{Name: name, MinVersion: cols[0], Template: -1}

			if len(cols) == 2 {
				t, err := strconv.Atoi(cols[1])
				if err != nil || t < 0 {
					return fmt.Errorf("%w: symbols line %d: bad template index %q", ErrInvalidControlFormat, n, cols[1])
				}

				sym.Template = t
			}

			cur.Symbols = append(cur.Symbols, sym)
		case strings.HasPrefix(line, "|"):
			if cur == nil {
				return fmt.Errorf("%w: symbols line %d: template before any library", ErrInvalidControlFormat, n)
			}

			cur.Alternatives = append(cur.Alternatives, strings.TrimSpace(line[1:]))
		case strings.HasPrefix(line, "*"):
			if cur == nil {
				return fmt.Errorf("%w: symbols line %d: field before any library", ErrInvalidControlFormat, n)
			}

			name, value, ok := strings.Cut(strings.TrimSpace(line[1:]), ":")
			if !ok || validFieldName(strings.TrimSpace(name)) != nil {
				return fmt.Errorf("%w: symbols line %d: bad field", ErrInvalidControlFormat, n)
			}

			cur.Fields = append(cur.Fields, Field{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
		default:
			soname, dep, ok := strings.Cut(line, " ")
			if !ok || strings.TrimSpace(dep) == "" {
				return fmt.Errorf("%w: symbols line %d: want \"soname dependency-template\"", ErrInvalidControlFormat, n)
			}

			out = append(out, SymbolsLibrary{SOName: soname, Dependency: strings.TrimSpace(dep)})
			cur = &out[len(out)-1]
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// scanMemberLines calls fn with the 1-based number and the text of every
// line of r that is neither blank nor a "#" comment, leading blanks kept.
// The line is never empty.
func scanMemberLines(r io.Reader, fn func(n int, line string) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), MaxLineBytes)

	n := 0

	for sc.Scan() {
		n++
		if n > maxMemberLines {
			return fmt.Errorf("%w: more than %d lines", ErrTooLarge, maxMemberLines)
		}

		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		if err := fn(n, line); err != nil {
			return err
		}
	}

	if err := sc.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidControlFormat, err)
	}

	return nil
}
