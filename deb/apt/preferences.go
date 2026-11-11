package apt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Bounds on preferences input. apt has none; these keep a hostile or runaway
// file from exhausting memory.
const (
	// maxPreferencesSize is the largest preferences file read, in bytes.
	maxPreferencesSize = 8 << 20
	// maxPreferencesPins is the most pin stanzas one Preferences holds.
	maxPreferencesPins = 1 << 16
	// maxPreferencesFiles is the most files of preferences.d read.
	maxPreferencesFiles = 4096
	// maxPinPriorityText is the longest Pin-Priority value apt parses; a longer
	// one reads as no priority.
	maxPinPriorityText = 299
)

// PriorityNever is the pin priority of "Pin-Priority: never", which keeps a
// version from being selected at all and cannot be overridden by another pin.
const PriorityNever = math.MinInt16

var (
	// ErrPreferences is matched by every [PreferencesError].
	ErrPreferences = errors.New("apt: invalid preferences")
	// ErrNoPackageHeader reports a preferences record without a Package field.
	ErrNoPackageHeader = errors.New("apt: preferences record has no Package header")
	// ErrPinPriority reports a Pin-Priority that is missing, zero, not a number
	// or outside -32768..32767.
	ErrPinPriority = errors.New("apt: invalid Pin-Priority")
	// ErrNeverPin reports "Pin-Priority: never" in a record that is not
	// "Package: *".
	ErrNeverPin = errors.New("apt: Pin-Priority never needs Package: *")
)

// PreferencesError reports a preferences record apt refuses. It matches
// [ErrPreferences] and the reason, one of [ErrNoPackageHeader],
// [ErrPinPriority] or [ErrNeverPin].
type PreferencesError struct {
	// File is the file the record was read from; empty for ParsePreferences.
	File string
	// Record is the 1-based number of the record in the file, counting only
	// records that have a field.
	Record int
	// Package is the Package field of the record, when it has one.
	Package string
	// Value is the offending field value, when there is one.
	Value string
	// Reason is the sentinel that says what is wrong.
	Reason error
}

// Error implements error.
func (e *PreferencesError) Error() string {
	var b strings.Builder

	b.WriteString("apt: preferences")

	if e.File != "" {
		b.WriteString(" ")
		b.WriteString(e.File)
	}

	fmt.Fprintf(&b, " record %d", e.Record)

	if e.Package != "" {
		fmt.Fprintf(&b, " (Package: %s)", e.Package)
	}

	b.WriteString(": ")
	b.WriteString(e.Reason.Error())

	if e.Value != "" {
		fmt.Fprintf(&b, ": %q", e.Value)
	}

	return b.String()
}

// Unwrap lets errors.Is match both [ErrPreferences] and the reason.
func (e *PreferencesError) Unwrap() []error { return []error{ErrPreferences, e.Reason} }

// PinType is what a pin's Pin field selects versions by.
type PinType int

const (
	// PinRelease matches the Release file a version comes from: "a=stable,c=main",
	// a bare archive or codename, a version number, or "*".
	PinRelease PinType = iota
	// PinVersion matches the version string, with the glob rules of apt.
	PinVersion
	// PinSourceVersion matches the version of the source package.
	PinSourceVersion
	// PinOrigin matches the host name of the archive; "" selects local files.
	PinOrigin
)

// String returns the word the Pin field starts with.
func (t PinType) String() string {
	switch t {
	case PinRelease:
		return "release"
	case PinVersion:
		return "version"
	case PinSourceVersion:
		return "source-version"
	case PinOrigin:
		return "origin"
	default:
		return "PinType(" + strconv.Itoa(int(t)) + ")"
	}
}

// Pin is one record of an apt preferences file.
type Pin struct {
	// Packages are the whitespace separated names of the Package field: plain
	// names, globs ("lib*"), regular expressions ("/^lib.*-dev$/"), "src:name"
	// for every binary package built from a source package, and any of them
	// with an architecture ("name:arch"). Nil for "Package: *", which pins
	// package files rather than versions.
	Packages []string
	// Type is the kind of the Pin field.
	Type PinType
	// Data is the rest of the Pin field after its type word.
	Data string
	// Priority is the Pin-Priority; [PriorityNever] for "never".
	Priority int
	// Explanation is the free-form Explanation field.
	Explanation string
}

// Preferences is the content of apt_preferences(5) files, as the ordered pins
// apt applies: the first pin that matches a version wins.
type Preferences struct {
	// Pins in the order apt sees them: /etc/apt/preferences first, then the
	// files of preferences.d by name.
	Pins []Pin
	// Warnings lists what apt only warns about: unknown pin types, a version
	// pin for "Package: *", a missing preferences.d.
	Warnings []string
}

// Add appends the pins and warnings of other.
func (p *Preferences) Add(other *Preferences) {
	if other == nil {
		return
	}

	p.Pins = append(p.Pins, other.Pins...)
	p.Warnings = append(p.Warnings, other.Warnings...)
}

// ParsePreferences reads one preferences file as apt does: records separated by
// blank lines, "#" lines are comments, field names are case-insensitive and a
// record without a Pin field is ignored.
//
// Like apt it stops at the first record it refuses and returns a
// [*PreferencesError] for it; the Preferences is never nil and holds the pins
// read before. A line without a colon ends the file silently, as in apt.
func ParsePreferences(content string) (*Preferences, error) {
	return parsePreferences(content, "")
}

// LoadPreferences reads the preferences file and the "*.pref" files of
// preferences.d (files without extension too; names must be made of letters,
// digits, '_', '-', '.' and ':'). An empty path is skipped and a path that does
// not exist adds nothing, like apt. Files are read in name order and a failing
// file does not stop the next one.
//
// The result is never nil; the error joins one [*PreferencesError] per refused
// record and the I/O errors, and matches [ErrTooLarge] for a file or
// directory over its bound.
func LoadPreferences(file, dir string) (*Preferences, error) {
	out := &Preferences{}

	var errs []error

	if file != "" {
		if err := loadPreferencesFile(out, file); err != nil {
			errs = append(errs, err)
		}
	}

	if dir != "" {
		files, warn, err := preferenceFiles(dir)
		if warn != "" {
			out.Warnings = append(out.Warnings, warn)
		}

		if err != nil {
			errs = append(errs, err)
		}

		for _, f := range files {
			if err := loadPreferencesFile(out, f); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return out, errors.Join(errs...)
}

// loadPreferencesFile appends the pins of one file to out. A file that does
// not exist, or is not a regular file, adds nothing.
func loadPreferencesFile(out *Preferences, path string) error {
	if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
		// apt's RealFileExists: a missing file is not an error.
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("apt: %w", err)
	}

	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxPreferencesSize+1))
	if err != nil {
		return fmt.Errorf("apt: reading %s: %w", path, err)
	}

	if len(data) > maxPreferencesSize {
		return fmt.Errorf("%w: %s over %d bytes", ErrTooLarge, path, maxPreferencesSize)
	}

	prefs, err := parsePreferences(string(data), path)
	out.Add(prefs)

	return err
}

// preferenceFiles lists the files of a preferences.d directory apt reads: the
// ones named *.pref or without extension, sorted by name. warn is apt's
// warning for a directory that cannot be read.
func preferenceFiles(dir string) (files []string, warn string, err error) {
	isDir := false
	if st, serr := os.Stat(dir); serr == nil {
		isDir = st.IsDir()
	}

	if !isDir {
		return nil, "Unable to read " + dir, nil
	}

	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		return nil, "", fmt.Errorf("apt: reading %s: %w", dir, rerr)
	}

	for _, e := range entries {
		if !validPreferenceName(e.Name()) {
			continue
		}

		files = append(files, filepath.Join(dir, e.Name()))
	}

	slices.Sort(files)

	if len(files) > maxPreferencesFiles {
		return nil, "", fmt.Errorf("%w: %s holds more than %d preference files", ErrTooLarge, dir, maxPreferencesFiles)
	}

	return files, "", nil
}

// validPreferenceName applies the file-name rules of apt's
// GetListOfFilesInDir for the extension "pref", no extension allowed.
func validPreferenceName(name string) bool {
	if name == "" || name[0] == '.' {
		return false
	}

	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		if ext := name[i+1:]; ext != "pref" && ext != "" {
			return false
		}
	}

	for i := range len(name) {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '-' || c == ':' || c == '.' {
			continue
		}

		return false
	}

	return name[len(name)-1] != '.'
}

// parsePreferences is ParsePreferences with the file name for error messages.
func parsePreferences(content, file string) (*Preferences, error) {
	out := &Preferences{}

	if len(content) > maxPreferencesSize {
		return out, fmt.Errorf("%w: preferences over %d bytes", ErrTooLarge, maxPreferencesSize)
	}

	record := 0

	var perr error

	scanTagFile([]byte(content), func(sec map[string]string) bool {
		record++

		perr = out.addRecord(sec, file, record)

		return perr == nil
	})

	return out, perr
}

// addRecord turns one record into pins, as apt's ReadPinFile does.
func (p *Preferences) addRecord(sec map[string]string, file string, record int) error {
	fail := func(reason error, value string) error {
		return &PreferencesError{File: file, Record: record, Package: sec["package"], Value: value, Reason: reason}
	}

	name := sec["package"]
	if name == "" {
		return fail(ErrNoPackageHeader, "")
	}

	pinField, ok := sec["pin"]
	if !ok {
		return nil
	}

	kind, data, known := splitPin(pinField, name != "*")
	if !known {
		p.Warnings = append(p.Warnings, "Did not understand pin type "+firstField(pinField))

		return nil
	}

	text := sec["pin-priority"]

	var priority int

	if text == "never" {
		priority = PriorityNever
	} else {
		priority = pinPriorityValue(text)
	}

	if text == "never" && name != "*" {
		return fail(ErrNeverPin, text)
	}

	if priority == PriorityNever && text != "never" {
		priority++
	}

	if priority < math.MinInt16 || priority > math.MaxInt16 {
		return fail(ErrPinPriority, text)
	}

	if priority == 0 {
		return fail(ErrPinPriority, text)
	}

	if len(p.Pins) >= maxPreferencesPins {
		return fmt.Errorf("%w: more than %d pins", ErrTooLarge, maxPreferencesPins)
	}

	pin := Pin{Type: kind, Data: data, Priority: priority, Explanation: sec["explanation"]}
	if name != "*" {
		pin.Packages = strings.Fields(name)
	}

	p.Pins = append(p.Pins, pin)

	return nil
}

// firstField returns s up to its first white space.
func firstField(s string) string {
	if i := strings.IndexFunc(s, isSpaceRune); i >= 0 {
		return s[:i]
	}

	return s
}

func isSpaceRune(r rune) bool { return r == ' ' || (r >= '\t' && r <= '\r') }

// splitPin splits a Pin field into its type and data. A version or
// source-version pin is only understood for a package name (named).
func splitPin(field string, named bool) (kind PinType, data string, ok bool) {
	word := firstField(field)
	data = strings.TrimLeftFunc(field[len(word):], isSpaceRune)

	switch {
	case strings.EqualFold(word, "version") && named:
		return PinVersion, data, true
	case strings.EqualFold(word, "source-version") && named:
		return PinSourceVersion, data, true
	case strings.EqualFold(word, "release"):
		return PinRelease, data, true
	case strings.EqualFold(word, "origin"):
		return PinOrigin, data, true
	default:
		return 0, "", false
	}
}

// pinPriorityValue reads a Pin-Priority the way apt does with strtol: white
// space, a sign, digits, anything after them ignored; no digits, or more than
// 299 bytes, is 0. A value too large for a long saturates, which the range
// check then refuses.
func pinPriorityValue(s string) int {
	if len(s) > maxPinPriorityText {
		return 0
	}

	s = strings.TrimLeftFunc(s, isSpaceRune)

	neg := false

	switch {
	case strings.HasPrefix(s, "-"):
		neg, s = true, s[1:]
	case strings.HasPrefix(s, "+"):
		s = s[1:]
	}

	n := 0

	for i := 0; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n > math.MaxInt32 {
			n = math.MaxInt32

			break
		}
	}

	if neg {
		return -n
	}

	return n
}

// scanTagFile reads a deb822-like file the way apt's tag file reader does with
// comment support, calling yield for every record that has a field until it
// returns false: lines that begin with '#' are dropped, records end at a blank
// line, a field starts on a line that does not begin with white space, a
// continuation line begins with white space, and a later field replaces an
// earlier one of the same (case-insensitive) name. Field values lose their
// trailing white space. A field line without a colon anywhere after it makes
// the reader stop quietly, like apt.
func scanTagFile(data []byte, yield func(map[string]string) bool) {
	data = stripCommentLines(data)
	data = append(data, '\n', '\n')

	for pos := 0; pos < len(data); {
		sec, next, ok := scanSection(data, pos)
		if !ok {
			return
		}

		pos = next

		if len(sec) == 0 {
			continue
		}

		if !yield(sec) {
			return
		}
	}
}

// stripCommentLines removes the lines that start with '#'.
func stripCommentLines(data []byte) []byte {
	if !bytes.Contains(data, []byte("#")) {
		return slices.Clone(data)
	}

	out := make([]byte, 0, len(data)+2)

	for len(data) > 0 {
		line := data
		rest := []byte(nil)

		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, rest = data[:i+1], data[i+1:]
		}

		if line[0] != '#' {
			out = append(out, line...)
		}

		data = rest
	}

	return out
}

func isSpaceByte(c byte) bool { return c == ' ' || (c >= '\t' && c <= '\r') }

// scanSection reads one record starting at start. It returns the fields, the
// offset of the next record and false when the record cannot be read.
func scanSection(data []byte, start int) (map[string]string, int, bool) {
	end := len(data)
	sec := map[string]string{}

	var (
		curKey   string
		curStart int
		open     bool
	)

	closeField := func(valEnd int) {
		if !open {
			return
		}

		v := data[curStart:max(valEnd, curStart)]
		v = bytes.TrimRightFunc(v, func(r rune) bool { return r < 0x80 && isSpaceByte(byte(r)) })
		sec[strings.ToLower(curKey)] = string(v)
		open = false
	}

	stop := start

	for stop < end {
		if !isSpaceByte(data[stop]) {
			closeField(stop)

			colon := bytes.IndexByte(data[stop:end], ':')
			if colon < 0 {
				return nil, end, false
			}

			colon += stop
			endTag := colon - 1

			for endTag > stop && isSpaceByte(data[endTag]) {
				endTag--
			}

			curKey = string(data[stop : endTag+1])

			stop = colon + 1
			for stop < end && isSpaceByte(data[stop]) {
				if data[stop] == '\n' && (stop+1 >= end || data[stop+1] != ' ') {
					break
				}

				stop++
			}

			if stop >= end {
				return nil, end, false
			}

			curStart, open = stop, true
		}

		nl := bytes.IndexByte(data[stop:end], '\n')
		if nl < 0 {
			return nil, end, false
		}

		stop += nl

		for stop+1 < end && data[stop+1] == '\r' {
			stop++
		}

		if stop+1 < end && data[stop+1] == '\n' {
			closeField(stop)

			for stop < end && (data[stop] == '\n' || data[stop] == '\r') {
				stop++
			}

			return sec, stop, true
		}

		stop++
	}

	return nil, end, false
}
