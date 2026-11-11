package apt

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
)

// MaxExtendedStatesBytes bounds the extended states file Load reads. A system
// with tens of thousands of automatically installed packages writes well
// under a megabyte.
const MaxExtendedStatesBytes = 32 << 20

// maxExtendedStates bounds how many "Package" paragraphs of the file are
// applied, so that a hostile file cannot make Load spend unbounded time.
const maxExtendedStates = 1 << 20

// ErrTooManyExtendedStates reports an extended states file with more than
// 1048576 paragraphs.
var ErrTooManyExtendedStates = errors.New("apt: too many paragraphs in the extended states file")

// ExtendedStatesError is the error Load joins for an extended states file it
// could not read: the file is unreadable, over [MaxExtendedStatesBytes]
// ([ErrTooLarge]), or holds more than 1048576 paragraphs
// ([ErrTooManyExtendedStates]). A missing file is not an error: apt treats it
// as no package being automatic.
type ExtendedStatesError struct {
	// Path is the file.
	Path string
	// Err is the cause.
	Err error
}

// Error names the file and the cause.
func (e *ExtendedStatesError) Error() string {
	return fmt.Sprintf("apt: extended states %s: %v", e.Path, e.Err)
}

// Unwrap exposes the cause to errors.Is and errors.As.
func (e *ExtendedStatesError) Unwrap() error { return e.Err }

// ParseExtendedStates reads the paragraphs of an apt extended states file
// (/var/lib/apt/extended_states) that carry a positive "Auto-Installed" field,
// as apt's readStateFile does. The architecture is "" for a paragraph without
// an Architecture field, which covers every architecture of the name. A
// paragraph without a Package, or whose Auto-Installed is absent, zero,
// negative or not a number, marks nothing. It fails with
// [ErrTooManyExtendedStates] for a file with more than 1048576 paragraphs.
func ParseExtendedStates(data []byte) ([]AutoMark, error) {
	var out []AutoMark

	count := 0

	err := deb.ScanControl(bytes.NewReader(data), func(cf *deb.ControlFile) error {
		count++
		if count > maxExtendedStates {
			return ErrTooManyExtendedStates
		}

		name := strings.TrimSpace(cf.Get("Package"))
		if name == "" {
			return nil
		}

		if !positive(cf.Get("Auto-Installed")) {
			return nil
		}

		out = append(out, AutoMark{Package: name, Architecture: strings.TrimSpace(cf.Get("Architecture"))})

		return nil
	})
	if err != nil {
		return nil, err //nolint:wrapcheck // ErrTooManyExtendedStates or a read error of the in-memory data
	}

	return out, nil
}

// positive reports a field value that is a number above zero.
func positive(s string) bool {
	v, err := strconv.Atoi(strings.TrimSpace(s))

	return err == nil && v > 0
}

// AutoMark is one package that an extended states file marks as automatically
// installed.
type AutoMark struct {
	// Package is the package name.
	Package string
	// Architecture is the Architecture of the paragraph; "" means every
	// architecture of the package.
	Architecture string
}

// loadExtendedStates marks the installed versions the file names as
// automatically installed. A missing file marks nothing.
func (c *Cache) loadExtendedStates(path string) error {
	data, err := readLocal(path, MaxExtendedStatesBytes)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}

		return &ExtendedStatesError{Path: path, Err: err}
	}

	marks, err := ParseExtendedStates(data)
	if err != nil {
		return &ExtendedStatesError{Path: path, Err: err}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, m := range marks {
		c.markAuto(m)
	}

	return nil
}

// markAuto sets AutoInstalled on the installed version of every slot the mark
// covers. c.mu must be held.
func (c *Cache) markAuto(m AutoMark) {
	var keys []string

	switch m.Architecture {
	case "", "any":
		keys = append(keys, m.Package)
		keys = append(keys, c.byBareName[m.Package]...)
	case archAll, c.hostArch:
		// apt files a package of architecture all under the native one, so
		// either spelling in the file reaches both kinds.
		keys = append(keys, m.Package, entryKey(m.Package, c.hostArch))
	default:
		keys = append(keys, entryKey(m.Package, m.Architecture))
	}

	for _, k := range keys {
		if p := c.installed[k]; p != nil {
			p.AutoInstalled = true
		}
	}
}
