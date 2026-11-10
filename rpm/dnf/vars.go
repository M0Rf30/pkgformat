package dnf

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/limitio"
	"github.com/M0Rf30/pkgformat/internal/pathseg"
)

// expandVars substitutes $name and ${name} in s: $basearch and $releasever
// from the options, then Options.Vars, then the files of Options.VarsDir. An
// unknown variable is left as written. The URL it yields has the double
// slashes of its path collapsed, which a variable that ends in a slash would
// otherwise leave.
func (c *Client) expandVars(s string) string {
	var b strings.Builder

	for i := 0; i < len(s); {
		if s[i] != '$' {
			b.WriteByte(s[i])

			i++

			continue
		}

		name, end, braced := scanVarName(s, i+1)
		if name == "" {
			b.WriteByte('$')

			i++

			continue
		}

		if val, ok := c.lookupVar(name); ok {
			b.WriteString(val)
		} else if braced {
			b.WriteString("${" + name + "}")
		} else {
			b.WriteString("$" + name)
		}

		i = end
	}

	return normalizeURL(b.String())
}

// scanVarName reads a variable name starting at s[i], the byte after the "$".
// end is the index after the reference.
func scanVarName(s string, i int) (name string, end int, braced bool) {
	if i < len(s) && s[i] == '{' {
		j := i + 1
		for j < len(s) && isVarChar(s[j], j == i+1) {
			j++
		}

		if j < len(s) && s[j] == '}' && j > i+1 {
			return s[i+1 : j], j + 1, true
		}

		return "", i, false
	}

	j := i
	for j < len(s) && isVarChar(s[j], j == i) {
		j++
	}

	return s[i:j], j, false
}

func isVarChar(ch byte, first bool) bool {
	switch {
	case ch == '_', ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z':
		return true
	case ch >= '0' && ch <= '9':
		return !first
	}

	return false
}

func (c *Client) lookupVar(name string) (string, bool) {
	switch name {
	case "basearch":
		return c.opts.BaseArch, true
	case "releasever":
		return c.opts.Releasever, c.opts.Releasever != ""
	}

	if v, ok := c.opts.Vars[name]; ok {
		return v, true
	}

	if c.opts.VarsDir == "" || !pathseg.Name(name) {
		return "", false
	}

	if cached, ok := c.vars.Load(name); ok {
		v, _ := cached.(*string)
		if v == nil {
			return "", false
		}

		return *v, true
	}

	// A variable file does not change under a running program; remember
	// misses too, so that expanding the URLs of many repositories does not
	// touch the file system for each.
	val, ok := readVarFile(filepath.Join(c.opts.VarsDir, name))
	if !ok {
		c.vars.Store(name, (*string)(nil))

		return "", false
	}

	c.vars.Store(name, &val)

	return val, true
}

func readVarFile(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}

	defer func() { _ = f.Close() }()

	data, err := limitio.ReadAll(f, maxVarBytes, ErrUnsafeLocation)
	if err != nil {
		return "", false
	}

	return strings.TrimSpace(string(data)), true
}

// normalizeURL collapses double slashes in the path of a URL: mirror lists
// hold entries such as "/pub/rocky//8.10/", which a substituted variable
// produces too. The scheme, host, query and fragment are left as written.
func normalizeURL(raw string) string {
	_, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return raw
	}

	start := strings.IndexByte(rest, '/')
	if start < 0 {
		return raw
	}

	end := len(rest)
	if q := strings.IndexAny(rest[start:], "?#"); q >= 0 {
		end = start + q
	}

	if !strings.Contains(rest[start:end], "//") {
		return raw
	}

	prefix := raw[:len(raw)-len(rest)]

	var b strings.Builder

	b.WriteString(prefix)
	b.WriteString(rest[:start])

	prevSlash := false

	for i := start; i < end; i++ {
		if rest[i] == '/' && prevSlash {
			continue
		}

		prevSlash = rest[i] == '/'

		b.WriteByte(rest[i])
	}

	b.WriteString(rest[end:])

	return b.String()
}
