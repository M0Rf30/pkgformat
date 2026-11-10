package apt

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// MaxSourcesFileBytes caps one sources.list or deb822 .sources file read by
// LoadSources.
const MaxSourcesFileBytes = 1 << 20

// SourceType is the Types value of a source: what kind of archive it is.
type SourceType string

const (
	// TypeDeb is a binary package archive ("deb").
	TypeDeb SourceType = "deb"
	// TypeDebSrc is a source package archive ("deb-src").
	TypeDebSrc SourceType = "deb-src"
)

// Switch is a yes/no source option that may be left to the global
// configuration. The zero value means unset.
type Switch uint8

const (
	// SwitchDefault leaves the option to the default (UpdateOptions or apt's).
	SwitchDefault Switch = iota
	// SwitchYes is yes, true or 1.
	SwitchYes
	// SwitchNo is no, false or 0.
	SwitchNo
)

// Enabled resolves the switch, using def when it is unset.
func (s Switch) Enabled(def bool) bool {
	switch s {
	case SwitchYes:
		return true
	case SwitchNo:
		return false
	default:
		return def
	}
}

// ByHashMode is the By-Hash source option.
type ByHashMode uint8

const (
	// ByHashDefault is unset: by-hash is used when the Release file says
	// Acquire-By-Hash: yes, as with "yes".
	ByHashDefault ByHashMode = iota
	// ByHashYes uses by-hash when the Release file offers it.
	ByHashYes
	// ByHashNo never uses by-hash.
	ByHashNo
	// ByHashForce uses by-hash even if the Release file does not say so, and
	// does not fall back to the plain index path.
	ByHashForce
)

// Source is one apt repository: a base URL, a suite and its components, with
// the options of a sources.list line or deb822 stanza.
type Source struct {
	// Type is TypeDeb or TypeDebSrc. The zero value means TypeDeb.
	Type SourceType
	// URL is the repository base URL with a trailing slash
	// ("https://archive.ubuntu.com/ubuntu/"). Besides http(s) it may carry
	// the schemes file:, copy:, cdrom:, mirror+http(s):// and mirror+file://
	// (and, accepted by the parser, anything else apt knows, which Update
	// refuses with ErrUnsupportedScheme).
	URL string
	// Suite is the distribution ("jammy", "bookworm-updates").
	Suite string
	// Components lists the archive areas ("main", "universe").
	Components []string
	// Architectures restricts the source to these architectures. Empty means
	// the default architecture.
	Architectures []string
	// ArchitecturesAdd and ArchitecturesRemove are the Architectures-Add and
	// Architectures-Remove options: architectures added to, or taken off, the
	// set the source is fetched for.
	ArchitecturesAdd, ArchitecturesRemove []string
	// Languages are the Languages option for the Translation indexes ("en",
	// "de", "none"); empty means the default (the translations apt would
	// fetch for the environment, here "none" unless UpdateOptions says
	// otherwise).
	Languages []string
	// Targets are the Targets option: the kinds of index to fetch, such as
	// "Packages", "Translations", "Contents", "Sources". Empty selects the
	// default of the Type: Packages for deb, Sources for deb-src.
	Targets []string
	// SignedBy is the Signed-By option verbatim: key fingerprints (separated
	// by comma or blank, each optionally ending in "!"), paths of keyring
	// files or directories, or an inline armored PGP public key block. "" means
	// the default keyrings.
	SignedBy string
	// Trusted, AllowInsecure, AllowWeak, AllowDowngradeToInsecure,
	// CheckValidUntil and CheckDate are the options of those names (trusted,
	// allow-insecure, allow-weak, allow-downgrade-to-insecure,
	// check-valid-until, check-date).
	Trusted, AllowInsecure, AllowWeak, AllowDowngradeToInsecure, CheckValidUntil, CheckDate Switch
	// ValidUntilMin and ValidUntilMax are the Valid-Until-Min and
	// Valid-Until-Max options, as durations. Zero is unset.
	ValidUntilMin, ValidUntilMax time.Duration
	// DateMaxFuture is the Date-Max-Future option: how far past the local clock
	// the Date of the Release may lie. Zero is unset.
	DateMaxFuture time.Duration
	// ByHash is the By-Hash option.
	ByHash ByHashMode
	// PDiffs is the PDiffs option.
	PDiffs Switch
	// Snapshot is the Snapshot option: a snapshot id for archives that serve
	// them, or "".
	Snapshot string
	// Options holds the options the parser does not interpret, with their
	// names as written, so that a writer can reproduce them.
	Options map[string]string
}

// IsSource reports whether the source is a source package archive.
func (s *Source) IsSource() bool { return s.Type == TypeDebSrc }

// isHTTPURL reports whether raw is an http or https URL.
func isHTTPURL(raw string) bool {
	return strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")
}

// withSlash returns raw with exactly one trailing slash.
func withSlash(raw string) string {
	if strings.HasSuffix(raw, "/") {
		return raw
	}

	return raw + "/"
}

// ParseSourcesList parses the one-line format of /etc/apt/sources.list and
// *.list files:
//
//	deb [arch=amd64 signed-by=/path] https://archive.ubuntu.com/ubuntu/ jammy main universe
//
// Comments, deb-src lines, non-http(s) URLs, and lines without a suite and a
// component are skipped.
func ParseSourcesList(content string) []Source {
	var out []Source

	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)

		rest, ok := strings.CutPrefix(line, "deb ")
		if !ok {
			continue // comment, blank, deb-src, or anything else
		}

		archs, signedBy, rest := parseLegacyOptions(rest)

		parts := strings.Fields(rest)
		if len(parts) < 3 || !isHTTPURL(parts[0]) {
			continue
		}

		out = append(out, Source{
			URL:           withSlash(parts[0]),
			Suite:         parts[1],
			Components:    parts[2:],
			Architectures: archs,
			SignedBy:      signedBy,
		})
	}

	return out
}

// parseLegacyOptions splits the optional "[arch=... signed-by=...]" block off
// a deb line.
func parseLegacyOptions(line string) (archs []string, signedBy, rest string) {
	if !strings.HasPrefix(line, "[") {
		return nil, "", line
	}

	opts, rest, ok := strings.Cut(line[1:], "]")
	if !ok {
		return nil, "", line
	}

	for opt := range strings.FieldsSeq(opts) {
		if after, ok := strings.CutPrefix(opt, "arch="); ok {
			archs = strings.Split(after, ",")
		} else if after, ok := strings.CutPrefix(opt, "signed-by="); ok {
			signedBy = after
		}
	}

	return archs, signedBy, strings.TrimSpace(rest)
}

// ParseSources822 parses the deb822 format of *.sources files. A paragraph
// yields one Source per URI and suite. Paragraphs that do not declare the
// binary "deb" type, that are disabled (Enabled: no), or that lack URIs, Suites
// or Components are skipped, as are non-http(s) URIs.
func ParseSources822(content string) []Source {
	var out []Source

	// The scanner is lenient and a reader over a string cannot fail.
	_ = deb.ScanControl(strings.NewReader(content), func(cf *deb.ControlFile) error {
		uris, suites, comps := cf.Get("URIs"), cf.Get("Suites"), cf.Get("Components")
		if uris == "" || suites == "" || comps == "" {
			return nil
		}

		if !slices.Contains(strings.Fields(cf.Get("Types")), "deb") || !sourceEnabled(cf) {
			return nil
		}

		for raw := range strings.FieldsSeq(uris) {
			if !isHTTPURL(raw) {
				continue
			}

			for suite := range strings.FieldsSeq(suites) {
				out = append(out, Source{
					URL:           withSlash(raw),
					Suite:         suite,
					Components:    strings.Fields(comps),
					Architectures: strings.Fields(cf.Get("Architectures")),
					SignedBy:      cf.Get("Signed-By"),
				})
			}
		}

		return nil
	})

	return out
}

// sourceEnabled reports whether a deb822 source is active. Per sources.list(5)
// Enabled defaults to yes; only an explicit negative disables it.
func sourceEnabled(cf *deb.ControlFile) bool {
	switch strings.ToLower(strings.TrimSpace(cf.Get("Enabled"))) {
	case "no", "false", "0":
		return false
	default:
		return true
	}
}

// LoadSources reads the configured sources. listFile is a sources.list style
// file and listDir a directory of *.list (one-line) and *.sources (deb822)
// files, read in name order. Either may be empty, and either may be missing:
// apt tolerates that, and so does LoadSources. A file that exists but cannot
// be read, or is larger than MaxSourcesFileBytes, is skipped and reported in
// the returned error, next to the sources that did load.
func LoadSources(listFile, listDir string) ([]Source, error) {
	var (
		out  []Source
		errs []error
	)

	read := func(path string) {
		data, err := readSourcesFile(path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}

			return
		}

		if strings.HasSuffix(path, ".sources") {
			out = append(out, ParseSources822(data)...)
		} else {
			out = append(out, ParseSourcesList(data)...)
		}
	}

	if listFile != "" {
		read(listFile)
	}

	if listDir != "" {
		entries, err := os.ReadDir(listDir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("apt: read sources directory: %w", err))
		}

		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || (!strings.HasSuffix(name, ".list") && !strings.HasSuffix(name, ".sources")) {
				continue
			}

			read(filepath.Join(listDir, name))
		}
	}

	return out, errors.Join(errs...)
}

func readSourcesFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("apt: open sources file: %w", err)
	}

	defer func() { _ = f.Close() }()

	data, err := limitio.ReadAll(f, MaxSourcesFileBytes, ErrTooLarge)
	if err != nil {
		return "", fmt.Errorf("apt: read sources file %s: %w", filepath.Base(path), err)
	}

	return string(data), nil
}

// encodeHostPath is the host-and-path prefix apt gives the files it stores for
// a repository: "https://ports.ubuntu.com/ubuntu-ports/" becomes
// "ports.ubuntu.com_ubuntu-ports".
func encodeHostPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	return u.Host + strings.ReplaceAll(strings.TrimSuffix(u.Path, "/"), "/", "_")
}

// BaseURLs maps the encoded host-and-path prefix of apt's list file names to
// the URL of the source. Of several sources with the same prefix the last wins.
func BaseURLs(sources []Source) map[string]string {
	m := make(map[string]string, len(sources))

	for _, s := range sources {
		if key := encodeHostPath(s.URL); key != "" {
			m[key] = s.URL
		}
	}

	return m
}

// ListFileName returns the name apt stores relPath of a repository under:
// ("https://archive.ubuntu.com/ubuntu/", "jammy", "main/binary-amd64/Packages.xz")
// gives "archive.ubuntu.com_ubuntu_dists_jammy_main_binary-amd64_Packages.xz".
// It returns "" for a URL that does not parse.
func ListFileName(baseURL, suite, relPath string) string {
	prefix := encodeHostPath(baseURL)
	if prefix == "" {
		return ""
	}

	return prefix + "_dists_" + suite + "_" + strings.ReplaceAll(relPath, "/", "_")
}
