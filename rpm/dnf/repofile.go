package dnf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/M0Rf30/pkgformat/internal/limitio"
	"github.com/M0Rf30/pkgformat/internal/pathseg"
	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

// ErrRepoFileTooLarge means a .repo file exceeds its size limit.
var ErrRepoFileTooLarge = errors.New("dnf: .repo file exceeds the size limit")

// Repo is a repository of a .repo file.
type Repo struct {
	// ID is the name of the section; it names the cache directory.
	ID string
	// BaseURLs are the baseurl entries in the order listed, variables not
	// yet expanded.
	BaseURLs []string
	// MirrorList is the mirrorlist or metalink URL, used when there is no
	// baseurl.
	MirrorList string
	// Enabled is false when the file says enabled=0.
	Enabled bool
	// GPGCheck is true when the file says gpgcheck=1: the signature of every
	// package downloaded from the repository is checked against GPGKeys.
	GPGCheck bool
	// GPGKeys are the gpgkey URLs (http, https or file), variables not yet
	// expanded.
	GPGKeys []string
	// Exclude holds the exclude and excludepkgs patterns: shell globs matched
	// against the name of a package, and against its name-version,
	// name-version-release, name.arch, name-version-release.arch and
	// epoch:name-version-release.arch forms. A matching package is left out of
	// the index.
	Exclude []string
	// Priority is the priority= of the repository, 99 when unset. A package
	// replaces every package of the same name from repositories with a higher
	// number, whatever their version.
	Priority int
	// Proxy is the proxy= URL used for every request of the repository, with
	// ProxyUsername and ProxyPassword as its credentials. "_none_" bypasses
	// any proxy; empty leaves the transport of [Options.HTTP] as it is.
	Proxy         string
	ProxyUsername string
	ProxyPassword string
}

// defaultPriority is the priority of a repository that sets none, as in dnf.
const defaultPriority = 99

// ParseRepoFile parses the INI-style content of a .repo file. A baseurl may
// list several URLs on the line or on indented lines after it. A section whose
// name cannot be a directory name (a repository id is joined to the cache path)
// is ignored with its keys. A line over 1 MiB fails with [ErrRepoFileTooLarge].
func ParseRepoFile(r io.Reader) ([]Repo, error) {
	var (
		repos   []Repo
		cur     Repo
		lastKey string
	)

	flush := func() {
		if cur.ID != "" {
			repos = append(repos, cur)
		}

		cur = Repo{}
	}

	scanner := bufio.NewScanner(limitio.Capped(r, maxRepoFileBytes+1, ErrRepoFileTooLarge))
	scanner.Buffer(nil, maxRepoFileBytes)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		if line[0] == '[' && line[len(line)-1] == ']' {
			flush()

			if id := line[1 : len(line)-1]; pathseg.Name(id) {
				cur = Repo{ID: id, Enabled: true, Priority: defaultPriority}
			}

			lastKey = ""

			continue
		}

		lastKey = applyRepoLine(&cur, line, lastKey)
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			err = ErrRepoFileTooLarge
		}

		return nil, fmt.Errorf("dnf: reading .repo file: %w", err)
	}

	flush()

	return repos, nil
}

// applyRepoLine folds one line of a section into cur and returns the key it
// belongs to, which a following continuation line extends.
func applyRepoLine(cur *Repo, line, lastKey string) string {
	if cur.ID == "" {
		return ""
	}

	// dnf's INI dialect lets the values of a list key follow on their own
	// lines: extra baseurls, gpgkey URLs, exclude patterns. Other continuation
	// lines are ignored.
	if isRepoURL(line) {
		appendRepoList(cur, lastKey, line)

		return lastKey
	}

	key, val, ok := strings.Cut(line, "=")
	if !ok {
		appendRepoList(cur, lastKey, line)

		return lastKey
	}

	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)

	switch key {
	case "baseurl", "gpgkey", "exclude", "excludepkgs":
		appendRepoList(cur, key, val)
	case "gpgcheck":
		cur.GPGCheck = isTrue(val)
	case "priority":
		if n, err := strconv.Atoi(val); err == nil {
			cur.Priority = n
		}
	case "proxy":
		cur.Proxy = val
	case "proxy_username":
		cur.ProxyUsername = val
	case "proxy_password":
		cur.ProxyPassword = val
	case "mirrorlist", "metalink":
		if fields := strings.Fields(val); len(fields) > 0 && cur.MirrorList == "" {
			cur.MirrorList = fields[0]
		}
	case "enabled":
		cur.Enabled = val != "0"
	}

	return key
}

// appendRepoList adds the whitespace or comma separated values of a list key.
// It does nothing for a key that is not a list.
func appendRepoList(cur *Repo, key, val string) {
	switch key {
	case "baseurl":
		cur.BaseURLs = append(cur.BaseURLs, strings.Fields(val)...)
	case "gpgkey":
		cur.GPGKeys = append(cur.GPGKeys, strings.Fields(val)...)
	case "exclude", "excludepkgs":
		cur.Exclude = append(cur.Exclude, strings.FieldsFunc(val, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})...)
	}
}

// isTrue reports whether an INI boolean is true, in the spellings dnf takes.
func isTrue(val string) bool {
	switch strings.ToLower(val) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// isRepoURL reports whether line is a bare URL, a baseurl continuation line.
func isRepoURL(line string) bool {
	return strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") ||
		strings.HasPrefix(line, "ftp://") || strings.HasPrefix(line, "file://")
}

// Repos reads the *.repo files of Options.RepoDir in name order and returns
// their repositories, enabled or not. A missing directory yields none; a file
// that cannot be read is skipped with a warning.
func (c *Client) Repos() ([]Repo, error) {
	if c.opts.RepoDir == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(c.opts.RepoDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("dnf: reading repository directory: %w", err)
	}

	var repos []Repo

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".repo") {
			continue
		}

		parsed, err := readRepoFile(filepath.Join(c.opts.RepoDir, e.Name()))
		if err != nil {
			c.opts.Logger.Warn("skipping repository file", "file", e.Name(), "error", err)

			continue
		}

		repos = append(repos, parsed...)
	}

	return slices.Clip(repos), nil
}

func readRepoFile(path string) ([]Repo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	return ParseRepoFile(f)
}

// enabledRepos returns the enabled repositories that have a way to be fetched.
func (c *Client) enabledRepos() ([]Repo, error) {
	repos, err := c.Repos()
	if err != nil {
		return nil, err
	}

	out := repos[:0:0]

	for _, r := range repos {
		if r.Enabled && (len(r.BaseURLs) > 0 || r.MirrorList != "") {
			out = append(out, r)
		}
	}

	return out, nil
}

// excludes reports whether one of the exclude patterns of r matches the
// package pp. A pattern that is not a valid glob matches nothing.
func (r *Repo) excludes(pp *repodata.PrimaryPackage) bool {
	if len(r.Exclude) == 0 {
		return false
	}

	epoch := strconv.FormatUint(uint64(pp.Epoch), 10)
	vr := pp.Version + "-" + pp.Release
	forms := [...]string{
		pp.Name,
		pp.Name + "." + pp.Arch,
		pp.Name + "-" + pp.Version,
		pp.Name + "-" + vr,
		pp.Name + "-" + vr + "." + pp.Arch,
		epoch + ":" + pp.Name + "-" + vr + "." + pp.Arch,
		pp.Name + "-" + epoch + ":" + vr + "." + pp.Arch,
	}

	for _, pattern := range r.Exclude {
		for _, form := range forms {
			if ok, _ := path.Match(pattern, form); ok {
				return true
			}
		}
	}

	return false
}
