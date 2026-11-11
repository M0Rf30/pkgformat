package dnf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/M0Rf30/pkgformat/internal/limitio"
	"github.com/M0Rf30/pkgformat/internal/pathseg"
)

// ErrRepoFileTooLarge means a .repo or dnf.conf file exceeds its size limit.
var ErrRepoFileTooLarge = errors.New("dnf: .repo file exceeds the size limit")

// MetadataExpireNever is the [Repo.MetadataExpire] of metadata_expire=never
// (or -1): cached metadata is never considered expired.
const MetadataExpireNever time.Duration = -1

// Defaults of the repository options, as dnf has them.
const (
	// defaultPriority is the priority of a repository that sets none.
	defaultPriority = 99
	// defaultCost is the cost of a repository that sets none.
	defaultCost = 1000
	// defaultMetadataExpire is the metadata_expire of a repository that sets
	// none: two days.
	defaultMetadataExpire = 48 * time.Hour
)

// Repo is a repository of a .repo file. Options a repository does not set
// take the value of the [main] section of dnf.conf ([Options.ConfigFile]),
// else dnf's own default.
type Repo struct {
	// ID is the name of the section; it names the cache directory.
	ID string
	// Name is the human readable name= of the repository.
	Name string
	// Type is type=: empty or one of the aliases of rpm-md. A repository of
	// another type cannot be read by this package and is not used.
	Type string
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
	// RepoGPGCheck is true for repo_gpgcheck=1: the detached signature of
	// repomd.xml (repomd.xml.asc) is checked against GPGKeys when the metadata
	// is updated, and a repository whose metadata is not signed by one of them
	// is refused.
	RepoGPGCheck bool
	// GPGKeys are the gpgkey URLs (http, https or file), variables not yet
	// expanded.
	GPGKeys []string
	// Exclude holds the exclude and excludepkgs patterns: shell globs matched
	// against the name of a package, and against its name-version,
	// name-version-release, name.arch, name-version-release.arch and
	// epoch:name-version-release.arch forms. A matching package is left out of
	// the index.
	Exclude []string
	// IncludePkgs holds the includepkgs patterns, of the same forms: when
	// there are any, only the packages of this repository that match one of
	// them are in the index.
	IncludePkgs []string
	// Priority is the priority= of the repository, 99 when unset. A package
	// replaces every package of the same name from repositories with a higher
	// number, whatever their version.
	Priority int
	// Cost is the cost= of the repository, 1000 when unset: of two
	// repositories that carry the same package (same name, version and
	// architecture) the one with the lower cost is the one it is taken from.
	Cost int
	// Proxy is the proxy= URL used for every request of the repository, with
	// ProxyUsername and ProxyPassword as its credentials. "_none_" bypasses
	// any proxy; empty leaves the transport of [Options.HTTP] as it is.
	Proxy         string
	ProxyUsername string
	ProxyPassword string
	// SkipSSLVerify is true for sslverify=0: the certificate of the server
	// is not checked. The default, and the zero value, is to check it.
	SkipSSLVerify bool
	// SSLCACert is the PEM file of sslcacert=, the authorities the server
	// certificate is checked against instead of the system's.
	SSLCACert string
	// SSLClientCert and SSLClientKey are sslclientcert= and sslclientkey=,
	// the PEM files of the client certificate and its key.
	SSLClientCert string
	SSLClientKey  string
	// Username and Password are the credentials (HTTP basic authentication)
	// sent to the servers of the repository.
	Username string
	Password string
	// ModuleHotfixes is module_hotfixes=1: the packages of the repository are
	// not filtered out by module metadata, whatever stream they belong to.
	ModuleHotfixes bool
	// SkipIfUnavailable is skip_if_unavailable=1: a repository that cannot be
	// fetched is skipped with a warning instead of failing the update.
	SkipIfUnavailable bool
	// MetadataExpire is how long cached metadata is fresh: 48 hours unless
	// set, [MetadataExpireNever] for never.
	MetadataExpire time.Duration
	// CountMe is countme=1: see [Options.PersistDir].
	CountMe bool
	// EnabledMetadata lists the metadata types fetched besides primary and
	// modules when the repository is updated, such as "filelists". The file
	// lists a resolution needs are fetched when it needs them whether or not
	// they are listed.
	EnabledMetadata []string
}

// defaultRepo is a repository section with nothing set.
func defaultRepo() Repo {
	return Repo{
		Enabled:        true,
		Priority:       defaultPriority,
		Cost:           defaultCost,
		MetadataExpire: defaultMetadataExpire,
	}
}

// clone returns a copy that shares no slice with r.
func (r Repo) clone() Repo {
	r.BaseURLs = slices.Clone(r.BaseURLs)
	r.GPGKeys = slices.Clone(r.GPGKeys)
	r.Exclude = slices.Clone(r.Exclude)
	r.IncludePkgs = slices.Clone(r.IncludePkgs)
	r.EnabledMetadata = slices.Clone(r.EnabledMetadata)

	return r
}

// usable reports whether the repository is of a type this package reads.
func (r *Repo) usable() bool {
	switch strings.ToLower(r.Type) {
	case "", "rpm-md", "rpm", "repomd", "rpmmd":
		return true
	default:
		return false
	}
}

// iniLine is what scanINI hands over: a section header or a line of a section.
type iniLine struct {
	section string // set on a header line
	header  bool
	text    string
}

// scanINI reads the lines of an INI file of dnf's dialect: blank lines and
// comments are dropped and lines are trimmed. A line over maxRepoFileBytes, or
// a file over it, fails with [ErrRepoFileTooLarge].
func scanINI(r io.Reader, fn func(iniLine)) error {
	scanner := bufio.NewScanner(limitio.Capped(r, maxRepoFileBytes+1, ErrRepoFileTooLarge))
	scanner.Buffer(nil, maxRepoFileBytes)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		if line[0] == '[' && line[len(line)-1] == ']' {
			fn(iniLine{header: true, section: line[1 : len(line)-1]})

			continue
		}

		fn(iniLine{text: line})
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			err = ErrRepoFileTooLarge
		}

		return fmt.Errorf("dnf: reading .repo file: %w", err)
	}

	return nil
}

// ParseRepoFile parses the INI-style content of a .repo file. A baseurl may
// list several URLs on the line or on indented lines after it. A section whose
// name cannot be a directory name (a repository id is joined to the cache path)
// is ignored with its keys. A line over 1 MiB fails with [ErrRepoFileTooLarge].
// Options the file does not set have dnf's defaults; [Client.Repos] starts from
// those of dnf.conf instead.
func ParseRepoFile(r io.Reader) ([]Repo, error) {
	return parseRepoFile(r, defaultRepo())
}

// parseRepoFile is [ParseRepoFile] with the defaults every section starts
// from.
func parseRepoFile(r io.Reader, defaults Repo) ([]Repo, error) {
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

	err := scanINI(r, func(l iniLine) {
		if l.header {
			flush()

			if pathseg.Name(l.section) {
				cur = defaults.clone()
				cur.ID = l.section
			}

			lastKey = ""

			return
		}

		lastKey = applyRepoLine(&cur, l.text, lastKey)
	})
	if err != nil {
		return nil, err
	}

	flush()

	return repos, nil
}

// splitKeyValue splits "key = value", and tells a continuation line (a value
// of the previous list key, on a line of its own) from it.
func splitKeyValue(line string) (key, val string, ok bool) {
	if isRepoURL(line) {
		return "", "", false
	}

	key, val, ok = strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}

	return strings.TrimSpace(key), strings.TrimSpace(val), true
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
	key, val, ok := splitKeyValue(line)
	if !ok {
		appendRepoList(cur, lastKey, line)

		return lastKey
	}

	applyRepoKey(cur, key, val)

	return key
}

// applyRepoKey sets the option key of a repository, and reports whether it is
// one this package knows.
func applyRepoKey(cur *Repo, key, val string) bool {
	switch key {
	case "baseurl", "gpgkey", "exclude", "excludepkgs", "includepkgs", "enabled_metadata":
		// A key that repeats replaces the earlier value, as in dnf.
		replaceRepoList(cur, key)
		appendRepoList(cur, key, val)
	case "mirrorlist", "metalink":
		if fields := strings.Fields(val); len(fields) > 0 && cur.MirrorList == "" {
			cur.MirrorList = fields[0]
		}
	case "name":
		cur.Name = val
	case "type":
		cur.Type = val
	case "enabled":
		setBool(&cur.Enabled, val)
	case "priority":
		setInt(&cur.Priority, val)
	case "cost":
		setInt(&cur.Cost, val)
	case "proxy":
		cur.Proxy = val
	case "proxy_username":
		cur.ProxyUsername = val
	case "proxy_password":
		cur.ProxyPassword = val
	case "username":
		cur.Username = val
	case "password":
		cur.Password = val
	case "gpgcheck":
		setBool(&cur.GPGCheck, val)
	case "repo_gpgcheck":
		setBool(&cur.RepoGPGCheck, val)
	case "sslverify":
		if v, ok := parseBool(val); ok {
			cur.SkipSSLVerify = !v
		}
	case "sslcacert":
		cur.SSLCACert = val
	case "sslclientcert":
		cur.SSLClientCert = val
	case "sslclientkey":
		cur.SSLClientKey = val
	case "module_hotfixes":
		setBool(&cur.ModuleHotfixes, val)
	case "skip_if_unavailable":
		setBool(&cur.SkipIfUnavailable, val)
	case "countme":
		setBool(&cur.CountMe, val)
	case "metadata_expire":
		if d, ok := parseExpire(val); ok {
			cur.MetadataExpire = d
		}
	case "deltarpm", "deltarpm_percentage", "deltarpm_metadata_percentage":
		// Delta rpms are not used: whole packages are downloaded and
		// checked, so these settings are accepted and have no effect.
	default:
		return false
	}

	return true
}

// replaceRepoList empties the list key so that its next value replaces it.
func replaceRepoList(cur *Repo, key string) {
	switch key {
	case "baseurl":
		cur.BaseURLs = nil
	case "gpgkey":
		cur.GPGKeys = nil
	case "exclude", "excludepkgs":
		// exclude and excludepkgs are two spellings of one list: both
		// accumulate.
	case "includepkgs":
		cur.IncludePkgs = nil
	case "enabled_metadata":
		cur.EnabledMetadata = nil
	}
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
		cur.Exclude = append(cur.Exclude, splitList(val)...)
	case "includepkgs":
		cur.IncludePkgs = append(cur.IncludePkgs, splitList(val)...)
	case "enabled_metadata":
		cur.EnabledMetadata = append(cur.EnabledMetadata, splitList(val)...)
	}
}

func splitList(val string) []string {
	return strings.FieldsFunc(val, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}

// parseBool reads an INI boolean in the spellings dnf takes.
func parseBool(val string) (value, ok bool) {
	switch strings.ToLower(val) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

// setBool sets *dst when val is a boolean, and leaves it otherwise.
func setBool(dst *bool, val string) {
	if v, ok := parseBool(val); ok {
		*dst = v
	}
}

func setInt(dst *int, val string) {
	if n, err := strconv.Atoi(val); err == nil {
		*dst = n
	}
}

// parseExpire reads metadata_expire: "never" or -1 for no expiry, else a
// number of seconds with an optional s, m, h or d suffix.
func parseExpire(val string) (time.Duration, bool) {
	val = strings.ToLower(strings.TrimSpace(val))
	if val == "never" || val == "-1" {
		return MetadataExpireNever, true
	}

	unit := time.Second

	if val != "" {
		switch val[len(val)-1] {
		case 's':
			val = val[:len(val)-1]
		case 'm':
			unit, val = time.Minute, val[:len(val)-1]
		case 'h':
			unit, val = time.Hour, val[:len(val)-1]
		case 'd':
			unit, val = 24*time.Hour, val[:len(val)-1]
		}
	}

	n, err := strconv.ParseUint(strings.TrimSpace(val), 10, 32)
	if err != nil {
		return 0, false
	}

	// a span longer than a Duration holds is as good as never expiring
	if n > uint64(math.MaxInt64/int64(unit)) {
		return time.Duration(math.MaxInt64), true
	}

	return time.Duration(n) * unit, true
}

// isRepoURL reports whether line is a bare URL, a baseurl continuation line.
func isRepoURL(line string) bool {
	return strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") ||
		strings.HasPrefix(line, "ftp://") || strings.HasPrefix(line, "file://")
}

// Repos reads the *.repo files of Options.RepoDir in name order and returns
// their repositories, enabled or not, with the defaults of the [main] section
// of Options.ConfigFile applied. A missing directory yields none; a file that
// cannot be read is skipped with a warning.
func (c *Client) Repos() ([]Repo, error) {
	if c.opts.RepoDir == "" {
		return nil, nil
	}

	cfg, err := c.Config()
	if err != nil {
		return nil, err
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

		parsed, err := readRepoFile(filepath.Join(c.opts.RepoDir, e.Name()), cfg.Defaults)
		if err != nil {
			c.opts.Logger.Warn("skipping repository file", "file", e.Name(), "error", err)

			continue
		}

		repos = append(repos, parsed...)
	}

	return slices.Clip(repos), nil
}

func readRepoFile(path string, defaults Repo) ([]Repo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	return parseRepoFile(f, defaults)
}

// enabledRepos returns the enabled repositories that have a way to be fetched
// and are of a type this package reads.
func (c *Client) enabledRepos() ([]Repo, error) {
	repos, err := c.Repos()
	if err != nil {
		return nil, err
	}

	out := repos[:0:0]

	for _, r := range repos {
		if !r.Enabled || (len(r.BaseURLs) == 0 && r.MirrorList == "") {
			continue
		}

		if !r.usable() {
			c.opts.Logger.Warn("repository type not supported, skipping", "repo", r.ID, "type", r.Type)

			continue
		}

		out = append(out, r)
	}

	return out, nil
}

// nevraForms lists the spellings a package is matched by in exclude and
// includepkgs patterns.
func nevraForms(name, epoch, version, release, arch string) [7]string {
	vr := version + "-" + release

	return [...]string{
		name,
		name + "." + arch,
		name + "-" + version,
		name + "-" + vr,
		name + "-" + vr + "." + arch,
		epoch + ":" + name + "-" + vr + "." + arch,
		name + "-" + epoch + ":" + vr + "." + arch,
	}
}

// matchesAny reports whether one of the patterns, shell globs, matches one of
// the forms. A pattern that is not a valid glob matches nothing.
func matchesAny(patterns []string, forms [7]string) bool {
	for _, pattern := range patterns {
		for _, form := range forms {
			if ok, _ := path.Match(pattern, form); ok {
				return true
			}
		}
	}

	return false
}
