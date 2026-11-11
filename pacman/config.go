package pacman

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
	"path"
	"strconv"
	"strings"
)

// Limits on the configuration files the parsers read.
const (
	// MaxConfigBytes bounds one pacman.conf, included file or mirrorlist.
	MaxConfigBytes = 4 << 20
	// MaxConfigTotalBytes bounds the bytes read from a configuration and all
	// the files it includes.
	MaxConfigTotalBytes = 32 << 20
	// MaxConfigRepos bounds the repositories of one configuration.
	MaxConfigRepos = 1000
	// MaxConfigServers bounds the servers (or cache servers) of one repository.
	MaxConfigServers = 10000
	// MaxConfigValues bounds the entries of one list option, such as
	// IgnorePkg, and the retained unknown directives.
	MaxConfigValues = 100000
	// DefaultMaxIncludeDepth is the include nesting ParseOptions allows when
	// MaxIncludeDepth is zero; it is pacman's own limit.
	DefaultMaxIncludeDepth = 10
	// DefaultMaxIncludeFiles is the number of included files ParseOptions
	// allows in total when MaxIncludeFiles is zero.
	DefaultMaxIncludeFiles = 1000
)

// Errors of the configuration parsers. Test with errors.Is.
var (
	// ErrInvalidConfig reports a pacman.conf or mirrorlist that cannot be
	// parsed or exceeds a limit. The errors below wrap it.
	ErrInvalidConfig = errors.New("pacman: invalid configuration")
	// ErrConfigLimit reports an include nested too deeply, too many included
	// files or a configuration over a size limit.
	ErrConfigLimit = fmt.Errorf("%w: limit exceeded", ErrInvalidConfig)
	// ErrUnknownDirective reports, in strict mode, a directive pacman does not
	// know.
	ErrUnknownDirective = fmt.Errorf("%w: unknown directive", ErrInvalidConfig)
)

// Config is a parsed pacman.conf: the [options] values, with libalpm's
// defaults applied where the file leaves an option out, and the repositories.
//
// Paths are cleaned lexically where pacman resolves them (RootDir, DBPath,
// GPGDir); symbolic links are not followed, as no file system is consulted.
type Config struct {
	// RootDir is the installation root, "/" by default.
	RootDir string
	// DBPath is the database directory, <RootDir>/var/lib/pacman/ by default.
	DBPath string
	// CacheDirs are the package cache directories in the order the file lists
	// them, /var/cache/pacman/pkg/ by default.
	CacheDirs []string
	// HookDirs are the extra hook directories, /etc/pacman.d/hooks/ by default.
	HookDirs []string
	// GPGDir is the GnuPG directory, /etc/pacman.d/gnupg/ by default.
	GPGDir string
	// LogFile is the log file, <RootDir>/var/log/pacman.log by default.
	LogFile string

	// HoldPkg, IgnorePkg, IgnoreGroup, NoUpgrade and NoExtract are the lists of
	// names and shell-style patterns of the options of the same names.
	HoldPkg     []string
	IgnorePkg   []string
	IgnoreGroup []string
	NoUpgrade   []string
	NoExtract   []string

	// Architectures are the Architecture values as written, "auto" included;
	// see Arch and AllowedArchitectures for the resolved ones. Empty when the
	// option is absent.
	Architectures []string

	// XferCommand is the external downloader command line, empty when unset.
	XferCommand string
	// CleanMethod says what a cache clean keeps; KeepInstalled by default.
	CleanMethod CleanMethod

	// SigLevel is the default signature level of repositories, "Required
	// TrustedOnly" unless set.
	SigLevel SigLevel
	// LocalFileSigLevel and RemoteFileSigLevel are the levels for package
	// files named explicitly (pacman -U on a path or on a URL). Each starts
	// from SigLevel, as pacman does; only the Package part applies to files.
	LocalFileSigLevel  SigLevel
	RemoteFileSigLevel SigLevel

	// ParallelDownloads is the number of concurrent download streams, 1 by
	// default.
	ParallelDownloads int
	// DownloadUser is the user downloads switch to, empty when unset.
	DownloadUser string

	// The flag options.
	UseSyslog              bool
	Color                  bool
	CheckSpace             bool
	VerbosePkgLists        bool
	ILoveCandy             bool
	NoProgressBar          bool
	DisableDownloadTimeout bool
	// DisableSandboxFilesystem and DisableSandboxSyscalls are set by their own
	// options and both by DisableSandbox.
	DisableSandboxFilesystem bool
	DisableSandboxSyscalls   bool

	// Repos are the repositories in the order the file lists them, which is
	// the order pacman searches them.
	Repos []Repo
	// Unknown holds the directives the parser does not know, in file order. In
	// strict mode they are an error instead.
	Unknown []Directive
}

// Repo is a repository: a name and the servers that carry it. A server is a
// URL that may contain the $repo and $arch placeholders (see ExpandServer).
type Repo struct {
	Name    string
	Servers []string
	// CacheServers are the CacheServer URLs: package locations a Client tries
	// before Servers. They never serve databases.
	CacheServers []string
	// Usage is what the repository may be used for; the zero value is all.
	Usage Usage
	// SigLevel is the signature level of the repository, merged over the
	// global one by ParseConfig. The zero value means unspecified: a Client
	// then applies its ClientOptions.
	SigLevel SigLevel
}

// Directive is a configuration line the parser does not know.
type Directive struct {
	// Section is the section the line appeared in.
	Section string
	// Key is the directive name; the whole line when it has no "=".
	Key string
	// Value is the text after "=", empty for a line without one.
	Value string
}

// CleanMethod is the CleanMethod option: what clearing the package cache keeps.
// The values combine with |.
type CleanMethod uint8

const (
	// CleanKeepInstalled keeps the packages that are installed.
	CleanKeepInstalled CleanMethod = 1 << iota
	// CleanKeepCurrent keeps the packages in a sync database.
	CleanKeepCurrent
)

// String returns the option value, such as "KeepInstalled KeepCurrent".
func (m CleanMethod) String() string {
	var names []string

	if m&CleanKeepInstalled != 0 {
		names = append(names, "KeepInstalled")
	}

	if m&CleanKeepCurrent != 0 {
		names = append(names, "KeepCurrent")
	}

	return strings.Join(names, " ")
}

// ParseOptions tunes the configuration parsers. The zero value is valid.
type ParseOptions struct {
	// Include opens the files an "Include = value" line names, expanding
	// globs. Library code never touches the file system on its own: the caller
	// decides where includes come from (see FSIncludeResolver and
	// OSIncludeResolver). With a nil Include, ParseConfig leaves Include lines
	// out; ParseConfigFS and ParseConfigFile default to their own resolver.
	Include IncludeResolver
	// MaxIncludeDepth bounds the include nesting; zero selects
	// DefaultMaxIncludeDepth.
	MaxIncludeDepth int
	// MaxIncludeFiles bounds the included files of the whole configuration;
	// zero selects DefaultMaxIncludeFiles.
	MaxIncludeFiles int
	// Strict rejects directives pacman does not know with
	// ErrUnknownDirective; by default they are kept in Config.Unknown.
	Strict bool
}

// IncludeFile is a file an include resolves to. Open is called once, when the
// parser reaches the file, so a pattern matching many files opens them one at
// a time.
type IncludeFile struct {
	// Name appears in error messages.
	Name string
	// Open returns the file's content; the parser closes it.
	Open func() (io.ReadCloser, error)
}

// IncludeText returns an IncludeFile that holds text, for resolvers that do not
// read files.
func IncludeText(name, text string) IncludeFile {
	return IncludeFile{Name: name, Open: func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(text)), nil
	}}
}

// IncludeResolver returns the files an "Include = value" line names, in the
// order pacman reads them (glob matches sorted). A value that names nothing is
// an error, as in pacman. Included files may hold repository sections, options
// or just servers, and are parsed as if their lines stood where the Include
// does.
type IncludeResolver func(include string) ([]IncludeFile, error)

// ParseConfig parses the text of a pacman.conf. [options] yields the global
// options and every other section is a repository; "Include" lines are expanded
// through opts.Include (nil leaves them out). Invalid values (a ParallelDownloads
// that is not a positive number, an unknown SigLevel, CleanMethod or Usage
// option) are errors, as in pacman; other unknown directives are kept in
// Config.Unknown unless opts.Strict.
func ParseConfig(r io.Reader, opts ParseOptions) (*Config, error) {
	return parseConfig("pacman.conf", r, opts)
}

func parseConfig(name string, r io.Reader, opts ParseOptions) (*Config, error) {
	p := &confParser{opts: opts, cfg: &Config{}, repo: -1}

	if p.opts.MaxIncludeDepth <= 0 {
		p.opts.MaxIncludeDepth = DefaultMaxIncludeDepth
	}

	if p.opts.MaxIncludeFiles <= 0 {
		p.opts.MaxIncludeFiles = DefaultMaxIncludeFiles
	}

	if err := p.parse(name, r, 0); err != nil {
		return nil, err
	}

	return p.finish()
}

// confParser holds the state of one parse, shared by the files it includes: a
// section started in an included file stays current after the include, as in
// pacman.
type confParser struct {
	opts    ParseOptions
	cfg     *Config
	section string
	repo    int // index in cfg.Repos of the current repository, -1 outside one
	files   int
	total   int

	// Path options are resolved at the end, once RootDir is known. pacman keeps
	// the first value of RootDir, DBPath, GPGDir, LogFile and DownloadUser.
	rootDir, dbPath, gpgDir, logFile, downloadUser firstValue
	cleanSet                                       CleanMethod
	// SigLevel options are applied at the end too, over the final global level.
	sig, localSig, remoteSig string
	repoSig                  []string
}

func (p *confParser) parse(name string, r io.Reader, depth int) error {
	data, err := p.read(name, r)
	if err != nil {
		return err
	}

	for n, line := range configLines(data) {
		if sec, ok := strings.CutPrefix(line, "["); ok && strings.HasSuffix(line, "]") {
			if err := p.startSection(name, n, strings.TrimSuffix(sec, "]")); err != nil {
				return err
			}

			continue
		}

		key, val, hasVal := strings.Cut(line, "=")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)

		if p.section == "" {
			return lineErr(name, n, "directive %q outside any section", key)
		}

		if key == "Include" {
			if !hasVal || val == "" {
				return lineErr(name, n, "directive 'Include' needs a value")
			}

			if err := p.include(name, n, val, depth); err != nil {
				return err
			}

			continue
		}

		var err error
		if p.repo < 0 {
			err = p.option(name, n, key, val, hasVal)
		} else {
			err = p.repoDirective(name, n, key, val, hasVal)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func lineErr(file string, line int, format string, args ...any) error {
	return fmt.Errorf("%w: %s:%d: %s", ErrInvalidConfig, file, line, fmt.Sprintf(format, args...))
}

func (p *confParser) read(name string, r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if err != nil {
		return "", fmt.Errorf("pacman: reading configuration %s: %w", name, err)
	}

	if len(data) > MaxConfigBytes {
		return "", fmt.Errorf("%w: %s too large", ErrConfigLimit, name)
	}

	if p.total += len(data); p.total > MaxConfigTotalBytes {
		return "", fmt.Errorf("%w: configuration over %d bytes", ErrConfigLimit, MaxConfigTotalBytes)
	}

	return string(data), nil
}

func (p *confParser) startSection(file string, n int, name string) error {
	if name == "" {
		return lineErr(file, n, "empty section name")
	}

	p.section, p.repo = name, -1

	if name == "options" {
		return nil
	}

	if len(p.cfg.Repos) >= MaxConfigRepos {
		return fmt.Errorf("%w: too many repositories", ErrConfigLimit)
	}

	p.cfg.Repos = append(p.cfg.Repos, Repo{Name: name})
	p.repoSig = append(p.repoSig, "")
	p.repo = len(p.cfg.Repos) - 1

	return nil
}

func (p *confParser) include(file string, n int, value string, depth int) error {
	if p.opts.Include == nil {
		return nil
	}

	if depth+1 > p.opts.MaxIncludeDepth {
		return fmt.Errorf("%w: %s:%d: includes nested deeper than %d", ErrConfigLimit, file, n, p.opts.MaxIncludeDepth)
	}

	files, err := p.opts.Include(value)
	if err != nil {
		return fmt.Errorf("pacman: resolving Include %q: %w", value, err)
	}

	if p.files+len(files) > p.opts.MaxIncludeFiles {
		return fmt.Errorf("%w: %s:%d: more than %d included files", ErrConfigLimit, file, n, p.opts.MaxIncludeFiles)
	}

	for _, f := range files {
		p.files++

		if err := p.parseIncluded(f, depth+1); err != nil {
			return err
		}
	}

	return nil
}

func (p *confParser) parseIncluded(f IncludeFile, depth int) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("pacman: opening included %s: %w", f.Name, err)
	}

	defer func() { _ = rc.Close() }()

	return p.parse(f.Name, rc, depth)
}

// option handles a directive of the [options] section.
func (p *confParser) option(file string, n int, key, val string, hasVal bool) error {
	if !hasVal {
		return p.flag(file, n, key)
	}

	c := p.cfg

	switch key {
	case "RootDir":
		p.rootDir.offer(val)
	case "DBPath":
		p.dbPath.offer(val)
	case "GPGDir":
		p.gpgDir.offer(val)
	case "LogFile":
		p.logFile.offer(val)
	case "DownloadUser":
		p.downloadUser.offer(val)
	case "XferCommand":
		c.XferCommand = val
	case "CacheDir":
		return appendValues(file, n, key, &c.CacheDirs, val)
	case "HookDir":
		return appendValues(file, n, key, &c.HookDirs, val)
	case "HoldPkg":
		return appendValues(file, n, key, &c.HoldPkg, val)
	case "IgnorePkg":
		return appendValues(file, n, key, &c.IgnorePkg, val)
	case "IgnoreGroup":
		return appendValues(file, n, key, &c.IgnoreGroup, val)
	case "NoUpgrade":
		return appendValues(file, n, key, &c.NoUpgrade, val)
	case "NoExtract":
		return appendValues(file, n, key, &c.NoExtract, val)
	case "Architecture":
		return appendValues(file, n, key, &c.Architectures, val)
	case "CleanMethod":
		return p.cleanMethod(file, n, val)
	case "ParallelDownloads":
		return p.parallelDownloads(file, n, val)
	case "SigLevel", "LocalFileSigLevel", "RemoteFileSigLevel":
		return p.optionSigLevel(file, n, key, val)
	default:
		return p.unknown(file, n, key, val)
	}

	return nil
}

func (p *confParser) flag(file string, n int, key string) error {
	c := p.cfg

	switch key {
	case "UseSyslog":
		c.UseSyslog = true
	case "Color":
		c.Color = true
	case "CheckSpace":
		c.CheckSpace = true
	case "VerbosePkgLists":
		c.VerbosePkgLists = true
	case "ILoveCandy":
		c.ILoveCandy = true
	case "NoProgressBar":
		c.NoProgressBar = true
	case "DisableDownloadTimeout":
		c.DisableDownloadTimeout = true
	case "DisableSandbox":
		c.DisableSandboxFilesystem, c.DisableSandboxSyscalls = true, true
	case "DisableSandboxFilesystem":
		c.DisableSandboxFilesystem = true
	case "DisableSandboxSyscalls":
		c.DisableSandboxSyscalls = true
	default:
		return p.unknown(file, n, key, "")
	}

	return nil
}

func appendValues(file string, n int, key string, dst *[]string, val string) error {
	vals := splitSpaces(val)

	if len(*dst)+len(vals) > MaxConfigValues {
		return lineErr(file, n, "too many values for %q", key)
	}

	*dst = append(*dst, vals...)

	return nil
}

func (p *confParser) cleanMethod(file string, n int, val string) error {
	for _, tok := range splitSpaces(val) {
		switch tok {
		case "KeepInstalled":
			p.cleanSet |= CleanKeepInstalled
		case "KeepCurrent":
			p.cleanSet |= CleanKeepCurrent
		default:
			return lineErr(file, n, "invalid value for 'CleanMethod' : %q", tok)
		}
	}

	return nil
}

func (p *confParser) parallelDownloads(file string, n int, val string) error {
	v, err := strconv.ParseInt(val, 10, 64)

	switch {
	case errors.Is(err, strconv.ErrRange) && v > 0:
		return lineErr(file, n, "value for 'ParallelDownloads' is too large : %q", val)
	case err != nil:
		return lineErr(file, n, "invalid value for 'ParallelDownloads' : %q", val)
	case v <= 0:
		return lineErr(file, n, "value for 'ParallelDownloads' has to be positive : %q", val)
	case v > math.MaxInt32:
		return lineErr(file, n, "value for 'ParallelDownloads' is too large : %q", val)
	}

	p.cfg.ParallelDownloads = int(v)

	return nil
}

func (p *confParser) optionSigLevel(file string, n int, key, val string) error {
	if _, err := DefaultSigLevel().Apply(val); err != nil {
		return lineErr(file, n, "invalid value for %q : %v", key, err)
	}

	switch key {
	case "SigLevel":
		p.sig += " " + val
	case "LocalFileSigLevel":
		p.localSig += " " + val
	default:
		p.remoteSig += " " + val
	}

	return nil
}

func (p *confParser) unknown(file string, n int, key, val string) error {
	if p.opts.Strict {
		return fmt.Errorf("%w: %s:%d: %q in [%s]", ErrUnknownDirective, file, n, key, p.section)
	}

	if len(p.cfg.Unknown) >= MaxConfigValues {
		return lineErr(file, n, "too many unknown directives")
	}

	p.cfg.Unknown = append(p.cfg.Unknown, Directive{Section: p.section, Key: key, Value: val})

	return nil
}

// repoDirective handles a directive of a repository section.
func (p *confParser) repoDirective(file string, n int, key, val string, hasVal bool) error {
	r := &p.cfg.Repos[p.repo]

	switch key {
	case "Server", "CacheServer", "SigLevel", "Usage":
		if !hasVal {
			return lineErr(file, n, "directive %q needs a value", key)
		}
	default:
		if !hasVal {
			return p.unknown(file, n, key, "")
		}
	}

	switch key {
	case "Server":
		return addServer(file, n, r.Name, &r.Servers, val)
	case "CacheServer":
		return addServer(file, n, r.Name, &r.CacheServers, val)
	case "SigLevel":
		if _, err := DefaultSigLevel().Apply(val); err != nil {
			return lineErr(file, n, "invalid value for 'SigLevel' : %v", err)
		}

		p.repoSig[p.repo] += " " + val
	case "Usage":
		return parseUsage(file, n, r, val)
	default:
		return p.unknown(file, n, key, val)
	}

	return nil
}

func addServer(file string, n int, repo string, dst *[]string, val string) error {
	if len(*dst) >= MaxConfigServers {
		return lineErr(file, n, "too many servers in [%s]", repo)
	}

	if hasControl(val) {
		return lineErr(file, n, "control character in a server of [%s]", repo)
	}

	*dst = append(*dst, val)

	return nil
}

// hasControl reports whether s holds an ASCII control character, which no
// server address can contain (a stray carriage return would end up in a URL).
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f })
}

func parseUsage(file string, n int, r *Repo, val string) error {
	for _, tok := range splitSpaces(val) {
		switch tok {
		case "Sync":
			r.Usage |= UsageSync
		case "Search":
			r.Usage |= UsageSearch
		case "Install":
			r.Usage |= UsageInstall
		case "Upgrade":
			r.Usage |= UsageUpgrade
		case "All":
			r.Usage |= UsageAll
		default:
			return lineErr(file, n, "'Usage' option %q not recognized", tok)
		}
	}

	return nil
}

// finish applies the defaults and merges the signature levels.
func (p *confParser) finish() (*Config, error) {
	c := p.cfg

	c.RootDir = "/"
	if p.rootDir.val != "" {
		c.RootDir = path.Clean(p.rootDir.val)
	}

	c.DownloadUser = p.downloadUser.val

	under := strings.TrimSuffix(c.RootDir, "/") + "/"

	c.DBPath = orDefault(cleanedOr(p.dbPath.val), under+"var/lib/pacman/")
	c.GPGDir = orDefault(cleanedOr(p.gpgDir.val), "/etc/pacman.d/gnupg/")
	c.LogFile = orDefault(p.logFile.val, under+"var/log/pacman.log")

	if len(c.CacheDirs) == 0 {
		c.CacheDirs = []string{"/var/cache/pacman/pkg/"}
	}

	if len(c.HookDirs) == 0 {
		c.HookDirs = []string{"/etc/pacman.d/hooks/"}
	}

	if c.ParallelDownloads == 0 {
		c.ParallelDownloads = 1
	}

	c.CleanMethod = p.cleanSet
	if c.CleanMethod == 0 {
		c.CleanMethod = CleanKeepInstalled
	}

	var err error

	if c.SigLevel, err = DefaultSigLevel().Apply(p.sig); err != nil {
		return nil, err
	}

	if c.LocalFileSigLevel, err = c.SigLevel.Apply(p.localSig); err != nil {
		return nil, err
	}

	if c.RemoteFileSigLevel, err = c.SigLevel.Apply(p.remoteSig); err != nil {
		return nil, err
	}

	for i := range c.Repos {
		if c.Repos[i].SigLevel, err = c.SigLevel.Apply(p.repoSig[i]); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// firstValue is a single-valued option of which pacman keeps the first value.
type firstValue struct {
	val string
	set bool
}

func (f *firstValue) offer(v string) {
	if !f.set {
		f.val, f.set = v, true
	}
}

func cleanedOr(p string) string {
	if p == "" {
		return ""
	}

	return path.Clean(p)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}

	return v
}

// ParseMirrorlist returns the Server entries of a mirrorlist, in order. A
// server holding a control character is an ErrInvalidConfig.
func ParseMirrorlist(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("pacman: reading mirrorlist: %w", err)
	}

	if len(data) > MaxConfigBytes {
		return nil, fmt.Errorf("%w: mirrorlist too large", ErrConfigLimit)
	}

	var servers []string

	for _, line := range configLines(string(data)) {
		key, val, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "Server" {
			continue
		}

		if len(servers) >= MaxConfigServers {
			return nil, fmt.Errorf("%w: too many servers", ErrConfigLimit)
		}

		val = strings.TrimSpace(val)
		if hasControl(val) {
			return nil, fmt.Errorf("%w: control character in a server", ErrInvalidConfig)
		}

		servers = append(servers, val)
	}

	return servers, nil
}

// configLines yields the meaningful lines of a configuration file with their
// 1-based line numbers: trimmed, without blanks and comments.
func configLines(data string) iter.Seq2[int, string] {
	return func(yield func(int, string) bool) {
		sc := bufio.NewScanner(strings.NewReader(data))
		sc.Buffer(make([]byte, 0, 64<<10), MaxConfigBytes+1)

		n := 0

		for sc.Scan() {
			n++

			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}

			if !yield(n, line) {
				return
			}
		}
	}
}

// ExpandServer returns the URL of a server entry for a repository and an
// architecture: $repo and $arch are replaced and trailing slashes dropped.
func ExpandServer(server, repo, arch string) string {
	s := strings.ReplaceAll(server, "$repo", repo)
	s = strings.ReplaceAll(s, "$arch", arch)

	return strings.TrimRight(s, "/")
}

// ArchFromGOARCH maps a GOARCH value to the architecture name Arch Linux
// (and its ports) use. Unknown values are returned unchanged.
func ArchFromGOARCH(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "arm":
		return "armv7h"
	case "386":
		return "i686"
	case "riscv64":
		return "riscv64"
	default:
		return goarch
	}
}
