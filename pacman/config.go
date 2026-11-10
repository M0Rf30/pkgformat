package pacman

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Limits on the configuration files the parsers read.
const (
	// MaxConfigBytes bounds a pacman.conf or a mirrorlist.
	MaxConfigBytes = 4 << 20
	// MaxConfigRepos bounds the repositories of one configuration.
	MaxConfigRepos = 1000
	// MaxConfigServers bounds the servers of one repository.
	MaxConfigServers = 10000
)

// ErrInvalidConfig reports a pacman.conf or mirrorlist that cannot be parsed
// or exceeds a limit.
var ErrInvalidConfig = errors.New("pacman: invalid configuration")

// Config is the part of a pacman.conf a repository client needs: the
// architecture and the repositories with their servers.
type Config struct {
	// Architecture is the value of the Architecture option, such as "auto" or
	// "x86_64"; empty when the option is absent.
	Architecture string
	// Repos are the repositories in the order the file lists them, which is
	// the order pacman searches them.
	Repos []Repo
}

// Repo is a repository: a name and the servers that carry it. A server is a
// URL that may contain the $repo and $arch placeholders (see ExpandServer).
type Repo struct {
	Name    string
	Servers []string
}

// IncludeResolver returns the servers named by an "Include = value" line of a
// repository section, typically by reading the mirrorlist the value points to
// and calling ParseMirrorlist. Library code never touches the file system on
// its own: the caller decides where includes come from.
type IncludeResolver func(include string) ([]string, error)

// ParseConfig parses the text of a pacman.conf. The [options] section yields
// the Architecture; every other section is a repository, whose Server lines
// are collected and whose Include lines are expanded through resolve (nil
// leaves Include lines out). Other options and sections' keys are ignored.
func ParseConfig(r io.Reader, resolve IncludeResolver) (*Config, error) {
	data, err := readConfig(r)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	section := ""

	var cur *Repo

	for line := range configLines(data) {
		if name, ok := strings.CutPrefix(line, "["); ok && strings.HasSuffix(line, "]") {
			section = strings.TrimSuffix(name, "]")
			cur = nil

			if section == "" {
				return nil, fmt.Errorf("%w: empty section name", ErrInvalidConfig)
			}

			if section != "options" {
				if len(cfg.Repos) >= MaxConfigRepos {
					return nil, fmt.Errorf("%w: too many repositories", ErrInvalidConfig)
				}

				cfg.Repos = append(cfg.Repos, Repo{Name: section})
				cur = &cfg.Repos[len(cfg.Repos)-1]
			}

			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key, val = strings.TrimSpace(key), strings.TrimSpace(val)

		switch {
		case section == "options" && key == "Architecture":
			cfg.Architecture = val
		case cur != nil && key == "Server":
			if err := cur.addServers(val); err != nil {
				return nil, err
			}
		case cur != nil && key == "Include" && resolve != nil:
			servers, err := resolve(val)
			if err != nil {
				return nil, fmt.Errorf("pacman: resolving Include %q: %w", val, err)
			}

			if err := cur.addServers(servers...); err != nil {
				return nil, err
			}
		}
	}

	return cfg, nil
}

func (r *Repo) addServers(servers ...string) error {
	if len(r.Servers)+len(servers) > MaxConfigServers {
		return fmt.Errorf("%w: too many servers in [%s]", ErrInvalidConfig, r.Name)
	}

	r.Servers = append(r.Servers, servers...)

	return nil
}

// ParseMirrorlist returns the Server entries of a mirrorlist, in order.
func ParseMirrorlist(r io.Reader) ([]string, error) {
	data, err := readConfig(r)
	if err != nil {
		return nil, err
	}

	var servers []string

	for line := range configLines(data) {
		key, val, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "Server" {
			continue
		}

		if len(servers) >= MaxConfigServers {
			return nil, fmt.Errorf("%w: too many servers", ErrInvalidConfig)
		}

		servers = append(servers, strings.TrimSpace(val))
	}

	return servers, nil
}

// ParseConfigFile reads the pacman.conf at path. Include values are
// mirrorlist paths; a value with glob characters is expanded, as pacman does.
// The path is the caller's: no location is built in.
func ParseConfigFile(path string) (*Config, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("pacman: opening configuration: %w", err)
	}

	defer func() { _ = f.Close() }()

	return ParseConfig(f, resolveIncludeFile)
}

func resolveIncludeFile(include string) ([]string, error) {
	paths := []string{include}

	if strings.ContainsAny(include, "*?[") {
		matches, err := filepath.Glob(include)
		if err != nil {
			return nil, fmt.Errorf("%w: Include pattern %q: %w", ErrInvalidConfig, include, err)
		}

		paths = matches
	}

	var servers []string

	for _, p := range paths {
		got, err := parseMirrorlistFile(p)
		if err != nil {
			return nil, err
		}

		servers = append(servers, got...)
	}

	return servers, nil
}

func parseMirrorlistFile(path string) ([]string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("pacman: opening mirrorlist: %w", err)
	}

	defer func() { _ = f.Close() }()

	return ParseMirrorlist(f)
}

func readConfig(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if err != nil {
		return "", fmt.Errorf("pacman: reading configuration: %w", err)
	}

	if len(data) > MaxConfigBytes {
		return "", fmt.Errorf("%w: file too large", ErrInvalidConfig)
	}

	return string(data), nil
}

// configLines yields the meaningful lines of a configuration file: trimmed,
// without blanks and comments.
func configLines(data string) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		sc := bufio.NewScanner(strings.NewReader(data))
		sc.Buffer(make([]byte, 0, 64<<10), MaxConfigBytes+1)

		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}

			if !yield(line) {
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
