package apk

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// Repo is one repository of a repositories file.
type Repo struct {
	// URL is the base URL of the repository, without a trailing slash: the
	// index is at <URL>/<arch>/APKINDEX.tar.gz.
	URL string
	// Tag is the tag of a tagged repository ("edge" for "@edge https://…"),
	// empty for an untagged one. The tag is carried for the caller: the
	// resolver does not use it.
	Tag string
}

// ErrInvalidRepositories is wrapped by every error ParseRepositories returns.
var ErrInvalidRepositories = errors.New("apk: invalid repositories file")

// Limits of ParseRepositories.
const (
	maxRepositoriesBytes = 1 << 20
	maxRepositories      = 10_000
	maxRepositoryLine    = 4096
)

// ParseRepositories parses the text of an apk repositories file (the
// repositories file of /etc/apk): one repository per line, either a URL or
// "@tag URL", with blank lines and '#' comments ignored. Trailing slashes are
// dropped. It reads at most 1 MiB and 10 000 repositories. The caller opens the file;
// the package never reads a host path.
func ParseRepositories(r io.Reader) ([]Repo, error) {
	sc := bufio.NewScanner(io.LimitReader(r, maxRepositoriesBytes+1))
	sc.Buffer(make([]byte, 0, 4096), maxRepositoryLine)

	var (
		repos []Repo
		read  int
	)

	for line := 1; sc.Scan(); line++ {
		text := sc.Text()

		read += len(text) + 1
		if read > maxRepositoriesBytes {
			return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidRepositories, maxRepositoriesBytes)
		}

		text = strings.TrimSpace(text)
		if text == "" || text[0] == '#' {
			continue
		}

		repo, err := parseRepositoryLine(text)
		if err != nil {
			return nil, fmt.Errorf("%w: line %d: %w", ErrInvalidRepositories, line, err)
		}

		if len(repos) >= maxRepositories {
			return nil, fmt.Errorf("%w: more than %d repositories", ErrInvalidRepositories, maxRepositories)
		}

		repos = append(repos, repo)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRepositories, err)
	}

	return repos, nil
}

func parseRepositoryLine(text string) (Repo, error) {
	fields := strings.Fields(text)

	var repo Repo

	if tag, ok := strings.CutPrefix(fields[0], "@"); ok {
		if tag == "" || len(fields) != 2 {
			return Repo{}, errors.New("a tagged repository is \"@tag URL\"")
		}

		repo.Tag, fields = tag, fields[1:]
	}

	if len(fields) != 1 {
		return Repo{}, errors.New("want one URL")
	}

	repo.URL = strings.TrimRight(fields[0], "/")
	if repo.URL == "" {
		return Repo{}, errors.New("empty URL")
	}

	return repo, nil
}

// checkRepoURL accepts an http or https base URL with a host.
func checkRepoURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("repository URL %q: %w", short(raw), err)
	}

	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("repository URL %q is not an http or https URL", short(raw))
	}

	return nil
}
