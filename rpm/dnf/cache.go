package dnf

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	repodataDir  = "repodata"
	repomdName   = "repomd.xml"
	baseURLName  = ".baseurl"
	dnfHashChars = 16
)

// repoCacheDir returns the cache directory of a repository: <CacheDir>/<id> if
// it exists, else a directory dnf named <id>-<hash>, else <CacheDir>/<id> for
// the caller to create.
func (c *Client) repoCacheDir(id string) string {
	return findRepoDir(c.opts.CacheDir, id)
}

// findRepoDir returns <base>/<id> if it exists, else a directory dnf named
// <id>-<hash> in base, else <base>/<id> for the caller to create.
func findRepoDir(base, id string) string {
	exact := filepath.Join(base, id)
	if isDir(exact) {
		return exact
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		return exact
	}

	for _, e := range entries {
		if e.IsDir() && isDNFCacheName(e.Name(), id) {
			return filepath.Join(base, e.Name())
		}
	}

	return exact
}

// isDNFCacheName reports whether name is "<id>-<16 hex digits>". Matching the
// whole shape keeps the repository "epel" away from the directory of
// "epel-modular".
func isDNFCacheName(name, id string) bool {
	hash, ok := strings.CutPrefix(name, id+"-")
	if !ok || len(hash) != dnfHashChars {
		return false
	}

	for i := range len(hash) {
		ch := hash[i]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}

	return true
}

func isDir(path string) bool {
	fi, err := os.Stat(path)

	return err == nil && fi.IsDir()
}
