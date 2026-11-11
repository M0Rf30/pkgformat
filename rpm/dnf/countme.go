package dnf

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/httpclient"
)

// The countme algorithm of dnf: a repository with countme=1 is counted once
// per week, by one request for its mirror list that carries "countme=N", where
// N says how long the system has been around (bucket 1 to 4). The week is a
// window that starts on a Monday at 00:00 UTC and slides along with the clock,
// so that the request that counts is not tied to the last one. Which request of
// the window counts is drawn at random among the first countmeBudget, so that
// no request is special.
const (
	countmeWindow int64 = 7 * 24 * 60 * 60
	// countmeOffset is Monday 1970-01-05 00:00:00 UTC.
	countmeOffset = 345600
	countmeBudget = 4
	countmeCookie = "countme"
	countmeFormat = 0
)

// countmeBuckets are the window steps that end the buckets 1, 2 and 3: bucket
// 1 is steps [0, 2), bucket 2 [2, 5), bucket 3 [5, 25), bucket 4 the rest.
var countmeBuckets = [...]int64{2, 5, 25}

// countmeFlag returns "countme=N" when the request for the mirror list of repo
// that is about to be made is the one of the current window that counts, and
// "" otherwise. It keeps the cookie <PersistDir>/repos/<repo>/countme (the file
// dnf keeps: the format version, the first window seen, the last window
// counted and what is left of the budget). Nothing is counted without
// Options.PersistDir, for a repository without a mirror list or metalink, or
// without countme=1.
func (c *Client) countmeFlag(repo *Repo) string {
	if !repo.CountMe || c.opts.PersistDir == "" || repo.MirrorList == "" {
		return ""
	}

	dir := findRepoDir(filepath.Join(c.opts.PersistDir, "repos"), repo.ID)
	cookie := filepath.Join(dir, countmeCookie)

	c.countmeMu.Lock()
	defer c.countmeMu.Unlock()

	var (
		version, epoch int64
		win            int64 = countmeOffset
		budget         int64 = -1
	)

	if data, err := readCapped(cookie, maxVarBytes); err == nil {
		_, _ = fmt.Sscan(string(data), &version, &epoch, &win, &budget)
	}

	now := c.now().Unix()

	delta := now - win
	if delta < countmeWindow {
		return ""
	}

	if budget < 0 {
		budget = int64(c.intn(countmeBudget)) + 1
	}

	budget--

	flag := ""

	if budget == 0 {
		win = now - delta%countmeWindow

		if sys := c.systemEpoch(); sys != 0 {
			epoch = sys - (sys-countmeOffset)%countmeWindow
		}

		if epoch == 0 {
			epoch = win
		}

		step := (win - epoch) / countmeWindow

		bucket := len(countmeBuckets)
		for i, limit := range countmeBuckets {
			if step < limit {
				bucket = i

				break
			}
		}

		flag = "countme=" + strconv.Itoa(bucket+1)
		budget = -1
	}

	if err := os.MkdirAll(dir, 0o755); err == nil { //nolint:gosec // state others may read, as dnf's
		_ = httpclient.AtomicWrite(cookie, func(w io.Writer) error {
			_, err := fmt.Fprintf(w, "%d %d %d %d", countmeFormat, epoch, win, budget)

			return err
		})
	}

	return flag
}

// systemEpoch returns the modification time of Options.MachineIDFile, the
// moment the system was installed or first booted, or 0 when it is not given,
// is empty or says "uninitialized".
func (c *Client) systemEpoch() int64 {
	if c.opts.MachineIDFile == "" {
		return 0
	}

	fi, err := os.Stat(c.opts.MachineIDFile)
	if err != nil || fi.Size() == 0 {
		return 0
	}

	data, err := readCapped(c.opts.MachineIDFile, maxVarBytes)
	if err != nil || strings.TrimSpace(string(data)) == "uninitialized" {
		return 0
	}

	return fi.ModTime().Unix()
}

// withQuery appends a query parameter to a URL.
func withQuery(rawURL, param string) string {
	if strings.Contains(rawURL, "?") {
		return rawURL + "&" + param
	}

	return rawURL + "?" + param
}
