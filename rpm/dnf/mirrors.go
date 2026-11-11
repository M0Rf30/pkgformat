package dnf

import (
	"context"
	"fmt"
	"strings"

	"github.com/M0Rf30/pkgformat/httpclient"
)

// candidates returns the ordered base URLs of a repository, without a trailing
// slash: every baseurl with its variables expanded, or, when there is none, the
// mirrors of its mirror list or metalink. Only http(s) URLs are kept and at
// most maxMirrors are returned. When the list is a metalink, what it says about
// repomd.xml comes back too, for the caller to verify the file with.
func (c *Client) candidates(ctx context.Context, hc *httpclient.Client, repo *Repo) ([]string, *metalinkInfo, error) {
	var (
		out  []string
		info *metalinkInfo
	)

	for _, raw := range repo.BaseURLs {
		if u := c.expandVars(raw); isHTTP(u) {
			out = append(out, strings.TrimSuffix(u, "/"))
		}
	}

	if len(out) == 0 && repo.MirrorList != "" {
		var (
			mirrors []string
			err     error
		)

		list := c.expandVars(repo.MirrorList)
		if flag := c.countmeFlag(repo); flag != "" {
			list = withQuery(list, flag)
		}

		mirrors, info, err = c.resolveMirrors(ctx, hc, list)
		if err != nil {
			return nil, nil, fmt.Errorf("dnf: repository %s: %w", repo.ID, err)
		}

		for _, m := range mirrors {
			out = append(out, strings.TrimSuffix(m, "/"))
		}
	}

	if len(out) == 0 {
		return nil, nil, fmt.Errorf("dnf: repository %s: %w", repo.ID, ErrNoMirror)
	}

	return out[:min(len(out), maxMirrors)], info, nil
}

func isHTTP(u string) bool {
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")
}

// resolveMirrors fetches a mirror list or metalink and returns its base URLs in
// the order the server gave them, at most maxMirrors, https before plain http.
//
// A plain list holds one URL per line, "#" lines are comments. A metalink is
// XML whose <url> elements point at repomd.xml files; the trailing
// /repodata/repomd.xml is stripped to get the base URL. The size and hashes it
// publishes for repomd.xml are returned as well; nil for a plain list.
//
// A 404 on a URL that holds the dotted release (8.10) is retried with the
// major release (8): some mirror managers register the major version only.
func (c *Client) resolveMirrors(
	ctx context.Context, hc *httpclient.Client, listURL string,
) ([]string, *metalinkInfo, error) {
	data, err := hc.FetchBytes(ctx, listURL, maxMirrorListBytes)
	if err != nil {
		data, err = c.retryMajorVersion(ctx, hc, listURL, err)
		if err != nil {
			return nil, nil, err
		}
	}

	body := strings.TrimSpace(string(data))

	var (
		secure, plain []string
		info          *metalinkInfo
	)

	if strings.HasPrefix(body, "<") {
		secure, plain, info = metalinkMirrors(body)
	} else {
		secure, plain = listMirrors(body)
	}

	mirrors := c.preferHTTPS(secure, plain, listURL)
	if len(mirrors) == 0 {
		return nil, nil, fmt.Errorf("%w in %s", ErrNoMirror, listURL)
	}

	return mirrors[:min(len(mirrors), maxMirrors)], info, nil
}

// preferHTTPS returns the secure mirrors when there are any. Plain-http mirrors
// alone are kept, with a warning: what they serve is still checked against the
// checksums of the metadata.
func (c *Client) preferHTTPS(secure, plain []string, source string) []string {
	if len(secure) > 0 {
		return secure
	}

	if len(plain) > 0 {
		c.opts.Logger.Warn("mirror list offers plain http mirrors only", "source", source, "count", len(plain))
	}

	return plain
}

// retryMajorVersion retries a mirror list with the dotted release replaced by
// its major part. It returns the original error when that does not apply or
// fails too.
func (c *Client) retryMajorVersion(
	ctx context.Context, hc *httpclient.Client, listURL string, origErr error,
) ([]byte, error) {
	rel := c.opts.Releasever

	major, _, dotted := strings.Cut(rel, ".")
	if !dotted || !strings.Contains(listURL, rel) {
		return nil, origErr
	}

	data, err := hc.FetchBytes(ctx, strings.ReplaceAll(listURL, rel, major), maxMirrorListBytes)
	if err != nil {
		return nil, origErr
	}

	return data, nil
}

// listMirrors reads a plain mirror list.
func listMirrors(body string) (secure, plain []string) {
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || !isHTTP(line) {
			continue
		}

		line = normalizeURL(line)
		if strings.HasPrefix(line, "https://") {
			secure = append(secure, line)
		} else {
			plain = append(plain, line)
		}
	}

	return secure, plain
}

// metalinkMirrors reads the mirror URLs of a metalink and what it states about
// repomd.xml. A document that does not parse as a metalink is read line by
// line for URLs, with nothing to verify against.
func metalinkMirrors(body string) (secure, plain []string, info *metalinkInfo) {
	lines, info, ok := parseMetalink(body)
	if !ok {
		lines = strings.Split(body, "\n")
	}

	for _, line := range lines {
		u, https := mirrorURL(strings.TrimSpace(line))
		if u == "" {
			continue
		}

		u = normalizeURL(u)
		if https {
			secure = append(secure, u)
		} else {
			plain = append(plain, u)
		}
	}

	return secure, plain, info
}

// mirrorURL pulls an http(s) URL out of a metalink line and turns it into a
// base URL: the /repodata/repomd.xml suffix is stripped and a trailing slash
// ensured. It returns "" for a line without a URL.
func mirrorURL(line string) (u string, https bool) {
	https = true

	start := strings.Index(line, "https://")
	if start < 0 {
		https = false

		if start = strings.Index(line, "http://"); start < 0 {
			return "", false
		}
	}

	end := strings.IndexAny(line[start:], "<\" \t")
	if end < 0 {
		end = len(line[start:])
	}

	u = line[start : start+end]

	if before, found := strings.CutSuffix(u, "/repodata/repomd.xml"); found {
		return before + "/", https
	}

	if strings.HasSuffix(u, "/") {
		return u, https
	}

	return u + "/", https
}
