package dnf

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/M0Rf30/pkgformat/httpclient"
)

// proxyNone is the proxy= value that turns the proxy off for a repository.
const proxyNone = "_none_"

// ErrProxyUnsupported means a repository sets proxy= but the transport of
// [Options.HTTP] is not an *http.Transport, so no proxy can be set on a copy.
var ErrProxyUnsupported = errors.New("dnf: cannot apply proxy= to this HTTP transport")

// httpFor returns the HTTP client for the requests of a repository: the client
// of Options when the repository sets no proxy, else a client on a copy of its
// transport that goes through the proxy (or, for "_none_", directly). Clients
// are shared between the requests that use the same proxy. They keep the
// timeout and redirect policy of Options.HTTP, not its retry policy.
func (c *Client) httpFor(repo *Repo) (*httpclient.Client, error) {
	if repo == nil || repo.Proxy == "" {
		return c.opts.HTTP, nil
	}

	var proxy *url.URL

	if repo.Proxy != proxyNone {
		u, err := url.Parse(c.expandVars(repo.Proxy))
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("dnf: repository %s: invalid proxy %q", repo.ID, repo.Proxy)
		}

		if repo.ProxyUsername != "" {
			u.User = url.UserPassword(repo.ProxyUsername, repo.ProxyPassword)
		}

		proxy = u
	}

	key := proxyNone
	if proxy != nil {
		key = proxy.String()
	}

	if v, ok := c.proxied.Load(key); ok {
		return v.(*httpclient.Client), nil //nolint:forcetypeassert // only httpFor stores here
	}

	base := c.opts.HTTP.HTTP()

	var tr *http.Transport

	switch t := base.Transport.(type) {
	case nil:
		tr, _ = http.DefaultTransport.(*http.Transport)
	case *http.Transport:
		tr = t
	}

	if tr == nil {
		return nil, ErrProxyUnsupported
	}

	clone := tr.Clone()
	if proxy == nil {
		clone.Proxy = nil
	} else {
		clone.Proxy = http.ProxyURL(proxy)
	}

	hc := httpclient.New(httpclient.Options{
		HTTPClient: &http.Client{
			Transport:     clone,
			Timeout:       base.Timeout,
			CheckRedirect: base.CheckRedirect,
			Jar:           base.Jar,
		},
		Logger: c.opts.Logger,
	})

	actual, _ := c.proxied.LoadOrStore(key, hc)

	return actual.(*httpclient.Client), nil //nolint:forcetypeassert // only httpFor stores here
}
