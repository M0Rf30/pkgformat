package dnf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/M0Rf30/pkgformat/httpclient"
)

// proxyNone is the proxy= value that turns the proxy off for a repository.
const proxyNone = "_none_"

// Errors of the per-repository HTTP settings. Test with errors.Is.
var (
	// ErrTransportUnsupported means a repository sets proxy=, ssl* options
	// or credentials but the transport of [Options.HTTP] is not an
	// *http.Transport, so no copy with those settings can be made.
	ErrTransportUnsupported = errors.New("dnf: cannot apply the repository's proxy, TLS or credential settings to this HTTP transport")
	// ErrInvalidTLS means the sslcacert, sslclientcert or sslclientkey of a
	// repository cannot be read or holds no certificate or key.
	ErrInvalidTLS = errors.New("dnf: invalid TLS settings of a repository")
)

// transportKey is what makes two repositories share a client: the settings
// that go into the transport.
type transportKey struct {
	proxy, proxyUser, proxyPass string
	insecure                    bool
	caCert, clientCert, key     string
	user, pass                  string
}

// httpFor returns the HTTP client for the requests of a repository: the client
// of Options when the repository changes nothing about how requests are made,
// else a client on a copy of its transport that goes through the repository's
// proxy (for "_none_", directly), checks the server against sslcacert, skips
// the check for sslverify=0, presents the client certificate and sends
// the username and password to the hosts of the repository's own URLs. Clients
// are shared between the repositories with the same settings. They keep the
// timeout and redirect policy of Options.HTTP, not its retry policy.
func (c *Client) httpFor(repo *Repo) (*httpclient.Client, error) {
	if repo == nil {
		return c.opts.HTTP, nil
	}

	key := transportKey{
		proxy:      repo.Proxy,
		proxyUser:  repo.ProxyUsername,
		proxyPass:  repo.ProxyPassword,
		insecure:   repo.SkipSSLVerify,
		caCert:     c.expandVars(repo.SSLCACert),
		clientCert: c.expandVars(repo.SSLClientCert),
		key:        c.expandVars(repo.SSLClientKey),
		user:       repo.Username,
		pass:       repo.Password,
	}

	if key == (transportKey{}) {
		return c.opts.HTTP, nil
	}

	// The hosts of a repository decide where its credentials go, so they are
	// part of what makes clients distinct.
	hosts := c.repoHosts(repo)
	cacheKey := fmt.Sprintf("%v|%v", key, hosts)

	if v, ok := c.proxied.Load(cacheKey); ok {
		return v.(*httpclient.Client), nil //nolint:forcetypeassert // only httpFor stores here
	}

	tr, err := c.cloneTransport(repo, &key)
	if err != nil {
		return nil, err
	}

	var rt http.RoundTripper = tr
	if key.user != "" {
		rt = &authTransport{next: tr, user: key.user, pass: key.pass, hosts: hosts}
	}

	base := c.opts.HTTP.HTTP()

	hc := httpclient.New(httpclient.Options{
		HTTPClient: &http.Client{
			Transport:     rt,
			Timeout:       base.Timeout,
			CheckRedirect: base.CheckRedirect,
			Jar:           base.Jar,
		},
		Logger: c.opts.Logger,
	})

	actual, _ := c.proxied.LoadOrStore(cacheKey, hc)

	return actual.(*httpclient.Client), nil //nolint:forcetypeassert // only httpFor stores here
}

// cloneTransport copies the transport of Options.HTTP and applies the proxy and
// TLS settings of the repository.
func (c *Client) cloneTransport(repo *Repo, key *transportKey) (*http.Transport, error) {
	var tr *http.Transport

	switch t := c.opts.HTTP.HTTP().Transport.(type) {
	case nil:
		tr, _ = http.DefaultTransport.(*http.Transport)
	case *http.Transport:
		tr = t
	}

	if tr == nil {
		return nil, ErrTransportUnsupported
	}

	clone := tr.Clone()

	switch {
	case key.proxy == proxyNone:
		clone.Proxy = nil
	case key.proxy != "":
		u, err := url.Parse(c.expandVars(key.proxy))
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("dnf: repository %s: invalid proxy %q", repo.ID, repo.Proxy)
		}

		if key.proxyUser != "" {
			u.User = url.UserPassword(key.proxyUser, key.proxyPass)
		}

		clone.Proxy = http.ProxyURL(u)
	}

	if key.insecure || key.caCert != "" || key.clientCert != "" {
		cfg, err := tlsConfig(clone.TLSClientConfig, key)
		if err != nil {
			return nil, fmt.Errorf("repository %s: %w", repo.ID, err)
		}

		clone.TLSClientConfig = cfg
	}

	return clone, nil
}

// tlsConfig builds the TLS settings of a repository on top of the transport's.
func tlsConfig(base *tls.Config, key *transportKey) (*tls.Config, error) {
	cfg := base.Clone()
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	cfg.InsecureSkipVerify = key.insecure

	if key.caCert != "" {
		pem, err := readCapped(key.caCert, gpg.MaxKeyringBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: sslcacert: %w", ErrInvalidTLS, err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: sslcacert %s holds no certificate", ErrInvalidTLS, key.caCert)
		}

		cfg.RootCAs = pool
	}

	if key.clientCert != "" {
		keyFile := key.key
		if keyFile == "" {
			// A PEM file may hold the certificate and its key together.
			keyFile = key.clientCert
		}

		cert, err := tls.LoadX509KeyPair(key.clientCert, keyFile)
		if err != nil {
			return nil, fmt.Errorf("%w: sslclientcert: %w", ErrInvalidTLS, err)
		}

		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// repoHosts returns the hosts of the URLs a repository names itself: where its
// credentials may go.
func (c *Client) repoHosts(repo *Repo) []string {
	var hosts []string

	add := func(raw string) {
		if u, err := url.Parse(c.expandVars(raw)); err == nil && u.Host != "" {
			hosts = append(hosts, strings.ToLower(u.Host))
		}
	}

	for _, b := range repo.BaseURLs {
		add(b)
	}

	if repo.MirrorList != "" {
		add(repo.MirrorList)
	}

	return hosts
}

// authTransport sends HTTP basic authentication, but only to the hosts it was
// made for: a redirect to another host must not carry the password along.
type authTransport struct {
	next       http.RoundTripper
	user, pass string
	hosts      []string
}

func (a *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := strings.ToLower(req.URL.Host)
	for _, h := range a.hosts {
		if h == host {
			req = req.Clone(req.Context())
			req.SetBasicAuth(a.user, a.pass)

			break
		}
	}

	return a.next.RoundTrip(req)
}
