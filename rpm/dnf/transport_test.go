package dnf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// tlsRepo serves the files of repo over https, optionally asking for a client
// certificate and basic authentication.
func tlsRepo(t *testing.T, repo *testRepo, mutate func(*httptest.Server, http.Handler) http.Handler) *httptest.Server {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(repo.serve))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)

	if mutate != nil {
		srv.Config.Handler = mutate(srv, srv.Config.Handler)
	}

	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv
}

func writePEM(t *testing.T, name, kind string, der []byte) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	return p
}

func serverCAFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()

	return writePEM(t, "ca.pem", "CERTIFICATE", srv.Certificate().Raw)
}

func TestSSLVerifyAndSSLCACert(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	srv := tlsRepo(t, repo, nil)

	// the certificate of the test server is not trusted by default
	if err := newEnv(t, baseurlSection(srv.URL)).Update(context.Background()); err == nil {
		t.Fatal("an untrusted certificate was accepted")
	}

	for name, extra := range map[string]string{
		"sslverify=0":    "sslverify=0\n",
		"sslcacert":      "sslcacert=" + serverCAFile(t, srv) + "\n",
		"sslverify=true": "sslverify=true\nsslcacert=" + serverCAFile(t, srv) + "\n",
	} {
		env := newEnv(t, baseurlSection(srv.URL)+extra)
		if err := env.Update(context.Background()); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSSLCACertErrors(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	srv := tlsRepo(t, repo, nil)

	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("no certificate here"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{"missing": "/does/not/exist.pem", "not pem": empty} {
		env := newEnv(t, baseurlSection(srv.URL)+"sslcacert="+path+"\n")

		err := env.Update(context.Background())
		if !errors.Is(err, ErrInvalidTLS) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// selfSigned makes a certificate and key for client authentication.
func selfSigned(t *testing.T) (certFile, keyFile string, cert *x509.Certificate, combined string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "dnf client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	certFile = writePEM(t, "client.pem", "CERTIFICATE", der)
	keyFile = writePEM(t, "client.key", "EC PRIVATE KEY", keyDER)

	both := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)

	combined = filepath.Join(t.TempDir(), "both.pem")
	if err := os.WriteFile(combined, both, 0o600); err != nil {
		t.Fatal(err)
	}

	return certFile, keyFile, cert, combined
}

func TestSSLClientCertificate(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	certFile, keyFile, cert, combined := selfSigned(t)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(repo.serve))
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	ca := "sslcacert=" + serverCAFile(t, srv) + "\n"

	if err := newEnv(t, baseurlSection(srv.URL)+ca).Update(context.Background()); err == nil {
		t.Fatal("the server accepted a client without a certificate")
	}

	for name, extra := range map[string]string{
		"cert and key":   "sslclientcert=" + certFile + "\nsslclientkey=" + keyFile + "\n",
		"combined (pem)": "sslclientcert=" + combined + "\n",
	} {
		if err := newEnv(t, baseurlSection(srv.URL)+ca+extra).Update(context.Background()); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// a key that does not belong
	err := newEnv(t, baseurlSection(srv.URL)+ca+"sslclientcert="+certFile+"\nsslclientkey=/does/not/exist\n").Update(context.Background())
	if !errors.Is(err, ErrInvalidTLS) {
		t.Errorf("err = %v", err)
	}
}

func TestBasicAuthGoesOnlyToTheRepositoryHost(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))

	var (
		mu        sync.Mutex
		elsewhere []string
	)

	// The repository answers with a redirect to another host, which serves the
	// metadata, and must not see the password.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		elsewhere = append(elsewhere, r.Header.Get("Authorization"))
		mu.Unlock()
		repo.serve(w, r)
	}))
	t.Cleanup(other.Close)

	home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "me" || pass != "s3cret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="repo"`)
			http.Error(w, "no", http.StatusUnauthorized)

			return
		}

		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(home.Close)

	env := newEnv(t, baseurlSection(home.URL)+"username=me\npassword=s3cret\n")
	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(elsewhere) == 0 {
		t.Fatal("the redirect was not followed")
	}

	for _, h := range elsewhere {
		if h != "" {
			t.Errorf("credentials sent to another host: %q", h)
		}
	}

	// without credentials the repository refuses (401: the repository is skipped)
	anon := newEnv(t, baseurlSection(home.URL))
	if err := anon.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	repos, _ := anon.Repos()
	if !anon.Expired(&repos[0]) {
		t.Error("anonymous access worked")
	}
}

func TestProxySettingsOfTheRepositoryAreChecked(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))

	// an invalid proxy URL
	err := newEnv(t, baseurlSection(repo.url())+"proxy=not a url\n").Update(context.Background())
	if err == nil {
		t.Error("an invalid proxy was accepted")
	}

	// _none_ bypasses a proxy of the environment
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")

	if err := newEnv(t, baseurlSection(repo.url())+"proxy=_none_\n").Update(context.Background()); err != nil {
		t.Errorf("proxy=_none_: %v", err)
	}
}
