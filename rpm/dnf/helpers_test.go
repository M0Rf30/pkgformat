package dnf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/M0Rf30/pkgformat/httpclient"
	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

// repoPkg is a package of a test repository: its metadata and the bytes the
// server hands out for it.
type repoPkg struct {
	pkg  rpm.Package
	body []byte
}

func pkgOf(name, version string, requires ...string) repoPkg {
	p := rpm.Package{Name: name, Version: version, Release: "1", Arch: "x86_64"}
	for _, r := range requires {
		p.Requires = append(p.Requires, rpm.Dependency{Name: r})
	}

	return repoPkg{pkg: p, body: []byte("rpm body of " + name + "-" + version)}
}

// testRepo is a repository served over HTTP. It counts the requests per path
// and can answer a path with a chosen status.
type testRepo struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	files   map[string][]byte
	status  map[string]int
	hits    map[string]int
	modTime time.Time
}

func newTestRepo(t *testing.T, pkgs ...repoPkg) *testRepo {
	t.Helper()

	r := &testRepo{
		t:       t,
		files:   map[string][]byte{},
		status:  map[string]int{},
		hits:    map[string]int{},
		modTime: time.Now().Add(-time.Hour),
	}

	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	r.publish(pkgs, "")

	return r
}

func (r *testRepo) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.hits[req.URL.Path]++
	code := r.status[req.URL.Path]
	body, ok := r.files[req.URL.Path]
	mod := r.modTime
	r.mu.Unlock()

	switch {
	case code != 0:
		http.Error(w, "forced", code)
	case !ok:
		http.NotFound(w, req)
	default:
		http.ServeContent(w, req, path.Base(req.URL.Path), mod, bytes.NewReader(body))
	}
}

// publish replaces the repository content: the packages, a primary document and
// optional modules.yaml, and the repomd.xml that names them.
func (r *testRepo) publish(pkgs []repoPkg, modulesYAML string) {
	r.t.Helper()

	files := map[string][]byte{}
	list := make([]rpm.Package, len(pkgs))

	for i, rp := range pkgs {
		sum := sha256.Sum256(rp.body)
		p := rp.pkg
		p.SHA256 = hex.EncodeToString(sum[:])
		p.PackageSize = int64(len(rp.body))
		list[i] = p
		files["/"+repodata.PackageLocation(&p)] = rp.body
	}

	primary, err := repodata.CompressMetadataStream(repodata.Gzip, func(w io.Writer) error {
		return repodata.WritePrimaryXML(w, list)
	})
	if err != nil {
		r.t.Fatal(err)
	}

	entries := []repodata.RepomdData{entryFor("primary", primary.SHA256, primary.Data)}
	files["/repodata/"+primary.SHA256+"-primary.xml.gz"] = primary.Data

	if modulesYAML != "" {
		data := []byte(modulesYAML)
		sum := sha256.Sum256(data)
		hexSum := hex.EncodeToString(sum[:])
		entries = append(entries, entryFor("modules", hexSum, data))
		entries[1].Location = "repodata/" + hexSum + "-modules.yaml"
		files["/"+entries[1].Location] = data
	}

	entries[0].Location = "repodata/" + primary.SHA256 + "-primary.xml.gz"

	repomd, err := repodata.GenerateRepomdXML("1", entries)
	if err != nil {
		r.t.Fatal(err)
	}

	files["/repodata/repomd.xml"] = repomd

	r.mu.Lock()
	r.files = files
	r.mu.Unlock()
}

func entryFor(kind, sum string, data []byte) repodata.RepomdData {
	return repodata.RepomdData{
		Type: kind, Checksum: sum, ChecksumType: "sha256", Timestamp: 1, Size: int64(len(data)),
	}
}

// primaryPath is where publish put the primary document.
func (r *testRepo) primaryPath() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	for p := range r.files {
		if strings.HasSuffix(p, "-primary.xml.gz") {
			return p
		}
	}

	return ""
}

func (r *testRepo) set(p string, code int) {
	r.mu.Lock()
	r.status[p] = code
	r.mu.Unlock()
}

func (r *testRepo) corrupt(p string) {
	r.mu.Lock()
	r.files[p] = []byte("not what the checksum says")
	r.mu.Unlock()
}

func (r *testRepo) count(p string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.hits[p]
}

func (r *testRepo) url() string { return r.srv.URL }

// testEnv is a client over temporary directories.
type testEnv struct {
	*Client

	repoDir, cacheDir, destDir string
}

// newEnv writes a "test.repo" with the given repo section body and returns a
// client that retries nothing.
func newEnv(t *testing.T, section string, tweak ...func(*Options)) *testEnv {
	t.Helper()

	dir := t.TempDir()
	env := &testEnv{
		repoDir:  filepath.Join(dir, "repos"),
		cacheDir: filepath.Join(dir, "cache"),
		destDir:  filepath.Join(dir, "dest"),
	}

	if err := os.MkdirAll(env.repoDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(env.repoDir, "test.repo"), []byte(section), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		RepoDir:    env.repoDir,
		CacheDir:   env.cacheDir,
		Releasever: "9",
		Arch:       "x86_64",
		HTTP:       httpclient.New(httpclient.Options{Retry: httpclient.RetryPolicy{Attempts: 1}}),
	}

	for _, f := range tweak {
		f(&opts)
	}

	env.Client = New(opts)

	return env
}

// baseurlSection is the usual one-repository file.
func baseurlSection(urls ...string) string {
	return "[test]\nname=Test\nenabled=1\nbaseurl=" + strings.Join(urls, " ") + "\n"
}

// fakeInstalled is an Installed over fixed lists.
type fakeInstalled struct {
	names, provides []string
	err             error
}

func (f fakeInstalled) InstalledNames(_ context.Context) ([]string, error) { return f.names, f.err }

func (f fakeInstalled) InstalledProvides(_ context.Context) ([]string, error) {
	return f.provides, f.err
}

func fileEntry(p string) rpm.FileEntry { return rpm.FileEntry{Path: p} }
