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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/M0Rf30/pkgformat/httpclient"
	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/repodata"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// repoPkg is a package of a test repository: its metadata and the bytes the
// server hands out for it.
type repoPkg struct {
	pkg  rpm.Package
	body []byte
	// listed are the files only filelists.xml names.
	listed []string
}

func pkgOf(name, version string, requires ...string) repoPkg {
	p := rpm.Package{Name: name, Version: version, Release: "1", Arch: "x86_64"}
	p.Requires = deps(requires...)

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

	if fl := filelistsXML(pkgs, list); fl != nil {
		packed, err := repodata.CompressMetadataStream(repodata.Gzip, func(w io.Writer) error {
			_, err := w.Write(fl)

			return err
		})
		if err != nil {
			r.t.Fatal(err)
		}

		e := entryFor("filelists", packed.SHA256, packed.Data)
		e.Location = "repodata/" + packed.SHA256 + "-filelists.xml.gz"
		entries = append(entries, e)
		files["/"+e.Location] = packed.Data
	}

	repomd, err := repodata.GenerateRepomdXML("1", entries)
	if err != nil {
		r.t.Fatal(err)
	}

	files["/repodata/repomd.xml"] = repomd

	r.mu.Lock()
	r.files = files
	r.mu.Unlock()
}

// filelistsXML renders the filelists.xml of the packages that have listed
// files, nil when none has.
func filelistsXML(pkgs []repoPkg, list []rpm.Package) []byte {
	var buf bytes.Buffer

	hasLists := false

	buf.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<filelists xmlns=\"http://linux.duke.edu/metadata/filelists\">\n")

	for i, rp := range pkgs {
		if len(rp.listed) == 0 {
			continue
		}

		hasLists = true

		p := list[i]
		buf.WriteString("<package pkgid=\"" + p.SHA256 + "\" name=\"" + p.Name + "\" arch=\"" + p.Arch + "\">")
		buf.WriteString("<version epoch=\"0\" ver=\"" + p.Version + "\" rel=\"" + p.Release + "\"/>")

		for _, f := range rp.listed {
			buf.WriteString("<file>" + f + "</file>")
		}

		buf.WriteString("</package>\n")
	}

	buf.WriteString("</filelists>\n")

	if !hasLists {
		return nil
	}

	return buf.Bytes()
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

// fakeInstalled is an Installed over a fixed list.
type fakeInstalled struct {
	pkgs []*rpm.Package
	err  error
}

func (f fakeInstalled) InstalledPackages(_ context.Context) ([]*rpm.Package, error) {
	return f.pkgs, f.err
}

// dep reads a dependency as written in a spec: "name", "name >= 1:2.0-3", or a
// rich dependency in parentheses.
func dep(s string) rpm.Dependency {
	if strings.HasPrefix(s, "(") {
		return rpm.Dependency{Name: s}
	}

	fields := strings.Fields(s)
	d := rpm.Dependency{Name: fields[0]}

	if len(fields) == 3 {
		d.Flags = map[string]uint32{
			"<": tag.RPMSENSE_LESS, "<=": tag.RPMSENSE_LESS | tag.RPMSENSE_EQUAL, "=": tag.RPMSENSE_EQUAL,
			">=": tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL, ">": tag.RPMSENSE_GREATER,
		}[fields[1]]

		d.Version = fields[2]
		if e, v, ok := strings.Cut(fields[2], ":"); ok {
			n, _ := strconv.ParseUint(e, 10, 32)
			d.Epoch, d.Version = uint32(n), v
		}
	}

	return d
}

func deps(specs ...string) []rpm.Dependency {
	var out []rpm.Dependency

	for _, s := range specs {
		out = append(out, dep(s))
	}

	return out
}

// tpkg describes a package of a unit test with dependency specs as strings.
type tpkg struct {
	name, version, release, arch  string
	epoch                         uint32
	requires, provides, conflicts []string
	obsoletes, recommends, files  []string
	priority, cost                int
	repo                          *Repo
}

func (t tpkg) build() *Package {
	p := &Package{
		Name: t.name, Version: t.version, Release: t.release, Arch: t.arch, Epoch: t.epoch,
		Provides: deps(t.provides...), Requires: deps(t.requires...), Conflicts: deps(t.conflicts...),
		Obsoletes: deps(t.obsoletes...), Recommends: deps(t.recommends...), Files: t.files,
		Priority: t.priority, Cost: t.cost, Repo: "test", Location: "Packages/" + t.name + ".rpm",
		repo: t.repo,
	}

	if p.Version == "" {
		p.Version = "1"
	}

	if p.Release == "" {
		p.Release = "1"
	}

	if p.Arch == "" {
		p.Arch = "x86_64"
	}

	if p.Priority == 0 {
		p.Priority = defaultPriority
	}

	if p.Cost == 0 {
		p.Cost = defaultCost
	}

	p.addSelfProvide()

	return p
}

// installedPkg builds a package of the host's database.
func installedPkg(t tpkg) *rpm.Package {
	p := t.build()
	out := &rpm.Package{
		Name: p.Name, Version: p.Version, Release: p.Release, Arch: p.Arch, Epoch: p.Epoch,
		Provides: p.Provides, Requires: p.Requires, Conflicts: p.Conflicts, Obsoletes: p.Obsoletes,
	}

	for _, f := range t.files {
		out.Files = append(out.Files, fileEntry(f))
	}

	return out
}

// testIndex builds an index of the given packages without a repository.
func testIndex(installed Installed, pkgs ...tpkg) *Index {
	c := New(Options{Arch: "x86_64", Installed: installed})
	ix := newIndex(c, DefaultConfig())

	for _, t := range pkgs {
		ix.add(t.build())
	}

	ix.finalize()

	return ix
}

func fileEntry(p string) rpm.FileEntry { return rpm.FileEntry{Path: p} }
