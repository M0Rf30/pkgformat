package apt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/M0Rf30/pkgformat/httpclient"
)

// hostArch is the host architecture the tests resolve against, whatever
// machine they run on.
const hostArch = "amd64"

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testClient is a client whose retries do not sleep.
func testClient(attempts int) *httpclient.Client {
	return httpclient.New(httpclient.Options{
		Retry: httpclient.RetryPolicy{Attempts: attempts, BaseDelay: -1},
	})
}

func writeFile(tb testing.TB, path, content string) {
	tb.Helper()

	require.NoError(tb, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(tb, os.WriteFile(path, []byte(content), 0o644))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// para renders a deb822 paragraph from "Field: value" lines.
func para(lines ...string) string {
	return strings.Join(lines, "\n") + "\n\n"
}

// indexName is the lists-directory file name of a Packages index for a source
// at example.org.
func indexName(suite, comp, arch string) string {
	return fmt.Sprintf("example.org_dists_%s_%s_binary-%s_Packages", suite, comp, arch)
}

// cacheFromFiles writes the named index files into a fresh lists directory and
// loads them with the host architecture, failing on any load error.
func cacheFromFiles(tb testing.TB, files map[string]string, sources ...Source) *Cache {
	tb.Helper()

	dir := tb.TempDir()

	for name, content := range files {
		writeFile(tb, filepath.Join(dir, name), content)
	}

	c, err := Load(LoadOptions{ListsDir: dir, HostArch: hostArch, Sources: sources})
	require.NoError(tb, err)
	require.NotNil(tb, c)

	return c
}

// cacheFromText loads one amd64 index.
func cacheFromText(tb testing.TB, text string) *Cache {
	tb.Helper()

	return cacheFromFiles(tb, map[string]string{indexName("x", "main", hostArch): text})
}

// names lists the Name:Architecture of resolved packages in order.
func names(pkgs []*PackageInfo) []string {
	out := make([]string, len(pkgs))
	for i, p := range pkgs {
		out[i] = p.Name + ":" + p.Architecture
	}

	return out
}

// testRepo is an in-memory HTTP repository that counts the requests it serves.
type testRepo struct {
	*httptest.Server

	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
}

func newTestRepo(tb testing.TB) *testRepo {
	tb.Helper()

	r := &testRepo{files: map[string][]byte{}, hits: map[string]int{}}
	r.Server = httptest.NewServer(http.HandlerFunc(r.serve))
	tb.Cleanup(r.Close)

	return r
}

func (r *testRepo) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.hits[req.URL.Path]++
	data, ok := r.files[req.URL.Path]
	r.mu.Unlock()

	if !ok {
		http.NotFound(w, req)

		return
	}

	_, _ = w.Write(data)
}

func (r *testRepo) put(path string, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.files[path] = data
}

func (r *testRepo) remove(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.files, path)
}

func (r *testRepo) count(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.hits[path]
}

func (r *testRepo) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := 0
	for _, c := range r.hits {
		n += c
	}

	return n
}

func (r *testRepo) baseURL() string { return r.URL + "/" }

// newSigner generates a throwaway ed25519 signing key.
func newSigner(tb testing.TB) *gpg.LocalSigner {
	tb.Helper()

	entity, err := gpg.GenerateEntity("apt test", "", "apt@example.org", gpg.AlgorithmED25519)
	require.NoError(tb, err)

	signer, err := gpg.NewLocalSignerFromEntity(entity)
	require.NoError(tb, err)

	return signer
}

// writeKeyring stores the public key of signer in a file and returns its path.
func writeKeyring(tb testing.TB, dir string, signer *gpg.LocalSigner) string {
	tb.Helper()

	pub, err := signer.PublicKey()
	require.NoError(tb, err)

	path := filepath.Join(dir, "key-"+signer.KeyID()+".asc")
	require.NoError(tb, os.WriteFile(path, pub, 0o644))

	return path
}

// Release signing modes of a fixture.
const (
	signInRelease = "inrelease" // InRelease only
	signDetached  = "detached"  // Release and Release.gpg only
	signNone      = "none"      // an unsigned Release only
)

// fixture is a signed apt repository served over HTTP, with one suite.
type fixture struct {
	tb      testing.TB
	repo    *testRepo
	signer  *gpg.LocalSigner
	keyPath string
	lists   string
	suite   string
	arch    string
	// comps maps a component to the text of its Packages index.
	comps   map[string]string
	formats []deb.Compression
	sign    string
	// mutate may adjust the Release before it is rendered.
	mutate func(*deb.Release)
	// debs holds the content of the packages addPackage published, by name.
	debs map[string][]byte
}

func newFixture(tb testing.TB) *fixture {
	tb.Helper()

	signer := newSigner(tb)

	return &fixture{
		tb:      tb,
		repo:    newTestRepo(tb),
		signer:  signer,
		keyPath: writeKeyring(tb, tb.TempDir(), signer),
		lists:   filepath.Join(tb.TempDir(), "lists"),
		suite:   "stable",
		arch:    hostArch,
		comps:   map[string]string{"main": ""},
		formats: []deb.Compression{deb.CompressionXZ, deb.CompressionGzip, deb.CompressionNone},
		sign:    signInRelease,
		debs:    map[string][]byte{},
	}
}

// addPackage publishes a fake .deb in the pool and lists it in the index of
// comp. extra are further control fields.
func (f *fixture) addPackage(comp, name, version string, extra ...string) []byte {
	f.tb.Helper()

	content := []byte("payload of " + name + " " + version)
	filename := fmt.Sprintf("pool/%s/%s_%s_%s.deb", comp, name, version, f.arch)

	f.repo.put("/"+filename, content)
	f.debs[name] = content

	lines := []string{
		"Package: " + name,
		"Version: " + version,
		"Architecture: " + f.arch,
		"Filename: " + filename,
		fmt.Sprintf("Size: %d", len(content)),
		"SHA256: " + sha256Hex(content),
	}

	f.comps[comp] += para(append(lines, extra...)...)

	return content
}

func (f *fixture) source() Source {
	comps := make([]string, 0, len(f.comps))
	for c := range f.comps {
		comps = append(comps, c)
	}

	slices.Sort(comps)

	return Source{URL: f.repo.baseURL(), Suite: f.suite, Components: comps, SignedBy: f.keyPath}
}

func (f *fixture) opts() UpdateOptions {
	return UpdateOptions{
		ListsDir:    f.lists,
		DefaultArch: f.arch,
		Client:      testClient(2),
		Concurrency: 4,
	}
}

func (f *fixture) distPath(rel string) string { return "/dists/" + f.suite + "/" + rel }

// indexRel is the Release-relative path of the index of a component.
func (f *fixture) indexRel(comp, ext string) string {
	return comp + "/binary-" + f.arch + "/Packages" + ext
}

// listPath is where Update stores the index variant of a component.
func (f *fixture) listPath(comp, ext string) string {
	return filepath.Join(f.lists, ListFileName(f.repo.baseURL(), f.suite, f.indexRel(comp, ext)))
}

// publish (re)renders the indexes and the signed Release into the repository.
func (f *fixture) publish() {
	f.tb.Helper()

	rel := &deb.Release{
		Suite:         f.suite,
		Codename:      f.suite,
		Date:          time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Architectures: []string{f.arch},
	}

	for comp, text := range f.comps {
		rel.Components = append(rel.Components, comp)

		var ix deb.Index

		ix.AddText(text)

		for _, c := range f.formats {
			data := ix.Bytes()
			if c != deb.CompressionNone {
				var err error

				data, err = ix.Compressed(c)
				require.NoError(f.tb, err)
			}

			path := f.indexRel(comp, c.Extension())
			f.repo.put(f.distPath(path), data)
			rel.AddFile(deb.HashBytes(path, data))
		}
	}

	slices.Sort(rel.Components)

	if f.mutate != nil {
		f.mutate(rel)
	}

	body := rel.Marshal()

	for _, p := range []string{"InRelease", "Release", "Release.gpg"} {
		f.repo.remove(f.distPath(p))
	}

	switch f.sign {
	case signNone:
		f.repo.put(f.distPath("Release"), body)
	case signDetached, signInRelease:
		signed, err := deb.SignRelease(f.signer, body)
		require.NoError(f.tb, err)

		if f.sign == signInRelease {
			f.repo.put(f.distPath("InRelease"), signed.InRelease)
		} else {
			f.repo.put(f.distPath("Release"), signed.Release)
			f.repo.put(f.distPath("Release.gpg"), signed.ReleaseGPG)
		}
	default:
		f.tb.Fatalf("unknown sign mode %q", f.sign)
	}
}

// load loads the lists directory with the fixture's source.
func (f *fixture) load() (*Cache, error) {
	return Load(LoadOptions{ListsDir: f.lists, HostArch: f.arch, Sources: []Source{f.source()}})
}

// runtimeArch is the Debian architecture of the running program.
func runtimeArch() string { return ArchFromGoarch(runtime.GOARCH) }

// deps parses a dependency field the way a Packages stanza carries it.
func deps(tb testing.TB, field string) []deb.Alternatives {
	tb.Helper()

	groups, err := deb.ParseRelations(field)
	require.NoError(tb, err)

	return groups
}

// rels parses a Conflicts, Breaks or Provides field.
func rels(tb testing.TB, field string) []deb.Relation {
	tb.Helper()

	var out []deb.Relation

	for _, alts := range deps(tb, field) {
		out = append(out, alts...)
	}

	return out
}

// mustGroups is deps for fixtures built outside a test function.
func mustGroups(field string) []deb.Alternatives {
	groups, err := deb.ParseRelations(field)
	if err != nil {
		panic(err)
	}

	return groups
}

// altsOf turns a flat relation list into one single-alternative group each,
// the form deb.FormatRelations writes.
func altsOf(rs []deb.Relation) []deb.Alternatives {
	out := make([]deb.Alternatives, len(rs))
	for i, r := range rs {
		out[i] = deb.Alternatives{r}
	}

	return out
}
