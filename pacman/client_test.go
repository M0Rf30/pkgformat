package pacman

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/M0Rf30/pkgformat/httpclient"
)

// mirror is a fake package mirror: a path-to-content map served with 404 for
// everything else, counting the requests it gets.
type mirror struct {
	*httptest.Server
	files map[string][]byte
	hits  atomic.Int64
}

func newMirror(t *testing.T, files map[string][]byte) *mirror {
	t.Helper()

	m := &mirror{files: files}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.hits.Add(1)

		body, ok := m.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)

			return
		}

		_, _ = w.Write(body)
	}))

	t.Cleanup(m.Close)

	return m
}

func testClient(t *testing.T, opts ClientOptions) *Client {
	t.Helper()

	if opts.HTTP == nil {
		opts.HTTP = httpclient.New(httpclient.Options{Retry: httpclient.RetryPolicy{Attempts: 1}})
	}

	if opts.Arch == "" {
		opts.Arch = "x86_64"
	}

	c, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}

	return c
}

func buildDB(t *testing.T, entries ...DBEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	if err := WriteDB(&buf, entries, false); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

type signedFixture struct {
	signer  *gpg.LocalSigner
	keyring *gpg.Keyring
}

func newSigner(t *testing.T) signedFixture {
	t.Helper()

	ent, err := gpg.GenerateEntity("Test", "", "test@example.org", gpg.Algorithm("ed25519"))
	if err != nil {
		t.Fatal(err)
	}

	s, err := gpg.NewLocalSignerFromEntity(ent)
	if err != nil {
		t.Fatal(err)
	}

	kr, err := s.Keyring()
	if err != nil {
		t.Fatal(err)
	}

	return signedFixture{signer: s, keyring: kr}
}

func (f signedFixture) sign(t *testing.T, data []byte) []byte {
	t.Helper()

	sig, err := f.signer.DetachedSignBinary(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	return sig
}

func TestNewClientNeedsKeyring(t *testing.T) {
	t.Parallel()

	for _, o := range []ClientOptions{{DBSignatures: VerifyRequired}, {PackageSignatures: VerifyIfPresent}} {
		if _, err := NewClient(o); !errors.Is(err, ErrNoKeyring) {
			t.Errorf("NewClient(%+v) err = %v", o, err)
		}
	}

	c, err := NewClient(ClientOptions{})
	if err != nil || c.opts.Arch == "" || c.opts.MaxDBBytes != DefaultMaxDBBytes {
		t.Errorf("defaults: %+v, %v", c, err)
	}
}

func TestValidRepoName(t *testing.T) {
	t.Parallel()

	for _, ok := range []string{"core", "my-repo_2", "a.b"} {
		if !ValidRepoName(ok) {
			t.Errorf("%q rejected", ok)
		}
	}

	for _, bad := range []string{"", ".", "..", ".hidden", "a/b", `a\b`, "a b", "a\x00", "é", strings.Repeat("a", MaxNameLen+1)} {
		if ValidRepoName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFetchDBFailoverAndSignature(t *testing.T) {
	t.Parallel()

	db := buildDB(t, DBEntry{Name: "a", Version: "1-1", Filename: "a-1-1-any.pkg.tar.zst", Arch: "any", CSize: 1, SHA256: "00"})
	fx := newSigner(t)

	dead := newMirror(t, nil)
	good := newMirror(t, map[string][]byte{"/core/os/x86_64/core.db": db, "/core/os/x86_64/core.db.sig": fx.sign(t, db)})

	c := testClient(t, ClientOptions{Keyring: fx.keyring, DBSignatures: VerifyRequired})

	got, err := c.FetchDB(context.Background(), Repo{Name: "core", Servers: []string{dead.URL + "/$repo/os/$arch/", good.URL + "/$repo/os/$arch"}})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.Data, db) || got.Verified == nil || got.Verified.Fingerprint != fx.signer.KeyFingerprint() {
		t.Errorf("db = %+v", got)
	}

	if dead.hits.Load() == 0 {
		t.Error("first mirror was not tried")
	}

	entries, err := got.Entries()
	if err != nil || len(entries) != 1 || entries[0].Name != "a" {
		t.Errorf("entries = %+v, %v", entries, err)
	}
}

func TestFetchDBSignaturePolicies(t *testing.T) {
	t.Parallel()

	db := buildDB(t, DBEntry{Name: "a", Version: "1-1"})
	fx := newSigner(t)
	other := newSigner(t)

	cases := []struct {
		name    string
		sig     []byte // nil: the server has no .sig
		mode    VerifyMode
		wantErr error
	}{
		{"none/unsigned", nil, VerifyNone, nil},
		{"none/garbage", []byte("junk"), VerifyNone, nil},
		{"optional/unsigned", nil, VerifyIfPresent, nil},
		{"optional/valid", fx.sign(t, db), VerifyIfPresent, nil},
		{"optional/wrong key", other.sign(t, db), VerifyIfPresent, gpg.ErrUnknownSigner},
		{"optional/tampered", fx.sign(t, []byte("other data")), VerifyIfPresent, gpg.ErrBadSignature},
		{"required/unsigned", nil, VerifyRequired, ErrSignatureRequired},
		{"required/valid", fx.sign(t, db), VerifyRequired, nil},
		{"required/wrong key", other.sign(t, db), VerifyRequired, gpg.ErrUnknownSigner},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			files := map[string][]byte{"/r/r.db": db}
			if tc.sig != nil {
				files["/r/r.db.sig"] = tc.sig
			}

			m := newMirror(t, files)
			c := testClient(t, ClientOptions{Keyring: fx.keyring, DBSignatures: tc.mode})

			got, err := c.FetchDB(context.Background(), Repo{Name: "r", Servers: []string{m.URL + "/$repo"}})
			if tc.wantErr == nil {
				if err != nil {
					t.Fatal(err)
				}

				if (got.Verified != nil) != (tc.mode != VerifyNone && tc.sig != nil) {
					t.Errorf("Verified = %v", got.Verified)
				}

				return
			}

			if !errors.Is(err, tc.wantErr) || !errors.Is(err, ErrAllServersFailed) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestFetchDBSigFetchFailureIsNotDowngrade(t *testing.T) {
	t.Parallel()

	db := buildDB(t, DBEntry{Name: "a", Version: "1-1"})
	fx := newSigner(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			http.Error(w, "boom", http.StatusInternalServerError)

			return
		}

		_, _ = w.Write(db)
	}))
	defer srv.Close()

	c := testClient(t, ClientOptions{Keyring: fx.keyring, DBSignatures: VerifyIfPresent})

	if _, err := c.FetchDB(context.Background(), Repo{Name: "r", Servers: []string{srv.URL}}); err == nil {
		t.Fatal("a signature that could not be fetched was treated as absent")
	}

	// Without verification the same server is fine.
	if _, err := testClient(t, ClientOptions{}).FetchDB(context.Background(), Repo{Name: "r", Servers: []string{srv.URL}}); err != nil {
		t.Fatal(err)
	}
}

func TestFetchDBErrors(t *testing.T) {
	t.Parallel()

	c := testClient(t, ClientOptions{})
	ctx := context.Background()

	if _, err := c.FetchDB(ctx, Repo{Name: "../x", Servers: []string{"http://x"}}); !errors.Is(err, ErrInvalidRepoName) {
		t.Errorf("bad name: %v", err)
	}

	if _, err := c.FetchDB(ctx, Repo{Name: "core"}); !errors.Is(err, ErrNoServers) {
		t.Errorf("no servers: %v", err)
	}

	m := newMirror(t, nil)
	if _, err := c.FetchDB(ctx, Repo{Name: "core", Servers: []string{m.URL, m.URL}}); !errors.Is(err, ErrAllServersFailed) {
		t.Errorf("all fail: %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	if _, err := c.FetchDB(cancelled, Repo{Name: "core", Servers: []string{m.URL}}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestFetchDBSizeLimit(t *testing.T) {
	t.Parallel()

	m := newMirror(t, map[string][]byte{"/core.db": bytes.Repeat([]byte("x"), 1000)})
	c := testClient(t, ClientOptions{MaxDBBytes: 100})

	_, err := c.FetchDB(context.Background(), Repo{Name: "core", Servers: []string{m.URL}})
	if !errors.Is(err, httpclient.ErrTooLarge) {
		t.Errorf("err = %v", err)
	}
}

func TestSyncDBWritesAndReplacesSignature(t *testing.T) {
	t.Parallel()

	db := buildDB(t, DBEntry{Name: "a", Version: "1-1"})
	dir := t.TempDir()
	repo := func(m *mirror) Repo { return Repo{Name: "core", Servers: []string{m.URL}} }
	c := testClient(t, ClientOptions{})

	withSig := newMirror(t, map[string][]byte{"/core.db": db, "/core.db.sig": []byte("sig-one")})
	if _, err := c.SyncDB(context.Background(), repo(withSig), dir); err != nil {
		t.Fatal(err)
	}

	assertFile(t, filepath.Join(dir, "core.db"), db)
	assertFile(t, filepath.Join(dir, "core.db.sig"), []byte("sig-one"))

	// The signature is replaced when it changes...
	withSig.files["/core.db.sig"] = []byte("sig-two")

	if _, err := c.SyncDB(context.Background(), repo(withSig), dir); err != nil {
		t.Fatal(err)
	}

	assertFile(t, filepath.Join(dir, "core.db.sig"), []byte("sig-two"))

	// ...and removed when the server stops providing one.
	withoutSig := newMirror(t, map[string][]byte{"/core.db": db})
	if _, err := c.SyncDB(context.Background(), repo(withoutSig), dir); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, "core.db.sig")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale signature kept: %v", err)
	}

	// No leftovers from the atomic writes.
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("directory holds %d files", len(ents))
	}
}

func TestSyncDBFailureLeavesOldDatabase(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "core.db"), "old")

	m := newMirror(t, nil)
	if _, err := testClient(t, ClientOptions{}).SyncDB(context.Background(), Repo{Name: "core", Servers: []string{m.URL}}, dir); err == nil {
		t.Fatal("expected an error")
	}

	assertFile(t, filepath.Join(dir, "core.db"), []byte("old"))
}

func TestSyncPartialFailure(t *testing.T) {
	t.Parallel()

	db := buildDB(t, DBEntry{Name: "a", Version: "1-1"})
	good := newMirror(t, map[string][]byte{"/core.db": db, "/extra.db": db, "/multilib.db": db})
	bad := newMirror(t, nil)
	dir := t.TempDir()

	repos := []Repo{
		{Name: "core", Servers: []string{good.URL}},
		{Name: "broken", Servers: []string{bad.URL}},
		{Name: "extra", Servers: []string{good.URL}},
		{Name: "multilib", Servers: []string{good.URL}},
		{Name: "noservers"},
	}

	n, err := testClient(t, ClientOptions{}).Sync(context.Background(), repos, dir)
	if n != 3 || !errors.Is(err, ErrAllServersFailed) || !errors.Is(err, ErrNoServers) {
		t.Fatalf("n = %d, err = %v", n, err)
	}

	for _, r := range []string{"core", "extra", "multilib"} {
		assertFile(t, filepath.Join(dir, r+".db"), db)
	}

	if n, err := testClient(t, ClientOptions{}).Sync(context.Background(), nil, dir); n != 0 || err != nil {
		t.Errorf("empty sync = %d, %v", n, err)
	}
}

func assertFile(t *testing.T, path string, want []byte) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("%s = %q, %v; want %q", path, got, err, want)
	}
}

// packageFixture is a real package with its database entry.
func packageFixture(t *testing.T) ([]byte, DBEntry) {
	t.Helper()

	s := sampleSpec()
	pkg := writeSpec(t, s, WriteOptions{ClampMTime: true})

	e, err := NewDBEntry(s.FileName(CompressionZstd), bytes.NewReader(pkg), nil)
	if err != nil {
		t.Fatal(err)
	}

	return pkg, *e
}

func TestNewDBEntry(t *testing.T) {
	t.Parallel()

	pkg, e := packageFixture(t)
	fx := newSigner(t)

	if e.Name != "hello" || e.Version != "1:2.12-3" || e.CSize != int64(len(pkg)) || len(e.SHA256) != 64 || len(e.MD5) != 32 ||
		e.Arch != "x86_64" || len(e.Depends) != 2 || len(e.Files) == 0 || e.PGPSig != "" || e.BuildDate != buildTime {
		t.Errorf("entry = %+v", e)
	}

	sig := fx.sign(t, pkg)

	signed, err := NewDBEntry(e.Filename, bytes.NewReader(pkg), sig)
	if err != nil || signed.PGPSig != base64.StdEncoding.EncodeToString(sig) {
		t.Errorf("signed entry: %+v, %v", signed, err)
	}

	for _, name := range []string{"../x.pkg.tar.zst", "a/b.pkg.tar.zst", ""} {
		if _, err := NewDBEntry(name, bytes.NewReader(pkg), nil); !errors.Is(err, ErrInvalidField) {
			t.Errorf("file name %q: %v", name, err)
		}
	}

	if _, err := NewDBEntry(e.Filename, bytes.NewReader([]byte("not a package")), nil); err == nil {
		t.Error("garbage accepted")
	}

	if _, err := NewDBEntry(e.Filename, bytes.NewReader(pkg), []byte("junk")); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("bad signature: %v", err)
	}
}

func TestDownloadPackage(t *testing.T) {
	t.Parallel()

	pkg, e := packageFixture(t)
	dir := t.TempDir()

	dead := newMirror(t, nil)
	good := newMirror(t, map[string][]byte{"/core/" + e.Filename: pkg})
	repo := Repo{Name: "core", Servers: []string{dead.URL + "/$repo", good.URL + "/$repo"}}

	var seen atomic.Int64

	c := testClient(t, ClientOptions{Progress: func(name string, done, total int64) {
		if name != e.Filename {
			t.Errorf("progress name %q", name)
		}

		seen.Store(done)
	}})

	path, err := c.DownloadPackage(context.Background(), repo, &e, dir)
	if err != nil {
		t.Fatal(err)
	}

	assertFile(t, path, pkg)

	if path != filepath.Join(dir, e.Filename) || seen.Load() != int64(len(pkg)) {
		t.Errorf("path = %s, progress = %d", path, seen.Load())
	}

	// The package reads back, so what was served is what was built.
	if f, err := os.Open(path); err != nil {
		t.Error(err)
	} else {
		defer func() { _ = f.Close() }()

		if p, err := ReadPackage(f); err != nil || p.Info.Name != "hello" {
			t.Errorf("ReadPackage: %v", err)
		}
	}

	// A valid copy in the directory is reused: no request is made.
	before := good.hits.Load()

	if _, err := c.DownloadPackage(context.Background(), repo, &e, dir); err != nil || good.hits.Load() != before {
		t.Errorf("cache hit: err = %v, hits %d -> %d", err, before, good.hits.Load())
	}

	// A corrupt copy is replaced.
	mustWrite(t, path, "corrupt")

	if _, err := c.DownloadPackage(context.Background(), repo, &e, dir); err != nil {
		t.Fatal(err)
	}

	assertFile(t, path, pkg)
}

func TestDownloadPackageRejects(t *testing.T) {
	t.Parallel()

	pkg, e := packageFixture(t)
	ctx := context.Background()
	tampered := append(bytes.Clone(pkg), 'x')

	flipped := bytes.Clone(pkg)
	flipped[len(flipped)/2] ^= 0xff

	for name, tc := range map[string]struct {
		served []byte
		mutate func(*DBEntry)
		want   error
	}{
		"digest":      {flipped, nil, ErrChecksumMismatch},
		"size":        {pkg, func(e *DBEntry) { e.CSize++ }, ErrChecksumMismatch},
		"too large":   {tampered, func(e *DBEntry) { e.CSize = int64(len(pkg)) }, httpclient.ErrTooLarge},
		"no checksum": {pkg, func(e *DBEntry) { e.SHA256, e.MD5 = "", "" }, ErrNoChecksum},
		"bad sum":     {pkg, func(e *DBEntry) { e.SHA256 = "zz" }, ErrInvalidField},
		"bad file":    {pkg, func(e *DBEntry) { e.Filename = "../escape" }, ErrInvalidField},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			entry := e
			if tc.mutate != nil {
				tc.mutate(&entry)
			}

			m := newMirror(t, map[string][]byte{"/" + e.Filename: tc.served})
			dir := t.TempDir()

			_, err := testClient(t, ClientOptions{}).DownloadPackage(ctx, Repo{Name: "core", Servers: []string{m.URL}}, &entry, dir)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}

			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Errorf("rejected download left %d files", len(ents))
			}
		})
	}

	// MD5 alone is accepted when the database has no SHA-256.
	md5only := e
	md5only.SHA256 = ""
	m := newMirror(t, map[string][]byte{"/" + e.Filename: pkg})

	if _, err := testClient(t, ClientOptions{}).DownloadPackage(ctx, Repo{Name: "core", Servers: []string{m.URL}}, &md5only, t.TempDir()); err != nil {
		t.Errorf("md5-only entry: %v", err)
	}

	c := testClient(t, ClientOptions{})
	if _, err := c.DownloadPackage(ctx, Repo{Name: "../core", Servers: []string{m.URL}}, &e, t.TempDir()); !errors.Is(err, ErrInvalidRepoName) {
		t.Errorf("repo name: %v", err)
	}

	if _, err := c.DownloadPackage(ctx, Repo{Name: "core"}, &e, t.TempDir()); !errors.Is(err, ErrNoServers) {
		t.Errorf("no servers: %v", err)
	}
}

func TestDownloadPackageSignatures(t *testing.T) {
	t.Parallel()

	pkg, e := packageFixture(t)
	fx := newSigner(t)
	other := newSigner(t)
	sig := fx.sign(t, pkg)
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

	cases := []struct {
		name     string
		mode     VerifyMode
		dbSig    string // PGPSIG of the entry
		fileSig  []byte // served as <file>.sig
		wantErr  error
		wantFile bool
	}{
		{"none ignores everything", VerifyNone, b64(other.sign(t, pkg)), nil, nil, true},
		{"required, entry sig", VerifyRequired, b64(sig), nil, nil, true},
		{"required, file sig", VerifyRequired, "", sig, nil, true},
		{"required, none", VerifyRequired, "", nil, ErrSignatureRequired, false},
		{"required, wrong key", VerifyRequired, b64(other.sign(t, pkg)), nil, gpg.ErrUnknownSigner, false},
		{"required, tampered file sig", VerifyRequired, "", fx.sign(t, []byte("else")), gpg.ErrBadSignature, false},
		{"required, bad base64", VerifyRequired, "!!!", nil, ErrInvalidField, false},
		{"optional, none", VerifyIfPresent, "", nil, nil, true},
		{"optional, valid", VerifyIfPresent, b64(sig), nil, nil, true},
		{"optional, wrong key", VerifyIfPresent, "", other.sign(t, pkg), gpg.ErrUnknownSigner, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			files := map[string][]byte{"/" + e.Filename: pkg}
			if tc.fileSig != nil {
				files["/"+e.Filename+".sig"] = tc.fileSig
			}

			m := newMirror(t, files)
			entry := e
			entry.PGPSig = tc.dbSig
			dir := t.TempDir()

			c := testClient(t, ClientOptions{Keyring: fx.keyring, PackageSignatures: tc.mode})

			path, err := c.DownloadPackage(context.Background(), Repo{Name: "core", Servers: []string{m.URL}}, &entry, dir)
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}

			if tc.wantErr == nil && err != nil {
				t.Fatal(err)
			}

			_, statErr := os.Stat(filepath.Join(dir, e.Filename))
			if (statErr == nil) != tc.wantFile {
				t.Errorf("file present = %v, want %v (path %q)", statErr == nil, tc.wantFile, path)
			}
		})
	}
}

func TestDownloadPackageCachedCopyIsReverified(t *testing.T) {
	t.Parallel()

	pkg, e := packageFixture(t)
	fx := newSigner(t)
	other := newSigner(t)
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, e.Filename), string(pkg))

	m := newMirror(t, map[string][]byte{"/" + e.Filename: pkg})
	entry := e
	entry.PGPSig = base64.StdEncoding.EncodeToString(other.sign(t, pkg))

	c := testClient(t, ClientOptions{Keyring: fx.keyring, PackageSignatures: VerifyRequired})

	if _, err := c.DownloadPackage(context.Background(), Repo{Name: "core", Servers: []string{m.URL}}, &entry, dir); !errors.Is(err, gpg.ErrUnknownSigner) {
		t.Errorf("err = %v", err)
	}
}
