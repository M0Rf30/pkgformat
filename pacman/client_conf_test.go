package pacman

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/gpg"
)

func levelOf(t *testing.T, s string) SigLevel {
	t.Helper()

	l, err := ParseSigLevel(s)
	if err != nil {
		t.Fatal(err)
	}

	return l
}

// Each repository's SigLevel governs its database and its packages, the Database
// and Package parts separately, over the client's defaults.
func TestRepoSigLevelDatabase(t *testing.T) {
	t.Parallel()

	db := buildDB(t, DBEntry{Name: "a", Version: "1-1"})
	fx := newSigner(t)
	other := newSigner(t)

	cases := []struct {
		name     string
		level    SigLevel
		def      VerifyMode // the client's default
		sig      []byte
		wantErr  error
		verified bool
	}{
		{"required, unsigned", levelOf(t, "DatabaseRequired"), VerifyNone, nil, ErrSignatureRequired, false},
		{"required, valid", levelOf(t, "DatabaseRequired"), VerifyNone, fx.sign(t, db), nil, true},
		{"required, wrong key", levelOf(t, "Required"), VerifyNone, other.sign(t, db), gpg.ErrUnknownSigner, false},
		{"optional, unsigned", levelOf(t, "DatabaseOptional"), VerifyRequired, nil, nil, false},
		{"optional, valid", levelOf(t, "Optional"), VerifyNone, fx.sign(t, db), nil, true},
		{"optional, wrong key", levelOf(t, "Optional"), VerifyNone, other.sign(t, db), gpg.ErrUnknownSigner, false},
		{"never over a required default", levelOf(t, "DatabaseNever"), VerifyRequired, nil, nil, false},
		{"never skips a bad signature", levelOf(t, "Never"), VerifyRequired, other.sign(t, db), nil, false},
		{"package part leaves the database to the default", levelOf(t, "PackageRequired DatabaseNever"), VerifyRequired, nil, nil, false},
		{"database part ignores the package part", levelOf(t, "PackageNever DatabaseRequired"), VerifyNone, nil, ErrSignatureRequired, false},
		{"unset falls back to the default", SigLevel{}, VerifyRequired, nil, ErrSignatureRequired, false},
		{"unset falls back to none", SigLevel{}, VerifyNone, nil, nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			files := map[string][]byte{"/r/r.db": db}
			if tc.sig != nil {
				files["/r/r.db.sig"] = tc.sig
			}

			m := newMirror(t, files)
			c := testClient(t, ClientOptions{Keyring: fx.keyring, DBSignatures: tc.def})

			got, err := c.FetchDB(context.Background(), Repo{Name: "r", Servers: []string{m.URL + "/$repo"}, SigLevel: tc.level})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if (got.Verified != nil) != tc.verified {
				t.Errorf("Verified = %v, want verified %v", got.Verified, tc.verified)
			}
		})
	}
}

func TestRepoSigLevelPackage(t *testing.T) {
	t.Parallel()

	pkg, e := packageFixture(t)
	fx := newSigner(t)
	other := newSigner(t)
	sig := fx.sign(t, pkg)

	cases := []struct {
		name    string
		level   SigLevel
		def     VerifyMode
		fileSig []byte
		wantErr error
	}{
		{"required, unsigned", levelOf(t, "PackageRequired"), VerifyNone, nil, ErrSignatureRequired},
		{"required, valid", levelOf(t, "PackageRequired"), VerifyNone, sig, nil},
		{"required, wrong key", levelOf(t, "Required"), VerifyNone, other.sign(t, pkg), gpg.ErrUnknownSigner},
		{"optional, unsigned", levelOf(t, "PackageOptional"), VerifyRequired, nil, nil},
		{"optional, wrong key", levelOf(t, "PackageOptional"), VerifyNone, other.sign(t, pkg), gpg.ErrUnknownSigner},
		{"never over a required default", levelOf(t, "PackageNever"), VerifyRequired, other.sign(t, pkg), nil},
		{"database part leaves packages alone", levelOf(t, "DatabaseRequired PackageNever"), VerifyRequired, nil, nil},
		{"package part ignores the database part", levelOf(t, "DatabaseNever PackageRequired"), VerifyNone, nil, ErrSignatureRequired},
		{"unset falls back to the default", SigLevel{}, VerifyRequired, nil, ErrSignatureRequired},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			files := map[string][]byte{"/core/" + e.Filename: pkg}
			if tc.fileSig != nil {
				files["/core/"+e.Filename+".sig"] = tc.fileSig
			}

			m := newMirror(t, files)
			dir := t.TempDir()
			c := testClient(t, ClientOptions{Keyring: fx.keyring, PackageSignatures: tc.def})

			_, err := c.DownloadPackage(context.Background(),
				Repo{Name: "core", Servers: []string{m.URL + "/$repo"}, SigLevel: tc.level}, &e, dir)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}

				if _, statErr := os.Stat(filepath.Join(dir, e.Filename)); statErr == nil {
					t.Error("a package that failed verification was kept")
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A SigLevel read from a pacman.conf drives the client end to end.
func TestSigLevelFromConfig(t *testing.T) {
	t.Parallel()

	db := buildDB(t, DBEntry{Name: "a", Version: "1-1"})
	fx := newSigner(t)

	signed := newMirror(t, map[string][]byte{"/signed/signed.db": db, "/signed/signed.db.sig": fx.sign(t, db)})
	unsigned := newMirror(t, map[string][]byte{"/unsigned/unsigned.db": db, "/unsigned/strict.db": db})

	cfg, err := ParseConfig(strings.NewReader(`
[options]
SigLevel = Required DatabaseOptional
[signed]
SigLevel = DatabaseRequired
Server = `+signed.URL+`/$repo
[unsigned]
Server = `+unsigned.URL+`/$repo
[strict]
SigLevel = Required
Server = `+unsigned.URL+`/unsigned
`), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}

	c := testClient(t, ClientOptions{Keyring: fx.keyring})
	ctx := context.Background()

	if got, err := c.FetchDB(ctx, cfg.Repos[0]); err != nil || got.Verified == nil {
		t.Errorf("signed: %+v, %v", got, err)
	}

	if got, err := c.FetchDB(ctx, cfg.Repos[1]); err != nil || got.Verified != nil {
		t.Errorf("unsigned under the optional global level: %+v, %v", got, err)
	}

	if _, err := c.FetchDB(ctx, cfg.Repos[2]); !errors.Is(err, ErrSignatureRequired) {
		t.Errorf("strict: err = %v", err)
	}
}

func TestRepoSigLevelNeedsKeyring(t *testing.T) {
	t.Parallel()

	pkg, e := packageFixture(t)
	m := newMirror(t, map[string][]byte{"/r/r.db": buildDB(t, e), "/r/" + e.Filename: pkg})
	repo := Repo{Name: "r", Servers: []string{m.URL + "/$repo"}, SigLevel: levelOf(t, "Optional")}
	c := testClient(t, ClientOptions{})

	if _, err := c.FetchDB(context.Background(), repo); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("FetchDB: %v", err)
	}

	if _, err := c.DownloadPackage(context.Background(), repo, &e, t.TempDir()); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("DownloadPackage: %v", err)
	}

	repo.SigLevel = levelOf(t, "Never")
	if _, err := c.FetchDB(context.Background(), repo); err != nil {
		t.Errorf("Never: %v", err)
	}
}

func TestSyncHonoursUsage(t *testing.T) {
	t.Parallel()

	db := buildDB(t, DBEntry{Name: "a", Version: "1-1"})
	all := newMirror(t, map[string][]byte{"/all.db": db})
	sync := newMirror(t, map[string][]byte{"/sync.db": db})
	install := newMirror(t, map[string][]byte{"/install.db": db})

	repos := []Repo{
		{Name: "all", Servers: []string{all.URL}},
		{Name: "sync", Servers: []string{sync.URL}, Usage: UsageSync | UsageSearch},
		{Name: "install", Servers: []string{install.URL}, Usage: UsageInstall | UsageUpgrade},
	}

	dir := t.TempDir()
	c := testClient(t, ClientOptions{})

	n, err := c.Sync(context.Background(), repos, dir)
	if err != nil || n != 2 {
		t.Fatalf("Sync = %d, %v", n, err)
	}

	assertFile(t, filepath.Join(dir, "all.db"), db)
	assertFile(t, filepath.Join(dir, "sync.db"), db)

	if _, err := os.Stat(filepath.Join(dir, "install.db")); err == nil || install.hits.Load() != 0 {
		t.Errorf("a repository that does not allow Sync was refreshed (hits %d)", install.hits.Load())
	}

	// Naming the repository is an explicit request, whatever its Usage.
	if _, err := c.SyncDB(context.Background(), repos[2], dir); err != nil {
		t.Fatal(err)
	}

	assertFile(t, filepath.Join(dir, "install.db"), db)

	if got, err := c.FetchDB(context.Background(), repos[2]); err != nil || !bytes.Equal(got.Data, db) {
		t.Errorf("FetchDB: %v", err)
	}

	// Sync does not modify the caller's slice.
	if len(repos) != 3 || repos[2].Name != "install" {
		t.Errorf("repos = %+v", repos)
	}
}

func TestCacheServers(t *testing.T) {
	t.Parallel()

	pkg, e := packageFixture(t)
	db := buildDB(t, e)

	t.Run("tried first", func(t *testing.T) {
		t.Parallel()

		cache := newMirror(t, map[string][]byte{"/core/" + e.Filename: pkg})
		origin := newMirror(t, map[string][]byte{"/core/" + e.Filename: pkg})
		repo := Repo{Name: "core", Servers: []string{origin.URL + "/$repo"}, CacheServers: []string{cache.URL + "/$repo/"}}

		path, err := testClient(t, ClientOptions{}).DownloadPackage(context.Background(), repo, &e, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}

		assertFile(t, path, pkg)

		if cache.hits.Load() == 0 || origin.hits.Load() != 0 {
			t.Errorf("cache hits %d, origin hits %d", cache.hits.Load(), origin.hits.Load())
		}
	})

	t.Run("falls back to the servers", func(t *testing.T) {
		t.Parallel()

		missing := newMirror(t, nil)
		broken := newMirror(t, map[string][]byte{"/core/" + e.Filename: []byte("corrupt")})
		origin := newMirror(t, map[string][]byte{"/core/" + e.Filename: pkg})
		repo := Repo{
			Name: "core", Servers: []string{origin.URL + "/$repo"},
			CacheServers: []string{missing.URL + "/$repo", broken.URL + "/$repo"},
		}

		path, err := testClient(t, ClientOptions{}).DownloadPackage(context.Background(), repo, &e, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}

		assertFile(t, path, pkg)

		if missing.hits.Load() == 0 || broken.hits.Load() == 0 || origin.hits.Load() == 0 {
			t.Errorf("hits: missing %d, broken %d, origin %d", missing.hits.Load(), broken.hits.Load(), origin.hits.Load())
		}
	})

	t.Run("cache only", func(t *testing.T) {
		t.Parallel()

		cache := newMirror(t, map[string][]byte{"/core/" + e.Filename: pkg, "/core/core.db": db})
		repo := Repo{Name: "core", CacheServers: []string{cache.URL + "/$repo"}}
		c := testClient(t, ClientOptions{})

		if _, err := c.DownloadPackage(context.Background(), repo, &e, t.TempDir()); err != nil {
			t.Fatal(err)
		}

		// Cache servers never serve databases.
		hits := cache.hits.Load()

		if _, err := c.FetchDB(context.Background(), repo); !errors.Is(err, ErrNoServers) || cache.hits.Load() != hits {
			t.Errorf("FetchDB err = %v, hits %d -> %d", err, hits, cache.hits.Load())
		}
	})

	t.Run("not used for databases", func(t *testing.T) {
		t.Parallel()

		cache := newMirror(t, map[string][]byte{"/core/core.db": []byte("from the cache")})
		origin := newMirror(t, map[string][]byte{"/core/core.db": db})
		repo := Repo{Name: "core", Servers: []string{origin.URL + "/$repo"}, CacheServers: []string{cache.URL + "/$repo"}}

		got, err := testClient(t, ClientOptions{}).FetchDB(context.Background(), repo)
		if err != nil || !bytes.Equal(got.Data, db) || cache.hits.Load() != 0 {
			t.Errorf("FetchDB: %v, cache hits %d", err, cache.hits.Load())
		}
	})

	t.Run("signatures apply to cache copies", func(t *testing.T) {
		t.Parallel()

		fx := newSigner(t)
		cache := newMirror(t, map[string][]byte{"/core/" + e.Filename: pkg})
		origin := newMirror(t, map[string][]byte{"/core/" + e.Filename: pkg, "/core/" + e.Filename + ".sig": fx.sign(t, pkg)})
		repo := Repo{
			Name: "core", Servers: []string{origin.URL + "/$repo"}, CacheServers: []string{cache.URL + "/$repo"},
			SigLevel: levelOf(t, "PackageRequired"),
		}

		// The cache has the package but not its signature: Required rejects it
		// and the origin, which has both, is used.
		path, err := testClient(t, ClientOptions{Keyring: fx.keyring}).DownloadPackage(context.Background(), repo, &e, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}

		assertFile(t, path, pkg)

		if cache.hits.Load() == 0 || origin.hits.Load() == 0 {
			t.Errorf("hits: cache %d, origin %d", cache.hits.Load(), origin.hits.Load())
		}
	})
}

func TestVerifyPackageFile(t *testing.T) {
	t.Parallel()

	pkg, _ := packageFixture(t)
	fx := newSigner(t)
	other := newSigner(t)
	dir := t.TempDir()

	signed := filepath.Join(dir, "signed.pkg.tar.zst")
	mustWrite(t, signed, string(pkg))
	mustWrite(t, signed+".sig", string(fx.sign(t, pkg)))

	bare := filepath.Join(dir, "bare.pkg.tar.zst")
	mustWrite(t, bare, string(pkg))

	wrong := filepath.Join(dir, "wrong.pkg.tar.zst")
	mustWrite(t, wrong, string(pkg))
	mustWrite(t, wrong+".sig", string(other.sign(t, pkg)))

	huge := filepath.Join(dir, "huge.pkg.tar.zst")
	mustWrite(t, huge, string(pkg))
	mustWrite(t, huge+".sig", strings.Repeat("x", MaxSignatureBytes+1))

	c := testClient(t, ClientOptions{Keyring: fx.keyring})
	required := SigPolicy{Check: SigRequired}
	optional := SigPolicy{Check: SigOptional}

	if v, err := c.VerifyPackageFile(signed, required); err != nil || v == nil || v.Fingerprint != fx.signer.KeyFingerprint() {
		t.Errorf("signed: %+v, %v", v, err)
	}

	if v, err := c.VerifyPackageFile(bare, optional); err != nil || v != nil {
		t.Errorf("optional, unsigned: %+v, %v", v, err)
	}

	if _, err := c.VerifyPackageFile(bare, required); !errors.Is(err, ErrSignatureRequired) {
		t.Errorf("required, unsigned: %v", err)
	}

	if _, err := c.VerifyPackageFile(wrong, optional); !errors.Is(err, gpg.ErrUnknownSigner) {
		t.Errorf("wrong key: %v", err)
	}

	if _, err := c.VerifyPackageFile(huge, optional); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("oversized signature: %v", err)
	}

	if v, err := c.VerifyPackageFile(wrong, SigPolicy{Check: SigNever}); err != nil || v != nil {
		t.Errorf("never: %+v, %v", v, err)
	}

	if _, err := c.VerifyPackageFile(filepath.Join(dir, "missing"), required); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}

	// An unset policy takes the client's default.
	strict := testClient(t, ClientOptions{Keyring: fx.keyring, PackageSignatures: VerifyRequired})
	if _, err := strict.VerifyPackageFile(bare, SigPolicy{}); !errors.Is(err, ErrSignatureRequired) {
		t.Errorf("default policy: %v", err)
	}

	if _, err := testClient(t, ClientOptions{}).VerifyPackageFile(signed, required); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("no keyring: %v", err)
	}

	// The unreadable ".sig" is an error, not an unsigned package.
	if err := os.Mkdir(filepath.Join(dir, "dir.pkg.tar.zst.sig"), 0o755); err != nil {
		t.Fatal(err)
	}

	mustWrite(t, filepath.Join(dir, "dir.pkg.tar.zst"), string(pkg))

	if _, err := c.VerifyPackageFile(filepath.Join(dir, "dir.pkg.tar.zst"), optional); err == nil {
		t.Error("an unreadable signature was treated as absent")
	}
}

func TestDownloadPackageFile(t *testing.T) {
	t.Parallel()

	pkg, e := packageFixture(t)
	fx := newSigner(t)
	other := newSigner(t)

	m := newMirror(t, map[string][]byte{
		"/p/" + e.Filename: pkg, "/p/" + e.Filename + ".sig": fx.sign(t, pkg),
		"/u/" + e.Filename: pkg,
		"/w/" + e.Filename: pkg, "/w/" + e.Filename + ".sig": other.sign(t, pkg),
	})

	c := testClient(t, ClientOptions{Keyring: fx.keyring})
	ctx := context.Background()
	required := SigPolicy{Check: SigRequired}

	dir := t.TempDir()

	path, err := c.DownloadPackageFile(ctx, m.URL+"/p/"+e.Filename, dir, required)
	if err != nil {
		t.Fatal(err)
	}

	assertFile(t, path, pkg)

	if path != filepath.Join(dir, e.Filename) {
		t.Errorf("path = %s", path)
	}

	never := SigPolicy{Check: SigNever}

	for name, tc := range map[string]struct {
		dir     string
		policy  SigPolicy
		want    error // nil: success
		anyFail bool  // any error will do
	}{
		"unsigned, required":  {"/u/", required, ErrSignatureRequired, false},
		"unsigned, optional":  {"/u/", SigPolicy{Check: SigOptional}, nil, false},
		"unsigned, never":     {"/u/", never, nil, false},
		"wrong key, required": {"/w/", required, gpg.ErrUnknownSigner, false},
		"wrong key, never":    {"/w/", never, nil, false},
		"unset policy":        {"/u/", SigPolicy{}, nil, false},
		"not on the server":   {"/nope/", never, nil, true},
	} {
		d := t.TempDir()

		got, err := c.DownloadPackageFile(ctx, m.URL+tc.dir+e.Filename, d, tc.policy)

		switch {
		case tc.anyFail && err == nil, !tc.anyFail && tc.want == nil && err != nil:
			t.Errorf("%s: err = %v", name, err)
		case tc.want != nil && !errors.Is(err, tc.want):
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}

		if err != nil {
			if entries, _ := os.ReadDir(d); len(entries) != 0 {
				t.Errorf("%s: left %d files behind", name, len(entries))
			}
		} else if got != filepath.Join(d, e.Filename) {
			t.Errorf("%s: path %q", name, got)
		}
	}

	if _, err := c.DownloadPackageFile(ctx, m.URL+"/", t.TempDir(), never); err == nil {
		t.Error("a URL without a file name was accepted")
	}

	if _, err := testClient(t, ClientOptions{}).DownloadPackageFile(ctx, m.URL+"/p/"+e.Filename, t.TempDir(), required); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("no keyring: %v", err)
	}

	if _, err := c.DownloadPackageFile(ctx, "http://[::1", t.TempDir(), required); err == nil {
		t.Error("invalid URL accepted")
	}
}
