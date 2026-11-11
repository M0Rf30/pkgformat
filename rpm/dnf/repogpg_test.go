package dnf

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/M0Rf30/pkgformat/gpg"
)

// signRepomd publishes repomd.xml.asc, a signature of the repomd.xml the repo
// serves, made by entity.
func signRepomd(t *testing.T, repo *testRepo, entity *openpgp.Entity) {
	t.Helper()

	repo.mu.Lock()
	repomd := repo.files["/repodata/repomd.xml"]
	repo.mu.Unlock()

	var sig bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sig, entity, bytes.NewReader(repomd), nil); err != nil {
		t.Fatal(err)
	}

	repo.mu.Lock()
	repo.files["/repodata/repomd.xml.asc"] = sig.Bytes()
	repo.mu.Unlock()
}

func repoGPGSection(repo *testRepo, extra string) string {
	return baseurlSection(repo.url()) + "repo_gpgcheck=1\n" + extra
}

func TestRepoGPGCheckAcceptsASignedRepository(t *testing.T) {
	entity := newSigningEntity(t)
	repo := newTestRepo(t, pkgOf("a", "1"))
	signRepomd(t, repo, entity)

	repo.mu.Lock()
	repo.files[keyPath] = armoredPublicKey(t, entity)
	repo.mu.Unlock()

	env := newEnv(t, repoGPGSection(repo, "gpgkey="+repo.url()+keyPath+"\n"))
	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil || ix.Len() != 1 {
		t.Errorf("Load = %v, %v", ix, err)
	}
}

func TestRepoGPGCheckRefusals(t *testing.T) {
	good, other := newSigningEntity(t), newSigningEntity(t)

	for name, tc := range map[string]struct {
		prepare func(repo *testRepo)
		keys    func(repo *testRepo) string
	}{
		"signed by another key": {
			func(r *testRepo) { signRepomd(t, r, other) },
			func(r *testRepo) string { return "gpgkey=" + r.url() + keyPath + "\n" },
		},
		"no signature published": {
			func(*testRepo) {},
			func(r *testRepo) string { return "gpgkey=" + r.url() + keyPath + "\n" },
		},
		"no gpgkey": {
			func(r *testRepo) { signRepomd(t, r, good) },
			func(*testRepo) string { return "" },
		},
		"empty signature": {
			func(r *testRepo) {
				signRepomd(t, r, good)
				r.mu.Lock()
				r.files["/repodata/repomd.xml.asc"] = nil
				r.mu.Unlock()
			},
			func(r *testRepo) string { return "gpgkey=" + r.url() + keyPath + "\n" },
		},
		"unreadable key": {
			func(r *testRepo) { signRepomd(t, r, good) },
			func(*testRepo) string { return "gpgkey=file:///does/not/exist\n" },
		},
	} {
		t.Run(name, func(t *testing.T) {
			repo := newTestRepo(t, pkgOf("a", "1"))
			repo.mu.Lock()
			repo.files[keyPath] = armoredPublicKey(t, good)
			repo.mu.Unlock()
			tc.prepare(repo)

			env := newEnv(t, repoGPGSection(repo, tc.keys(repo)))

			err := env.Update(context.Background())
			if !errors.Is(err, ErrRepoSignature) {
				t.Fatalf("err = %v", err)
			}

			// nothing of a refused repository is left in the cache
			repos, _ := env.Repos()
			if !env.Expired(&repos[0]) {
				t.Error("the metadata of a refused repository was committed")
			}
		})
	}
}

func TestRepoGPGCheckOffIgnoresTheSignature(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env := newEnv(t, baseurlSection(repo.url()))

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	if repo.count("/repodata/repomd.xml.asc") != 0 {
		t.Error("the signature was fetched although repo_gpgcheck is off")
	}
}

func TestRepoGPGCheckFailureIsSkippedWithSkipIfUnavailable(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env := newEnv(t, repoGPGSection(repo, "skip_if_unavailable=1\n"))

	if err := env.Update(context.Background()); err != nil {
		t.Errorf("Update = %v", err)
	}
}

func TestVerifyLocal(t *testing.T) {
	entity, other := newSigningEntity(t), newSigningEntity(t)
	signed := filepath.Join(t.TempDir(), "signed.rpm")
	unsigned := filepath.Join(t.TempDir(), "unsigned.rpm")

	if err := os.WriteFile(signed, simpleRPM(t, entity.PrivateKey), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(unsigned, simpleRPM(t, nil), 0o600); err != nil {
		t.Fatal(err)
	}

	keyring := func(e *openpgp.Entity) *gpg.Keyring {
		kr, err := gpg.ParseKeyring(armoredPublicKey(t, e))
		if err != nil {
			t.Fatal(err)
		}

		return kr
	}

	on := &Config{LocalPkgGPGCheck: true, Defaults: defaultRepo()}
	ctx := context.Background()

	// off: nothing is checked
	if err := New(Options{Config: DefaultConfig()}).VerifyLocal(ctx, unsigned); err != nil {
		t.Errorf("localpkg_gpgcheck=0: %v", err)
	}

	// on: signed by a local key
	if err := New(Options{Config: on, LocalKeys: keyring(entity)}).VerifyLocal(ctx, signed); err != nil {
		t.Errorf("signed: %v", err)
	}

	// on, the key is the gpgkey of an enabled repository
	repo := newTestRepo(t)
	repo.mu.Lock()
	repo.files[keyPath] = armoredPublicKey(t, entity)
	repo.mu.Unlock()

	env := newEnv(t, baseurlSection(repo.url())+"gpgkey="+repo.url()+keyPath+"\n", func(o *Options) { o.Config = on })
	if err := env.VerifyLocal(ctx, signed); err != nil {
		t.Errorf("repository key: %v", err)
	}

	if err := env.VerifyLocal(ctx, unsigned); err == nil {
		t.Error("an unsigned package passed")
	}

	// on: a key that did not sign it, no key at all, no such file
	if err := New(Options{Config: on, LocalKeys: keyring(other)}).VerifyLocal(ctx, signed); err == nil {
		t.Error("a package signed by another key passed")
	}

	if err := New(Options{Config: on}).VerifyLocal(ctx, signed); !errors.Is(err, ErrNoGPGKey) {
		t.Errorf("without keys: %v", err)
	}

	if err := New(Options{Config: on, LocalKeys: keyring(entity)}).VerifyLocal(ctx, signed+".missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}

	// a repository whose key cannot be loaded
	bad := newEnv(t, baseurlSection(repo.url())+"gpgkey=file:///does/not/exist\n", func(o *Options) { o.Config = on })
	if err := bad.VerifyLocal(ctx, signed); err == nil {
		t.Error("an unreadable repository key was ignored")
	}

	// a configuration that cannot be read
	if err := New(Options{ConfigFile: "/does/not/exist"}).VerifyLocal(ctx, signed); err == nil {
		t.Error("a missing dnf.conf was ignored")
	}
}
