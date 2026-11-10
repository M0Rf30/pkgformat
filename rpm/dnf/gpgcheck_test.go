package dnf

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/M0Rf30/pkgformat/rpm"
)

const (
	signedPkgName = "simple"
	signedPkgFile = "simple-1.0.1-1.i386.rpm"
	keyPath       = "/RPM-GPG-KEY-test"
)

func newSigningEntity(t *testing.T) *openpgp.Entity {
	t.Helper()

	entity, err := openpgp.NewEntity("dnf test", "", "dnf@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA,
		Curve:     packet.Curve25519,
	})
	if err != nil {
		t.Fatal(err)
	}

	return entity
}

func armoredPublicKey(t *testing.T, entity *openpgp.Entity) []byte {
	t.Helper()

	var buf bytes.Buffer

	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := entity.Serialize(w); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

// simpleRPM returns a real package, unsigned or signed by key.
func simpleRPM(t *testing.T, key *packet.PrivateKey) []byte {
	t.Helper()

	pkg, err := os.ReadFile(filepath.Join("..", "testdata", signedPkgFile))
	if err != nil {
		t.Fatal(err)
	}

	if key == nil {
		return pkg
	}

	hdr, err := rpm.SignRpmStream(bytes.NewReader(pkg), key, &rpm.SignatureOptions{})
	if err != nil {
		t.Fatal(err)
	}

	head, err := hdr.DumpSignatureHeader(false)
	if err != nil {
		t.Fatal(err)
	}

	return append(head, pkg[hdr.OriginalSignatureHeaderSize():]...)
}

func simplePkg(body []byte) repoPkg {
	return repoPkg{
		pkg:  rpm.Package{Name: signedPkgName, Version: "1.0.1", Release: "1", Arch: "i386"},
		body: body,
	}
}

// gpgRepo serves one package and the public key of entity.
func gpgRepo(t *testing.T, body []byte, entity *openpgp.Entity) *testRepo {
	t.Helper()

	repo := newTestRepo(t, simplePkg(body))

	repo.mu.Lock()
	repo.files[keyPath] = armoredPublicKey(t, entity)
	repo.mu.Unlock()

	return repo
}

func gpgSection(repo *testRepo, gpgcheck string, keys ...string) string {
	s := baseurlSection(repo.url()) + "gpgcheck=" + gpgcheck + "\n"
	for i, k := range keys {
		if i == 0 {
			s += "gpgkey=" + k + "\n"
		} else {
			s += "    " + k + "\n"
		}
	}

	return s
}

// downloadSimple updates, loads and downloads the package of the repository.
func downloadSimple(t *testing.T, env *testEnv) (*Package, string, error) {
	t.Helper()

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	p, ok := ix.Lookup(signedPkgName)
	if !ok {
		t.Fatal("the package is not in the index")
	}

	path, err := env.Download(context.Background(), p, env.destDir)

	return p, path, err
}

func notThere(t *testing.T, env *testEnv) {
	t.Helper()

	if _, err := os.Stat(filepath.Join(env.destDir, signedPkgFile)); err == nil {
		t.Error("a package that failed its signature check was left in the destination")
	}
}

func TestGPGCheckAcceptsASignedPackage(t *testing.T) {
	entity := newSigningEntity(t)
	repo := gpgRepo(t, simpleRPM(t, entity.PrivateKey), entity)

	for name, key := range map[string]string{
		"http key": repo.url() + keyPath,
		"file key": "file://" + writeKeyFile(t, entity),
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t, gpgSection(repo, "1", key))

			_, path, err := downloadSimple(t, env)
			if err != nil {
				t.Fatal(err)
			}

			if filepath.Base(path) != signedPkgFile {
				t.Errorf("path = %s", path)
			}
		})
	}
}

func writeKeyFile(t *testing.T, entity *openpgp.Entity) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), "key.asc")
	if err := os.WriteFile(p, armoredPublicKey(t, entity), 0o600); err != nil {
		t.Fatal(err)
	}

	return p
}

func TestGPGCheckRefusesWhatIsNotProperlySigned(t *testing.T) {
	entity := newSigningEntity(t)
	stranger := newSigningEntity(t)

	revoked := newSigningEntity(t)
	revokedPkg := simpleRPM(t, revoked.PrivateKey)

	if err := revoked.RevokeKey(packet.KeyCompromised, "leaked", nil); err != nil {
		t.Fatal(err)
	}

	expired, err := openpgp.NewEntity("expired", "", "e@example.com", &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Curve:           packet.Curve25519,
		Time:            func() time.Time { return time.Now().Add(-48 * time.Hour) },
		KeyLifetimeSecs: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		body []byte
		key  *openpgp.Entity
		want error
	}{
		"unsigned":              {simpleRPM(t, nil), entity, rpm.ErrUnsigned},
		"signed by a stranger":  {simpleRPM(t, stranger.PrivateKey), entity, nil},
		"signed, key revoked":   {revokedPkg, revoked, gpg.ErrKeyRevoked},
		"signed, key expired":   {simpleRPM(t, expired.PrivateKey), expired, gpg.ErrKeyExpired},
		"corrupted by one byte": {corrupt(simpleRPM(t, entity.PrivateKey)), entity, nil},
	} {
		t.Run(name, func(t *testing.T) {
			repo := gpgRepo(t, tc.body, tc.key)
			env := newEnv(t, gpgSection(repo, "1", repo.url()+keyPath))

			_, _, err := downloadSimple(t, env)
			if err == nil {
				t.Fatal("the package was accepted")
			}

			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}

			notThere(t, env)
		})
	}
}

func corrupt(pkg []byte) []byte {
	out := bytes.Clone(pkg)
	out[len(out)-1] ^= 0xff

	return out
}

func TestGPGCheckOffAcceptsAnything(t *testing.T) {
	entity := newSigningEntity(t)
	repo := gpgRepo(t, simpleRPM(t, nil), entity)

	for name, section := range map[string]string{
		"gpgcheck=0":          gpgSection(repo, "0", repo.url()+keyPath),
		"gpgcheck=0 no key":   gpgSection(repo, "0"),
		"no gpgcheck at all":  baseurlSection(repo.url()),
		"gpgcheck=False":      gpgSection(repo, "False", repo.url()+keyPath),
		"key that is missing": gpgSection(repo, "0", repo.url()+"/nothing"),
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t, section)
			if _, _, err := downloadSimple(t, env); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGPGCheckWithoutAKeyFails(t *testing.T) {
	entity := newSigningEntity(t)
	repo := gpgRepo(t, simpleRPM(t, entity.PrivateKey), entity)
	env := newEnv(t, gpgSection(repo, "1"))

	_, _, err := downloadSimple(t, env)
	if !errors.Is(err, ErrNoGPGKey) {
		t.Fatalf("err = %v", err)
	}

	notThere(t, env)
}

func TestGPGCheckKeyErrors(t *testing.T) {
	entity := newSigningEntity(t)
	repo := gpgRepo(t, simpleRPM(t, entity.PrivateKey), entity)

	for name, tc := range map[string]struct {
		key  string
		want error
	}{
		"unsupported scheme": {"ftp://keys.example/key", ErrUnsupportedKeyURL},
		"remote file host":   {"file://elsewhere/etc/key", ErrUnsupportedKeyURL},
		"no such http key":   {repo.url() + "/nothing", nil},
		"no such file":       {"file:///nonexistent/key", os.ErrNotExist},
		"not a key":          {repo.url() + "/repodata/repomd.xml", nil},
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t, gpgSection(repo, "1", tc.key))

			_, _, err := downloadSimple(t, env)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}

			notThere(t, env)
		})
	}
}

func TestGPGCheckSeveralKeysAndCaching(t *testing.T) {
	entity := newSigningEntity(t)
	other := newSigningEntity(t)
	repo := gpgRepo(t, simpleRPM(t, entity.PrivateKey), entity)
	otherFile := writeKeyFile(t, other)

	// the signer is the second of two keys
	env := newEnv(t, gpgSection(repo, "1", "file://"+otherFile, repo.url()+keyPath))

	p, _, err := downloadSimple(t, env)
	if err != nil {
		t.Fatal(err)
	}

	// a second download, of a file that is there already, checks it again
	// with the keys it has fetched
	if _, err := env.Download(context.Background(), p, env.destDir); err != nil {
		t.Fatal(err)
	}

	if n := repo.count(keyPath); n != 1 {
		t.Errorf("the key was fetched %d times", n)
	}
}

func TestGPGCheckAFileAlreadyThereIsChecked(t *testing.T) {
	entity := newSigningEntity(t)
	repo := gpgRepo(t, simpleRPM(t, nil), entity)

	// the unsigned package is downloaded without a check ...
	env := newEnv(t, baseurlSection(repo.url()))

	p, path, err := downloadSimple(t, env)
	if err != nil {
		t.Fatal(err)
	}

	// ... and is refused once the repository asks for signatures
	strict := *p
	r := *p.repo
	r.GPGCheck = true
	r.GPGKeys = []string{repo.url() + keyPath}
	strict.repo = &r

	if _, err := env.Download(context.Background(), &strict, env.destDir); !errors.Is(err, rpm.ErrUnsigned) {
		t.Fatalf("err = %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Error("a file that was there before was removed")
	}
}

func TestGPGKeyVariablesAreExpanded(t *testing.T) {
	entity := newSigningEntity(t)
	repo := gpgRepo(t, simpleRPM(t, entity.PrivateKey), entity)
	env := newEnv(t, gpgSection(repo, "1", repo.url()+"/keys/$releasever"+keyPath))

	repo.mu.Lock()
	repo.files["/keys/9"+keyPath] = repo.files[keyPath]
	repo.mu.Unlock()

	if _, _, err := downloadSimple(t, env); err != nil {
		t.Fatal(err)
	}
}
