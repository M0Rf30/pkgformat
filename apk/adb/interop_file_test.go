package adb

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// testKey is a key pair for the tests: the signer, the private key in a file
// apk can read and a directory holding the public key, as apk --keys-dir
// wants.
type testKey struct {
	name    string
	signer  *Signer
	priv    string
	keysDir string
}

var testKeys = sync.OnceValues(func() ([]testKey, error) {
	dir, err := os.MkdirTemp("", "adbkeys")
	if err != nil {
		return nil, err
	}

	rsaKey, err := GenerateKey(2048)
	if err != nil {
		return nil, err
	}

	ecKey, err := GenerateECKey(elliptic.P256())
	if err != nil {
		return nil, err
	}

	var keys []testKey

	for _, k := range []struct {
		name string
		key  crypto.Signer
	}{{"rsa", rsaKey}, {"ec", ecKey}} {
		s, err := NewSigner(k.key)
		if err != nil {
			return nil, err
		}

		privPEM, err := MarshalPrivateKeyPEM(k.key)
		if err != nil {
			return nil, err
		}

		pubPEM, err := MarshalPublicKeyPEM(k.key.Public())
		if err != nil {
			return nil, err
		}

		kd := filepath.Join(dir, k.name+"-keys")
		if err := os.Mkdir(kd, 0o755); err != nil {
			return nil, err
		}

		priv := filepath.Join(dir, k.name+".priv")
		if err := os.WriteFile(priv, privPEM, 0o600); err != nil {
			return nil, err
		}

		if err := os.WriteFile(filepath.Join(kd, "test-"+k.name+".pub"), pubPEM, 0o644); err != nil {
			return nil, err
		}

		keys = append(keys, testKey{k.name, s, priv, kd})
	}

	return keys, nil
})

func keysOf(t testing.TB) []testKey {
	t.Helper()

	k, err := testKeys()
	if err != nil {
		t.Fatal(err)
	}

	return k
}

func keyringOf(t testing.TB, k testKey) *Keyring {
	t.Helper()

	kr, err := LoadKeyring(k.keysDir)
	if err != nil {
		t.Fatal(err)
	}

	return kr
}

func save(t testing.TB, name string, data []byte) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}

	return p
}

// sampleTree is a tree with every kind of entry apk mkpkg takes.
func sampleTree(tr *tree) {
	tr.File("usr/bin/hello", fs.ModeSetuid|0o755, []byte("#!/bin/sh\necho hello\n"))
	tr.Symlink("usr/bin/hi", "hello")
	tr.File("etc/app.conf", 0o644, []byte("conf\n"))
	tr.Hardlink("etc/app.conf.hard", "etc/app.conf")
	tr.File("etc/empty", 0o600, nil)
	tr.File("usr/share/big", 0o644, bytes.Repeat([]byte("0123456789abcdef"), 20000))
	tr.Dir("var/empty", 0o700)
}

var compressions = []struct {
	name string
	c    Compression
	arg  string
}{
	{"default", Compression{}, ""},
	{"none", NoCompression, "none"},
	{"deflate9", Compression{Alg: CompDeflate, Level: 9}, "deflate:9"},
	{"deflate1", Compression{Alg: CompDeflate, Level: 1}, "deflate:1"},
	{"zstd", Compression{Alg: CompZstd, Level: 3}, "zstd:3"},
	{"zstd19", Compression{Alg: CompZstd, Level: 19}, "zstd:19"},
}

// TestApkVerifiesOurPackages has apk check what the writer signs.
func TestApkVerifiesOurPackages(t *testing.T) {
	needApk(t)

	tr := newTree(t)
	sampleTree(tr)

	for _, k := range keysOf(t) {
		for _, c := range compressions {
			t.Run(k.name+"/"+c.name, func(t *testing.T) {
				var out bytes.Buffer

				spec := &Spec{Info: minimalInfo(), Files: tr.files}
				if _, err := WritePackage(&out, spec, WriteOptions{Signers: []*Signer{k.signer}, Compression: c.c}); err != nil {
					t.Fatal(err)
				}

				p := save(t, "p.apk", out.Bytes())
				runApk(t, "--keys-dir", k.keysDir, "verify", p)

				if got := string(runApk(t, "--keys-dir", k.keysDir, "adbdump", p)); !strings.Contains(got, "OK") {
					t.Errorf("adbdump does not show a trusted signature:\n%s", got)
				}

				other := keysOf(t)[1-slices.IndexFunc(keysOf(t), func(x testKey) bool { return x.name == k.name })]
				if _, err := apkCombined("--keys-dir", other.keysDir, "verify", p); err == nil {
					t.Error("apk verify accepted a package signed by a key it does not trust")
				}

				pkg, id, err := VerifyPackage(bytes.NewReader(out.Bytes()), keyringOf(t, k), ReadOptions{})
				if err != nil {
					t.Fatal(err)
				}

				if id != k.signer.KeyID() || pkg.Info.Name != "minimal" {
					t.Errorf("VerifyPackage = %v, %q", id, pkg.Info.Name)
				}
			})
		}
	}
}

// TestWriterMultipleSignatures signs with both keys; apk trusts either.
func TestWriterMultipleSignatures(t *testing.T) {
	needApk(t)

	keys := keysOf(t)
	spec := &Spec{Info: minimalInfo(), Files: []File{MemFile("a", 0o644, []byte("a"))}}

	var out bytes.Buffer
	if _, err := WritePackage(&out, spec, WriteOptions{Signers: []*Signer{keys[0].signer, keys[1].signer}}); err != nil {
		t.Fatal(err)
	}

	p := save(t, "p.apk", out.Bytes())
	for _, k := range keys {
		runApk(t, "--keys-dir", k.keysDir, "verify", p)

		if _, id, err := VerifyPackage(bytes.NewReader(out.Bytes()), keyringOf(t, k), ReadOptions{}); err != nil || id != k.signer.KeyID() {
			t.Errorf("%s: %v %v", k.name, id, err)
		}
	}

	rd, err := NewReader(bytes.NewReader(out.Bytes()), ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = rd.Close() }()

	if n := len(rd.Signatures()); n != 2 {
		t.Errorf("%d signatures, want 2", n)
	}
}

// TestVerifyPackagesFromMkpkg checks what apk mkpkg signs.
func TestVerifyPackagesFromMkpkg(t *testing.T) {
	needApk(t)

	tr := newTree(t)
	sampleTree(tr)

	for _, k := range keysOf(t) {
		for _, c := range compressions {
			t.Run(k.name+"/"+c.name, func(t *testing.T) {
				extra := []string{"--sign-key", k.priv}
				if c.arg != "" {
					extra = append(extra, "--compression", c.arg)
				}

				ref := tr.mkpkg(&Spec{Info: minimalInfo()}, extra...)

				pkg, id, err := VerifyPackage(bytes.NewReader(ref), keyringOf(t, k), ReadOptions{})
				if err != nil {
					t.Fatal(err)
				}

				if id != k.signer.KeyID() {
					t.Errorf("key id %x, want %x", id, k.signer.KeyID())
				}

				if len(pkg.Paths) == 0 {
					t.Error("no paths")
				}

				for _, other := range keysOf(t) {
					if other.name == k.name {
						continue
					}

					if _, _, err := VerifyPackage(bytes.NewReader(ref), keyringOf(t, other), ReadOptions{}); !errors.Is(err, ErrUntrusted) {
						t.Errorf("verified with the wrong key: %v", err)
					}
				}

				rd, err := NewReader(bytes.NewReader(ref), ReadOptions{})
				if err != nil {
					t.Fatal(err)
				}

				defer func() { _ = rd.Close() }()

				if rd.Compression().Alg != c.c.Alg && (c.arg != "" || rd.Compression().Alg != CompDeflate) {
					t.Errorf("compression %+v, want %+v", rd.Compression(), c.c)
				}
			})
		}
	}
}

func TestVerifyFailures(t *testing.T) {
	needApk(t)

	k := keysOf(t)[0]
	tr := newTree(t)
	tr.File("a", 0o644, []byte("hello"))

	signed := tr.mkpkg(&Spec{Info: minimalInfo()}, "--sign-key", k.priv, "--compression", "none")
	unsigned := tr.mkpkg(&Spec{Info: minimalInfo()}, "--compression", "none")

	if _, _, err := VerifyPackage(bytes.NewReader(unsigned), keyringOf(t, k), ReadOptions{}); !errors.Is(err, ErrUnsigned) {
		t.Errorf("unsigned: %v", err)
	}

	if _, _, err := VerifyPackage(bytes.NewReader(signed), NewKeyring(), ReadOptions{}); !errors.Is(err, ErrNoKeyring) {
		t.Errorf("empty keyring: %v", err)
	}

	// Flip a byte of the ADB block (the version string) and of the content.
	bad := bytes.Clone(signed)
	i := bytes.Index(bad, []byte("1.0-r0"))
	bad[i] ^= 1

	if _, _, err := VerifyPackage(bytes.NewReader(bad), keyringOf(t, k), ReadOptions{}); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered ADB block: %v", err)
	}

	bad = bytes.Clone(signed)
	i = bytes.Index(bad, []byte("hello"))
	bad[i] ^= 1

	if _, _, err := VerifyPackage(bytes.NewReader(bad), keyringOf(t, k), ReadOptions{}); !errors.Is(err, ErrDigest) {
		t.Errorf("tampered content: %v", err)
	}
}

// snapshot describes a tree: for each path its kind, permissions and content.
func snapshot(t testing.TB, root string) map[string]string {
	t.Helper()

	out := map[string]string{}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == root {
			return err
		}

		rel, _ := filepath.Rel(root, p)

		info, err := d.Info()
		if err != nil {
			return err
		}

		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			out[rel] = "link " + target

			return err
		case info.IsDir():
			out[rel] = fmt.Sprintf("dir %o", info.Mode().Perm())
		case info.Mode().IsRegular():
			data, err := os.ReadFile(p)
			out[rel] = fmt.Sprintf("file %o %x", info.Mode().Perm(), data)

			return err
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// TestExtractMatchesTree unpacks what apk mkpkg wrote and what the writer
// wrote, and compares both with the source tree.
func TestExtractMatchesTree(t *testing.T) {
	needApk(t)

	tr := newTree(t)
	sampleTree(tr)

	want := snapshot(t, tr.root)
	// Extract drops the setuid bit.
	for k, v := range want {
		if strings.HasPrefix(k, "usr/bin/hello") && strings.HasPrefix(v, "file") {
			want[k] = strings.Replace(v, "file 4755", "file 755", 1)
		}
	}

	var ours bytes.Buffer
	if _, err := WritePackage(&ours, &Spec{Info: minimalInfo(), Files: tr.files}, WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		pkg  []byte
	}{
		{"apk", tr.mkpkg(&Spec{Info: minimalInfo()})},
		{"apk-zstd", tr.mkpkg(&Spec{Info: minimalInfo()}, "--compression", "zstd:5")},
		{"ours", ours.Bytes()},
	} {
		t.Run(c.name, func(t *testing.T) {
			dest := t.TempDir()

			pkg, err := Extract(bytes.NewReader(c.pkg), dest, ExtractOptions{AllowUntrusted: true})
			if err != nil {
				t.Fatal(err)
			}

			if pkg.Info.Name != "minimal" {
				t.Errorf("name %q", pkg.Info.Name)
			}

			got := snapshot(t, dest)
			for k, v := range want {
				if got[k] != v {
					t.Errorf("%s: got %.60q, want %.60q", k, got[k], v)
				}
			}

			if len(got) != len(want) {
				t.Errorf("%d entries, want %d", len(got), len(want))
			}

			info, err := os.Stat(filepath.Join(dest, "etc/app.conf.hard"))
			if err != nil {
				t.Fatal(err)
			}

			orig, _ := os.Stat(filepath.Join(dest, "etc/app.conf"))
			if !os.SameFile(info, orig) {
				t.Error("the hard link was not made")
			}
		})
	}
}

// TestEntriesMatchApk reads the entries of an apk-made package.
func TestEntriesMatchApk(t *testing.T) {
	needApk(t)

	tr := newTree(t)
	sampleTree(tr)
	tr.Xattr("etc/app.conf", "user.k", []byte("v"))

	ref := tr.mkpkg(&Spec{Info: minimalInfo()}, "--xattrs")

	rd, err := NewReader(bytes.NewReader(ref), ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = rd.Close() }()

	got := map[string]*Entry{}

	for {
		e, err := rd.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			t.Fatal(err)
		}

		if _, err := io.Copy(io.Discard, rd); err != nil {
			t.Fatal(err)
		}

		got[e.Name] = e
	}

	for _, f := range tr.files {
		e := got[f.Name]
		if e == nil {
			t.Errorf("no entry %q", f.Name)

			continue
		}

		if e.Mode != f.Mode || e.User != f.Uname || e.Group != f.Gname || e.ModTime.Unix() != fixtureTime && f.Mode&fs.ModeDir == 0 {
			t.Errorf("%s: %+v, want mode %v owner %s:%s", f.Name, e, f.Mode, f.Uname, f.Gname)
		}

		switch {
		case f.HardLink != "":
			if e.Kind != KindHardlink || e.LinkTarget != f.HardLink {
				t.Errorf("%s: kind %v target %q", f.Name, e.Kind, e.LinkTarget)
			}
		case f.Mode&fs.ModeSymlink != 0:
			if e.Kind != KindSymlink || e.LinkTarget != f.LinkTarget {
				t.Errorf("%s: kind %v target %q", f.Name, e.Kind, e.LinkTarget)
			}
		case f.Mode.IsRegular():
			if e.Kind != KindFile || e.Size != f.Size {
				t.Errorf("%s: kind %v size %d", f.Name, e.Kind, e.Size)
			}
		}
	}

	if x := got["etc/app.conf"].Xattrs; len(x) != 1 || x[0].Name != "user.k" || string(x[0].Value) != "v" {
		t.Errorf("xattrs %v", x)
	}
}

// TestApkAddInstallsOurPackage installs a package the writer made in an
// Alpine container with apk add, trusted by key, and runs its scripts.
func TestApkAddInstallsOurPackage(t *testing.T) {
	podman, err := exec.LookPath("podman")
	if err != nil {
		t.Skip("podman is not installed")
	}

	const image = "docker.io/library/alpine:3.24"

	if exec.Command(podman, "image", "exists", image).Run() != nil {
		t.Skipf("image %s is not available locally", image)
	}

	k := keysOf(t)

	for _, key := range k {
		t.Run(key.name, func(t *testing.T) {
			dir := t.TempDir()

			spec := &Spec{
				Info: Info{
					Name: "adbhello", Version: "1.0-r0", Arch: "noarch", Description: "interop test",
					Depends: []string{"busybox"}, Provides: []string{"adbhello-virt=1"},
				},
				Scripts: Scripts{PostInstall: "#!/bin/sh\necho ran > /var/post-install-marker\n"},
				Files: []File{
					MemFile("usr/bin/adbhello", 0o755, []byte("#!/bin/sh\necho hello from adb\n")),
					MemFile("etc/adbhello.conf", 0o644, []byte("setting=1\n")),
					{Name: "usr/bin/hi", Mode: fs.ModeSymlink | 0o777, LinkTarget: "adbhello"},
					MemFile("usr/share/adbhello/data", 0o644, bytes.Repeat([]byte("data"), 5000)),
				},
			}

			var out bytes.Buffer
			if _, err := WritePackage(&out, spec, WriteOptions{Signers: []*Signer{key.signer}}); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(filepath.Join(dir, "adbhello-1.0-r0.apk"), out.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}

			pub, err := os.ReadFile(filepath.Join(key.keysDir, "test-"+key.name+".pub"))
			if err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(filepath.Join(dir, "test.pub"), pub, 0o644); err != nil {
				t.Fatal(err)
			}

			script := `set -ex
cp /t/test.pub /etc/apk/keys/test.pub
apk add --no-network --no-cache /t/adbhello-1.0-r0.apk
adbhello
test "$(cat /var/post-install-marker)" = ran
cat /etc/adbhello.conf
test "$(hi)" = "hello from adb"
test -z "$(apk audit --full | grep -E ' (usr/bin/(adbhello|hi)|usr/share/adbhello.*|etc/adbhello.conf)$')"
apk info -e adbhello
`
			script = ": > /etc/apk/repositories\n" + script

			cmd := exec.Command(podman, "run", "--rm", "--network", "none", "-v", dir+":/t:ro", image, "sh", "-c", script)

			combined, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("podman run: %v\n%s", err, combined)
			}

			for _, want := range []string{"hello from adb", "setting=1", "adbhello"} {
				if !bytes.Contains(combined, []byte(want)) {
					t.Errorf("output lacks %q:\n%s", want, combined)
				}
			}

			// Without the key the package is refused.
			untrusted := strings.Replace(script, "cp /t/test.pub /etc/apk/keys/test.pub\n", "", 1)
			if err := exec.Command(podman, "run", "--rm", "--network", "none", "-v", dir+":/t:ro", image, "sh", "-c", untrusted).Run(); err == nil {
				t.Error("apk add installed a package signed by an unknown key")
			}
		})
	}
}
