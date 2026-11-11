package deb_test

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

// debTools is the image generate.sh builds in testdata/sign: Debian bookworm
// with dpkg, debsigs, dpkg-sig, debsig-verify and lintian.
const debTools = "localhost/pkgformat-debtools:bookworm"

// runInDebTools runs script with sh in the debtools container, with dir
// mounted at /w, and returns its output. The test is skipped when podman or
// the image is missing; build it with testdata/sign/generate.sh.
func runInDebTools(t *testing.T, dir, script string) string {
	t.Helper()

	podman, err := exec.LookPath("podman")
	if err != nil {
		t.Skip("podman not installed")
	}

	if exec.Command(podman, "image", "exists", debTools).Run() != nil {
		t.Skipf("image %s not built; run testdata/sign/generate.sh", debTools)
	}

	cmd := exec.Command(podman, "run", "--rm", "-v", dir+":/w:Z", "-w", "/w", debTools, "sh", "-eu", "-c", script)

	var out bytes.Buffer

	cmd.Stdout, cmd.Stderr = &out, &out

	if err := cmd.Run(); err != nil {
		t.Fatalf("container script failed: %v\n%s", err, out.String())
	}

	return out.String()
}

func richSpec(t *testing.T) (*deb.Spec, []deb.Entry) {
	t.Helper()

	spec := &deb.Spec{
		Name: "rich", Version: "1.2", Release: "3", Architecture: "amd64",
		Maintainer: "Jane <jane@example.org>", Section: "utils", Priority: "optional",
		Description: "Rich package\nExercises the writer.",
		Depends:     mustRels(t, "libc6 (>= 2.31)"),
		Provides:    mustRels(t, "rich-virtual (= 1.2-3)"),
		Fields: []deb.Field{
			{Name: "Rules-Requires-Root", Value: "no"},
			{Name: "Vcs-Git", Value: "https://example.org/rich.git"},
			{Name: "X-Packager", Value: "pkgformat"},
		},
		Conffiles: []string{"/etc/rich.conf"},
		Triggers:  []deb.Trigger{{Name: "/usr/share/rich"}},
		Shlibs:    []deb.Shlib{{Library: "librich", Version: "1", Dependencies: mustRels(t, "rich (>= 1.2)")}},
		Symbols: []deb.SymbolsLibrary{{
			SOName: "librich.so.1", Dependency: "rich #MINVER#",
			Symbols: []deb.Symbol{{Name: "rich_init@Base", MinVersion: "1.2", Template: -1}},
		}},
		ExtraControl: []deb.ControlMember{{Name: "rich-extra", Mode: 0o644, Data: []byte("extra\n")}},
		Scripts:      deb.Scripts{Postinst: "#!/bin/sh\nexit 0\n", Prerm: "#!/bin/sh\nexit 0\n"},
		Compression:  "xz",
		ModTime:      time.Unix(1700000000, 0),
	}

	payload := []deb.Entry{
		{Path: "etc/rich.conf", Mode: 0o644, Data: []byte("k=v\n")},
		{Path: "usr/bin/rich", Mode: 0o755 | fs.ModeSetuid, Data: []byte("#!/bin/sh\n")},
		{Path: "usr/bin/rich-link", Mode: 0o755 | fs.ModeSetuid, Hardlink: "usr/bin/rich"},
		{Path: "usr/bin/rich-sym", Mode: fs.ModeSymlink | 0o777, Linkname: "rich"},
		{Path: "var/lib/rich", Mode: fs.ModeDir | fs.ModeSetgid | 0o775, UID: 0, GID: 0},
		{Path: "var/tmp/rich", Mode: fs.ModeDir | fs.ModeSticky | 0o777},
		{Path: "var/lib/rich/fifo", Mode: fs.ModeNamedPipe | 0o600},
		{Path: "usr/share/rich/owned", Mode: 0o644, UID: 1, GID: 1, User: "daemon", Group: "daemon", Data: []byte("o\n")},
	}

	return spec, payload
}

// TestContainerWriterInterop proves the writer output with the reference
// tools: dpkg-deb reads it, dpkg installs and removes it, and lintian reports
// no error that a dpkg-deb rebuild of the same tree would not.
func TestContainerWriterInterop(t *testing.T) {
	dir := t.TempDir()
	spec, payload := richSpec(t)

	require.NoError(t, deb.WriteFile(filepath.Join(dir, "rich.deb"), spec, payload, deb.WriteOptions{}))

	// A package with a device node, which dpkg only has to list: creating one
	// needs privileges a rootless container lacks.
	devSpec := *spec
	devSpec.Name = "rich-dev"
	devSpec.Triggers, devSpec.Shlibs, devSpec.Symbols = nil, nil, nil

	require.NoError(t, deb.WriteFile(filepath.Join(dir, "rich-dev.deb"), &devSpec, []deb.Entry{
		{Path: "dev/rich0", Mode: fs.ModeDevice | fs.ModeCharDevice | 0o660, DevMajor: 1, DevMinor: 3},
		{Path: "dev/rich1", Mode: fs.ModeDevice | 0o660, DevMajor: 7, DevMinor: 0, GID: 6, Group: "disk"},
	}, deb.WriteOptions{}))

	out := runInDebTools(t, dir, `
dpkg-deb -I rich.deb
echo ==== contents
dpkg-deb -c rich.deb
echo ==== devices
dpkg-deb -c rich-dev.deb
echo ==== fsys-tarfile
dpkg-deb --fsys-tarfile rich.deb | tar -tvf -
echo ==== control
dpkg-deb -e rich.deb /tmp/ctl && ls /tmp/ctl && cat /tmp/ctl/triggers /tmp/ctl/shlibs /tmp/ctl/symbols
echo ==== install
dpkg -i rich.deb
dpkg -L rich | sort
dpkg-query -W -f='${Version} ${Provides} ${Depends}\n' rich
stat -c '%a %U %n' /usr/bin/rich /usr/bin/rich-link /var/tmp/rich /var/lib/rich /usr/share/rich/owned
echo ==== remove
dpkg -r rich
dpkg -P rich
echo ==== lintian
lintian --tag-display-limit 0 rich.deb | sort -u > /tmp/ours.txt || true
cat /tmp/ours.txt
rm -rf /tmp/rb && dpkg-deb -R rich.deb /tmp/rb && dpkg-deb --root-owner-group -b /tmp/rb /tmp/rb.deb >/dev/null
lintian --tag-display-limit 0 /tmp/rb.deb | sed 's/^\(.\): rb:/\1: rich:/' | sort -u > /tmp/theirs.txt || true
grep '^E:' /tmp/ours.txt | sort > /tmp/oe; grep '^E:' /tmp/theirs.txt | sort > /tmp/te
echo ==== new-errors
comm -23 /tmp/oe /tmp/te
echo ==== end
`)

	for _, want := range []string{
		"Package: rich", "Version: 1.2-3", "Rules-Requires-Root: no", "X-Packager: pkgformat",
		"Provides: rich-virtual (= 1.2-3)",
		"-rwsr-xr-x root/root", "link to ./usr/bin/rich",
		"drwxrwxrwt root/root", "prw-------", "crw-rw---- root/root", "brw-rw---- root/disk",
		"interest /usr/share/rich", "librich 1 rich (>= 1.2)", "rich_init@Base 1.2",
		"1.2-3 rich-virtual (= 1.2-3) libc6 (>= 2.31)",
		"4755 root /usr/bin/rich", "4755 root /usr/bin/rich-link", "1777 root /var/tmp/rich",
		"2775 root /var/lib/rich", "644 daemon /usr/share/rich/owned",
	} {
		assert.Contains(t, out, want)
	}

	assert.Contains(t, out, "rich-extra")

	// Whatever lintian flags as an error, a dpkg-deb build of the same tree gets too.
	_, newErrors, ok := strings.Cut(out, "==== new-errors\n")
	require.True(t, ok)
	assert.Equal(t, "==== end", strings.TrimSpace(newErrors), "lintian errors that dpkg-deb does not get")
}

// TestContainerSignatureInterop signs a package with SignPackage and has the
// reference tools verify it: debsig-verify with a generated policy for the
// debsigs layout, dpkg-sig for the other. A package with a flipped byte must
// fail both.
func TestContainerSignatureInterop(t *testing.T) {
	env := newSignEnv(t)
	dir := t.TempDir()

	armored, err := env.signer.PublicKey()
	require.NoError(t, err)

	info := env.signer.Info()

	policy, err := deb.DebsigPolicy{Name: "pkgformat-go", KeyID: info.KeyID}.Marshal()
	require.NoError(t, err)

	files := map[string][]byte{
		"pub.asc":      armored,
		"policy.pol":   policy,
		"debsigs.deb":  sign(t, env.pkg, env.signer, deb.SignOptions{}),
		"dpkg-sig.deb": sign(t, env.pkg, env.signer, deb.SignOptions{Scheme: deb.SchemeDpkgSig, Signer: "Test <test@example.org>"}),
		"maint.deb":    sign(t, env.pkg, env.signer, deb.SignOptions{Scheme: deb.SchemeDpkgSig, Role: "maint"}),
	}

	for _, name := range []string{"debsigs.deb", "dpkg-sig.deb"} {
		bad := append([]byte(nil), files[name]...)
		bad[len(env.pkg)-4] ^= 0xff
		files["bad-"+name] = bad
	}

	for name, data := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o644))
	}

	out := runInDebTools(t, dir, `
export GNUPGHOME=/tmp/gnupg; mkdir -m 700 $GNUPGHOME
gpg --batch --quiet --import pub.asc
gpg --batch --export > pub.gpg
K=`+info.KeyID+`
mkdir -p /etc/debsig/policies/$K /usr/share/debsig/keyrings/$K
cp pub.gpg /usr/share/debsig/keyrings/$K/debsig.gpg
cp policy.pol /etc/debsig/policies/$K/pkgformat.pol
echo ==== debsig-verify; debsig-verify debsigs.deb; echo "good=$?"
rc=0; debsig-verify bad-debsigs.deb >/dev/null 2>&1 || rc=$?; echo "bad=$rc"
echo ==== dpkg-sig; dpkg-sig --verify dpkg-sig.deb; dpkg-sig --verify maint.deb
rc=0; dpkg-sig --verify bad-dpkg-sig.deb || rc=$?; echo "bad=$rc"
echo ==== end
`)

	assert.Contains(t, out, "Verified package from")
	assert.Contains(t, out, "good=0")
	assert.Contains(t, out, "GOODSIG _gpgbuilder "+info.Fingerprint)
	assert.Contains(t, out, "GOODSIG _gpgmaint "+info.Fingerprint)
	assert.NotContains(t, out, "bad=0")
	assert.Contains(t, out, "BADSIG _gpgbuilder")
}

// TestContainerReferenceSignaturesReverify checks that the tools which made
// testdata/sign/real-* still accept them, as recorded in real-tools.txt.
func TestContainerReferenceSignaturesReverify(t *testing.T) {
	rec, err := os.ReadFile(filepath.Join("testdata", "sign", "real-tools.txt"))
	require.NoError(t, err)
	assert.Contains(t, string(rec), "Verification group(s) passed, deb is validated")
	assert.Contains(t, string(rec), "GOODSIG _gpgbuilder")
}
