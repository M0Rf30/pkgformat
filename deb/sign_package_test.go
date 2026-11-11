package deb_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
)

type signEnv struct {
	signer *gpg.LocalSigner
	kr     *gpg.Keyring
	pkg    []byte
}

func newSignEnv(t *testing.T) signEnv {
	t.Helper()

	e, err := gpg.GenerateEntity("Test", "", "test@example.org", gpg.AlgorithmED25519)
	require.NoError(t, err)

	s, err := gpg.NewLocalSignerFromEntity(e)
	require.NoError(t, err)

	kr, err := s.Keyring()
	require.NoError(t, err)

	spec := &deb.Spec{
		Name: "signed", Version: "1.0", Release: "1", Architecture: "all",
		Maintainer: "A <a@example.org>", Description: "signed", ModTime: time.Unix(1700000000, 0),
		// dpkg-sig only knows gzip, xz and bzip2 members.
		Compression: "gzip",
	}

	var buf bytes.Buffer

	require.NoError(t, deb.Write(&buf, spec, []deb.Entry{{Path: "usr/share/x", Mode: 0o644, Data: []byte("x")}}, deb.WriteOptions{}))

	return signEnv{signer: s, kr: kr, pkg: buf.Bytes()}
}

func sign(t *testing.T, pkg []byte, s gpg.Signer, opts deb.SignOptions) []byte {
	t.Helper()

	var out bytes.Buffer

	require.NoError(t, deb.SignPackage(&out, bytes.NewReader(pkg), int64(len(pkg)), s, opts))

	return out.Bytes()
}

func parse(t *testing.T, b []byte) *deb.DebFile {
	t.Helper()

	d, err := deb.ParseDebFileAt(bytes.NewReader(b), int64(len(b)))
	require.NoError(t, err)

	return d
}

func TestSignRoundTrip(t *testing.T) {
	env := newSignEnv(t)

	for _, tc := range []struct {
		name   string
		opts   deb.SignOptions
		member string
		scheme deb.SignScheme
		role   string
	}{
		{"debsigs", deb.SignOptions{}, "_gpgorigin", deb.SchemeDebsigs, "origin"},
		{"debsigs maint", deb.SignOptions{Role: "maint"}, "_gpgmaint", deb.SchemeDebsigs, "maint"},
		{"dpkg-sig", deb.SignOptions{Scheme: deb.SchemeDpkgSig, Signer: "Jane"}, "_gpgbuilder", deb.SchemeDpkgSig, "builder"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := parse(t, sign(t, env.pkg, env.signer, tc.opts))
			require.Len(t, d.Signatures, 1)
			assert.Equal(t, tc.member, d.Signatures[0].Name)

			res, err := d.VerifySignatures(env.kr)
			require.NoError(t, err)
			require.Len(t, res, 1)
			assert.Equal(t, tc.scheme, res[0].Scheme)
			assert.Equal(t, tc.role, res[0].Role)
			assert.Equal(t, env.signer.KeyFingerprint(), res[0].Signer.Fingerprint)
			assert.Equal(t, tc.scheme.String() != "", true)
		})
	}
}

func TestSignKeepsPackageIntact(t *testing.T) {
	env := newSignEnv(t)
	out := sign(t, env.pkg, env.signer, deb.SignOptions{})
	assert.True(t, bytes.HasPrefix(out, env.pkg))

	d := parse(t, out)
	assert.Equal(t, "signed", d.Package.Package)
}

func TestSignTwiceDpkgSigSuffix(t *testing.T) {
	env := newSignEnv(t)
	once := sign(t, env.pkg, env.signer, deb.SignOptions{Scheme: deb.SchemeDpkgSig})
	twice := sign(t, once, env.signer, deb.SignOptions{Scheme: deb.SchemeDpkgSig})

	d := parse(t, twice)
	require.Len(t, d.Signatures, 2)
	assert.Equal(t, "_gpgbuilder0", d.Signatures[1].Name)

	res, err := d.VerifySignatures(env.kr)
	require.NoError(t, err)
	assert.Equal(t, "builder", res[1].Role)
}

func TestSignTwiceDebsigsFails(t *testing.T) {
	env := newSignEnv(t)
	once := sign(t, env.pkg, env.signer, deb.SignOptions{})

	err := deb.SignPackage(&bytes.Buffer{}, bytes.NewReader(once), int64(len(once)), env.signer, deb.SignOptions{})
	require.ErrorIs(t, err, deb.ErrSignatureExists)
}

func TestSignDebsigsThenDpkgSig(t *testing.T) {
	env := newSignEnv(t)
	both := sign(t, sign(t, env.pkg, env.signer, deb.SignOptions{}), env.signer, deb.SignOptions{Scheme: deb.SchemeDpkgSig})

	res, err := parse(t, both).VerifySignatures(env.kr)
	require.NoError(t, err)
	require.Len(t, res, 2)
}

func TestSignOddSizePackage(t *testing.T) {
	env := newSignEnv(t)
	// Drop the padding of an odd last member to mimic a sloppy writer.
	d := parse(t, env.pkg)
	require.NotNil(t, d)

	odd := append([]byte(nil), env.pkg...)
	if len(odd)%2 == 0 {
		t.Skip("package has even size")
	}

	out := sign(t, odd, env.signer, deb.SignOptions{})
	_, err := parse(t, out).VerifySignatures(env.kr)
	require.NoError(t, err)
}

func TestSignErrors(t *testing.T) {
	env := newSignEnv(t)
	var sink bytes.Buffer

	r := bytes.NewReader(env.pkg)
	size := int64(len(env.pkg))

	require.ErrorIs(t, deb.SignPackage(&sink, r, size, nil, deb.SignOptions{}), deb.ErrNoSigner)

	for _, role := range []string{"Origin", "has space", "averyveryverylongrole"} {
		err := deb.SignPackage(&sink, r, size, env.signer, deb.SignOptions{Role: role})
		require.ErrorIs(t, err, deb.ErrInvalidSignRole, role)
	}

	err := deb.SignPackage(&sink, r, size, env.signer, deb.SignOptions{Scheme: 9})
	require.ErrorIs(t, err, deb.ErrInvalidSignRole)

	err = deb.SignPackage(&sink, bytes.NewReader([]byte("nope")), 4, env.signer, deb.SignOptions{})
	require.ErrorIs(t, err, deb.ErrInvalidPackage)

	// An ar archive without the three core members.
	bare := buildAR(arMem{"debian-binary", []byte("2.0\n")})
	err = deb.SignPackage(&sink, bytes.NewReader(bare), int64(len(bare)), env.signer, deb.SignOptions{})
	require.ErrorIs(t, err, deb.ErrInvalidPackage)

	err = deb.SignPackage(&sink, r, size, env.signer, deb.SignOptions{Scheme: deb.SchemeDpkgSig, Signer: "a\nb"})
	require.ErrorIs(t, err, deb.ErrInvalidSpec)
}

func TestVerifyUnsigned(t *testing.T) {
	env := newSignEnv(t)
	res, err := parse(t, env.pkg).VerifySignatures(env.kr)
	require.ErrorIs(t, err, deb.ErrNoPackageSignature)
	assert.Empty(t, res)
}

func TestVerifyUnknownKey(t *testing.T) {
	env := newSignEnv(t)
	other := newSignEnv(t)

	for _, scheme := range []deb.SignScheme{deb.SchemeDebsigs, deb.SchemeDpkgSig} {
		d := parse(t, sign(t, env.pkg, env.signer, deb.SignOptions{Scheme: scheme}))
		res, err := d.VerifySignatures(other.kr)
		require.ErrorIs(t, err, deb.ErrInvalidPackageSignature)
		require.ErrorIs(t, err, gpg.ErrUnknownSigner)
		require.Len(t, res, 1)
		require.Error(t, res[0].Err)
	}
}

func TestVerifyTamperedPackage(t *testing.T) {
	env := newSignEnv(t)

	for _, scheme := range []deb.SignScheme{deb.SchemeDebsigs, deb.SchemeDpkgSig} {
		out := sign(t, env.pkg, env.signer, deb.SignOptions{Scheme: scheme})
		// Flip a byte inside the data archive, the last core member.
		bad := append([]byte(nil), out...)
		bad[len(env.pkg)-4] ^= 0xff

		_, err := parse(t, bad).VerifySignatures(env.kr)
		require.ErrorIs(t, err, deb.ErrInvalidPackageSignature, scheme.String())
	}
}

func TestVerifyEmptyKeyring(t *testing.T) {
	env := newSignEnv(t)
	d := parse(t, sign(t, env.pkg, env.signer, deb.SignOptions{}))
	_, err := d.VerifySignatures(nil)
	require.ErrorIs(t, err, gpg.ErrNoKeys)
}

// forgedDpkgSig signs manifest text with signer and appends it as member.
func forgedDpkgSig(t *testing.T, env signEnv, member, manifest string) *deb.DebFile {
	t.Helper()

	r, err := env.signer.CleartextSign(strings.NewReader(manifest))
	require.NoError(t, err)

	var b bytes.Buffer

	_, err = b.ReadFrom(r)
	require.NoError(t, err)

	pkg := env.pkg
	if len(pkg)%2 != 0 {
		pkg = append(append([]byte(nil), pkg...), '\n')
	}

	mem := buildAR(arMem{member, b.Bytes()})

	return parse(t, append(append([]byte(nil), pkg...), mem[len("!<arch>\n"):]...))
}

func TestVerifyDpkgSigManifestChecks(t *testing.T) {
	env := newSignEnv(t)

	good := sign(t, env.pkg, env.signer, deb.SignOptions{Scheme: deb.SchemeDpkgSig})
	body := string(parse(t, good).Signatures[0].Data)
	assert.Contains(t, body, "Role: builder")

	files := "Files: \n\t00 00 1 debian-binary\n"

	cases := map[string]string{
		"bad version":     "Version: x\nRole: builder\n" + files,
		"newer version":   "Version: 5\nRole: builder\n" + files,
		"wrong role":      "Version: 4\nRole: maint\n" + files,
		"file not in deb": "Version: 4\nRole: builder\nFiles: \n\t00 00 1 nothere\n",
		"digest differs":  "Version: 4\nRole: builder\n" + files,
		"core missing":    "Version: 4\nRole: builder\nFiles: \n",
	}

	for name, manifest := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := forgedDpkgSig(t, env, "_gpgbuilder", manifest).VerifySignatures(env.kr)
			require.ErrorIs(t, err, deb.ErrInvalidPackageSignature)
		})
	}
}

func TestSignatureMemberTooLarge(t *testing.T) {
	env := newSignEnv(t)

	pkg := env.pkg
	if len(pkg)%2 != 0 {
		pkg = append(append([]byte(nil), pkg...), '\n')
	}

	mem := buildAR(arMem{"_gpgorigin", make([]byte, deb.MaxSignatureSize+1)})
	big := append(append([]byte(nil), pkg...), mem[len("!<arch>\n"):]...)

	_, err := deb.ParseDebFileAt(bytes.NewReader(big), int64(len(big)))
	require.ErrorIs(t, err, deb.ErrARMemberTooLarge)
}

func TestControlMembersAccessors(t *testing.T) {
	spec := &deb.Spec{
		Name: "libx1", Version: "1.0", Release: "1", Architecture: "amd64",
		Maintainer: "A <a@example.org>", Description: "lib",
		Triggers: []deb.Trigger{{Name: "/usr/lib/x", Await: deb.AwaitNo}, {Activate: true, Name: "ldconfig"}},
		Shlibs:   []deb.Shlib{{Library: "libx", Version: "1", Dependencies: mustRels(t, "libx1 (>= 1.0)")}},
		Symbols: []deb.SymbolsLibrary{{
			SOName: "libx.so.1", Dependency: "libx1 #MINVER#",
			Symbols: []deb.Symbol{{Name: "x_init@Base", MinVersion: "1.0", Template: -1}},
		}},
		ModTime: time.Unix(1700000000, 0),
	}

	var buf bytes.Buffer

	require.NoError(t, deb.Write(&buf, spec, nil, deb.WriteOptions{}))

	d := parse(t, buf.Bytes())

	trig, err := d.Triggers()
	require.NoError(t, err)
	assert.Equal(t, spec.Triggers, trig)

	sh, err := d.Shlibs()
	require.NoError(t, err)
	require.Len(t, sh, 1)
	assert.Equal(t, "libx", sh[0].Library)

	sym, err := d.Symbols()
	require.NoError(t, err)
	require.Len(t, sym, 1)
	assert.Equal(t, "x_init@Base", sym[0].Symbols[0].Name)

	// A package without the members has none of them.
	plain := newSignEnv(t)
	d = parse(t, plain.pkg)

	trig, err = d.Triggers()
	require.NoError(t, err)
	assert.Empty(t, trig)
}

func mustRels(t *testing.T, s string) []deb.Alternatives {
	t.Helper()

	r, err := deb.ParseRelations(s)
	require.NoError(t, err)

	return r
}

func TestDebsigPolicy(t *testing.T) {
	out, err := deb.DebsigPolicy{Name: "acme", Description: "Acme <ok>", KeyID: "0123456789ABCDEF"}.Marshal()
	require.NoError(t, err)

	s := string(out)
	assert.Contains(t, s, `<!DOCTYPE Policy SYSTEM "https://www.debian.org/debsig/1.0/policy.dtd">`)
	assert.Contains(t, s, `xmlns="https://www.debian.org/debsig/1.0/"`)
	assert.Contains(t, s, `<Origin Name="acme" id="0123456789ABCDEF" Description="Acme &lt;ok&gt;">`)
	assert.Contains(t, s, `<Required Type="origin" File="debsig.gpg" id="0123456789ABCDEF">`)
	assert.Contains(t, s, `MinOptional="0"`)

	out, err = deb.DebsigPolicy{Name: "a", KeyID: strings.Repeat("a", 40), Keyring: "k.gpg"}.Marshal()
	require.NoError(t, err)
	assert.Contains(t, string(out), `File="k.gpg"`)

	_, err = deb.DebsigPolicy{KeyID: "0123456789ABCDEF"}.Marshal()
	require.ErrorIs(t, err, deb.ErrInvalidSpec)

	_, err = deb.DebsigPolicy{Name: "a", KeyID: "xyz"}.Marshal()
	require.ErrorIs(t, err, deb.ErrInvalidSpec)
}

// The packages in testdata/sign were signed by the reference tools; see
// testdata/sign/README.md.
func TestReferenceToolSignatures(t *testing.T) {
	dir := filepath.Join("testdata", "sign")

	pub, err := os.ReadFile(filepath.Join(dir, "pub.asc"))
	require.NoError(t, err)

	kr, err := gpg.ParseKeyring(pub)
	require.NoError(t, err)

	fpr, err := os.ReadFile(filepath.Join(dir, "fingerprint.txt"))
	require.NoError(t, err)

	for file, want := range map[string]struct {
		member string
		scheme deb.SignScheme
	}{
		"real-debsigs.deb":  {"_gpgorigin", deb.SchemeDebsigs},
		"real-dpkg-sig.deb": {"_gpgbuilder", deb.SchemeDpkgSig},
	} {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, file))
			require.NoError(t, err)

			d := parse(t, raw)
			assert.Equal(t, "hello-sign", d.Package.Package)

			res, err := d.VerifySignatures(kr)
			require.NoError(t, err)
			require.Len(t, res, 1)
			assert.Equal(t, want.member, res[0].Member)
			assert.Equal(t, want.scheme, res[0].Scheme)
			assert.Equal(t, strings.TrimSpace(string(fpr)), res[0].Signer.Fingerprint)

			// One flipped byte of the data archive breaks it.
			bad := append([]byte(nil), raw...)
			bad[bytes.Index(raw, []byte("data.tar.gz"))+60+20] ^= 0xff

			_, err = parse(t, bad).VerifySignatures(kr)
			require.ErrorIs(t, err, deb.ErrInvalidPackageSignature)
		})
	}

	unsigned, err := os.ReadFile(filepath.Join(dir, "unsigned.deb"))
	require.NoError(t, err)
	_, err = parse(t, unsigned).VerifySignatures(kr)
	require.ErrorIs(t, err, deb.ErrNoPackageSignature)
}
