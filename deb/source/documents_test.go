package source_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/deb/source"
	"github.com/M0Rf30/pkgformat/gpg"
)

func newSigner(t testing.TB) (*gpg.LocalSigner, *gpg.Keyring) {
	t.Helper()

	e, err := gpg.GenerateEntity("Test Signer", "", "signer@example.org", gpg.AlgorithmED25519)
	if err != nil {
		t.Fatal(err)
	}

	s, err := gpg.NewLocalSignerFromEntity(e)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	kr, err := gpg.ParseKeyring(pub)
	if err != nil {
		t.Fatal(err)
	}

	return s, kr
}

func TestParseDSCFields(t *testing.T) {
	d, _ := fixtureDSC(t, "hello")

	if d.Format != source.FormatQuilt || d.Source != "hello" || d.Version != "2.10-5" {
		t.Fatalf("identity: %q %q %q", d.Format, d.Source, d.Version)
	}

	if !reflect.DeepEqual(d.Binary, []string{"hello"}) || !reflect.DeepEqual(d.Architecture, []string{"any"}) {
		t.Errorf("binary/arch: %v %v", d.Binary, d.Architecture)
	}

	if d.Testsuite != "autopkgtest" || d.TestsuiteTriggers != "make" {
		t.Errorf("testsuite: %q %q", d.Testsuite, d.TestsuiteTriggers)
	}

	if d.Vcs["Vcs-Git"] != "https://salsa.debian.org/sanvila/hello.git" || d.Vcs["Vcs-Browser"] == "" {
		t.Errorf("vcs: %v", d.Vcs)
	}

	want := source.PackageListEntry{Name: "hello", Type: "deb", Section: "devel", Priority: "optional", Options: []string{"arch=any"}}
	if len(d.PackageList) != 1 || !reflect.DeepEqual(d.PackageList[0], want) {
		t.Errorf("package list: %+v", d.PackageList)
	}

	if got := d.PackageList[0].String(); got != "hello deb devel optional arch=any" {
		t.Errorf("entry string: %q", got)
	}

	if len(d.Files) != 3 || d.Files[0].Name != "hello_2.10.orig.tar.gz" || d.Files[0].Size != 725946 ||
		d.Files[0].MD5 == "" || d.Files[0].SHA1 == "" || d.Files[0].SHA256 == "" || d.Files[0].SHA512 != "" {
		t.Errorf("files: %+v", d.Files)
	}

	if d.File("hello_2.10.orig.tar.gz.asc") == nil || d.File("nope") != nil {
		t.Error("File lookup")
	}

	rels, err := d.Relations("Build-Depends")
	if err != nil || len(rels) != 2 || rels[0][0].Name != "debhelper-compat" || rels[0][0].Version != "13" {
		t.Errorf("Build-Depends: %v %v", rels, err)
	}

	if _, err := d.Relations("Depends"); !errors.Is(err, source.ErrInvalid) {
		t.Errorf("Relations(Depends): %v", err)
	}

	for _, f := range []string{"build-depends-arch", "build-depends-indep", "build-conflicts", "build-conflicts-arch", "build-conflicts-indep"} {
		if r, err := d.Relations(f); err != nil || len(r) != 0 {
			t.Errorf("%s: %v %v", f, r, err)
		}
	}
}

func TestDSCMarshalMatchesDpkgSource(t *testing.T) {
	// A .dsc written by dpkg-source parses and marshals back to itself.
	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			d, p := fixtureDSC(t, fx.name)
			// Some maintainers write "Uploaders:  name"; the parser reads it as
			// a single space, which is what dpkg-source itself writes.
			want := bytes.ReplaceAll(deb.StripClearsign(mustRead(t, p)), []byte(":  "), []byte(": "))

			got, err := d.Marshal()
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(bytes.TrimRight(got, "\n"), bytes.TrimRight(want, "\n")) {
				t.Errorf("marshal differs from the dpkg-source output\n--- got\n%s\n--- want\n%s", got, want)
			}

			again, err := source.ParseDSC(got)
			if err != nil || !reflect.DeepEqual(d, again) {
				t.Errorf("reparse: %v", err)
			}
		})
	}
}

func TestDSCSignAndVerify(t *testing.T) {
	signer, kr := newSigner(t)
	d, _ := fixtureDSC(t, "sl")

	signed, err := d.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}

	got, who, err := source.ParseSignedDSC(signed, kr)
	if err != nil {
		t.Fatalf("ParseSignedDSC: %v", err)
	}

	if who.Fingerprint == "" || !reflect.DeepEqual(got, d) {
		t.Errorf("verified %+v, equal %v", who, reflect.DeepEqual(got, d))
	}

	// A changed field breaks the signature.
	tampered := bytes.Replace(signed, []byte("Source: sl"), []byte("Source: sx"), 1)
	if _, _, err := source.ParseSignedDSC(tampered, kr); err == nil {
		t.Error("tampered .dsc verified")
	}

	// An unsigned document is reported as such.
	body, _ := d.Marshal()
	if _, _, err := source.ParseSignedDSC(body, kr); !errors.Is(err, source.ErrNotSigned) {
		t.Errorf("unsigned: %v", err)
	}

	// A key that is not in the keyring is unknown.
	_, other := newSigner(t)
	if _, _, err := source.ParseSignedDSC(signed, other); !errors.Is(err, gpg.ErrUnknownSigner) {
		t.Errorf("other key: %v", err)
	}

	// ParseDSC reads the signed form without verifying.
	if _, err := source.ParseDSC(signed); err != nil {
		t.Errorf("ParseDSC(signed): %v", err)
	}

	if _, err := d.Sign(nil); !errors.Is(err, deb.ErrNoSigner) {
		t.Errorf("nil signer: %v", err)
	}
}

func TestSignedDocumentsInteropWithGPG(t *testing.T) {
	gpgBin, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not installed")
	}

	signer, kr := newSigner(t)
	pub, _ := signer.PublicKey()

	home := t.TempDir()
	_ = os.Chmod(home, 0o700)

	run := func(stdin []byte, args ...string) []byte {
		t.Helper()

		cmd := exec.Command(gpgBin, append([]string{"--homedir", home, "--batch", "--no-tty"}, args...)...)
		cmd.Stdin = bytes.NewReader(stdin)

		var out, errb bytes.Buffer

		cmd.Stdout, cmd.Stderr = &out, &errb

		if err := cmd.Run(); err != nil {
			t.Fatalf("gpg %v: %v\n%s", args, err, errb.String())
		}

		return out.Bytes()
	}

	run(pub, "--import")

	d, _ := fixtureDSC(t, "sl")
	signed, _ := d.Sign(signer)

	// gpg accepts our signature.
	file := filepath.Join(home, "sl.dsc")
	_ = os.WriteFile(file, signed, 0o600)
	run(nil, "--verify", file)

	// gpg's own signature is accepted by us, for the three document kinds.
	run(nil, "--quick-generate-key", "--passphrase", "", "Other <o@example.org>", "ed25519", "sign", "never")

	exported := run(nil, "--armor", "--export", "o@example.org")

	gkr, err := gpg.ParseKeyring(exported)
	if err != nil {
		t.Fatal(err)
	}

	body, _ := d.Marshal()
	gsigned := run(body, "--clearsign", "-u", "o@example.org")

	if got, _, err := source.ParseSignedDSC(gsigned, gkr); err != nil || got.Source != "sl" {
		t.Fatalf("verifying gpg --clearsign: %v", err)
	}

	if _, _, err := source.ParseSignedDSC(gsigned, kr); err == nil {
		t.Error("a signature of another key verified")
	}
}

func TestParseDSCRejects(t *testing.T) {
	const good = "Format: 3.0 (native)\nSource: foo\nVersion: 1.0\nFiles:\n 00000000000000000000000000000000 1 foo_1.0.tar.xz\n"

	if _, err := source.ParseDSC([]byte(good)); err != nil {
		t.Fatalf("good: %v", err)
	}

	for name, doc := range map[string]string{
		"no format":     "Source: foo\nVersion: 1.0\n",
		"bad source":    "Format: 1.0\nSource: Foo_Bar\nVersion: 1.0\n",
		"bad version":   "Format: 1.0\nSource: foo\nVersion: 1 0\n",
		"short digest":  "Format: 1.0\nSource: foo\nVersion: 1.0\nFiles:\n abcd 1 foo\n",
		"path in name":  "Format: 1.0\nSource: foo\nVersion: 1.0\nFiles:\n 00000000000000000000000000000000 1 ../foo\n",
		"bad size":      "Format: 1.0\nSource: foo\nVersion: 1.0\nFiles:\n 00000000000000000000000000000000 -1 foo\n",
		"columns":       "Format: 1.0\nSource: foo\nVersion: 1.0\nFiles:\n 00000000000000000000000000000000 1\n",
		"size mismatch": "Format: 1.0\nSource: foo\nVersion: 1.0\nFiles:\n 00000000000000000000000000000000 1 foo\nChecksums-Sha1:\n 0000000000000000000000000000000000000000 2 foo\n",
		"package list":  "Format: 1.0\nSource: foo\nVersion: 1.0\nPackage-List:\n foo deb\n",
		"not deb822":    "this is not a control file\n",
		"hex digest":    "Format: 1.0\nSource: foo\nVersion: 1.0\nFiles:\n zz000000000000000000000000000000 1 foo\n",
		"huge":          "Format: 1.0\n" + strings.Repeat("X-Pad: x\n", 1) + strings.Repeat(" ", source.MaxDocumentBytes+1),
	} {
		if _, err := source.ParseDSC([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if _, err := source.ReadDSC(strings.NewReader(good)); err != nil {
		t.Errorf("ReadDSC: %v", err)
	}

	if _, err := source.ReadDSC(strings.NewReader(strings.Repeat("a", source.MaxDocumentBytes+10))); !errors.Is(err, source.ErrTooLarge) {
		t.Errorf("ReadDSC huge: %v", err)
	}

	bad := &source.DSC{Format: source.Format10, Source: "foo", Version: "1.0", Files: []source.FileRef{{Name: "a/b"}}}
	if _, err := bad.Marshal(); !errors.Is(err, source.ErrInvalid) {
		t.Errorf("Marshal with a path name: %v", err)
	}

	if _, err := (&source.DSC{}).Marshal(); !errors.Is(err, source.ErrInvalid) {
		t.Errorf("Marshal empty: %v", err)
	}
}

func TestDSCGitAndDgitMetadata(t *testing.T) {
	doc := "Format: 3.0 (git)\nSource: foo\nBinary: foo\nArchitecture: any\nVersion: 1.0-1\n" +
		"Dgit: 0123456789abcdef0123456789abcdef01234567 debian archive/debian/1.0-1 https://git.example.org/foo\n" +
		"Build-Depends: debhelper (>= 12), libfoo-dev [linux-any] <!nocheck>\nBuild-Conflicts: bar\n" +
		"Files:\n 00000000000000000000000000000000 1 foo_1.0.orig.tar.gz\n"

	d, err := source.ParseDSC([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}

	if d.Format != source.FormatGit || !d.Format.Known() || d.Dgit == "" {
		t.Errorf("format %q dgit %q", d.Format, d.Dgit)
	}

	rels, err := d.Relations("Build-Depends")
	if err != nil || len(rels) != 2 || len(rels[1][0].ArchRestrictions) != 1 || len(rels[1][0].ProfileGroups) != 1 {
		t.Errorf("relations %+v %v", rels, err)
	}

	out, _ := d.Marshal()
	if !strings.Contains(string(out), "Dgit: 0123") {
		t.Errorf("Dgit lost:\n%s", out)
	}

	if source.Format("9.9").Known() {
		t.Error("9.9 known")
	}
}

// -- .changes and .buildinfo --

func TestChangesMatchDpkgGenchanges(t *testing.T) {
	for _, kind := range []string{"full", "binary"} {
		t.Run(kind, func(t *testing.T) {
			data := mustRead(t, filepath.Join("testdata", "changes", kind, "hello_2.10-5_amd64.changes"))

			c, err := source.ParseChanges(data)
			if err != nil {
				t.Fatal(err)
			}

			out, err := c.Marshal()
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(out, data) {
				t.Errorf("marshal differs from dpkg-genchanges\n--- got\n%s\n--- want\n%s", out, data)
			}

			if c.Format != source.ChangesFormat || c.Source != "hello" || c.Version != "2.10-5" ||
				c.Distribution != "unstable" || c.Urgency != "medium" || !reflect.DeepEqual(c.Closes, []int{1103293}) {
				t.Errorf("fields: %+v", c)
			}

			if !c.Date.Equal(time.Date(2025, 4, 16, 9, 50, 0, 0, time.UTC)) {
				t.Errorf("date %v", c.Date)
			}

			if len(c.Description) != 1 || c.Description[0].Package != "hello" ||
				c.Description[0].Summary != "example package based on GNU hello" {
				t.Errorf("description: %+v", c.Description)
			}

			f := c.File("hello_2.10-5_amd64.deb")
			if f == nil || f.Section != "devel" || f.Priority != "optional" || f.SHA256 == "" || f.SHA1 == "" || f.MD5 == "" {
				t.Errorf("deb entry: %+v", f)
			}

			if c.File("hello-dbgsym_2.10-5_amd64.deb").Section != "debug" || c.File("nope") != nil {
				t.Error("file lookup")
			}

			if !strings.Contains(c.Changes, "Closes: #1103293.") || !strings.Contains(c.Changes, "\n\n") {
				t.Errorf("changes text: %q", c.Changes)
			}
		})
	}
}

func TestChangesFilesVerifyAgainstPackage(t *testing.T) {
	c, err := source.ParseChanges(mustRead(t, filepath.Join("testdata", "changes", "full", "hello_2.10-5_amd64.changes")))
	if err != nil {
		t.Fatal(err)
	}

	// The orig files of the .changes are the fixture's.
	var origs []source.FileRef

	for _, f := range c.Files {
		if strings.Contains(f.Name, ".orig.") {
			origs = append(origs, f)
		}
	}

	if err := source.VerifyFiles(origs, fixtureDir("hello")); err != nil {
		t.Fatal(err)
	}

	if err := source.VerifyFiles(c.Files[len(c.Files)-1:], fixtureDir("hello")); !errors.Is(err, source.ErrMissingFile) {
		t.Errorf("missing: %v", err)
	}
}

func TestChangesSignVerify(t *testing.T) {
	signer, kr := newSigner(t)
	data := mustRead(t, filepath.Join("testdata", "changes", "full", "hello_2.10-5_amd64.changes"))
	c, _ := source.ParseChanges(data)

	signed, err := c.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}

	got, _, err := source.ParseSignedChanges(signed, kr)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("verify: %v", err)
	}

	if _, _, err := source.ParseSignedChanges(data, kr); !errors.Is(err, source.ErrNotSigned) {
		t.Errorf("unsigned: %v", err)
	}

	if _, _, err := source.ParseSignedChanges(bytes.Replace(signed, []byte("unstable"), []byte("stable"), 1), kr); err == nil {
		t.Error("tampered .changes verified")
	}

	if _, err := c.Sign(nil); err == nil {
		t.Error("nil signer accepted")
	}

	if got, err := source.ReadChanges(bytes.NewReader(signed)); err != nil || got.Source != "hello" {
		t.Errorf("ReadChanges: %v", err)
	}
}

func TestChangesBuilt(t *testing.T) {
	c := &source.Changes{
		Format: source.ChangesFormat, Date: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Source: "foo", Binary: []string{"foo", "foo-doc"}, BuiltForProfiles: []string{"nodoc"},
		Architecture: []string{"source", "all"}, Version: "1:1.0-1", Distribution: "unstable", Urgency: "low",
		Maintainer: "A <a@example.org>", ChangedBy: "B <b@example.org>",
		Description: []source.BinaryDescription{{Package: "foo", Summary: "the foo"}, {Package: "foo-documentation-long", Summary: "docs"}},
		Closes:      []int{1, 22},
		Changes:     "foo (1:1.0-1) unstable; urgency=low\n\n  * First.",
		Files:       []source.FileRef{{Name: "foo_1.0-1.dsc", Size: 10, MD5: strings.Repeat("a", 32), SHA256: strings.Repeat("b", 64), Section: "", Priority: ""}},
		Extra:       []source.Field{{Name: "Launchpad-Bugs-Fixed", Value: "5"}},
	}

	data, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"Date: Tue, 02 Jan 2024 03:04:05 +0000\n", "Built-For-Profiles: nodoc\n", "Binary: foo foo-doc\n",
		" foo        - the foo\n", " foo-documentation-long - docs\n", "Closes: 1 22\n",
		"Changes:\n foo (1:1.0-1) unstable; urgency=low\n .\n   * First.\n",
		" " + strings.Repeat("a", 32) + " 10 - - foo_1.0-1.dsc\n", "Launchpad-Bugs-Fixed: 5\n",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing %q in\n%s", want, data)
		}
	}

	back, err := source.ParseChanges(data)
	if err != nil {
		t.Fatal(err)
	}

	// Section and priority "-" read back as "-"; the rest is equal.
	back.Files[0].Section, back.Files[0].Priority = "", ""
	back.Date = c.Date

	if !reflect.DeepEqual(back, c) {
		t.Errorf("round trip\n got %+v\nwant %+v", back, c)
	}

	for name, doc := range map[string]string{
		"no source":   "Format: 1.8\nVersion: 1\n",
		"bad version": "Format: 1.8\nSource: foo\nVersion: a b\n",
		"bad date":    "Format: 1.8\nSource: foo\nVersion: 1\nDate: yesterday\n",
		"bad closes":  "Format: 1.8\nSource: foo\nVersion: 1\nCloses: x\n",
		"bad desc":    "Format: 1.8\nSource: foo\nVersion: 1\nDescription:\n foo without dash\n",
		"files cols":  "Format: 1.8\nSource: foo\nVersion: 1\nFiles:\n 00000000000000000000000000000000 1 foo\n",
	} {
		if _, err := source.ParseChanges([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	if _, err := (&source.Changes{}).Marshal(); !errors.Is(err, source.ErrInvalid) {
		t.Errorf("empty: %v", err)
	}

	if _, err := (&source.Changes{Format: "1.8", Source: "a", Version: "1", Files: []source.FileRef{{Name: "../x"}}}).Marshal(); err == nil {
		t.Error("path in file name accepted")
	}
}

func TestBuildInfoMatchesDpkgGenbuildinfo(t *testing.T) {
	for _, kind := range []string{"full", "binary"} {
		t.Run(kind, func(t *testing.T) {
			data := mustRead(t, filepath.Join("testdata", "changes", kind, "hello_2.10-5_amd64.buildinfo"))

			b, err := source.ParseBuildInfo(data)
			if err != nil {
				t.Fatal(err)
			}

			out, err := b.Marshal()
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(out, data) {
				t.Errorf("marshal differs from dpkg-genbuildinfo\n--- got\n%s\n--- want\n%s", out, data)
			}

			if b.Format != "1.0" || b.BuildOrigin != "Debian" || b.BuildArchitecture != "amd64" ||
				!reflect.DeepEqual(b.BuildTaintedBy, []string{"merged-usr-via-aliased-dirs"}) {
				t.Errorf("fields: %+v", b)
			}

			if len(b.InstalledBuildDepends) < 100 || b.InstalledBuildDepends[0].Name != "autoconf" ||
				b.InstalledBuildDepends[0].Version != "2.71-3" || b.InstalledBuildDepends[0].String() != "autoconf (= 2.71-3)" {
				t.Errorf("installed: %v", b.InstalledBuildDepends[:2])
			}

			if len(b.Environment) != 2 || b.Environment[1] != (source.EnvVar{Name: "SOURCE_DATE_EPOCH", Value: "1700000000"}) {
				t.Errorf("environment: %+v", b.Environment)
			}

			if f := b.Files[1]; f.MD5 == "" || f.SHA1 == "" || f.SHA256 == "" || f.SHA512 != "" {
				t.Errorf("digests: %+v", f)
			}

			if b.BuildDate.Year() != 2026 {
				t.Errorf("date: %v", b.BuildDate)
			}
		})
	}
}

func TestBuildInfoSignVerifyAndEdgeCases(t *testing.T) {
	signer, kr := newSigner(t)
	data := mustRead(t, filepath.Join("testdata", "changes", "binary", "hello_2.10-5_amd64.buildinfo"))
	b, _ := source.ParseBuildInfo(data)

	signed, err := b.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}

	got, _, err := source.ParseSignedBuildInfo(signed, kr)
	if err != nil || !reflect.DeepEqual(got, b) {
		t.Fatalf("verify: %v", err)
	}

	if _, _, err := source.ParseSignedBuildInfo(data, kr); !errors.Is(err, source.ErrNotSigned) {
		t.Errorf("unsigned: %v", err)
	}

	if _, err := b.Sign(nil); err == nil {
		t.Error("nil signer accepted")
	}

	if r, err := source.ReadBuildInfo(bytes.NewReader(data)); err != nil || r.Source != "hello" {
		t.Errorf("ReadBuildInfo: %v", err)
	}

	custom := &source.BuildInfo{
		Format: "1.0", Source: "foo", Version: "1.0-1", Architecture: []string{"amd64"},
		BinaryOnlyChanges: "foo (1.0-1+b1) unstable; urgency=low, binary-only=yes\n\n  * Rebuild.",
		BuildDate:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		InstalledBuildDepends: []source.InstalledPackage{
			{Name: "libc6", Architecture: "amd64", Version: "2.36-9"}, {Name: "make", Version: "4.3-4.1"},
		},
		Environment: []source.EnvVar{{Name: "LANG", Value: `C "quoted" \ back`}},
		Files:       []source.FileRef{{Name: "foo.deb", Size: 3, MD5: strings.Repeat("1", 32), SHA1: strings.Repeat("2", 40), SHA256: strings.Repeat("3", 64), SHA512: strings.Repeat("4", 128)}},
	}

	out, err := custom.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	back, err := source.ParseBuildInfo(out)
	if err != nil {
		t.Fatal(err)
	}

	again, _ := back.Marshal()
	if !bytes.Equal(again, out) || !reflect.DeepEqual(back.InstalledBuildDepends, custom.InstalledBuildDepends) ||
		!reflect.DeepEqual(back.Environment, custom.Environment) || !reflect.DeepEqual(back.Files, custom.Files) ||
		back.BinaryOnlyChanges != custom.BinaryOnlyChanges || !back.BuildDate.Equal(custom.BuildDate) {
		t.Fatalf("round trip\n%s\n%+v", out, back)
	}

	for name, doc := range map[string]string{
		"no format":     "Source: foo\nVersion: 1\n",
		"bad depends":   "Format: 1.0\nSource: foo\nVersion: 1\nInstalled-Build-Depends:\n foo (>= 1)\n",
		"alternatives":  "Format: 1.0\nSource: foo\nVersion: 1\nInstalled-Build-Depends:\n foo (= 1) | bar (= 1)\n",
		"env unquoted":  "Format: 1.0\nSource: foo\nVersion: 1\nEnvironment:\n LANG=C\n",
		"env no equals": "Format: 1.0\nSource: foo\nVersion: 1\nEnvironment:\n LANG\n",
		"bad date":      "Format: 1.0\nSource: foo\nVersion: 1\nBuild-Date: never\n",
	} {
		if _, err := source.ParseBuildInfo([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	if _, err := (&source.BuildInfo{}).Marshal(); !errors.Is(err, source.ErrInvalid) {
		t.Errorf("empty: %v", err)
	}

	if _, err := (&source.BuildInfo{Format: "1.0", Source: "a", Version: "1", Files: []source.FileRef{{Name: "a b"}}}).Marshal(); err == nil {
		t.Error("space in file name accepted")
	}
}
