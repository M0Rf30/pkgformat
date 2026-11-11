package apk

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// interopSpec is the package written for the interop proofs: every file kind
// the writer supports, the capability xattr, scripts, triggers and the
// dependency fields.
// deviceSpec holds the device nodes: they cannot be extracted without root,
// so tar lists them instead.
func deviceSpec() *Spec {
	return &Spec{
		Info: Info{Name: "devices", Version: "1-r0", Arch: "noarch"},
		Files: []File{
			{Name: "dev/null", Mode: fs.ModeDevice | fs.ModeCharDevice | 0o666, DevMajor: 1, DevMinor: 3},
			{Name: "dev/loop0", Mode: fs.ModeDevice | 0o660, Gname: "disk", DevMajor: 7, DevMinor: 0},
		},
	}
}

func interopSpec() *Spec {
	spec := fullSpec()
	spec.Info = Info{
		Name: "interop", Version: "1.2.3-r4", Arch: "x86_64",
		Description: "Fixture written by the apk writer", URL: "https://example.org/interop",
		Licenses: []string{"MIT", "Apache-2.0"}, Origin: "interop-src", Maintainer: "Test <test@example.org>",
		Commit: "0123456789abcdef0123456789abcdef01234567", BuildDate: time.Unix(1700000000, 0),
		Provides: []string{"cmd:interop=1.2.3-r4"}, Replaces: []string{"old-interop"},
		ReplacesPriority: 3, ProviderPriority: 7, InstallIf: []string{"busybox", "docs"},
		Triggers: []string{"/usr/share/interop/*"},
	}
	spec.Scripts = Scripts{PostInstall: "#!/bin/sh\nexit 0\n", Trigger: "#!/bin/sh\nexit 0\n"}
	spec.Files = slices.DeleteFunc(spec.Files, func(f File) bool { return f.Name == "dev/null" })
	spec.Files = append(spec.Files, MemFile("usr/bin/suid", 0o755|fs.ModeSetuid, []byte("suid\n")))

	return spec
}

// TestInterop_fixtures checks the committed packages in testdata/extract that
// the writer produced: they must read back as the spec. With
// PKGFORMAT_UPDATE=1 it rewrites them (run testdata/extract/generate.sh, which
// does it, then asks apk for the listings).
func TestInterop_fixtures(t *testing.T) {
	dir := filepath.Join("testdata", "extract")

	if os.Getenv("PKGFORMAT_UPDATE") != "" {
		key, err := GenerateKey(2048)
		if err != nil {
			t.Fatal(err)
		}

		signer, err := NewSigner("pkgformat-test.rsa.pub", opaqueSigner{key}, SigRSASHA256)
		if err != nil {
			t.Fatal(err)
		}

		for name, w := range map[string]struct {
			spec *Spec
			opts WriteOptions
		}{
			"interop-1.2.3-r4.apk": {interopSpec(), WriteOptions{}},
			"signed-1.2.3-r4.apk":  {interopSpec(), WriteOptions{Signer: signer}},
			"devices-1-r0.apk":     {deviceSpec(), WriteOptions{}},
		} {
			var buf bytes.Buffer
			if _, err := WritePackage(&buf, w.spec, w.opts); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(dir, "keys", "pkgformat-test.rsa.pub"), MarshalPublicKeyPEM(&key.PublicKey), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	raw, err := os.ReadFile(filepath.Join(dir, "interop-1.2.3-r4.apk"))
	if err != nil {
		t.Fatal(err)
	}

	a := openArchiveBytes(t, raw)
	pkg := a.Package()

	if pkg.Name != "interop" || pkg.ReplacesPriority != 3 || pkg.ProviderPriority != 7 ||
		strings.Join(pkg.Triggers, " ") != "/usr/share/interop/*" || pkg.License != "MIT AND Apache-2.0" && pkg.License != "MIT Apache-2.0" {
		t.Fatalf("%+v", pkg)
	}

	if a.Scripts().Trigger == "" || a.Scripts().PostInstall == "" {
		t.Fatalf("scripts %+v", a.Scripts())
	}
}

// TestInterop_hostApk has the apk binary of the host verify, extract and
// index the written packages; it is skipped without apk.
func TestInterop_hostApk(t *testing.T) {
	apkBin, err := exec.LookPath("apk")
	if err != nil {
		t.Skip("apk not installed")
	}

	dir := filepath.Join("testdata", "extract")
	keys, _ := filepath.Abs(filepath.Join(dir, "keys"))

	run := func(args ...string) string {
		t.Helper()

		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()

		out, err := exec.CommandContext(ctx, apkBin, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("apk %v: %v\n%s", args, err, out)
		}

		return string(out)
	}

	signed, _ := filepath.Abs(filepath.Join(dir, "signed-1.2.3-r4.apk"))
	plain, _ := filepath.Abs(filepath.Join(dir, "interop-1.2.3-r4.apk"))

	if out := run("--keys-dir", keys, "--no-network", "verify", signed); !strings.Contains(out, "OK") && !strings.Contains(out, "signed") {
		t.Fatalf("verify: %s", out)
	}

	// An unsigned package is refused without --allow-untrusted.
	if err := exec.CommandContext(t.Context(), apkBin, "--keys-dir", keys, "--no-network", "verify", plain).Run(); err == nil {
		t.Fatal("apk verified an unsigned package")
	}

	idx := filepath.Join(t.TempDir(), "APKINDEX.tar.gz")
	run("index", "--allow-untrusted", "--no-warnings", "-o", idx, plain)

	f, err := os.Open(idx)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	pkgs, err := ParseIndex(f)
	if err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(plain)
	want := openArchiveBytes(t, raw).Package()

	if len(pkgs) != 1 || pkgs[0].Checksum != want.Checksum || pkgs[0].Name != "interop" ||
		pkgs[0].Version != want.Version {
		t.Fatalf("apk index: %+v, writer: %+v", pkgs, want)
	}
}

// TestInterop_devices compares the device entries of the written package with
// the listing GNU tar made of it.
func TestInterop_devices(t *testing.T) {
	dir := filepath.Join("testdata", "extract")

	list, err := os.ReadFile(filepath.Join(dir, "listings", "devices-1-r0.tarlist"))
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "devices-1-r0.apk"))
	if err != nil {
		t.Fatal(err)
	}

	entries, err := openArchiveBytes(t, raw).Files()
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{}

	for _, line := range strings.Split(string(list), "\n") {
		f := strings.Fields(line)
		if len(f) >= 6 && (f[0][0] == 'c' || f[0][0] == 'b') {
			want[f[len(f)-1]] = f[0][:1] + " " + f[2]
		}
	}

	if len(want) != 2 {
		t.Fatalf("tar listing: %q", list)
	}

	for _, e := range entries {
		var got string

		switch e.Type {
		case TypeCharDevice:
			got = "c " + strconv.FormatInt(e.DevMajor, 10) + "," + strconv.FormatInt(e.DevMinor, 10)
		case TypeBlockDevice:
			got = "b " + strconv.FormatInt(e.DevMajor, 10) + "," + strconv.FormatInt(e.DevMinor, 10)
		default:
			continue
		}

		if want[e.Name] != got {
			t.Errorf("%s: %s, tar %s", e.Name, got, want[e.Name])
		}

		delete(want, e.Name)
	}

	if len(want) != 0 {
		t.Errorf("tar lists entries Files does not: %v", want)
	}
}
