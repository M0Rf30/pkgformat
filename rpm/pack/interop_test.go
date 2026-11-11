package pack

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/M0Rf30/pkgformat/rpm/tag"
)

const interopDir = "testdata/interop"

func writePackage(t testing.TB, r *RPM) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func newScripted(t testing.TB, name string, files ...RPMFile) *RPM {
	t.Helper()
	r, err := NewRPM(RPMMetaData{Name: name, Version: "1", Release: "1", Arch: "noarch", Licence: "MIT",
		Summary: "interop", Description: name, BuildTime: time.Unix(1700000000, 0), ClampTime: time.Unix(1700000000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		r.AddFile(f)
	}
	return r
}

func logScript(name string) Scriptlet {
	return Scriptlet{Script: "echo " + name + " >> /tmp/order.log"}
}

// newTrig mirrors testdata/interop/trig.spec.
func newTrig(t testing.TB) *RPM {
	rel := func(s string) Relations {
		r, err := NewRelation(s)
		if err != nil {
			t.Fatal(err)
		}
		return Relations{r}
	}
	r := newScripted(t, "trig",
		RPMFile{Name: "/opt/trig", Mode: 040755},
		RPMFile{Name: "/opt/trig/f", Mode: 0644, Body: []byte("t\n")})
	r.AddScriptlet(ScriptPretrans, Scriptlet{Script: "local f = io.open(\"/tmp/order.log\", \"a\"); f:write(\"pretrans\\n\"); f:close()", Interpreter: []string{LuaInterpreter}})
	r.AddScriptlet(ScriptPrein, logScript("pre"))
	r.AddScriptlet(ScriptPostin, logScript("post"))
	r.AddScriptlet(ScriptPreun, logScript("preun"))
	r.AddScriptlet(ScriptPostun, logScript("postun"))
	r.AddScriptlet(ScriptPosttrans, logScript("posttrans"))
	r.AddScriptlet(ScriptPreuntrans, logScript("preuntrans"))
	r.AddScriptlet(ScriptPostuntrans, logScript("postuntrans"))
	for kind, name := range map[TriggerKind]string{TriggerPrein: "triggerprein", TriggerIn: "triggerin", TriggerUn: "triggerun", TriggerPostun: "triggerpostun"} {
		r.AddTrigger(Trigger{Kind: kind, Conditions: rel("bar"), Script: logScript(name)})
	}
	ft := func(kind FileTriggerKind, trans bool, prio int32, name string) {
		r.AddFileTrigger(FileTrigger{Kind: kind, Transaction: trans, Priority: prio, Prefixes: []string{"/opt/bar"}, Script: logScript(name)})
	}
	ft(FileTriggerIn, false, 100, "filetriggerin-100")
	ft(FileTriggerIn, false, 5, "filetriggerin-5")
	ft(FileTriggerUn, false, 0, "filetriggerun")
	ft(FileTriggerPostun, false, 0, "filetriggerpostun")
	ft(FileTriggerIn, true, 0, "transfiletriggerin")
	ft(FileTriggerUn, true, 0, "transfiletriggerun")
	ft(FileTriggerPostun, true, 0, "transfiletriggerpostun")
	return r
}

// newBar mirrors testdata/interop/bar.spec.
func newBar(t testing.TB) *RPM {
	return newScripted(t, "bar",
		RPMFile{Name: "/opt/bar", Mode: 040755},
		RPMFile{Name: "/opt/bar/x", Mode: 0644, Body: []byte("b\n")})
}

func loadSigningKeys(t testing.TB) FileSigning {
	t.Helper()
	read := func(name string) *pem.Block {
		b, err := os.ReadFile(filepath.Join(interopDir, name))
		if err != nil {
			t.Fatal(err)
		}
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				t.Fatalf("no PEM block in %s", name)
			}
			if blk.Type != "EXPECTED" {
				return blk
			}
		}
	}
	k, err := x509.ParsePKCS8PrivateKey(read("sign-key.pem").Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(read("sign-cert.pem").Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := k.(*rsa.PrivateKey)
	return FileSigning{IMAKey: key, VerityKey: key, VerityCert: cert}
}

// newSignBase is the unsigned package that signbase-signed.rpm was signed from.
func newSignBase(t testing.TB) *RPM {
	r := newScripted(t, "signbase",
		RPMFile{Name: "/opt/sb", Mode: 040755},
		RPMFile{Name: "/opt/sb/abc", Mode: 0644, Body: []byte("abc\n")},
		RPMFile{Name: "/opt/sb/big", Mode: 0755, Body: bytes.Repeat([]byte("x"), 10000)},
		RPMFile{Name: "/opt/sb/empty", Mode: 0644},
		RPMFile{Name: "/opt/sb/link", Mode: 0120777, Body: []byte("abc")},
		RPMFile{Name: "/opt/sb/ghost", Type: GhostFile})
	r.Format = FormatV6
	return r
}

// TestInteropEmit writes the packages the container side of generate.sh needs.
func TestInteropEmit(t *testing.T) {
	dir := os.Getenv("PKGFORMAT_EMIT")
	if dir == "" {
		t.Skip("PKGFORMAT_EMIT not set")
	}
	for name, r := range map[string]*RPM{"trig.rpm": newTrig(t), "bar.rpm": newBar(t), "signbase.rpm": newSignBase(t)} {
		if err := os.WriteFile(filepath.Join(dir, name), writePackage(t, r), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(interopDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// notCompared are the main header tags that depend on the build host, on the
// file system of the build root, or that rpmbuild derives by looking at the
// content (see testdata/interop/README.md).
var notCompared = map[int]string{
	62:                     "region trailer holds the size of the data",
	63:                     "region trailer holds the size of the data",
	tag.BUILDHOST:          "build host",
	tag.RPMVERSION:         "rpmbuild version",
	tag.OPTFLAGS:           "rpmbuild default",
	tag.PLATFORM:           "rpmbuild default",
	tag.FILECLASS:          "libmagic output",
	tag.CLASSDICT:          "libmagic output",
	tag.FILEINODES:         "inode numbers of the build root",
	tag.SIZE:               "rpmbuild subtracts files listed twice",
	tag.LONGSIZE:           "rpmbuild subtracts files listed twice",
	tag.PREIN:              "rpmbuild expands %{name} in the script",
	tag.PAYLOADDIGEST:      "payload bytes",
	tag.PAYLOADSHA256ALT:   "payload bytes",
	tag.PAYLOADSIZE:        "payload bytes",
	tag.PAYLOADSIZEALT:     "payload bytes",
	tag.PAYLOADSHA512:      "payload bytes",
	tag.PAYLOADSHA512ALT:   "payload bytes",
	tag.PAYLOADSHA3_256:    "payload bytes",
	tag.PAYLOADSHA3_256ALT: "payload bytes",
	tag.ARCHIVESIZE:        "payload bytes",
}

func TestInteropMainHeaderMatchesRpmbuild(t *testing.T) {
	for _, tc := range []struct {
		format int
		ref    string
	}{{FormatV4, "ref-feat-v4.rpm"}, {FormatV6, "ref-feat-v6.rpm"}} {
		t.Run(tc.ref, func(t *testing.T) {
			ref := parseRPM(t, readFixture(t, tc.ref))
			got := parseRPM(t, writePackage(t, newFeat(t, tc.format)))
			for id, want := range ref.main.entries {
				if _, skip := notCompared[id]; skip {
					continue
				}
				g, ok := got.main.entries[id]
				if !ok {
					t.Errorf("tag %d missing, rpmbuild writes %d x type %d", id, want.count, want.typ)
					continue
				}
				if g.typ != want.typ || g.count != want.count || !bytes.Equal(g.data, want.data) {
					t.Errorf("tag %d differs:\n got  type %d x%d %q\n want type %d x%d %q", id, g.typ, g.count, g.data, want.typ, want.count, want.data)
				}
			}
			for id := range got.main.entries {
				if _, ok := ref.main.entries[id]; !ok {
					if _, skip := notCompared[id]; !skip {
						t.Errorf("tag %d written but rpmbuild does not write it", id)
					}
				}
			}
		})
	}
}

func needTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not installed", name)
	}
	return p
}

func runTool(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(needTool(t, name), args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

var lsTime = regexp.MustCompile(`\s+\d+\s+\w{3}\s+\d+\s+\d{4}\s`)

func TestInteropRpmQueries(t *testing.T) {
	needTool(t, "rpm")
	dir := t.TempDir()
	for _, format := range []int{FormatV4, FormatV6} {
		ours := filepath.Join(dir, "ours.rpm")
		if err := os.WriteFile(ours, writePackage(t, newFeat(t, format)), 0o644); err != nil {
			t.Fatal(err)
		}
		ref := filepath.Join(interopDir, map[int]string{FormatV4: "ref-feat-v4.rpm", FormatV6: "ref-feat-v6.rpm"}[format])
		for _, q := range [][]string{
			{"-qp", "--qf", "%{NVRA} %{EPOCH} %{SUMMARY} %{VENDOR} %{PACKAGER} %{URL} %{LICENSE} %{GROUP}\n"},
			{"-qp", "--requires"}, {"-qp", "--provides"}, {"-qp", "--recommends"}, {"-qp", "--suggests"},
			{"-qp", "--supplements"}, {"-qp", "--enhances"}, {"-qp", "--conflicts"}, {"-qp", "--obsoletes"},
			{"-qp", "--scripts", "--triggers", "--filetriggers"},
			{"-qp", "--changelog"},
			{"-qp", "--qf", "[%{FILENAMES} %{FILEMODES:perms} %{FILEUSERNAME} %{FILEGROUPNAME} %{FILEFLAGS:fflags} %{FILELANGS} %{FILEVERIFYFLAGS:vflags} %{FILECAPS} %{FILEDIGESTS}\n]"},
		} {
			args := func(f string) []string { return append(append([]string{}, q...), f) }
			// the scripts differ in the one script rpmbuild macro-expands
			norm := func(s string) string { return strings.ReplaceAll(s, "echo pre feat", "echo pre %{name}") }
			want := norm(runTool(t, "rpm", args(ref)...))
			got := norm(runTool(t, "rpm", args(ours)...))
			if got != want {
				t.Errorf("v%d rpm %v:\n got  %q\n want %q", format, q, got, want)
			}
		}
		// the listing, but for the sizes of directories and the inode counts
		list := func(f string) string { return lsTime.ReplaceAllString(runTool(t, "rpm", "-qplv", f), " ") }
		if g, w := list(ours), list(ref); g != w {
			t.Errorf("v%d -qplv:\n got\n%s\n want\n%s", format, g, w)
		}
		// the package is not signed, so rpm exits with 1 after verifying the digests
		outb, _ := exec.Command("rpm", "-Kv", ours).CombinedOutput()
		out := string(outb)
		if !strings.Contains(out, "Header SHA256 digest: OK") || !strings.Contains(out, "Payload SHA256 digest: OK") || strings.Contains(out, "BAD") {
			t.Errorf("v%d rpm -Kv:\n%s", format, out)
		}
	}
}

func TestInteropFileSignaturesMatchRpmsign(t *testing.T) {
	r := newSignBase(t)
	r.SetFileSigning(loadSigningKeys(t))
	raw := writePackage(t, r)
	verifyFileSignatures(t, raw)
	got := parseRPM(t, raw)
	ref := parseRPM(t, readFixture(t, "signbase-signed.rpm"))
	for _, id := range []int{sigFileSignatures, sigFileSignatureLength, tag.SIG_VERITYSIGNATURES, tag.SIG_VERITYSIGNATUREALGO} {
		w, ok := ref.sig.entries[id]
		if !ok {
			t.Fatalf("rpmsign wrote no tag %d", id)
		}
		g, ok := got.sig.entries[id]
		if !ok {
			t.Fatalf("tag %d missing", id)
		}
		if g.typ != w.typ || g.count != w.count || !bytes.Equal(g.data, w.data) {
			t.Errorf("signature tag %d differs from rpmsign:\n got  %q\n want %q", id, g.data, w.data)
		}
	}
}

// containerImage names an image with rpm in which the scriptlets of a package may
// run, see testdata/interop/generate.sh.
func containerImage(t *testing.T) string {
	t.Helper()
	img := os.Getenv("PKGFORMAT_RPM_IMAGE")
	if img == "" {
		t.Skip("PKGFORMAT_RPM_IMAGE not set")
	}
	needTool(t, "podman")
	return img
}

func TestInteropTriggerOrder(t *testing.T) {
	img := containerImage(t)
	dir := t.TempDir()
	for name, r := range map[string]*RPM{"trig.rpm": newTrig(t), "bar.rpm": newBar(t)} {
		if err := os.WriteFile(filepath.Join(dir, name), writePackage(t, r), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	abs, _ := filepath.Abs(interopDir)
	out := runTool(t, "podman", "run", "--rm", "-v", dir+":/work:Z", "-v", abs+":/here:Z", "-w", "/work", img, "sh", "/here/scenario.sh", "trig.rpm", "bar.rpm")
	if want := string(readFixture(t, "trigger-order.txt")); out != want {
		t.Errorf("execution order differs from rpmbuild's package:\n got\n%s\n want\n%s", out, want)
	}
}

func TestInteropFileSignaturesQuery(t *testing.T) {
	needTool(t, "rpm")
	r := newSignBase(t)
	r.SetFileSigning(loadSigningKeys(t))
	p := filepath.Join(t.TempDir(), "signed.rpm")
	if err := os.WriteFile(p, writePackage(t, r), 0o644); err != nil {
		t.Fatal(err)
	}
	const qf = "[%{FILENAMES} %{FILESIGNATURES}\n]"
	got := runTool(t, "rpm", "-qp", "--qf", qf, p)
	want := runTool(t, "rpm", "-qp", "--qf", qf, filepath.Join(interopDir, "signbase-signed.rpm"))
	// the reference also carries an OpenPGP signature rpm has no key for
	want = want[strings.Index(want, "/opt/sb"):]
	if got != want || !strings.Contains(got, "0302") {
		t.Errorf("file signatures:\n got\n%s\n want\n%s", got, want)
	}
	out, _ := exec.Command("rpm", "-Kv", p).CombinedOutput()
	if !strings.Contains(string(out), "Header SHA256 digest: OK") {
		t.Errorf("rpm -Kv:\n%s", out)
	}
}

func TestInteropInstall(t *testing.T) {
	img := containerImage(t)
	dir := t.TempDir()
	for _, f := range []int{FormatV4, FormatV6} {
		name := map[int]string{FormatV4: "v4.rpm", FormatV6: "v6.rpm"}[f]
		if err := os.WriteFile(filepath.Join(dir, name), writePackage(t, newFeat(t, f)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	script := `set -e
groupadd g1; useradd -g g1 u1
for p in v4 v6; do
  rpm -i --nodeps --nosignature --noscripts --notriggers $p.rpm
  a=$(stat -c %i /opt/feat/bin/hello); b=$(stat -c %i /opt/feat/bin/hello2)
  [ "$a" = "$b" ] || { echo "$p: hello and hello2 are different files"; exit 1; }
  [ "$(stat -c %h /opt/feat/bin/hello)" = 2 ] || { echo "$p: link count"; exit 1; }
  [ "$(cat /opt/feat/bin/hello2)" = hello ] || { echo "$p: content"; exit 1; }
  [ "$(stat -c '%U:%G %a' /opt/feat/bin/hello)" = "u1:g1 755" ] || { stat /opt/feat/bin/hello; exit 1; }
  [ -p /opt/feat/fifo ] || { echo "$p: no fifo"; exit 1; }
  [ ! -e /opt/feat/ghost ] || { echo "$p: ghost installed"; exit 1; }
  rpm -V --nodeps --nocaps feat || { echo "$p: verify failed"; exit 1; }
  rpm -e --noscripts --notriggers feat
done
echo installed`
	out := runTool(t, "podman", "run", "--rm", "-v", dir+":/work:Z", "-w", "/work", img, "sh", "-c", script)
	if !strings.HasSuffix(strings.TrimSpace(out), "installed") {
		t.Errorf("install:\n%s", out)
	}
}
