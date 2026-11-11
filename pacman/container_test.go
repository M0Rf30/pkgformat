package pacman

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The container tests install a package this module wrote with the pacman of
// an Arch Linux container, which runs as root with a user namespace of its own,
// so that owners, hard links, pipes, xattrs and file capabilities all take
// effect. They need podman and the image (docker.io/library/archlinux:latest)
// to be present already; nothing is pulled.
//
// The test binary itself is run inside the container (the second half of the
// proof): it reads the local database pacman wrote and verifies the installed
// files against it, and has to agree with "pacman -Qkk".

const (
	archImage = "docker.io/library/archlinux:latest"
	// containerPkgEnv names the package the inner test looks for. It is set only
	// inside the container.
	containerPkgEnv = "PKGFORMAT_CONTAINER_PKG"
)

// fileCap is the security.capability value of "cap_net_raw=ep": revision 2
// with the effective bit, CAP_NET_RAW (13) permitted.
var fileCap = []byte{0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func shapesSpec() *Spec {
	built := time.Unix(buildTime, 0)

	return &Spec{
		Info: PkgInfo{
			Name: "shapes", Version: "1.0-1", Description: "Every file shape a package can hold", Arch: "any",
			BuildDate: buildTime, Backup: []string{"etc/shapes.conf"},
		},
		Files: []File{
			{Path: "etc/shapes.conf", Mode: 0o644, ModTime: built, Data: []byte("x=1\n")},
			{Path: "usr/bin/tool", Mode: 0o755, ModTime: built, Data: []byte("#!/bin/sh\n")},
			{Path: "usr/bin/tool-hard", Hardlink: "usr/bin/tool", ModTime: built},
			{Path: "usr/bin/tool-sym", Mode: fs.ModeSymlink | 0o777, Linkname: "tool", ModTime: built},
			{Path: "usr/bin/tool-fifo", Mode: fs.ModeNamedPipe | 0o640, ModTime: built},
			{Path: "usr/bin/tool-suid", Mode: fs.ModeSetuid | 0o755, ModTime: built, Data: []byte("s\n")},
			{
				Path: "usr/bin/tool-cap", Mode: 0o755, ModTime: built, Data: []byte("c\n"),
				Xattrs: map[string][]byte{"security.capability": fileCap},
			},
			{Path: "usr/share/shapes/owned", Mode: 0o640, UID: 1234, GID: 5678, ModTime: built, Data: []byte("owned\n")},
			{Path: "usr/share/shapes/chowned", Mode: 0o644, ModTime: built, Data: []byte("chowned\n")},
			{Path: "usr/share/shapes/gone", Mode: 0o644, ModTime: built, Data: []byte("gone\n")},
			{Path: "usr/share/shapes/chmodded", Mode: 0o644, ModTime: built, Data: []byte("chmodded\n")},
			{
				Path: "usr/share/shapes/tagged", Mode: 0o644, ModTime: built, Data: []byte("tagged\n"),
				Xattrs: map[string][]byte{"user.shape": []byte("tagged")},
			},
			{Path: "usr/share/a b/c=d", Mode: 0o644, ModTime: built, Data: []byte("hi\n")},
			{Path: "var/lib/shapes/", Mode: fs.ModeDir | fs.ModeSticky | 0o770, UID: 1234, GID: 5678, ModTime: built},
		},
	}
}

// containerScript runs in the container. The inner test binary is mounted at
// /inner and the package at /pkg.
const containerScript = `
export LC_ALL=C TZ=UTC
pacman -U --noconfirm --noscriptlet -dd /pkg/shapes.pkg.tar.zst >/dev/null 2>&1 || { echo "install failed"; exit 10; }
echo '== qkk clean'
pacman -Qkk shapes 2>&1
for f in desc files mtree; do cp /var/lib/pacman/local/shapes-1.0-1/$f /out/; done
echo '== files'
stat -c '%n %a %u:%g %h %F' /etc/shapes.conf /usr/bin/tool /usr/bin/tool-hard /usr/bin/tool-sym /usr/bin/tool-fifo /usr/bin/tool-suid \
  /usr/share/shapes/owned /var/lib/shapes
getfattr -h -d -m - -e hex /usr/bin/tool-cap /usr/share/shapes/tagged 2>/dev/null
echo '== inner clean'
` + containerPkgEnv + `=shapes /inner -test.run '^TestContainerInstalled$' -test.v 2>&1
echo '== tamper'
echo more >> /usr/bin/tool
chown 1:1 /usr/share/shapes/chowned
rm /usr/share/shapes/gone
chmod 600 /usr/share/shapes/chmodded
echo edited > /etc/shapes.conf
echo '== qkk tampered'
pacman -Qkk shapes 2>&1
echo '== inner tampered'
` + containerPkgEnv + `=shapes /inner -test.run '^TestContainerInstalledTampered$' -test.v 2>&1
`

func podmanOrSkip(t *testing.T) string {
	t.Helper()

	podman := pacmanTool(t, "podman")

	if err := exec.Command(podman, "image", "exists", archImage).Run(); err != nil {
		t.Skipf("%s is not present", archImage)
	}

	return podman
}

func TestPacmanInstallsSpecialFilesInContainer(t *testing.T) {
	podman := podmanOrSkip(t)
	goTool := pacmanTool(t, "go")

	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "pkg")

	if err := os.Mkdir(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := shapesSpec().WriteFile(filepath.Join(pkgDir, "shapes.pkg.tar.zst"), WriteOptions{MtreeMD5: true}); err != nil {
		t.Fatal(err)
	}

	inner := filepath.Join(dir, "inner")

	build := exec.Command(goTool, "test", "-c", "-o", inner, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")

	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go test -c: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	outDir := filepath.Join(dir, "out")
	if err := os.Mkdir(outDir, 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(ctx, podman, "run", "--rm",
		"-v", pkgDir+":/pkg:ro,Z", "-v", inner+":/inner:ro,Z", "-v", outDir+":/out:Z", archImage, "sh", "-c", containerScript)

	raw, err := cmd.CombinedOutput()
	out := string(raw)

	if err != nil {
		t.Fatalf("container: %v\n%s", err, out)
	}

	section := func(name string) string {
		_, rest, _ := strings.Cut(out, "== "+name+"\n")
		body, _, _ := strings.Cut(rest, "\n== ")

		return body
	}

	if q := section("qkk clean"); !strings.Contains(q, " total files, 0 altered files") {
		t.Errorf("pacman -Qkk after the install:\n%s", q)
	}

	files := section("files")

	for _, want := range []string{
		"/usr/bin/tool 755 0:0 2 regular file", "/usr/bin/tool-hard 755 0:0 2 regular file",
		"/usr/bin/tool-sym 777 0:0 1 symbolic link", "/usr/bin/tool-fifo 640 0:0 1 fifo",
		"/usr/bin/tool-suid 4755 0:0 1 regular file", "/usr/share/shapes/owned 640 1234:5678 1 regular file",
		"/var/lib/shapes 1770 1234:5678", "security.capability=0x" + hexOf(fileCap), "user.shape=0x" + hexOf([]byte("tagged")),
	} {
		if !strings.Contains(files, want) {
			t.Errorf("installed state lacks %q:\n%s", want, files)
		}
	}

	for _, name := range []string{"inner clean", "inner tampered"} {
		if body := section(name); !strings.Contains(body, "--- PASS") || strings.Contains(body, "--- FAIL") {
			t.Errorf("%s:\n%s", name, body)
		}
	}

	checkAgreement(t, section("qkk tampered"), section("inner tampered"))

	if os.Getenv(updateEnv) != "" {
		recordContainerFixtures(t, pkgDir, outDir, section)
	}
}

// updateEnv, when set, makes the container test rewrite testdata/container
// from what the container did (see testdata/container/generate.sh).
const updateEnv = "PKGFORMAT_UPDATE_FIXTURES"

func recordContainerFixtures(t *testing.T, pkgDir, outDir string, section func(string) string) {
	t.Helper()

	dest := "testdata/container"
	local := filepath.Join(dest, "local", "shapes-1.0-1")

	if err := os.RemoveAll(filepath.Join(dest, "local")); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}

	copyFile := func(from, to string) {
		raw, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(to, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	copyFile(filepath.Join(pkgDir, "shapes.pkg.tar.zst"), filepath.Join(dest, "shapes-1.0-1-any.pkg.tar.zst"))

	for _, f := range []string{"desc", "files", "mtree"} {
		copyFile(filepath.Join(outDir, f), filepath.Join(local, f))
	}

	for name, sec := range map[string]string{
		"qkk-clean.expected": "qkk clean", "files.expected": "files", "qkk-tampered.expected": "qkk tampered",
	} {
		if err := os.WriteFile(filepath.Join(dest, name), []byte(section(sec)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func hexOf(b []byte) string { return fmt.Sprintf("%x", b) }

var qkkLine = regexp.MustCompile(`(?m)^warning: shapes: (/\S+) \(([^)]+)\)$`)

// checkAgreement compares the paths "pacman -Qkk" reports with those
// VerifyInstalled reported inside the container.
func checkAgreement(t *testing.T, qkk, inner string) {
	t.Helper()

	pacmanPaths := map[string]bool{}
	for _, m := range qkkLine.FindAllStringSubmatch(qkk, -1) {
		pacmanPaths[m[1]] = true
	}

	ourPaths := map[string]bool{}

	for l := range strings.SplitSeq(inner, "\n") {
		if p, ok := strings.CutPrefix(l, "DIFF "); ok {
			ourPaths["/"+strings.Fields(p)[0]] = true
		}
	}

	if len(pacmanPaths) == 0 {
		t.Fatalf("pacman -Qkk reported nothing:\n%s", qkk)
	}

	if !slices.Equal(sortedKeys(pacmanPaths), sortedKeys(ourPaths)) {
		t.Errorf("pacman -Qkk reports %v, VerifyInstalled %v\n%s\n%s", sortedKeys(pacmanPaths), sortedKeys(ourPaths), qkk, inner)
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	slices.Sort(out)

	return out
}

// installedInContainer opens the local database of the container and finds the
// package.
func installedInContainer(t *testing.T) (*LocalDB, *InstalledPackage) {
	t.Helper()

	name := os.Getenv(containerPkgEnv)
	if name == "" {
		t.Skip("runs inside the container only")
	}

	db := NewLocalDB(os.DirFS("/var/lib/pacman/local"), LocalDBOptions{})

	pkgs, err := db.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range pkgs {
		if p.Name == name {
			return db, p
		}
	}

	t.Fatalf("%s is not installed", name)

	return nil, nil
}

// TestContainerInstalled runs inside the container, after the install: the
// installed files agree with the mtree of the local database, owners and all.
func TestContainerInstalled(t *testing.T) {
	db, pkg := installedInContainer(t)

	if err := db.VerifyInstalled(pkg, os.DirFS("/"), VerifyOptions{}); err != nil {
		t.Fatalf("VerifyInstalled: %v", err)
	}

	mt, err := db.Mtree(pkg)
	if err != nil {
		t.Fatal(err)
	}

	owned, ok := mt.Lookup("usr/share/shapes/owned")
	if !ok || owned.UID != 1234 || owned.GID != 5678 {
		t.Errorf("owned: %+v", owned)
	}

	tool, _ := mt.Lookup("usr/bin/tool-hard")
	if tool == nil || tool.Type != MtreeFile || tool.Size != 10 {
		t.Errorf("hard link: %+v", tool)
	}

	if v, err := getXattr("/usr/bin/tool-cap", "security.capability"); err != nil || v != string(fileCap) {
		t.Errorf("security.capability = %x, %v", v, err)
	}
}

// TestContainerInstalledTampered runs inside the container after the files
// were altered and prints what VerifyInstalled reports, to be compared with
// pacman's own report.
func TestContainerInstalledTampered(t *testing.T) {
	db, pkg := installedInContainer(t)

	err := db.VerifyInstalled(pkg, os.DirFS("/"), VerifyOptions{})

	me, ok := err.(*MtreeError) //nolint:errorlint // the concrete error is the point
	if !ok {
		t.Fatalf("VerifyInstalled: %v", err)
	}

	var b bytes.Buffer

	for _, d := range me.Diffs {
		fmt.Fprintf(&b, "DIFF %s %s %s\n", d.Path, d.Kind, d.Keyword)
	}

	fmt.Print(b.String())
}
