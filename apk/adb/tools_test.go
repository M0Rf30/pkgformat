package adb

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests that compare with the real tool run only when apk-tools 3 is on the
// PATH. Files are made owned by root as far as apk can tell, by running the
// tool in a user namespace that maps the user to root; without podman the
// files stay owned by the user, whose name is then recorded.

const fixtureTime = 1600000000

var hostApk = sync.OnceValue(func() string {
	p, err := exec.LookPath("apk")
	if err != nil {
		return ""
	}

	out, err := exec.Command(p, "--version").CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("apk-tools 3")) {
		return ""
	}

	return p
})

var hostUnshare = sync.OnceValue(func() bool {
	p, err := exec.LookPath("podman")
	if err != nil {
		return false
	}

	return exec.Command(p, "unshare", "true").Run() == nil
})

// ownerNames returns the owner the files of a tree are recorded with.
func ownerNames(t testing.TB) (uname, gname string) {
	t.Helper()

	if hostUnshare() {
		return "root", "root"
	}

	u, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}

	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("no current group: %v", err)
	}

	return u.Username, g.Name
}

func needApk(t testing.TB) string {
	t.Helper()

	p := hostApk()
	if p == "" {
		t.Skip("apk-tools 3 is not installed")
	}

	return p
}

// runApk runs apk with the arguments, in the user namespace when there is one,
// and returns its standard output.
func runApk(t testing.TB, args ...string) []byte {
	t.Helper()

	out, err := apkCombined(args...)
	if err != nil {
		t.Fatalf("apk %s: %v", strings.Join(args, " "), err)
	}

	return out
}

func apkCombined(args ...string) ([]byte, error) {
	var cmd *exec.Cmd

	if hostUnshare() {
		cmd = exec.Command("podman", append([]string{"unshare", hostApk()}, args...)...)
	} else {
		cmd = exec.Command(hostApk(), args...)
	}

	// SOURCE_DATE_EPOCH would override the modification times of the files.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "SOURCE_DATE_EPOCH=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return out, nil
}

// tree is a directory tree on disk and the spec of the package that holds it.
type tree struct {
	t     testing.TB
	root  string
	files []File
	user  string
	group string
	seen  map[string]bool
}

func newTree(t testing.TB) *tree {
	t.Helper()

	u, g := ownerNames(t)
	root := filepath.Join(t.TempDir(), "root")

	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}

	return &tree{t: t, root: root, user: u, group: g, seen: map[string]bool{}}
}

func (tr *tree) abs(name string) string { return filepath.Join(tr.root, filepath.FromSlash(name)) }

// parents lists the directories above name that are not in the tree yet.
func (tr *tree) parents(name string) {
	tr.t.Helper()

	if dir := path.Dir(name); dir != "." {
		tr.Dir(dir, 0o755)
	}
}

func (tr *tree) stamp(name string) time.Time {
	tm := time.Unix(fixtureTime, 0)

	if fi, err := os.Lstat(tr.abs(name)); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		// Chtimes would follow the link.
		if out, err := exec.Command("touch", "-h", "-d", fmt.Sprintf("@%d", fixtureTime), tr.abs(name)).CombinedOutput(); err != nil {
			tr.t.Skipf("touch -h: %v: %s", err, out)
		}

		return tm
	}

	if err := os.Chtimes(tr.abs(name), tm, tm); err != nil {
		tr.t.Fatal(err)
	}

	return tm
}

// Dir adds a directory, and the ones above it.
func (tr *tree) Dir(name string, perm fs.FileMode) {
	tr.t.Helper()

	if tr.seen[name] {
		return
	}

	tr.parents(name)

	if err := os.MkdirAll(tr.abs(name), 0o755); err != nil {
		tr.t.Fatal(err)
	}

	if err := os.Chmod(tr.abs(name), perm); err != nil {
		tr.t.Fatal(err)
	}

	tr.seen[name] = true
	tr.files = append(tr.files, File{Name: name, Mode: fs.ModeDir | perm&^(fs.ModeType), Uname: tr.user, Gname: tr.group})
}

// File adds a regular file; mode may carry fs.ModeSetuid and the like.
func (tr *tree) File(name string, mode fs.FileMode, data []byte) {
	tr.t.Helper()
	tr.parents(name)

	if err := os.WriteFile(tr.abs(name), data, 0o600); err != nil {
		tr.t.Fatal(err)
	}

	if err := os.Chmod(tr.abs(name), mode); err != nil {
		tr.t.Fatal(err)
	}

	tm := tr.stamp(name)
	f := MemFile(name, mode, data)
	f.ModTime, f.Uname, f.Gname = tm, tr.user, tr.group
	tr.files = append(tr.files, f)
}

// Symlink adds a symbolic link.
func (tr *tree) Symlink(name, target string) {
	tr.t.Helper()
	tr.parents(name)

	if err := os.Symlink(target, tr.abs(name)); err != nil {
		tr.t.Fatal(err)
	}

	tm := tr.stamp(name)
	tr.files = append(tr.files, File{
		Name: name, Mode: fs.ModeSymlink | 0o777, LinkTarget: target, ModTime: tm, Uname: tr.user, Gname: tr.group,
	})
}

// Hardlink adds a second name for a file added before.
func (tr *tree) Hardlink(name, target string) {
	tr.t.Helper()
	tr.parents(name)

	if err := os.Link(tr.abs(target), tr.abs(name)); err != nil {
		tr.t.Fatal(err)
	}

	for _, f := range tr.files {
		if f.Name == target {
			f.Name, f.HardLink = name, target
			tr.files = append(tr.files, f)

			return
		}
	}

	tr.t.Fatalf("no file %q to link to", target)
}

// Fifo adds a named pipe.
func (tr *tree) Fifo(name string, perm fs.FileMode) {
	tr.t.Helper()
	tr.parents(name)

	if err := mkfifo(tr.abs(name), perm); err != nil {
		tr.t.Skipf("mkfifo: %v", err)
	}

	tm := tr.stamp(name)
	tr.files = append(tr.files, File{
		Name: name, Mode: fs.ModeNamedPipe | perm, ModTime: tm, Uname: tr.user, Gname: tr.group,
	})
}

// Xattr sets an extended attribute on an entry added before.
func (tr *tree) Xattr(name, key string, value []byte) {
	tr.t.Helper()

	if err := setxattr(tr.abs(name), key, value); err != nil {
		tr.t.Skipf("extended attributes are not available: %v", err)
	}

	for i := range tr.files {
		if tr.files[i].Name == name {
			tr.files[i].Xattrs = append(tr.files[i].Xattrs, Xattr{Name: key, Value: value})

			return
		}
	}

	tr.t.Fatalf("no entry %q", name)
}

// shuffled returns the files in a fixed scrambled order, to show that the
// writer sorts.
func (tr *tree) shuffled() []File {
	out := append([]File(nil), tr.files...)

	for i := range out {
		j := (i*7 + 3) % len(out)
		out[i], out[j] = out[j], out[i]
	}

	return out
}

// infoArgs renders info as apk mkpkg --info arguments.
func infoArgs(in *Info) []string {
	var args []string

	add := func(k, v string) {
		if v != "" {
			args = append(args, "--info", k+":"+v)
		}
	}

	num := func(k string, n uint64) {
		if n != 0 {
			add(k, fmt.Sprint(n))
		}
	}

	add("name", in.Name)
	add("version", in.Version)
	add("arch", in.Arch)
	add("description", in.Description)
	add("license", in.License)
	add("origin", in.Origin)
	add("maintainer", in.Maintainer)
	add("url", in.URL)
	add("repo-commit", in.RepoCommit)
	num("build-time", in.BuildTime)
	num("provider-priority", in.ProviderPriority)
	add("depends", strings.Join(in.Depends, " "))
	add("provides", strings.Join(in.Provides, " "))
	add("replaces", strings.Join(in.Replaces, " "))
	add("install-if", strings.Join(in.InstallIf, " "))
	add("recommends", strings.Join(in.Recommends, " "))
	num("layer", in.Layer)
	add("tags", strings.Join(in.Tags, " "))

	return args
}

// mkpkg makes the package of the spec with apk mkpkg, from the files of tr.
func (tr *tree) mkpkg(spec *Spec, extra ...string) []byte {
	tr.t.Helper()

	dir := tr.t.TempDir()
	out := filepath.Join(dir, "ref.apk")
	args := []string{"mkpkg", "--output", out}
	if len(tr.files) > 0 {
		args = append(args, "--files", tr.root)
	}

	args = append(args, infoArgs(&spec.Info)...)

	if spec.ReplacesPriority != 0 {
		args = append(args, "--info", fmt.Sprintf("replaces-priority:%d", spec.ReplacesPriority))
	}

	for _, s := range []struct{ name, body string }{
		{"trigger", spec.Scripts.Trigger}, {"pre-install", spec.Scripts.PreInstall},
		{"post-install", spec.Scripts.PostInstall}, {"pre-deinstall", spec.Scripts.PreDeinstall},
		{"post-deinstall", spec.Scripts.PostDeinstall}, {"pre-upgrade", spec.Scripts.PreUpgrade},
		{"post-upgrade", spec.Scripts.PostUpgrade},
	} {
		if s.body == "" {
			continue
		}

		p := filepath.Join(dir, s.name+".sh")
		if err := os.WriteFile(p, []byte(s.body), 0o600); err != nil {
			tr.t.Fatal(err)
		}

		args = append(args, "--script", s.name+":"+p)
	}

	for _, trg := range spec.Triggers {
		args = append(args, "--trigger", trg)
	}

	runApk(tr.t, append(args, extra...)...)

	b, err := os.ReadFile(out)
	if err != nil {
		tr.t.Fatal(err)
	}

	return b
}

// adbOf returns the ADB block of a package or index file.
func adbOf(t testing.TB, file []byte) []byte {
	t.Helper()

	rd, err := NewReader(bytes.NewReader(file), ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = rd.Close() }()

	return rd.ADB()
}

// dumpOf is what apk adbdump says of a file.
func dumpOf(t testing.TB, file []byte) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), "f.apk")
	if err := os.WriteFile(p, file, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := apkCombined("adbdump", p)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("adbdump: %v", err)
	}

	return string(out)
}
