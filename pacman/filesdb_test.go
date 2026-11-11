package pacman

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// dbMembers returns the "name-version/member" bodies of a database tarball.
func dbMembers(t *testing.T, r io.Reader) map[string]string {
	t.Helper()

	dec, _, closeDec, err := openCompressed(r)
	if err != nil {
		t.Fatal(err)
	}

	defer closeDec()

	out := map[string]string{}
	tr := tar.NewReader(dec)

	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}

		if err != nil {
			t.Fatal(err)
		}

		if h.Typeflag != tar.TypeReg {
			continue
		}

		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}

		out[h.Name] = string(body)
	}
}

// signPackage detach-signs the file with a throw-away key and returns the
// signature file.
func signPackage(t *testing.T, pkgPath string) string {
	t.Helper()

	gpgBin := pacmanTool(t, "gpg")

	home, err := os.MkdirTemp("", "gnupg")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(home) })

	run := func(args ...string) {
		t.Helper()

		cmd := exec.Command(gpgBin, append([]string{"--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("gpg %v: %v\n%s", args, err, out)
		}
	}

	run("--quick-generate-key", "pkgformat test <test@example.org>", "ed25519", "sign", "never")
	run("--detach-sign", "--output", pkgPath+".sig", pkgPath)

	return pkgPath + ".sig"
}

// TestFilesDatabaseMatchesRepoAdd: the files database this module writes has
// the same desc and files members as the one repo-add writes for the same
// signed package, and reads back to the same entries.
func TestFilesDatabaseMatchesRepoAdd(t *testing.T) {
	repoAdd := pacmanTool(t, "repo-add")

	dir := t.TempDir()
	s := specialSpec()
	s.Files = s.Files[:len(s.Files)-1] // no device nodes in what repo-add lists
	s.Files = append(s.Files, File{Path: "usr/share/doc/with space/README", Mode: 0o644, Data: []byte("r")})

	pkgPath := filepath.Join(dir, s.FileName(CompressionZstd))
	if err := s.WriteFile(pkgPath, WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	sigPath := signPackage(t, pkgPath)

	// repo-add writes the files database next to the sync database.
	files := filepath.Join(dir, "repo.files.tar.gz")

	if out, err := exec.Command(repoAdd, "--include-sigs", filepath.Join(dir, "repo.db.tar.gz"), pkgPath).CombinedOutput(); err != nil {
		t.Fatalf("repo-add: %v\n%s", err, out)
	}

	pkg, err := os.Open(pkgPath)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = pkg.Close() }()

	sig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}

	entry, err := NewDBEntry(filepath.Base(pkgPath), pkg, sig)
	if err != nil {
		t.Fatal(err)
	}

	var written bytes.Buffer
	if err := WriteDB(&written, []DBEntry{*entry}, true); err != nil {
		t.Fatal(err)
	}

	ours := written.Bytes()

	theirs, err := os.Open(files)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = theirs.Close() }()

	want := dbMembers(t, theirs)
	got := dbMembers(t, bytes.NewReader(ours))

	// repo-add 7.1 no longer writes %MD5SUM%, which older pacman versions
	// read; the writer keeps it.
	for name, body := range got {
		got[name] = strings.Replace(body, "%MD5SUM%\n"+entry.MD5+"\n\n", "", 1)
	}

	for name, body := range want {
		if got[name] != body {
			t.Errorf("%s\n ours:\n%s\n repo-add:\n%s", name, got[name], body)
		}
	}

	if len(got) != len(want) {
		t.Errorf("members: ours %d, repo-add %d", len(got), len(want))
	}

	if !strings.Contains(want[entry.DirName()+"/desc"], "%PGPSIG%\n") {
		t.Errorf("repo-add left the signature out:\n%s", want[entry.DirName()+"/desc"])
	}

	// Reading the one repo-add wrote gives back what NewDBEntry computed.
	if _, err := theirs.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	read, err := ReadDB(theirs)
	if err != nil || len(read) != 1 {
		t.Fatalf("ReadDB: %v %v", read, err)
	}

	r := read[0]
	if r.PGPSig != entry.PGPSig || r.SHA256 != entry.SHA256 || strings.Join(r.Files, "\n") != strings.Join(entry.Files, "\n") ||
		!strings.Contains(strings.Join(r.Files, "\n"), "usr/bin/aaa-link\n") && len(r.Files) < 5 {
		t.Errorf("read %+v\n want %+v", r, entry)
	}

	lists, err := ReadFileLists(bytes.NewReader(ours), func(string) bool { return true })
	if err != nil || strings.Join(lists[entry.DirName()], "\n") != strings.Join(r.Files, "\n") {
		t.Errorf("ReadFileLists: %v %v", lists, err)
	}
}

// TestFilesDatabaseReadByPacman: pacman -Fy fetches the files database this
// module wrote from a file:// server, and -Fl and -F answer from it.
func TestFilesDatabaseReadByPacman(t *testing.T) {
	pacman := pacmanTool(t, "pacman")
	unshare := pacmanTool(t, "unshare")

	if err := exec.Command(unshare, "-rm", "true").Run(); err != nil {
		t.Skipf("no user namespaces: %v", err)
	}

	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	root := filepath.Join(base, "root")

	for _, d := range []string{repo, filepath.Join(root, "db", "sync"), filepath.Join(root, "cache"), filepath.Join(root, "gnupg")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	var entries []DBEntry

	for _, s := range []*Spec{sampleSpec(), shapesSpec()} {
		pkgPath := filepath.Join(repo, s.FileName(CompressionZstd))
		if err := s.WriteFile(pkgPath, WriteOptions{}); err != nil {
			t.Fatal(err)
		}

		f, err := os.Open(pkgPath)
		if err != nil {
			t.Fatal(err)
		}

		e, err := NewDBEntry(filepath.Base(pkgPath), f, nil)
		_ = f.Close()

		if err != nil {
			t.Fatal(err)
		}

		entries = append(entries, *e)
	}

	// The same bytes serve as the sync database and the files database, as
	// repo-add's two outputs are both tarballs with the files members.
	var db bytes.Buffer
	if err := WriteDB(&db, entries, true); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"test.db", "test.files"} {
		if err := os.WriteFile(filepath.Join(repo, name), db.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	conf := filepath.Join(base, "pacman.conf")
	text := "[options]\nArchitecture = x86_64\nSigLevel = Never\n\n[test]\nServer = file://" + repo + "\n"

	if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) string {
		t.Helper()

		full := append([]string{
			"--root", root, "--dbpath", filepath.Join(root, "db"), "--cachedir", filepath.Join(root, "cache"),
			"--gpgdir", filepath.Join(root, "gnupg"), "--config", conf,
		}, args...)

		// pacman -F needs to be root: be root of a user namespace.
		cmd := exec.Command(unshare, append([]string{"-rm", pacman}, full...)...)
		cmd.Env = append(os.Environ(), "LC_ALL=C")

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("pacman %v: %v\n%s", args, err, out)
		}

		return string(out)
	}

	run("-Fy")

	if _, err := os.Stat(filepath.Join(root, "db", "sync", "test.files")); err != nil {
		t.Fatalf("no files database was downloaded: %v", err)
	}

	list := run("-Fl", "hello")
	for _, want := range []string{"hello usr/bin/hello\n", "hello usr/share/doc/hello with space/README\n"} {
		if !strings.Contains(list, want) {
			t.Errorf("pacman -Fl hello lacks %q:\n%s", want, list)
		}
	}

	if owner := run("-F", "usr/bin/tool-sym"); !strings.Contains(owner, "usr/bin/tool-sym is owned by test/shapes 1.0-1") {
		t.Errorf("pacman -F:\n%s", owner)
	}

	if owner := run("-Fq", "/etc/shapes.conf"); strings.TrimSpace(owner) != "test/shapes" {
		t.Errorf("pacman -Fq:\n%s", owner)
	}

	// What pacman keeps as the files database reads back to the lists written.
	f, err := os.Open(filepath.Join(root, "db", "sync", "test.files"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	lists, err := ReadFileLists(f, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	for _, e := range entries {
		if strings.Join(lists[e.DirName()], "\n") != strings.Join(e.Files, "\n") {
			t.Errorf("%s: %v, want %v", e.Name, lists[e.DirName()], e.Files)
		}
	}

	if _, err := ReadFileLists(strings.NewReader("junk"), nil); !errors.Is(err, ErrNotDatabase) {
		t.Errorf("junk: %v", err)
	}
}

// TestFilesDatabaseFixture reads the files database repo-add wrote for the
// makepkg package of testdata/makepkg (see testdata/filesdb/generate.sh) and
// writes the same one.
func TestFilesDatabaseFixture(t *testing.T) {
	t.Parallel()

	pkgRaw, err := os.ReadFile(makepkgFixture)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := os.ReadFile("testdata/filesdb/package.sig")
	if err != nil {
		t.Fatal(err)
	}

	entry, err := NewDBEntry(filepath.Base(makepkgFixture), bytes.NewReader(pkgRaw), sig)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"repo.files.tar.gz", "repo.db.tar.gz"} {
		raw, err := os.ReadFile(filepath.Join("testdata/filesdb", name))
		if err != nil {
			t.Fatal(err)
		}

		read, err := ReadDB(bytes.NewReader(raw))
		if err != nil || len(read) != 1 {
			t.Fatalf("%s: %v %v", name, read, err)
		}

		got := read[0]
		if got.Name != entry.Name || got.Version != entry.Version || got.SHA256 != entry.SHA256 || got.CSize != entry.CSize ||
			got.PGPSig != entry.PGPSig || got.ISize != entry.ISize || got.BuildDate != entry.BuildDate {
			t.Errorf("%s: read %+v\n want %+v", name, got, entry)
		}

		if name != "repo.files.tar.gz" {
			if len(got.Files) != 0 {
				t.Errorf("the sync database lists files: %v", got.Files)
			}

			continue
		}

		if strings.Join(got.Files, "\n") != strings.Join(entry.Files, "\n") || len(got.Files) != 14 {
			t.Errorf("files %q\n want %q", got.Files, entry.Files)
		}

		// Writing the entry again gives repo-add's members, but for %MD5SUM%.
		var written bytes.Buffer
		if err := WriteDB(&written, []DBEntry{*entry}, true); err != nil {
			t.Fatal(err)
		}

		want := dbMembers(t, bytes.NewReader(raw))

		for member, body := range dbMembers(t, &written) {
			body = strings.Replace(body, "%MD5SUM%\n"+entry.MD5+"\n\n", "", 1)
			if want[member] != body {
				t.Errorf("%s\n ours:\n%s\n repo-add:\n%s", member, body, want[member])
			}
		}

		// ReadFileLists keeps only what is asked for.
		lists, err := ReadFileLists(bytes.NewReader(raw), func(dir string) bool { return dir == "nothing-1.0-1" })
		if err != nil || len(lists) != 0 {
			t.Errorf("ReadFileLists: %v %v", lists, err)
		}
	}

	// pacman -Fl lists exactly the files of the database.
	fl, err := os.ReadFile("testdata/filesdb/Fl.expected")
	if err != nil {
		t.Fatal(err)
	}

	var listed []string
	for l := range strings.SplitSeq(strings.TrimSpace(string(fl)), "\n") {
		listed = append(listed, strings.TrimPrefix(l, "tree-shapes "))
	}

	if strings.Join(listed, "\n") != strings.Join(entry.Files, "\n") {
		t.Errorf("pacman -Fl lists %q, the entry has %q", listed, entry.Files)
	}
}
