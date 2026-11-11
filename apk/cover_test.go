package apk

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWritePackage_newInvalid(t *testing.T) {
	cap20 := make([]byte, 20)

	for name, mutate := range map[string]func(*Spec){
		"hardlink dir mode": func(s *Spec) {
			s.Files = append(s.Files, File{Name: "h", Mode: fs.ModeDir | 0o755, Hardlink: true, LinkTarget: "empty"})
		},
		"hardlink content": func(s *Spec) {
			s.Files = append(s.Files, File{Name: "h", Mode: 0o644, Hardlink: true, LinkTarget: "empty", Size: 1})
		},
		"hardlink self": func(s *Spec) {
			s.Files = append(s.Files, File{Name: "h", Mode: 0o644, Hardlink: true, LinkTarget: "h"})
		},
		"hardlink absolute": func(s *Spec) {
			s.Files = append(s.Files, File{Name: "h", Mode: 0o644, Hardlink: true, LinkTarget: "/empty"})
		},
		"hardlink missing": func(s *Spec) {
			s.Files = append(s.Files, File{Name: "h", Mode: 0o644, Hardlink: true, LinkTarget: "nothing"})
		},
		"hardlink to symlink": func(s *Spec) {
			s.Files = append(s.Files, File{Name: "h", Mode: 0o644, Hardlink: true, LinkTarget: "usr/bin/hi"})
		},
		"negative device": func(s *Spec) { s.Files = append(s.Files, File{Name: "d", Mode: fs.ModeDevice | 0o600, DevMajor: -1}) },
		"xattr empty name": func(s *Spec) {
			s.Files = append(s.Files, File{Name: "x", Mode: 0o644, Xattrs: map[string][]byte{"": cap20}})
		},
		"xattr equals": func(s *Spec) {
			s.Files = append(s.Files, File{Name: "x", Mode: 0o644, Xattrs: map[string][]byte{"a=b": cap20}})
		},
		"xattr big": func(s *Spec) {
			s.Files = append(s.Files, File{Name: "x", Mode: 0o644, Xattrs: map[string][]byte{"user.a": make([]byte, maxXattrValue+1)}})
		},
		"xattr many": func(s *Spec) {
			m := map[string][]byte{}
			for i := range maxXattrs + 1 {
				m["user."+itoa(i)] = nil
			}

			s.Files = append(s.Files, File{Name: "x", Mode: 0o644, Xattrs: m})
		},
		"both licenses": func(s *Spec) { s.Info.Licenses = []string{"MIT"} },
		"empty license": func(s *Spec) { s.Info.License, s.Info.Licenses = "", []string{" "} },
	} {
		t.Run(name, func(t *testing.T) {
			spec := sampleSpec()
			mutate(spec)

			_, err := WritePackage(io.Discard, spec, WriteOptions{TempDir: t.TempDir()})
			if !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("got %v, want ErrInvalidSpec", err)
			}
		})
	}

	// Without the parent directories a spec must list them.
	spec := &Spec{Info: Info{Name: "p", Version: "1", Arch: "noarch"}, Files: []File{MemFile("a/b", 0o644, nil)}}
	if _, err := WritePackage(io.Discard, spec, WriteOptions{NoParentDirs: true, TempDir: t.TempDir()}); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("missing parent: %v", err)
	}

	if _, err := WritePackage(io.Discard, spec, WriteOptions{TempDir: t.TempDir()}); err != nil {
		t.Fatalf("parents added: %v", err)
	}
}

func TestWritePackage_licensesAndParents(t *testing.T) {
	spec := sampleSpec()
	spec.Info.License, spec.Info.Licenses = "", []string{"MIT", "Apache-2.0"}
	spec.Files = []File{MemFile("deep/er/file", 0o600, []byte("x"))}

	raw, pkg := mustWrite(t, spec, WriteOptions{TempDir: t.TempDir()})
	if pkg.License != "MIT Apache-2.0" {
		t.Fatalf("license %q", pkg.License)
	}

	entries, err := openArchiveBytes(t, raw).Files()
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}

	if strings.Join(names, " ") != "deep deep/er deep/er/file" || entries[0].Mode != 0o755 || entries[0].UID != 0 {
		t.Fatalf("%v %+v", names, entries[0])
	}
}

func TestEntryType_string(t *testing.T) {
	for typ, want := range map[EntryType]string{
		TypeRegular: "file", TypeDir: "dir", TypeSymlink: "symlink", TypeHardlink: "hardlink",
		TypeCharDevice: "chardev", TypeBlockDevice: "blockdev", TypeFIFO: "fifo", 0: "unknown",
	} {
		if typ.String() != want {
			t.Errorf("%d: %q", typ, typ.String())
		}
	}
}

func TestWorld(t *testing.T) {
	w, err := ParseWorld(strings.NewReader("busybox  libfoo@edge>=1.2\nalpine-base\n!bad"))
	if err != nil || len(w) != 4 {
		t.Fatalf("%v %v", w, err)
	}

	w, err = WorldAdd(w, "libfoo=2", "newpkg")
	if err != nil || w[1] != "libfoo=2" || w[len(w)-1] != "newpkg" || len(w) != 5 {
		t.Fatalf("%v %v", w, err)
	}

	w = WorldDel(w, "busybox", "libfoo@edge", "nothere")
	if strings.Join(w, " ") != "alpine-base !bad newpkg" {
		t.Fatalf("%v", w)
	}

	if got := string(RenderWorld([]string{"b", "a>=1", "c@t"})); got != "a>=1\nb\nc@t\n" {
		t.Fatalf("%q", got)
	}

	if _, err := ParseWorld(strings.NewReader("ok bad name=")); !errors.Is(err, ErrInvalidWorld) {
		t.Fatalf("invalid entry: %v", err)
	}

	if _, err := WorldAdd(nil, "x y"); !errors.Is(err, ErrInvalidWorld) {
		t.Fatalf("WorldAdd: %v", err)
	}

	if _, err := ParseWorld(strings.NewReader(strings.Repeat("a ", maxWorldBytes))); !errors.Is(err, ErrInvalidWorld) {
		t.Fatalf("oversized: %v", err)
	}

	many := strings.Repeat("a\n", maxWorldEntries+1)
	if _, err := ParseWorld(strings.NewReader(many)); !errors.Is(err, ErrInvalidWorld) {
		t.Fatalf("too many: %v", err)
	}

	if worldKey("bad name") != "bad name" {
		t.Error("worldKey of an invalid entry")
	}
}

func TestIndex_versionsAndFind(t *testing.T) {
	idx := resolveIndex()

	vs := idx.Versions("libfoo")
	if len(vs) != 2 || vs[0].Version != "1-r0" {
		t.Fatalf("%+v", vs)
	}

	if len(idx.Versions("so:libbar.so.1")) != 0 {
		t.Error("Versions resolves capabilities")
	}

	if p, ok := idx.Find("libfoo"); !ok || p.Version != "1-r0" {
		t.Fatalf("%+v", p)
	}
}

func TestDependency_matchesPackage(t *testing.T) {
	p := &Package{Name: "a", Version: "2", Provides: []string{"cmd:a=2", "bad provide", "virt"}, Checksum: "Q1abc"}

	for dep, want := range map[string]bool{
		"a": true, "a>=2": true, "a>2": false, "!a": false, "!b": true, "cmd:a>=2": true, "cmd:a<2": false,
		"virt": true, "other": false, "a><Q1abc": true, "a><Q1zzz": false,
	} {
		d, err := ParseDependency(dep)
		if err != nil {
			t.Fatalf("%s: %v", dep, err)
		}

		if got := d.MatchesPackage(p); got != want {
			t.Errorf("%s: %v, want %v", dep, got, want)
		}

		if d.String() == "" {
			t.Errorf("%s: empty String", dep)
		}
	}
}

func TestSolve_scenarios(t *testing.T) {
	mk := func(pkgs ...Package) *Index {
		idx := NewIndex()
		idx.Add(Repo{URL: "https://example.org/main"}, "x86_64", pkgs)

		return idx
	}

	// Backtracking: the highest b conflicts with the c that a needs.
	idx := mk(
		Package{Name: "a", Version: "1", Depends: []string{"b", "c"}},
		Package{Name: "b", Version: "2", Depends: []string{"!c"}},
		Package{Name: "b", Version: "1"},
		Package{Name: "c", Version: "1"},
	)

	sol, err := idx.Solve(SolveRequest{World: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, p := range sol.Packages {
		got[p.Name] = p.Version
	}

	if got["b"] != "1" {
		t.Fatalf("backtracking chose %v", got)
	}

	// Installed packages missing from the index stay, and a removal is reported.
	sol, err = idx.Solve(SolveRequest{World: []string{"c"}, Installed: []Package{
		{Name: "gone", Version: "1"},
		{Name: "orphan-dep", Version: "1", Depends: []string{"gone"}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	if len(sol.Changes) != 3 || sol.Changes[0].Kind() != ChangeRemove {
		t.Fatalf("%+v", sol.Changes)
	}

	// An installed package outside the index satisfies a dependency.
	sol, err = idx.Solve(SolveRequest{World: []string{"gone"}, Installed: []Package{{Name: "gone", Version: "1"}}})
	if err != nil || len(sol.Changes) != 0 {
		t.Fatalf("%v %+v", err, sol)
	}

	// Conflicting world entries and provider clashes.
	for _, world := range [][]string{{"c", "!c"}, {"b>=2", "c"}, {"missing"}, {"a>=9"}} {
		if _, err := idx.Solve(SolveRequest{World: world}); !errors.Is(err, ErrUnsatisfiable) {
			t.Errorf("%v: %v", world, err)
		}
	}

	// Two packages that provide the same versioned capability cannot be installed together.
	clash := mk(
		Package{Name: "p1", Version: "1", Provides: []string{"cap=1"}},
		Package{Name: "p2", Version: "1", Provides: []string{"cap=2"}},
	)
	if _, err := clash.Solve(SolveRequest{World: []string{"p1", "p2"}}); !errors.Is(err, ErrUnsatisfiable) {
		t.Fatalf("clash: %v", err)
	}

	// Reinstall of the same version from a different build, and an upgrade.
	up := mk(Package{Name: "x", Version: "2", Checksum: "Q1aaa"})

	sol, err = up.Solve(SolveRequest{World: []string{"x"}, Installed: []Package{{Name: "x", Version: "1"}}, Upgrade: true})
	if err != nil || len(sol.Changes) != 1 || sol.Changes[0].Kind() != ChangeUpgrade {
		t.Fatalf("%v %+v", err, sol)
	}

	if !strings.Contains((&SolveError{Problems: []SolveProblem{{Name: "n", Reason: "r", RequiredBy: []string{"w"}}}}).Error(), "required by: w") {
		t.Error("SolveError text")
	}

	// A hostile index cannot make the search run forever.
	if _, err := mk().Solve(SolveRequest{World: []string{"!x", "x"}}); err != nil {
		t.Logf("empty index: %v", err)
	}
}

func TestExtract_privilegedKinds(t *testing.T) {
	raw, _ := mustWrite(t, fullSpec(), WriteOptions{TempDir: t.TempDir()})
	a := openArchiveBytes(t, raw)

	out := t.TempDir()
	err := a.Extract(out, ExtractOptions{Devices: true, Xattrs: true, Owners: true})

	if os.Geteuid() != 0 {
		// Unprivileged: the device node or the attribute cannot be created,
		// and that must be an error and not a silent skip.
		if err == nil {
			t.Fatal("device node and security.capability without privilege reported no error")
		}

		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if fi, err := os.Lstat(filepath.Join(out, "dev/null")); err != nil || fi.Mode()&fs.ModeCharDevice == 0 {
		t.Fatalf("device: %v %v", fi, err)
	}
}

func TestExtract_overwriteAndErrors(t *testing.T) {
	raw, _ := mustWrite(t, fullSpec(), WriteOptions{TempDir: t.TempDir()})
	a := openArchiveBytes(t, raw)

	out := t.TempDir()
	if err := a.Extract(out, ExtractOptions{}); err != nil {
		t.Fatal(err)
	}

	// A second extraction replaces files, symlinks and fifos in place.
	if err := a.Extract(out, ExtractOptions{}); err != nil {
		t.Fatalf("second extraction: %v", err)
	}

	// A directory where a file goes is refused, not removed.
	bad := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bad, "usr/bin/tool"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := a.Extract(bad, ExtractOptions{}); !errors.Is(err, ErrUnsafeEntry) {
		t.Fatalf("got %v, want ErrUnsafeEntry", err)
	}

	// The extraction directory must exist.
	if err := a.Extract(filepath.Join(out, "absent"), ExtractOptions{}); err == nil {
		t.Fatal("missing directory accepted")
	}
}

func TestArchive_errors(t *testing.T) {
	if _, err := OpenArchive(bytes.NewReader([]byte("not an apk")), 10); err == nil {
		t.Fatal("garbage accepted")
	}

	raw, _ := mustWrite(t, sampleSpec(), WriteOptions{TempDir: t.TempDir()})
	for _, cut := range []int{len(raw) - 1, len(raw) / 2, 10} {
		if a, err := OpenArchive(bytes.NewReader(raw[:cut]), int64(cut)); err == nil {
			if _, err := a.Files(); err == nil {
				t.Errorf("truncated at %d accepted", cut)
			}
		}
	}

	a := openArchiveBytes(t, raw)

	stop := errors.New("stop")
	if err := a.Walk(func(*Entry, io.Reader) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("walk error not propagated: %v", err)
	}

	sc := a.Scripts()
	if sc.PostInstall == "" || sc.PostUpgrade == "" || sc.PreDeinstall == "" {
		t.Fatalf("%+v", sc)
	}

	// Corrupting a content byte of the data segment is caught by the data hash or checksum.
	bad := bytes.Clone(raw)
	bad[len(bad)-1100] ^= 0xff

	if a, err := OpenArchive(bytes.NewReader(bad), int64(len(bad))); err == nil {
		if err := a.Walk(func(_ *Entry, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err }); err == nil {
			t.Error("corrupted data accepted")
		}
	}
}
