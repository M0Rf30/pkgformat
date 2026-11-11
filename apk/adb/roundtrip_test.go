package adb

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type seen struct {
	Entry
	data []byte
}

// readAll walks a package file entry by entry.
func readAll(t testing.TB, file []byte, opts ReadOptions) (map[string]seen, []string, error) {
	t.Helper()

	rd, err := NewReader(bytes.NewReader(file), opts)
	if err != nil {
		return nil, nil, err
	}

	defer func() { _ = rd.Close() }()

	got := make(map[string]seen)

	var order []string

	for {
		e, err := rd.Next()
		if errors.Is(err, io.EOF) {
			return got, order, nil
		}

		if err != nil {
			return got, order, err
		}

		data, err := io.ReadAll(rd)
		if err != nil {
			return got, order, err
		}

		got[e.Name] = seen{*e, data}
		order = append(order, e.Name)
	}
}

func kindsSpec() *Spec {
	mt := time.Unix(1<<33, 0)

	file := func(name string, mode fs.FileMode, data string) File {
		f := MemFile(name, mode, []byte(data))
		f.ModTime = mt

		return f
	}

	shadow := file("etc/shadow", 0o640, "root:!::\n")
	shadow.Gname = "shadow"
	shadow.Xattrs = []Xattr{{Name: "user.b", Value: []byte("2")}, {Name: "user.a", Value: []byte("1")}, {Name: "user.empty"}}

	so := file("lib/libx.so.1", 0o755, "ELF")

	return &Spec{
		Info: Info{
			Name: "kinds", Version: "1.0-r0", Arch: "noarch", BuildTime: 1 << 40, Layer: 3,
			ProviderPriority: 1 << 33, Depends: []string{"b", "a>=1", "a>=1"},
		},
		Files: []File{
			file("bin/tool", fs.ModeSetuid|fs.ModeSetgid|0o755, "tool\n"),
			file("tmp/sticky/f", 0o666, "x"),
			{Name: "tmp/sticky", Mode: fs.ModeDir | fs.ModeSticky | 0o777, Uname: "builder"},
			{Name: "dev/null", Mode: fs.ModeDevice | fs.ModeCharDevice | 0o666, Rdev: 0x103},
			{Name: "dev/sda", Mode: fs.ModeDevice | 0o660, Gname: "disk", Rdev: 0x800},
			{Name: "run/pipe", Mode: fs.ModeNamedPipe | 0o600},
			shadow,
			so,
			{Name: "lib/libx.so", Mode: fs.ModeSymlink | 0o777, LinkTarget: "libx.so.1", ModTime: mt},
			func() File {
				f := so
				f.Name, f.HardLink = "lib/libx.so.1.hard", "lib/libx.so.1"

				return f
			}(),
			file("empty", 0o600, ""),
			{Name: "var/lib/empty", Mode: fs.ModeDir | 0o700},
		},
	}
}

func TestRoundTripKinds(t *testing.T) {
	for _, comp := range compressions {
		t.Run(comp.name, func(t *testing.T) {
			spec := kindsSpec()

			var out bytes.Buffer

			wrote, err := WritePackage(&out, spec, WriteOptions{Compression: comp.c})
			if err != nil {
				t.Fatal(err)
			}

			got, order, err := readAll(t, out.Bytes(), ReadOptions{})
			if err != nil {
				t.Fatal(err)
			}

			pkg, err := ParsePackage(bytes.NewReader(out.Bytes()), ReadOptions{})
			if err != nil || !reflect.DeepEqual(pkg, wrote) {
				t.Fatalf("ParsePackage differs from the written package: %v", err)
			}

			if !sortedEntries(order) {
				t.Errorf("entries out of order: %v", order)
			}

			check := func(name string, kind Kind, mode fs.FileMode) seen {
				t.Helper()

				s, ok := got[name]
				if !ok {
					t.Fatalf("%s is missing from %v", name, order)
				}

				if s.Kind != kind || s.Mode != mode {
					t.Errorf("%s: kind %v mode %v, want %v %v", name, s.Kind, s.Mode, kind, mode)
				}

				return s
			}

			if s := check("bin/tool", KindFile, fs.ModeSetuid|fs.ModeSetgid|0o755); string(s.data) != "tool\n" || s.ModTime.Unix() != 1<<33 || s.User != "root" {
				t.Errorf("bin/tool: %+v", s)
			}

			check("tmp/sticky", KindDir, fs.ModeDir|fs.ModeSticky|0o777)

			if got["tmp/sticky"].User != "builder" {
				t.Errorf("owner of tmp/sticky: %q", got["tmp/sticky"].User)
			}

			if s := check("dev/null", KindChar, fs.ModeDevice|fs.ModeCharDevice|0o666); s.Rdev != 0x103 {
				t.Errorf("dev/null rdev %#x", s.Rdev)
			}

			if s := check("dev/sda", KindBlock, fs.ModeDevice|0o660); s.Rdev != 0x800 || s.Group != "disk" {
				t.Errorf("dev/sda: %+v", s.Entry)
			}

			check("run/pipe", KindFIFO, fs.ModeNamedPipe|0o600)

			if s := check("etc/shadow", KindFile, 0o640); s.Group != "shadow" ||
				!reflect.DeepEqual(s.Xattrs, []Xattr{{Name: "user.a", Value: []byte("1")}, {Name: "user.b", Value: []byte("2")}, {Name: "user.empty", Value: []byte{}}}) {
				t.Errorf("etc/shadow: %+v", s.Entry)
			}

			if s := check("lib/libx.so", KindSymlink, fs.ModeSymlink|0o777); s.LinkTarget != "libx.so.1" {
				t.Errorf("symlink target %q", s.LinkTarget)
			}

			if s := check("lib/libx.so.1.hard", KindHardlink, 0o755); s.LinkTarget != "lib/libx.so.1" || s.Size != 3 || len(s.data) != 0 {
				t.Errorf("hard link: %+v", s)
			}

			if s := check("empty", KindFile, 0o600); s.Size != 0 || len(s.data) != 0 {
				t.Errorf("empty: %+v", s)
			}

			check("var/lib/empty", KindDir, fs.ModeDir|0o700)

			if !reflect.DeepEqual(pkg.Info.Depends, []string{"a>=1", "b"}) || pkg.Info.BuildTime != 1<<40 || pkg.Info.Layer != 3 || pkg.Info.ProviderPriority != 1<<33 {
				t.Errorf("info: %+v", pkg.Info)
			}

			if _, _, err := VerifyPackage(bytes.NewReader(out.Bytes()), keyringOf(t, keysOf(t)[0]), ReadOptions{}); !errors.Is(err, ErrUnsigned) {
				t.Errorf("unsigned package: %v", err)
			}
		})
	}
}

// sortedEntries reports whether directories come before what they hold.
func sortedEntries(names []string) bool {
	pos := make(map[string]int, len(names))
	for i, n := range names {
		pos[n] = i
	}

	for _, n := range names {
		if i := strings.LastIndexByte(n, '/'); i >= 0 {
			if p, ok := pos[n[:i]]; ok && p > pos[n] {
				return false
			}
		}
	}

	return true
}

func TestRoundTripInfo(t *testing.T) {
	in := fullInfo()
	in.InstalledSize = 12345

	spec := &Spec{
		Info: in, Triggers: []string{"/a", "/b"}, ReplacesPriority: 1 << 35,
		Scripts: Scripts{PostInstall: "echo hi\n", Trigger: "t"},
	}

	var out bytes.Buffer
	if _, err := WritePackage(&out, spec, WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	pkg, err := ParsePackage(&out, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if pkg.Info.InstalledSize != 12345 || pkg.Info.Description != in.Description || pkg.Info.RepoCommit != in.RepoCommit ||
		!reflect.DeepEqual(pkg.Info.Tags, in.Tags) || len(pkg.Info.Hashes) != 20 {
		t.Errorf("info: %+v", pkg.Info)
	}

	if pkg.Scripts != spec.Scripts || !reflect.DeepEqual(pkg.Triggers, spec.Triggers) || pkg.ReplacesPriority != 1<<35 || len(pkg.Paths) != 0 {
		t.Errorf("rest: %+v", pkg)
	}
}

func TestWritePackageInvalid(t *testing.T) {
	ok := func() *Spec {
		return &Spec{Info: Info{Name: "p", Version: "1.0-r0", Arch: "noarch"}}
	}

	failing := MemFile("f", 0o644, []byte("abc"))
	failing.Open = func() (io.ReadCloser, error) { return nil, errors.New("boom") }

	short := MemFile("f", 0o644, []byte("abc"))
	short.Size = 5

	long := MemFile("f", 0o644, []byte("abc"))
	long.Size = 2

	link := File{Name: "l", Mode: fs.ModeSymlink | 0o777, LinkTarget: "t"}
	hard := func(name, target string) File {
		f := MemFile(name, 0o644, []byte("x"))
		f.HardLink = target

		return f
	}

	for name, mod := range map[string]func(*Spec){
		"no arch":        func(s *Spec) { s.Info.Arch = "" },
		"no name":        func(s *Spec) { s.Info.Name = "" },
		"bad name":       func(s *Spec) { s.Info.Name = "-x" },
		"bad name char":  func(s *Spec) { s.Info.Name = "a b" },
		"bad version":    func(s *Spec) { s.Info.Version = "x1" },
		"bad dependency": func(s *Spec) { s.Info.Depends = []string{"a b"} },
		"bad provides":   func(s *Spec) { s.Info.Provides = []string{"a>="} },
		"bad commit":     func(s *Spec) { s.Info.RepoCommit = "xyz" },
		"short commit":   func(s *Spec) { s.Info.RepoCommit = "abcd" },
		"long commit":    func(s *Spec) { s.Info.RepoCommit = strings.Repeat("a", 130) },
		"bad tag":        func(s *Spec) { s.Info.Tags = []string{"a b"} },
		"empty tag":      func(s *Spec) { s.Info.Tags = []string{""} },
		"bad compat":     func(s *Spec) { s.Files = nil },
		"duplicate":      func(s *Spec) { s.Files = []File{MemFile("a", 0o644, nil), MemFile("a", 0o644, nil)} },
		"dotdot":         func(s *Spec) { s.Files = []File{MemFile("../a", 0o644, nil)} },
		"absolute":       func(s *Spec) { s.Files = []File{MemFile("/a", 0o644, nil)} },
		"empty name":     func(s *Spec) { s.Files = []File{MemFile("", 0o644, nil)} },
		"dot component":  func(s *Spec) { s.Files = []File{MemFile("a/./b", 0o644, nil)} },
		"trailing slash": func(s *Spec) { s.Files = []File{MemFile("a/", 0o644, nil)} },
		"below a file":   func(s *Spec) { s.Files = []File{MemFile("a", 0o644, nil), MemFile("a/b", 0o644, nil)} },
		"negative size":  func(s *Spec) { f := MemFile("a", 0o644, nil); f.Size = -1; s.Files = []File{f} },
		"no content":     func(s *Spec) { s.Files = []File{{Name: "a", Mode: 0o644, Size: 3}} },
		"short content":  func(s *Spec) { s.Files = []File{short} },
		"long content":   func(s *Spec) { s.Files = []File{long} },
		"open fails":     func(s *Spec) { s.Files = []File{failing} },
		"no link target": func(s *Spec) { s.Files = []File{{Name: "l", Mode: fs.ModeSymlink}} },
		"long link target": func(s *Spec) {
			s.Files = []File{{Name: "l", Mode: fs.ModeSymlink, LinkTarget: strings.Repeat("a", 5000)}}
		},
		"socket":            func(s *Spec) { s.Files = []File{{Name: "s", Mode: fs.ModeSocket | 0o600}} },
		"irregular":         func(s *Spec) { s.Files = []File{{Name: "s", Mode: fs.ModeIrregular | 0o600}} },
		"bad xattr":         func(s *Spec) { f := MemFile("a", 0o644, nil); f.Xattrs = []Xattr{{Name: ""}}; s.Files = []File{f} },
		"hard link missing": func(s *Spec) { s.Files = []File{hard("b", "a")} },
		"hard link to dir":  func(s *Spec) { s.Files = []File{{Name: "d", Mode: fs.ModeDir | 0o755}, hard("e", "d")} },
		"hard link to link": func(s *Spec) { s.Files = []File{link, hard("m", "l")} },
		"hard link later":   func(s *Spec) { s.Files = []File{MemFile("z", 0o644, []byte("x")), hard("a", "z")} },
		"hard link chain": func(s *Spec) {
			s.Files = []File{MemFile("a", 0o644, []byte("x")), hard("b", "a"), hard("c", "b")}
		},
		"typed hard link": func(s *Spec) {
			f := link
			f.HardLink = "x"
			s.Files = []File{MemFile("x", 0o644, nil), f}
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := ok()
			mod(spec)

			opts := WriteOptions{}
			if name == "bad compat" {
				opts.Compat = "zzz"
			}

			_, err := WritePackage(io.Discard, spec, opts)
			if err == nil {
				t.Fatal("accepted")
			}

			if name != "open fails" && !errors.Is(err, ErrInvalidSpec) {
				t.Errorf("%v is not ErrInvalidSpec", err)
			}
		})
	}

	for _, c := range []Compression{{Alg: CompDeflate, Level: 10}, {Alg: CompZstd, Level: 23}, {Alg: CompDeflate, Level: -1}, {Alg: 9}} {
		if _, err := WritePackage(io.Discard, ok(), WriteOptions{Compression: c}); !errors.Is(err, ErrCompression) {
			t.Errorf("compression %+v: %v", c, err)
		}
	}
}

type failWriter struct{ after int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("disk full")
	}

	f.after -= len(p)

	return len(p), nil
}

// TestWriteFailures makes the destination fail at every point of a write.
func TestWriteFailures(t *testing.T) {
	k := keysOf(t)[0]

	for _, comp := range compressions {
		var whole bytes.Buffer
		if _, err := WritePackage(&whole, kindsSpec(), WriteOptions{Compression: comp.c, Signers: []*Signer{k.signer}}); err != nil {
			t.Fatal(err)
		}

		for after := 0; after < min(whole.Len(), 400); after += 7 {
			if _, err := WritePackage(&failWriter{after: after}, kindsSpec(), WriteOptions{Compression: comp.c, Signers: []*Signer{k.signer}}); err == nil && comp.c.Alg == CompNone {
				t.Fatalf("%s: write succeeded though the destination failed after %d bytes", comp.name, after)
			}
		}
	}

	idx := &Index{Packages: []Info{{Name: "a", Version: "1"}}}

	var whole bytes.Buffer
	if err := BuildIndex(&whole, idx, WriteOptions{Compression: NoCompression}); err != nil {
		t.Fatal(err)
	}

	for after := 0; after < whole.Len(); after += 5 {
		if err := BuildIndex(&failWriter{after: after}, idx, WriteOptions{Compression: NoCompression}); err == nil {
			t.Fatalf("index write succeeded though the destination failed after %d bytes", after)
		}
	}
}

func TestIndexRoundTrip(t *testing.T) {
	var infos []Info

	for i := range 300 {
		in := fullInfo()
		in.Name = fmt.Sprintf("pkg%03d", 299-i)
		in.Hashes = bytes.Repeat([]byte{byte(i)}, 32)
		in.FileSize = uint64(i) * 1000
		in.InstalledSize = uint64(i) << 20
		infos = append(infos, in)
	}

	idx := &Index{Description: "d", PkgnameSpec: "${name}.apk", Packages: infos}

	for _, comp := range compressions {
		var out bytes.Buffer
		if err := BuildIndex(&out, idx, WriteOptions{Compression: comp.c}); err != nil {
			t.Fatal(err)
		}

		got, err := ParseIndex(&out, ReadOptions{})
		if err != nil {
			t.Fatal(err)
		}

		if got.Description != "d" || got.PkgnameSpec != "${name}.apk" || len(got.Packages) != 300 {
			t.Fatalf("%s: %+v", comp.name, got)
		}

		for i, p := range got.Packages {
			if p.Name != fmt.Sprintf("pkg%03d", i) {
				t.Fatalf("entry %d is %s", i, p.Name)
			}

			if !reflect.DeepEqual(p.Hashes, bytes.Repeat([]byte{byte(299 - i)}, 32)) || p.FileSize != uint64(299-i)*1000 {
				t.Errorf("entry %d: %+v", i, p)
			}
		}
	}

	// The caller's slice is left in the order given.
	if idx.Packages[0].Name != "pkg299" {
		t.Error("BuildIndex reordered the caller's entries")
	}

	if err := BuildIndex(io.Discard, &Index{}, WriteOptions{}); err != nil {
		t.Errorf("empty index: %v", err)
	}

	for _, bad := range []Info{{Name: "", Version: "1"}, {Name: "a", Version: "x"}, {Name: "a", Version: "1", Depends: []string{"a b"}}} {
		if err := BuildIndex(io.Discard, &Index{Packages: []Info{bad}}, WriteOptions{}); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestIndexOrder(t *testing.T) {
	idx := &Index{Packages: []Info{
		{Name: "b", Version: "1"}, {Name: "a", Version: "2"}, {Name: "a", Version: "1.10"}, {Name: "a", Version: "1.9"},
		{Name: "a", Version: "1.9", Hashes: []byte{1}}, {Name: "a", Version: "1.9", Hashes: []byte{0}, Description: "x"},
	}}

	var out bytes.Buffer
	if err := BuildIndex(&out, idx, WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	got, err := ParseIndex(&out, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, p := range got.Packages {
		names = append(names, p.Name+"-"+p.Version)
	}

	if want := []string{"a-1.9", "a-1.9", "a-1.9", "a-1.10", "a-2", "b-1"}; !reflect.DeepEqual(names, want) {
		t.Errorf("order %v, want %v", names, want)
	}
}

func TestReaderAPI(t *testing.T) {
	var out bytes.Buffer
	if _, err := WritePackage(&out, kindsSpec(), WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	rd, err := NewReader(bytes.NewReader(out.Bytes()), ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if rd.Schema() != SchemaPackage || rd.Compression().Alg != CompDeflate || len(rd.Signatures()) != 0 || len(rd.ADB()) == 0 {
		t.Errorf("head: %x %+v %v", rd.Schema(), rd.Compression(), rd.Signatures())
	}

	if _, err := rd.Index(); !errors.Is(err, ErrSchema) {
		t.Errorf("Index of a package: %v", err)
	}

	in, err := rd.IndexInfo(-1)
	if err != nil || len(in.Hashes) != 32 || in.FileSize != 0 {
		t.Errorf("IndexInfo: %+v %v", in, err)
	}

	if in, _ := rd.IndexInfo(77); in.FileSize != 77 {
		t.Errorf("IndexInfo file size %d", in.FileSize)
	}

	// Skipping the content of an entry is fine; the next one still reads.
	skipped := 0

	for {
		_, err := rd.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			t.Fatal(err)
		}

		skipped++
	}

	if skipped != 20 {
		t.Errorf("%d entries", skipped)
	}

	if _, err := rd.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("Next after the end: %v", err)
	}

	if n, err := rd.Read(make([]byte, 4)); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("Read after the end: %d %v", n, err)
	}

	if err := rd.Close(); err != nil {
		t.Fatal(err)
	}

	if err := rd.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	var idx bytes.Buffer
	if err := BuildIndex(&idx, &Index{Packages: []Info{{Name: "a", Version: "1"}}}, WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	ird, err := NewReader(&idx, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = ird.Close() }()

	if _, err := ird.Package(); !errors.Is(err, ErrSchema) {
		t.Errorf("Package of an index: %v", err)
	}

	if _, err := ird.Next(); !errors.Is(err, ErrSchema) {
		t.Errorf("Next of an index: %v", err)
	}

	if _, err := ird.IndexInfo(-1); err == nil {
		t.Error("IndexInfo of an index")
	}
}

func TestEntryKindString(t *testing.T) {
	for k, want := range map[Kind]string{
		KindFile: "file", KindDir: "dir", KindSymlink: "symlink", KindHardlink: "hardlink",
		KindBlock: "block", KindChar: "char", KindFIFO: "fifo", Kind(99): "unknown",
	} {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d) = %q, want %q", k, got, want)
		}
	}
}

func TestFilesFromDir(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(name, data string, perm fs.FileMode) {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, []byte(data), perm); err != nil {
			t.Fatal(err)
		}
	}

	mustWrite("b/two", "2", 0o644)
	mustWrite("a/one", "1", 0o755)
	mustWrite("a/sub/three", "333", 0o600)

	if err := os.Symlink("one", filepath.Join(root, "a", "link")); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(filepath.Join(root, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}

	files, err := FilesFromDir(root)
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, f := range files {
		names = append(names, f.Name)

		if f.Uname != "" && f.Uname != "root" || !f.ModTime.IsZero() && f.ModTime.Unix() != 0 {
			t.Errorf("%s: owner %q time %v", f.Name, f.Uname, f.ModTime)
		}
	}

	if want := []string{"a", "a/link", "a/one", "a/sub", "a/sub/three", "b", "b/two", "empty"}; !reflect.DeepEqual(names, want) {
		t.Errorf("files %v, want %v", names, want)
	}

	var out bytes.Buffer
	if _, err := WritePackage(&out, &Spec{Info: Info{Name: "d", Version: "1", Arch: "noarch"}, Files: files}, WriteOptions{}); err != nil {
		t.Fatal(err)
	}

	got, _, err := readAll(t, out.Bytes(), ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if string(got["a/sub/three"].data) != "333" || got["a/link"].LinkTarget != "one" || got["empty"].Mode != fs.ModeDir|0o700 {
		t.Errorf("round trip: %+v", got)
	}

	if _, err := FilesFromDir(filepath.Join(root, "missing")); err == nil {
		t.Error("missing directory")
	}
}
