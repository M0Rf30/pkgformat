package pacman

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func parseMtreeText(t *testing.T, text string) *Mtree {
	t.Helper()

	mt, err := ParseMtree(strings.NewReader(text))
	if err != nil {
		t.Fatalf("ParseMtree: %v", err)
	}

	return mt
}

func TestParseMtreeMakepkg(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("testdata/makepkg/mtree.expected")
	if err != nil {
		t.Fatal(err)
	}

	mt := parseMtreeText(t, string(raw))

	cases := map[string]func(*MtreeEntry) bool{
		".PKGINFO": func(e *MtreeEntry) bool {
			return e.Type == MtreeFile && e.Mode == 0o644 && e.Size == 313 && e.Has(KeySHA256) && !e.Has(KeyMD5) &&
				e.Time.Equal(time.Unix(1700000000, 0)) && e.UID == 0 && e.Has(KeyUID|KeyGID)
		},
		"etc": func(e *MtreeEntry) bool { return e.Type == MtreeDir && e.Mode == 0o755 },
		"usr": func(e *MtreeEntry) bool { return e.Type == MtreeDir && e.Mode == 0o755 },
		"usr/bin/shape-sym": func(e *MtreeEntry) bool {
			return e.Type == MtreeLink && e.Link == "shape" && e.Mode == 0o777 && !e.Has(KeySize)
		},
		"usr/bin/shape-fifo": func(e *MtreeEntry) bool { return e.Type == MtreeFifo && e.Mode == 0o640 },
		"usr/bin/shape-suid": func(e *MtreeEntry) bool { return e.Mode == 0o4755 && e.FileMode()&fs.ModeSetuid != 0 },
		"usr/share/owned":    func(e *MtreeEntry) bool { return e.UID == 1234 && e.GID == 5678 },
		"usr/share/a b/c=d":  func(e *MtreeEntry) bool { return e.Size == 3 && e.Mode == 0o644 },
		"usr/bin/shape":      func(e *MtreeEntry) bool { return e.Mode == 0o755 && e.FileMode() == 0o755 },
	}

	for path, ok := range cases {
		e, found := mt.Lookup(path)
		if !found {
			t.Errorf("%s: not found", path)

			continue
		}

		if !ok(e) {
			t.Errorf("%s: %+v", path, e)
		}
	}

	if _, ok := mt.Lookup("nope"); ok {
		t.Error("Lookup invented an entry")
	}
}

func TestParseMtreeLocalDatabase(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("testdata/localdb/local/*/mtree")
	if err != nil || len(files) < 9 {
		t.Fatalf("fixtures: %v %v", files, err)
	}

	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}

		mt, err := ParseMtree(bytes.NewReader(raw))
		if err != nil {
			t.Errorf("%s: %v", f, err)

			continue
		}

		if _, ok := mt.Lookup(".PKGINFO"); !ok || len(mt.Entries) < 3 {
			t.Errorf("%s: %d entries", f, len(mt.Entries))
		}
	}
}

func TestParseMtreeSetAndUnset(t *testing.T) {
	t.Parallel()

	mt := parseMtreeText(t, `#mtree
# a comment
/set type=file uid=0 gid=0 mode=644
./a size=1
/set mode=755 uname=root
./b
/unset mode uname
./c uid=7 mode=600
/unset all
./d type=dir
`)

	want := []struct {
		path  string
		mode  uint32
		keys  MtreeKeys
		uid   int64
		uname string
	}{
		{"a", 0o644, KeyType | KeyUID | KeyGID | KeyMode | KeySize, 0, ""},
		{"b", 0o755, KeyType | KeyUID | KeyGID | KeyMode | KeyUname, 0, "root"},
		{"c", 0o600, KeyType | KeyUID | KeyGID | KeyMode, 7, ""},
		{"d", 0, KeyType, 0, ""},
	}

	if len(mt.Entries) != len(want) {
		t.Fatalf("entries = %+v", mt.Entries)
	}

	for i, w := range want {
		e := mt.Entries[i]
		if e.Path != w.path || e.Mode != w.mode || e.Keys != w.keys || e.UID != w.uid || e.Uname != w.uname {
			t.Errorf("%d: %+v, want %+v", i, e, w)
		}
	}
}

func TestParseMtreeAllKeywords(t *testing.T) {
	t.Parallel()

	const (
		md5 = "00112233445566778899aabbccddeeff"
	)

	sha1 := strings.Repeat("a1", 20)
	sha256 := strings.Repeat("b2", 32)
	sha384 := strings.Repeat("c3", 48)
	sha512 := strings.Repeat("d4", 64)
	rmd := strings.Repeat("e5", 20)

	mt := parseMtreeText(t, "#mtree\n./f type=file mode=4755 uid=10 gid=20 uname=bob gname=staff size=12 time=1700000000.123456789 "+
		"nlink=2 md5digest="+md5+" sha1digest="+sha1+" sha256digest="+sha256+" sha384digest="+sha384+" sha512digest="+sha512+
		" rmd160digest="+rmd+" cksum=123 flags=nodump device=native,1,2 inode=99 contents=a\\040b optional vendor=x\n")

	e := mt.Entries[0]

	if e.Type != MtreeFile || e.Mode != 0o4755 || e.UID != 10 || e.GID != 20 || e.Uname != "bob" || e.Gname != "staff" ||
		e.Size != 12 || e.Nlink != 2 || e.MD5 != md5 || e.SHA1 != sha1 || e.SHA256 != sha256 || e.SHA384 != sha384 ||
		e.SHA512 != sha512 || e.RMD160 != rmd || e.Cksum != "123" || e.Flags != "nodump" || e.Device != "native,1,2" ||
		e.Inode != 99 || e.Contents != "a b" || !e.Optional || e.Extra["vendor"] != "x" {
		t.Errorf("entry %+v", e)
	}

	if e.Time.Unix() != 1700000000 || e.Time.Nanosecond() != 123456789 {
		t.Errorf("time %v", e.Time)
	}

	for _, k := range []MtreeKeys{KeyType, KeyMode, KeyUID, KeyGID, KeyUname, KeyGname, KeySize, KeyTime, KeyNlink, KeyMD5,
		KeySHA1, KeySHA256, KeySHA384, KeySHA512, KeyRMD160, KeyCksum, KeyFlags, KeyDevice, KeyInode, KeyContents, KeyOptional} {
		if !e.Has(k) {
			t.Errorf("key %b missing", k)
		}
	}

	// The short digest names are accepted too.
	short := parseMtreeText(t, "./f type=file md5="+md5+" sha256="+sha256+"\n")
	if short.Entries[0].MD5 != md5 || short.Entries[0].SHA256 != sha256 {
		t.Errorf("short names: %+v", short.Entries[0])
	}
}

func TestParseMtreeNestedAndEscapes(t *testing.T) {
	t.Parallel()

	mt := parseMtreeText(t, `#mtree
/set type=file mode=644
. type=dir mode=755
    usr type=dir mode=755
        bin type=dir mode=755
            tool mode=755 size=1
        ..
        share type=dir
            a\040b size=2
            c\075d link=t\\x type=link
        ..
    ..
    top size=3
..
./abs/path size=4 \
  mode=600
`)

	got := map[string]MtreeEntry{}
	for _, e := range mt.Entries {
		got[e.Path] = e
	}

	for _, p := range []string{".", "usr", "usr/bin", "usr/bin/tool", "usr/share", "usr/share/a b", "usr/share/c=d", "top", "abs/path"} {
		if _, ok := got[p]; !ok {
			t.Errorf("%q missing in %v", p, mt.Entries)
		}
	}

	if got["usr/share/c=d"].Link != `t\x` || got["abs/path"].Mode != 0o600 {
		t.Errorf("escapes or continuation: %+v %+v", got["usr/share/c=d"], got["abs/path"])
	}
}

func TestParseMtreeGzip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("#mtree\n./x type=file size=1\n"))
	_ = zw.Close()

	mt, err := ParseMtree(&buf)
	if err != nil || len(mt.Entries) != 1 {
		t.Fatalf("%v %v", mt, err)
	}

	if _, err := ParseMtree(bytes.NewReader([]byte{0x1f, 0x8b, 0, 0})); !errors.Is(err, ErrInvalidMtree) {
		t.Errorf("bad gzip: %v", err)
	}
}

func TestParseMtreeRejects(t *testing.T) {
	t.Parallel()

	long := "./" + strings.Repeat("a", MaxMtreeLineBytes) + " type=file\n"

	tests := map[string]string{
		"no type":          "./a size=1\n",
		"bad type":         "./a type=weird\n",
		"bad mode":         "./a type=file mode=9z\n",
		"negative size":    "./a type=file size=-1\n",
		"bad size":         "./a type=file size=x\n",
		"short digest":     "./a type=file sha256digest=abcd\n",
		"non hex digest":   "./a type=file md5digest=" + strings.Repeat("z", 32) + "\n",
		"bad time":         "./a type=file time=abc\n",
		"bad fraction":     "./a type=file time=1.x\n",
		"keyword no value": "./a type=file size\n",
		"set no value":     "/set mode\n",
		"unknown command":  "/frob a=b\n",
		"parent":           "./../etc type=file\n",
		"nested parent":    "./a/../../b type=file\n",
		"absolute":         "/etc/passwd type=file\n",
		"escape overflow":  "./a\\777 type=file\n",
		"trailing escape":  "./a\\\\\\ type=file\n",
		"long line":        long,
	}

	for name, text := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := ParseMtree(strings.NewReader(text)); !errors.Is(err, ErrInvalidMtree) {
				t.Errorf("err = %v, want ErrInvalidMtree", err)
			}
		})
	}

	t.Run("too many keywords", func(t *testing.T) {
		t.Parallel()

		var b strings.Builder

		b.WriteString("./a type=file")

		for i := range 40 {
			b.WriteString(" k" + string(rune('A'+i%26)) + string(rune('a'+i/26)) + "=1")
		}

		if _, err := ParseMtree(strings.NewReader(b.String())); !errors.Is(err, ErrInvalidMtree) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("too many set keywords", func(t *testing.T) {
		t.Parallel()

		var b strings.Builder

		for i := range 70 {
			b.WriteString("/set k" + string(rune('A'+i%26)) + string(rune('a'+i/26)) + "=1\n")
		}

		if _, err := ParseMtree(strings.NewReader(b.String())); !errors.Is(err, ErrInvalidMtree) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestReadMtreeStopsOnCallbackError(t *testing.T) {
	t.Parallel()

	stop := errors.New("stop")
	n := 0

	err := ReadMtree(strings.NewReader("./a type=file\n./b type=file\n./c type=file\n"), func(*MtreeEntry) error {
		if n++; n == 2 {
			return stop
		}

		return nil
	})
	if !errors.Is(err, stop) || n != 2 {
		t.Errorf("err = %v after %d entries", err, n)
	}
}

func TestMtreeTypeAndFileMode(t *testing.T) {
	t.Parallel()

	for typ, want := range map[MtreeType]fs.FileMode{
		MtreeDir: fs.ModeDir | 0o751, MtreeLink: fs.ModeSymlink | 0o751, MtreeFifo: fs.ModeNamedPipe | 0o751,
		MtreeChar: fs.ModeDevice | fs.ModeCharDevice | 0o751, MtreeBlock: fs.ModeDevice | 0o751,
		MtreeSocket: fs.ModeSocket | 0o751, MtreeFile: 0o751,
	} {
		e := MtreeEntry{Type: typ, Mode: 0o751}
		if got := e.FileMode(); got != want {
			t.Errorf("%s: %v, want %v", typ, got, want)
		}

		if !typ.valid() {
			t.Errorf("%s not valid", typ)
		}
	}

	e := MtreeEntry{Mode: 0o7000}
	if got := e.FileMode(); got != fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky {
		t.Errorf("special bits: %v", got)
	}
}

func TestMtreeTextLimit(t *testing.T) {
	t.Parallel()

	// A reader that never ends: the limit must stop the parse, not memory.
	r := io.MultiReader(strings.NewReader("#mtree\n"), endless{})

	if err := readMtree(r, func(*MtreeEntry) error { return nil }, 1<<20); !errors.Is(err, ErrInvalidMtree) {
		t.Errorf("plain: %v", err)
	}

	var gz bytes.Buffer

	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(strings.Repeat("# padding padding padding padding padding padding padding\n", 1<<15)))
	_ = zw.Close()

	if err := readMtree(&gz, func(*MtreeEntry) error { return nil }, 1<<20); !errors.Is(err, ErrInvalidMtree) {
		t.Errorf("gzip: %v", err)
	}
}

// endless yields comment lines forever.
type endless struct{}

func (endless) Read(p []byte) (int, error) {
	const line = "# padding padding padding padding padding padding padding\n"

	n := 0
	for n+len(line) <= len(p) {
		n += copy(p[n:], line)
	}

	if n == 0 {
		n = copy(p, line[:1])
	}

	return n, nil
}
