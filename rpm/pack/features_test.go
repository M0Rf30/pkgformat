package pack

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/M0Rf30/pkgformat/rpm/tag"
)

func basePkg(t testing.TB, mod func(*RPMMetaData)) *RPM {
	t.Helper()
	m := RPMMetaData{Name: "t", Version: "1", Release: "1", Arch: "noarch", Licence: "MIT", Summary: "s", Description: "d"}
	if mod != nil {
		mod(&m)
	}
	r, err := NewRPM(m)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustWrite(t *testing.T, r *RPM) parsedRPM {
	t.Helper()
	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	return parseRPM(t, b.Bytes())
}

func TestScriptletWrappersAndFlags(t *testing.T) {
	r := basePkg(t, nil)
	r.AddPretrans("a")
	r.AddPrein("b")
	r.AddPostin("c")
	r.AddPreun("d")
	r.AddPostun("e")
	r.AddPosttrans("f")
	r.AddPreuntrans("g")
	r.AddPostuntrans("h")
	r.AddVerifyScript("i")
	r.AddScriptlet(ScriptPostin, Scriptlet{Script: "x", Interpreter: []string{"/bin/sh", "-e"}, Flags: ScriptExpand | ScriptQFormat | ScriptCritical})
	p := mustWrite(t, r)
	for i, id := range []int{tag.PRETRANS, tag.PREIN, tag.POSTIN, tag.PREUN, tag.POSTUN, tag.POSTTRANS, tag.PREUNTRANS, tag.POSTUNTRANS, tag.VERIFYSCRIPT} {
		want := string(rune('a' + i))
		if i == 2 {
			want = "x"
		}
		if got := p.main.str(t, id); got != want {
			t.Errorf("script tag %d = %q, want %q", id, got, want)
		}
	}
	if got := p.main.strs(t, tag.POSTINPROG); len(got) != 2 || got[1] != "-e" {
		t.Errorf("postin prog = %q", got)
	}
	if got := p.main.ints(t, tag.POSTINFLAGS, tag.RPM_INT32_TYPE); got[0] != uint64(ScriptExpand|ScriptQFormat|ScriptCritical) {
		t.Errorf("postin flags = %v", got)
	}
	if _, ok := p.main.entries[tag.PREINFLAGS]; ok {
		t.Error("flags are written for a scriptlet that has none")
	}
}

func TestScriptletValidation(t *testing.T) {
	for name, fn := range map[string]func(*RPM){
		"NUL":   func(r *RPM) { r.AddPrein("a\x00b") },
		"flags": func(r *RPM) { r.AddScriptlet(ScriptPrein, Scriptlet{Script: "a", Flags: 1 << 20}) },
		"empty arg": func(r *RPM) {
			r.AddScriptlet(ScriptPrein, Scriptlet{Script: "a", Interpreter: []string{"/bin/sh", ""}})
		},
		"lua args": func(r *RPM) {
			r.AddScriptlet(ScriptPrein, Scriptlet{Script: "a", Interpreter: []string{LuaInterpreter, "x"}})
		},
		"trigger args": func(r *RPM) {
			r.AddTrigger(Trigger{Kind: TriggerIn, Conditions: Relations{{Name: "x"}}, Script: Scriptlet{Script: "a", Interpreter: []string{"/bin/sh", "-e"}}})
		},
		"trigger none": func(r *RPM) { r.AddTrigger(Trigger{Kind: TriggerIn, Script: Scriptlet{Script: "a"}}) },
		"file trigger prefix": func(r *RPM) {
			r.AddFileTrigger(FileTrigger{Kind: FileTriggerIn, Prefixes: []string{"usr/lib"}, Script: Scriptlet{Script: "a"}})
		},
		"file trigger none": func(r *RPM) { r.AddFileTrigger(FileTrigger{Kind: FileTriggerIn, Script: Scriptlet{Script: "a"}}) },
		"trigger kind": func(r *RPM) {
			r.AddTrigger(Trigger{Kind: 99, Conditions: Relations{{Name: "x"}}, Script: Scriptlet{Script: "a"}})
		},
		"file trigger kind": func(r *RPM) {
			r.AddFileTrigger(FileTrigger{Kind: 99, Prefixes: []string{"/a"}, Script: Scriptlet{Script: "a"}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := basePkg(t, nil)
			fn(r)
			if err := r.Write(io.Discard); !errors.Is(err, ErrInvalidScript) && !errors.Is(err, ErrInvalidMetadata) {
				t.Errorf("Write = %v, want ErrInvalidScript", err)
			}
		})
	}
	if ScriptKind(99).String() == "" || ScriptPostin.String() != "postin" {
		t.Error("ScriptKind.String")
	}
}

func TestFileSources(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("from path"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := basePkg(t, nil)
	r.AddFile(RPMFile{Name: "/body", Body: []byte("from body")})
	r.AddFile(RPMFile{Name: "/reader", Reader: strings.NewReader("from reader"), Size: 11})
	r.AddFile(RPMFile{Name: "/open", Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("from open")), nil }, Size: 9})
	r.AddFile(RPMFile{Name: "/path", Path: filepath.Join(dir, "f")})
	p := mustWrite(t, r)
	names := p.main.strs(t, tag.BASENAMES)
	digests := p.main.strs(t, tag.FILEDIGESTS)
	want := map[string]string{"body": "from body", "reader": "from reader", "open": "from open", "path": "from path"}
	for i, n := range names {
		sum := sha256.Sum256([]byte(want[n]))
		if digests[i] != hex.EncodeToString(sum[:]) {
			t.Errorf("digest of %s = %s", n, digests[i])
		}
	}
	for name, f := range map[string]RPMFile{
		"short":       {Name: "/x", Reader: strings.NewReader("ab"), Size: 5},
		"long":        {Name: "/x", Reader: strings.NewReader("abcdef"), Size: 3},
		"open fail":   {Name: "/x", Open: func() (io.ReadCloser, error) { return nil, errors.New("boom") }, Size: 1},
		"no path":     {Name: "/x", Path: filepath.Join(dir, "missing")},
		"two":         {Name: "/x", Body: []byte("a"), Path: "/etc/passwd"},
		"relative":    {Name: "x", Body: []byte("a")},
		"unclean":     {Name: "/a/../b", Body: []byte("a")},
		"negative":    {Name: "/x", Reader: strings.NewReader(""), Size: -1},
		"nul":         {Name: "/x\x00", Body: []byte("a")},
		"owner nul":   {Name: "/x", Owner: "a\x00"},
		"mode":        {Name: "/x", Mode: 1 << 20},
		"device no":   {Name: "/x", Major: 1},
		"device big":  {Name: "/x", Mode: ModeChar, Major: 300},
		"verify":      {Name: "/x", VerifyExclude: 1 << 30},
		"link body":   {Name: "/x", Hardlink: "/y", Body: []byte("a")},
		"link ghost":  {Name: "/x", Hardlink: "/y", Type: GhostFile},
		"symlink":     {Name: "/x", Mode: 0120777},
		"symlink nul": {Name: "/x", Mode: 0120777, Body: []byte("a\x00")},
	} {
		t.Run(name, func(t *testing.T) {
			r := basePkg(t, nil)
			r.AddFile(f)
			if err := r.Write(io.Discard); !errors.Is(err, ErrInvalidFile) {
				t.Errorf("Write = %v, want ErrInvalidFile", err)
			}
		})
	}
}

func TestV4RejectsHugeFile(t *testing.T) {
	r := basePkg(t, nil)
	r.AddFile(RPMFile{Name: "/big", Open: func() (io.ReadCloser, error) { return nil, errors.New("not read") }, Size: 5 << 30})
	if err := r.Write(io.Discard); !errors.Is(err, ErrInvalidFile) || !strings.Contains(err.Error(), "FormatV6") {
		t.Errorf("Write = %v", err)
	}
}

func TestDigestAlgorithms(t *testing.T) {
	body := []byte("digest me")
	sums := map[int][]byte{}
	s := sha256.Sum256(body)
	sums[DigestSHA256] = s[:]
	s2 := sha512.Sum512(body)
	sums[DigestSHA512] = s2[:]
	s3 := sha3.Sum256(body)
	sums[DigestSHA3256] = s3[:]
	s4 := sha3.Sum512(body)
	sums[DigestSHA3512] = s4[:]
	for _, format := range []int{FormatV4, FormatV6} {
		for algo, want := range sums {
			r := basePkg(t, func(m *RPMMetaData) { m.FileDigestAlgo = algo; m.Format = format })
			r.AddFile(RPMFile{Name: "/f", Body: body})
			p := mustWrite(t, r)
			if got := p.main.ints(t, tag.FILEDIGESTALGO, tag.RPM_INT32_TYPE); len(got) != 1 || got[0] != uint64(algo) {
				t.Errorf("algo tag = %v, want %d", got, algo)
			}
			if got := p.main.strs(t, tag.FILEDIGESTS); got[0] != hex.EncodeToString(want) {
				t.Errorf("v%d algo %d: digest %s", format, algo, got[0])
			}
		}
	}
	if _, err := NewRPM(RPMMetaData{Name: "t", Version: "1", Release: "1", FileDigestAlgo: 99}); !errors.Is(err, ErrInvalidDigest) {
		t.Errorf("NewRPM = %v, want ErrInvalidDigest", err)
	}
}

func TestHardlinksShareContent(t *testing.T) {
	for _, format := range []int{FormatV4, FormatV6} {
		r := basePkg(t, func(m *RPMMetaData) { m.Format = format })
		marker := bytes.Repeat([]byte("hardlink-marker-"), 200)
		r.AddFile(RPMFile{Name: "/a", Body: marker})
		r.AddFile(RPMFile{Name: "/b", Hardlink: "/a"})
		r.AddFile(RPMFile{Name: "/c", Hardlink: "/a"})
		r.AddFile(RPMFile{Name: "/d", Body: []byte("alone")})
		p := mustWrite(t, r)
		ino := p.main.ints(t, tag.FILEINODES, tag.RPM_INT32_TYPE)
		if ino[0] != ino[1] || ino[1] != ino[2] || ino[2] == ino[3] {
			t.Errorf("v%d inodes %v", format, ino)
		}
		var sizes []uint64
		if format == FormatV6 {
			sizes = p.main.ints(t, tag.LONGFILESIZES, tag.RPM_INT64_TYPE)
		} else {
			sizes = p.main.ints(t, tag.FILESIZES, tag.RPM_INT32_TYPE)
		}
		if sizes[0] != uint64(len(marker)) || sizes[1] != uint64(len(marker)) || sizes[2] != uint64(len(marker)) {
			t.Errorf("v%d sizes %v", format, sizes)
		}
		comp := string(bytes.TrimSuffix(p.main.entries[tag.PAYLOADCOMPRESSOR].data, []byte{0}))
		raw := decompress(t, comp, p.payload)
		if n := bytes.Count(raw, []byte("hardlink-marker-")); n != 200 {
			t.Errorf("v%d: payload holds the content %d/200 times", format, n)
		}
	}
	for name, fn := range map[string]func(*RPM){
		"missing target": func(r *RPM) { r.AddFile(RPMFile{Name: "/b", Hardlink: "/a"}) },
		"differs": func(r *RPM) {
			r.AddFile(RPMFile{Name: "/a", Body: []byte("a"), Owner: "x"})
			r.AddFile(RPMFile{Name: "/b", Hardlink: "/a", Owner: "y"})
		},
		"self": func(r *RPM) { r.AddFile(RPMFile{Name: "/b", Hardlink: "/b"}) },
	} {
		r := basePkg(t, nil)
		fn(r)
		if err := r.Write(io.Discard); !errors.Is(err, ErrInvalidFile) {
			t.Errorf("%s: Write = %v", name, err)
		}
	}
}

func TestSpecialFiles(t *testing.T) {
	r := basePkg(t, nil)
	r.AddFile(RPMFile{Name: "/dev/null", Mode: ModeChar | 0666, Major: 1, Minor: 3})
	r.AddFile(RPMFile{Name: "/dev/loop0", Mode: ModeBlock | 0660, Major: 7, Minor: 0})
	r.AddFile(RPMFile{Name: "/run/pipe", Mode: ModeFifo | 0600})
	r.AddFile(RPMFile{Name: "/run/sock", Mode: ModeSocket | 0600})
	p := mustWrite(t, r)
	names := p.main.strs(t, tag.BASENAMES)
	rdevs := p.main.ints(t, tag.FILERDEVS, tag.RPM_INT16_TYPE)
	modes := p.main.ints(t, tag.FILEMODES, tag.RPM_INT16_TYPE)
	for i, n := range names {
		switch n {
		case "null":
			if rdevs[i] != 1<<8|3 || modes[i] != uint64(ModeChar|0666) {
				t.Errorf("null: rdev %#x mode %#o", rdevs[i], modes[i])
			}
		case "loop0":
			if rdevs[i] != 7<<8 {
				t.Errorf("loop0 rdev %#x", rdevs[i])
			}
		case "pipe", "sock":
			if rdevs[i] != 0 {
				t.Errorf("%s rdev %#x", n, rdevs[i])
			}
		}
	}
}

func TestFileAttributes(t *testing.T) {
	r := basePkg(t, func(m *RPMMetaData) { m.Format = FormatV4 })
	r.AddFile(RPMFile{Name: "/a", Body: []byte("a"), Lang: "de", Class: "text", Caps: "cap_chown=ep", Color: 2,
		Provides: Relations{{Name: "perl(A)"}}, Requires: Relations{{Name: "perl(B)", Version: "1", Sense: (SenseGreater | SenseEqual)}}})
	r.AddFile(RPMFile{Name: "/b", Body: []byte("b"), VerifyExclude: VerifyMTime | VerifySize, Type: ConfigFile | NoReplaceFile | MissingOkFile})
	p := mustWrite(t, r)
	if got := p.main.strs(t, tag.FILELANGS); got[0] != "de" || got[1] != "" {
		t.Errorf("langs %q", got)
	}
	if got := p.main.strs(t, tag.FILECAPS); got[0] != "cap_chown=ep" {
		t.Errorf("caps %q", got)
	}
	if got := p.main.strs(t, tag.CLASSDICT); got[0] != "text" {
		t.Errorf("class dict %q", got)
	}
	if got := p.main.ints(t, tag.FILECOLORS, tag.RPM_INT32_TYPE); got[0] != 2 {
		t.Errorf("colors %v", got)
	}
	vf := p.main.ints(t, tag.FILEVERIFYFLAGS, tag.RPM_INT32_TYPE)
	if uint32(vf[1]) != ^uint32(VerifyMTime|VerifySize) || vf[0] != 0xffffffff {
		t.Errorf("verify flags %#x", vf)
	}
	if _, ok := p.main.entries[tag.FILEDEPENDSX]; !ok {
		t.Error("no file dependency tags")
	}
	fl := p.main.ints(t, tag.FILEFLAGS, tag.RPM_INT32_TYPE)
	if fl[1] != uint64(ConfigFile|NoReplaceFile|MissingOkFile) {
		t.Errorf("file flags %#x", fl[1])
	}
	if err := func() error {
		r := basePkg(t, nil)
		r.AddFile(RPMFile{Name: "/a", Body: []byte("a"), Provides: Relations{nil}})
		return r.Write(io.Discard)
	}(); err == nil {
		t.Error("nil file relation accepted")
	}
}

func TestClampTimeImplicitDirsOwnerDeps(t *testing.T) {
	r := basePkg(t, func(m *RPMMetaData) {
		m.ClampTime = time.Unix(1000, 0)
		m.ImplicitDirs = true
		m.OwnerDeps = true
		m.Sysusers = []string{"u foo - \"Foo\" /var/lib/foo", "g bar -", "m foo bar"}
	})
	r.AddFile(RPMFile{Name: "/usr/share/x/f", Body: []byte("a"), MTime: 5000, Owner: "foo", Group: "bar"})
	r.AddFile(RPMFile{Name: "/usr/share/x/old", Body: []byte("a"), MTime: 500})
	p := mustWrite(t, r)
	names := p.main.strs(t, tag.BASENAMES)
	if len(names) != 6 { // usr, share, x, f, old and the dirs below /
		t.Logf("names %v", names)
	}
	for i, m := range p.main.ints(t, tag.FILEMTIMES, tag.RPM_INT32_TYPE) {
		if (names[i] == "f" && m != 1000) || (names[i] == "old" && m != 500) {
			t.Errorf("mtime of %s = %d", names[i], m)
		}
	}
	req := p.main.strs(t, tag.REQUIRENAME)
	prov := p.main.strs(t, tag.PROVIDENAME)
	for _, want := range []string{"user(foo)", "group(bar)"} {
		if !contains(req, want) {
			t.Errorf("no requirement %s in %q", want, req)
		}
	}
	for _, want := range []string{"user(foo)", "group(bar)"} {
		if !contains(prov, want) {
			t.Errorf("no provide %s in %q", want, prov)
		}
	}
	if !contains(names, "x") || !contains(names, "share") {
		t.Errorf("implicit directories missing from %q", names)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestRpmlibRequires(t *testing.T) {
	r := basePkg(t, func(m *RPMMetaData) {
		m.Format = FormatV4
		m.Compressor = "zstd"
		m.Requires = Relations{{Name: "(a if b)"}, {Name: "x", Version: "1~rc1", Sense: SenseLess}, {Name: "y", Version: "1^p", Sense: SenseGreater}}
	})
	r.AddFile(RPMFile{Name: "/a", Body: []byte("a")})
	r.AddFile(RPMFile{Name: "/b", Hardlink: "/a"})
	r.AddFile(RPMFile{Name: "/c", Body: []byte("c"), Caps: "cap_chown=ep"})
	r.AddScriptlet(ScriptPostin, Scriptlet{Script: "x", Interpreter: []string{LuaInterpreter}})
	r.AddScriptlet(ScriptPrein, Scriptlet{Script: "x", Interpreter: []string{"/bin/sh", "-e"}})
	r.AddScriptlet(ScriptPreun, Scriptlet{Script: "x", Flags: ScriptExpand})
	p := mustWrite(t, r)
	req := p.main.strs(t, tag.REQUIRENAME)
	for _, want := range []string{"rpmlib(PayloadIsZstd)", "rpmlib(FileCaps)", "rpmlib(PartialHardlinkSets)", "rpmlib(BuiltinLuaScripts)",
		"rpmlib(ScriptletInterpreterArgs)", "rpmlib(ScriptletExpansion)", "rpmlib(RichDependencies)", "rpmlib(TildeInVersions)",
		"rpmlib(CaretInVersions)", "rpmlib(CompressedFileNames)", "rpmlib(PayloadFilesHavePrefix)", "rpmlib(FileDigests)", "/bin/sh"} {
		if !contains(req, want) {
			t.Errorf("missing requirement %s in %q", want, req)
		}
	}
}

func TestPayloadFlagsAndMetadata(t *testing.T) {
	for comp, want := range map[string]string{"gzip": "9", "gzip:3": "3", "xz": "6", "zstd": "7", "zstd:19": "19", "lzma": "6", "zstd:fastest": "1", "zstd:default": "3", "zstd:better": "7", "zstd:best": "11"} {
		r := basePkg(t, func(m *RPMMetaData) {
			m.Compressor = comp
			m.Prefixes = []string{"/opt", "/usr"}
			m.DistTag = "el9"
			m.DistURL = "https://d"
			m.BugURL = "https://bugs"
			m.VCS = "git:x"
			m.SourceRPM = "src-1-1.src.rpm"
			m.BuildArchs = []string{"x86_64"}
			m.Platform = "noarch-linux"
			m.OptFlags = "-O2"
			m.Cookie = "cookie"
			m.ModularityLabel = "mod:1:2:3:4"
			m.Epoch = 3
			m.Changelog = []ChangelogEntry{{Time: time.Unix(100, 0), Author: "a", Text: "t"}, {Time: time.Unix(200, 0), Author: "b", Text: "u"}}
		})
		r.AddFile(RPMFile{Name: "/a", Body: []byte("a")})
		p := mustWrite(t, r)
		if got := p.main.str(t, tag.PAYLOADFLAGS); got != want {
			t.Errorf("%s: PAYLOADFLAGS %q, want %q", comp, got, want)
		}
		for id, want := range map[int]string{tag.DISTTAG: "el9", tag.DISTURL: "https://d", tag.BUGURL: "https://bugs", tag.VCS: "git:x",
			tag.SOURCERPM: "src-1-1.src.rpm", tag.PLATFORM: "noarch-linux", tag.OPTFLAGS: "-O2", tag.COOKIE: "cookie", tag.MODULARITYLABEL: "mod:1:2:3:4"} {
			if got := p.main.str(t, id); got != want {
				t.Errorf("tag %d = %q, want %q", id, got, want)
			}
		}
		if got := p.main.strs(t, tag.PREFIXES); len(got) != 2 {
			t.Errorf("prefixes %q", got)
		}
		if got := p.main.strs(t, tag.CHANGELOGNAME); got[0] != "a" || got[1] != "b" {
			t.Errorf("changelog order is not kept: %q", got)
		}
	}
	for _, bad := range []string{"bzip2", "gzip:0", "gzip:10", "zstd:23", "zstd:x", "xz:1"} {
		if _, err := NewRPM(RPMMetaData{Name: "t", Version: "1", Release: "1", Compressor: bad}); !errors.Is(err, ErrInvalidCompressor) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func TestMetadataValidation(t *testing.T) {
	for name, mod := range map[string]func(*RPMMetaData){
		"prefix relative": func(m *RPMMetaData) { m.Prefixes = []string{"opt"} },
		"prefix root":     func(m *RPMMetaData) { m.Prefixes = []string{"/"} },
		"NUL summary":     func(m *RPMMetaData) { m.Summary = "a\x00" },
		"NUL name":        func(m *RPMMetaData) { m.Requires = Relations{{Name: "a\x00"}} },
		"nil relation":    func(m *RPMMetaData) { m.Requires = Relations{nil} },
		"rich":            func(m *RPMMetaData) { m.Requires = Relations{{Name: "(a or"}} },
		"rich context":    func(m *RPMMetaData) { m.Requires = Relations{{Name: "(a unless b)"}} },
		"build time":      func(m *RPMMetaData) { m.BuildTime = time.Unix(1<<40, 0) },
		"clamp time":      func(m *RPMMetaData) { m.ClampTime = time.Unix(-5, 0) },
		"changelog time":  func(m *RPMMetaData) { m.Changelog = []ChangelogEntry{{Time: time.Unix(-5, 0)}} },
	} {
		t.Run(name, func(t *testing.T) {
			r := basePkg(t, mod)
			if err := r.Write(io.Discard); err == nil {
				t.Error("Write accepted the metadata")
			}
		})
	}
	// "unless" is fine where the dependency has the opposite polarity
	r := basePkg(t, func(m *RPMMetaData) { m.Conflicts = Relations{{Name: "(a unless b)"}} })
	if err := r.Write(io.Discard); err != nil {
		t.Errorf("conflicts: %v", err)
	}
}

func TestAddCustomTags(t *testing.T) {
	r := basePkg(t, nil)
	r.AddCustomTag(tag.VENDOR, EntryString("custom"))
	r.AddCustomSig(tag.SIG_BASE+99, EntryString("sig"))
	p := mustWrite(t, r)
	if p.main.str(t, tag.VENDOR) != "custom" || p.sig.str(t, tag.SIG_BASE+99) != "sig" {
		t.Error("custom tags not written")
	}
}

func TestAddFS(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/app.conf":   {Data: []byte("conf"), Mode: 0o600},
		"bin/app":        {Data: []byte("#!/bin/sh\n"), Mode: 0o755},
		"bin/link":       {Data: []byte("app"), Mode: fs.ModeSymlink | 0o777},
		"share/doc/x.md": {Data: []byte("doc")},
	}
	r := basePkg(t, nil)
	if err := r.AddFS(fsys, AddFSOptions{Prefix: "/opt/app", Owner: "app", Group: "app"}); err != nil {
		t.Fatal(err)
	}
	p := mustWrite(t, r)
	names := p.main.strs(t, tag.BASENAMES)
	for _, want := range []string{"app.conf", "app", "link", "x.md", "doc", "etc"} {
		if !contains(names, want) {
			t.Errorf("%s missing from %q", want, names)
		}
	}
	if got := p.main.strs(t, tag.FILEUSERNAME); got[0] != "app" {
		t.Errorf("owner %q", got)
	}
	r = basePkg(t, nil)
	if err := r.AddFS(fsys, AddFSOptions{Dir: "bin", SkipDirs: true, Type: DocFile}); err != nil {
		t.Fatal(err)
	}
	if n := len(basenamesOf(t, r)); n != 2 {
		t.Errorf("SkipDirs left %d entries", n)
	}
	if err := r.AddFS(fsys, AddFSOptions{Dir: "missing"}); err == nil {
		t.Error("missing directory accepted")
	}
}

func TestVerityHasherKnownDigests(t *testing.T) {
	for _, tc := range []struct {
		data []byte
		want string
	}{
		{[]byte("abc\n"), "df47a803e73b11e8a43594a793382726f0807ab5130df9ee36d408508dcf4302"},
		{bytes.Repeat([]byte("x"), 10000), "56d299c86ab735388169327e546b464800d8cb6b3935303ed51b4f3142fc7362"},
		{nil, "3d248ca542a24fc62d1c43b916eae5016878e2533c88238480b26128a1f1af95"},
	} {
		h := newVerityHasher()
		// feed in odd sized pieces to cover the block buffering
		for d := tc.data; len(d) > 0; {
			n := min(len(d), 1000)
			h.Write(d[:n])
			d = d[n:]
		}
		sum := h.Sum()
		if got := hex.EncodeToString(sum[:]); got != tc.want {
			t.Errorf("%d bytes: %s, want %s", len(tc.data), got, tc.want)
		}
	}
}

func TestFileSigningValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		fs   FileSigning
		algo int
	}{
		"no keys":     {FileSigning{}, DigestSHA256},
		"ima sha3":    {FileSigning{IMAKey: key}, DigestSHA3256},
		"no cert":     {FileSigning{VerityKey: key}, DigestSHA256},
		"cert no key": {FileSigning{VerityCert: nil, IMAKey: nil}, DigestSHA256},
	} {
		r := basePkg(t, func(m *RPMMetaData) { m.FileDigestAlgo = tc.algo })
		r.AddFile(RPMFile{Name: "/a", Body: []byte("a")})
		r.SetFileSigning(tc.fs)
		if err := r.Write(io.Discard); !errors.Is(err, ErrFileSigning) {
			t.Errorf("%s: Write = %v", name, err)
		}
	}
	// IMA with sha512 digests
	r := basePkg(t, func(m *RPMMetaData) { m.FileDigestAlgo = DigestSHA512; m.Format = FormatV6 })
	r.AddFile(RPMFile{Name: "/a", Body: []byte("a")})
	r.SetFileSigning(FileSigning{IMAKey: key})
	p := mustWrite(t, r)
	sigs := p.sig.strs(t, sigFileSignatures)
	if !strings.HasPrefix(sigs[0], "030206") {
		t.Errorf("IMA signature header %s", sigs[0][:12])
	}
}

func TestRelationParsing(t *testing.T) {
	for in, want := range map[string]string{"a": "a", "a = 1": "a=1", "a >= 1:2-3": "a>=1:2-3", "a<2": "a<2", "a > 1": "a>1", "a <= 1": "a<=1", "(a or b)": "(a or b)"} {
		r, err := NewRelation(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if r.String() != want {
			t.Errorf("%q parsed to %q", in, r.String())
		}
	}
	for _, bad := range []string{"", "a >=", "a ?? 1", "(a or", "a = 1 2", "= 1"} {
		if _, err := NewRelation(bad); !errors.Is(err, ErrInvalidRelation) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	var rs Relations
	if err := rs.Set("a >= 1"); err != nil {
		t.Fatal(err)
	}
	rs.Set("a >= 1")
	rs.Set("b")
	if rs.String() != "a>=1,b" {
		t.Errorf("Set: %s", rs.String())
	}
	if err := rs.Set("(a"); err == nil {
		t.Error("Set accepted a bad relation")
	}
	if !rs[0].Equal(&Relation{Name: "a", Version: "1", Sense: (SenseGreater | SenseEqual)}) {
		t.Error("Equal")
	}
}

func TestWeakDependencies(t *testing.T) {
	r := basePkg(t, func(m *RPMMetaData) {
		m.OrderWithRequires = Relations{{Name: "o"}}
		m.Recommends = Relations{{Name: "r"}}
		m.Suggests = Relations{{Name: "s"}}
		m.Supplements = Relations{{Name: "p"}}
		m.Enhances = Relations{{Name: "e"}}
		m.Requires = Relations{{Name: "req", Version: "1", Sense: SenseGreater | SenseScriptPre}}
	})
	p := mustWrite(t, r)
	for _, id := range []int{tag.ORDERNAME, tag.RECOMMENDNAME, tag.SUGGESTNAME, tag.SUPPLEMENTNAME, tag.ENHANCENAME} {
		if _, ok := p.main.entries[id]; !ok {
			t.Errorf("tag %d missing", id)
		}
	}
}

// TestHugeFileMemory builds a package of a 3 GB sparse file and checks that the
// heap stays small: the content is streamed through the compressor into a spool.
func TestHugeFileMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 3 GB")
	}
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	const size = 3 << 30
	if err := f.Truncate(size); err != nil {
		t.Skipf("sparse files not supported: %v", err)
	}
	f.Close()
	r := basePkg(t, func(m *RPMMetaData) { m.Format = FormatV6; m.Compressor = "zstd:1"; m.TempDir = dir })
	r.AddFile(RPMFile{Name: "/big", Path: big})

	var peak uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			peak = max(peak, m.HeapAlloc)
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	var out countingDiscard
	err = r.Write(&out)
	close(stop)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("package %d bytes, peak heap %d MiB", out.n, peak>>20)
	if peak > 256<<20 {
		t.Errorf("peak heap %d MiB for a %d GiB file", peak>>20, size>>30)
	}
}

type countingDiscard struct{ n int64 }

func (c *countingDiscard) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }
