package pacman

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

const sampleConf = `
# a comment
[options]
Architecture = x86_64
HoldPkg = pacman glibc
Server = http://ignored.example/outside-repo

[core]
Include = /mirrors/list
Server = https://direct.example/$repo/os/$arch/

[extra]
SigLevel = Required
Server = https://extra.example/$repo/os/$arch
not a key value line
`

func mirrorsResolver(t *testing.T) IncludeResolver {
	t.Helper()

	return func(inc string) ([]IncludeFile, error) {
		if inc != "/mirrors/list" {
			t.Errorf("unexpected include %q", inc)
		}

		return []IncludeFile{IncludeText(inc, "Server = https://m1.example/$repo/os/$arch\n")}, nil
	}
}

func TestParseConfig(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfig(strings.NewReader(sampleConf), ParseOptions{Include: mirrorsResolver(t)})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(cfg.Architectures, []string{"x86_64"}) || !reflect.DeepEqual(cfg.HoldPkg, []string{"pacman", "glibc"}) {
		t.Errorf("options = %+v", cfg)
	}

	want := []Repo{
		{
			Name:     "core",
			Servers:  []string{"https://m1.example/$repo/os/$arch", "https://direct.example/$repo/os/$arch/"},
			SigLevel: DefaultSigLevel(),
		},
		{
			Name:     "extra",
			Servers:  []string{"https://extra.example/$repo/os/$arch"},
			SigLevel: DefaultSigLevel(),
		},
	}
	if !reflect.DeepEqual(cfg.Repos, want) {
		t.Errorf("repos = %+v, want %+v", cfg.Repos, want)
	}

	wantUnknown := []Directive{
		{Section: "options", Key: "Server", Value: "http://ignored.example/outside-repo"},
		{Section: "extra", Key: "not a key value line"},
	}
	if !reflect.DeepEqual(cfg.Unknown, wantUnknown) {
		t.Errorf("unknown = %+v, want %+v", cfg.Unknown, wantUnknown)
	}
}

func TestParseConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfig(strings.NewReader("[options]\n"), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}

	want := &Config{
		RootDir: "/", DBPath: "/var/lib/pacman/", CacheDirs: []string{"/var/cache/pacman/pkg/"},
		HookDirs: []string{"/etc/pacman.d/hooks/"}, GPGDir: "/etc/pacman.d/gnupg/", LogFile: "/var/log/pacman.log",
		CleanMethod: CleanKeepInstalled, ParallelDownloads: 1,
		SigLevel: DefaultSigLevel(), LocalFileSigLevel: DefaultSigLevel(), RemoteFileSigLevel: DefaultSigLevel(),
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("defaults = %+v, want %+v", cfg, want)
	}

	cfg, err = ParseConfig(strings.NewReader("[options]\nRootDir = /mnt/sys/\nLogFile =\n"), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.RootDir != "/mnt/sys" || cfg.DBPath != "/mnt/sys/var/lib/pacman/" || cfg.LogFile != "/mnt/sys/var/log/pacman.log" ||
		cfg.GPGDir != "/etc/pacman.d/gnupg/" {
		t.Errorf("root-relative defaults = %+v", cfg)
	}
}

func TestParseConfigIncludeWithoutResolverIsSkipped(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfig(strings.NewReader("[core]\nInclude = /x\nServer = s\n"), ParseOptions{})
	if err != nil || len(cfg.Repos) != 1 || !reflect.DeepEqual(cfg.Repos[0].Servers, []string{"s"}) {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}
}

func TestParseConfigResolverErrors(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")

	_, err := ParseConfig(strings.NewReader("[core]\nInclude = /x\n"), ParseOptions{
		Include: func(string) ([]IncludeFile, error) { return nil, boom },
	})
	if !errors.Is(err, boom) {
		t.Fatalf("resolver error: %v", err)
	}

	_, err = ParseConfig(strings.NewReader("[core]\nInclude = /x\n"), ParseOptions{
		Include: func(string) ([]IncludeFile, error) {
			return []IncludeFile{{Name: "x", Open: func() (io.ReadCloser, error) { return nil, boom }}}, nil
		},
	})
	if !errors.Is(err, boom) {
		t.Fatalf("open error: %v", err)
	}
}

func TestParseConfigIncludeSharesSection(t *testing.T) {
	t.Parallel()

	files := map[string]string{
		"opts":  "Color\nHoldPkg = held\n",
		"repos": "[inner]\nServer = https://inner.example\n",
	}
	resolve := func(inc string) ([]IncludeFile, error) { return []IncludeFile{IncludeText(inc, files[inc])}, nil }

	cfg, err := ParseConfig(strings.NewReader(
		"[options]\nInclude = opts\n[core]\nServer = s0\nInclude = repos\nServer = after\n"), ParseOptions{Include: resolve})
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.Color || !reflect.DeepEqual(cfg.HoldPkg, []string{"held"}) {
		t.Errorf("options from include: %+v", cfg)
	}

	if len(cfg.Repos) != 2 || !reflect.DeepEqual(cfg.Repos[0].Servers, []string{"s0"}) ||
		!reflect.DeepEqual(cfg.Repos[1].Servers, []string{"https://inner.example", "after"}) {
		t.Errorf("repos = %+v", cfg.Repos)
	}
}

func TestParseConfigIncludeLimits(t *testing.T) {
	t.Parallel()

	self := func(inc string) ([]IncludeFile, error) {
		return []IncludeFile{IncludeText(inc, "Include = again\n")}, nil
	}

	for name, opts := range map[string]ParseOptions{
		"default depth": {Include: self},
		"custom depth":  {Include: self, MaxIncludeDepth: 3},
		"files": {
			Include: func(inc string) ([]IncludeFile, error) {
				return []IncludeFile{IncludeText("a", ""), IncludeText("b", ""), IncludeText("c", "")}, nil
			},
			MaxIncludeFiles: 2,
		},
	} {
		if _, err := ParseConfig(strings.NewReader("[core]\nInclude = start\n"), opts); !errors.Is(err, ErrConfigLimit) ||
			!errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	// Ten nested includes are fine, eleven are not; the depth is configurable.
	depth := 0
	chain := func(inc string) ([]IncludeFile, error) {
		depth++

		return []IncludeFile{IncludeText(inc, "Include = next\n")}, nil
	}

	if _, err := ParseConfig(strings.NewReader("[core]\nInclude = start\n"), ParseOptions{Include: chain}); err == nil || depth != DefaultMaxIncludeDepth {
		t.Errorf("default depth reached %d, err = %v", depth, err)
	}

	// The total size across files is bounded.
	big := strings.Repeat("#"+strings.Repeat("x", 1<<20)+"\n", 3)
	bigs := func(inc string) ([]IncludeFile, error) {
		files := make([]IncludeFile, 12)
		for i := range files {
			files[i] = IncludeText("big", big)
		}

		return files, nil
	}

	if _, err := ParseConfig(strings.NewReader("[core]\nInclude = start\n"), ParseOptions{Include: bigs}); !errors.Is(err, ErrConfigLimit) {
		t.Errorf("total bytes: err = %v", err)
	}
}

func TestParseConfigLimits(t *testing.T) {
	t.Parallel()

	for name, in := range map[string]string{
		"empty section": "[]\n",
		"too large":     strings.Repeat("#", MaxConfigBytes+1),
		"repos":         strings.Repeat("[r]\n", MaxConfigRepos+1),
		"servers":       "[r]\n" + strings.Repeat("Server = s\n", MaxConfigServers+1),
		"cache servers": "[r]\n" + strings.Repeat("CacheServer = s\n", MaxConfigServers+1),
		"values":        "[options]\n" + strings.Repeat("IgnorePkg = a\n", MaxConfigValues+1),
		"unknown":       "[options]\n" + strings.Repeat("Foo\n", MaxConfigValues+1),
	} {
		if _, err := ParseConfig(strings.NewReader(in), ParseOptions{}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	if _, err := ParseMirrorlist(strings.NewReader(strings.Repeat("Server = s\n", MaxConfigServers+1))); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("mirrorlist servers: err = %v", err)
	}

	if _, err := ParseMirrorlist(strings.NewReader(strings.Repeat("#", MaxConfigBytes+1))); !errors.Is(err, ErrConfigLimit) {
		t.Errorf("mirrorlist size: err = %v", err)
	}
}

func TestParseConfigInvalidValues(t *testing.T) {
	t.Parallel()

	for name, in := range map[string]string{
		"outside section":   "Color\n",
		"include no value":  "[core]\nInclude\n",
		"include empty":     "[core]\nInclude =\n",
		"parallel zero":     "[options]\nParallelDownloads = 0\n",
		"parallel negative": "[options]\nParallelDownloads = -1\n",
		"parallel text":     "[options]\nParallelDownloads = x\n",
		"parallel huge":     "[options]\nParallelDownloads = 99999999999\n",
		"parallel int64":    "[options]\nParallelDownloads = 99999999999999999999\n",
		"clean method":      "[options]\nCleanMethod = Nope\n",
		"siglevel":          "[options]\nSigLevel = Nope\n",
		"local siglevel":    "[options]\nLocalFileSigLevel = Nope\n",
		"remote siglevel":   "[options]\nRemoteFileSigLevel = Nope\n",
		"repo siglevel":     "[core]\nSigLevel = Nope\n",
		"repo no value":     "[core]\nServer\n",
		"usage":             "[core]\nUsage = Nope\n",
		"server control":    "[core]\nServer = a\rb\n",
		"cache control":     "[core]\nCacheServer = a\x00b\n",
	} {
		_, err := ParseConfig(strings.NewReader(in), ParseOptions{Include: func(string) ([]IncludeFile, error) { return nil, nil }})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	_, err := ParseConfig(strings.NewReader("[options]\nSigLevel = Nope\n"), ParseOptions{})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "pacman.conf:2") {
		t.Errorf("error lacks its position: %v", err)
	}
}

func TestParseConfigStrict(t *testing.T) {
	t.Parallel()

	if _, err := ParseConfig(strings.NewReader("[options]\nBogus = 1\n"), ParseOptions{Strict: true}); !errors.Is(err, ErrUnknownDirective) ||
		!errors.Is(err, ErrInvalidConfig) {
		t.Errorf("strict: err = %v", err)
	}

	cfg, err := ParseConfig(strings.NewReader("[options]\nBogus = 1\n"), ParseOptions{})
	if err != nil || len(cfg.Unknown) != 1 {
		t.Errorf("lenient: %+v, %v", cfg, err)
	}

	// Valid directives are not unknown in strict mode, whatever the section.
	strict := "[options]\nColor\nDisableSandbox\nDisableSandboxFilesystem\nDisableSandboxSyscalls\nUseSyslog\n" +
		"CheckSpace\nVerbosePkgLists\nILoveCandy\nNoProgressBar\nDisableDownloadTimeout\nDownloadUser = a\n" +
		"[core]\nServer = s\n"
	if _, err := ParseConfig(strings.NewReader(strict), ParseOptions{Strict: true}); err != nil {
		t.Errorf("strict, valid: %v", err)
	}
}

func TestParseConfigFlagsAndSandbox(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfig(strings.NewReader("[options]\nDisableSandboxFilesystem\nParallelDownloads = 4\nCleanMethod =\n"), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.DisableSandboxFilesystem || cfg.DisableSandboxSyscalls || cfg.ParallelDownloads != 4 || cfg.CleanMethod != CleanKeepInstalled {
		t.Errorf("cfg = %+v", cfg)
	}

	cfg, err = ParseConfig(strings.NewReader("[options]\nDisableSandbox\n"), ParseOptions{})
	if err != nil || !cfg.DisableSandboxFilesystem || !cfg.DisableSandboxSyscalls {
		t.Errorf("DisableSandbox: %+v, %v", cfg, err)
	}
}

func TestCleanMethodString(t *testing.T) {
	t.Parallel()

	for m, want := range map[CleanMethod]string{
		0: "", CleanKeepInstalled: "KeepInstalled", CleanKeepCurrent: "KeepCurrent",
		CleanKeepInstalled | CleanKeepCurrent: "KeepInstalled KeepCurrent",
	} {
		if got := m.String(); got != want {
			t.Errorf("CleanMethod(%d) = %q, want %q", m, got, want)
		}
	}
}

func TestParseMirrorlist(t *testing.T) {
	t.Parallel()

	got, err := ParseMirrorlist(strings.NewReader("## Germany\n#Server = https://off.example/$repo\n\nServer = https://a.example/$repo/os/$arch\nOther = x\nServer=https://b.example\n"))
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"https://a.example/$repo/os/$arch", "https://b.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("servers = %v, want %v", got, want)
	}

	got, err = ParseMirrorlist(strings.NewReader(""))
	if err != nil || len(got) != 0 {
		t.Errorf("empty: %v, %v", got, err)
	}

	// A CRLF file is fine; a carriage return inside a value is not.
	got, err = ParseMirrorlist(strings.NewReader("Server = https://a.example\r\n"))
	if err != nil || len(got) != 1 || got[0] != "https://a.example" {
		t.Errorf("CRLF: %v, %v", got, err)
	}

	if _, err := ParseMirrorlist(strings.NewReader("Server = a\rb\n")); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("control character: %v", err)
	}
}

func TestParseConfigFileWithGlobAndNestedInclude(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "mirrors", "a.list"), "Server = https://a.example/$repo\n")
	mustWrite(t, filepath.Join(dir, "mirrors", "b.list"), "Server = https://b.example/$repo\nInclude = "+filepath.Join(dir, "single")+"\n")
	mustWrite(t, filepath.Join(dir, "single"), "Server = https://s.example/$repo\n")
	mustWrite(t, filepath.Join(dir, "general.conf"), "Color\n[extra]\nServer = https://e.example/$repo\n")
	mustWrite(t, filepath.Join(dir, "pacman.conf"),
		"[options]\nArchitecture = auto\nInclude = "+filepath.Join(dir, "general.conf")+"\n"+
			"[core]\nInclude = "+filepath.Join(dir, "mirrors", "*.list")+"\n")

	cfg, err := ParseConfigFile(filepath.Join(dir, "pacman.conf"), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.Color || !reflect.DeepEqual(cfg.Architectures, []string{"auto"}) || len(cfg.Repos) != 2 {
		t.Fatalf("cfg = %+v", cfg)
	}

	// The include in [options] opened [extra], so [core] follows it.
	if cfg.Repos[0].Name != "extra" || !reflect.DeepEqual(cfg.Repos[0].Servers, []string{"https://e.example/$repo"}) ||
		!reflect.DeepEqual(cfg.Repos[1].Servers, []string{"https://a.example/$repo", "https://b.example/$repo", "https://s.example/$repo"}) {
		t.Errorf("repos = %+v", cfg.Repos)
	}
}

func TestParseConfigFileErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if _, err := ParseConfigFile(filepath.Join(dir, "missing.conf"), ParseOptions{}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing config: %v", err)
	}

	mustWrite(t, filepath.Join(dir, "bad.conf"), "[core]\nInclude = "+filepath.Join(dir, "nope")+"\n")

	if _, err := ParseConfigFile(filepath.Join(dir, "bad.conf"), ParseOptions{}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing include: %v", err)
	}

	mustWrite(t, filepath.Join(dir, "none.conf"), "[core]\nInclude = "+filepath.Join(dir, "*.nothing")+"\n")

	if _, err := ParseConfigFile(filepath.Join(dir, "none.conf"), ParseOptions{}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("glob matching nothing: %v", err)
	}

	mustWrite(t, filepath.Join(dir, "badglob.conf"), "[core]\nInclude = "+dir+"/[\n")

	if _, err := ParseConfigFile(filepath.Join(dir, "badglob.conf"), ParseOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("bad glob: %v", err)
	}

	mustWrite(t, filepath.Join(dir, "loop.conf"), "[core]\nInclude = "+filepath.Join(dir, "loop.conf")+"\n")

	if _, err := ParseConfigFile(filepath.Join(dir, "loop.conf"), ParseOptions{}); !errors.Is(err, ErrConfigLimit) {
		t.Errorf("include loop: %v", err)
	}
}

func TestParseConfigFS(t *testing.T) {
	t.Parallel()

	fsys := fstest.MapFS{
		"etc/pacman.conf":          {Data: []byte("[options]\nArchitecture = x86_64\n[core]\nInclude = pacman.d/extra.list\n")},
		"etc/pacman.d/mirrorlist":  {Data: []byte("Server = https://m.example/$repo/os/$arch\n")},
		"etc/pacman.d/extra.list":  {Data: []byte("Server = https://x.example/$repo/os/$arch\n")},
		"etc/pacman.d/escape.conf": {Data: []byte("[core]\nInclude = /../secret\n")},
	}

	cfg, err := ParseConfigFS(fsys, "/etc/pacman.conf", ParseOptions{})
	if err == nil {
		t.Fatalf("relative include resolved against the FS root: %+v", cfg)
	}

	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}

	fsys["etc/pacman.conf"] = &fstest.MapFile{Data: []byte("[options]\nArchitecture = x86_64\n[core]\nInclude = /etc/pacman.d/m*\nInclude = /etc/pacman.d/extra.list\n")}

	cfg, err = ParseConfigFS(fsys, "etc/pacman.conf", ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Repos) != 1 || !reflect.DeepEqual(cfg.Repos[0].Servers,
		[]string{"https://m.example/$repo/os/$arch", "https://x.example/$repo/os/$arch"}) {
		t.Errorf("repos = %+v", cfg.Repos)
	}

	if _, err := ParseConfigFS(fsys, "etc/missing.conf", ParseOptions{}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}

	if _, err := ParseConfigFS(fsys, "../etc/pacman.conf", ParseOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("escaping name: %v", err)
	}

	if _, err := ParseConfigFS(fsys, "etc/pacman.d/escape.conf", ParseOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("escaping include: %v", err)
	}

	fsys["etc/pacman.d/badglob.conf"] = &fstest.MapFile{Data: []byte("[core]\nInclude = /etc/[\n")}

	if _, err := ParseConfigFS(fsys, "etc/pacman.d/badglob.conf", ParseOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("bad glob: %v", err)
	}

	// A custom resolver wins over the FS one.
	cfg, err = ParseConfigFS(fsys, "etc/pacman.conf", ParseOptions{Include: func(inc string) ([]IncludeFile, error) {
		return []IncludeFile{IncludeText(inc, "Server = "+inc+"\n")}, nil
	}})
	if err != nil || len(cfg.Repos[0].Servers) != 2 || cfg.Repos[0].Servers[0] != "/etc/pacman.d/m*" {
		t.Errorf("custom resolver: %+v, %v", cfg, err)
	}
}

func TestExpandServer(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"https://m.example/$repo/os/$arch":    "https://m.example/core/os/x86_64",
		"https://m.example/$arch/$repo///":    "https://m.example/x86_64/core",
		"https://m.example/static":            "https://m.example/static",
		"":                                    "",
		"https://m.example/$repo/$repo/$arch": "https://m.example/core/core/x86_64",
	} {
		if got := ExpandServer(in, "core", "x86_64"); got != want {
			t.Errorf("ExpandServer(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestArchFromGOARCH(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"amd64": "x86_64", "arm64": "aarch64", "arm": "armv7h", "386": "i686", "riscv64": "riscv64", "s390x": "s390x",
	} {
		if got := ArchFromGOARCH(in); got != want {
			t.Errorf("ArchFromGOARCH(%q) = %q, want %q", in, got, want)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
