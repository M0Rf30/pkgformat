package pacman

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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

func TestParseConfig(t *testing.T) {
	t.Parallel()

	resolve := func(inc string) ([]string, error) {
		if inc != "/mirrors/list" {
			t.Errorf("unexpected include %q", inc)
		}

		return []string{"https://m1.example/$repo/os/$arch"}, nil
	}

	cfg, err := ParseConfig(strings.NewReader(sampleConf), resolve)
	if err != nil {
		t.Fatal(err)
	}

	want := &Config{Architecture: "x86_64", Repos: []Repo{
		{Name: "core", Servers: []string{"https://m1.example/$repo/os/$arch", "https://direct.example/$repo/os/$arch/"}},
		{Name: "extra", Servers: []string{"https://extra.example/$repo/os/$arch"}},
	}}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("config = %+v, want %+v", cfg, want)
	}
}

func TestParseConfigIncludeWithoutResolverIsSkipped(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfig(strings.NewReader("[core]\nInclude = /x\nServer = s\n"), nil)
	if err != nil || len(cfg.Repos) != 1 || !reflect.DeepEqual(cfg.Repos[0].Servers, []string{"s"}) {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}
}

func TestParseConfigResolverError(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")

	_, err := ParseConfig(strings.NewReader("[core]\nInclude = /x\n"), func(string) ([]string, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseConfigLimits(t *testing.T) {
	t.Parallel()

	for name, in := range map[string]string{
		"empty section": "[]\n",
		"too large":     strings.Repeat("#", MaxConfigBytes+1),
		"repos":         strings.Repeat("[r]\n", MaxConfigRepos+1),
		"servers":       "[r]\n" + strings.Repeat("Server = s\n", MaxConfigServers+1),
	} {
		if _, err := ParseConfig(strings.NewReader(in), nil); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	if _, err := ParseMirrorlist(strings.NewReader(strings.Repeat("Server = s\n", MaxConfigServers+1))); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("mirrorlist servers: err = %v", err)
	}
}

func TestParseConfigEmptyInputs(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "# only comments\n\n   \n", "[options]\nArchitecture=auto\n"} {
		cfg, err := ParseConfig(strings.NewReader(in), nil)
		if err != nil || len(cfg.Repos) != 0 {
			t.Errorf("%q: %+v, %v", in, cfg, err)
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
}

func TestParseConfigFileWithGlobInclude(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "mirrors", "a.list"), "Server = https://a.example/$repo\n")
	mustWrite(t, filepath.Join(dir, "mirrors", "b.list"), "Server = https://b.example/$repo\n")
	mustWrite(t, filepath.Join(dir, "single"), "Server = https://s.example/$repo\n")
	mustWrite(t, filepath.Join(dir, "pacman.conf"),
		"[options]\nArchitecture = auto\n[core]\nInclude = "+filepath.Join(dir, "mirrors", "*.list")+"\n[extra]\nInclude = "+filepath.Join(dir, "single")+"\n")

	cfg, err := ParseConfigFile(filepath.Join(dir, "pacman.conf"))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Architecture != "auto" || len(cfg.Repos) != 2 ||
		!reflect.DeepEqual(cfg.Repos[0].Servers, []string{"https://a.example/$repo", "https://b.example/$repo"}) ||
		!reflect.DeepEqual(cfg.Repos[1].Servers, []string{"https://s.example/$repo"}) {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestParseConfigFileErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if _, err := ParseConfigFile(filepath.Join(dir, "missing.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing config: %v", err)
	}

	mustWrite(t, filepath.Join(dir, "bad.conf"), "[core]\nInclude = "+filepath.Join(dir, "nope")+"\n")

	if _, err := ParseConfigFile(filepath.Join(dir, "bad.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing include: %v", err)
	}

	mustWrite(t, filepath.Join(dir, "badglob.conf"), "[core]\nInclude = "+dir+"/[\n")

	if _, err := ParseConfigFile(filepath.Join(dir, "badglob.conf")); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("bad glob: %v", err)
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
