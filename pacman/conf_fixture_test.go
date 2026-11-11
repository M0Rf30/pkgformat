package pacman

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The fixtures under testdata/conf are parsed here and compared with what the
// real pacman-conf printed for them (see testdata/conf/generate.sh): every
// option of [options] and every repository, field by field.

const confFixtureDir = "testdata/conf"

// confSection is one section of a pacman-conf dump: the directive values in
// the order printed, by name. Flag directives have an empty value.
type confSection struct {
	name   string
	values map[string][]string
}

func parsePacmanConfDump(t *testing.T, text string) []confSection {
	t.Helper()

	var out []confSection

	for line := range strings.Lines(text) {
		line = strings.TrimSuffix(line, "\n")

		if name, ok := strings.CutPrefix(line, "["); ok && strings.HasSuffix(line, "]") {
			out = append(out, confSection{name: strings.TrimSuffix(name, "]"), values: map[string][]string{}})

			continue
		}

		if len(out) == 0 {
			t.Fatalf("directive before a section: %q", line)
		}

		key, val, _ := strings.Cut(line, " = ")
		key = strings.TrimSuffix(key, " =") // "Server = " with an empty value

		cur := &out[len(out)-1]
		cur.values[key] = append(cur.values[key], val)
	}

	return out
}

// dumpOf renders a Config the way pacman-conf prints it, for a host whose
// architecture is arch.
func dumpOf(c *Config, goarch string) []confSection {
	opts := confSection{name: "options", values: map[string][]string{}}
	add := func(key string, vals ...string) {
		if len(vals) > 0 {
			opts.values[key] = append(opts.values[key], vals...)
		}
	}
	flag := func(key string, on bool) {
		if on {
			add(key, "")
		}
	}
	str := func(key, v string) {
		if v != "" {
			add(key, v)
		}
	}

	add("RootDir", c.RootDir)
	add("DBPath", c.DBPath)
	add("CacheDir", c.CacheDirs...)
	add("HookDir", c.HookDirs...)
	add("GPGDir", c.GPGDir)
	add("LogFile", c.LogFile)
	str("DownloadUser", c.DownloadUser)
	add("HoldPkg", c.HoldPkg...)
	add("IgnorePkg", c.IgnorePkg...)
	add("IgnoreGroup", c.IgnoreGroup...)
	add("NoUpgrade", c.NoUpgrade...)
	add("NoExtract", c.NoExtract...)
	add("Architecture", c.AllowedArchitectures(goarch)...)
	str("XferCommand", c.XferCommand)
	flag("UseSyslog", c.UseSyslog)
	flag("Color", c.Color)
	flag("CheckSpace", c.CheckSpace)
	flag("VerbosePkgLists", c.VerbosePkgLists)
	flag("DisableDownloadTimeout", c.DisableDownloadTimeout)
	flag("ILoveCandy", c.ILoveCandy)
	flag("NoProgressBar", c.NoProgressBar)
	flag("DisableSandboxFilesystem", c.DisableSandboxFilesystem)
	flag("DisableSandboxSyscalls", c.DisableSandboxSyscalls)
	add("ParallelDownloads", strconv.Itoa(c.ParallelDownloads))
	add("CleanMethod", strings.Fields(c.CleanMethod.String())...)
	add("SigLevel", c.SigLevel.Tokens()...)

	out := []confSection{opts}

	for _, r := range c.Repos {
		sec := confSection{name: r.Name, values: map[string][]string{}}
		sec.values["Usage"] = strings.Fields(r.Usage.String())
		sec.values["SigLevel"] = r.SigLevel.Tokens()

		expand := func(servers []string) []string {
			var got []string

			for _, s := range servers {
				s = strings.ReplaceAll(s, "$repo", r.Name)
				got = append(got, strings.ReplaceAll(s, "$arch", c.Arch(goarch)))
			}

			return got
		}

		if len(r.CacheServers) > 0 {
			sec.values["CacheServer"] = expand(r.CacheServers)
		}

		if len(r.Servers) > 0 {
			sec.values["Server"] = expand(r.Servers)
		}

		out = append(out, sec)
	}

	return out
}

// fixtureNames returns the fixtures with an expected dump, sorted.
func fixtureNames(t *testing.T) []string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(confFixtureDir, "expected", "*.txt"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}

	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = strings.TrimSuffix(filepath.Base(m), ".txt")
	}

	return names
}

func readFixture(t *testing.T, rel string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(confFixtureDir, rel))
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

func TestPacmanConfDifferential(t *testing.T) {
	t.Parallel()

	fsys := os.DirFS(confFixtureDir)

	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := ParseConfigFS(fsys, name+".conf", ParseOptions{})
			if err != nil {
				t.Fatal(err)
			}

			got := dumpOf(cfg, "amd64")
			want := parsePacmanConfDump(t, readFixture(t, "expected/"+name+".txt"))

			// pacman-conf prints LocalFileSigLevel and RemoteFileSigLevel only
			// when the file sets them, and only the package part.
			for _, f := range []struct {
				key   string
				level SigLevel
			}{{"LocalFileSigLevel", cfg.LocalFileSigLevel}, {"RemoteFileSigLevel", cfg.RemoteFileSigLevel}} {
				printed, set := want[0].values[f.key]
				if !set {
					if f.level != cfg.SigLevel {
						t.Errorf("%s differs from SigLevel though unset", f.key)
					}

					continue
				}

				got[0].values[f.key] = f.level.Package.words("Package")

				if !reflect.DeepEqual(got[0].values[f.key], printed) {
					t.Errorf("%s = %v, pacman-conf %v", f.key, got[0].values[f.key], printed)
				}
			}

			if len(got) != len(want) {
				t.Fatalf("%d sections, pacman-conf %d", len(got), len(want))
			}

			for i := range want {
				if got[i].name != want[i].name {
					t.Fatalf("section %d is [%s], pacman-conf [%s]", i, got[i].name, want[i].name)
				}

				// A repository's SigLevel is printed only when the file sets it;
				// otherwise it is the global one.
				if _, set := want[i].values["SigLevel"]; i > 0 && !set {
					if cfg.Repos[i-1].SigLevel != cfg.SigLevel {
						t.Errorf("[%s] SigLevel %v differs from the global %v though unset", want[i].name, cfg.Repos[i-1].SigLevel, cfg.SigLevel)
					}

					delete(got[i].values, "SigLevel")
				}

				for _, key := range unionKeys(got[i].values, want[i].values) {
					g, w := got[i].values[key], want[i].values[key]
					if !reflect.DeepEqual(g, w) {
						t.Errorf("[%s] %s = %q, pacman-conf %q", want[i].name, key, g, w)
					}
				}
			}

			names := strings.Fields(readFixture(t, "expected/"+name+".repos"))
			if len(names) != len(cfg.Repos) {
				t.Fatalf("repo list %v, got %d repositories", names, len(cfg.Repos))
			}

			for i, r := range cfg.Repos {
				// pacman-conf --repo-list does not print names with a space.
				if names[i] != r.Name && !strings.ContainsAny(r.Name, " ") {
					t.Errorf("repository %d is %q, pacman-conf %q", i, r.Name, names[i])
				}
			}
		})
	}
}

func unionKeys(a, b map[string][]string) []string {
	seen := map[string]bool{}

	var keys []string

	for _, m := range []map[string][]string{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true

				keys = append(keys, k)
			}
		}
	}

	return keys
}

var warnRE = regexp.MustCompile(`^warning: config file (\S+), line (\d+): directive '(.*)' in section '(.*)' not recognized\.$`)

func TestPacmanConfUnknownDirectives(t *testing.T) {
	t.Parallel()

	fsys := os.DirFS(confFixtureDir)

	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := ParseConfigFS(fsys, name+".conf", ParseOptions{})
			if err != nil {
				t.Fatal(err)
			}

			var want []Directive

			for line := range strings.Lines(readFixture(t, "expected/"+name+".warn")) {
				m := warnRE.FindStringSubmatch(strings.TrimSpace(line))
				if m == nil {
					t.Fatalf("unexpected pacman-conf warning %q", line)
				}

				want = append(want, Directive{Section: m[4], Key: m[3]})
			}

			got := make([]Directive, len(cfg.Unknown))
			for i, d := range cfg.Unknown {
				got[i] = Directive{Section: d.Section, Key: d.Key}
			}

			if !slices.Equal(got, want) {
				t.Errorf("unknown = %+v, pacman-conf warned about %+v", got, want)
			}

			_, strictErr := ParseConfigFS(fsys, name+".conf", ParseOptions{Strict: true})
			if (len(want) > 0) != errors.Is(strictErr, ErrUnknownDirective) {
				t.Errorf("strict err = %v with %d unknown directives", strictErr, len(want))
			}
		})
	}
}

// Includes in the fixtures are relative to the directory: the host file
// system variant, run from there, must agree with the fs.FS one.
func TestParseConfigFileMatchesFS(t *testing.T) { //nolint:paralleltest // changes the working directory
	names := fixtureNames(t)

	t.Chdir(confFixtureDir)

	fsys := os.DirFS(".")

	for _, name := range names {
		fromFS, err := ParseConfigFS(fsys, name+".conf", ParseOptions{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		fromFile, err := ParseConfigFile(name+".conf", ParseOptions{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if !reflect.DeepEqual(fromFile, fromFS) {
			t.Errorf("%s: ParseConfigFile and ParseConfigFS disagree", name)
		}
	}
}

var invalidWhy = map[string]error{
	"include_missing":      fs.ErrNotExist,
	"include_glob_nothing": fs.ErrNotExist,
	"include_loop":         ErrConfigLimit,
	"include_depth":        ErrConfigLimit,
}

func TestPacmanConfInvalid(t *testing.T) {
	t.Parallel()

	fsys := os.DirFS(confFixtureDir)

	matches, err := filepath.Glob(filepath.Join(confFixtureDir, "expected", "invalid", "*.err"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no invalid fixtures: %v", err)
	}

	for _, m := range matches {
		name := strings.TrimSuffix(filepath.Base(m), ".err")

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// pacman-conf rejected the file; so must the parser.
			_, err := ParseConfigFS(fsys, "invalid/"+name+".conf", ParseOptions{})
			if !errors.Is(err, ErrInvalidConfig) && !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("err = %v", err)
			}

			if why, ok := invalidWhy[name]; ok && !errors.Is(err, why) {
				t.Errorf("err = %v, want %v", err, why)
			}
		})
	}
}

// The deepest include chain pacman accepts (ten levels) parses.
func TestPacmanConfIncludeDepth(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfigFS(os.DirFS(confFixtureDir), "depth10.conf", ParseOptions{})
	if err != nil || len(cfg.Repos) != 1 || len(cfg.Repos[0].Servers) != 1 {
		t.Fatalf("depth10: %+v, %v", cfg, err)
	}

	if _, err := ParseConfigFS(os.DirFS(confFixtureDir), "depth10.conf", ParseOptions{MaxIncludeDepth: 9}); !errors.Is(err, ErrConfigLimit) {
		t.Errorf("depth 9 allowed ten levels: %v", err)
	}
}

// Spot checks on the parsed values, independent of the dumps.
func TestPacmanConfFullFixture(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfigFS(os.DirFS(confFixtureDir), "full.conf", ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ParallelDownloads != 5 || cfg.DownloadUser != "alpm" || cfg.CleanMethod != CleanKeepInstalled|CleanKeepCurrent ||
		!cfg.DisableSandboxFilesystem || !cfg.DisableSandboxSyscalls || cfg.XferCommand == "" {
		t.Errorf("options = %+v", cfg)
	}

	if !cfg.IsHeld("linux-zen") || !cfg.IsHeld("included-held") || cfg.IsHeld("bash") {
		t.Error("HoldPkg across the include")
	}

	if !cfg.IsIgnored("gcc") || !cfg.IsIgnored("hcc") || cfg.IsIgnored("icc") || !cfg.IsIgnored("x", "kde-games") {
		t.Error("ignore patterns")
	}

	names := make([]string, len(cfg.Repos))
	for i, r := range cfg.Repos {
		names[i] = r.Name
	}

	if !reflect.DeepEqual(names, []string{"custom", "core", "extra", "multilib"}) {
		t.Errorf("repositories = %v", names)
	}

	multilib := cfg.Repos[3]
	if len(multilib.CacheServers) != 2 || multilib.Usage != UsageInstall|UsageUpgrade ||
		multilib.SigLevel.Database.Check != SigNever || multilib.SigLevel.Package.Trust != SigTrustAll {
		t.Errorf("multilib = %+v", multilib)
	}

	if cfg.Repos[1].SigLevel != DefaultSigLevel() && cfg.Repos[1].SigLevel.Database.Check != SigRequired {
		t.Errorf("core SigLevel = %v", cfg.Repos[1].SigLevel)
	}
}
