package dnf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const sampleConf = `# dnf.conf
[main]
gpgcheck=1
repo_gpgcheck=true
installonly_limit=3
install_weak_deps=False
obsoletes=0
best=no
multilib_policy=all
localpkg_gpgcheck=1
exclude=kernel* ,glibc-2.1
excludepkgs=zip
includepkgs=a b
varsdir=/etc/dnf/vars /srv/vars
metadata_expire=6h
cost=500
priority=50
sslverify=0
skip_if_unavailable=1
module_hotfixes=1
countme=1
username=me
password=secret
deltarpm=0
name=ignored
baseurl=https://ignored.example/
enabled=0

[other]
gpgcheck=0
install_weak_deps=1
`

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(sampleConf))
	if err != nil {
		t.Fatal(err)
	}

	d := cfg.Defaults

	if !d.GPGCheck || !d.RepoGPGCheck || d.Priority != 50 || d.Cost != 500 || !d.SkipSSLVerify ||
		!d.SkipIfUnavailable || !d.ModuleHotfixes || !d.CountMe || d.Username != "me" || d.Password != "secret" ||
		d.MetadataExpire != 6*time.Hour {
		t.Errorf("defaults = %+v", d)
	}

	// Options of a single repository are not defaults for all of them.
	if !d.Enabled || len(d.BaseURLs) != 0 || d.Name != "" {
		t.Errorf("per-repository keys leaked into the defaults: %+v", d)
	}

	if cfg.InstallWeakDeps || cfg.Obsoletes || cfg.Best || cfg.MultilibPolicy != MultilibAll || !cfg.LocalPkgGPGCheck {
		t.Errorf("config = %+v", cfg)
	}

	if want := []string{"kernel*", "glibc-2.1", "zip"}; !reflect.DeepEqual(cfg.Exclude, want) {
		t.Errorf("exclude = %v", cfg.Exclude)
	}

	if !reflect.DeepEqual(cfg.IncludePkgs, []string{"a", "b"}) ||
		!reflect.DeepEqual(cfg.VarsDirs, []string{"/etc/dnf/vars", "/srv/vars"}) {
		t.Errorf("includepkgs = %v, varsdirs = %v", cfg.IncludePkgs, cfg.VarsDirs)
	}
}

func TestParseConfigWithoutMainKeepsDnfDefaults(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader("[other]\ngpgcheck=1\n"))
	if err != nil {
		t.Fatal(err)
	}

	want := DefaultConfig()
	if !reflect.DeepEqual(cfg, want) || !cfg.InstallWeakDeps || cfg.Defaults.GPGCheck {
		t.Errorf("config = %+v", cfg)
	}

	// invalid values leave the defaults
	cfg, err = ParseConfig(strings.NewReader("[main]\nmultilib_policy=sometimes\nbest=maybe\nmetadata_expire=soon\ncost=x\n"))
	if err != nil || cfg.MultilibPolicy != MultilibBest || !cfg.Best || cfg.Defaults.MetadataExpire != 48*time.Hour ||
		cfg.Defaults.Cost != defaultCost {
		t.Errorf("config = %+v, %v", cfg, err)
	}
}

func TestParseConfigRejectsHugeLines(t *testing.T) {
	_, err := ParseConfig(strings.NewReader("[main]\nexclude=" + strings.Repeat("a", 2<<20) + "\n"))
	if !errors.Is(err, ErrRepoFileTooLarge) {
		t.Errorf("err = %v", err)
	}
}

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnf.conf")
	if err := os.WriteFile(path, []byte(sampleConf), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil || cfg.Defaults.Cost != 500 {
		t.Fatalf("LoadConfig = %+v, %v", cfg, err)
	}

	if _, err := LoadConfig(path + ".missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v", err)
	}
}

func TestClientConfigSources(t *testing.T) {
	// nothing given: the defaults of dnf
	if cfg, err := New(Options{}).Config(); err != nil || !cfg.InstallWeakDeps {
		t.Errorf("default = %+v, %v", cfg, err)
	}

	// an explicit one wins over a file
	given := &Config{Exclude: []string{"x"}}
	if cfg, _ := New(Options{Config: given, ConfigFile: "/does/not/exist"}).Config(); cfg != given {
		t.Error("Options.Config was not used")
	}

	// a file that cannot be read is an error everywhere the config is needed
	c := New(Options{ConfigFile: "/does/not/exist", RepoDir: t.TempDir()})
	if _, err := c.Config(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v", err)
	}

	if _, err := c.Repos(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Repos err = %v", err)
	}
}

func TestRepositoriesInheritTheMainSection(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"), pkgOf("excluded", "1"), pkgOf("b", "1"))

	conf := filepath.Join(t.TempDir(), "dnf.conf")
	main := "[main]\ngpgcheck=0\nexclude=excluded\npriority=7\ncost=10\nmetadata_expire=1h\nskip_if_unavailable=1\n"

	if err := os.WriteFile(conf, []byte(main), 0o600); err != nil {
		t.Fatal(err)
	}

	env := newEnv(t, baseurlSection(repo.url())+"cost=20\n", func(o *Options) { o.ConfigFile = conf })

	repos, err := env.Repos()
	if err != nil || len(repos) != 1 {
		t.Fatalf("repos = %v, %v", repos, err)
	}

	if r := repos[0]; r.Priority != 7 || r.Cost != 20 || r.MetadataExpire != time.Hour || !r.SkipIfUnavailable || r.GPGCheck {
		t.Errorf("repo = %+v", r)
	}

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := ix.Lookup("excluded"); ok || ix.Len() != 2 {
		t.Errorf("the global exclude was not applied: %d names", ix.Len())
	}

	if p, _ := ix.Lookup("a"); p.Priority != 7 || p.Cost != 20 {
		t.Errorf("a = %+v", p)
	}
}

func TestIncludePkgsOfRepositoryAndMain(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"), pkgOf("ab", "1"), pkgOf("b", "1"), pkgOf("c", "1"))
	env := newEnv(t, baseurlSection(repo.url())+"includepkgs=a* b\n", func(o *Options) {
		o.Config = &Config{IncludePkgs: []string{"a", "b", "c"}, Defaults: defaultRepo(), InstallWeakDeps: true}
	})

	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got := pkgNamesOf(ix, "a", "ab", "b", "c"); got != "a b" {
		t.Errorf("index has %q", got)
	}
}

func TestRepoKeys(t *testing.T) {
	const content = `[r]
name=R
baseurl=https://a.example/
type=rpm-md
cost=1
priority=2
proxy=http://proxy.example:3128
proxy_username=pu
proxy_password=pp
username=u
password=p
sslverify=false
sslcacert=/ca.pem
sslclientcert=/cert.pem
sslclientkey=/key.pem
module_hotfixes=yes
skip_if_unavailable=true
metadata_expire=never
countme=on
enabled_metadata=filelists, other
deltarpm=1
deltarpm_percentage=0
repo_gpgcheck=1
includepkgs=a b
includepkgs=c
excludepkgs=x
exclude=y
`

	repos, err := ParseRepoFile(strings.NewReader(content))
	if err != nil || len(repos) != 1 {
		t.Fatal(repos, err)
	}

	want := Repo{
		ID: "r", Name: "R", Type: "rpm-md", BaseURLs: []string{"https://a.example/"}, Enabled: true,
		Cost: 1, Priority: 2, Proxy: "http://proxy.example:3128", ProxyUsername: "pu", ProxyPassword: "pp",
		Username: "u", Password: "p", SkipSSLVerify: true, SSLCACert: "/ca.pem", SSLClientCert: "/cert.pem",
		SSLClientKey: "/key.pem", ModuleHotfixes: true, SkipIfUnavailable: true, MetadataExpire: MetadataExpireNever,
		CountMe: true, EnabledMetadata: []string{"filelists", "other"}, RepoGPGCheck: true,
		IncludePkgs: []string{"c"}, Exclude: []string{"x", "y"},
	}

	if !reflect.DeepEqual(repos[0], want) {
		t.Errorf("repo = %+v\nwant   %+v", repos[0], want)
	}
}

func TestMetadataExpireForms(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"90":    90 * time.Second,
		"90s":   90 * time.Second,
		"2m":    2 * time.Minute,
		"6h":    6 * time.Hour,
		"2d":    48 * time.Hour,
		"0":     0,
		"never": MetadataExpireNever,
		"-1":    MetadataExpireNever,
		" 1H ":  time.Hour,
	} {
		if got, ok := parseExpire(in); !ok || got != want {
			t.Errorf("parseExpire(%q) = %v, %v, want %v", in, got, ok, want)
		}
	}

	for _, in := range []string{"", "x", "5w", "-5", "1.5h", "99999999999999999999d"} {
		if _, ok := parseExpire(in); ok {
			t.Errorf("parseExpire(%q) accepted", in)
		}
	}
}

func TestUnsupportedRepositoryTypeIsSkipped(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	env := newEnv(t, "[rpm]\nbaseurl="+repo.url()+"\ntype=rpm-md\n\n[deb]\nbaseurl="+repo.url()+"\ntype=deb\n")

	repos, err := env.enabledRepos()
	if err != nil || len(repos) != 1 || repos[0].ID != "rpm" {
		t.Errorf("repos = %+v, %v", repos, err)
	}

	for typ, want := range map[string]bool{"": true, "rpm": true, "rpm-md": true, "repomd": true, "rpmmd": true, "RPM-MD": true, "yum": false} {
		if got := (&Repo{Type: typ}).usable(); got != want {
			t.Errorf("type %q usable = %v", typ, got)
		}
	}
}

func TestSkipIfUnavailable(t *testing.T) {
	good := newTestRepo(t, pkgOf("a", "1"))
	bad := newTestRepo(t, pkgOf("b", "1"))
	bad.set("/repodata/repomd.xml", 500)

	section := func(extra string) string {
		return "[good]\nbaseurl=" + good.url() + "\n\n[bad]\nbaseurl=" + bad.url() + "\n" + extra
	}

	if err := newEnv(t, section("")).Update(context.Background()); err == nil {
		t.Error("a failing repository was ignored")
	}

	env := newEnv(t, section("skip_if_unavailable=1\n"))
	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	ix, err := env.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := ix.Lookup("a"); !ok || ix.Len() != 1 {
		t.Errorf("index has %d names", ix.Len())
	}
}

func TestMetadataExpireAndUpdateExpired(t *testing.T) {
	repo := newTestRepo(t, pkgOf("a", "1"))
	now := time.Now()

	env := newEnv(t, baseurlSection(repo.url())+"metadata_expire=1h\n")
	env.now = func() time.Time { return now }

	repos, _ := env.Repos()
	r := &repos[0]

	if !env.Expired(r) {
		t.Error("a repository that was never fetched is not expired")
	}

	// the first call fetches, the second one finds the metadata fresh
	if err := env.UpdateExpired(context.Background()); err != nil {
		t.Fatal(err)
	}

	hits := repo.count("/repodata/repomd.xml")
	if hits == 0 || env.Expired(r) {
		t.Fatalf("hits = %d, expired = %v", hits, env.Expired(r))
	}

	if err := env.UpdateExpired(context.Background()); err != nil || repo.count("/repodata/repomd.xml") != hits {
		t.Errorf("a fresh repository was asked again: %d requests, %v", repo.count("/repodata/repomd.xml"), err)
	}

	// 61 minutes later it is stale
	env.now = func() time.Time { return now.Add(61 * time.Minute) }
	if !env.Expired(r) {
		t.Error("not expired after the metadata_expire")
	}

	if err := env.UpdateExpired(context.Background()); err != nil || repo.count("/repodata/repomd.xml") == hits {
		t.Errorf("an expired repository was not asked: %d requests, %v", repo.count("/repodata/repomd.xml"), err)
	}

	// never expires once cached
	r.MetadataExpire = MetadataExpireNever

	env.now = func() time.Time { return now.Add(10000 * time.Hour) }
	if env.Expired(r) {
		t.Error("metadata_expire=never expired")
	}
}

func TestEnabledMetadataIsFetched(t *testing.T) {
	repo := newTestRepo(t, repoPkgWithListed("a", "/usr/bin/a"))

	env := newEnv(t, baseurlSection(repo.url())+"enabled_metadata=filelists\n")
	if err := env.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	fl := ""

	repo.mu.Lock()
	for p := range repo.files {
		if strings.HasSuffix(p, "-filelists.xml.gz") {
			fl = p
		}
	}
	repo.mu.Unlock()

	if fl == "" || repo.count(fl) != 1 {
		t.Errorf("filelists requested %d times", repo.count(fl))
	}

	// without enabled_metadata it is left for when a file dependency needs it
	repo2 := newTestRepo(t, repoPkgWithListed("a", "/usr/bin/a"))

	env2 := newEnv(t, baseurlSection(repo2.url()))
	if err := env2.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	repo2.mu.Lock()
	for p := range repo2.files {
		if strings.HasSuffix(p, "-filelists.xml.gz") && repo2.hits[p] != 0 {
			t.Errorf("%s fetched by Update", p)
		}
	}
	repo2.mu.Unlock()
}

func TestEnabledMetadataFailureIsOnlyAWarning(t *testing.T) {
	repo := newTestRepo(t, repoPkgWithListed("a", "/usr/bin/a"))
	repo.mu.Lock()
	for p := range repo.files {
		if strings.HasSuffix(p, "-filelists.xml.gz") {
			repo.status[p] = 404
		}
	}
	repo.mu.Unlock()

	env := newEnv(t, baseurlSection(repo.url())+"enabled_metadata=filelists other\n")
	if err := env.Update(context.Background()); err != nil {
		t.Fatalf("Update = %v", err)
	}
}

func repoPkgWithListed(name string, files ...string) repoPkg {
	p := pkgOf(name, "1")
	p.listed = files

	return p
}
