package dnf

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseRepoFile(t *testing.T) {
	const content = `# a comment
[base]
name=Base
baseurl=https://a.example/os https://b.example/os
    https://c.example/os
gpgkey=https://keys.example/key
    https://keys.example/other
enabled=1

[extras]
mirrorlist=https://m.example/list?repo=extras
metalink=https://ignored.example/second
enabled=0

[no-urls]
name=nothing

[../escape]
baseurl=https://evil.example/
`

	repos, err := ParseRepoFile(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}

	want := []Repo{
		{
			ID: "base", Name: "Base", Enabled: true, Priority: 99, Cost: 1000, MetadataExpire: 48 * time.Hour,
			BaseURLs: []string{"https://a.example/os", "https://b.example/os", "https://c.example/os"},
			GPGKeys:  []string{"https://keys.example/key", "https://keys.example/other"},
		},
		{
			ID: "extras", Enabled: false, Priority: 99, Cost: 1000, MetadataExpire: 48 * time.Hour,
			MirrorList: "https://m.example/list?repo=extras",
		},
		{ID: "no-urls", Name: "nothing", Enabled: true, Priority: 99, Cost: 1000, MetadataExpire: 48 * time.Hour},
	}

	if !reflect.DeepEqual(repos, want) {
		t.Errorf("repos = %+v\nwant %+v", repos, want)
	}
}

func TestParseRepoFileEdgeCases(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want int
	}{
		"empty":               {"", 0},
		"only comments":       {"# a\n; b\n", 0},
		"keys before section": {"baseurl=https://x/\n[a]\n", 1},
		"no equals sign":      {"[a]\njunk line\n", 1},
		"unterminated header": {"[a\nbaseurl=https://x/\n", 0},
		"empty section name":  {"[]\n", 0},
		"slash in id":         {"[a/b]\n", 0},
	} {
		t.Run(name, func(t *testing.T) {
			repos, err := ParseRepoFile(strings.NewReader(tc.in))
			if err != nil || len(repos) != tc.want {
				t.Errorf("got %d repos, err %v; want %d", len(repos), err, tc.want)
			}
		})
	}
}

func TestParseRepoFileFirstMirrorListWins(t *testing.T) {
	repos, _ := ParseRepoFile(strings.NewReader("[a]\nmirrorlist=https://one/\nmirrorlist=https://two/\n"))
	if len(repos) != 1 || repos[0].MirrorList != "https://one/" {
		t.Errorf("repos = %+v", repos)
	}
}

func TestParseRepoFileTooLarge(t *testing.T) {
	for name, in := range map[string]string{
		"long line":  "[a]\nbaseurl=" + strings.Repeat("x", maxRepoFileBytes+10) + "\n",
		"many lines": "[a]\n" + strings.Repeat("name=0123456789\n", maxRepoFileBytes/16+10),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRepoFile(strings.NewReader(in)); !errors.Is(err, ErrRepoFileTooLarge) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestReposReadsDirectory(t *testing.T) {
	env := newEnv(t, "[b]\nbaseurl=https://b/\n")

	write := func(name, content string) {
		t.Helper()

		if err := os.WriteFile(filepath.Join(env.repoDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("a.repo", "[a]\nbaseurl=https://a/\n")
	write("notes.txt", "[ignored]\nbaseurl=https://x/\n")

	if err := os.Mkdir(filepath.Join(env.repoDir, "dir.repo"), 0o755); err != nil {
		t.Fatal(err)
	}

	repos, err := env.Repos()
	if err != nil {
		t.Fatal(err)
	}

	var ids []string
	for _, r := range repos {
		ids = append(ids, r.ID)
	}

	// "a.repo" sorts before "test.repo": file name order.
	if !reflect.DeepEqual(ids, []string{"a", "b"}) {
		t.Errorf("ids = %v", ids)
	}
}

func TestReposMissingOrUnsetDirectory(t *testing.T) {
	if repos, err := New(Options{}).Repos(); err != nil || repos != nil {
		t.Errorf("unset: %v, %v", repos, err)
	}

	missing := New(Options{RepoDir: filepath.Join(t.TempDir(), "absent")})
	if repos, err := missing.Repos(); err != nil || repos != nil {
		t.Errorf("missing: %v, %v", repos, err)
	}
}

func TestReposSkipsOversizedFile(t *testing.T) {
	env := newEnv(t, "[ok]\nbaseurl=https://ok/\n")
	big := "[big]\nbaseurl=" + strings.Repeat("x", maxRepoFileBytes+10) + "\n"

	if err := os.WriteFile(filepath.Join(env.repoDir, "big.repo"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}

	repos, err := env.Repos()
	if err != nil || len(repos) != 1 || repos[0].ID != "ok" {
		t.Errorf("repos = %+v, %v", repos, err)
	}
}

func TestParseRepoFilePolicyKeys(t *testing.T) {
	const content = `[r]
baseurl=https://a.example/os
gpgcheck=1
gpgkey=file:///etc/pki/key-a https://k.example/b
    file:///etc/pki/key-c
exclude=kernel* foo,bar
    baz-1.0
excludepkgs=qux
priority=10
proxy=http://user@proxy.example:3128
proxy_username=u
proxy_password=p

[s]
gpgcheck=False
priority=abc
proxy=_none_
`

	repos, err := ParseRepoFile(strings.NewReader(content))
	if err != nil || len(repos) != 2 {
		t.Fatalf("repos = %+v, err %v", repos, err)
	}

	r := repos[0]
	if !r.GPGCheck || r.Priority != 10 || r.Proxy != "http://user@proxy.example:3128" ||
		r.ProxyUsername != "u" || r.ProxyPassword != "p" {
		t.Errorf("repo r = %+v", r)
	}

	if want := []string{"file:///etc/pki/key-a", "https://k.example/b", "file:///etc/pki/key-c"}; !reflect.DeepEqual(r.GPGKeys, want) {
		t.Errorf("GPGKeys = %q, want %q", r.GPGKeys, want)
	}

	if want := []string{"kernel*", "foo", "bar", "baz-1.0", "qux"}; !reflect.DeepEqual(r.Exclude, want) {
		t.Errorf("Exclude = %q, want %q", r.Exclude, want)
	}

	if s := repos[1]; s.GPGCheck || s.Priority != defaultPriority || s.Proxy != "_none_" {
		t.Errorf("repo s = %+v", s)
	}
}
