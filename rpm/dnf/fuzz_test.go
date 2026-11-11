package dnf

import (
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/internal/pathseg"
)

func FuzzParseRepoFile(f *testing.F) {
	f.Add("[base]\nbaseurl=https://a/ https://b/\n    https://c/\nenabled=1\n")
	f.Add("[x]\nmirrorlist=https://m/\ngpgkey=https://k\n  https://k2\n")
	f.Add("[../a]\nbaseurl=x\n[]\n[ok]\n")
	f.Add("[r]\ngpgcheck=1\ngpgkey=file:///k\nexclude=a* b-1,c\npriority=-5\nproxy=http://p:3128\nproxy_username=u\n")

	f.Fuzz(func(t *testing.T, in string) {
		repos, err := ParseRepoFile(strings.NewReader(in))
		if err != nil {
			return
		}

		for _, r := range repos {
			// An id is joined to the cache path: it must be a plain name.
			if !pathseg.Name(r.ID) {
				t.Fatalf("repository id %q is not a path segment", r.ID)
			}

			// patterns of any content must be matchable
			DefaultConfig().allowed(&r, "n", "0", "1", "2", "x86_64")
		}
	})
}

func FuzzMirrorLists(f *testing.F) {
	f.Add("https://a.example/os\nhttp://b.example/os\n# c\n")
	f.Add(`<url protocol="https">https://m.example/x/repodata/repomd.xml</url>`)
	f.Add(`<metalink><files><file name="repomd.xml"><size>3</size><verification><hash type="sha256">00</hash></verification><resources><url>https://m.example/x/repodata/repomd.xml</url></resources></file></files></metalink>`)

	f.Fuzz(func(t *testing.T, in string) {
		secure, plain := listMirrors(in)
		checkMirrors(t, secure, plain)

		secure, plain, info := metalinkMirrors(in)
		checkMirrors(t, secure, plain)

		// whatever the document says, verifying must not panic
		_ = info.verify([]byte(in))
	})
}

func checkMirrors(t *testing.T, secure, plain []string) {
	t.Helper()

	for _, m := range secure {
		if !strings.HasPrefix(m, "https://") {
			t.Fatalf("secure mirror %q", m)
		}
	}

	for _, m := range plain {
		if !strings.HasPrefix(m, "http://") {
			t.Fatalf("plain mirror %q", m)
		}
	}
}

func FuzzParseConfig(f *testing.F) {
	f.Add("[main]\ngpgcheck=1\nexclude=a* b\n  c\ninstall_weak_deps=False\nmetadata_expire=6h\nmultilib_policy=all\n")
	f.Add("[main]\nvarsdir=/a /b\nproxy=http://p\nsslverify=0\nmetadata_expire=never\n[x]\nbest=1\n")
	f.Add("[main\nk\n=\n")

	f.Fuzz(func(t *testing.T, in string) {
		cfg, err := ParseConfig(strings.NewReader(in))
		if err != nil {
			return
		}

		if cfg.MultilibPolicy != MultilibBest && cfg.MultilibPolicy != MultilibAll {
			t.Fatalf("multilib policy %q", cfg.MultilibPolicy)
		}

		repos, err := parseRepoFile(strings.NewReader(in), cfg.Defaults)
		if err != nil {
			return
		}

		for _, r := range repos {
			cfg.allowed(&r, "n", "0", "1", "2", "x86_64")
		}
	})
}

func FuzzParseExpire(f *testing.F) {
	f.Add("6h")
	f.Add("never")
	f.Add("-1")
	f.Add("99999999999999999999d")

	f.Fuzz(func(t *testing.T, in string) {
		if d, ok := parseExpire(in); ok && d < MetadataExpireNever {
			t.Fatalf("%q -> %v", in, d)
		}
	})
}

func FuzzMatchSpec(f *testing.F) {
	f.Add("foo-1.0-2.x86_64")
	f.Add("1:foo-2.0-1.i686")
	f.Add("py.12")
	f.Add("-:-.-")

	ix := testIndex(nil,
		tpkg{name: "foo", version: "1.0", release: "2"},
		tpkg{name: "foo", version: "2.0", release: "1", epoch: 1, arch: "i686"},
		tpkg{name: "py.12", version: "3"},
	)

	f.Fuzz(func(t *testing.T, in string) {
		for _, p := range ix.Match(in) {
			if _, ok := ix.Lookup(p.Name); !ok {
				t.Fatalf("matched %v, not in the index", p)
			}
		}
	})
}

func FuzzReadFilelists(f *testing.F) {
	f.Add(`<filelists><package pkgid="abc" name="a" arch="x"><version epoch="0" ver="1" rel="1"/><file>/usr/bin/a</file><file type="dir">/usr/share/a</file></package></filelists>`)
	f.Add(`<package pkgid="x"><file>/a</file>`)

	f.Fuzz(func(t *testing.T, in string) {
		wanted := map[string]struct{}{"/usr/bin/a": {}, "/a": {}}

		_ = readFilelists(strings.NewReader(in), wanted, func(pkgid, file string) {
			if _, ok := wanted[file]; !ok {
				t.Fatalf("%q reported but not wanted", file)
			}
		})
	})
}

func FuzzExpandVars(f *testing.F) {
	f.Add("https://h/$releasever/${basearch}//os/$infra")
	f.Add("$${a}$")

	c := New(Options{Releasever: "9", Arch: "x86_64", Vars: map[string]string{"infra": "stock"}})

	f.Fuzz(func(t *testing.T, in string) {
		out := c.expandVars(in)

		if again := normalizeURL(out); again != out {
			t.Fatalf("normalizeURL is not idempotent: %q -> %q", out, again)
		}
	})
}
