package dnf

import (
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/internal/pathseg"
	"github.com/M0Rf30/pkgformat/rpm/repodata"
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
			r.excludes(&repodata.PrimaryPackage{Name: "n", Version: "1", Release: "2", Arch: "x86_64"})
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

func FuzzDependencyNames(f *testing.F) {
	f.Add("(gcc-plugin-annobin if gcc)")
	f.Add("glibc >= 2.17")
	f.Add("(a and (b or rpmlib(X) >= 1))")

	f.Fuzz(func(t *testing.T, in string) {
		_ = StripRPMConstraint(in)

		for _, tok := range ExpandBooleanDep(in) {
			if tok == "" || strings.ContainsAny(tok, " \t\n") {
				t.Fatalf("token %q from %q", tok, in)
			}
		}
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
