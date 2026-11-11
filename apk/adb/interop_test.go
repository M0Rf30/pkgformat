package adb

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
)

func bigData(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

func minimalInfo() Info {
	return Info{Name: "minimal", Version: "1.0-r0", Arch: "x86_64", BuildTime: 1700000000}
}

func fullInfo() Info {
	return Info{
		Name: "full", Version: "1.2.3_rc1-r4", Arch: "x86_64", Description: "Full test",
		License: "MIT BSD-2-Clause", URL: "https://example.org", Origin: "fullorigin",
		Maintainer: "A B <a@b.c>", BuildTime: 1700000000, ProviderPriority: 10, Layer: 1,
		RepoCommit: "0123456789abcdef0123456789abcdef01234567",
		Depends:    []string{"busybox>=1.0", "!conflicting", "so:libc.musl-x86_64.so.1", "foo~1.2", "bar<2", "baz<=3", "qux>4", "quux=5", "foo~1.2"},
		Provides:   []string{"cmd:full=1.2.3-r4", "virt"},
		Replaces:   []string{"other"},
		InstallIf:  []string{"foo=1", "bar"},
		Recommends: []string{"rec1", "rec2"},
		Tags:       []string{"b", "a"},
	}
}

type writerCase struct {
	name  string
	info  Info
	build func(tr *tree)
	spec  func(s *Spec)
	extra []string
	opts  WriteOptions
}

func writerCases() []writerCase {
	return []writerCase{
		{name: "empty", info: minimalInfo(), build: func(*tree) {}},
		{name: "one file", info: minimalInfo(), build: func(tr *tree) {
			tr.File("hello", 0o644, []byte("hello\n"))
		}},
		{name: "files and dirs", info: minimalInfo(), build: func(tr *tree) {
			tr.File("usr/bin/hello", 0o755, []byte("#!/bin/sh\necho hi\n"))
			tr.File("usr/bin/other", 0o755, []byte("#!/bin/sh\necho hi\n"))
			tr.File("etc/app.conf", 0o644, []byte("conf\n"))
			tr.File("etc/empty", 0o644, nil)
			tr.File("usr/share/doc/app/README", 0o644, []byte("readme\n"))
			tr.Dir("var/empty", 0o700)
			tr.Dir("var/lib/app", 0o755)
		}},
		{name: "special modes", info: minimalInfo(), build: func(tr *tree) {
			tr.File("usr/bin/su", fs.ModeSetuid|0o755, []byte("su"))
			tr.File("usr/bin/wall", fs.ModeSetgid|0o755, []byte("wall"))
			tr.Dir("tmp", fs.ModeSticky|0o777)
			tr.Dir("opt/priv", 0o700)
		}},
		{name: "links", info: minimalInfo(), build: func(tr *tree) {
			tr.File("usr/bin/hello", 0o755, []byte("hello"))
			tr.Symlink("usr/bin/hi", "hello")
			tr.Symlink("etc/hello.link", "../usr/bin/hello")
			tr.Symlink("etc/abs.link", "/usr/bin/hello")
			tr.File("etc/app.conf", 0o644, []byte("conf\n"))
			tr.Hardlink("etc/app.conf.hard", "etc/app.conf")
			tr.Hardlink("etc/zz.hard", "etc/app.conf")
			tr.File("usr/bin/other", 0o644, []byte("top"))
			tr.Hardlink("usr/bin/otherlink", "usr/bin/other")
		}},
		{name: "large", info: minimalInfo(), build: func(tr *tree) {
			tr.File("big", 0o644, bigData(100000, 'x'))
			tr.File("small", 0o644, bigData(300, 'y'))
			tr.File("same", 0o644, bigData(300, 'y'))
		}},
		{name: "xattrs", info: minimalInfo(), extra: []string{"--xattrs"}, build: func(tr *tree) {
			tr.File("etc/app.conf", 0o644, []byte("conf\n"))
			tr.Xattr("etc/app.conf", "user.foo", []byte("bar"))
			tr.Xattr("etc/app.conf", "user.abc", []byte("zz"))
			tr.Dir("etc/dir", 0o755)
			tr.Xattr("etc/dir", "user.d", []byte("dir"))
		}},
		{name: "full metadata", info: fullInfo(), build: func(tr *tree) {
			tr.File("usr/bin/full", 0o755, []byte("full"))
		}, spec: func(s *Spec) {
			s.ReplacesPriority = 5
			s.Triggers = []string{"/usr/share/*", "/lib/x"}
			s.Scripts = Scripts{
				Trigger: "#!/bin/sh\necho trig\n", PreInstall: "#!/bin/sh\necho pre\n",
				PostInstall: "#!/bin/sh\necho post\n", PreDeinstall: "#!/bin/sh\necho prd\n",
				PostDeinstall: "#!/bin/sh\necho pod\n", PreUpgrade: "#!/bin/sh\necho pru\n",
				PostUpgrade: "#!/bin/sh\necho pou\n",
			}
		}},
		{name: "big script", info: minimalInfo(), build: func(tr *tree) {
			tr.File("a", 0o644, []byte("a"))
		}, spec: func(s *Spec) {
			s.Scripts.PostInstall = "#!/bin/sh\n" + strings.Repeat("echo padding\n", 6000)
		}},
		{name: "scripts only", info: minimalInfo(), build: func(*tree) {}, spec: func(s *Spec) {
			s.Scripts.PostInstall = "#!/bin/sh\ntrue\n"
		}},
		{name: "compat pre3", info: minimalInfo(), extra: []string{"--compat", "3.0.0_pre3"}, opts: WriteOptions{Compat: "3.0.0_pre3"}, build: nestedTree},
		{name: "compat rc9", info: minimalInfo(), extra: []string{"--compat", "3.0.0_rc9"}, opts: WriteOptions{Compat: "3.0.0_rc9"}, build: nestedTree},
		{name: "compat default", info: minimalInfo(), build: nestedTree},
		{name: "compat 3.0.9", info: minimalInfo(), extra: []string{"--compat", "3.0.9"}, opts: WriteOptions{Compat: "3.0.9"}, build: nestedTree},
	}
}

func nestedTree(tr *tree) {
	tr.File("usr/lib/app/lib.so", 0o644, []byte("lib"))
	tr.File("usr/bin/tool", 0o755, []byte("tool"))
	tr.Dir("var/log/app", 0o755)
	tr.Dir("etc", 0o755)
}

// TestWriterMatchesMkpkg writes packages with the writer and with apk mkpkg
// from the same tree, and demands the same ADB block, byte for byte.
func TestWriterMatchesMkpkg(t *testing.T) {
	needApk(t)

	for _, c := range writerCases() {
		t.Run(c.name, func(t *testing.T) {
			tr := newTree(t)
			c.build(tr)

			spec := &Spec{Info: c.info}
			if c.spec != nil {
				c.spec(spec)
			}

			ref := tr.mkpkg(spec, c.extra...)

			spec.Files = tr.shuffled()

			var out bytes.Buffer
			if _, err := WritePackage(&out, spec, c.opts); err != nil {
				t.Fatal(err)
			}

			got, want := adbOf(t, out.Bytes()), adbOf(t, ref)
			if !bytes.Equal(got, want) {
				t.Errorf("ADB blocks differ (%d bytes, want %d)\n--- ours\n%s\n--- apk\n%s",
					len(got), len(want), dumpOf(t, out.Bytes()), dumpOf(t, ref))
			}
		})
	}
}
