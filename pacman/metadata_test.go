package pacman

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestReadMetadataMakepkg(t *testing.T) {
	t.Parallel()

	md, err := ReadMetadata(bytes.NewReader(fixtureBytes(t)))
	if err != nil {
		t.Fatal(err)
	}

	if md.Info.Name != "tree-shapes" || md.Info.Version != "1.0-1" || md.Info.Arch != "any" {
		t.Errorf("info %+v", md.Info)
	}

	want, err := os.ReadFile("testdata/makepkg/buildinfo.expected")
	if err != nil {
		t.Fatal(err)
	}

	direct, err := ParseBuildInfo(bytes.NewReader(want))
	if err != nil {
		t.Fatal(err)
	}

	if md.BuildInfo.Format != 2 || md.BuildInfo.PkgName != "tree-shapes" || md.BuildInfo.BuildTool != "makepkg" ||
		md.BuildInfo.PkgbuildSHA256 != direct.PkgbuildSHA256 || len(md.BuildInfo.Installed) != len(direct.Installed) ||
		len(md.BuildInfo.Installed) == 0 || md.BuildInfo.BuildDate != 1700000000 {
		t.Errorf("buildinfo %+v", md.BuildInfo)
	}

	if len(md.Install.Hooks) != 6 || !md.Install.Has(HookPostUpgrade) || !strings.Contains(string(md.Install.Raw), `echo "pre_install $1"`) {
		t.Errorf("install %+v", md.Install)
	}

	if !strings.Contains(string(md.Changelog), "1.0-1: first release") {
		t.Errorf("changelog %q", md.Changelog)
	}

	if len(md.Mtree.Entries) != 18 {
		t.Errorf("%d mtree entries", len(md.Mtree.Entries))
	}
}

func TestReadMetadataOfWrittenPackage(t *testing.T) {
	t.Parallel()

	s := sampleSpec()
	md, err := ReadMetadata(bytes.NewReader(writeSpec(t, s, WriteOptions{})))
	if err != nil {
		t.Fatal(err)
	}

	if md.Info.Name != "hello" || md.BuildInfo.PkgName != "hello" || string(md.Changelog) != "1.0: first\n" {
		t.Errorf("%+v", md)
	}

	for _, h := range []string{HookPostInstall, HookPreRemove, HookPostUpgrade} {
		if !md.Install.Has(h) {
			t.Errorf("hook %s missing: %v", h, md.Install.Hooks)
		}
	}

	if md.Install.Has(HookPreInstall) || md.Install.Has(HookPostRemove) || md.Install.Has(HookPreUpgrade) {
		t.Errorf("hooks = %v", md.Install.Hooks)
	}

	if err := VerifyPackage(bytes.NewReader(writeSpec(t, s, WriteOptions{})), VerifyOptions{}); err != nil {
		t.Errorf("VerifyPackage: %v", err)
	}
}

func TestReadMetadataMinimal(t *testing.T) {
	t.Parallel()

	md, err := ReadMetadata(bytes.NewReader(rawPackage(t)))
	if err != nil {
		t.Fatal(err)
	}

	if md.BuildInfo != nil || md.Install != nil || md.Changelog != nil || md.Mtree != nil {
		t.Errorf("%+v", md)
	}

	if md.Install.Has(HookPostInstall) {
		t.Error("nil script has a hook")
	}
}

func TestReadMetadataErrors(t *testing.T) {
	t.Parallel()

	if _, err := ReadMetadata(bytes.NewReader(compress(t, CompressionZstd, buildTar(t, []member{{name: "a", body: "x"}})))); !errors.Is(err, ErrNoPkgInfo) {
		t.Errorf("no .PKGINFO: %v", err)
	}

	if _, err := ReadMetadata(strings.NewReader("junk")); !errors.Is(err, ErrNotPackage) {
		t.Errorf("junk: %v", err)
	}

	dup := rawPackage(t, tm{hdr: tar.Header{Name: ".PKGINFO", Mode: 0o644}, body: samplePkgInfo})
	if _, err := ReadMetadata(bytes.NewReader(dup)); !errors.Is(err, ErrInvalidField) {
		t.Errorf("duplicate: %v", err)
	}

	badMtree := rawPackage(t, tm{hdr: tar.Header{Name: ".MTREE", Mode: 0o644}, body: "./a type=weird\n"})
	if _, err := ReadMetadata(bytes.NewReader(badMtree)); !errors.Is(err, ErrInvalidMtree) {
		t.Errorf("bad mtree: %v", err)
	}

	badBuild := rawPackage(t, tm{hdr: tar.Header{Name: ".BUILDINFO", Mode: 0o644}, body: "format = x\n"})
	if _, err := ReadMetadata(bytes.NewReader(badBuild)); !errors.Is(err, ErrInvalidField) {
		t.Errorf("bad buildinfo: %v", err)
	}
}

func TestParseInstall(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		text string
		want []string
	}{
		{"classic", "pre_install() {\n\t:\n}\npost_install() {\n\t:\n}\n", []string{HookPreInstall, HookPostInstall}},
		{"spaced", "post_upgrade ()\n{\n:\n}\n  pre_upgrade   (  )   {\n:\n}\n", []string{HookPreUpgrade, HookPostUpgrade}},
		{"function keyword", "function pre_remove {\n:\n}\nfunction post_remove() {\n:\n}\n", []string{HookPreRemove, HookPostRemove}},
		{"comments and calls", "# post_install() {\nfoo() { post_install; }\npost_install\n  echo pre_install() {\n", nil},
		{"one liner", "post_install() { echo hi; }\n", []string{HookPostInstall}},
		{"crlf", "pre_install() {\r\n:\r\n}\r\n", []string{HookPreInstall}},
		{"duplicate", "pre_install() {\n:\n}\npre_install() {\n:\n}\n", []string{HookPreInstall}},
		{"empty", "", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := ParseInstall(strings.NewReader(tc.text))
			if err != nil {
				t.Fatal(err)
			}

			if strings.Join(s.Hooks, ",") != strings.Join(tc.want, ",") || string(s.Raw) != tc.text {
				t.Errorf("hooks = %v, want %v", s.Hooks, tc.want)
			}
		})
	}

	if _, err := ParseInstall(strings.NewReader(strings.Repeat("#", MaxInstallBytes+1))); !errors.Is(err, ErrMetadataTooLarge) {
		t.Errorf("too large: %v", err)
	}
}

// The writer's .INSTALL reads back with exactly the hooks that were set.
func TestInstallRenderParseRoundTrip(t *testing.T) {
	t.Parallel()

	sc := &Scriptlets{PreInstall: "echo 1", PostUpgrade: "echo 2", PostRemove: "echo 3", Preamble: "helper() { :; }\n"}

	s, err := ParseInstall(bytes.NewReader(sc.Render()))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Join(s.Hooks, ",") != "pre_install,post_upgrade,post_remove" {
		t.Errorf("hooks = %v", s.Hooks)
	}
}

func TestParseBuildInfoFormats(t *testing.T) {
	t.Parallel()

	// Format 1, as makepkg 5.1 wrote it: no pkgbase, startdir or buildtool.
	v1, err := ParseBuildInfo(strings.NewReader(`format = 1
pkgname = foo
pkgver = 1:2.0-3
pkgarch = x86_64
pkgbuild_sha256sum = ` + strings.Repeat("a", 64) + `
packager = Jane <jane@example.org>
builddate = 1600000000
builddir = /build
buildenv = !distcc
buildenv = color
options = strip
options = !debug
installed = glibc-2.31-1-x86_64
installed = zlib-1.2.11-3-x86_64
`))
	if err != nil {
		t.Fatal(err)
	}

	if v1.Format != 1 || v1.PkgName != "foo" || v1.PkgVer != "1:2.0-3" || v1.BuildDate != 1600000000 || v1.StartDir != "" ||
		v1.BuildTool != "" || len(v1.BuildEnv) != 2 || len(v1.Options) != 2 || len(v1.Installed) != 2 || v1.Installed[1] != "zlib-1.2.11-3-x86_64" {
		t.Errorf("format 1: %+v", v1)
	}

	raw, err := os.ReadFile("testdata/makepkg/buildinfo.expected")
	if err != nil {
		t.Fatal(err)
	}

	v2, err := ParseBuildInfo(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	if v2.Format != 2 || v2.PkgBase != "tree-shapes" || v2.StartDir == "" || v2.BuildTool != "makepkg" || v2.BuildToolVer == "" ||
		len(v2.BuildEnv) == 0 || len(v2.Options) == 0 {
		t.Errorf("format 2: %+v", v2)
	}

	// Both render back to something that parses to the same value.
	for _, bi := range []*BuildInfo{v1, v2} {
		text, err := bi.Render()
		if err != nil {
			t.Fatal(err)
		}

		again, err := ParseBuildInfo(bytes.NewReader(text))
		if err != nil {
			t.Fatal(err)
		}

		if again.Format != bi.Format || again.PkgName != bi.PkgName || len(again.Installed) != len(bi.Installed) {
			t.Errorf("round trip of format %d: %+v", bi.Format, again)
		}
	}
}
