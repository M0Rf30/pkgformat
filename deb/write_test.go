package deb_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

func testSpec() *deb.Spec {
	return &deb.Spec{
		Name:         "hello-tool",
		Epoch:        "1",
		Version:      "2.0",
		Release:      "3",
		Architecture: "amd64",
		Section:      "utils",
		Priority:     "optional",
		Maintainer:   "Jane Doe <jane@example.org>",
		SourcePkg:    "hello-src",
		URL:          "https://example.org/hello",
		Bugs:         "https://example.org/bugs",
		Description:  "Say hello\nA longer text.\n\nSecond paragraph.",
		Depends:      rels("libc6 (>= 2.31)", "bash"),
		PreDepends:   rels("dpkg"),
		Recommends:   rels("curl"),
		Suggests:     rels("git"),
		Enhances:     rels("vim"),
		Provides:     rels("hello"),
		Conflicts:    rels("hello-old"),
		Breaks:       rels("hello-older (<< 1.0)"),
		Replaces:     rels("hello-old"),
		BuiltUsing:   rels("golang (= 1.27)"),
		Conffiles:    []string{"etc/hello.conf"},
		Licenses:     []string{"MIT"},
		Copyrights:   []string{"2024 Jane Doe", "2025 John Doe"},
		Scripts: deb.Scripts{
			Preinst: "#!/bin/sh\nexit 0\n", Postinst: "#!/bin/sh\nexit 0\n",
			Prerm: "echo prerm\n", Postrm: "echo postrm\n",
			Config:    "#!/bin/sh\n. /usr/share/debconf/confmodule\n",
			Templates: "Template: hello/x\nType: string\nDescription: x\n",
		},
		Changelog: []byte("hello-tool (2.0-3) unstable; urgency=low\n\n  * Release.\n\n -- Jane Doe <jane@example.org>  Mon, 01 Jan 2024 00:00:00 +0000\n"),
		ModTime:   time.Unix(1700000000, 0),
	}
}

func testPayload() []deb.Entry {
	return []deb.Entry{
		{Path: "usr/bin/hello", Mode: 0o755, Data: []byte("#!/bin/sh\necho hello\n")},
		{Path: "usr/bin/hi", Mode: fs.ModeSymlink | 0o777, Linkname: "hello"},
		{Path: "etc/hello.conf", Mode: 0o644, Data: []byte("greeting=hi\n")},
		{Path: "usr/share/hello/odd", Mode: 0o600, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("odd")), nil
		}, Size: 3},
		{Path: "var/lib/hello", Mode: fs.ModeDir | 0o750},
	}
}

func TestWriteRoundTrip(t *testing.T) {
	for _, comp := range []string{"gzip", "xz", "zstd", ""} {
		t.Run("comp="+comp, func(t *testing.T) {
			spec := testSpec()
			spec.Compression = comp

			var buf bytes.Buffer
			require.NoError(t, deb.Write(&buf, spec, testPayload(), deb.WriteOptions{TempDir: t.TempDir()}))

			f, err := deb.ParseDebFileAt(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			require.NoError(t, err)

			assert.Equal(t, "hello-tool", f.Package.Package)
			assert.Equal(t, "1:2.0-3", f.Package.Version)
			assert.Equal(t, "amd64", f.Package.Architecture)
			assert.Equal(t, "libc6 (>= 2.31), bash", f.Package.Depends)
			assert.Equal(t, "Say hello\nA longer text.\n\nSecond paragraph.", f.Package.Description)
			assert.Equal(t, "hello-src", f.Package.Source)
			assert.Equal(t, []string{"/etc/hello.conf"}, f.Conffiles())
			assert.Contains(t, string(f.Control["prerm"]), deb.RemoveScriptHeader)
			assert.Contains(t, string(f.Control["md5sums"]), "  usr/bin/hello\n")
			assert.NotContains(t, string(f.Control["md5sums"]), "hi\n")
			assert.Contains(t, string(f.Control["copyright"]), "Copyright: 2024 Jane Doe\n 2025 John Doe\n")

			dir := t.TempDir()
			require.NoError(t, f.Extract(dir, deb.ExtractOptions{}))

			got, err := os.ReadFile(filepath.Join(dir, "usr/bin/hello"))
			require.NoError(t, err)
			assert.Equal(t, "#!/bin/sh\necho hello\n", string(got))

			link, err := os.Readlink(filepath.Join(dir, "usr/bin/hi"))
			require.NoError(t, err)
			assert.Equal(t, "hello", link)

			_, err = os.Stat(filepath.Join(dir, "usr/share/doc/hello-tool/changelog.Debian.gz"))
			require.NoError(t, err)

			st, err := os.Stat(filepath.Join(dir, "var/lib/hello"))
			require.NoError(t, err)
			assert.Equal(t, fs.FileMode(0o750), st.Mode().Perm())
		})
	}
}

func TestWriteDeterministic(t *testing.T) {
	var a, b bytes.Buffer

	require.NoError(t, deb.Write(&a, testSpec(), testPayload(), deb.WriteOptions{}))
	require.NoError(t, deb.Write(&b, testSpec(), testPayload(), deb.WriteOptions{}))
	assert.Equal(t, a.Bytes(), b.Bytes())
}

func TestWriteMultiArchAll(t *testing.T) {
	spec := testSpec()
	spec.Architecture = "all"

	var buf bytes.Buffer
	require.NoError(t, deb.Write(&buf, spec, testPayload(), deb.WriteOptions{}))

	f, err := deb.ParseDebFileAt(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	assert.Equal(t, "foreign", f.Package.MultiArch)
}

func TestWriteInvalid(t *testing.T) {
	cases := map[string]func(*deb.Spec){
		"name":       func(s *deb.Spec) { s.Name = "Bad_Name" },
		"version":    func(s *deb.Spec) { s.Version = "1 0" },
		"arch":       func(s *deb.Spec) { s.Architecture = "" },
		"injection":  func(s *deb.Spec) { s.Maintainer = "x\nDepends: evil" },
		"dep inject": func(s *deb.Spec) { s.Depends = []deb.Alternatives{{{Name: "a\nB: c"}}} },
		"epoch":      func(s *deb.Spec) { s.Epoch = "x" },
		"comp":       func(s *deb.Spec) { s.Compression = "lzma9" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := testSpec()
			mutate(spec)

			err := deb.Write(io.Discard, spec, nil, deb.WriteOptions{})
			require.Error(t, err)
			assert.True(t, errors.Is(err, deb.ErrInvalidSpec) || errors.Is(err, deb.ErrUnsupportedCompression), err)
		})
	}
}

func TestWriteBadEntries(t *testing.T) {
	cases := map[string][]deb.Entry{
		"duplicate": {{Path: "a", Mode: 0o644}, {Path: "./a", Mode: 0o644}},
		"traversal": {{Path: "../x", Mode: 0o644}},
		"irregular": {{Path: "dev/x", Mode: fs.ModeIrregular | 0o644}},
		"no target": {{Path: "l", Mode: fs.ModeSymlink | 0o777}},
		"short":     {{Path: "s", Mode: 0o644, Size: 10, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("x")), nil }}},
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			require.Error(t, deb.Write(io.Discard, testSpec(), payload, deb.WriteOptions{}))
		})
	}
}

func TestDpkgDebAccepts(t *testing.T) {
	dpkgDeb, err := exec.LookPath("dpkg-deb")
	if err != nil {
		t.Skip("dpkg-deb not installed")
	}

	for _, comp := range []string{"gzip", "xz", "zstd", "none"} {
		t.Run(comp, func(t *testing.T) {
			spec := testSpec()
			spec.Compression = comp

			path := filepath.Join(t.TempDir(), spec.FileName())
			require.NoError(t, deb.WriteFile(path, spec, testPayload(), deb.WriteOptions{}))

			out, err := exec.Command(dpkgDeb, "-f", path).CombinedOutput()
			require.NoError(t, err, string(out))
			assert.Contains(t, string(out), "Package: hello-tool\n")
			assert.Contains(t, string(out), "Version: 1:2.0-3\n")
			assert.Contains(t, string(out), "Description: Say hello\n A longer text.\n .\n Second paragraph.\n")

			out, err = exec.Command(dpkgDeb, "-c", path).CombinedOutput()
			require.NoError(t, err, string(out))
			assert.Contains(t, string(out), "./usr/bin/hello")
			assert.Contains(t, string(out), "./usr/bin/hi -> hello")
			assert.Contains(t, string(out), "./usr/share/doc/hello-tool/changelog.Debian.gz")

			out, err = exec.Command(dpkgDeb, "-I", path).CombinedOutput()
			require.NoError(t, err, string(out))
			assert.NotContains(t, string(out), "warning")

			dir := t.TempDir()
			out, err = exec.Command(dpkgDeb, "-x", path, dir).CombinedOutput()
			require.NoError(t, err, string(out))
			assert.FileExists(t, filepath.Join(dir, "usr/bin/hello"))

			ctl := t.TempDir()
			out, err = exec.Command(dpkgDeb, "-e", path, ctl).CombinedOutput()
			require.NoError(t, err, string(out))
			assert.FileExists(t, filepath.Join(ctl, "md5sums"))
			assert.FileExists(t, filepath.Join(ctl, "conffiles"))

			// The checksums the writer computed are the ones dpkg computes.
			md5sums, err := os.ReadFile(filepath.Join(ctl, "md5sums"))
			require.NoError(t, err)
			check := exec.Command("md5sum", "-c", filepath.Join(ctl, "md5sums"))
			check.Dir = dir
			out, err = check.CombinedOutput()
			require.NoError(t, err, string(out)+string(md5sums))
		})
	}
}

func TestDataArchiveHeaders(t *testing.T) {
	spec := testSpec()
	spec.Compression = "none"

	var buf bytes.Buffer
	require.NoError(t, deb.Write(&buf, spec, testPayload(), deb.WriteOptions{}))

	f, err := deb.ParseDebFileAt(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)

	rc, err := f.OpenData()
	require.NoError(t, err)

	defer rc.Close()

	tr := tar.NewReader(rc)

	var names []string

	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		require.NoError(t, err)
		assert.Equal(t, "root", h.Uname)
		assert.Equal(t, 0, h.Uid)
		names = append(names, h.Name)
	}

	assert.Equal(t, []string{
		"./", "./usr/", "./usr/bin/", "./usr/bin/hello", "./usr/bin/hi", "./etc/", "./etc/hello.conf",
		"./usr/share/", "./usr/share/hello/", "./usr/share/hello/odd", "./var/", "./var/lib/", "./var/lib/hello/",
		"./usr/share/doc/", "./usr/share/doc/hello-tool/", "./usr/share/doc/hello-tool/changelog.Debian.gz",
	}, names)
}
