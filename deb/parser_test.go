package deb_test

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

func TestParseDebFileCompressions(t *testing.T) {
	for _, ext := range []string{"", ".gz", ".xz", ".zst"} {
		t.Run("ext="+ext, func(t *testing.T) {
			ctl := compressWith(t, ext, controlTar(t, validControl+"Depends: libc6 (>= 2.31)\n",
				reg("./conffiles", "/etc/a.conf\n\n  /etc/b.conf  \n"),
				reg("md5sums", "abc  usr/bin/x\n"),
				dirEntry("./sub/", 0o755),
				symlinkEntry("./link", "control"),
			))
			data := compressWith(t, ext, buildTar(t, reg("./usr/bin/x", "x")))

			raw := debOf("control.tar"+ext, ctl, "data.tar"+ext, data)

			f, err := parseDeb(raw)
			require.NoError(t, err)

			assert.Equal(t, "crafted", f.Package.Package)
			assert.Equal(t, "1.0-1", f.Package.Version)
			assert.Equal(t, "libc6 (>= 2.31)", f.Package.Depends)
			assert.Equal(t, "crafted", f.ControlFile.Get("Package"))
			assert.Equal(t, ctl, f.ControlTarGz)
			assert.Equal(t, []string{"/etc/a.conf", "/etc/b.conf"}, f.Conffiles())
			assert.Contains(t, f.Control, "md5sums")
			assert.NotContains(t, f.Control, "link", "only regular files are listed")
			assert.NotContains(t, f.Control, "sub")

			rc, err := f.OpenData()
			require.NoError(t, err)

			tr := tar.NewReader(rc)
			h, err := tr.Next()
			require.NoError(t, err)
			assert.Equal(t, "./usr/bin/x", h.Name)
			require.NoError(t, rc.Close())
		})
	}
}

func TestParseDebFileBzip2(t *testing.T) {
	ctl, err := base64.StdEncoding.DecodeString(bz2ControlTar)
	require.NoError(t, err)

	raw := debOf("control.tar.bz2", ctl, "data.tar", buildTar(t, reg("./f", "x")))

	f, err := parseDeb(raw)
	require.NoError(t, err)
	assert.Equal(t, "bz", f.Package.Package)

	// A bz2 data member is not rejected by the format check; it fails on the
	// content, which is not bzip2.
	raw = debOf("control.tar.gz", compressWith(t, ".gz", controlTar(t, validControl)), "data.tar.bz2", []byte("not bzip2"))
	f, err = parseDeb(raw)
	require.NoError(t, err)

	rc, err := f.OpenData()
	require.NoError(t, err)

	_, err = io.ReadAll(rc)
	require.Error(t, err)
	_ = rc.Close()
}

func TestParseDebFileNoMemberOrderAssumption(t *testing.T) {
	ctl := compressWith(t, ".gz", controlTar(t, validControl))
	data := compressWith(t, ".gz", buildTar(t, reg("./f", "x")))

	raw := buildAR(arMem{"data.tar.gz", data}, arMem{"_gpgbuilder", []byte("sig")}, arMem{"control.tar.gz", ctl}, arMem{"debian-binary", []byte("2.0\n")})

	f, err := parseDeb(raw)
	require.NoError(t, err)
	assert.Equal(t, "crafted", f.Package.Package)

	rc, err := f.OpenData()
	require.NoError(t, err)
	require.NoError(t, rc.Close())
}

func TestParseDebFileErrors(t *testing.T) {
	gz := func(b []byte) []byte { return compressWith(t, ".gz", b) }
	data := gz(buildTar(t, reg("./f", "x")))

	badControls := map[string]struct {
		raw  []byte
		want error
	}{
		"empty file":            {nil, nil},
		"bad magic":             {[]byte("!<arch>X" + strings.Repeat(" ", 100)), deb.ErrInvalidARMagic},
		"magic only":            {[]byte("!<arch>\n"), deb.ErrControlArchiveNotFound},
		"no control member":     {debOf("", nil, "data.tar.gz", data), deb.ErrControlArchiveNotFound},
		"unsupported control":   {debOf("control.tar.foo", gz(controlTar(t, validControl)), "data.tar.gz", data), deb.ErrUnsupportedArchiveFormat},
		"lz4 control":           {debOf("control.tar.lz4", []byte("x"), "data.tar.gz", data), deb.ErrUnsupportedArchiveFormat},
		"corrupt gzip control":  {debOf("control.tar.gz", []byte("not gzip at all"), "data.tar.gz", data), nil},
		"corrupt tar control":   {debOf("control.tar.gz", gz([]byte(strings.Repeat("x", 600))), "data.tar.gz", data), nil},
		"no control file":       {debOf("control.tar.gz", gz(buildTar(t, reg("./other", "x"))), "data.tar.gz", data), deb.ErrFileNotFoundInTar},
		"malformed control":     {debOf("control.tar.gz", gz(controlTar(t, "Package: a\nthis is not a field\n")), "data.tar.gz", data), deb.ErrInvalidControlFormat},
		"missing package":       {debOf("control.tar.gz", gz(controlTar(t, "Version: 1\nArchitecture: all\n")), "data.tar.gz", data), deb.ErrMissingRequiredField},
		"missing version":       {debOf("control.tar.gz", gz(controlTar(t, "Package: a\nArchitecture: all\n")), "data.tar.gz", data), deb.ErrMissingRequiredField},
		"missing architecture":  {debOf("control.tar.gz", gz(controlTar(t, "Package: a\nVersion: 1\n")), "data.tar.gz", data), deb.ErrMissingRequiredField},
		"empty control file":    {debOf("control.tar.gz", gz(controlTar(t, "")), "data.tar.gz", data), deb.ErrMissingRequiredField},
		"empty control archive": {debOf("control.tar.gz", nil, "data.tar.gz", data), nil},
		"truncated archive":     {debOf("control.tar.gz", gz(controlTar(t, validControl))[:20], "data.tar.gz", data), nil},
	}

	for name, tc := range badControls {
		t.Run(name, func(t *testing.T) {
			f, err := parseDeb(tc.raw)
			require.Error(t, err)
			require.ErrorIs(t, err, deb.ErrInvalidPackage)
			assert.Nil(t, f)

			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
			}
		})
	}
}

func TestParseDebFileTooLarge(t *testing.T) {
	raw := debWithData(t, buildTar(t, reg("./f", "x")))

	_, err := deb.ParseDebFile(bytes.NewReader(raw), int64(len(raw)), deb.ParseOptions{MaxFileSize: int64(len(raw)) - 1})
	require.ErrorIs(t, err, deb.ErrDebFileTooLarge)
	require.ErrorIs(t, err, deb.ErrInvalidPackage)

	_, err = deb.ParseDebFile(bytes.NewReader(raw), int64(len(raw)), deb.ParseOptions{MaxFileSize: int64(len(raw))})
	require.NoError(t, err)

	// The default limit applies to the declared size without reading anything.
	_, err = deb.ParseDebFileAt(bytes.NewReader(nil), deb.MaxDebFileSize+1)
	require.ErrorIs(t, err, deb.ErrDebFileTooLarge)
}

// zeroTail serves a prefix and then zeros up to size, so that a huge member can
// be declared without holding it in memory.
type zeroTail struct {
	head []byte
	size int64
}

func (z zeroTail) ReadAt(p []byte, off int64) (int, error) {
	if off >= z.size {
		return 0, io.EOF
	}

	n := min(int64(len(p)), z.size-off)
	for i := range n {
		if pos := off + i; pos < int64(len(z.head)) {
			p[i] = z.head[pos]
		} else {
			p[i] = 0
		}
	}

	if n < int64(len(p)) {
		return int(n), io.EOF
	}

	return int(n), nil
}

func TestParseDebFileControlMemberTooLarge(t *testing.T) {
	size := int64(deb.MaxControlArchiveSize) + 1
	head := []byte("!<arch>\n" + fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n", "control.tar.gz", 0, 0, 0, "100644", size))

	_, err := deb.ParseDebFileAt(zeroTail{head: head, size: int64(len(head)) + size}, int64(len(head))+size)
	require.ErrorIs(t, err, deb.ErrARMemberTooLarge)
	require.ErrorIs(t, err, deb.ErrInvalidPackage)
}

func TestParseDebFileControlArchiveBomb(t *testing.T) {
	// 70 MiB of zeros in one tar entry compresses to a few hundred KiB.
	var tarBuf bytes.Buffer

	tw := tar.NewWriter(&tarBuf)
	big := int64(deb.MaxControlArchiveSize) + 6<<20
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "./big", Mode: 0o644, Size: big}))
	_, err := io.CopyN(tw, zeros{}, big)
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	raw := debOf("control.tar.gz", compressWith(t, ".gz", tarBuf.Bytes()), "data.tar.gz", nil)
	require.Less(t, len(raw), 1<<20, "the bomb must be small on disk")

	_, err = parseDeb(raw)
	require.ErrorIs(t, err, deb.ErrControlArchiveTooLarge)
	require.ErrorIs(t, err, deb.ErrInvalidPackage)
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestParseDebFileControlFileTooLarge(t *testing.T) {
	big := "Package: a\nVersion: 1\nArchitecture: all\nDescription: " + strings.Repeat("x", deb.MaxControlFileSize+1) + "\n"
	raw := debOf("control.tar.gz", compressWith(t, ".gz", controlTar(t, big)), "data.tar.gz", nil)

	_, err := parseDeb(raw)
	require.ErrorIs(t, err, deb.ErrControlFileTooLarge)

	// Another member of the control archive over the limit counts too.
	raw = debOf("control.tar.gz", compressWith(t, ".gz", controlTar(t, validControl, reg("./preinst", strings.Repeat("#", deb.MaxControlFileSize+1)))), "data.tar.gz", nil)
	_, err = parseDeb(raw)
	require.ErrorIs(t, err, deb.ErrControlFileTooLarge)
}

func TestParseDebFileTooManyControlEntries(t *testing.T) {
	entries := []tarEntry{reg("./control", validControl)}
	for i := range 300 {
		entries = append(entries, reg(fmt.Sprintf("./f%d", i), "x"))
	}

	raw := debOf("control.tar.gz", compressWith(t, ".gz", buildTar(t, entries...)), "data.tar.gz", nil)

	_, err := parseDeb(raw)
	require.ErrorIs(t, err, deb.ErrTooLarge)
}

func TestControlNameNormalisation(t *testing.T) {
	ctl := buildTar(t, reg("./control", validControl), reg("preinst", "a"), reg("./usr/../postinst", "b"))

	f, err := parseDeb(debOf("control.tar", ctl, "data.tar", nil))
	require.NoError(t, err)
	assert.Equal(t, "a", string(f.Control["preinst"]))
	assert.Equal(t, "b", string(f.Control["postinst"]))
	assert.Contains(t, f.Control, "control")
}

func TestOpenDataErrors(t *testing.T) {
	ctl := compressWith(t, ".gz", controlTar(t, validControl))

	t.Run("no data member", func(t *testing.T) {
		f, err := parseDeb(debOf("control.tar.gz", ctl, "", nil))
		require.NoError(t, err)

		_, err = f.OpenData()
		require.ErrorIs(t, err, deb.ErrDataArchiveNotFound)
		require.ErrorIs(t, err, deb.ErrInvalidPackage)

		require.ErrorIs(t, f.Extract(t.TempDir(), deb.ExtractOptions{}), deb.ErrDataArchiveNotFound)
	})

	for _, name := range []string{"data.tar.lz4", "data.tar.foo", "data.tar.Z"} {
		t.Run(name, func(t *testing.T) {
			f, err := parseDeb(debOf("control.tar.gz", ctl, name, []byte("x")))
			require.NoError(t, err)

			_, err = f.OpenData()
			require.ErrorIs(t, err, deb.ErrUnsupportedArchiveFormat)
		})
	}

	t.Run("corrupt gzip", func(t *testing.T) {
		f, err := parseDeb(debOf("control.tar.gz", ctl, "data.tar.gz", []byte("garbage that is not gzip")))
		require.NoError(t, err)

		_, err = f.OpenData()
		require.ErrorIs(t, err, deb.ErrInvalidPackage)
	})

	t.Run("corrupt xz", func(t *testing.T) {
		f, err := parseDeb(debOf("control.tar.gz", ctl, "data.tar.xz", []byte("garbage that is not xz")))
		require.NoError(t, err)

		_, err = f.OpenData()
		require.Error(t, err)
	})
}

func TestConffilesEmpty(t *testing.T) {
	f, err := parseDeb(debWithData(t, buildTar(t)))
	require.NoError(t, err)
	assert.Empty(t, f.Conffiles())
}

func TestParseDebFileFromDpkgDeb(t *testing.T) {
	dpkgDeb, err := exec.LookPath("dpkg-deb")
	if err != nil {
		t.Skip("dpkg-deb not installed")
	}

	for _, comp := range []string{"gzip", "xz", "zstd", "none"} {
		t.Run(comp, func(t *testing.T) {
			tree := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(tree, "DEBIAN"), 0o755))
			require.NoError(t, os.MkdirAll(filepath.Join(tree, "usr/bin"), 0o755))
			require.NoError(t, os.MkdirAll(filepath.Join(tree, "etc"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(tree, "DEBIAN/control"),
				[]byte("Package: from-dpkg\nVersion: 3:1.2-4\nArchitecture: amd64\nMaintainer: A <a@example.org>\nInstalled-Size: 4\nDepends: libc6 (>= 2.31) | musl\nDescription: built by dpkg-deb\n long text\n .\n more\n"), 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(tree, "DEBIAN/conffiles"), []byte("/etc/tool.conf\n"), 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(tree, "DEBIAN/postinst"), []byte("#!/bin/sh\nexit 0\n"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(tree, "usr/bin/tool"), []byte("#!/bin/sh\necho tool\n"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(tree, "etc/tool.conf"), []byte("a=1\n"), 0o644))
			require.NoError(t, os.Symlink("tool", filepath.Join(tree, "usr/bin/alias")))

			out := filepath.Join(t.TempDir(), "x.deb")

			cmd := exec.Command(dpkgDeb, "--root-owner-group", "-Z"+comp, "-b", tree, out)
			if msg, err := cmd.CombinedOutput(); err != nil {
				if comp == "zstd" {
					t.Skipf("dpkg-deb cannot write zstd: %s", msg)
				}

				require.NoError(t, err, string(msg))
			}

			file, err := os.Open(out)
			require.NoError(t, err)

			defer file.Close()

			st, err := file.Stat()
			require.NoError(t, err)

			f, err := deb.ParseDebFileAt(file, st.Size())
			require.NoError(t, err)

			assert.Equal(t, "from-dpkg", f.Package.Package)
			assert.Equal(t, "3:1.2-4", f.Package.Version)
			assert.Equal(t, "amd64", f.Package.Architecture)
			assert.Equal(t, "libc6 (>= 2.31) | musl", f.Package.Depends)
			assert.Equal(t, "built by dpkg-deb\nlong text\n\nmore", f.Package.Description)
			assert.Equal(t, int64(4), f.Package.InstalledSize)
			assert.Equal(t, []string{"/etc/tool.conf"}, f.Conffiles())
			assert.Equal(t, "#!/bin/sh\nexit 0\n", string(f.Control["postinst"]))

			dir := t.TempDir()
			require.NoError(t, f.Extract(dir, deb.ExtractOptions{}))

			got, err := os.ReadFile(filepath.Join(dir, "usr/bin/tool"))
			require.NoError(t, err)
			assert.Equal(t, "#!/bin/sh\necho tool\n", string(got))

			link, err := os.Readlink(filepath.Join(dir, "usr/bin/alias"))
			require.NoError(t, err)
			assert.Equal(t, "tool", link)

			st, err = os.Stat(filepath.Join(dir, "usr/bin/tool"))
			require.NoError(t, err)
			assert.NotZero(t, st.Mode()&0o100, "the executable bit survives")
		})
	}
}

// FuzzParseDebFileAt feeds arbitrary bytes to the .deb parser; whatever it
// accepts must be extractable without leaving the directory.
func FuzzParseDebFileAt(f *testing.F) {
	f.Add([]byte("!<arch>\n"))
	f.Add([]byte{})
	f.Add(debWithData(f, buildTar(f, reg("./usr/bin/x", "x"), dirEntry("./etc/", 0o755), symlinkEntry("./l", "x"))))
	f.Add(debOf("control.tar.gz", compressWith(f, ".gz", controlTar(f, validControl)), "data.tar.xz", compressWith(f, ".xz", buildTar(f, reg("./a", "b")))))

	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := deb.ParseDebFileAt(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			require.ErrorIs(t, err, deb.ErrInvalidPackage)

			return
		}

		require.NotNil(t, d.Package)
		assert.NotEmpty(t, d.Package.Package)

		_ = d.Conffiles()

		if len(data) > 1<<16 {
			return
		}

		dir := t.TempDir()
		root := filepath.Join(dir, "root")
		require.NoError(t, os.Mkdir(root, 0o755))

		_ = d.Extract(root, deb.ExtractOptions{MaxBytes: 1 << 20, MaxEntries: 1000})

		// Nothing may have been created beside the root.
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Len(t, entries, 1)
	})
}

func TestParseErrorsAreSentinelMatchable(t *testing.T) {
	_, err := parseDeb([]byte("!<arch>\n"))
	require.True(t, errors.Is(err, deb.ErrInvalidPackage))
}
