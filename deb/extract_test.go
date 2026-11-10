package deb_test

import (
	"archive/tar"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

func extractTar(t *testing.T, opts deb.ExtractOptions, entries ...tarEntry) (string, error) {
	t.Helper()

	f, err := parseDeb(debWithData(t, buildTar(t, entries...)))
	require.NoError(t, err)

	dir := t.TempDir()

	return dir, f.Extract(dir, opts)
}

func TestExtractBasics(t *testing.T) {
	dir, err := extractTar(t, deb.ExtractOptions{},
		dirEntry("./", 0o755),
		dirEntry("./usr/", 0o755),
		dirEntry("./usr/bin/", 0o755),
		reg("./usr/bin/tool", "tool"),
		symlinkEntry("./usr/bin/alias", "tool"),
		hardlinkEntry("./usr/bin/hard", "./usr/bin/tool"),
		reg("etc/implicit/parent.conf", "p"),
		reg("/abs/name", "absolute names are root-relative"),
	)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(dir, "usr/bin/tool"))
	require.NoError(t, err)
	assert.Equal(t, "tool", string(got))

	link, err := os.Readlink(filepath.Join(dir, "usr/bin/alias"))
	require.NoError(t, err)
	assert.Equal(t, "tool", link)

	hard, err := os.ReadFile(filepath.Join(dir, "usr/bin/hard"))
	require.NoError(t, err)
	assert.Equal(t, "tool", string(hard))

	st1, _ := os.Stat(filepath.Join(dir, "usr/bin/tool"))
	st2, _ := os.Stat(filepath.Join(dir, "usr/bin/hard"))
	assert.True(t, os.SameFile(st1, st2))

	assert.FileExists(t, filepath.Join(dir, "etc/implicit/parent.conf"))
	assert.FileExists(t, filepath.Join(dir, "abs/name"))
}

func TestExtractModes(t *testing.T) {
	dir, err := extractTar(t, deb.ExtractOptions{},
		dirEntry("./private/", 0o750),
		dirEntry("./readonly/", 0o555),
		dirEntry("./sticky/", 0o1755),
		tarEntry{hdr: tar.Header{Name: "./private/exec", Mode: 0o755}, body: "x"},
		tarEntry{hdr: tar.Header{Name: "./private/suid", Mode: 0o4755}, body: "x"},
		tarEntry{hdr: tar.Header{Name: "./private/sgid", Mode: 0o2755}, body: "x"},
		tarEntry{hdr: tar.Header{Name: "./private/secret", Mode: 0o600}, body: "x"},
	)
	require.NoError(t, err)

	mode := func(p string) fs.FileMode {
		st, err := os.Lstat(filepath.Join(dir, p))
		require.NoError(t, err)

		return st.Mode()
	}

	assert.Equal(t, fs.ModeDir|0o750, mode("private"))
	assert.Equal(t, fs.ModeDir|0o755, mode("readonly"), "the owner keeps write access so entries below can be created")
	assert.Zero(t, mode("sticky")&fs.ModeSticky)
	assert.NotZero(t, mode("private/exec")&0o100)
	assert.Zero(t, mode("private/suid")&(fs.ModeSetuid|fs.ModeSetgid))
	assert.Zero(t, mode("private/sgid")&(fs.ModeSetuid|fs.ModeSetgid))
	assert.Equal(t, fs.FileMode(0o600), mode("private/secret"))
}

func TestExtractSkipsDevices(t *testing.T) {
	dir, err := extractTar(t, deb.ExtractOptions{},
		tarEntry{hdr: tar.Header{Name: "./dev/null", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3}},
		tarEntry{hdr: tar.Header{Name: "./dev/sda", Typeflag: tar.TypeBlock, Devmajor: 8}},
		tarEntry{hdr: tar.Header{Name: "./run/fifo", Typeflag: tar.TypeFifo}},
		reg("./kept", "x"),
	)
	require.NoError(t, err)

	assert.NoFileExists(t, filepath.Join(dir, "dev/null"))
	assert.NoFileExists(t, filepath.Join(dir, "dev/sda"))
	assert.NoFileExists(t, filepath.Join(dir, "run/fifo"))
	assert.FileExists(t, filepath.Join(dir, "kept"))
}

func TestExtractReplacesExisting(t *testing.T) {
	dir, err := extractTar(t, deb.ExtractOptions{},
		reg("./a", "first"),
		reg("./a", "second, longer"),
		symlinkEntry("./l", "a"),
		symlinkEntry("./l", "b"),
		hardlinkEntry("./h", "./a"),
		hardlinkEntry("./h", "./a"),
	)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(dir, "a"))
	require.NoError(t, err)
	assert.Equal(t, "second, longer", string(got))

	link, err := os.Readlink(filepath.Join(dir, "l"))
	require.NoError(t, err)
	assert.Equal(t, "b", link)
}

func TestExtractUnsafeEntries(t *testing.T) {
	cases := map[string][]tarEntry{
		"file with ..":              {reg("../x", "evil")},
		"file climbing":             {reg("a/../../x", "evil")},
		"dot-slash climbing":        {reg("./../x", "evil")},
		"dir with ..":               {dirEntry("../d/", 0o755)},
		"symlink name with ..":      {symlinkEntry("../l", "target")},
		"symlink escaping":          {symlinkEntry("evil", "../outside")},
		"nested symlink escaping":   {symlinkEntry("a/b/evil", "../../../outside")},
		"symlink escaping via dots": {symlinkEntry("a/evil", "b/../../../outside")},
		"hardlink escaping":         {hardlinkEntry("evil", "../../etc/passwd")},
		"hardlink name with ..":     {reg("src", "x"), hardlinkEntry("../evil", "src")},
		"root as symlink":           {symlinkEntry("./", "x")},
	}

	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "root")
			require.NoError(t, os.Mkdir(root, 0o755))

			f, err := parseDeb(debWithData(t, buildTar(t, entries...)))
			require.NoError(t, err)

			err = f.Extract(root, deb.ExtractOptions{})
			require.ErrorIs(t, err, deb.ErrUnsafeEntry)

			// Nothing was created next to the extraction root.
			siblings, err := os.ReadDir(parent)
			require.NoError(t, err)
			assert.Len(t, siblings, 1)
		})
	}
}

func TestExtractSymlinkWriteThrough(t *testing.T) {
	victim := t.TempDir()

	for name, entries := range map[string][]tarEntry{
		"absolute symlink then file":             {symlinkEntry("evil", victim), reg("evil/pwned", "x")},
		"absolute symlink then dir":              {symlinkEntry("evil", victim), dirEntry("evil/sub/", 0o755), reg("evil/sub/pwned", "x")},
		"absolute symlink then link":             {reg("src", "x"), symlinkEntry("evil", victim), hardlinkEntry("evil/pwned", "src")},
		"absolute symlink then link, symlink":    {symlinkEntry("evil", victim), symlinkEntry("evil/pwned", "x")},
		"absolute file symlink":                  {symlinkEntry("evil", filepath.Join(victim, "pwned")), reg("evil", "x")},
		"usr-merge style":                        {symlinkEntry("a", "/"), reg("a/pwned", "x")},
		"chain of symlinks":                      {symlinkEntry("a", "b"), symlinkEntry("b", victim), reg("a/pwned", "x")},
		"relative symlink to parent dir of root": {dirEntry("d/", 0o755), symlinkEntry("d/up", ".."), reg("d/up/up/up/pwned", "x")},
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "root")
			require.NoError(t, os.Mkdir(root, 0o755))

			f, err := parseDeb(debWithData(t, buildTar(t, entries...)))
			require.NoError(t, err)

			// The extraction either fails or confines the write to root.
			_ = f.Extract(root, deb.ExtractOptions{})

			assert.NoFileExists(t, filepath.Join(victim, "pwned"))
			assert.NoFileExists(t, filepath.Join(parent, "pwned"))

			siblings, err := os.ReadDir(parent)
			require.NoError(t, err)
			assert.Len(t, siblings, 1)
		})
	}
}

func TestExtractAbsoluteSymlinkReinterpreted(t *testing.T) {
	// A link to an absolute path is created as is (it only resolves once the
	// package is installed), but writing through it lands inside the root.
	dir, err := extractTar(t, deb.ExtractOptions{},
		symlinkEntry("lib", "/usr/lib"),
		reg("lib/libx.so", "x"),
	)
	require.NoError(t, err)

	link, err := os.Readlink(filepath.Join(dir, "lib"))
	require.NoError(t, err)
	assert.Equal(t, "/usr/lib", link)
	assert.FileExists(t, filepath.Join(dir, "usr/lib/libx.so"))
}

func TestExtractLimits(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		_, err := extractTar(t, deb.ExtractOptions{MaxBytes: 10}, reg("a", "123456"), reg("b", "123456"))
		require.ErrorIs(t, err, deb.ErrDataTooLarge)
	})

	t.Run("single file over the limit", func(t *testing.T) {
		dir, err := extractTar(t, deb.ExtractOptions{MaxBytes: 5}, reg("a", "123456"))
		require.ErrorIs(t, err, deb.ErrDataTooLarge)
		assert.NoFileExists(t, filepath.Join(dir, "a"))
	})

	t.Run("bytes exactly at the limit", func(t *testing.T) {
		_, err := extractTar(t, deb.ExtractOptions{MaxBytes: 12}, reg("a", "123456"), reg("b", "123456"))
		require.NoError(t, err)
	})

	t.Run("entries", func(t *testing.T) {
		var entries []tarEntry
		for i := range 5 {
			entries = append(entries, reg(fmt.Sprintf("f%d", i), "x"))
		}

		_, err := extractTar(t, deb.ExtractOptions{MaxEntries: 4}, entries...)
		require.ErrorIs(t, err, deb.ErrDataTooLarge)

		_, err = extractTar(t, deb.ExtractOptions{MaxEntries: 5}, entries...)
		require.NoError(t, err)
	})

	t.Run("directories count as entries", func(t *testing.T) {
		_, err := extractTar(t, deb.ExtractOptions{MaxEntries: 2}, dirEntry("a/", 0o755), dirEntry("b/", 0o755), dirEntry("c/", 0o755))
		require.ErrorIs(t, err, deb.ErrDataTooLarge)
	})
}

func TestExtractBadArchive(t *testing.T) {
	good := buildTar(t, reg("./f", strings.Repeat("x", 4096)))

	f, err := parseDeb(debWithData(t, good[:700]))
	require.NoError(t, err)
	require.Error(t, f.Extract(t.TempDir(), deb.ExtractOptions{}))

	f, err = parseDeb(debWithData(t, []byte(strings.Repeat("z", 1024))))
	require.NoError(t, err)
	require.Error(t, f.Extract(t.TempDir(), deb.ExtractOptions{}))
}

func TestExtractIntoMissingOrFileDir(t *testing.T) {
	f, err := parseDeb(debWithData(t, buildTar(t, reg("f", "x"))))
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "afile")
	require.NoError(t, os.WriteFile(file, nil, 0o644))
	require.Error(t, f.Extract(file, deb.ExtractOptions{}))
}

func TestExtractWriterRoundTrip(t *testing.T) {
	// A package the writer produced extracts to the payload it was given.
	payload := []deb.Entry{
		{Path: "usr/share/doc/x/README", Mode: 0o644, Data: []byte("readme")},
		{Path: "usr/bin/x", Mode: 0o4755, Data: []byte("bin")},
		{Path: "var/empty", Mode: fs.ModeDir | 0o700},
	}

	path := filepath.Join(t.TempDir(), "x.deb")
	require.NoError(t, deb.WriteFile(path, testSpec(), payload, deb.WriteOptions{}))

	file, err := os.Open(path)
	require.NoError(t, err)

	defer file.Close()

	st, err := file.Stat()
	require.NoError(t, err)

	f, err := deb.ParseDebFileAt(file, st.Size())
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, f.Extract(dir, deb.ExtractOptions{}))

	got, err := os.ReadFile(filepath.Join(dir, "usr/share/doc/x/README"))
	require.NoError(t, err)
	assert.Equal(t, "readme", string(got))

	info, err := os.Stat(filepath.Join(dir, "usr/bin/x"))
	require.NoError(t, err)
	assert.Zero(t, info.Mode()&fs.ModeSetuid, "setuid is dropped on extraction")

	info, err = os.Stat(filepath.Join(dir, "var/empty"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}
