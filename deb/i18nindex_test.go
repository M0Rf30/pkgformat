package deb_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

// Ubuntu's i18n/Index is read and written back byte for byte.
func TestI18nIndexMatchesUbuntuArchive(t *testing.T) {
	data := readFixture(t, "repo", "ubuntu-jammy.i18n.Index")

	ix, err := deb.ParseI18nIndex(data)
	require.NoError(t, err)

	assert.Equal(t, string(data), string(ix.Marshal()))

	langs := ix.Languages()
	require.NotEmpty(t, langs)
	assert.Contains(t, langs, "en")
	assert.Contains(t, langs, "de")
	assert.IsIncreasing(t, langs)

	vs := ix.Variants("de")
	require.Len(t, vs, 3)
	assert.Equal(t, []string{".xz", ".gz", ""}, []string{vs[0].Extension, vs[1].Extension, vs[2].Extension})
	assert.Equal(t, "Translation-de.xz", vs[0].Path)
	assert.Equal(t, int64(492612), vs[0].Info.Size)
	assert.Equal(t, "4f8ceb1651998353d48f427e560114a597fad7de", vs[0].Info.SHA1)
	assert.Empty(t, ix.Variants("xx"))

	assert.Equal(t, "main/i18n/Index", deb.I18nIndexName("main"))
}

func TestI18nIndexBuild(t *testing.T) {
	var ix deb.I18nIndex

	for _, f := range []struct {
		name string
		data string
	}{{"Translation-en", "en"}, {"Translation-en.xz", "en-packed"}, {"Translation-de.gz", "de-packed"}, {"Translation-pt_BR", "pt"}} {
		ix.AddFile(deb.HashBytes(f.name, []byte(f.data)))
	}

	assert.Equal(t, []string{"de", "en", "pt_BR"}, ix.Languages())

	out := string(ix.Marshal())
	for _, sec := range []string{"MD5Sum:\n", "SHA1:\n", "SHA256:\n", "SHA512:\n"} {
		assert.Contains(t, out, sec)
	}

	got, err := deb.ParseI18nIndex([]byte(out))
	require.NoError(t, err)
	assert.Equal(t, ix.Files, got.Files)

	// Only SHA1 digests: only the SHA1 section.
	sha1only := &deb.I18nIndex{}
	sha1only.AddFile(deb.FileInfo{Path: "Translation-en", Size: 5, SHA1: strings.Repeat("a", 40)})
	assert.Equal(t, "SHA1:\n "+strings.Repeat("a", 40)+"       5 Translation-en\n", string(sha1only.Marshal()))

	// A Release lists the index like any other file.
	rel := &deb.Release{}
	rel.AddFile(deb.HashBytes(deb.I18nIndexName("main"), ix.Marshal()))
	assert.Equal(t, int64(len(ix.Marshal())), rel.Files["main/i18n/Index"].Size)
}

func TestParseI18nIndexErrors(t *testing.T) {
	_, err := deb.ParseI18nIndex([]byte("SHA1:\n abc 5 Translation-en\n"))
	require.Error(t, err, "a digest of the wrong length")

	_, err = deb.ParseI18nIndex(make([]byte, deb.MaxReleaseBytes+1))
	require.ErrorIs(t, err, deb.ErrTooLarge)

	ix, err := deb.ParseI18nIndex(nil)
	require.NoError(t, err)
	assert.Empty(t, ix.Files)
	assert.Empty(t, ix.Marshal())
}

func FuzzParseI18nIndex(f *testing.F) {
	f.Add(string(readFixtureBytes("repo", "ubuntu-jammy.i18n.Index")))
	f.Add("SHA256:\n " + strings.Repeat("a", 64) + " 1 Translation-en.xz\n")
	f.Add("-----BEGIN PGP SIGNED MESSAGE-----\n\nSHA1:\n x\n")

	f.Fuzz(func(t *testing.T, in string) {
		ix, err := deb.ParseI18nIndex([]byte(in))
		if err != nil {
			return
		}

		for name, fi := range ix.Files {
			assert.Equal(t, name, fi.Path)
			assert.GreaterOrEqual(t, fi.Size, int64(0))
		}

		_ = ix.Languages()

		again, err := deb.ParseI18nIndex(ix.Marshal())
		require.NoError(t, err)
		assert.Equal(t, ix.Files, again.Files)
	})
}
