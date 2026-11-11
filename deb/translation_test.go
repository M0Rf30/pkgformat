package deb_test

import (
	"bytes"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

func scanTranslationAll(t testing.TB, data []byte, lang string) []deb.TranslationEntry {
	t.Helper()

	var out []deb.TranslationEntry

	for e, err := range deb.ScanTranslation(bytes.NewReader(data), lang) {
		require.NoError(t, err)

		out = append(out, e)
	}

	return out
}

// Every English description of the Debian archive hashes to the
// Description-md5 it is filed under.
func TestDescriptionMD5MatchesDebianArchive(t *testing.T) {
	entries := scanTranslationAll(t, readFixture(t, "repo-translation", "debian-Translation-en"), "en")
	require.Len(t, entries, 12)

	multiline := 0

	for _, e := range entries {
		assert.Equal(t, e.DescriptionMD5, deb.DescriptionMD5(e.Description), e.Package)
		assert.Len(t, e.DescriptionMD5, 32)

		if strings.Contains(e.Description, "\n") {
			multiline++
		}
	}

	assert.Equal(t, 12, multiline)
	assert.Equal(t, "0ad", entries[0].Package)
	assert.Equal(t, "d943033bedada21853d2ae54a2578a7b", entries[0].DescriptionMD5)
	assert.Equal(t, "Real-time strategy game of ancient warfare", deb.ShortDescription(entries[0].Description))
}

func TestDescriptionMD5Forms(t *testing.T) {
	// A blank line of the logical text is the " ." of the file.
	a := deb.DescriptionMD5("short\nlong\n\nmore")
	assert.Equal(t, a, deb.DescriptionMD5("short\nlong\n.\nmore"), "a lone dot is how the file writes a blank line")
	assert.Equal(t, a, deb.DescriptionMD5("short\nlong\n \nmore"), "blank lines are alike")
	assert.NotEqual(t, a, deb.DescriptionMD5("short\nlong\nmore"))
	assert.Len(t, deb.DescriptionMD5(""), 32)
	assert.Equal(t, "short", deb.ShortDescription("short\nlong"))
	assert.Equal(t, "short", deb.ShortDescription("short"))
}

// The Packages stanzas of the Debian archive carry the short description and
// the md5 that finds the full text in Translation-en and its German
// translation in Translation-de.
func TestRealPackagesKeyTranslations(t *testing.T) {
	en, err := deb.ParseTranslation(bytes.NewReader(readFixture(t, "repo-translation", "debian-Translation-en")), "en")
	require.NoError(t, err)

	de, err := deb.ParseTranslation(bytes.NewReader(readFixture(t, "repo-translation", "debian-Translation-de")), "de")
	require.NoError(t, err)

	assert.Len(t, en, 12)
	assert.Len(t, de, 12)

	checked := 0

	err = deb.ScanControl(bytes.NewReader(readFixture(t, "repo-translation", "debian-Packages.head")), func(cf *deb.ControlFile) error {
		key := cf.Get("Description-md5")
		require.NotEmpty(t, key, cf.Get("Package"))

		full, ok := en[key]
		require.True(t, ok, "%s: no English text for %s", cf.Get("Package"), key)

		assert.Equal(t, cf.Get("Package"), full.Package)
		assert.Equal(t, cf.Get("Description"), deb.ShortDescription(full.Description), "the stanza holds the short description")
		assert.Equal(t, key, deb.DescriptionMD5(full.Description))
		assert.NotContains(t, cf.Get("Description"), "\n")

		if tr, ok := de[key]; ok {
			assert.Equal(t, cf.Get("Package"), tr.Package)
			assert.NotEqual(t, full.Description, tr.Description)
		}

		checked++

		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 8, checked)

	// German is keyed by the English md5, not by its own text.
	tr := de["d943033bedada21853d2ae54a2578a7b"]
	assert.Equal(t, "0ad", tr.Package)
	assert.True(t, strings.HasPrefix(tr.Description, "Echtzeit-Strategiespiel über antike Kriegsführung\n0 A.D. ist ein freies"))
	assert.NotEqual(t, deb.DescriptionMD5(tr.Description), tr.DescriptionMD5)
}

// What is read from a real Translation file is written back byte for byte.
func TestMarshalTranslationReproducesDebianFiles(t *testing.T) {
	for lang, name := range map[string]string{"en": "debian-Translation-en", "de": "debian-Translation-de"} {
		t.Run(lang, func(t *testing.T) {
			data := readFixture(t, "repo-translation", name)
			entries := scanTranslationAll(t, data, lang)

			assert.Equal(t, string(data), string(deb.MarshalTranslation(lang, entries)))

			// The archive lists packages in its own order; the builder sorts by
			// package name, so it holds the same paragraphs in another order.
			b := deb.NewTranslationBuilder(lang)
			for _, e := range entries {
				require.NoError(t, b.Add(e))
			}

			assert.Equal(t, lang, b.Language())
			assert.ElementsMatch(t, entries, b.Entries())

			again, err := deb.ParseTranslation(bytes.NewReader(b.Bytes()), lang)
			require.NoError(t, err)

			orig, err := deb.ParseTranslation(bytes.NewReader(data), lang)
			require.NoError(t, err)
			assert.Equal(t, orig, again)
		})
	}
}

func TestTranslationBuilder(t *testing.T) {
	en := deb.NewTranslationBuilder("en")

	require.NoError(t, en.Add(deb.TranslationEntry{Package: "zeta", Description: "Z\nlong z"}))
	require.NoError(t, en.Add(deb.TranslationEntry{Package: "alpha", Description: "A\nlong a"}))
	require.NoError(t, en.Add(deb.TranslationEntry{Package: "alpha-dup", Description: "A\nlong a"}), "the same description is one paragraph")
	require.NoError(t, en.Add(deb.TranslationEntry{Package: "beta", Description: "B", DescriptionMD5: strings.ToUpper(deb.DescriptionMD5("B"))}))

	assert.Equal(t, 3, en.Len())

	var names []string
	for _, e := range en.Entries() {
		names = append(names, e.Package)
	}

	assert.Equal(t, []string{"alpha", "beta", "zeta"}, names, "sorted by package; the first of a shared description stays")

	want := "Package: alpha\nDescription-md5: " + deb.DescriptionMD5("A\nlong a") + "\nDescription-en: A\n long a\n\n" +
		"Package: beta\nDescription-md5: " + deb.DescriptionMD5("B") + "\nDescription-en: B\n\n" +
		"Package: zeta\nDescription-md5: " + deb.DescriptionMD5("Z\nlong z") + "\nDescription-en: Z\n long z\n\n"
	assert.Equal(t, want, string(en.Bytes()))

	// The order of Add does not matter.
	other := deb.NewTranslationBuilder("en")
	for _, e := range []deb.TranslationEntry{{Package: "beta", Description: "B"}, {Package: "alpha", Description: "A\nlong a"}, {Package: "zeta", Description: "Z\nlong z"}} {
		require.NoError(t, other.Add(e))
	}

	assert.Equal(t, string(en.Bytes()), string(other.Bytes()))

	// A translation is filed under the English md5.
	de := deb.NewTranslationBuilder("de")
	require.NoError(t, de.Add(deb.TranslationEntry{Package: "alpha", DescriptionMD5: deb.DescriptionMD5("A\nlong a"), Description: "Ä\nlang ä"}))
	assert.Contains(t, string(de.Bytes()), "Description-md5: "+deb.DescriptionMD5("A\nlong a")+"\nDescription-de: Ä\n lang ä\n")

	got, err := deb.ParseTranslation(bytes.NewReader(de.Bytes()), "de")
	require.NoError(t, err)
	assert.Equal(t, "Ä\nlang ä", got[deb.DescriptionMD5("A\nlong a")].Description)

	// Blank lines survive a round trip.
	blank := deb.NewTranslationBuilder("en")
	require.NoError(t, blank.Add(deb.TranslationEntry{Package: "p", Description: "s\nfirst\n\nsecond"}))
	assert.Contains(t, string(blank.Bytes()), "Description-en: s\n first\n .\n second\n")

	rt := scanTranslationAll(t, blank.Bytes(), "en")
	require.Len(t, rt, 1)
	assert.Equal(t, deb.DescriptionMD5("s\nfirst\n\nsecond"), rt[0].DescriptionMD5)
}

func TestTranslationBuilderErrors(t *testing.T) {
	b := deb.NewTranslationBuilder("en")

	require.ErrorIs(t, b.Add(deb.TranslationEntry{Description: "x"}), deb.ErrInvalidTranslation)
	require.ErrorIs(t, b.Add(deb.TranslationEntry{Package: "p"}), deb.ErrInvalidTranslation)
	require.ErrorIs(t, b.Add(deb.TranslationEntry{Package: "p", Description: "  \n "}), deb.ErrInvalidTranslation)

	for _, lang := range []string{"", "d e", "../x", "de/../en", "de\n"} {
		require.ErrorIs(t, deb.NewTranslationBuilder(lang).Add(deb.TranslationEntry{Package: "p", Description: "d"}), deb.ErrInvalidTranslation, "%q", lang)
	}

	require.NoError(t, deb.NewTranslationBuilder("pt_BR").Add(deb.TranslationEntry{Package: "p", Description: "d"}))
	require.NoError(t, deb.NewTranslationBuilder("zh-Hans").Add(deb.TranslationEntry{Package: "p", Description: "d"}))
}

func TestTranslationBuilderCompressed(t *testing.T) {
	b := deb.NewTranslationBuilder("de")
	for i := range 50 {
		require.NoError(t, b.Add(deb.TranslationEntry{Package: "p" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Description: "Kurz " + strings.Repeat("x", i) + "\nLang"}))
	}

	for c, ext := range map[deb.Compression]string{deb.CompressionNone: "", deb.CompressionGzip: ".gz", deb.CompressionXZ: ".xz", deb.CompressionZstd: ".zst"} {
		packed, err := b.Compressed(c)
		require.NoError(t, err)

		rc, err := deb.OpenIndex(bytes.NewReader(packed), deb.TranslationFileName("de", ext))
		require.NoError(t, err)

		got, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
		assert.Equal(t, string(b.Bytes()), string(got))

		var buf bytes.Buffer

		n, err := b.WriteTo(&buf, c)
		require.NoError(t, err)
		assert.Equal(t, int64(buf.Len()), n)
		assert.Equal(t, packed, buf.Bytes(), "compression %d is deterministic", c)
	}

	_, err := b.Compressed(deb.Compression(42))
	require.Error(t, err)

	_, err = b.WriteTo(ctsFailWriter{}, deb.CompressionGzip)
	require.Error(t, err)
	assert.Equal(t, "Translation-de.xz", deb.TranslationFileName("de", ".xz"))
}

func TestScanTranslationShapes(t *testing.T) {
	doc := "Package: a\nDescription-md5: ABCDEF\nDescription-de: Kurz\n lang\n\n" +
		"Package: b\nDescription-md5: 1\nDescription-en: only English\n\n" +
		"Description-md5: 2\nDescription-de: no package\n\n" +
		"Package: c\nDescription-de: no md5\n\n"

	got := scanTranslationAll(t, []byte(doc), "de")
	require.Len(t, got, 2)
	assert.Equal(t, deb.TranslationEntry{Package: "a", DescriptionMD5: "abcdef", Description: "Kurz\nlang"}, got[0], "md5 is lower-cased")
	assert.Equal(t, "", got[1].DescriptionMD5)

	m, err := deb.ParseTranslation(strings.NewReader(doc), "de")
	require.NoError(t, err)
	assert.Contains(t, m, "abcdef")
	assert.Contains(t, m, deb.DescriptionMD5("no md5"), "no md5: keyed by the text's own")

	// Stopping early.
	for range deb.ScanTranslation(strings.NewReader(doc), "de") {
		break
	}

	// Errors are reported through the iterator.
	var seen error

	for _, err := range deb.ScanTranslation(strings.NewReader("Package: a\n"+strings.Repeat("x", deb.MaxLineBytes+10)), "de") {
		seen = err
	}

	require.Error(t, seen)

	_, err = deb.ParseTranslation(strings.NewReader("Package: a\n"+strings.Repeat("x", deb.MaxLineBytes+10)), "de")
	require.Error(t, err)
}

// The short Packages stanza of apt-ftparchive (LongDescription off) is what
// FormatPackagesEntryShort writes, and its Description-md5 finds the text the
// TranslationBuilder files.
func TestFormatPackagesEntryShortMatchesAptFTPArchive(t *testing.T) {
	ftp, err := exec.LookPath("apt-ftparchive")
	if err != nil {
		t.Skip("apt-ftparchive not installed")
	}

	pool := filepath.Join("testdata", "repo-contents", "pool")
	names, err := filepath.Glob(filepath.Join(pool, "*.deb"))
	require.NoError(t, err)
	require.Len(t, names, 3)

	cmd := exec.Command(ftp, "-o", "APT::FTPArchive::LongDescription=false", "packages", "pool")
	cmd.Dir = filepath.Join("testdata", "repo-contents")

	out, err := cmd.Output()
	require.NoError(t, err)

	var short, full strings.Builder

	b := deb.NewTranslationBuilder("en")

	for _, n := range names {
		e := indexEntryOf(t, n, "pool/"+filepath.Base(n))
		short.WriteString(deb.FormatPackagesEntryShort(e))
		full.WriteString(deb.FormatPackagesEntry(e))

		require.NoError(t, b.AddIndexEntry(e))
	}

	// The tool's field order depends on its version; the fields and values
	// are the contract.
	theirs, ours := scanAll(t, string(out)), scanAll(t, short.String())
	require.Len(t, ours, len(theirs))

	for i := range theirs {
		assert.Equal(t, stanzaFields(t, theirs[i].Text), stanzaFields(t, ours[i].Text), theirs[i].Package)
	}

	assert.NotEqual(t, short.String(), full.String())
	assert.Contains(t, short.String(), "Description: alpha test package\nDescription-md5: ")

	// Each md5 of the short Packages is a key of the Translation-en built from the same entries.
	keys := map[string]bool{}
	for _, e := range b.Entries() {
		keys[e.DescriptionMD5] = true
	}

	require.NoError(t, deb.ScanControl(strings.NewReader(short.String()), func(cf *deb.ControlFile) error {
		assert.True(t, keys[cf.Get("Description-md5")], cf.Get("Package"))

		return nil
	}))
}

func TestFormatPackagesEntryShortWithoutDescription(t *testing.T) {
	e := deb.IndexEntry{Name: "p", Version: "1", Arch: "all", Filename: "pool/p.deb", Size: 1, SHA256: strings.Repeat("a", 64)}
	assert.Equal(t, deb.FormatPackagesEntry(e), deb.FormatPackagesEntryShort(e))
	assert.Empty(t, e.TranslationEntry().Description)

	b := deb.NewTranslationBuilder("en")
	require.NoError(t, b.AddIndexEntry(e))
	assert.Zero(t, b.Len(), "no description, nothing to translate")
}

func FuzzScanTranslation(f *testing.F) {
	f.Add(string(readFixtureBytes("repo-translation", "debian-Translation-de"))[:900])
	f.Add("Package: a\nDescription-md5: x\nDescription-en: s\n l\n .\n m\n\n")
	f.Add("Package: a\nDescription-en: \n\n\n\nPackage: b\n")

	f.Fuzz(func(t *testing.T, in string) {
		m, err := deb.ParseTranslation(strings.NewReader(in), "en")
		if err != nil {
			return
		}

		b := deb.NewTranslationBuilder("en")

		for _, e := range m {
			assert.NotEmpty(t, e.Package)
			assert.NotEmpty(t, e.Description)

			// Entries a builder accepts are read back the same.
			if b.Add(e) != nil {
				return
			}
		}

		again, err := deb.ParseTranslation(bytes.NewReader(b.Bytes()), "en")
		require.NoError(t, err)

		for k, e := range m {
			if got, ok := again[k]; ok {
				assert.Equal(t, e.Package, got.Package)
			}
		}
	})
}
