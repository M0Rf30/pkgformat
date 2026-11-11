package deb_test

import (
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

const translationRepoDir = "repo-translation"

// translationRepoPackages are the packages of the end-to-end repository, with
// their English and German descriptions.
var translationRepoPackages = []struct {
	spec deb.Spec
	de   string
}{
	{
		spec: deb.Spec{
			Name: "hello", Version: "1.0", Release: "1", Architecture: "amd64", Section: "utils", Priority: "optional",
			Maintainer: "Test <test@example.org>", Description: "friendly greeter\nPrints a greeting.\n\nSecond paragraph.",
		},
		de: "freundlicher Gruesser\nGibt einen Gruss aus.\n\nZweiter Absatz.",
	},
	{
		spec: deb.Spec{
			Name: "hello-doc", Version: "1.0", Release: "1", Architecture: "all", Section: "doc", Priority: "optional",
			Maintainer: "Test <test@example.org>", Description: "documentation of hello\nThe manual.",
		},
		de: "Dokumentation von hello\nDas Handbuch.",
	},
}

// buildTranslationRepo writes, with this package only, a repository for suite
// bookworm: two packages, Packages with short descriptions, Translation-en and
// Translation-de, their i18n/Index, the by-hash tree and the Release. Times are
// fixed, so the tree is the same on every run.
func buildTranslationRepo(t *testing.T, root string) {
	t.Helper()

	stamp := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	dist := filepath.Join(root, "dists", "bookworm")

	write := func(rel string, data []byte) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, data, 0o644))
		require.NoError(t, os.Chtimes(full, stamp, stamp))
	}

	var packages deb.Index

	en, de := deb.NewTranslationBuilder("en"), deb.NewTranslationBuilder("de")

	for _, p := range translationRepoPackages {
		spec := p.spec
		spec.Compression = "gzip"
		spec.ModTime = stamp

		poolDir := deb.PoolPath("main", spec.Name, spec.FileName())
		require.NoError(t, os.MkdirAll(filepath.Join(root, filepath.Dir(filepath.FromSlash(poolDir))), 0o755))

		debPath := filepath.Join(root, filepath.FromSlash(poolDir))
		require.NoError(t, deb.WriteFile(debPath, &spec, []deb.Entry{{Path: "usr/share/doc/" + spec.Name + "/README", Mode: 0o644, Data: []byte(spec.Name + "\n")}}, deb.WriteOptions{}))
		require.NoError(t, os.Chtimes(debPath, stamp, stamp))

		e := indexEntryOf(t, debPath, poolDir)
		packages.AddText(deb.FormatPackagesEntryShort(e))

		require.NoError(t, en.AddIndexEntry(e))
		require.NoError(t, de.Add(deb.TranslationEntry{Package: spec.Name, DescriptionMD5: e.TranslationEntry().DescriptionMD5, Description: p.de}))
	}

	rel := &deb.Release{
		Origin: "pkgformat test", Label: "pkgformat", Suite: "stable", Codename: "bookworm", Date: stamp, AcquireByHash: true,
		Architectures: []string{"amd64"}, Components: []string{"main"}, Description: "Translation end-to-end repository",
	}

	var i18n deb.I18nIndex

	addIndex := func(rel2 *deb.Release, relPath string, data []byte) {
		write(path.Join("dists/bookworm", relPath), data)
		rel2.AddFile(deb.HashBytes(relPath, data))
	}

	for _, c := range []struct {
		comp deb.Compression
		ext  string
	}{{deb.CompressionNone, ""}, {deb.CompressionGzip, ".gz"}, {deb.CompressionXZ, ".xz"}} {
		raw, err := packages.Compressed(c.comp)
		require.NoError(t, err)

		addIndex(rel, "main/binary-amd64/Packages"+c.ext, raw)
	}

	for lang, b := range map[string]*deb.TranslationBuilder{"en": en, "de": de} {
		for _, ext := range []string{"", ".xz"} {
			comp := deb.CompressionNone
			if ext == ".xz" {
				comp = deb.CompressionXZ
			}

			data, err := b.Compressed(comp)
			require.NoError(t, err)

			name := deb.TranslationFileName(lang, ext)
			addIndex(rel, "main/i18n/"+name, data)
			i18n.AddFile(deb.HashBytes(name, data))
		}
	}

	addIndex(rel, deb.I18nIndexName("main"), i18n.Marshal())

	require.NoError(t, os.MkdirAll(dist, 0o755))
	write("dists/bookworm/Release", rel.Marshal())

	_, err := deb.WriteByHash(dist, rel, deb.ByHashOptions{})
	require.NoError(t, err)
}

func treeFiles(t testing.TB, root string) map[string]string {
	t.Helper()

	out := map[string]string{}

	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		rel, _ := filepath.Rel(root, p)
		data, err := os.ReadFile(p)
		require.NoError(t, err)

		out[filepath.ToSlash(rel)] = string(data)

		return nil
	}))

	return out
}

// The committed repository (testdata/repo-translation/repo) is what the code
// builds. Set PKGFORMAT_UPDATE=1 to rewrite it (generate.sh does).
func TestTranslationRepoFixture(t *testing.T) {
	committed := filepath.Join("testdata", translationRepoDir, "repo")

	if os.Getenv("PKGFORMAT_UPDATE") == "1" {
		require.NoError(t, os.RemoveAll(committed))
		buildTranslationRepo(t, committed)
	}

	built := t.TempDir()
	buildTranslationRepo(t, built)

	want, got := treeFiles(t, committed), treeFiles(t, built)
	require.NotEmpty(t, want, "run generate.sh")

	assert.Equal(t, len(want), len(got))

	for p, content := range want {
		assert.Equal(t, content, got[p], p)
	}

	// The committed Release lists every file of the tree it is part of, with
	// the digests the files have, and by-hash copies for each.
	rel, err := deb.ParseRelease([]byte(want["dists/bookworm/Release"]))
	require.NoError(t, err)

	assert.True(t, rel.AcquireByHash)
	assert.Equal(t, []string{"de", "en"}, rel.TranslationLanguages("main"))
	assert.Equal(t, []string{"main/i18n/Translation-de.xz", "main/i18n/Translation-de"}, rel.IndexPaths("main", "", "Translation-de"))
	assert.Len(t, rel.PackagesVariants("main", "amd64"), 3)

	for p, fi := range rel.Files {
		content, ok := want["dists/bookworm/"+p]
		require.True(t, ok, p)
		assert.Equal(t, deb.HashBytes(p, []byte(content)), fi, p)

		for _, ref := range rel.ByHashRefs(p) {
			if ref.Algorithm != deb.ByHashSHA256 && ref.Algorithm != deb.ByHashSHA512 {
				continue
			}

			assert.Equal(t, content, want["dists/bookworm/"+ref.Path], ref.Path)
		}
	}

	// The i18n Index lists the Translation files with their digests.
	ix, err := deb.ParseI18nIndex([]byte(want["dists/bookworm/main/i18n/Index"]))
	require.NoError(t, err)
	assert.Equal(t, []string{"de", "en"}, ix.Languages())

	for _, v := range ix.Variants("de") {
		assert.Equal(t, deb.HashBytes(v.Path, []byte(want["dists/bookworm/main/i18n/"+v.Path])), v.Info)
	}

	// The short Packages stanzas are keyed to the Translation files.
	de, err := deb.ParseTranslation(strings.NewReader(want["dists/bookworm/main/i18n/Translation-de"]), "de")
	require.NoError(t, err)

	require.NoError(t, deb.ScanControl(strings.NewReader(want["dists/bookworm/main/binary-amd64/Packages"]), func(cf *deb.ControlFile) error {
		assert.NotContains(t, cf.Get("Description"), "\n")
		assert.Contains(t, de, cf.Get("Description-md5"), cf.Get("Package"))

		return nil
	}))

	// What apt printed for them when the fixture was generated.
	for _, mode := range []string{"trusted", "signed"} {
		expected := string(readFixture(t, translationRepoDir, "expected-"+mode+".txt"))
		assert.Contains(t, expected, "Description-de: freundlicher Gruesser\n Gibt einen Gruss aus.\n .\n Zweiter Absatz.\n", mode)
		assert.Contains(t, expected, "Description-md5: ", mode)
		assert.Contains(t, expected, "Translation-de", mode)
	}
}

// With PKGFORMAT_E2E=1 and podman, apt itself updates from the repository with
// the German translations enabled and shows Description-de. The container
// runs testdata/repo-translation/container.sh; PKGFORMAT_E2E_IMAGE overrides
// the image (default docker.io/library/debian:bookworm-slim).
func TestTranslationRepoWithApt(t *testing.T) {
	if os.Getenv("PKGFORMAT_E2E") != "1" {
		t.Skip("set PKGFORMAT_E2E=1 to run the podman end-to-end test")
	}

	podman, err := exec.LookPath("podman")
	if err != nil {
		t.Skip("podman not installed")
	}

	image := os.Getenv("PKGFORMAT_E2E_IMAGE")
	if image == "" {
		image = "docker.io/library/debian:bookworm-slim"
	}

	script, err := filepath.Abs(filepath.Join("testdata", translationRepoDir, "container.sh"))
	require.NoError(t, err)

	for _, mode := range []string{"trusted", "signed"} {
		t.Run(mode, func(t *testing.T) {
			repo := t.TempDir()
			buildTranslationRepo(t, repo)

			if mode == "signed" {
				signRepo(t, repo)
			}

			out := runAptContainer(t, podman, image, repo, script, mode)

			assert.Equal(t, string(readFixture(t, translationRepoDir, "expected-"+mode+".txt")), out)
			assert.Contains(t, out, "Description-de: freundlicher Gruesser")
		})
	}
}

// signRepo signs the Release of the repository with a fresh key: InRelease,
// Release.gpg and key.asc at the root.
func signRepo(t testing.TB, repo string) {
	t.Helper()

	signer := newSigner(t, "e2e")

	release, err := os.ReadFile(filepath.Join(repo, "dists", "bookworm", "Release"))
	require.NoError(t, err)

	signed, err := deb.SignRelease(signer, release)
	require.NoError(t, err)

	pub, err := signer.PublicKey()
	require.NoError(t, err)

	for name, data := range map[string][]byte{
		"dists/bookworm/InRelease": signed.InRelease, "dists/bookworm/Release.gpg": signed.ReleaseGPG, "key.asc": pub,
	} {
		require.NoError(t, os.WriteFile(filepath.Join(repo, filepath.FromSlash(name)), data, 0o644))
	}
}

// runAptContainer runs container.sh in the image against the repository and
// returns its output.
func runAptContainer(t testing.TB, podman, image, repo, script, mode string) string {
	t.Helper()

	cmd := exec.Command(podman, "run", "--rm", "--network=none",
		"-v", repo+":/repo:ro,z", "-v", script+":/container.sh:ro,z", image, "sh", "/container.sh", mode)

	var stderr strings.Builder

	cmd.Stderr = &stderr

	out, err := cmd.Output()
	require.NoError(t, err, stderr.String())

	return string(out)
}

// UpdateExpected is used by generate.sh: it runs the container and writes the
// expected outputs. It is a test so that it shares the repository builder.
func TestTranslationRepoRecordExpected(t *testing.T) {
	if os.Getenv("PKGFORMAT_UPDATE") != "1" {
		t.Skip("run by generate.sh with PKGFORMAT_UPDATE=1")
	}

	podman, err := exec.LookPath("podman")
	if err != nil {
		t.Skip("podman not installed")
	}

	image := os.Getenv("PKGFORMAT_E2E_IMAGE")
	if image == "" {
		image = "docker.io/library/debian:bookworm-slim"
	}

	script, err := filepath.Abs(filepath.Join("testdata", translationRepoDir, "container.sh"))
	require.NoError(t, err)

	for _, mode := range []string{"trusted", "signed"} {
		repo := t.TempDir()
		buildTranslationRepo(t, repo)

		if mode == "signed" {
			signRepo(t, repo)
		}

		out := runAptContainer(t, podman, image, repo, script, mode)
		require.NoError(t, os.WriteFile(filepath.Join("testdata", translationRepoDir, "expected-"+mode+".txt"), []byte(out), 0o644))
	}
}
