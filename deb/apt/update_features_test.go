package apt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/download"
)

// publishedBytes is the uncompressed Packages index of a component as the
// fixture publishes it.
func (f *fixture) publishedBytes(comp string) []byte {
	var ix deb.Index

	ix.AddText(f.comps[comp])

	return ix.Bytes()
}

// exportTo writes the files the repository serves into dir.
func (f *fixture) exportTo(dir string) {
	f.tb.Helper()

	f.repo.mu.Lock()
	defer f.repo.mu.Unlock()

	for p, data := range f.repo.files {
		dest := filepath.Join(dir, filepath.FromSlash(p))
		require.NoError(f.tb, os.MkdirAll(filepath.Dir(dest), 0o755))
		require.NoError(f.tb, os.WriteFile(dest, data, 0o644))
	}
}

func readFileString(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	return string(data)
}

func TestUpdateKeepsReleaseAndLoadReadsIt(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.addPackage("main", "alpha", "1.0")
	f.mutate = func(r *deb.Release) {
		r.Origin, r.Label, r.Version = "Acme", "Acme Stable", "12"
		r.NotAutomatic, r.ButAutomaticUpgrades = true, true
	}
	f.publish()

	n, err := Update(context.Background(), []Source{f.source()}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	rel := filepath.Join(f.lists, ListFileName(f.repo.baseURL(), f.suite, "InRelease"))
	assert.FileExists(t, rel)

	c, err := f.load()
	require.NoError(t, err)

	alpha, ok := c.Lookup("alpha")
	require.True(t, ok)
	require.Len(t, alpha.Releases, 1)
	assert.Equal(t, ReleaseInfo{
		Origin: "Acme", Label: "Acme Stable", Suite: "stable", Codename: "stable", Version: "12",
		Component: "main", Architecture: "amd64", Site: "127.0.0.1",
		NotAutomatic: true, ButAutomaticUpgrades: true,
	}, *alpha.Releases[0])
	assert.Equal(t, "alpha", alpha.SourceName)
}

func TestUpdateReplacesReleaseForm(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.addPackage("main", "alpha", "1.0")
	f.publish()

	_, err := Update(context.Background(), []Source{f.source()}, f.opts())
	require.NoError(t, err)

	f.sign = signDetached
	f.publish()

	_, err = Update(context.Background(), []Source{f.source()}, f.opts())
	require.NoError(t, err)

	name := ListFileName(f.repo.baseURL(), f.suite, "")
	assert.NoFileExists(t, filepath.Join(f.lists, name+"InRelease"))
	assert.FileExists(t, filepath.Join(f.lists, name+"Release"))
	assert.FileExists(t, filepath.Join(f.lists, name+"Release.gpg"))
}

func TestUpdateByHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup adjusts the source, the release and the published files.
		offer    bool // the Release says Acquire-By-Hash: yes
		byHash   ByHashMode
		present  bool // by-hash files are served
		plain    bool // plain files are served
		wantErr  bool
		wantHash bool // the by-hash path was requested
		wantPlan bool // the plain path was requested
	}{
		{name: "offered and served", offer: true, present: true, plain: true, wantHash: true},
		{name: "offered, plain only is a fallback", offer: true, present: false, plain: true, wantHash: true, wantPlan: true},
		{name: "not offered", offer: false, present: true, plain: true, wantPlan: true},
		{name: "disabled by the source", offer: true, byHash: ByHashNo, present: true, plain: true, wantPlan: true},
		{name: "forced without offer", offer: false, byHash: ByHashForce, present: true, plain: false, wantHash: true},
		{name: "forced, missing is final", offer: true, byHash: ByHashForce, present: false, plain: true, wantErr: true, wantHash: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			f.formats = []deb.Compression{deb.CompressionGzip}
			f.addPackage("main", "alpha", "1.0")
			f.mutate = func(r *deb.Release) { r.AcquireByHash = tt.offer }
			f.publish()

			rel := f.indexRel("main", ".gz")
			fi := mustRelease(t, f).Files[rel]
			byHash := f.distPath(deb.ByHashPath(rel, deb.ByHashSHA512, fi.SHA512))

			if tt.present {
				data := mustGet(t, f, f.distPath(rel))
				f.repo.put(byHash, data)
			}

			if !tt.plain {
				f.repo.remove(f.distPath(rel))
			}

			src := f.source()
			src.ByHash = tt.byHash

			n, err := Update(context.Background(), []Source{src}, f.opts())
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, 1, n)
			}

			assert.Equal(t, tt.wantHash, f.repo.count(byHash) > 0, "by-hash request")
			assert.Equal(t, tt.wantPlan, f.repo.count(f.distPath(rel)) > 0, "plain request")
		})
	}
}

func mustGet(t *testing.T, f *fixture, path string) []byte {
	t.Helper()

	f.repo.mu.Lock()
	defer f.repo.mu.Unlock()

	data, ok := f.repo.files[path]
	require.True(t, ok, path)

	return data
}

func mustRelease(t *testing.T, f *fixture) *deb.Release {
	t.Helper()

	body := deb.StripClearsign(mustGet(t, f, f.distPath("InRelease")))
	rel, err := deb.ParseRelease(body)
	require.NoError(t, err)

	return rel
}

func TestUpdateByHashDisabledByOptions(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.formats = []deb.Compression{deb.CompressionGzip}
	f.addPackage("main", "alpha", "1.0")
	f.mutate = func(r *deb.Release) { r.AcquireByHash = true }
	f.publish()

	rel := f.indexRel("main", ".gz")
	byHash := f.distPath(deb.ByHashPath(rel, deb.ByHashSHA512, mustRelease(t, f).Files[rel].SHA512))
	f.repo.put(byHash, mustGet(t, f, f.distPath(rel)))

	opts := f.opts()
	opts.DisableByHash = true

	_, err := Update(context.Background(), []Source{f.source()}, opts)
	require.NoError(t, err)
	assert.Zero(t, f.repo.count(byHash))
}

func TestUpdateTranslationsContentsAndSources(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.formats = []deb.Compression{deb.CompressionGzip}
	f.addPackage("main", "alpha", "1.0")

	translation := []byte("Package: alpha\nDescription-md5: 00\nDescription-de: hallo\n\n")
	contents := []byte("usr/bin/alpha  main/alpha\n")
	sources := []byte("Package: alpha\nVersion: 1.0\n\n")

	f.mutate = func(r *deb.Release) {
		r.AddFile(deb.HashBytes("main/i18n/Translation-de", translation))
		r.AddFile(deb.HashBytes("Contents-amd64", contents))
		r.AddFile(deb.HashBytes("main/Contents-amd64", contents))
		r.AddFile(deb.HashBytes("main/source/Sources", sources))
	}
	f.publish()
	f.repo.put(f.distPath("main/i18n/Translation-de"), translation)
	f.repo.put(f.distPath("Contents-amd64"), contents)
	f.repo.put(f.distPath("main/Contents-amd64"), contents)
	f.repo.put(f.distPath("main/source/Sources"), sources)

	list := func(rel string) string { return filepath.Join(f.lists, ListFileName(f.repo.baseURL(), f.suite, rel)) }

	t.Run("languages", func(t *testing.T) {
		src := f.source()
		src.Languages = []string{"de_DE", "none"}

		n, err := Update(context.Background(), []Source{src}, f.opts())
		require.NoError(t, err)
		assert.Equal(t, 2, n, "packages and the de translation, which de_DE falls back to")
		assert.Equal(t, string(translation), readFileString(t, list("main/i18n/Translation-de")))
	})

	t.Run("default languages", func(t *testing.T) {
		opts := f.opts()
		opts.ListsDir = t.TempDir()
		opts.DefaultLanguages = []string{"de"}

		n, err := Update(context.Background(), []Source{f.source()}, opts)
		require.NoError(t, err)
		assert.Equal(t, 2, n)
	})

	t.Run("a language the release lacks is skipped", func(t *testing.T) {
		src := f.source()
		src.Languages = []string{"fr"}

		n, err := Update(context.Background(), []Source{src}, UpdateOptions{
			ListsDir: t.TempDir(), DefaultArch: f.arch, Client: testClient(1),
		})
		require.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("contents", func(t *testing.T) {
		src := f.source()
		src.Targets = []string{"Packages", "Contents"}

		opts := f.opts()
		opts.ListsDir = t.TempDir()

		n, err := Update(context.Background(), []Source{src}, opts)
		require.NoError(t, err)
		assert.Equal(t, 3, n, "packages, the distribution-wide and the component Contents")
		assert.FileExists(t, filepath.Join(opts.ListsDir, ListFileName(f.repo.baseURL(), f.suite, "Contents-amd64")))
	})

	t.Run("deb-src", func(t *testing.T) {
		src := f.source()
		src.Type = TypeDebSrc

		opts := f.opts()
		opts.ListsDir = t.TempDir()

		n, err := Update(context.Background(), []Source{src}, opts)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		assert.Equal(t, string(sources), readFileString(t, filepath.Join(opts.ListsDir,
			ListFileName(f.repo.baseURL(), f.suite, "main/source/Sources"))))

		c, err := Load(LoadOptions{ListsDir: opts.ListsDir, HostArch: f.arch})
		require.NoError(t, err)
		assert.Zero(t, c.PackageCount(), "Sources lists no binary package")
	})

	t.Run("architectures add and remove", func(t *testing.T) {
		src := f.source()
		src.ArchitecturesAdd = []string{"arm64"}
		src.ArchitecturesRemove = []string{"amd64"}

		n, err := Update(context.Background(), []Source{src}, UpdateOptions{
			ListsDir: t.TempDir(), DefaultArch: f.arch, Client: testClient(1),
		})
		require.NoError(t, err)
		assert.Zero(t, n, "only arm64 is asked for, and the Release lists none")
	})
}

func TestUpdateFlatRepository(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.formats = []deb.Compression{deb.CompressionGzip}

	index := []byte(para("Package: flat", "Version: 1", "Architecture: amd64", "Filename: flat.deb", "Size: 1",
		"SHA256: "+sha256Hex([]byte("x"))))

	rel := &deb.Release{Suite: "flat"}

	var ix deb.Index

	ix.AddText(string(index))

	gz, err := ix.Compressed(deb.CompressionGzip)
	require.NoError(t, err)

	rel.AddFile(deb.HashBytes("Packages.gz", gz))

	signed, err := deb.SignRelease(f.signer, rel.Marshal())
	require.NoError(t, err)

	f.repo.put("/flat/InRelease", signed.InRelease)
	f.repo.put("/flat/Packages.gz", gz)

	src := Source{URL: f.repo.baseURL(), Suite: "flat/", SignedBy: f.keyPath}

	n, err := Update(context.Background(), []Source{src}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	c, err := Load(LoadOptions{ListsDir: f.lists, HostArch: f.arch})
	require.NoError(t, err)
	assert.Equal(t, 1, c.PackageCount())
}

func TestUpdateFileAndCopySchemes(t *testing.T) {
	t.Parallel()

	for _, scheme := range []string{"file", "copy"} {
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			f.addPackage("main", "alpha", "1.0")
			f.publish()

			dir := t.TempDir()
			f.exportTo(dir)

			src := f.source()
			src.URL = scheme + "://" + dir + "/"

			n, err := Update(context.Background(), []Source{src}, f.opts())
			require.NoError(t, err)
			assert.Equal(t, 1, n)

			c, err := Load(LoadOptions{ListsDir: f.lists, HostArch: f.arch, Sources: []Source{src}})
			require.NoError(t, err)

			alpha, ok := c.Lookup("alpha")
			require.True(t, ok)
			assert.Equal(t, src.URL, alpha.BaseURL)
			assert.Empty(t, alpha.Releases[0].Site, "a local source has no site")
		})
	}
}

func TestUpdateFileSchemeIntegrity(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.addPackage("main", "alpha", "1.0")
	f.publish()

	dir := t.TempDir()
	f.exportTo(dir)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "dists/stable", filepath.FromSlash(f.indexRel("main", ".xz"))),
		[]byte("tampered"), 0o644))

	src := f.source()
	src.URL = "file://" + dir + "/"

	_, err := Update(context.Background(), []Source{src}, f.opts())
	require.ErrorIs(t, err, ErrIntegrity)
}

func TestUpdateMirrorList(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.addPackage("main", "alpha", "1.0")
	f.publish()

	f.repo.put("/mirrors.txt", []byte("# mirrors\nhttp://127.0.0.1:1/dead/\tpriority:1\n"+f.repo.baseURL()+"\n"))

	src := f.source()
	src.URL = "mirror+" + f.repo.baseURL() + "mirrors.txt"

	n, err := Update(context.Background(), []Source{src}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "the dead mirror is skipped")

	c, err := Load(LoadOptions{ListsDir: f.lists, HostArch: f.arch, Sources: []Source{src}})
	require.NoError(t, err)

	alpha, ok := c.Lookup("alpha")
	require.True(t, ok)
	assert.Equal(t, src.URL, alpha.BaseURL, "the package keeps the mirror list as its base")
	assert.Equal(t, "127.0.0.1", alpha.Releases[0].Site)

	t.Run("download", func(t *testing.T) {
		dest := t.TempDir()
		require.NoError(t, c.Download(context.Background(), dest, []string{"alpha"}, DownloadOptions{Client: testClient(1)}))
		assert.Equal(t, string(f.debs["alpha"]), readFileString(t, filepath.Join(dest, "alpha_1.0_amd64.deb")))
	})

	t.Run("empty list", func(t *testing.T) {
		f.repo.put("/empty.txt", []byte("# nothing\nftp://x/\n"))

		bad := src
		bad.URL = "mirror+" + f.repo.baseURL() + "empty.txt"

		_, err := Update(context.Background(), []Source{bad}, f.opts())
		require.ErrorIs(t, err, ErrEmptyMirrorList)
	})

	t.Run("missing list", func(t *testing.T) {
		bad := src
		bad.URL = "mirror+" + f.repo.baseURL() + "absent.txt"

		_, err := Update(context.Background(), []Source{bad}, f.opts())
		require.Error(t, err)
	})
}

func TestUpdateMirrorFileList(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.addPackage("main", "alpha", "1.0")
	f.publish()

	dir := t.TempDir()
	f.exportTo(dir)

	list := filepath.Join(t.TempDir(), "mirrors.txt")
	require.NoError(t, os.WriteFile(list, []byte("file://"+dir+"/\n"), 0o644))

	src := f.source()
	src.URL = "mirror+file://" + list

	n, err := Update(context.Background(), []Source{src}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestUpdateUnsupportedSchemes(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"cdrom://Debian 12/", "ftp://example.org/debian/", "rsh://example.org/x/"} {
		_, err := Update(context.Background(), []Source{{URL: raw, Suite: "s", Components: []string{"main"}}},
			UpdateOptions{ListsDir: t.TempDir(), Client: testClient(1)})
		require.ErrorIs(t, err, ErrUnsupportedScheme, raw)
	}

	_, err := Update(context.Background(), []Source{{URL: "cdrom://Debian 12/", Suite: "s"}},
		UpdateOptions{ListsDir: t.TempDir()})
	assert.ErrorContains(t, err, "no medium")
}

func TestUpdateTrustOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sign    string
		edit    func(*Source, *UpdateOptions)
		wantErr bool
	}{
		{name: "unsigned is refused", sign: signNone, wantErr: true},
		{name: "trusted accepts unsigned", sign: signNone, edit: func(s *Source, _ *UpdateOptions) { s.Trusted = SwitchYes }},
		{name: "allow-insecure accepts unsigned", sign: signNone, edit: func(s *Source, _ *UpdateOptions) { s.AllowInsecure = SwitchYes }},
		{
			name: "trusted=no refuses even with AllowUnverified", sign: signNone,
			edit:    func(s *Source, o *UpdateOptions) { s.Trusted = SwitchNo; o.AllowUnverified = true },
			wantErr: true,
		},
		{name: "trusted skips verification of a detached signature", sign: signDetached, edit: func(s *Source, _ *UpdateOptions) {
			s.Trusted = SwitchYes
			s.SignedBy = filepath.Join(os.TempDir(), "absent.gpg")
		}},
		{name: "trusted skips an InRelease signature check", sign: signInRelease, edit: func(s *Source, _ *UpdateOptions) {
			s.Trusted = SwitchYes
			s.SignedBy = filepath.Join(os.TempDir(), "absent.gpg")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			f.sign = tt.sign
			f.addPackage("main", "alpha", "1.0")
			f.publish()

			src, opts := f.source(), f.opts()
			if tt.sign == signNone {
				src.SignedBy = ""
			}

			if tt.edit != nil {
				tt.edit(&src, &opts)
			}

			n, err := Update(context.Background(), []Source{src}, opts)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, 1, n)
		})
	}
}

func TestUpdateDowngradeToInsecure(t *testing.T) {
	t.Parallel()

	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow=%t", allow), func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			f.addPackage("main", "alpha", "1.0")
			f.publish()

			_, err := Update(context.Background(), []Source{f.source()}, f.opts())
			require.NoError(t, err)

			f.sign = signNone
			f.publish()

			src := f.source()
			src.SignedBy = ""
			src.AllowInsecure = SwitchYes

			if allow {
				src.AllowDowngradeToInsecure = SwitchYes
			}

			_, err = Update(context.Background(), []Source{src}, f.opts())
			if allow {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrDowngradeToInsecure)
		})
	}
}

func TestUpdateReleaseDates(t *testing.T) {
	t.Parallel()

	date := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	tests := []struct {
		name    string
		valid   time.Time
		now     time.Time
		edit    func(*Source)
		wantErr error
	}{
		{name: "no Valid-Until never expires", now: date.Add(1000 * time.Hour)},
		{name: "expired", valid: date.Add(time.Hour), now: date.Add(2 * time.Hour), wantErr: deb.ErrReleaseExpired},
		{
			name: "check-valid-until=no", valid: date.Add(time.Hour), now: date.Add(2 * time.Hour),
			edit: func(s *Source) { s.CheckValidUntil = SwitchNo },
		},
		{
			name: "Valid-Until-Max bounds a Release without a limit", now: date.Add(3 * time.Hour),
			edit: func(s *Source) { s.ValidUntilMax = 2 * time.Hour }, wantErr: deb.ErrReleaseExpired,
		},
		{
			name: "Valid-Until-Max shortens a long Valid-Until", valid: date.Add(100 * time.Hour), now: date.Add(3 * time.Hour),
			edit: func(s *Source) { s.ValidUntilMax = 2 * time.Hour }, wantErr: deb.ErrReleaseExpired,
		},
		{
			name: "Valid-Until-Min extends a short Valid-Until", valid: date.Add(time.Hour), now: date.Add(2 * time.Hour),
			edit: func(s *Source) { s.ValidUntilMin = 5 * time.Hour },
		},
		{name: "a Date in the future", now: date.Add(-time.Hour), wantErr: ErrReleaseFromFuture},
		{name: "a Date a little in the future", now: date.Add(-5 * time.Second)},
		{
			name: "Date-Max-Future", now: date.Add(-time.Hour),
			edit: func(s *Source) { s.DateMaxFuture = 2 * time.Hour },
		},
		{
			name: "check-date=no", now: date.Add(-time.Hour),
			edit: func(s *Source) { s.CheckDate = SwitchNo },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			f.addPackage("main", "alpha", "1.0")
			f.mutate = func(r *deb.Release) { r.ValidUntil = tt.valid }
			f.publish()

			src, opts := f.source(), f.opts()
			opts.Now = func() time.Time { return tt.now }

			if tt.edit != nil {
				tt.edit(&src)
			}

			_, err := Update(context.Background(), []Source{src}, opts)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

// pdiffFixture is a repository with a large Packages index (so that patches
// are worth fetching) and the means to publish the next generation of it.
type pdiffFixture struct {
	*fixture

	fs      *deb.PDiffMemFS
	builder *deb.PDiffIndexBuilder
	count   int
}

func newPDiffFixture(t *testing.T) *pdiffFixture {
	t.Helper()

	f := newFixture(t)
	f.formats = []deb.Compression{deb.CompressionXZ, deb.CompressionNone}

	for i := range 60 {
		f.addPackage("main", fmt.Sprintf("pkg%03d", i), "1.0", "Description: a package with a long enough description to matter")
	}

	fs := deb.NewPDiffMemFS()
	builder, err := deb.NewPDiffIndexBuilder(fs, deb.PDiffBuilderOptions{})
	require.NoError(t, err)

	return &pdiffFixture{fixture: f, fs: fs, builder: builder, count: 60}
}

// advance adds one package and publishes the new generation together with its
// Packages.diff; it returns the number of the patch files written.
func (p *pdiffFixture) advance(t *testing.T) {
	t.Helper()

	old := p.publishedBytes("main")

	p.count++
	p.addPackage("main", fmt.Sprintf("pkg%03d", p.count), "1.0", "Description: a package with a long enough description to matter")

	upd, err := p.builder.UpdateFrom(old, p.publishedBytes("main"), time.Date(2026, 1, 2, 3, p.count, 0, 0, time.UTC))
	require.NoError(t, err)

	dir := "main/binary-" + p.arch + "/"

	for _, name := range upd.Written {
		data, err := p.fs.ReadFile(name)
		require.NoError(t, err)

		p.repo.put(p.distPath(dir+name), data)
	}

	index := upd.IndexData
	p.mutate = func(r *deb.Release) { r.AddFile(deb.HashBytes(dir+"Packages.diff/Index", index)) }
	p.publish()
}

func TestUpdateWithPDiffs(t *testing.T) {
	t.Parallel()

	p := newPDiffFixture(t)
	p.publish()

	ctx := context.Background()
	xz := p.distPath(p.indexRel("main", ".xz"))
	plain := p.distPath(p.indexRel("main", ""))

	_, err := Update(ctx, []Source{p.source()}, p.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, p.repo.count(xz), "the first update has nothing to patch")

	p.advance(t)

	n, err := Update(ctx, []Source{p.source()}, p.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 1, p.repo.count(xz), "the second update is patched")
	assert.Zero(t, p.repo.count(plain))

	patches := 0
	for path, hits := range p.repo.hits {
		if strings.Contains(path, "Packages.diff/") && strings.HasSuffix(path, ".gz") {
			patches += hits
		}
	}

	assert.Equal(t, 1, patches)

	assert.Equal(t, string(p.publishedBytes("main")), readFileString(t, p.listPath("main", "")))
	assert.NoFileExists(t, p.listPath("main", ".xz"))

	c, err := p.load()
	require.NoError(t, err)

	_, ok := c.Lookup(fmt.Sprintf("pkg%03d", p.count))
	assert.True(t, ok, "the patched index is read")

	// Nothing changed since: the patched file is the current one.
	hits := p.repo.total()

	n, err = Update(ctx, []Source{p.source()}, p.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, hits+1, p.repo.total(), "only the release is fetched again")

	// Two generations behind: a chain of patches.
	p.advance(t)
	p.advance(t)

	n, err = Update(ctx, []Source{p.source()}, p.opts())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 1, p.repo.count(xz))
	assert.Equal(t, string(p.publishedBytes("main")), readFileString(t, p.listPath("main", "")))
}

func TestUpdateWithPDiffsDisabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		edit func(*Source, *UpdateOptions)
	}{
		{"option", func(_ *Source, o *UpdateOptions) { o.DisablePDiffs = true }},
		{"source", func(s *Source, _ *UpdateOptions) { s.PDiffs = SwitchNo }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := newPDiffFixture(t)
			p.publish()

			_, err := Update(context.Background(), []Source{p.source()}, p.opts())
			require.NoError(t, err)

			p.advance(t)

			src, opts := p.source(), p.opts()
			tt.edit(&src, &opts)

			_, err = Update(context.Background(), []Source{src}, opts)
			require.NoError(t, err)
			assert.Equal(t, 2, p.repo.count(p.distPath(p.indexRel("main", ".xz"))), "fetched whole")
		})
	}
}

func TestUpdateWithPDiffsFallsBack(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// sabotage runs after the second generation is published.
		sabotage func(p *pdiffFixture, t *testing.T)
		edit     func(p *pdiffFixture) // before the first update
	}{
		{name: "patch is missing", sabotage: func(p *pdiffFixture, t *testing.T) {
			for path := range p.repo.files {
				if strings.HasSuffix(path, ".gz") && strings.Contains(path, "Packages.diff/2") {
					p.repo.remove(path)
				}
			}
		}},
		{name: "patch is corrupt", sabotage: func(p *pdiffFixture, t *testing.T) {
			for path := range p.repo.files {
				if strings.HasSuffix(path, ".gz") && strings.Contains(path, "Packages.diff/2") {
					p.repo.put(path, []byte("garbage"))
				}
			}
		}},
		{name: "index is corrupt", sabotage: func(p *pdiffFixture, t *testing.T) {
			p.repo.put(p.distPath("main/binary-amd64/Packages.diff/Index"), []byte("garbage"))
		}},
		{name: "index is missing", sabotage: func(p *pdiffFixture, t *testing.T) {
			p.repo.remove(p.distPath("main/binary-amd64/Packages.diff/Index"))
		}},
		{name: "local copy is unknown", sabotage: func(p *pdiffFixture, t *testing.T) {
			require.NoError(t, os.WriteFile(p.listPath("main", ".xz"), []byte("not an index"), 0o644))
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := newPDiffFixture(t)
			p.publish()

			_, err := Update(context.Background(), []Source{p.source()}, p.opts())
			require.NoError(t, err)

			p.advance(t)
			tt.sabotage(p, t)

			n, err := Update(context.Background(), []Source{p.source()}, p.opts())
			require.NoError(t, err)
			assert.Equal(t, 1, n)

			c, err := p.load()
			require.NoError(t, err)

			_, ok := c.Lookup(fmt.Sprintf("pkg%03d", p.count))
			assert.True(t, ok, "the whole index was fetched instead")
		})
	}
}

func TestUpdateWithPDiffsNotWorthIt(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.formats = []deb.Compression{deb.CompressionXZ, deb.CompressionNone}
	f.addPackage("main", "alpha", "1.0")
	f.publish()

	_, err := Update(context.Background(), []Source{f.source()}, f.opts())
	require.NoError(t, err)

	old := f.publishedBytes("main")
	f.comps["main"] = ""
	f.addPackage("main", "beta", "1.0")

	fs := deb.NewPDiffMemFS()
	builder, err := deb.NewPDiffIndexBuilder(fs, deb.PDiffBuilderOptions{})
	require.NoError(t, err)

	upd, err := builder.UpdateFrom(old, f.publishedBytes("main"), time.Now())
	require.NoError(t, err)

	for _, name := range upd.Written {
		data, err := fs.ReadFile(name)
		require.NoError(t, err)

		f.repo.put(f.distPath("main/binary-amd64/"+name), data)
	}

	f.mutate = func(r *deb.Release) {
		r.AddFile(deb.HashBytes("main/binary-amd64/Packages.diff/Index", upd.IndexData))
	}
	f.publish()

	_, err = Update(context.Background(), []Source{f.source()}, f.opts())
	require.NoError(t, err)
	assert.Equal(t, 2, f.repo.count(f.distPath(f.indexRel("main", ".xz"))), "a tiny index is fetched whole")
}

func TestTransportHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		path string
		ok   bool
	}{
		{"file:///var/lib/x", "/var/lib/x", true},
		{"file:/var/lib/x", "/var/lib/x", true},
		{"file://localhost/var/x", "/var/x", true},
		{"copy:///a%20b/c", "/a b/c", true},
		{"file://host/var/x", "", false},
		{"file:relative", "", false},
		{"file:///%zz", "", false},
		{"http://x/y", "", false},
	}

	for _, tt := range tests {
		path, ok := localPath(tt.raw)
		assert.Equal(t, tt.ok, ok, tt.raw)
		assert.Equal(t, tt.path, path, tt.raw)
	}

	list, ok := mirrorListURL("mirror+https://h/m.txt")
	assert.True(t, ok)
	assert.Equal(t, "https://h/m.txt", list)

	list, ok = mirrorListURL("mirror://h/m.txt")
	assert.True(t, ok)
	assert.Equal(t, "http://h/m.txt", list)

	assert.False(t, isMirrorURL("http://h/"))
	assert.True(t, isMirrorURL("mirror+file:///m"))

	assert.Equal(t, []string{"http://a/", "https://b/x/", "file:///m/"},
		parseMirrorList([]byte("# c\n\nhttp://a/\nhttp://a/\nftp://z/\nhttps://b/x\tpriority:2\nfile:///m/\n")))

	assert.True(t, supportedScheme(&Source{URL: "mirror+http://h/"}))
	assert.False(t, supportedScheme(&Source{URL: "cdrom://x/"}))
}

func TestCopyLocal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	require.NoError(t, os.WriteFile(src, []byte("hello"), 0o644))

	require.NoError(t, copyLocal(src, filepath.Join(dir, "plain"), nil, 100))
	assert.Equal(t, "hello", readFileString(t, filepath.Join(dir, "plain")))

	require.ErrorIs(t, copyLocal(src, filepath.Join(dir, "big"), nil, 2), download.ErrTooLarge)
	require.Error(t, copyLocal(filepath.Join(dir, "absent"), filepath.Join(dir, "x"), nil, 10))

	_, err := readLocal(src, 2)
	require.ErrorIs(t, err, ErrTooLarge)
}

func TestDownloadFromFileBase(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := []byte("a package")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "pool"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pool/a_1_amd64.deb"), content, 0o644))

	c := NewCache("amd64")
	c.AddEntry(&PackageInfo{
		Name: "a", Version: "1", Architecture: "amd64", HasCandidate: true, Filename: "pool/a_1_amd64.deb",
		Size: int64(len(content)), SHA256: sha256Hex(content), BaseURL: "file://" + dir + "/",
	})

	dest := t.TempDir()
	require.NoError(t, c.Download(context.Background(), dest, []string{"a"}, DownloadOptions{}))
	assert.Equal(t, string(content), readFileString(t, filepath.Join(dest, "a_1_amd64.deb")))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "pool/a_1_amd64.deb"), []byte("tampered!"), 0o644))

	err := c.Download(context.Background(), t.TempDir(), []string{"a"}, DownloadOptions{})
	require.ErrorIs(t, err, ErrIntegrity)

	c.AddEntry(&PackageInfo{
		Name: "b", Version: "1", Architecture: "amd64", HasCandidate: true, Filename: "pool/b.deb",
		Size: 1, SHA256: sha256Hex([]byte("x")), BaseURL: "cdrom://disc/",
	})

	err = c.Download(context.Background(), t.TempDir(), []string{"b"}, DownloadOptions{})
	require.ErrorIs(t, err, ErrUnsupportedScheme)
}

func TestLoadParsesSourceAndPhased(t *testing.T) {
	t.Parallel()

	c := cacheFromText(t, para("Package: bin", "Version: 2", "Architecture: amd64", "Source: srcpkg (1.5)",
		"Phased-Update-Percentage: 37")+
		para("Package: bin2", "Version: 2", "Architecture: amd64", "Source: srconly",
			"Phased-Update-Percentage: lots")+
		para("Package: bin3", "Version: 2", "Architecture: amd64", "Source: srcempty ()"))

	bin, _ := c.Lookup("bin")
	assert.Equal(t, "srcpkg", bin.SourceName)
	assert.Equal(t, "1.5", bin.SourceVersion)
	require.NotNil(t, bin.PhasedUpdatePercentage)
	assert.Equal(t, 37, *bin.PhasedUpdatePercentage)

	bin2, _ := c.Lookup("bin2")
	assert.Equal(t, "srconly", bin2.SourceName)
	assert.Equal(t, "2", bin2.SourceVersion)
	assert.Nil(t, bin2.PhasedUpdatePercentage)

	bin3, _ := c.Lookup("bin3")
	assert.Equal(t, "srcempty", bin3.SourceName)
	assert.Equal(t, "2", bin3.SourceVersion)
}

func TestCacheCandidateFollowsPins(t *testing.T) {
	t.Parallel()

	c := NewCache("amd64")
	stable := &ReleaseInfo{Suite: "stable", Codename: "bookworm", Origin: "Debian"}
	testing_ := &ReleaseInfo{Suite: "testing", Codename: "trixie", Origin: "Debian"}

	c.AddEntry(&PackageInfo{Name: "x", Version: "1", Architecture: "amd64", HasCandidate: true, Filename: "x1.deb", Releases: []*ReleaseInfo{stable}})
	c.AddEntry(&PackageInfo{Name: "x", Version: "2", Architecture: "amd64", HasCandidate: true, Filename: "x2.deb", Releases: []*ReleaseInfo{testing_}})

	got, ok := c.Candidate("x", nil)
	require.True(t, ok)
	assert.Equal(t, "2", got.Version, "equal priorities: the highest version")

	prefs, err := ParsePreferences("Package: *\nPin: release n=bookworm\nPin-Priority: 900\n")
	require.NoError(t, err)

	got, ok = c.Candidate("x", NewPolicy(prefs, PolicyOptions{}))
	require.True(t, ok)
	assert.Equal(t, "1", got.Version, "the pinned release wins")

	prefs, err = ParsePreferences("Package: x\nPin: release n=trixie\nPin-Priority: -1\n")
	require.NoError(t, err)

	got, ok = c.Candidate("x", NewPolicy(prefs, PolicyOptions{}))
	require.True(t, ok)
	assert.Equal(t, "1", got.Version, "a version pinned below zero is never chosen")

	_, ok = c.Candidate("absent", nil)
	assert.False(t, ok)
}

func TestTransportFailureUnwraps(t *testing.T) {
	t.Parallel()

	inner := fmt.Errorf("boom")
	err := error(&transportFailure{err: inner})

	assert.Equal(t, "boom", err.Error())
	require.ErrorIs(t, err, inner)
}
