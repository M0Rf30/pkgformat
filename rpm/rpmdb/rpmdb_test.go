package rpmdb_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/dnf"
	"github.com/M0Rf30/pkgformat/rpm/rpmdb"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// *DB answers the resolver of the dnf client.
var _ dnf.Installed = (*rpmdb.DB)(nil)

// fixtures are real databases written by the rpm of the distribution named in
// the .info file next to them. The .expected file is what that rpm printed for
// the same database; see testdata/README.md.
var fixtures = []struct {
	file   string
	format rpmdb.Format
	// the name rpm gives the file in a root.
	canonical string
}{
	{"rpmdb.sqlite", rpmdb.FormatSQLite, "var/lib/rpm/rpmdb.sqlite"},
	{"Packages.bdb", rpmdb.FormatBDB, "var/lib/rpm/Packages"},
	{"Packages.ndb", rpmdb.FormatNDB, "usr/lib/sysimage/rpm/Packages.db"},
}

// copyFixture copies a fixture into a temporary directory, so that SQLite's
// side files never appear in testdata.
func copyFixture(t *testing.T, name string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	return path
}

type expectedPackage struct {
	name, epoch, version, release, arch, installTime string

	provides, requires [][]string // name, flags, version
	files              [][]string // path mode size digest linkto user group mtime flags
}

// loadExpected parses the records testdata/generate.sh asks rpm to print.
func loadExpected(t *testing.T, name string) (order []string, byName map[string]*expectedPackage) {
	t.Helper()

	f, err := os.Open(filepath.Join("testdata", name+".expected"))
	require.NoError(t, err)

	defer f.Close()

	byName = map[string]*expectedPackage{}
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)

	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		require.GreaterOrEqual(t, len(fields), 2, sc.Text())

		if fields[0] == "P" {
			require.Len(t, fields, 7)

			p := &expectedPackage{
				name: fields[1], epoch: fields[2], version: fields[3], release: fields[4],
				arch: fields[5], installTime: fields[6],
			}
			if p.arch == "(none)" {
				p.arch = ""
			}

			byName[p.name] = p
			order = append(order, p.name)

			continue
		}

		p := byName[fields[1]]
		require.NotNil(t, p, sc.Text())

		switch fields[0] {
		case "D":
			require.Len(t, fields, 5)
			p.provides = append(p.provides, fields[2:])
		case "Q":
			require.Len(t, fields, 5)
			p.requires = append(p.requires, fields[2:])
		case "F":
			require.Len(t, fields, 11)
			p.files = append(p.files, fields[2:])
		default:
			t.Fatalf("unknown record %q", fields[0])
		}
	}

	require.NoError(t, sc.Err())

	return order, byName
}

func depStrings(deps []rpm.Dependency) [][]string {
	var out [][]string

	for _, d := range deps {
		v := d.Version
		if d.Epoch > 0 {
			v = fmt.Sprintf("%d:%s", d.Epoch, v)
		}

		out = append(out, []string{d.Name, strconv.FormatUint(uint64(d.Flags), 10), v})
	}

	return out
}

func fileStrings(files []rpm.FileEntry) [][]string {
	var out [][]string

	for _, f := range files {
		out = append(out, []string{
			f.Path, strconv.FormatUint(uint64(f.Mode), 10), strconv.FormatInt(f.Size, 10), f.Digest, f.LinkTo,
			f.User, f.Group, strconv.FormatInt(f.MTime, 10), strconv.FormatUint(uint64(f.Flags), 10),
		})
	}

	return out
}

func TestPackagesMatchRpm(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx.file, func(t *testing.T) {
			order, want := loadExpected(t, fx.file)

			db, err := rpmdb.Open(copyFixture(t, fx.file), rpmdb.Options{})
			require.NoError(t, err)

			defer db.Close()

			assert.Equal(t, fx.format, db.Format())

			pkgs, err := db.List(t.Context())
			require.NoError(t, err)
			require.Len(t, pkgs, len(want))

			var names []string

			for _, p := range pkgs {
				names = append(names, p.Name)
				exp := want[p.Name]
				require.NotNil(t, exp, p.Name)

				assert.Equal(t, exp.epoch, strconv.FormatUint(uint64(p.Epoch), 10), p.Name)
				assert.Equal(t, exp.version, p.Version, p.Name)
				assert.Equal(t, exp.release, p.Release, p.Name)
				assert.Equal(t, exp.arch, p.Arch, p.Name)
				assert.Equal(t, exp.installTime, strconv.FormatInt(p.InstallTime, 10), p.Name)
				assert.Equal(t, orNil(exp.provides), orNil(depStrings(p.Provides)), p.Name)
				assert.Equal(t, orNil(exp.requires), orNil(depStrings(p.Requires)), p.Name)
				assert.Equal(t, orNil(exp.files), orNil(fileStrings(p.Files)), p.Name)
				assert.False(t, p.FilesTruncated)
			}

			slices.Sort(order)
			slices.Sort(names)
			assert.Equal(t, order, names)

			// The sets the resolver asks for.
			gotNames, err := db.InstalledNames(t.Context())
			require.NoError(t, err)
			assert.Equal(t, order, gotNames)

			var provides []string

			for _, p := range want {
				provides = append(provides, p.name)

				for _, d := range p.provides {
					provides = append(provides, d[0])
				}
			}

			slices.Sort(provides)

			gotProvides, err := db.InstalledProvides(t.Context())
			require.NoError(t, err)
			assert.Equal(t, slices.Compact(provides), gotProvides)
		})
	}
}

// orNil lets an empty list equal a missing one.
func orNil(s [][]string) [][]string {
	if len(s) == 0 {
		return nil
	}

	return s
}

func TestFixturesAreNotTrivial(t *testing.T) {
	// The BerkeleyDB fixture must hold values on overflow pages, the one that
	// carries gpg-pubkey a package without an architecture.
	_, want := loadExpected(t, "Packages.bdb")
	require.Contains(t, want, "gpg-pubkey")
	assert.Empty(t, want["gpg-pubkey"].arch)

	for _, fx := range fixtures {
		_, want := loadExpected(t, fx.file)

		var files int
		for _, p := range want {
			files += len(p.files)
		}

		assert.Greater(t, files, 30, fx.file)
	}
}

func TestFindEachLocation(t *testing.T) {
	cases := []struct {
		fixture string
		rel     string
		format  rpmdb.Format
	}{
		{"rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite", rpmdb.FormatSQLite},
		{"rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite", rpmdb.FormatSQLite},
		{"Packages.ndb", "var/lib/rpm/Packages.db", rpmdb.FormatNDB},
		{"Packages.ndb", "usr/lib/sysimage/rpm/Packages.db", rpmdb.FormatNDB},
		{"Packages.bdb", "var/lib/rpm/Packages", rpmdb.FormatBDB},
		{"Packages.bdb", "usr/lib/sysimage/rpm/Packages", rpmdb.FormatBDB},
	}

	for _, c := range cases {
		t.Run(c.rel, func(t *testing.T) {
			root := t.TempDir()
			place(t, root, c.rel, c.fixture)

			path, format, err := rpmdb.Find(root)
			require.NoError(t, err)
			assert.Equal(t, c.format, format)
			assert.Equal(t, filepath.Join(root, c.rel), path)

			db, err := rpmdb.Open(path, rpmdb.Options{})
			require.NoError(t, err)
			require.NoError(t, db.Close())
		})
	}
}

// place copies a fixture to rel under root.
func place(t *testing.T, root, rel, fixture string) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", fixture))
	require.NoError(t, err)

	path := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func TestFindOrderAndSkips(t *testing.T) {
	root := t.TempDir()

	_, _, err := rpmdb.Find(root)
	require.ErrorIs(t, err, rpmdb.ErrNotFound)

	_, _, err = rpmdb.Find("")
	require.ErrorIs(t, err, rpmdb.ErrNotFound)

	// An empty file, a file of another kind and a directory are not databases.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "var/lib/rpm"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "var/lib/rpm/rpmdb.sqlite"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "var/lib/rpm/Packages.db"), []byte("hello"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr/lib/sysimage/rpm/Packages"), 0o755))
	_, _, err = rpmdb.Find(root)
	require.ErrorIs(t, err, rpmdb.ErrNotFound)

	// The legacy file is found when nothing better is there...
	place(t, root, "var/lib/rpm/Packages", "Packages.bdb")

	path, format, err := rpmdb.Find(root)
	require.NoError(t, err)
	assert.Equal(t, rpmdb.FormatBDB, format)
	assert.Equal(t, filepath.Join(root, "var/lib/rpm/Packages"), path)

	// ... and SQLite wins over it.
	place(t, root, "usr/lib/sysimage/rpm/rpmdb.sqlite", "rpmdb.sqlite")

	_, format, err = rpmdb.Find(root)
	require.NoError(t, err)
	assert.Equal(t, rpmdb.FormatSQLite, format)
}

func TestFindStaysInsideRoot(t *testing.T) {
	outside := t.TempDir()
	place(t, outside, "rpmdb.sqlite", "rpmdb.sqlite")

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "var/lib"), 0o755))
	// An absolute link must be read as relative to root, not to the host.
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "var/lib/rpm")))

	_, _, err := rpmdb.Find(root)
	require.ErrorIs(t, err, rpmdb.ErrNotFound)

	// A relative link that stays inside is followed, as on distributions that
	// moved the database to /usr.
	root = t.TempDir()
	place(t, root, "usr/lib/sysimage/rpm/Packages.db", "Packages.ndb")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "var/lib"), 0o755))
	require.NoError(t, os.Symlink("../../usr/lib/sysimage/rpm", filepath.Join(root, "var/lib/rpm")))

	path, format, err := rpmdb.Find(root)
	require.NoError(t, err)
	assert.Equal(t, rpmdb.FormatNDB, format)
	assert.Equal(t, filepath.Join(root, "usr/lib/sysimage/rpm/Packages.db"), path)
}

func TestOpenRejects(t *testing.T) {
	dir := t.TempDir()

	_, err := rpmdb.Open(filepath.Join(dir, "missing"), rpmdb.Options{})
	require.ErrorIs(t, err, os.ErrNotExist)

	_, err = rpmdb.Open(dir, rpmdb.Options{})
	require.ErrorIs(t, err, rpmdb.ErrFormat)

	for name, content := range map[string][]byte{
		"empty":   nil,
		"garbage": bytes.Repeat([]byte("not a database "), 100),
		// A BerkeleyDB btree database, which rpm never used.
		"btree": append(make([]byte, 12), 0x62, 0x31, 0x05, 0x00),
	} {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, content, 0o600))

		_, err = rpmdb.Open(path, rpmdb.Options{})
		require.Error(t, err, name)
	}

	// SQLite that is not an rpm database is corrupt for our purposes.
	path := filepath.Join(dir, "other.sqlite")
	require.NoError(t, os.WriteFile(path, []byte("SQLite format 3\x00"+strings.Repeat("\x00", 100)), 0o600))
	_, err = rpmdb.Open(path, rpmdb.Options{})
	require.ErrorIs(t, err, rpmdb.ErrCorrupt)
}

func TestFormatString(t *testing.T) {
	assert.Equal(t, "sqlite", rpmdb.FormatSQLite.String())
	assert.Equal(t, "bdb", rpmdb.FormatBDB.String())
	assert.Equal(t, "ndb", rpmdb.FormatNDB.String())
	assert.Equal(t, "unknown", rpmdb.FormatUnknown.String())
}

func TestContextCancelStopsEveryFormat(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx.file, func(t *testing.T) {
			db, err := rpmdb.Open(copyFixture(t, fx.file), rpmdb.Options{})
			require.NoError(t, err)

			defer db.Close()

			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			_, err = db.List(ctx)
			require.ErrorIs(t, err, context.Canceled)

			_, err = db.InstalledNames(ctx)
			require.ErrorIs(t, err, context.Canceled)

			_, err = db.InstalledProvides(ctx)
			require.ErrorIs(t, err, context.Canceled)

			// Cancelling in the middle of a walk.
			ctx, cancel = context.WithCancel(t.Context())
			defer cancel()

			var seen int

			var last error

			for _, err := range db.Packages(ctx) {
				last = err

				if seen++; seen == 1 {
					cancel()
				}
			}

			require.ErrorIs(t, last, context.Canceled)
		})
	}
}

func TestStoppingEarlyIsClean(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx.file, func(t *testing.T) {
			db, err := rpmdb.Open(copyFixture(t, fx.file), rpmdb.Options{})
			require.NoError(t, err)

			for pkg, err := range db.Packages(t.Context()) {
				require.NoError(t, err)
				require.NotEmpty(t, pkg.Name)

				break
			}

			require.NoError(t, db.Close())
		})
	}
}

func TestOptions(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx.file, func(t *testing.T) {
			path := copyFixture(t, fx.file)

			db, err := rpmdb.Open(path, rpmdb.Options{MaxRecords: 1})
			require.NoError(t, err)

			_, err = db.List(t.Context())
			require.ErrorIs(t, err, rpmdb.ErrTooLarge)

			_, err = db.InstalledNames(t.Context())
			require.ErrorIs(t, err, rpmdb.ErrTooLarge)
			require.NoError(t, db.Close())

			// Records over the size limit are skipped, and say so.
			var log bytes.Buffer

			logger := slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))

			db, err = rpmdb.Open(path, rpmdb.Options{MaxBlobBytes: 64, Logger: logger})
			require.NoError(t, err)

			pkgs, err := db.List(t.Context())
			require.NoError(t, err)
			assert.Empty(t, pkgs)
			assert.Contains(t, log.String(), "skipping")
			require.NoError(t, db.Close())

			// Limits on the decoding of one header: a package that exceeds them
			// is skipped, or has its file list cut.
			db, err = rpmdb.Open(path, rpmdb.Options{})
			require.NoError(t, err)

			full, err := db.List(t.Context())
			require.NoError(t, err)
			require.NoError(t, db.Close())

			db, err = rpmdb.Open(path, rpmdb.Options{Package: rpm.PackageLimits{MaxArrayEntries: 5}})
			require.NoError(t, err)

			pkgs, err = db.List(t.Context())
			require.NoError(t, err)
			assert.Less(t, len(pkgs), len(full))
			require.NoError(t, db.Close())
		})
	}
}

func TestImmutableSQLite(t *testing.T) {
	path := copyFixture(t, "rpmdb.sqlite")

	db, err := rpmdb.Open(path, rpmdb.Options{Immutable: true})
	require.NoError(t, err)

	defer db.Close()

	names, err := db.InstalledNames(t.Context())
	require.NoError(t, err)
	assert.Contains(t, names, "setup")

	// Nothing was created next to the database.
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestReadOnlyLeavesTheFileAlone(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx.file, func(t *testing.T) {
			path := copyFixture(t, fx.file)
			before, err := os.ReadFile(path)
			require.NoError(t, err)

			db, err := rpmdb.Open(path, rpmdb.Options{})
			require.NoError(t, err)

			_, err = db.List(t.Context())
			require.NoError(t, err)
			require.NoError(t, db.Close())

			after, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(before, after))
		})
	}
}

func TestReadsAfterCloseFail(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx.file, func(t *testing.T) {
			db, err := rpmdb.Open(copyFixture(t, fx.file), rpmdb.Options{})
			require.NoError(t, err)
			require.NoError(t, db.Close())

			_, err = db.List(t.Context())
			require.Error(t, err)
		})
	}
}

func TestConcurrentReads(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx.file, func(t *testing.T) {
			db, err := rpmdb.Open(copyFixture(t, fx.file), rpmdb.Options{})
			require.NoError(t, err)

			defer db.Close()

			errs := make(chan error, 8)

			for range cap(errs) {
				go func() {
					_, err := db.List(t.Context())
					errs <- err
				}()
			}

			for range cap(errs) {
				require.NoError(t, <-errs)
			}
		})
	}
}

func TestSkippedRecordsAreLogged(t *testing.T) {
	var log bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// The BerkeleyDB file keeps a counter next to the packages.
	db, err := rpmdb.Open(copyFixture(t, "Packages.bdb"), rpmdb.Options{Logger: logger})
	require.NoError(t, err)

	defer db.Close()

	pkgs, err := db.List(t.Context())
	require.NoError(t, err)
	assert.Len(t, pkgs, 4)
	assert.Contains(t, log.String(), "not a header image")
}

func TestErrorsAreTyped(t *testing.T) {
	for _, err := range []error{rpmdb.ErrNotFound, rpmdb.ErrFormat, rpmdb.ErrUnsupported, rpmdb.ErrCorrupt, rpmdb.ErrTooLarge} {
		assert.True(t, errors.Is(fmt.Errorf("wrapped: %w", err), err))
		assert.True(t, strings.HasPrefix(err.Error(), "rpmdb: "))
	}
}
