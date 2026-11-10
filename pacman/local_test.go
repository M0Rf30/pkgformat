package pacman_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/pacman"
)

const localFixture = "testdata/localdb"

func openLocal(t *testing.T, opts pacman.LocalDBOptions) *pacman.LocalDB {
	t.Helper()

	db, err := pacman.OpenLocalDB(filepath.Join(localFixture, "local"), opts)
	require.NoError(t, err)

	t.Cleanup(func() { _ = db.Close() })

	return db
}

// qiRecord is one package of "pacman -Qi": field name to its lines.
type qiRecord map[string][]string

func readQi(t *testing.T) []qiRecord {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(localFixture, "Qi.expected"))
	require.NoError(t, err)

	var (
		recs []qiRecord
		cur  qiRecord
		key  string
	)

	for line := range strings.SplitSeq(string(data), "\n") {
		switch {
		case line == "":
			cur = nil
		case strings.HasPrefix(line, " "):
			cur[key] = append(cur[key], strings.TrimSpace(line))
		default:
			k, v, ok := strings.Cut(line, " : ")
			require.True(t, ok, line)

			key = strings.TrimSpace(k)

			if key == "Name" {
				cur = qiRecord{}
				recs = append(recs, cur)
			}

			cur[key] = []string{v}
		}
	}

	return recs
}

// words splits a pacman -Qi list, whose entries are separated by two spaces.
func words(lines []string) []string {
	if len(lines) == 1 && lines[0] == "None" {
		return nil
	}

	return strings.Split(lines[0], "  ")
}

func qiTime(t *testing.T, s string) int64 {
	t.Helper()

	tm, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", s, time.UTC)
	require.NoError(t, err, s)

	return tm.Unix()
}

func TestLocalDBMatchesPacman(t *testing.T) {
	pkgs, err := openLocal(t, pacman.LocalDBOptions{}).List(context.Background())
	require.NoError(t, err)

	recs := readQi(t)
	require.Len(t, pkgs, len(recs))

	for i, p := range pkgs {
		rec := recs[i]
		name := rec["Name"][0]

		assert.Equal(t, name, p.Name)
		assert.Equal(t, rec["Version"][0], p.Version, name)
		assert.Equal(t, rec["Description"][0], p.Description, name)
		assert.Equal(t, rec["Architecture"][0], p.Arch, name)
		assert.Equal(t, rec["URL"][0], p.URL, name)
		assert.Equal(t, rec["Packager"][0], p.Packager, name)
		assert.Equal(t, name+"-"+p.Version, p.Dir)
		assert.Equal(t, words(rec["Licenses"]), p.Licenses, name)
		assert.Equal(t, words(rec["Provides"]), p.Provides, name)
		assert.Equal(t, words(rec["Depends On"]), p.Depends, name)
		assert.Equal(t, words(rec["Conflicts With"]), p.Conflicts, name)
		assert.Equal(t, words(rec["Replaces"]), p.Replaces, name)
		assert.Equal(t, words(rec["Groups"]), p.Groups, name)

		var opt []string

		for _, l := range rec["Optional Deps"] {
			if l != "None" {
				opt = append(opt, l)
			}
		}

		assert.Equal(t, opt, p.OptDepends, name)
		assert.Equal(t, qiTime(t, rec["Build Date"][0]), p.BuildDate, name)
		assert.Equal(t, qiTime(t, rec["Install Date"][0]), p.InstallDate, name)

		if rec["Install Reason"][0] == "Explicitly installed" {
			assert.Equal(t, pacman.ReasonExplicit, p.Reason, name)
		} else {
			assert.Equal(t, pacman.ReasonDependency, p.Reason, name)
		}

		assert.Equal(t, []string{"pgp"}, p.Validation, name)
		assert.Equal(t, "Signature", rec["Validated By"][0])
		assert.Positive(t, p.Size, name)
		require.NotEmpty(t, p.XData, name)
		assert.True(t, strings.HasPrefix(p.XData[0], "pkgtype="), name)
	}
}

func TestLocalDBMatchesPacmanQAndQl(t *testing.T) {
	db := openLocal(t, pacman.LocalDBOptions{})

	pkgs, err := db.List(context.Background())
	require.NoError(t, err)

	q, err := os.ReadFile(filepath.Join(localFixture, "Q.expected"))
	require.NoError(t, err)

	var got []string

	for _, p := range pkgs {
		got = append(got, p.Name+" "+p.Version)
	}

	assert.Equal(t, strings.TrimSpace(string(q)), strings.Join(got, "\n"))

	ql, err := os.ReadFile(filepath.Join(localFixture, "Ql.expected"))
	require.NoError(t, err)

	var want []string

	for _, p := range pkgs {
		for _, f := range p.Files {
			want = append(want, p.Name+" /"+f)
		}
	}

	assert.Equal(t, strings.TrimSpace(string(ql)), strings.Join(want, "\n"))

	names, err := db.InstalledNames(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{
		"acl", "attr", "bash", "binutils", "ca-certificates-utils", "filesystem",
		"pacman", "pacman-mirrorlist", "tree",
	}, names)
}

func TestLocalDBBackupAndFiles(t *testing.T) {
	pkgs, err := openLocal(t, pacman.LocalDBOptions{}).List(context.Background())
	require.NoError(t, err)

	byName := map[string]*pacman.InstalledPackage{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	mirror := byName["pacman-mirrorlist"]
	require.NotNil(t, mirror)
	assert.Equal(t, []string{"etc/", "etc/pacman.d/", "etc/pacman.d/mirrorlist"}, mirror.Files)
	assert.Equal(t, []pacman.BackupFile{{Path: "etc/pacman.d/mirrorlist", MD5: "(null)"}}, mirror.Backup)

	pm := byName["pacman"]
	require.NotNil(t, pm)
	assert.NotEmpty(t, pm.Backup)

	for _, b := range pm.Backup {
		assert.NotEmpty(t, b.Path)
	}
}

func TestLocalDBSkipFiles(t *testing.T) {
	pkgs, err := openLocal(t, pacman.LocalDBOptions{SkipFiles: true}).List(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, pkgs)

	for _, p := range pkgs {
		assert.Empty(t, p.Files)
		assert.Empty(t, p.Backup)
	}
}

func TestLocalDBInstalledProvides(t *testing.T) {
	provides, err := openLocal(t, pacman.LocalDBOptions{}).InstalledProvides(context.Background())
	require.NoError(t, err)

	assert.Contains(t, provides, "libacl.so", "version stripped")
	assert.NotContains(t, provides, "libacl.so=1-64")
	assert.Contains(t, provides, "acl", "the package's own name")
	assert.Contains(t, provides, "sh", "bash provides sh")
	assert.Contains(t, provides, "libalpm.so")
	assert.IsIncreasing(t, provides)
}

// memDB builds a database directory in memory: package directory to desc and
// files members.
func memDB(entries map[string][2]string) fstest.MapFS {
	fsys := fstest.MapFS{"ALPM_DB_VERSION": {Data: []byte("9\n")}}

	for dir, m := range entries {
		if m[0] != "" {
			fsys[dir+"/desc"] = &fstest.MapFile{Data: []byte(m[0])}
		}

		if m[1] != "" {
			fsys[dir+"/files"] = &fstest.MapFile{Data: []byte(m[1])}
		}
	}

	return fsys
}

func desc(name, version string, extra ...string) string {
	return "%NAME%\n" + name + "\n\n%VERSION%\n" + version + "\n\n" + strings.Join(extra, "")
}

func TestLocalDBNameComesFromDesc(t *testing.T) {
	fsys := memDB(map[string][2]string{
		"whatever-dir": {desc("real", "1.0-1", "%PROVIDES%\nvirt=2\nsh\n\n"), ""},
	})

	pkgs, err := pacman.NewLocalDB(fsys, pacman.LocalDBOptions{}).List(context.Background())
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "real", pkgs[0].Name)
	assert.Equal(t, "whatever-dir", pkgs[0].Dir)
	assert.Equal(t, pacman.ReasonExplicit, pkgs[0].Reason, "no %REASON% means explicit")
}

func TestLocalDBSkipsInvalidPackages(t *testing.T) {
	bad := func(extra string) [2]string { return [2]string{desc("p", "1-1", extra), ""} }

	fsys := memDB(map[string][2]string{
		"good-1-1":    {desc("good", "1-1", "%INSTALLDATE%\n5\n\n%SIZE%\n7\n\n%REASON%\n1\n\n%GROUPS%\ng1\n\n%REPLACES%\nold\n\n%CONFLICTS%\nc\n\n%BASE%\nb\n\n"), "%FILES%\nusr/\nusr/bin/x\n\n%BACKUP%\nusr/bin/x\tabc\nusr/bin/y\n\n"},
		"nodesc-1-1":  {"", "%FILES%\nusr/\n"},
		"badname-1-1": {desc("Bad Name", "1-1"), ""},
		"badver-1":    {desc("badver", "1"), ""},
		"badarch-1-1": bad("%ARCH%\nx 86\n\n"),
		"badnum-1-1":  bad("%SIZE%\nlots\n\n"),
		"neg-1-1":     bad("%INSTALLDATE%\n-1\n\n"),
		"toolong-1-1": bad("%DESC%\n" + strings.Repeat("x", pacman.MaxValueLen+1) + "\n\n"),
		"escape-1-1":  {desc("escape", "1-1"), "%FILES%\nusr/../../etc/passwd\n"},
		"abs-1-1":     {desc("abs", "1-1"), "%FILES%\n/etc/passwd\n"},
		"dirbackup-1": {desc("dirbackup", "1-1"), "%BACKUP%\nusr/\tabc\n"},
		"longline-1":  {desc("longline", "1-1"), "%FILES%\n" + strings.Repeat("a", 9000) + "\n"},
	})
	fsys["afile"] = &fstest.MapFile{Data: []byte("x")}
	fsys["link-1-1"] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("good-1-1")}

	var buf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	pkgs, err := pacman.NewLocalDB(fsys, pacman.LocalDBOptions{Logger: logger}).List(context.Background())
	require.NoError(t, err)
	require.Len(t, pkgs, 1)

	g := pkgs[0]
	assert.Equal(t, "good", g.Name)
	assert.Equal(t, int64(5), g.InstallDate)
	assert.Equal(t, int64(7), g.Size)
	assert.Equal(t, pacman.ReasonDependency, g.Reason)
	assert.Equal(t, []string{"g1"}, g.Groups)
	assert.Equal(t, []string{"old"}, g.Replaces)
	assert.Equal(t, []string{"c"}, g.Conflicts)
	assert.Equal(t, "b", g.Base)
	assert.Equal(t, []string{"usr/", "usr/bin/x"}, g.Files)
	assert.Equal(t, []pacman.BackupFile{{Path: "usr/bin/x", MD5: "abc"}, {Path: "usr/bin/y"}}, g.Backup)
	assert.Contains(t, buf.String(), "skipping a local package")

	// Without the files members, a bad one does not hide the package.
	pkgs, err = pacman.NewLocalDB(fsys, pacman.LocalDBOptions{SkipFiles: true}).List(context.Background())
	require.NoError(t, err)

	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name)
	}

	assert.Equal(t, []string{"abs", "dirbackup", "escape", "good", "longline"}, names)
}

func TestLocalDBVersion(t *testing.T) {
	fsys := memDB(map[string][2]string{"a-1-1": {desc("a", "1-1"), ""}})
	fsys["ALPM_DB_VERSION"] = &fstest.MapFile{Data: []byte("8\n")}

	_, err := pacman.NewLocalDB(fsys, pacman.LocalDBOptions{}).List(context.Background())
	require.ErrorIs(t, err, pacman.ErrUnsupportedLocalDB)

	delete(fsys, "ALPM_DB_VERSION")

	pkgs, err := pacman.NewLocalDB(fsys, pacman.LocalDBOptions{}).List(context.Background())
	require.NoError(t, err, "a database without a version file reads as the current one")
	assert.Len(t, pkgs, 1)

	fsys["ALPM_DB_VERSION"] = &fstest.MapFile{Mode: fs.ModeDir}

	_, err = pacman.NewLocalDB(fsys, pacman.LocalDBOptions{}).List(context.Background())
	require.ErrorIs(t, err, pacman.ErrInvalidLocalDB)

	fsys["ALPM_DB_VERSION"] = &fstest.MapFile{Data: bytes.Repeat([]byte("9"), 100)}

	_, err = pacman.NewLocalDB(fsys, pacman.LocalDBOptions{}).List(context.Background())
	require.ErrorIs(t, err, pacman.ErrInvalidLocalDB)
}

func TestLocalDBLimits(t *testing.T) {
	entries := map[string][2]string{}
	for i := range 5 {
		entries[fmt.Sprintf("p%d-1-1", i)] = [2]string{desc(fmt.Sprintf("p%d", i), "1-1"), ""}
	}

	fsys := memDB(entries) // five directories and ALPM_DB_VERSION

	_, err := pacman.NewLocalDB(fsys, pacman.LocalDBOptions{MaxPackages: 5}).List(context.Background())
	require.ErrorIs(t, err, pacman.ErrLocalDBTooLarge)

	pkgs, err := pacman.NewLocalDB(fsys, pacman.LocalDBOptions{MaxPackages: 6}).List(context.Background())
	require.NoError(t, err)
	assert.Len(t, pkgs, 5)

	// A package with too many file records is skipped, not the database.
	files := "%FILES%\n" + strings.Repeat("a\n", 10)
	many := memDB(map[string][2]string{
		"many-1-1": {desc("many", "1-1"), files},
		"few-1-1":  {desc("few", "1-1"), "%FILES%\na\n"},
	})

	pkgs, err = pacman.NewLocalDB(many, pacman.LocalDBOptions{MaxFiles: 5}).List(context.Background())
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "few", pkgs[0].Name)

	// An oversized desc is skipped.
	big := memDB(map[string][2]string{"big-1-1": {desc("big", "1-1", "%DESC%\n"+strings.Repeat("x", pacman.MaxDescBytes)), ""}})
	pkgs, err = pacman.NewLocalDB(big, pacman.LocalDBOptions{}).List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}

func TestLocalDBEntriesWithoutDirectories(t *testing.T) {
	// A plain file where the database directory should be.
	fsys := fstest.MapFS{"x": {Data: []byte("x")}}
	db := pacman.NewLocalDB(subFS{fsys}, pacman.LocalDBOptions{})

	_, err := db.List(context.Background())
	require.ErrorIs(t, err, pacman.ErrInvalidLocalDB)
}

// subFS opens "." as a regular file, which is no directory.
type subFS struct{ fstest.MapFS }

func (s subFS) Open(name string) (fs.File, error) {
	if name == "." {
		return s.MapFS.Open("x")
	}

	return s.MapFS.Open(name)
}

type failDir struct {
	fs.File
	n int
}

func (d *failDir) ReadDir(int) ([]fs.DirEntry, error) {
	if d.n++; d.n > 1 {
		return nil, errors.New("disk on fire")
	}

	return []fs.DirEntry{fs.FileInfoToDirEntry(dirInfo{"a"})}, nil
}

type dirInfo struct{ name string }

func (d dirInfo) Name() string               { return d.name }
func (dirInfo) Size() int64                  { return 0 }
func (dirInfo) Mode() fs.FileMode            { return fs.ModeDir | 0o755 }
func (dirInfo) ModTime() time.Time           { return time.Time{} }
func (dirInfo) IsDir() bool                  { return true }
func (dirInfo) Sys() any                     { return nil }
func (d dirInfo) Stat() (fs.FileInfo, error) { return d, nil }

type brokenFS struct{ fstest.MapFS }

func (b brokenFS) Open(name string) (fs.File, error) {
	f, err := b.MapFS.Open(name)
	if name == "." && err == nil {
		return &failDir{File: f}, nil
	}

	return f, err
}

func TestLocalDBReadDirError(t *testing.T) {
	_, err := pacman.NewLocalDB(brokenFS{fstest.MapFS{"a/desc": {Data: []byte("x")}}}, pacman.LocalDBOptions{}).List(context.Background())
	require.ErrorIs(t, err, pacman.ErrInvalidLocalDB)
	require.ErrorContains(t, err, "disk on fire")
}

func TestLocalDBEarlyStopAndCancel(t *testing.T) {
	db := openLocal(t, pacman.LocalDBOptions{})

	n := 0

	for p, err := range db.Packages(context.Background()) {
		require.NoError(t, err)
		require.NotNil(t, p)

		if n++; n == 2 {
			break
		}
	}

	assert.Equal(t, 2, n)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	n = 0

	var last error

	for _, err := range db.Packages(ctx) {
		if err != nil {
			last = err

			break
		}

		if n++; n == 1 {
			cancel()
		}
	}

	require.ErrorIs(t, last, context.Canceled)

	_, err := db.InstalledNames(ctx)
	require.ErrorIs(t, err, context.Canceled)
	_, err = db.InstalledProvides(ctx)
	require.ErrorIs(t, err, context.Canceled)
	_, err = db.List(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestOpenAndFindLocalDB(t *testing.T) {
	_, err := pacman.OpenLocalDB(filepath.Join(t.TempDir(), "missing"), pacman.LocalDBOptions{})
	require.ErrorIs(t, err, fs.ErrNotExist)

	require.NoError(t, pacman.NewLocalDB(fstest.MapFS{}, pacman.LocalDBOptions{}).Close())

	root := t.TempDir()

	_, err = pacman.FindLocalDB(root)
	require.ErrorIs(t, err, pacman.ErrLocalDBNotFound)

	_, err = pacman.FindLocalDB("")
	require.ErrorIs(t, err, pacman.ErrLocalDBNotFound)

	dir := filepath.Join(root, "var/lib/pacman")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "local"), nil, 0o644))

	_, err = pacman.FindLocalDB(root)
	require.ErrorIs(t, err, pacman.ErrLocalDBNotFound, "a file is no database")

	require.NoError(t, os.Remove(filepath.Join(dir, "local")))
	require.NoError(t, os.CopyFS(filepath.Join(dir, "local"), os.DirFS(filepath.Join(localFixture, "local"))))

	path, err := pacman.FindLocalDB(root)
	require.NoError(t, err)

	db, err := pacman.OpenLocalDB(path, pacman.LocalDBOptions{})
	require.NoError(t, err)

	defer db.Close()

	names, err := db.InstalledNames(context.Background())
	require.NoError(t, err)
	assert.Contains(t, names, "bash")
}

// TestLocalDBStaysInDirectory checks that links inside the database that point
// out of it are not followed.
func TestLocalDBStaysInDirectory(t *testing.T) {
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "desc"), []byte(desc("evil", "1-1")), 0o644))

	dir := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "evil-1-1")))

	good := filepath.Join(dir, "ok-1-1")
	require.NoError(t, os.Mkdir(good, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(good, "desc"), []byte(desc("ok", "1-1")), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(outside, "desc"), filepath.Join(good, "files")))

	db, err := pacman.OpenLocalDB(dir, pacman.LocalDBOptions{})
	require.NoError(t, err)

	defer db.Close()

	pkgs, err := db.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, pkgs, "a symlinked directory is skipped and a symlinked files member fails its package")

	names, err := db.InstalledNames(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"ok"}, names, "without files members the package is there")
}

// FuzzReadLocalDB reads a database whose members are arbitrary text.
func FuzzReadLocalDB(f *testing.F) {
	descData, _ := os.ReadFile(filepath.Join(localFixture, "local/acl-2.4.0-1/desc"))
	filesData, _ := os.ReadFile(filepath.Join(localFixture, "local/pacman-mirrorlist-20260610-1/files"))

	f.Add(descData, filesData)
	f.Add([]byte(desc("a", "1-1")), []byte("%FILES%\n../x\n/y\n%BACKUP%\nz\t\n"))
	f.Add([]byte("%NAME%\n%VERSION%\n%SIZE%\n-1\n"), []byte("%%\n%FILES%\n\n\x00"))
	f.Add([]byte(""), []byte(""))

	f.Fuzz(func(t *testing.T, descIn, filesIn []byte) {
		fsys := fstest.MapFS{
			"ALPM_DB_VERSION": {Data: []byte("9\n")},
			"a-1-1/desc":      {Data: descIn},
			"a-1-1/files":     {Data: filesIn},
		}

		for _, skip := range []bool{false, true} {
			db := pacman.NewLocalDB(fsys, pacman.LocalDBOptions{SkipFiles: skip, MaxFiles: 1000})

			for p, err := range db.Packages(context.Background()) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if !pacman.ValidName(p.Name) || !pacman.ValidVersion(p.Version) {
					t.Fatalf("package without an identity: %+v", p)
				}

				for _, file := range p.Files {
					for seg := range strings.SplitSeq(strings.TrimSuffix(file, "/"), "/") {
						if seg == "" || seg == "." || seg == ".." {
							t.Fatalf("path outside the root: %q", file)
						}
					}
				}
			}
		}

		db := pacman.NewLocalDB(fsys, pacman.LocalDBOptions{})
		_, _ = db.InstalledNames(context.Background())
		_, _ = db.InstalledProvides(context.Background())
	})
}
