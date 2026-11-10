package apk_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/apk"
)

var installedFixtures = []string{"alpine-3.24", "alpine-3.20"}

func fixturePath(fixture, file string) string {
	return filepath.Join("testdata", "installed", fixture, file)
}

func openInstalled(t *testing.T, fixture string, opts apk.InstalledOptions) *apk.InstalledDB {
	t.Helper()

	db, err := apk.OpenInstalled(fixturePath(fixture, "installed"), opts)
	require.NoError(t, err)

	t.Cleanup(func() { _ = db.Close() })

	return db
}

// infoBlocks reads what "apk info -L/-P/-R" printed: a header line
// "<name>-<version> <what>:" and the lines up to a blank one. The result maps
// the "<name>-<version>" to the lines.
func infoBlocks(t *testing.T, fixture, file, what string) map[string][]string {
	t.Helper()

	data, err := os.ReadFile(fixturePath(fixture, file))
	require.NoError(t, err)

	blocks := map[string][]string{}
	cur := ""

	for line := range strings.SplitSeq(string(data), "\n") {
		switch {
		case strings.HasSuffix(line, " "+what+":"):
			cur = strings.TrimSuffix(line, " "+what+":")
			blocks[cur] = []string{}
		case line == "":
			cur = ""
		case cur != "":
			blocks[cur] = append(blocks[cur], line)
		}
	}

	return blocks
}

// listRow is a line of "apk list -I": "name-version arch {origin} (license) [installed]".
type listRow struct{ id, arch, origin, license string }

func listRows(t *testing.T, fixture string) []listRow {
	t.Helper()

	data, err := os.ReadFile(fixturePath(fixture, "list.expected"))
	require.NoError(t, err)

	var rows []listRow

	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		id, rest, _ := strings.Cut(line, " ")
		arch, rest, _ := strings.Cut(rest, " ")
		origin, rest, _ := strings.Cut(rest, " ")
		license := strings.TrimSuffix(strings.TrimPrefix(rest, "("), ") [installed]")
		rows = append(rows, listRow{id, arch, strings.Trim(origin, "{}"), license})
	}

	return rows
}

func TestInstalledMatchesApkInfo(t *testing.T) {
	for _, fixture := range installedFixtures {
		t.Run(fixture, func(t *testing.T) {
			pkgs, err := openInstalled(t, fixture, apk.InstalledOptions{}).List(context.Background())
			require.NoError(t, err)

			rows := listRows(t, fixture)
			require.Len(t, pkgs, len(rows))

			files := infoBlocks(t, fixture, "files.expected", "contains")
			provides := infoBlocks(t, fixture, "provides.expected", "provides")
			depends := infoBlocks(t, fixture, "depends.expected", "depends on")

			for i, p := range pkgs {
				row := rows[i]
				id := p.Name + "-" + p.Version

				assert.Equal(t, row.id, id)
				assert.Equal(t, row.arch, p.Arch, id)
				assert.Equal(t, row.license, p.License, id)

				if p.Origin != "" { // a virtual package has none, and apk list shows its name
					assert.Equal(t, row.origin, p.Origin, id)
				} else {
					assert.Equal(t, p.Name, row.origin, id)
				}

				assert.Equal(t, files[id], emptyIfNil(p.FilePaths()), "files of %s", id)
				assert.Equal(t, provides[id], emptyIfNil(p.Provides), "provides of %s", id)
				assert.Equal(t, depends[id], emptyIfNil(p.Depends), "depends of %s", id)

				assert.NotEmpty(t, p.Checksum, id)

				if p.Origin != "" {
					assert.NotZero(t, p.BuildTime, id)
				}
			}
		})
	}
}

// nameOf splits "name-version" at the first hyphen that is followed by a digit.
func nameOf(t *testing.T, id string) string {
	t.Helper()

	m := idPattern.FindStringSubmatch(id)
	require.NotNil(t, m, id)

	return m[1]
}

var idPattern = regexp.MustCompile(`^(.+?)-[0-9]`)

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}

	return s
}

func TestInstalledFileRecords(t *testing.T) {
	pkgs, err := openInstalled(t, "alpine-3.24", apk.InstalledOptions{}).List(context.Background())
	require.NoError(t, err)

	byName := map[string]*apk.InstalledPackage{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	musl := byName["musl"]
	require.NotNil(t, musl)

	require.Len(t, musl.Files, 3)
	assert.Equal(t, apk.InstalledFile{Path: "lib", Dir: true}, musl.Files[0])
	assert.Equal(t, "lib/ld-musl-x86_64.so.1", musl.Files[1].Path)
	assert.False(t, musl.Files[1].Dir)
	assert.True(t, musl.Files[1].HasACL)
	assert.Equal(t, uint32(0o755), musl.Files[1].Mode)
	assert.True(t, strings.HasPrefix(musl.Files[1].Checksum, "Q1"), musl.Files[1].Checksum)

	// The virtual package has a name no index entry could have.
	virtual := byName[".build-deps"]
	require.NotNil(t, virtual)
	assert.Equal(t, "noarch", virtual.Arch)
	assert.Empty(t, virtual.Files)
	assert.Equal(t, []string{"zlib-dev"}, virtual.Depends)

	// A directory with an ACL: /etc/crontabs is 0600 root.
	base := byName["alpine-baselayout"]
	require.NotNil(t, base)

	var crontabs, root *apk.InstalledFile

	for i := range base.Files {
		switch base.Files[i].Path {
		case "etc/crontabs":
			crontabs = &base.Files[i]
		case "etc/crontabs/root":
			root = &base.Files[i]
		}
	}

	require.NotNil(t, crontabs)
	require.NotNil(t, root)
	assert.True(t, crontabs.Dir)
	assert.Equal(t, uint32(0o600), root.Mode)
	assert.Equal(t, 1000, base.ReplacesPriority)

	// Replaces and the other fields of apk 2.
	old, err := openInstalled(t, "alpine-3.20", apk.InstalledOptions{}).List(context.Background())
	require.NoError(t, err)

	var replacing int

	for _, p := range old {
		if len(p.Replaces) > 0 {
			replacing++
		}
	}

	assert.Positive(t, replacing)
}

func TestInstalledSkipFiles(t *testing.T) {
	pkgs, err := openInstalled(t, "alpine-3.20", apk.InstalledOptions{SkipFiles: true}).List(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, pkgs)

	for _, p := range pkgs {
		assert.Empty(t, p.Files, p.Name)
	}
}

func TestInstalledNamesAndProvides(t *testing.T) {
	for _, fixture := range installedFixtures {
		t.Run(fixture, func(t *testing.T) {
			db := openInstalled(t, fixture, apk.InstalledOptions{})

			names, err := db.InstalledNames(context.Background())
			require.NoError(t, err)

			want := map[string]bool{}
			wantProvides := map[string]bool{}

			for _, row := range listRows(t, fixture) {
				name := nameOf(t, row.id)
				want[name] = true
				wantProvides[name] = true
			}

			for id, lines := range infoBlocks(t, fixture, "provides.expected", "provides") {
				_ = id

				for _, l := range lines {
					wantProvides[apk.DependencyName(l)] = true
				}
			}

			assert.Len(t, names, len(want))

			for _, n := range names {
				assert.True(t, want[n], n)
			}

			assert.IsIncreasing(t, names)

			provides, err := db.InstalledProvides(context.Background())
			require.NoError(t, err)
			assert.Len(t, provides, len(wantProvides))

			for _, p := range provides {
				assert.True(t, wantProvides[p], p)
			}

			assert.IsIncreasing(t, provides)
			assert.Contains(t, provides, "busybox")
		})
	}

	provides, err := openInstalled(t, "alpine-3.24", apk.InstalledOptions{}).InstalledProvides(context.Background())
	require.NoError(t, err)
	assert.Contains(t, provides, "so:libc.musl-x86_64.so.1", "a version constraint is dropped")
	assert.Contains(t, provides, "cmd:apk")
	assert.NotContains(t, provides, "cmd:apk=3.0.8-r0")
}

func readerDB(text string, opts apk.InstalledOptions) *apk.InstalledDB {
	return apk.NewInstalledDB(strings.NewReader(text), int64(len(text)), opts)
}

const goodRecord = "C:Q1qvTGHdzF6KLavt4PO0gs2a6pQ00=\nP:%s\nV:1.0-r0\nA:x86_64\nS:10\nI:20\nT:t\n"

func rec(name string) string { return strings.Replace(goodRecord, "%s", name, 1) }

func TestInstalledSkipsInvalidRecords(t *testing.T) {
	text := rec("good1") + "F:usr\nR:a\na:0:0:755\nZ:Q1abc=\n\n" +
		"P:novers\nA:x86_64\n\n" + // no V
		"C:Q1x=\nP:twice\nP:twice\nV:1\nA:noarch\n\n" + // repeated field
		"P:bad name\nV:1\nA:noarch\n\n" +
		"P:badnum\nV:1\nA:noarch\nS:12x\n\n" +
		"P:noletter\nV:1\nA:noarch\njunk line\n\n" +
		"P:escape\nV:1\nA:noarch\nF:usr/../..\n\n" +
		"P:escape2\nV:1\nA:noarch\nF:usr\nR:../../x\n\n" +
		"P:orphan\nV:1\nA:noarch\nZ:Q1abc=\n\n" +
		"P:dirz\nV:1\nA:noarch\nF:usr\nZ:Q1abc=\n\n" +
		"P:filem\nV:1\nA:noarch\nF:usr\nR:a\nM:0:0:755\n\n" +
		"P:badacl\nV:1\nA:noarch\nF:usr\nR:a\na:x:0:755\n\n" +
		"P:badacl2\nV:1\nA:noarch\nF:usr\nR:a\na:0:0:99999\n\n" +
		"P:badacl3\nV:1\nA:noarch\nF:usr\nR:a\na:0:0\n\n" +
		"P:badz\nV:1\nA:noarch\nF:usr\nR:a\nZ:\n\n" +
		"P:badq\nV:1\nA:noarch\nq:x\n\n" +
		"P:ctrl\nV:1\nA:noarch\nC:Q1\x01\n\n" +
		"P:longname" + strings.Repeat("x", 200) + "\nV:1\nA:noarch\n\n" +
		"\n\n\n" + rec("good2") + "p:so:x=1 cmd:y\nr:old-pkg\nq:5\n"

	var buf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	pkgs, err := readerDB(text, apk.InstalledOptions{Logger: logger}).List(context.Background())
	require.NoError(t, err)

	require.Len(t, pkgs, 2)
	assert.Equal(t, "good1", pkgs[0].Name)
	assert.Equal(t, "good2", pkgs[1].Name)
	assert.Equal(t, []string{"usr/a"}, pkgs[0].FilePaths())
	assert.Equal(t, []string{"so:x=1", "cmd:y"}, pkgs[1].Provides)
	assert.Equal(t, []string{"old-pkg"}, pkgs[1].Replaces)
	assert.Equal(t, 5, pkgs[1].ReplacesPriority)
	assert.Contains(t, buf.String(), "skipping an installed record")
}

func TestInstalledToleratesChecksumsOfOtherAlgorithms(t *testing.T) {
	text := "C:Q2" + strings.Repeat("A", 43) + "=\nP:v3\nV:1\nA:noarch\nF:usr\nR:x\nZ:Q2" + strings.Repeat("B", 43) + "=\n\n" +
		"P:nocsum\nV:1\nA:noarch\n"

	pkgs, err := readerDB(text, apk.InstalledOptions{}).List(context.Background())
	require.NoError(t, err)
	require.Len(t, pkgs, 2)
	assert.Equal(t, "Q2"+strings.Repeat("A", 43)+"=", pkgs[0].Checksum)
	assert.Empty(t, pkgs[1].Checksum)
}

func TestInstalledEmptyRootFiles(t *testing.T) {
	pkgs, err := readerDB("P:p\nV:1\nA:noarch\nF:\nR:top\nF:a\nF:a/b\nR:c\n", apk.InstalledOptions{}).List(context.Background())
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, []string{"top", "a/b/c"}, pkgs[0].FilePaths())
}

func TestInstalledLimits(t *testing.T) {
	text := strings.Repeat(rec("p")+"\n", 5)

	_, err := readerDB(text, apk.InstalledOptions{MaxPackages: 4}).List(context.Background())
	require.ErrorIs(t, err, apk.ErrInstalledTooLarge)

	pkgs, err := readerDB(text, apk.InstalledOptions{MaxPackages: 5}).List(context.Background())
	require.NoError(t, err)
	assert.Len(t, pkgs, 5)

	// Too many file records skip the package, not the database.
	big := rec("many") + "F:d\n" + strings.Repeat("R:f\n", 10) + "\n" + rec("few")
	pkgs, err = readerDB(big, apk.InstalledOptions{MaxFiles: 5}).List(context.Background())
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "few", pkgs[0].Name)

	// The bytes are bounded whatever the size the caller states.
	_, err = apk.NewInstalledDB(strings.NewReader(text), 1<<20, apk.InstalledOptions{MaxBytes: 100}).List(context.Background())
	require.ErrorIs(t, err, apk.ErrInstalledTooLarge)

	_, err = apk.NewInstalledDB(strings.NewReader(text), int64(len(text)), apk.InstalledOptions{MaxBytes: 100}).List(context.Background())
	require.ErrorIs(t, err, apk.ErrInstalledTooLarge)

	_, err = readerDB("P:p\nT:"+strings.Repeat("x", 1<<20+10)+"\n", apk.InstalledOptions{}).List(context.Background())
	require.ErrorIs(t, err, apk.ErrInstalledTooLarge)

	_, err = apk.OpenInstalled(fixturePath("alpine-3.24", "installed"), apk.InstalledOptions{MaxBytes: 1000})
	require.ErrorIs(t, err, apk.ErrInstalledTooLarge)
}

type errReaderAt struct{}

func (errReaderAt) ReadAt([]byte, int64) (int, error) { return 0, errors.New("disk on fire") }

func TestInstalledReadError(t *testing.T) {
	_, err := apk.NewInstalledDB(errReaderAt{}, 100, apk.InstalledOptions{}).List(context.Background())
	require.ErrorIs(t, err, apk.ErrInvalidInstalled)
	require.ErrorContains(t, err, "disk on fire")
}

func TestInstalledEarlyStopAndCancel(t *testing.T) {
	db := openInstalled(t, "alpine-3.24", apk.InstalledOptions{})

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

func TestInstalledCancelInsideLongRecord(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	text := "P:p\nV:1\nA:noarch\nF:d\n" + strings.Repeat("R:f\n", 20000)

	_, err := readerDB(text, apk.InstalledOptions{}).List(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestOpenAndFindInstalled(t *testing.T) {
	_, err := apk.OpenInstalled(filepath.Join(t.TempDir(), "missing"), apk.InstalledOptions{})
	require.ErrorIs(t, err, fs.ErrNotExist)

	_, err = apk.OpenInstalled(t.TempDir(), apk.InstalledOptions{})
	require.ErrorIs(t, err, apk.ErrInvalidInstalled)

	require.NoError(t, readerDB("", apk.InstalledOptions{}).Close())

	root := t.TempDir()

	_, err = apk.FindInstalled(root)
	require.ErrorIs(t, err, apk.ErrInstalledNotFound)

	_, err = apk.FindInstalled("")
	require.ErrorIs(t, err, apk.ErrInstalledNotFound)

	dir := filepath.Join(root, "lib/apk/db")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "installed"), 0o755))

	_, err = apk.FindInstalled(root)
	require.ErrorIs(t, err, apk.ErrInstalledNotFound, "a directory is no database")

	require.NoError(t, os.Remove(filepath.Join(dir, "installed")))

	data, err := os.ReadFile(fixturePath("alpine-3.24", "installed"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "installed"), data, 0o644))

	path, err := apk.FindInstalled(root)
	require.NoError(t, err)

	db, err := apk.OpenInstalled(path, apk.InstalledOptions{})
	require.NoError(t, err)

	defer db.Close()

	names, err := db.InstalledNames(context.Background())
	require.NoError(t, err)
	assert.Contains(t, names, "musl")
}

// TestFindInstalledStaysInRoot checks that a link inside the root that points
// out of it is resolved inside the root, not on the host.
func TestFindInstalledStaysInRoot(t *testing.T) {
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "installed"), []byte("P:evil\n"), 0o644))

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "lib/apk"), 0o755))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "lib/apk/db")))

	_, err := apk.FindInstalled(root)
	require.ErrorIs(t, err, apk.ErrInstalledNotFound)
}

// FuzzReadInstalled feeds arbitrary text to the installed-database reader.
func FuzzReadInstalled(f *testing.F) {
	data, err := os.ReadFile(fixturePath("alpine-3.20", "installed"))
	if err == nil {
		f.Add(data[:min(len(data), 8<<10)])
	}

	f.Add([]byte(rec("p") + "F:usr/bin\nR:tool\na:0:0:755\nZ:Q1abc=\nM:0:0:755\n\n"))
	f.Add([]byte("P:a\nV:1\nA:noarch\nF:../x\nR:/y\n\n\x00\xff\n"))
	f.Add([]byte("\n\n\nX\n:\n::\nF:\nR:\na:\nZ:\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, in []byte) {
		opts := apk.InstalledOptions{MaxPackages: 1000, MaxFiles: 1000, MaxBytes: 1 << 20}

		for _, skip := range []bool{false, true} {
			opts.SkipFiles = skip

			db := apk.NewInstalledDB(bytes.NewReader(in), int64(len(in)), opts)

			for p, err := range db.Packages(context.Background()) {
				if err != nil {
					break
				}

				if p.Name == "" || p.Version == "" || p.Arch == "" {
					t.Fatalf("package without an identity: %+v", p)
				}

				for _, file := range p.Files {
					if strings.HasPrefix(file.Path, "/") || slices.Contains(strings.Split(file.Path, "/"), "..") {
						t.Fatalf("path outside the root: %q", file.Path)
					}
				}
			}
		}

		db := apk.NewInstalledDB(bytes.NewReader(in), int64(len(in)), opts)
		_, _ = db.InstalledNames(context.Background())
		_, _ = db.InstalledProvides(context.Background())
	})
}
