package deb_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

const statusFixture = "testdata/status/status"

func openFixture(t *testing.T, opts deb.StatusOptions) *deb.StatusDB {
	t.Helper()

	db, err := deb.OpenStatus(statusFixture, opts)
	require.NoError(t, err)

	t.Cleanup(func() { _ = db.Close() })

	return db
}

// expectedRow is one line of status.expected, which dpkg-query wrote.
type expectedRow struct {
	name, version, arch, abbrev, status, provides string
}

func readExpected(t *testing.T) []expectedRow {
	t.Helper()

	data, err := os.ReadFile("testdata/status/status.expected")
	require.NoError(t, err)

	var rows []expectedRow

	for line := range strings.SplitSeq(strings.TrimRight(string(data), "\n"), "\n") {
		f := strings.Split(line, "\t")
		require.Len(t, f, 6, line)
		rows = append(rows, expectedRow{f[0], f[1], f[2], f[3], f[4], f[5]})
	}

	return rows
}

// TestStatusMatchesDpkgQuery checks every package dpkg-query lists against
// the stanza the reader returns for it.
func TestStatusMatchesDpkgQuery(t *testing.T) {
	entries, err := openFixture(t, deb.StatusOptions{}).List(context.Background())
	require.NoError(t, err)

	byKey := make(map[string]*deb.StatusEntry, len(entries))
	for _, e := range entries {
		byKey[e.Package.Package+":"+e.Package.Architecture] = e
	}

	rows := readExpected(t)
	require.NotEmpty(t, rows)

	for _, row := range rows {
		e, ok := byKey[row.name+":"+row.arch]
		require.True(t, ok, "%s:%s", row.name, row.arch)

		assert.Equal(t, row.version, e.Package.Version, row.name)
		assert.Equal(t, row.status, e.Status.String(), row.name)
		assert.Equal(t, row.provides, e.Package.Provides, row.name)
		assert.Equal(t, row.status, e.Control.Get("Status"), row.name)
		assert.Equal(t, row.abbrev[1] == 'i', e.Status.Installed(), "%s %q", row.name, row.abbrev)
	}

	assert.Len(t, entries, len(rows), "every stanza of the fixture is a package dpkg-query lists")
}

func TestStatusFixtureStates(t *testing.T) {
	entries, err := openFixture(t, deb.StatusOptions{}).List(context.Background())
	require.NoError(t, err)

	states := map[string]deb.Status{}
	for _, e := range entries {
		states[e.Package.Package+":"+e.Package.Architecture] = e.Status
	}

	assert.Equal(t, deb.Status{Want: deb.WantHold, Flag: deb.FlagOK, State: deb.StateInstalled}, states["hello:amd64"])
	assert.Equal(t, deb.Status{Want: deb.WantInstall, Flag: deb.FlagOK, State: deb.StateUnpacked}, states["less:amd64"])
	assert.Equal(t, deb.Status{Want: deb.WantDeinstall, Flag: deb.FlagOK, State: deb.StateConfigFiles}, states["wget:amd64"])
	assert.Equal(t, deb.StateInstalled, states["libgcc-s1:i386"].State)
	assert.Equal(t, deb.StateInstalled, states["libgcc-s1:amd64"].State)
}

func TestStatusInstalledNames(t *testing.T) {
	db := openFixture(t, deb.StatusOptions{})

	names, err := db.InstalledNames(context.Background())
	require.NoError(t, err)

	var want []string

	for _, row := range readExpected(t) {
		if row.abbrev[1] == 'i' {
			want = append(want, row.name)
		}
	}

	assert.Equal(t, sortedUniq(want), names)
	assert.Contains(t, names, "hello", "a package on hold is installed")
	assert.Contains(t, names, "libgcc-s1", "the architectures of a name count once")
	assert.NotContains(t, names, "wget", "a removed package keeps its configuration files only")
	assert.NotContains(t, names, "less", "an unpacked package is not configured")

	for _, n := range names {
		assert.NotContains(t, n, ":", "names carry no architecture qualifier")
	}
}

func TestStatusInstalledProvides(t *testing.T) {
	db := openFixture(t, deb.StatusOptions{})

	provides, err := db.InstalledProvides(context.Background())
	require.NoError(t, err)

	want := map[string]bool{}

	for _, row := range readExpected(t) {
		if row.abbrev[1] != 'i' {
			continue
		}

		want[row.name] = true

		for p := range strings.SplitSeq(row.provides, ",") {
			p, _, _ = strings.Cut(strings.TrimSpace(p), " ")
			if p != "" {
				want[p] = true
			}
		}
	}

	assert.Len(t, provides, len(want))

	for _, p := range provides {
		assert.True(t, want[p], p)
	}

	assert.Contains(t, provides, "usr-is-merged", "provided by base-files")
	assert.Contains(t, provides, "apt-transport-https", "a versioned provide loses its constraint")
	assert.Contains(t, provides, "apt")
}

func sortedUniq(s []string) []string {
	m := map[string]bool{}
	for _, v := range s {
		m[v] = true
	}

	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}

	// insertion sort: the lists are short
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}

	return out
}

func TestParseStatus(t *testing.T) {
	good := map[string]deb.Status{
		"install ok installed":              {Want: deb.WantInstall, Flag: deb.FlagOK, State: deb.StateInstalled},
		"hold ok installed":                 {Want: deb.WantHold, Flag: deb.FlagOK, State: deb.StateInstalled},
		"deinstall ok config-files":         {Want: deb.WantDeinstall, Flag: deb.FlagOK, State: deb.StateConfigFiles},
		"purge ok not-installed":            {Want: deb.WantPurge, Flag: deb.FlagOK, State: deb.StateNotInstalled},
		"install reinstreq half-installed":  {Want: deb.WantInstall, Flag: deb.FlagReinstReq, State: deb.StateHalfInstalled},
		"install hold-reinstreq unpacked":   {Want: deb.WantInstall, Flag: deb.FlagHoldReinstReq, State: deb.StateUnpacked},
		"unknown ok half-configured":        {Want: deb.WantUnknown, Flag: deb.FlagOK, State: deb.StateHalfConfigured},
		"install ok triggers-awaited":       {Want: deb.WantInstall, Flag: deb.FlagOK, State: deb.StateTriggersAwaited},
		"  install   ok\ttriggers-pending ": {Want: deb.WantInstall, Flag: deb.FlagOK, State: deb.StateTriggersPending},
	}

	for in, want := range good {
		got, err := deb.ParseStatus(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
		assert.Equal(t, strings.Join(strings.Fields(in), " "), got.String())
	}

	for _, in := range []string{
		"", "install", "install ok", "install ok installed extra", "frobnicate ok installed",
		"install maybe installed", "install ok fine", strings.Repeat("x ", 100),
	} {
		_, err := deb.ParseStatus(in)
		require.ErrorIs(t, err, deb.ErrInvalidStatus, in)
	}

	assert.Empty(t, deb.Status{}.String())
	assert.False(t, deb.Status{}.Installed())
}

func TestInstalledSemantics(t *testing.T) {
	cases := map[string]bool{
		"install ok installed":             true,
		"hold ok installed":                true,
		"deinstall ok installed":           true,
		"install reinstreq installed":      true,
		"install ok unpacked":              false,
		"install ok half-configured":       false,
		"install reinstreq half-installed": false,
		"deinstall ok config-files":        false,
		"purge ok not-installed":           false,
		"install ok triggers-pending":      false,
		"install ok triggers-awaited":      false,
		"unknown ok not-installed":         false,
	}

	for in, want := range cases {
		st, err := deb.ParseStatus(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, st.Installed(), in)
	}
}

func statusDB(text string, opts deb.StatusOptions) *deb.StatusDB {
	return deb.NewStatusDB(strings.NewReader(text), int64(len(text)), opts)
}

func TestStatusEntriesLeniency(t *testing.T) {
	const text = "Package: a\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n" +
		"Description: first\n second\n .\n third\n\n" +
		"Status: install ok installed\nVersion: 2\n\n" + // no Package
		"Package: nostatus\nVersion: 1\n\n" +
		"Package: badstatus\nStatus: gibberish\nProvides: virt (= 1), other:any\n\n" +
		"Package: purged\nStatus: purge ok not-installed\n\n" +
		"junk line\n\n" +
		"Package: b\nStatus: install ok installed\nProvides: virt\n"

	var buf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	db := statusDB(text, deb.StatusOptions{Logger: logger})

	entries, err := db.List(context.Background())
	require.NoError(t, err)

	var names []string
	for _, e := range entries {
		names = append(names, e.Package.Package)
	}

	assert.Equal(t, []string{"a", "nostatus", "badstatus", "purged", "b"}, names)
	assert.Equal(t, "first\nsecond\n\nthird", entries[0].Package.Description)
	assert.Equal(t, "first\nsecond\n\nthird", entries[0].Control.Get("Description"))
	assert.Zero(t, entries[1].Status)
	assert.Zero(t, entries[2].Status)
	assert.Equal(t, deb.StateNotInstalled, entries[3].Status.State)
	assert.Empty(t, entries[3].Package.Version)
	assert.Contains(t, buf.String(), "without a Package")
	assert.Contains(t, buf.String(), "no valid Status")

	// Only a and b are installed; the others are in no list.
	n, err := db.InstalledNames(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, n)

	p, err := db.InstalledProvides(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "virt"}, p)
}

func TestStatusEntriesRoundTrip(t *testing.T) {
	data, err := os.ReadFile(statusFixture)
	require.NoError(t, err)

	entries, err := statusDB(string(data), deb.StatusOptions{}).List(context.Background())
	require.NoError(t, err)

	var out strings.Builder

	for _, e := range entries {
		out.WriteString(e.Control.String())
		out.WriteString("\n")
	}

	assert.Equal(t, string(data), out.String(), "the control files render the status file back")
}

func TestStatusEntriesEarlyStopAndCancel(t *testing.T) {
	db := openFixture(t, deb.StatusOptions{})

	n := 0

	for e, err := range db.Entries(context.Background()) {
		require.NoError(t, err)
		require.NotNil(t, e)

		if n++; n == 3 {
			break
		}
	}

	assert.Equal(t, 3, n)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	n = 0

	var last error

	for _, err := range db.Entries(ctx) {
		if err != nil {
			last = err

			break
		}

		if n++; n == 2 {
			cancel()
		}
	}

	require.ErrorIs(t, last, context.Canceled)
	assert.Equal(t, 2, n)

	_, err := db.InstalledNames(ctx)
	require.ErrorIs(t, err, context.Canceled)
	_, err = db.InstalledProvides(ctx)
	require.ErrorIs(t, err, context.Canceled)
	_, err = db.List(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestStatusLimits(t *testing.T) {
	text := strings.Repeat("Package: p\nStatus: install ok installed\n\n", 10)

	_, err := statusDB(text, deb.StatusOptions{MaxEntries: 9}).List(context.Background())
	require.ErrorIs(t, err, deb.ErrTooLarge)

	n, err := statusDB(text, deb.StatusOptions{MaxEntries: 10}).InstalledNames(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"p"}, n)

	// A reader that holds more than its size says is cut at MaxBytes.
	r := strings.NewReader(text)
	_, err = deb.NewStatusDB(r, int64(len(text)), deb.StatusOptions{MaxBytes: 100}).List(context.Background())
	require.ErrorIs(t, err, deb.ErrTooLarge)

	// The paragraph limit of the control parser applies too.
	big := "Package: p\nDescription: " + strings.Repeat("x\n y", 1) + "\n" + strings.Repeat(" "+strings.Repeat("z", 1<<20)+"\n", 17)
	_, err = statusDB(big, deb.StatusOptions{}).List(context.Background())
	require.ErrorIs(t, err, deb.ErrTooLarge)

	_, err = statusDB("Package: p\n"+strings.Repeat("x", deb.MaxLineBytes+1)+"\n", deb.StatusOptions{}).List(context.Background())
	require.ErrorIs(t, err, deb.ErrTooLarge)

	// A file over MaxBytes is refused at Open.
	_, err = deb.OpenStatus(statusFixture, deb.StatusOptions{MaxBytes: 1000})
	require.ErrorIs(t, err, deb.ErrTooLarge)
}

type errReaderAt struct{}

func (errReaderAt) ReadAt([]byte, int64) (int, error) { return 0, errors.New("disk on fire") }

func TestStatusReadError(t *testing.T) {
	_, err := deb.NewStatusDB(errReaderAt{}, 100, deb.StatusOptions{}).List(context.Background())
	require.ErrorContains(t, err, "disk on fire")
}

func TestOpenStatusErrors(t *testing.T) {
	_, err := deb.OpenStatus(filepath.Join(t.TempDir(), "missing"), deb.StatusOptions{})
	require.ErrorIs(t, err, fs.ErrNotExist)

	_, err = deb.OpenStatus(t.TempDir(), deb.StatusOptions{})
	require.ErrorIs(t, err, deb.ErrInvalidStatus)

	db := statusDB("", deb.StatusOptions{})
	require.NoError(t, db.Close(), "closing a database over a reader is a no-op")

	entries, err := db.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestFindStatus(t *testing.T) {
	root := t.TempDir()

	_, err := deb.FindStatus(root)
	require.ErrorIs(t, err, deb.ErrStatusNotFound)

	_, err = deb.FindStatus("")
	require.ErrorIs(t, err, deb.ErrStatusNotFound)

	dir := filepath.Join(root, "var/lib/dpkg")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "status"), 0o755))

	_, err = deb.FindStatus(root)
	require.ErrorIs(t, err, deb.ErrStatusNotFound, "a directory is no status file")

	require.NoError(t, os.Remove(filepath.Join(dir, "status")))

	data, err := os.ReadFile(statusFixture)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "status"), data, 0o644))

	path, err := deb.FindStatus(root)
	require.NoError(t, err)

	db, err := deb.OpenStatus(path, deb.StatusOptions{})
	require.NoError(t, err)

	defer db.Close()

	names, err := db.InstalledNames(context.Background())
	require.NoError(t, err)
	assert.Contains(t, names, "dpkg")
}

// TestFindStatusStaysInRoot checks that a link inside the root that points out
// of it is resolved inside the root, not on the host.
func TestFindStatusStaysInRoot(t *testing.T) {
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "status"), []byte("Package: evil\n"), 0o644))

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "var/lib"), 0o755))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "var/lib/dpkg")))

	_, err := deb.FindStatus(root)
	require.ErrorIs(t, err, deb.ErrStatusNotFound)
}

// infoFixture loads testdata/status/info as dpkg lays it out. Go module paths
// may not contain ":", so the fixtures store "name:arch" as "name%3Aarch".
func infoFixture(t *testing.T) fstest.MapFS {
	t.Helper()

	entries, err := os.ReadDir("testdata/status/info")
	require.NoError(t, err)

	fsys := fstest.MapFS{}

	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join("testdata/status/info", e.Name()))
		require.NoError(t, err)

		fsys[strings.ReplaceAll(e.Name(), "%3A", ":")] = &fstest.MapFile{Data: data}
	}

	return fsys
}

func TestReadInfoList(t *testing.T) {
	fsys := infoFixture(t)

	for _, c := range []struct{ name, arch, file string }{
		{"hello", "amd64", "hello"},
		{"hello", "", "hello"},
		{"libgcc-s1", "amd64", "libgcc-s1:amd64"},
		{"libgcc-s1", "i386", "libgcc-s1:i386"},
		{"libc6", "i386", "libc6:i386"},
		{"base-files", "amd64", "base-files"},
		{"wget", "amd64", "wget"},
	} {
		got, err := deb.ReadInfoList(fsys, c.name, c.arch, deb.StatusOptions{})
		require.NoError(t, err, c.file)

		data, err := fs.ReadFile(fsys, c.file+".expected")
		require.NoError(t, err)

		assert.Equal(t, strings.Split(strings.TrimRight(string(data), "\n"), "\n"), got, c.file)
	}

	_, err := deb.ReadInfoList(fsys, "absent", "amd64", deb.StatusOptions{})
	require.ErrorIs(t, err, fs.ErrNotExist)

	for _, bad := range [][2]string{{"", ""}, {"../x", ""}, {"a/b", ""}, {"a", "x/y"}, {"a\x00", ""}} {
		_, err = deb.ReadInfoList(fsys, bad[0], bad[1], deb.StatusOptions{})
		require.ErrorIs(t, err, deb.ErrInvalidStatus, "%q", bad)
	}
}

func TestReadInfoListLimits(t *testing.T) {
	fsys := fstest.MapFS{
		"big.list":   {Data: []byte(strings.Repeat("/usr/share/x\n", 100))},
		"long.list":  {Data: []byte("/" + strings.Repeat("a", deb.MaxLineBytes+1) + "\n")},
		"crlf.list":  {Data: []byte("/a\r\n\r\n/b\r\n")},
		"dir.list":   {Mode: fs.ModeDir},
		"empty.list": {},
	}

	_, err := deb.ReadInfoList(fsys, "big", "", deb.StatusOptions{MaxBytes: 50})
	require.ErrorIs(t, err, deb.ErrTooLarge)

	_, err = deb.ReadInfoList(fsys, "long", "", deb.StatusOptions{})
	require.ErrorIs(t, err, deb.ErrTooLarge)

	got, err := deb.ReadInfoList(fsys, "crlf", "", deb.StatusOptions{})
	require.NoError(t, err)
	assert.Equal(t, []string{"/a", "/b"}, got)

	got, err = deb.ReadInfoList(fsys, "empty", "", deb.StatusOptions{})
	require.NoError(t, err)
	assert.Empty(t, got)

	_, err = deb.ReadInfoList(fsys, "dir", "", deb.StatusOptions{})
	require.Error(t, err)
}

func TestParsePackageStillStrict(t *testing.T) {
	cf := parseControl(t, "Package: x\nVersion: 1\n")
	_, err := cf.ParsePackage()
	require.ErrorIs(t, err, deb.ErrMissingRequiredField)
}

// FuzzReadStatus feeds arbitrary text to the status reader.
func FuzzReadStatus(f *testing.F) {
	data, err := os.ReadFile(statusFixture)
	if err == nil {
		f.Add(data[:min(len(data), 8<<10)])
	}

	f.Add([]byte("Package: a\nStatus: install ok installed\nProvides: b (= 1), c:any\n\n"))
	f.Add([]byte("Status: install ok installed\n\nPackage:\n\n\x00\xff\n"))
	f.Add([]byte("Package: a\nStatus: purge ok not-installed\n a\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, in []byte) {
		db := deb.NewStatusDB(bytes.NewReader(in), int64(len(in)), deb.StatusOptions{MaxEntries: 1000, MaxBytes: 1 << 20})

		var installed []string

		for e, err := range db.Entries(context.Background()) {
			if err != nil {
				return
			}

			if e.Package.Package == "" || e.Control == nil {
				t.Fatalf("entry without a name: %+v", e)
			}

			if e.Status.Installed() {
				installed = append(installed, e.Package.Package)
			}
		}

		names, err := db.InstalledNames(context.Background())
		if err != nil {
			t.Fatalf("names failed where entries did not: %v", err)
		}

		if len(names) > len(installed) {
			t.Fatalf("%d names from %d installed entries", len(names), len(installed))
		}

		if _, err := db.InstalledProvides(context.Background()); err != nil {
			t.Fatalf("provides failed where entries did not: %v", err)
		}
	})
}

// FuzzParseStatus feeds arbitrary text to the Status field parser.
func FuzzParseStatus(f *testing.F) {
	f.Add("install ok installed")
	f.Add("a b c")
	f.Add("")

	f.Fuzz(func(t *testing.T, in string) {
		st, err := deb.ParseStatus(in)
		if err != nil {
			if !errors.Is(err, deb.ErrInvalidStatus) {
				t.Fatalf("untyped error: %v", err)
			}

			return
		}

		again, err := deb.ParseStatus(st.String())
		if err != nil || again != st {
			t.Fatalf("%q does not round-trip: %v %v", st.String(), again, err)
		}
	})
}

// FuzzReadInfoList feeds arbitrary text to the list file reader.
func FuzzReadInfoList(f *testing.F) {
	f.Add([]byte("/.\n/usr\n/usr/bin\n"), "pkg", "amd64")
	f.Add([]byte("\r\n\x00"), "p", "")

	f.Fuzz(func(t *testing.T, data []byte, name, arch string) {
		fsys := fstest.MapFS{
			name + ".list":              {Data: data},
			name + ":" + arch + ".list": {Data: data},
		}

		_, _ = deb.ReadInfoList(fsys, name, arch, deb.StatusOptions{MaxBytes: 1 << 20})
	})
}

func TestControlValueKeepsLeadingNewline(t *testing.T) {
	const text = "Package: p\nConffiles:\n /etc/a 0123\n /etc/b 4567\nDescription: d\n"

	cf := parseControl(t, text)
	assert.Equal(t, "\n/etc/a 0123\n/etc/b 4567", cf.Get("Conffiles"))
	assert.Equal(t, text, cf.String())
	assert.Equal(t, "d", cf.Get("Description"))
}
