package repodata

import (
	"bytes"
	"database/sql"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

func openRef(t testing.TB, name string, lim SQLiteLimits) *SQLiteDB {
	t.Helper()

	lim.TempDir = t.TempDir()

	db, err := OpenSQLite(bytes.NewReader(readGzFile(t, filepath.Join(refRepo, name+".sqlite.gz"))), lim)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = db.Close() })

	return db
}

func readAllPrimary(t testing.TB, db *SQLiteDB) []PrimaryPackage {
	t.Helper()

	var out []PrimaryPackage

	err := db.Primary(func(p *PrimaryPackage) error {
		out = append(out, *p)

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// pathsOnly keeps the paths of the file entries: primary.xml does not tell
// directories from ghost files, the database does.
func pathsOnly(p PrimaryPackage) PrimaryPackage {
	files := make([]rpm.FileEntry, len(p.Files))
	for i, f := range p.Files {
		files[i] = rpm.FileEntry{Path: f.Path}
	}

	p.Files = files

	if len(files) == 0 {
		p.Files = nil
	}

	return p
}

// TestReadCreaterepoPrimaryDatabase reads the primary database createrepo_c
// wrote: the packages are those of its primary.xml, read by ReadPrimary.
func TestReadCreaterepoPrimaryDatabase(t *testing.T) {
	db := openRef(t, "primary", SQLiteLimits{})

	if db.Kind() != DocPrimary || db.Info().Version != DatabaseVersion {
		t.Fatalf("kind %d, info %+v", db.Kind(), db.Info())
	}

	if want := sqliteFileSHA256(t, filepath.Join(refRepo, "primary.xml.gz")); db.Info().Checksum != want {
		t.Errorf("db_info checksum %s, want the checksum of primary.xml.gz %s", db.Info().Checksum, want)
	}

	var want []PrimaryPackage

	err := ReadPrimary(bytes.NewReader(readGzFile(t, filepath.Join(refRepo, "primary.xml.gz"))), PrimaryLimits{},
		func(p *PrimaryPackage) error {
			want = append(want, *p)

			return nil
		})
	if err != nil {
		t.Fatal(err)
	}

	got := readAllPrimary(t, db)
	if len(got) != len(want) || len(got) == 0 {
		t.Fatalf("%d packages, primary.xml has %d", len(got), len(want))
	}

	for i := range want {
		if g := pathsOnly(got[i]); !reflect.DeepEqual(g, want[i]) {
			t.Errorf("package %d (%s) differs from primary.xml\ndatabase: %+v\nxml:      %+v", i, want[i].Name, g, want[i])
		}
	}
}

// TestReadCreaterepoFilelistsDatabase checks the file lists against the
// packages the corpus was built from: every path, with directories and ghost
// files marked.
func TestReadCreaterepoFilelistsDatabase(t *testing.T) {
	byID := make(map[string]rpm.Package)
	for _, p := range loadCorpus(t) {
		byID[p.SHA256] = p
	}

	n := 0

	err := openRef(t, "filelists", SQLiteLimits{}).Filelists(func(f *FilelistsPackage) error {
		n++

		p, ok := byID[f.PkgID]
		if !ok {
			t.Fatalf("unknown package %s", f.PkgID)
		}

		if got, want := fileSet(f.Files), fileSet(p.Files); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: files differ: %d, want %d", p.Name, len(got), len(want))
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if n != len(byID) {
		t.Errorf("%d packages, want %d", n, len(byID))
	}
}

// fileSet maps each path to its kind: "d", "g" or "f".
func fileSet(files []rpm.FileEntry) map[string]string {
	out := make(map[string]string, len(files))

	for _, f := range files {
		switch {
		case f.IsDir():
			out[f.Path] = "d"
		case f.IsGhost():
			out[f.Path] = "g"
		default:
			out[f.Path] = "f"
		}
	}

	return out
}

// TestReadCreaterepoOtherDatabase checks the changelogs against the corpus:
// the newest entries, newest first, with dates made distinct as the XML does.
func TestReadCreaterepoOtherDatabase(t *testing.T) {
	byID := make(map[string]rpm.Package)
	for _, p := range loadCorpus(t) {
		byID[p.SHA256] = p
	}

	n := 0

	err := openRef(t, "other", SQLiteLimits{}).Other(func(o *OtherPackage) error {
		n++

		p := byID[o.PkgID]

		keep := len(p.Changelogs)
		if keep > DefaultChangelogLimit {
			keep = DefaultChangelogLimit
		}

		if len(o.Changelogs) != keep {
			t.Fatalf("%s: %d entries, want %d", p.Name, len(o.Changelogs), keep)
		}

		for i, c := range o.Changelogs {
			w := p.Changelogs[i]
			if c.Author != text(w.Author) || c.Description != text(w.Description) || c.Time < w.Time {
				t.Errorf("%s: entry %d = %+v, want %+v", p.Name, i, c, w)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if n != len(byID) {
		t.Errorf("%d packages, want %d", n, len(byID))
	}
}

// TestSQLiteRoundTrip writes the databases for the corpus and reads them back:
// primary equals what ReadPrimary yields for the XML written from the same
// packages, and the file lists and changelogs equal the input.
func TestSQLiteRoundTrip(t *testing.T) {
	pkgs, opts := refCorpus(t)

	var xmlBuf bytes.Buffer

	d := NewDocWriter(&xmlBuf, DocPrimary, len(pkgs))
	for i := range pkgs {
		d.PackageAt(&pkgs[i], opts.Location(&pkgs[i]))
	}

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	var want []PrimaryPackage

	if err := ReadPrimary(&xmlBuf, PrimaryLimits{}, func(p *PrimaryPackage) error {
		want = append(want, *p)

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	open := func(kind DocKind) *SQLiteDB {
		db, err := OpenSQLite(bytes.NewReader(buildSQLiteBytes(t, kind, pkgs, opts)), SQLiteLimits{TempDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = db.Close() })

		return db
	}

	got := readAllPrimary(t, open(DocPrimary))
	if len(got) != len(want) {
		t.Fatalf("%d packages, want %d", len(got), len(want))
	}

	for i := range want {
		if g := pathsOnly(got[i]); !reflect.DeepEqual(g, want[i]) {
			t.Errorf("package %d (%s) differs\ndatabase: %+v\nxml:      %+v", i, want[i].Name, g, want[i])
		}
	}

	i := 0

	err := open(DocFilelists).Filelists(func(f *FilelistsPackage) error {
		if f.PkgID != pkgs[i].SHA256 || !reflect.DeepEqual(fileSet(f.Files), fileSet(pkgs[i].Files)) {
			t.Errorf("filelists of %s differ", pkgs[i].Name)
		}

		i++

		return nil
	})
	if err != nil || i != len(pkgs) {
		t.Fatalf("filelists: %d packages, err %v", i, err)
	}

	i = 0

	err = open(DocOther).Other(func(o *OtherPackage) error {
		p := pkgs[i]
		i++

		keep := min(len(p.Changelogs), DefaultChangelogLimit)

		if o.PkgID != p.SHA256 || len(o.Changelogs) != keep {
			t.Errorf("other of %s: %d entries, want %d", p.Name, len(o.Changelogs), keep)
		}

		return nil
	})
	if err != nil || i != len(pkgs) {
		t.Fatalf("other: %d packages, err %v", i, err)
	}
}

// TestSQLiteRoundTripEdges reads back the edge package: the dependency flags,
// the pre marker, an epoch, the root directory, and files without a directory.
func TestSQLiteRoundTripEdges(t *testing.T) {
	pkg := edgePackage()
	pkgs := []rpm.Package{pkg}

	open := func(kind DocKind) *SQLiteDB {
		db, err := OpenSQLite(bytes.NewReader(buildSQLiteBytes(t, kind, pkgs, SQLiteOptions{})), SQLiteLimits{TempDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = db.Close() })

		return db
	}

	got := readAllPrimary(t, open(DocPrimary))[0]

	if got.Name != "edge" || got.Epoch != 3 || got.Version != "1.0" || got.Release != "2" || got.SHA256 != "abc" ||
		got.Location != "Packages/edge-1.0-2.noarch.rpm" || got.Vendor != "" || got.Packager != "" {
		t.Errorf("package = %+v", got)
	}

	wantReq := []rpm.Dependency{
		{Name: "a", Flags: tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL, Version: "1.0-2", Epoch: 4},
		{Name: "b", Flags: tag.RPMSENSE_PREREQ},
	}

	if !reflect.DeepEqual(got.Requires, wantReq) {
		t.Errorf("requires = %+v, want %+v", got.Requires, wantReq)
	}

	if len(got.Provides) != 1 || got.Provides[0].Flags != tag.RPMSENSE_EQUAL || got.Provides[0].Version != "3:1.0-2" {
		t.Errorf("provides = %+v", got.Provides)
	}

	if len(got.Conflicts) != 1 || len(got.Obsoletes) != 1 || len(got.Recommends) != 1 || len(got.Suggests) != 1 ||
		len(got.Supplements) != 1 || len(got.Enhances) != 1 {
		t.Errorf("weak dependency lists: %+v", got)
	}

	wantFiles := map[string]string{
		"relative": "f", "/": "f", "/etc/own": "f", "/etc/dir": "d", "/etc/ghost": "g",
		"/usr/bin/tool": "f", "/usr/share/doc/edge/README": "f", "/usr/share/doc/edge/": "f",
	}

	err := open(DocFilelists).Filelists(func(f *FilelistsPackage) error {
		if g := fileSet(f.Files); !reflect.DeepEqual(g, wantFiles) {
			t.Errorf("files = %v, want %v", g, wantFiles)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	err = open(DocOther).Other(func(o *OtherPackage) error {
		want := []rpm.ChangelogEntry{
			{Time: 30, Author: "c", Description: "third"},
			{Time: 20, Author: "b", Description: "second"},
			{Time: 10, Author: "a", Description: "first"},
		}
		if !reflect.DeepEqual(o.Changelogs, want) {
			t.Errorf("changelogs = %+v, want %+v", o.Changelogs, want)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSplitFilenames(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a/b/c", []string{"a", "b", "c"}},
		{"/", []string{""}},
		{"a//", []string{"a", ""}},
		{"a///b", []string{"a", "", "b"}},
		{"a/", []string{"a"}},
	} {
		if got := splitFilenames(tc.in, 3); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("splitFilenames(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestJoinFilelistPath(t *testing.T) {
	for _, tc := range [][3]string{{".", "x", "x"}, {"", "x", "x"}, {"/", "x", "/x"}, {"/a", "x", "/a/x"}, {"/a", "", "/a/"}} {
		if got := joinFilelistPath(tc[0], tc[1]); got != tc[2] {
			t.Errorf("joinFilelistPath(%q, %q) = %q, want %q", tc[0], tc[1], got, tc[2])
		}
	}
}

func TestSenseFromFlagsInvertsSenseFlagsString(t *testing.T) {
	for _, f := range []rpm.Sense{
		tag.RPMSENSE_LESS, tag.RPMSENSE_GREATER, tag.RPMSENSE_EQUAL,
		tag.RPMSENSE_LESS | tag.RPMSENSE_EQUAL, tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL, 0,
	} {
		if got := senseFromFlags(rpm.SenseFlagsString(f)); got != f {
			t.Errorf("flags %#x round-trip to %#x", f, got)
		}
	}
}

func TestOpenSQLiteRejects(t *testing.T) {
	pkgs, opts := refCorpus(t)
	primary := buildSQLiteBytes(t, DocPrimary, pkgs, opts)

	t.Run("garbage", func(t *testing.T) {
		_, err := OpenSQLite(strings.NewReader("this is not a database at all"), SQLiteLimits{TempDir: t.TempDir()})
		if !errors.Is(err, ErrInvalidDatabase) {
			t.Errorf("err = %v, want ErrInvalidDatabase", err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		_, err := OpenSQLite(strings.NewReader(""), SQLiteLimits{TempDir: t.TempDir()})
		if !errors.Is(err, ErrInvalidDatabase) {
			t.Errorf("err = %v, want ErrInvalidDatabase", err)
		}
	})

	t.Run("too large", func(t *testing.T) {
		_, err := OpenSQLite(bytes.NewReader(primary), SQLiteLimits{MaxBytes: 1000, TempDir: t.TempDir()})
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("err = %v, want ErrTooLarge", err)
		}
	})

	t.Run("file too large", func(t *testing.T) {
		_, err := OpenSQLiteFile(writeTemp(t, "p.sqlite", primary), SQLiteLimits{MaxBytes: 1000})
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("err = %v, want ErrTooLarge", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := OpenSQLiteFile(filepath.Join(t.TempDir(), "nope.sqlite"), SQLiteLimits{}); err == nil {
			t.Error("a missing file must fail")
		}
	})

	t.Run("bad temp dir", func(t *testing.T) {
		if _, err := OpenSQLite(bytes.NewReader(primary), SQLiteLimits{TempDir: filepath.Join(t.TempDir(), "missing")}); err == nil {
			t.Error("a missing temporary directory must fail")
		}
	})

	t.Run("failing reader", func(t *testing.T) {
		_, err := OpenSQLite(io.MultiReader(bytes.NewReader(primary[:100]), errReader{}), SQLiteLimits{TempDir: t.TempDir()})
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("err = %v, want the reader's error", err)
		}
	})

	t.Run("version", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "old.sqlite")
		execAll(t, path,
			sqlDBInfo, sqlPackageIDs, sqlChangelog, "INSERT INTO db_info VALUES (9, 'x')")

		_, err := OpenSQLiteFile(path, SQLiteLimits{})
		if !errors.Is(err, ErrDatabaseVersion) {
			t.Errorf("err = %v, want ErrDatabaseVersion", err)
		}
	})

	t.Run("no db_info row", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.sqlite")
		execAll(t, path, sqlDBInfo, sqlPackageIDs, sqlChangelog)

		_, err := OpenSQLiteFile(path, SQLiteLimits{})
		if !errors.Is(err, ErrInvalidDatabase) {
			t.Errorf("err = %v, want ErrInvalidDatabase", err)
		}
	})

	t.Run("other schema", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "other.sqlite")
		execAll(t, path, "CREATE TABLE t (a)")

		_, err := OpenSQLiteFile(path, SQLiteLimits{})
		if !errors.Is(err, ErrInvalidDatabase) {
			t.Errorf("err = %v, want ErrInvalidDatabase", err)
		}
	})
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// execAll creates a database file and runs the statements on it.
func execAll(t *testing.T, path string, stmts ...string) {
	t.Helper()

	u := url.URL{Scheme: "file", Path: path}

	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()

	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func TestSQLiteWrongKind(t *testing.T) {
	pkgs, opts := refCorpus(t)

	db, err := OpenSQLite(bytes.NewReader(buildSQLiteBytes(t, DocFilelists, pkgs, opts)), SQLiteLimits{TempDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()

	if err := db.Primary(func(*PrimaryPackage) error { return nil }); !errors.Is(err, ErrDatabaseKind) {
		t.Errorf("Primary: %v", err)
	}

	if err := db.Other(func(*OtherPackage) error { return nil }); !errors.Is(err, ErrDatabaseKind) {
		t.Errorf("Other: %v", err)
	}

	if db.Kind() != DocFilelists {
		t.Errorf("kind = %d", db.Kind())
	}

	other, err := OpenSQLite(bytes.NewReader(buildSQLiteBytes(t, DocOther, pkgs, opts)), SQLiteLimits{TempDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = other.Close() }()

	if err := other.Filelists(func(*FilelistsPackage) error { return nil }); !errors.Is(err, ErrDatabaseKind) {
		t.Errorf("Filelists: %v", err)
	}
}

func TestSQLiteReadLimits(t *testing.T) {
	pkgs, opts := refCorpus(t)

	open := func(kind DocKind, lim SQLiteLimits) *SQLiteDB {
		lim.TempDir = t.TempDir()

		db, err := OpenSQLite(bytes.NewReader(buildSQLiteBytes(t, kind, pkgs, opts)), lim)
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = db.Close() })

		return db
	}

	primary := func(lim SQLiteLimits) error {
		return open(DocPrimary, lim).Primary(func(*PrimaryPackage) error { return nil })
	}

	for name, lim := range map[string]SQLiteLimits{
		"dependencies": {MaxDependencies: 2},
		"files":        {MaxFiles: 1},
		"file bytes":   {MaxFileBytes: 10},
		"field bytes":  {MaxFieldBytes: 10},
	} {
		if err := primary(lim); !errors.Is(err, ErrTooLarge) {
			t.Errorf("primary %s: err = %v, want ErrTooLarge", name, err)
		}
	}

	for name, lim := range map[string]SQLiteLimits{
		"files": {MaxFiles: 3}, "file bytes": {MaxFileBytes: 100}, "field bytes": {MaxFieldBytes: 20},
	} {
		err := open(DocFilelists, lim).Filelists(func(*FilelistsPackage) error { return nil })
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("filelists %s: err = %v, want ErrTooLarge", name, err)
		}
	}

	for name, lim := range map[string]SQLiteLimits{"changelogs": {MaxChangelogs: 1}, "field bytes": {MaxFieldBytes: 10}} {
		err := open(DocOther, lim).Other(func(*OtherPackage) error { return nil })
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("other %s: err = %v, want ErrTooLarge", name, err)
		}
	}

	stop := errors.New("stop")

	if err := open(DocPrimary, SQLiteLimits{}).Primary(func(*PrimaryPackage) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("Primary callback error = %v", err)
	}

	if err := open(DocFilelists, SQLiteLimits{}).Filelists(func(*FilelistsPackage) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("Filelists callback error = %v", err)
	}

	if err := open(DocOther, SQLiteLimits{}).Other(func(*OtherPackage) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("Other callback error = %v", err)
	}
}

// TestSQLiteReadSkipsMalformedRows mirrors ReadPrimary: a package without a
// name, or with a malformed number, is skipped.
func TestSQLiteReadSkipsMalformedRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sqlite")

	stmts := append([]string{}, sqlTables(DocPrimary)...)
	stmts = append(stmts,
		"INSERT INTO db_info VALUES (10, NULL)",
		"INSERT INTO packages (pkgId, name, arch, epoch, version, release) VALUES ('1', 'ok', 'noarch', '', '1', '1')",
		"INSERT INTO packages (pkgId, name, arch) VALUES ('2', '', 'noarch')",
		"INSERT INTO packages (pkgId, name, arch, epoch) VALUES ('3', 'badepoch', 'noarch', 'x')",
		"INSERT INTO packages (pkgId, name, arch, size_package) VALUES ('4', 'negative', 'noarch', -1)",
		"INSERT INTO packages (pkgId, name, arch) VALUES ('5', 'baddep', 'noarch')",
		"INSERT INTO requires (name, flags, epoch, pkgKey) VALUES ('r', 'EQ', 'x', 5)",
		"INSERT INTO packages (pkgId, name, arch) VALUES ('6', 'last', 'noarch')",
		"INSERT INTO requires (name, flags, epoch, version, release, pkgKey, pre) VALUES ('rpmlib(X)', 'LE', '0', '1', '2', 6, 'TRUE')",
	)
	execAll(t, path, stmts...)

	db, err := OpenSQLiteFile(path, SQLiteLimits{})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()

	var names []string

	err = db.Primary(func(p *PrimaryPackage) error {
		names = append(names, p.Name)

		if p.Name == "last" {
			want := rpm.Dependency{
				Name: "rpmlib(X)", Version: "1-2",
				Flags: tag.RPMSENSE_LESS | tag.RPMSENSE_EQUAL | tag.RPMSENSE_PREREQ | tag.RPMSENSE_RPMLIB,
			}
			if len(p.Requires) != 1 || p.Requires[0] != want {
				t.Errorf("requires = %+v, want %+v", p.Requires, want)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(names, []string{"ok", "last"}) {
		t.Errorf("packages = %q, want [ok last]", names)
	}
}

func TestSQLiteCloseRemovesSpool(t *testing.T) {
	dir := t.TempDir()
	pkgs, opts := refCorpus(t)

	db, err := OpenSQLite(bytes.NewReader(buildSQLiteBytes(t, DocOther, pkgs, opts)), SQLiteLimits{TempDir: dir})
	if err != nil {
		t.Fatal(err)
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d spooled files while open, want 1", len(entries))
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("%d files left after Close", len(entries))
	}

	// A rejected database leaves nothing behind either.
	if _, err := OpenSQLite(strings.NewReader("junk"), SQLiteLimits{TempDir: dir}); err == nil {
		t.Fatal("junk must fail")
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("%d files left after a failed open", len(entries))
	}
}

func TestWriteSQLiteLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()

	if err := WriteSQLite(io.Discard, DocPrimary, []rpm.Package{edgePackage()}, SQLiteOptions{TempDir: dir}); err != nil {
		t.Fatal(err)
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("%d files left in the temporary directory", len(entries))
	}
}
