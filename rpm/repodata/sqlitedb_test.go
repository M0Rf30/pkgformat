package repodata

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

var sqliteKinds = []struct {
	name string
	kind DocKind
}{
	{"primary", DocPrimary},
	{"filelists", DocFilelists},
	{"other", DocOther},
}

// refRepo is the repodata createrepo_c --database wrote for the corpus
// (testdata/sqlitedb/generate.sh).
const refRepo = "testdata/sqlitedb/repo"

func readGzFile(t testing.TB, path string) []byte {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func sqliteFileSHA256(t testing.TB, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// refCorpus returns the corpus in the order of the reference primary.xml, and
// the options that give each package the location createrepo_c used.
func refCorpus(t testing.TB) ([]rpm.Package, SQLiteOptions) {
	t.Helper()

	pkgs := orderLike(t, loadCorpus(t), string(readGzFile(t, filepath.Join(refRepo, "primary.xml.gz"))))

	return pkgs, SQLiteOptions{
		Location: func(p *rpm.Package) Location {
			return Location{Href: "Packages/" + corpusFile[p.SHA256]}
		},
	}
}

// refOpts returns opts with the checksum of the reference XML document of the
// kind, which createrepo_c records in the database.
func refOpts(t testing.TB, opts SQLiteOptions, name string) SQLiteOptions {
	t.Helper()

	opts.XMLChecksum = sqliteFileSHA256(t, filepath.Join(refRepo, name+".xml.gz"))

	return opts
}

func buildSQLiteBytes(t testing.TB, kind DocKind, pkgs []rpm.Package, opts SQLiteOptions) []byte {
	t.Helper()

	var buf bytes.Buffer
	if err := WriteSQLite(&buf, kind, pkgs, opts); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func writeTemp(t testing.TB, name string, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func rawDB(t testing.TB, path string) *sql.DB {
	t.Helper()

	u := url.URL{Scheme: "file", Path: path}

	db, err := sql.Open("sqlite", u.String()+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = db.Close() })

	return db
}

// schemaOf returns the statements that create the objects of a database, one
// per line with the terminating semicolon, as `sqlite3 .schema` prints them.
func schemaOf(t testing.TB, path string) string {
	t.Helper()

	rows, err := rawDB(t, path).Query("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY rowid")
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = rows.Close() }()

	var b strings.Builder

	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}

		b.WriteString(s + ";\n")
	}

	return b.String()
}

// dumpTables returns, per table, its rows rendered with quote() (so the type
// of every value shows) and sorted: rowids and the order of rows that share a
// table are not part of a database's content.
func dumpTables(t testing.TB, path string) map[string][]string {
	t.Helper()

	db := rawDB(t, path)

	tables, err := db.Query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}

	var names []string

	for tables.Next() {
		var n string
		if err := tables.Scan(&n); err != nil {
			t.Fatal(err)
		}

		names = append(names, n)
	}

	_ = tables.Close()

	out := make(map[string][]string)

	for _, n := range names {
		cols, err := db.Query("SELECT name FROM pragma_table_info('" + n + "')")
		if err != nil {
			t.Fatal(err)
		}

		var exprs []string

		for cols.Next() {
			var c string
			if err := cols.Scan(&c); err != nil {
				t.Fatal(err)
			}

			exprs = append(exprs, "quote("+c+")")
		}

		_ = cols.Close()

		rows, err := db.Query("SELECT " + strings.Join(exprs, " || '|' || ") + " FROM " + n)
		if err != nil {
			t.Fatal(err)
		}

		lines := []string{}

		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}

			lines = append(lines, s)
		}

		_ = rows.Close()

		sort.Strings(lines)
		out[n] = lines
	}

	return out
}

func compareDumps(t *testing.T, want, got map[string][]string, what string) {
	t.Helper()

	for table, w := range want {
		g := got[table]
		if reflect.DeepEqual(w, g) {
			continue
		}

		t.Errorf("%s: table %s differs: %d rows, want %d", what, table, len(g), len(w))

		set := make(map[string]int, len(w))
		for _, r := range w {
			set[r]++
		}

		shown := 0

		for _, r := range g {
			if set[r] > 0 {
				set[r]--

				continue
			}

			if shown++; shown <= 3 {
				t.Errorf("  extra row: %.300s", r)
			}
		}

		for r, n := range set {
			if n > 0 && shown < 6 {
				shown++
				t.Errorf("  missing row: %.300s", r)
			}
		}
	}

	if len(want) != len(got) {
		t.Errorf("%s: %d tables, want %d", what, len(got), len(want))
	}
}

// TestSQLiteSchemaMatchesCreaterepo compares the statements stored in the
// databases with those of the databases createrepo_c wrote, which are
// committed as `sqlite3 .schema` output.
func TestSQLiteSchemaMatchesCreaterepo(t *testing.T) {
	pkgs, opts := refCorpus(t)

	for _, tc := range sqliteKinds {
		t.Run(tc.name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", "sqlitedb", "schema", tc.name+".schema"))
			if err != nil {
				t.Fatal(err)
			}

			got := schemaOf(t, writeTemp(t, tc.name+".sqlite", buildSQLiteBytes(t, tc.kind, pkgs, opts)))
			if got != string(want) {
				t.Errorf("schema differs from createrepo_c\ngot:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

// TestSQLiteRowsMatchCreaterepo compares the content of the databases written
// for the corpus with createrepo_c's: every table, row by row with the type of
// each value, db_info included. The one documented difference is the order of
// the rows, which the comparison sorts away: createrepo_c writes the
// directories of a filelist in hash order.
func TestSQLiteRowsMatchCreaterepo(t *testing.T) {
	pkgs, opts := refCorpus(t)

	for _, tc := range sqliteKinds {
		t.Run(tc.name, func(t *testing.T) {
			ref := writeTemp(t, "ref.sqlite", readGzFile(t, filepath.Join(refRepo, tc.name+".sqlite.gz")))
			ours := writeTemp(t, "ours.sqlite", buildSQLiteBytes(t, tc.kind, pkgs, refOpts(t, opts, tc.name)))

			compareDumps(t, dumpTables(t, ref), dumpTables(t, ours), tc.name)
		})
	}
}

// TestSQLitePkgKeyIsInputOrder checks the key of a package is its position.
func TestSQLitePkgKeyIsInputOrder(t *testing.T) {
	pkgs, opts := refCorpus(t)

	for _, tc := range sqliteKinds {
		path := writeTemp(t, tc.name+".sqlite", buildSQLiteBytes(t, tc.kind, pkgs, opts))

		rows, err := rawDB(t, path).Query("SELECT pkgKey, pkgId FROM packages ORDER BY pkgKey")
		if err != nil {
			t.Fatal(err)
		}

		n := 0

		for rows.Next() {
			var (
				key int
				id  string
			)

			if err := rows.Scan(&key, &id); err != nil {
				t.Fatal(err)
			}

			if key != n+1 || id != pkgs[n].SHA256 {
				t.Fatalf("%s: row %d is key %d id %s, want key %d id %s", tc.name, n, key, id, n+1, pkgs[n].SHA256)
			}

			n++
		}

		_ = rows.Close()

		if n != len(pkgs) {
			t.Fatalf("%s: %d packages, want %d", tc.name, n, len(pkgs))
		}
	}
}

// TestSQLiteIntegrity has sqlite3 itself check the files.
func TestSQLiteIntegrity(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 is not installed")
	}

	pkgs, opts := refCorpus(t)

	for _, tc := range sqliteKinds {
		path := writeTemp(t, tc.name+".sqlite", buildSQLiteBytes(t, tc.kind, pkgs, opts))

		out, err := exec.Command("sqlite3", path, "PRAGMA integrity_check; PRAGMA foreign_key_check;").CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "ok" {
			t.Errorf("%s: sqlite3: %v\n%s", tc.name, err, out)
		}
	}
}

func TestDatabaseNames(t *testing.T) {
	for _, tc := range []struct {
		kind DocKind
		typ  string
		name string
	}{
		{DocPrimary, "primary_db", "primary.sqlite.zst"},
		{DocFilelists, "filelists_db", "filelists.sqlite.zst"},
		{DocOther, "other_db", "other.sqlite.zst"},
		{DocFilelistsExt, "", ""},
	} {
		if got := DatabaseType(tc.kind); got != tc.typ {
			t.Errorf("DatabaseType(%d) = %q, want %q", tc.kind, got, tc.typ)
		}

		if got := DatabaseFileName(tc.kind, Zstd); got != tc.name {
			t.Errorf("DatabaseFileName(%d) = %q, want %q", tc.kind, got, tc.name)
		}
	}

	if got := DatabaseFileName(DocPrimary, XZ); got != "primary.sqlite.xz" {
		t.Errorf("DatabaseFileName xz = %q", got)
	}
}

func TestWriteSQLiteRejectsKinds(t *testing.T) {
	err := WriteSQLite(io.Discard, DocFilelistsExt, nil, SQLiteOptions{})
	if !errors.Is(err, ErrDatabaseKind) {
		t.Errorf("filelists-ext: err = %v, want ErrDatabaseKind", err)
	}

	if _, err := CompressSQLite(Gzip, DocKind(99), nil, SQLiteOptions{}); !errors.Is(err, ErrDatabaseKind) {
		t.Errorf("kind 99: err = %v, want ErrDatabaseKind", err)
	}
}

func TestWriteSQLiteTempDirError(t *testing.T) {
	err := WriteSQLite(io.Discard, DocPrimary, nil, SQLiteOptions{TempDir: filepath.Join(t.TempDir(), "missing")})
	if err == nil {
		t.Fatal("a missing temporary directory must fail")
	}
}

type sqliteFailWriter struct{}

func (sqliteFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriteSQLiteWriterError(t *testing.T) {
	err := WriteSQLite(sqliteFailWriter{}, DocOther, nil, SQLiteOptions{})
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("err = %v, want io.ErrClosedPipe", err)
	}
}

// TestSQLiteEmptyRepository writes the three databases for no package.
func TestSQLiteEmptyRepository(t *testing.T) {
	for _, tc := range sqliteKinds {
		data := buildSQLiteBytes(t, tc.kind, nil, SQLiteOptions{})

		db, err := OpenSQLite(bytes.NewReader(data), SQLiteLimits{TempDir: t.TempDir()})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		if db.Kind() != tc.kind || db.Info() != (SQLiteInfo{Version: DatabaseVersion}) {
			t.Errorf("%s: kind %d info %+v", tc.name, db.Kind(), db.Info())
		}

		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// edgePackage exercises the rules of the primary columns that createrepo_c
// leaves NULL or empty, and the file and dependency encodings.
func edgePackage() rpm.Package {
	return rpm.Package{
		Name: "edge", Version: "1.0", Release: "2", Arch: "noarch", Epoch: 3,
		SHA256: "abc", BuildTime: 100, PackageSize: 5, InstalledSize: 6, ArchiveSize: 7,
		HeaderStart: 8, HeaderEnd: 9, Vendor: "", Summary: "s\x01\xffend",
		Requires: []rpm.Dependency{
			{Name: "rpmlib(PayloadIsZstd)", Flags: tag.RPMSENSE_RPMLIB | tag.RPMSENSE_LESS | tag.RPMSENSE_EQUAL, Version: "5.4.18-1"},
			{Name: "a", Flags: tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL, Version: "1.0-2", Epoch: 4},
			{Name: "b", Flags: tag.RPMSENSE_SCRIPT_PRE},
			{Name: "/etc/own"},
		},
		Provides:    []rpm.Dependency{{Name: "edge", Flags: tag.RPMSENSE_EQUAL, Version: "3:1.0-2"}},
		Obsoletes:   []rpm.Dependency{{Name: "old"}},
		Recommends:  []rpm.Dependency{{Name: "rec", Flags: tag.RPMSENSE_LESS, Version: "9"}},
		Suggests:    []rpm.Dependency{{Name: "sug"}},
		Supplements: []rpm.Dependency{{Name: "sup"}},
		Enhances:    []rpm.Dependency{{Name: "enh"}},
		Conflicts:   []rpm.Dependency{{Name: "con", Flags: tag.RPMSENSE_GREATER, Version: "1"}},
		Files: []rpm.FileEntry{
			{Path: "/etc/own"},
			{Path: "/etc/dir", Mode: 0o040755},
			{Path: "/etc/ghost", Flags: tag.RPMFILE_GHOST},
			{Path: "/usr/bin/tool"},
			{Path: "/usr/share/doc/edge/README"},
			{Path: "/usr/share/doc/edge/"},
			{Path: "/"},
			{Path: "relative"},
		},
		Changelogs: []rpm.ChangelogEntry{
			{Time: 30, Author: "c", Description: "third"},
			{Time: 20, Author: "b", Description: "second"},
			{Time: 10, Author: "a", Description: "first"},
		},
	}
}

func TestSQLiteEdgeRows(t *testing.T) {
	pkg := edgePackage()
	pkgs := []rpm.Package{pkg}

	path := writeTemp(t, "p.sqlite", buildSQLiteBytes(t, DocPrimary, pkgs, SQLiteOptions{Location: func(*rpm.Package) Location {
		return Location{Href: "x/p.rpm", Base: "http://b/"}
	}}))
	dump := dumpTables(t, path)

	want := map[string][]string{
		"db_info":  {"10|NULL"},
		"packages": {"1|'abc'|'edge'|'noarch'|'1.0'|'3'|'2'|'s\uFFFD\uFFFDend'|NULL|NULL|100|100|NULL|''|NULL|NULL|''|8|9|NULL|5|6|7|'x/p.rpm'|'http://b/'|'sha256'"},
		"requires": {
			"'a'|'GE'|'4'|'1.0'|'2'|1|'FALSE'",
			"'b'|NULL|NULL|NULL|NULL|1|'TRUE'",
		},
		"provides":    {"'edge'|'EQ'|'0'|'3:1.0'|'2'|1"},
		"obsoletes":   {"'old'|NULL|NULL|NULL|NULL|1"},
		"recommends":  {"'rec'|'LT'|'0'|'9'|NULL|1"},
		"suggests":    {"'sug'|NULL|NULL|NULL|NULL|1"},
		"supplements": {"'sup'|NULL|NULL|NULL|NULL|1"},
		"enhances":    {"'enh'|NULL|NULL|NULL|NULL|1"},
		"conflicts":   {"'con'|'GT'|'0'|'1'|NULL|1"},
		"files":       {"'/etc/dir'|'dir'|1", "'/etc/ghost'|'ghost'|1", "'/etc/own'|'file'|1", "'/usr/bin/tool'|'file'|1"},
	}

	for table, rows := range want {
		if !reflect.DeepEqual(dump[table], rows) {
			t.Errorf("primary %s = %q, want %q", table, dump[table], rows)
		}
	}

	files := dumpTables(t, writeTemp(t, "f.sqlite", buildSQLiteBytes(t, DocFilelists, pkgs, SQLiteOptions{})))["filelist"]
	wantFiles := []string{
		"1|'.'|'relative'|'f'",
		"1|'/'|'/'|'f'",
		"1|'/etc'|'own/dir/ghost'|'fdg'",
		"1|'/usr/bin'|'tool'|'f'",
		"1|'/usr/share/doc/edge'|'README//'|'ff'",
	}

	if !reflect.DeepEqual(files, wantFiles) {
		t.Errorf("filelist = %q, want %q", files, wantFiles)
	}

	other := dumpTables(t, writeTemp(t, "o.sqlite", buildSQLiteBytes(t, DocOther, pkgs, SQLiteOptions{ChangelogLimit: 2})))["changelog"]
	wantOther := []string{"1|'b'|20|'second'", "1|'c'|30|'third'"}

	if !reflect.DeepEqual(other, wantOther) {
		t.Errorf("changelog = %q, want %q", other, wantOther)
	}

	all := dumpTables(t, writeTemp(t, "o.sqlite", buildSQLiteBytes(t, DocOther, pkgs, SQLiteOptions{ChangelogLimit: -1})))["changelog"]
	if len(all) != 3 {
		t.Errorf("unlimited changelog kept %d entries, want 3", len(all))
	}

	def := dumpTables(t, writeTemp(t, "o.sqlite", buildSQLiteBytes(t, DocOther, pkgs, SQLiteOptions{})))["changelog"]
	if len(def) != 3 {
		t.Errorf("default changelog kept %d entries, want 3", len(def))
	}
}

func TestGroupByDirectory(t *testing.T) {
	groups := groupByDirectory([]rpm.FileEntry{
		{Path: "/a/b"}, {Path: "/a/c", Mode: 0o040000}, {Path: "/d"}, {Path: "/a/g", Flags: tag.RPMFILE_GHOST}, {Path: "x"},
	})

	var got []string
	for _, g := range groups {
		got = append(got, g.dir+"="+g.names.String()+":"+g.types.String())
	}

	want := []string{"/a=b/c/g:fdg", "/=d:f", ".=x:f"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("groups = %q, want %q", got, want)
	}
}

func TestCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"plain":         "plain",
		"tab\tnl\ncr":   "tab\tnl\ncr",
		"\x00a":         "\uFFFDa",
		"\xc3\x28":      "\uFFFD(",
		"ok \U0001F600": "ok \U0001F600",
		"\uFFFE":        "\uFFFD",
	} {
		if got := text(in); got != want {
			t.Errorf("text(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCompressSQLiteEntries compresses the three databases with each
// compression and checks the repomd.xml entries and that the files read back.
func TestCompressSQLiteEntries(t *testing.T) {
	pkgs, _ := refCorpus(t)

	for _, c := range []Compression{Gzip, Zstd, XZ} {
		var entries []RepomdData

		for _, tc := range sqliteKinds {
			xmlDoc, err := CompressMetadataStream(c, func(w io.Writer) error {
				return writeDocument(w, tc.kind, pkgs)
			})
			if err != nil {
				t.Fatal(err)
			}

			cm, err := CompressSQLite(c, tc.kind, pkgs, SQLiteOptions{XMLChecksum: xmlDoc.SHA256})
			if err != nil {
				t.Fatal(err)
			}

			name := DatabaseFileName(tc.kind, c)
			e := DatabaseEntry(cm, tc.kind, name, 7)

			if e.Type != tc.name+"_db" || e.Location != "repodata/"+name || e.DatabaseVersion != DatabaseVersion ||
				e.Checksum != cm.SHA256 || e.OpenChecksum != cm.OpenSHA256 || e.Timestamp != 7 || e.OpenSize != cm.OpenSize {
				t.Errorf("%v %s: entry %+v", c, tc.name, e)
			}

			entries = append(entries, e)

			rc, err := OpenMetadata(io.NopCloser(bytes.NewReader(cm.Data)), name, 0)
			if err != nil {
				t.Fatal(err)
			}

			db, err := OpenSQLite(rc, SQLiteLimits{TempDir: t.TempDir()})
			if err != nil {
				t.Fatalf("%v %s: %v", c, tc.name, err)
			}

			if db.Kind() != tc.kind || db.Info().Checksum != xmlDoc.SHA256 {
				t.Errorf("%v %s: kind %d info %+v", c, tc.name, db.Kind(), db.Info())
			}

			_ = db.Close()
			_ = rc.Close()
		}

		doc, err := GenerateRepomdXML("1", entries)
		if err != nil {
			t.Fatal(err)
		}

		if got := strings.Count(string(doc), "<database_version>10</database_version>"); got != 3 {
			t.Errorf("%v: repomd.xml has %d database_version, want 3", c, got)
		}

		m, err := ParseRepomd(bytes.NewReader(doc))
		if err != nil {
			t.Fatal(err)
		}

		for _, tc := range sqliteKinds {
			if d, ok := m.Find(tc.name + "_db"); !ok || d.DatabaseVersion != DatabaseVersion {
				t.Errorf("%v: %s_db entry %+v", c, tc.name, d)
			}
		}
	}
}

// sqliteBuildRepo lays out a repository the way createrepo_c --simple-md-filenames
// does: the compressed XML documents, and with withDBs the databases, and the
// repomd.xml that lists them. It returns the checksum of each XML document.
func sqliteBuildRepo(t *testing.T, pkgs []rpm.Package, opts SQLiteOptions, withDBs bool) (string, map[string]string) {
	t.Helper()

	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "repodata"), 0o755); err != nil {
		t.Fatal(err)
	}

	var entries []RepomdData

	sums := make(map[string]string)

	for _, tc := range sqliteKinds {
		xmlDoc, err := CompressMetadataStream(Gzip, func(w io.Writer) error {
			d := NewDocWriter(w, tc.kind, len(pkgs))
			for i := range pkgs {
				d.PackageAt(&pkgs[i], opts.Location(&pkgs[i]))
			}

			return d.Close()
		})
		if err != nil {
			t.Fatal(err)
		}

		sums[tc.name] = xmlDoc.SHA256
		xmlName := tc.name + ".xml.gz"

		if err := os.WriteFile(filepath.Join(repo, "repodata", xmlName), xmlDoc.Data, 0o600); err != nil {
			t.Fatal(err)
		}

		entries = append(entries, xmlDoc.Entry(tc.name, xmlName, 1700000000))

		if !withDBs {
			continue
		}

		o := opts
		o.XMLChecksum = xmlDoc.SHA256

		dbDoc, err := CompressSQLite(Gzip, tc.kind, pkgs, o)
		if err != nil {
			t.Fatal(err)
		}

		dbName := DatabaseFileName(tc.kind, Gzip)
		if err := os.WriteFile(filepath.Join(repo, "repodata", dbName), dbDoc.Data, 0o600); err != nil {
			t.Fatal(err)
		}

		entries = append(entries, DatabaseEntry(dbDoc, tc.kind, dbName, 1700000000))
	}

	repomd, err := GenerateRepomdXML("1700000000", entries)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(repo, "repodata", "repomd.xml"), repomd, 0o600); err != nil {
		t.Fatal(err)
	}

	return repo, sums
}

// compareWithTool compares the databases of a repository createrepo_c's tools
// wrote with the ones this package writes for the same packages.
func compareWithTool(t *testing.T, repo string, sums map[string]string, pkgs []rpm.Package, opts SQLiteOptions, what string) {
	t.Helper()

	m, err := ParseRepomd(bytes.NewReader(mustRead(t, filepath.Join(repo, "repodata", "repomd.xml"))))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range sqliteKinds {
		d, ok := m.Find(tc.name + "_db")
		// sqliterepo_c leaves database_version out of repomd.xml.
		if !ok {
			t.Fatalf("%s: repomd.xml has no %s_db entry", what, tc.name)
		}

		theirs := writeTemp(t, "theirs.sqlite", readGzFile(t, filepath.Join(repo, filepath.FromSlash(d.Location))))

		o := opts
		o.XMLChecksum = sums[tc.name]
		ours := writeTemp(t, "ours.sqlite", buildSQLiteBytes(t, tc.kind, pkgs, o))

		compareDumps(t, dumpTables(t, theirs), dumpTables(t, ours), what+" "+tc.name)
	}
}

// TestSQLiteAcceptedByCreaterepoTools has createrepo_c's sqliterepo_c convert
// the XML this package writes, and compares its databases with ours: the same
// documents give the same databases.
func TestSQLiteAcceptedByCreaterepoTools(t *testing.T) {
	if _, err := exec.LookPath("sqliterepo_c"); err != nil {
		t.Skip("sqliterepo_c is not installed")
	}

	pkgs, opts := refCorpus(t)
	repo, sums := sqliteBuildRepo(t, pkgs, opts, false)

	if out, err := exec.Command("sqliterepo_c", "--compress-type=gz", repo).CombinedOutput(); err != nil {
		t.Fatalf("sqliterepo_c: %v\n%s", err, out)
	}

	compareWithTool(t, repo, sums, pkgs, opts, "sqliterepo_c")
}

// TestSQLiteRepositoryReadByCreaterepoTools gives sqliterepo_c a repository
// that already carries our databases: it must find them through repomd.xml
// and refuse to overwrite them, and --force must replace them with equal ones.
func TestSQLiteRepositoryReadByCreaterepoTools(t *testing.T) {
	if _, err := exec.LookPath("sqliterepo_c"); err != nil {
		t.Skip("sqliterepo_c is not installed")
	}

	pkgs, opts := refCorpus(t)
	repo, sums := sqliteBuildRepo(t, pkgs, opts, true)
	before := sqliteFileSHA256(t, filepath.Join(repo, "repodata", "primary.sqlite.gz"))

	out, err := exec.Command("sqliterepo_c", "--compress-type=gz", repo).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "already has sqlitedb present in repomd.xml") {
		t.Errorf("sqliterepo_c did not recognise the databases: %v\n%s", err, out)
	}

	if after := sqliteFileSHA256(t, filepath.Join(repo, "repodata", "primary.sqlite.gz")); after != before {
		t.Error("sqliterepo_c rewrote primary.sqlite.gz")
	}

	if out, err := exec.Command("sqliterepo_c", "--force", "--compress-type=gz", repo).CombinedOutput(); err != nil {
		t.Fatalf("sqliterepo_c --force: %v\n%s", err, out)
	}

	compareWithTool(t, repo, sums, pkgs, opts, "forced")
}

func mustRead(t testing.TB, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return data
}
