package repodata

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	_ "modernc.org/sqlite" // CGO-free SQLite driver, also linked by rpm/rpmdb.

	"github.com/M0Rf30/pkgformat/rpm"
)

var (
	// ErrDatabaseKind means a SQLite database was asked for a document that
	// has none: only primary, filelists and other have one.
	ErrDatabaseKind = errors.New("repodata: no sqlite database for this document kind")
	// ErrInvalidDatabase means a file is not a primary, filelists or other
	// database in the createrepo_c layout.
	ErrInvalidDatabase = errors.New("repodata: not a repodata sqlite database")
	// ErrDatabaseVersion means a database has a schema version other than
	// [DatabaseVersion].
	ErrDatabaseVersion = errors.New("repodata: unsupported sqlite database version")
)

// SQLiteOptions tunes [WriteSQLite] and [CompressSQLite].
type SQLiteOptions struct {
	// XMLChecksum is the hex checksum of the compressed XML document the
	// database accompanies (the checksum of its repomd.xml data entry). It is
	// recorded in db_info, which clients compare with repomd.xml to tell
	// whether a database they hold is current. Empty records NULL.
	XMLChecksum string
	// Location gives the location a primary database lists a package under;
	// nil lists every package under [PackageLocation]. The other databases
	// ignore it.
	Location func(*rpm.Package) Location
	// ChangelogLimit is how many of the newest changelog entries of each
	// package an other database keeps: zero selects [DefaultChangelogLimit]
	// and a negative value keeps all of them.
	ChangelogLimit int
	// TempDir is where the database is assembled before it is copied out; the
	// default is os.TempDir.
	TempDir string
}

// DatabaseType returns the repomd.xml data type of the SQLite database of a
// document kind: "primary_db", "filelists_db" or "other_db"; empty for a kind
// that has none.
func DatabaseType(kind DocKind) string {
	switch kind {
	case DocPrimary:
		return "primary_db"
	case DocFilelists:
		return "filelists_db"
	case DocOther:
		return "other_db"
	default:
		return ""
	}
}

// DatabaseFileName returns the name createrepo_c gives the compressed
// database of a document kind: "primary.sqlite.gz", "filelists.sqlite.zst",
// and so on; empty for a kind that has none.
func DatabaseFileName(kind DocKind, c Compression) string {
	switch kind {
	case DocPrimary:
		return "primary.sqlite" + c.Extension()
	case DocFilelists:
		return "filelists.sqlite" + c.Extension()
	case DocOther:
		return "other.sqlite" + c.Extension()
	default:
		return ""
	}
}

// DatabaseEntry returns the repomd.xml data entry of a compressed database
// stored as repodata/<name>: [CompressedMetadata.Entry] typed by
// [DatabaseType] and carrying the [DatabaseVersion].
func DatabaseEntry(c *CompressedMetadata, kind DocKind, name string, timestamp int64) RepomdData {
	e := c.Entry(DatabaseType(kind), name, timestamp)
	e.DatabaseVersion = DatabaseVersion

	return e
}

// CompressSQLite builds the database of kind (DocPrimary, DocFilelists or
// DocOther) for packages and compresses it with c, like
// [CompressMetadataStream] does for an XML document.
func CompressSQLite(c Compression, kind DocKind, packages []rpm.Package, opts SQLiteOptions) (*CompressedMetadata, error) {
	return CompressMetadataStream(c, func(w io.Writer) error {
		return WriteSQLite(w, kind, packages, opts)
	})
}

// The schema of version 10, character for character as createrepo_c creates
// it: sqlite stores the text of each statement, and clients and tools compare
// it.
const (
	sqlDBInfo = "CREATE TABLE db_info (dbversion INTEGER, checksum TEXT)"

	sqlPackagesPrimary = "CREATE TABLE packages (" +
		"  pkgKey INTEGER PRIMARY KEY," +
		"  pkgId TEXT," +
		"  name TEXT," +
		"  arch TEXT," +
		"  version TEXT," +
		"  epoch TEXT," +
		"  release TEXT," +
		"  summary TEXT," +
		"  description TEXT," +
		"  url TEXT," +
		"  time_file INTEGER," +
		"  time_build INTEGER," +
		"  rpm_license TEXT," +
		"  rpm_vendor TEXT," +
		"  rpm_group TEXT," +
		"  rpm_buildhost TEXT," +
		"  rpm_sourcerpm TEXT," +
		"  rpm_header_start INTEGER," +
		"  rpm_header_end INTEGER," +
		"  rpm_packager TEXT," +
		"  size_package INTEGER," +
		"  size_installed INTEGER," +
		"  size_archive INTEGER," +
		"  location_href TEXT," +
		"  location_base TEXT," +
		"  checksum_type TEXT)"

	sqlFiles = "CREATE TABLE files (  name TEXT,  type TEXT,  pkgKey INTEGER)"

	sqlPackageIDs = "CREATE TABLE packages (  pkgKey INTEGER PRIMARY KEY,  pkgId TEXT)"

	sqlFilelist = "CREATE TABLE filelist (  pkgKey INTEGER,  dirname TEXT,  filenames TEXT,  filetypes TEXT)"

	sqlChangelog = "CREATE TABLE changelog (  pkgKey INTEGER,  author TEXT,  date INTEGER,  changelog TEXT)"

	sqlTriggerRemovals = "CREATE TRIGGER removals AFTER DELETE ON packages" +
		"  BEGIN" +
		"    DELETE FROM files WHERE pkgKey = old.pkgKey;" +
		"    DELETE FROM requires WHERE pkgKey = old.pkgKey;" +
		"    DELETE FROM provides WHERE pkgKey = old.pkgKey;" +
		"    DELETE FROM conflicts WHERE pkgKey = old.pkgKey;" +
		"    DELETE FROM obsoletes WHERE pkgKey = old.pkgKey;" +
		"    DELETE FROM suggests WHERE pkgKey = old.pkgKey;" +
		"    DELETE FROM enhances WHERE pkgKey = old.pkgKey;" +
		"    DELETE FROM recommends WHERE pkgKey = old.pkgKey;" +
		"    DELETE FROM supplements WHERE pkgKey = old.pkgKey;" +
		"  END;"

	sqlTriggerFilelist = "CREATE TRIGGER remove_filelist AFTER DELETE ON packages" +
		"  BEGIN" +
		"    DELETE FROM filelist WHERE pkgKey = old.pkgKey;" +
		"  END;"

	sqlTriggerChangelogs = "CREATE TRIGGER remove_changelogs AFTER DELETE ON packages" +
		"  BEGIN" +
		"    DELETE FROM changelog WHERE pkgKey = old.pkgKey;" +
		"  END;"

	sqlInsertDBInfo = "INSERT INTO db_info (dbversion, checksum) VALUES (?, ?)"

	sqlInsertPackage = "INSERT INTO packages (" +
		"  pkgId, name, arch, version, epoch, release, summary, description," +
		"  url, time_file, time_build, rpm_license, rpm_vendor, rpm_group," +
		"  rpm_buildhost, rpm_sourcerpm, rpm_header_start, rpm_header_end," +
		"  rpm_packager, size_package, size_installed, size_archive," +
		"  location_href, location_base, checksum_type) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?," +
		"  ?, ?, ?, ?, ?, ?, ?)"

	sqlInsertFile      = "INSERT INTO files (name, type, pkgKey) VALUES (?, ?, ?)"
	sqlInsertPackageID = "INSERT INTO packages (pkgId) VALUES (?)"
	sqlInsertFilelist  = "INSERT INTO filelist (pkgKey, dirname, filenames, filetypes)  VALUES (?, ?, ?, ?)"
	sqlInsertChangelog = "INSERT INTO changelog (pkgKey, author, date, changelog)  VALUES (?, ?, ?, ?)"
)

// depTables lists the dependency tables in the order createrepo_c creates
// them, with the part of the package each one holds.
var depTables = [...]struct {
	name string
	list func(*rpm.Package) []rpm.Dependency
}{
	{"requires", func(p *rpm.Package) []rpm.Dependency { return p.Requires }},
	{"provides", func(p *rpm.Package) []rpm.Dependency { return p.Provides }},
	{"conflicts", func(p *rpm.Package) []rpm.Dependency { return p.Conflicts }},
	{"obsoletes", func(p *rpm.Package) []rpm.Dependency { return p.Obsoletes }},
	{"suggests", func(p *rpm.Package) []rpm.Dependency { return p.Suggests }},
	{"enhances", func(p *rpm.Package) []rpm.Dependency { return p.Enhances }},
	{"recommends", func(p *rpm.Package) []rpm.Dependency { return p.Recommends }},
	{"supplements", func(p *rpm.Package) []rpm.Dependency { return p.Supplements }},
}

func depTableSQL(name string) string {
	pre := ""
	if name == "requires" {
		pre = ", pre BOOLEAN DEFAULT FALSE"
	}

	return "CREATE TABLE " + name + " (  name TEXT,  flags TEXT,  epoch TEXT,  version TEXT,  release TEXT,  pkgKey INTEGER " + pre + ")"
}

func depInsertSQL(name string) string {
	if name == "requires" {
		return "INSERT INTO requires (name, flags, epoch, version, release, pkgKey, pre) VALUES (?, ?, ?, ?, ?, ?, ?)"
	}

	return "INSERT INTO " + name + " (name, flags, epoch, version, release, pkgKey) VALUES (?, ?, ?, ?, ?, ?)"
}

// sqlIndexes returns the indexes createrepo_c adds when it closes a database
// of kind, in its order.
func sqlIndexes(kind DocKind) []string {
	switch kind {
	case DocPrimary:
		out := []string{
			"CREATE INDEX packagename ON packages (name)",
			"CREATE INDEX packageId ON packages (pkgId)",
			"CREATE INDEX filenames ON files (name)",
			"CREATE INDEX pkgfiles ON files (pkgKey)",
		}

		for i, d := range depTables {
			out = append(out, "CREATE INDEX pkg"+d.name+" on "+d.name+" (pkgKey)")

			if i < 2 {
				out = append(out, "CREATE INDEX "+d.name+"name ON "+d.name+" (name)")
			}
		}

		return out
	case DocFilelists:
		return []string{
			"CREATE INDEX keyfile ON filelist (pkgKey)",
			"CREATE INDEX pkgId ON packages (pkgId)",
			"CREATE INDEX dirnames ON filelist (dirname)",
		}
	default:
		return []string{
			"CREATE INDEX keychange ON changelog (pkgKey)",
			"CREATE INDEX pkgId ON packages (pkgId)",
		}
	}
}

// sqlTables returns the statements that create the tables and the trigger of
// a database of kind.
func sqlTables(kind DocKind) []string {
	switch kind {
	case DocPrimary:
		out := []string{sqlDBInfo, sqlPackagesPrimary, sqlFiles}
		for _, d := range depTables {
			out = append(out, depTableSQL(d.name))
		}

		return append(out, sqlTriggerRemovals)
	case DocFilelists:
		return []string{sqlDBInfo, sqlPackageIDs, sqlFilelist, sqlTriggerFilelist}
	default:
		return []string{sqlDBInfo, sqlPackageIDs, sqlChangelog, sqlTriggerChangelogs}
	}
}

// WriteSQLite writes the SQLite database of the given kind (DocPrimary,
// DocFilelists or DocOther) for packages to w, in the schema version 10 that
// createrepo_c --database writes and dnf reads: the same tables, columns,
// indexes and trigger, and the same rows, a package's pkgKey being its
// position in packages counted from 1. A primary database applies the
// filtering of [WritePrimaryXML] to the requirements, lists only the files
// primary.xml lists, and records the location and checksum of each package
// like it does. The rows of the filelist table follow the first appearance of
// a directory in the package rather than createrepo_c's hash order.
//
// The database is assembled in a temporary file, so memory use does not grow
// with the repository; w receives it once it is complete.
func WriteSQLite(w io.Writer, kind DocKind, packages []rpm.Package, opts SQLiteOptions) error {
	if DatabaseType(kind) == "" {
		return fmt.Errorf("%w: %d", ErrDatabaseKind, int(kind))
	}

	f, err := os.CreateTemp(opts.TempDir, "repodata-*.sqlite")
	if err != nil {
		return fmt.Errorf("repodata: creating the database: %w", err)
	}

	path := f.Name()

	defer func() { _ = os.Remove(path) }()

	if err := f.Close(); err != nil {
		return fmt.Errorf("repodata: creating the database: %w", err)
	}

	if err := buildSQLite(path, kind, packages, opts); err != nil {
		return err
	}

	out, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("repodata: reading the database: %w", err)
	}

	defer func() { _ = out.Close() }()

	if _, err := io.Copy(w, out); err != nil {
		return fmt.Errorf("repodata: writing the database: %w", err)
	}

	return nil
}

// sqliteDSN returns the data source name of a database file with the settings
// createrepo_c uses for a build: no waiting on the disk, journal and
// temporaries in memory.
func sqliteDSN(path string, extra string) string {
	u := url.URL{Scheme: "file", Path: path}

	return u.String() + "?" + extra
}

func buildSQLite(path string, kind DocKind, packages []rpm.Package, opts SQLiteOptions) (err error) {
	db, err := sql.Open("sqlite", sqliteDSN(path,
		"_pragma=synchronous(OFF)&_pragma=journal_mode(MEMORY)&_pragma=temp_store(MEMORY)"))
	if err != nil {
		return fmt.Errorf("repodata: opening the database: %w", err)
	}

	db.SetMaxOpenConns(1)

	defer func() {
		if cerr := db.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("repodata: closing the database: %w", cerr)
		}
	}()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("repodata: building the database: %w", err)
	}

	defer func() { _ = tx.Rollback() }()

	for _, stmt := range sqlTables(kind) {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("repodata: creating a table: %w", err)
		}
	}

	if err := fillSQLite(tx, kind, packages, opts); err != nil {
		return fmt.Errorf("repodata: filling the database: %w", err)
	}

	for _, stmt := range sqlIndexes(kind) {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("repodata: indexing the database: %w", err)
		}
	}

	var checksum any
	if opts.XMLChecksum != "" {
		checksum = opts.XMLChecksum
	}

	if _, err := tx.Exec(sqlInsertDBInfo, DatabaseVersion, checksum); err != nil {
		return fmt.Errorf("repodata: recording the database version: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("repodata: committing the database: %w", err)
	}

	return nil
}

// stmtSet prepares statements on a transaction and closes them together.
type stmtSet struct {
	tx    *sql.Tx
	stmts []*sql.Stmt
}

func (s *stmtSet) prepare(query string) (*sql.Stmt, error) {
	st, err := s.tx.Prepare(query)
	if err != nil {
		return nil, err
	}

	s.stmts = append(s.stmts, st)

	return st, nil
}

func (s *stmtSet) close() {
	for _, st := range s.stmts {
		_ = st.Close()
	}
}

func fillSQLite(tx *sql.Tx, kind DocKind, packages []rpm.Package, opts SQLiteOptions) error {
	set := &stmtSet{tx: tx}
	defer set.close()

	switch kind {
	case DocPrimary:
		return fillPrimary(set, packages, opts)
	case DocFilelists:
		return fillFilelists(set, packages)
	default:
		return fillOther(set, packages, opts)
	}
}

// nullable maps the empty string to NULL, as createrepo_c does for the
// columns it leaves unset when a header does not carry the value.
func nullable(s string) any {
	if s == "" {
		return nil
	}

	return text(s)
}

// text replaces what XML 1.0 cannot carry and what is not UTF-8 with
// U+FFFD, the way the xml writers do and createrepo_c does when it reads a
// header.
func text(s string) string {
	bad := false

	for i := 0; i < len(s); {
		c := s[i]
		if c >= 0x20 && c < utf8.RuneSelf {
			i++
			continue
		}

		r, width := utf8.DecodeRuneInString(s[i:])
		if !isXMLChar(r) || (r == utf8.RuneError && width == 1) {
			bad = true

			break
		}

		i += width
	}

	if !bad {
		return s
	}

	var b strings.Builder

	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])
		if !isXMLChar(r) || (r == utf8.RuneError && width == 1) {
			b.WriteRune(utf8.RuneError)
		} else {
			b.WriteString(s[i : i+width])
		}

		i += width
	}

	return b.String()
}

func fillPrimary(set *stmtSet, packages []rpm.Package, opts SQLiteOptions) error {
	pkgStmt, err := set.prepare(sqlInsertPackage)
	if err != nil {
		return err
	}

	fileStmt, err := set.prepare(sqlInsertFile)
	if err != nil {
		return err
	}

	depStmts := make([]*sql.Stmt, len(depTables))

	for i, d := range depTables {
		if depStmts[i], err = set.prepare(depInsertSQL(d.name)); err != nil {
			return err
		}
	}

	rf := newRequiresFilter()

	for i := range packages {
		p := &packages[i]

		loc := Location{Href: PackageLocation(p)}
		if opts.Location != nil {
			loc = opts.Location(p)
		}

		fileTime := p.FileTime
		if fileTime <= 0 {
			fileTime = p.BuildTime
		}

		res, err := pkgStmt.Exec(
			text(p.SHA256), text(p.Name), text(p.Arch), text(p.Version), strconv.FormatUint(uint64(p.Epoch), 10), text(p.Release),
			nullable(p.Summary), nullable(p.Description), nullable(p.URL), fileTime, p.BuildTime,
			nullable(p.License), text(p.Vendor), nullable(p.Group), nullable(p.BuildHost), text(p.SourceRPM),
			p.HeaderStart, p.HeaderEnd, nullable(p.Packager),
			p.PackageSize, p.InstalledSize, p.ArchiveSize,
			text(loc.Href), nullable(loc.Base), "sha256")
		if err != nil {
			return fmt.Errorf("package %s: %w", p.Name, err)
		}

		key, err := res.LastInsertId()
		if err != nil {
			return err
		}

		for j, d := range depTables {
			deps := d.list(p)
			if d.name == "requires" {
				deps = rf.filter(p)
			}

			if err := insertDeps(depStmts[j], key, deps, d.name == "requires"); err != nil {
				return fmt.Errorf("package %s: %s: %w", p.Name, d.name, err)
			}
		}

		for j := range p.Files {
			f := &p.Files[j]
			if !isPrimaryFile(f.Path) {
				continue
			}

			typ := "file"

			switch {
			case f.IsDir():
				typ = "dir"
			case f.IsGhost():
				typ = "ghost"
			}

			if _, err := fileStmt.Exec(text(f.Path), typ, key); err != nil {
				return fmt.Errorf("package %s: files: %w", p.Name, err)
			}
		}
	}

	return nil
}

func insertDeps(st *sql.Stmt, key int64, deps []rpm.Dependency, isRequires bool) error {
	for i := range deps {
		d := &deps[i]
		if isRequires && d.IsRPMLib() {
			continue
		}

		var flags, epoch, ver, rel any

		if f := rpm.SenseFlagsString(d.Flags); f != "" {
			flags = f
			epoch = strconv.FormatUint(uint64(d.Epoch), 10)
			v, r := rpm.SplitVersionRelease(d.Version)
			ver, rel = nullable(v), nullable(r)
		}

		args := []any{text(d.Name), flags, epoch, ver, rel, key}

		if isRequires {
			pre := "FALSE"
			if isPre(*d) {
				pre = "TRUE"
			}

			args = append(args, pre)
		}

		if _, err := st.Exec(args...); err != nil {
			return err
		}
	}

	return nil
}

// insertPackageID adds a row to the packages table of a filelists or other
// database and returns its pkgKey.
func insertPackageID(st *sql.Stmt, p *rpm.Package) (int64, error) {
	res, err := st.Exec(text(p.SHA256))
	if err != nil {
		return 0, fmt.Errorf("package %s: %w", p.Name, err)
	}

	return res.LastInsertId()
}

func fillFilelists(set *stmtSet, packages []rpm.Package) error {
	idStmt, err := set.prepare(sqlInsertPackageID)
	if err != nil {
		return err
	}

	listStmt, err := set.prepare(sqlInsertFilelist)
	if err != nil {
		return err
	}

	for i := range packages {
		p := &packages[i]

		key, err := insertPackageID(idStmt, p)
		if err != nil {
			return err
		}

		for _, d := range groupByDirectory(p.Files) {
			if _, err := listStmt.Exec(key, d.dir, d.names.String(), d.types.String()); err != nil {
				return fmt.Errorf("package %s: filelist: %w", p.Name, err)
			}
		}
	}

	return nil
}

// dirGroup is the files of one directory of a package, as a filelist row
// stores them: base names joined by '/', one type letter per name.
type dirGroup struct {
	dir   string
	names strings.Builder
	types strings.Builder
}

// groupByDirectory groups files by directory in order of first appearance.
// The directory is the path up to its last '/', without the trailing slashes
// (a lone "/" is kept, and the empty directory is ".").
func groupByDirectory(files []rpm.FileEntry) []*dirGroup {
	var (
		groups []*dirGroup
		index  = make(map[string]*dirGroup)
	)

	for i := range files {
		f := &files[i]
		dir, name := "", f.Path

		if j := strings.LastIndexByte(f.Path, '/'); j >= 0 { //nolint:modernize // CutLast is not in every supported toolchain
			dir, name = f.Path[:j+1], f.Path[j+1:]
		}

		g, ok := index[dir]
		if !ok {
			g = &dirGroup{dir: filelistDir(dir)}
			index[dir] = g
			groups = append(groups, g)
		}

		if g.names.Len() > 0 {
			g.names.WriteByte('/')
		}

		// The root directory has an empty name, written as "/".
		if name == "" {
			g.names.WriteByte('/')
		} else {
			g.names.WriteString(text(name))
		}

		switch {
		case f.IsDir():
			g.types.WriteByte('d')
		case f.IsGhost():
			g.types.WriteByte('g')
		default:
			g.types.WriteByte('f')
		}
	}

	return groups
}

func filelistDir(dir string) string {
	n := len(dir)
	for n > 1 && dir[n-1] == '/' {
		n--
	}

	if n == 0 {
		return "."
	}

	return text(dir[:n])
}

func fillOther(set *stmtSet, packages []rpm.Package, opts SQLiteOptions) error {
	idStmt, err := set.prepare(sqlInsertPackageID)
	if err != nil {
		return err
	}

	clStmt, err := set.prepare(sqlInsertChangelog)
	if err != nil {
		return err
	}

	limit := opts.ChangelogLimit
	if limit == 0 {
		limit = DefaultChangelogLimit
	}

	for i := range packages {
		p := &packages[i]

		key, err := insertPackageID(idStmt, p)
		if err != nil {
			return err
		}

		// A header lists the changelog newest first; the newest limit entries
		// are stored oldest first.
		n := len(p.Changelogs)
		if limit > 0 && n > limit {
			n = limit
		}

		// Entries sharing a date are told apart by a second, as in other.xml.
		prev := int64(-1)

		for j := n - 1; j >= 0; j-- {
			cl := &p.Changelogs[j]

			date := cl.Time
			if date <= prev {
				date = prev + 1
			}

			prev = date

			if _, err := clStmt.Exec(key, text(cl.Author), date, text(cl.Description)); err != nil {
				return fmt.Errorf("package %s: changelog: %w", p.Name, err)
			}
		}
	}

	return nil
}
