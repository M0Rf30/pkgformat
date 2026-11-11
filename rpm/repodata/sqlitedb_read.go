package repodata

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/M0Rf30/pkgformat/internal/limitio"
	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// Default limits of [OpenSQLite].
const (
	// DefaultMaxDatabaseBytes bounds the size of a database; it is
	// [DefaultMaxDocument].
	DefaultMaxDatabaseBytes = DefaultMaxDocument
	// DefaultMaxChangelogs bounds the changelog entries of a package.
	DefaultMaxChangelogs = 10_000
)

// SQLiteInfo is the db_info table of a database.
type SQLiteInfo struct {
	// Version is the schema version, [DatabaseVersion] for every database
	// this package reads.
	Version int
	// Checksum is the checksum of the compressed XML document the database
	// was written with; empty when the database records none.
	Checksum string
}

// SQLiteLimits bounds [OpenSQLite] and what the readers of the database
// return. A zero field selects its default.
type SQLiteLimits struct {
	// MaxBytes bounds the size of the database; a larger one fails with
	// [ErrTooLarge]. Default [DefaultMaxDatabaseBytes].
	MaxBytes int64
	// TempDir is where [OpenSQLite] spools the database; the default is
	// os.TempDir.
	TempDir string
	// MaxDependencies, MaxFiles, MaxFileBytes and MaxFieldBytes bound each
	// package like the fields of [PrimaryLimits] do; exceeding one fails the
	// read with [ErrTooLarge]. MaxFiles and MaxFileBytes apply to the files of
	// both primary and filelists databases.
	MaxDependencies int
	MaxFiles        int
	MaxFileBytes    int
	MaxFieldBytes   int
	// MaxChangelogs bounds the changelog entries of a package. Default
	// [DefaultMaxChangelogs].
	MaxChangelogs int
}

func (l SQLiteLimits) normalized() SQLiteLimits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxDatabaseBytes
	}

	p := PrimaryLimits{
		MaxDependencies: l.MaxDependencies, MaxFiles: l.MaxFiles,
		MaxFileBytes: l.MaxFileBytes, MaxFieldBytes: l.MaxFieldBytes,
	}.normalized()
	l.MaxDependencies, l.MaxFiles, l.MaxFileBytes, l.MaxFieldBytes = p.MaxDependencies, p.MaxFiles, p.MaxFileBytes, p.MaxFieldBytes

	if l.MaxChangelogs <= 0 {
		l.MaxChangelogs = DefaultMaxChangelogs
	}

	return l
}

// FilelistsPackage is the file list of one package of a filelists database.
type FilelistsPackage struct {
	// PkgID is the checksum that identifies the package, the pkgid of
	// filelists.xml.
	PkgID string
	// Files holds the path of every file, and marks the directories (Mode)
	// and the ghost files (Flags).
	Files []rpm.FileEntry
}

// OtherPackage is the changelog of one package of an other database.
type OtherPackage struct {
	// PkgID is the checksum that identifies the package.
	PkgID string
	// Changelogs lists the entries newest first, the order of a header and of
	// [rpm.Package.Changelogs].
	Changelogs []rpm.ChangelogEntry
}

// SQLiteDB is an open primary, filelists or other database.
type SQLiteDB struct {
	db      *sql.DB
	kind    DocKind
	info    SQLiteInfo
	lim     SQLiteLimits
	cleanup func()
}

// OpenSQLite spools a decompressed database from r (see [OpenMetadata]) to a
// temporary file, at most [SQLiteLimits.MaxBytes] of it, and opens it. Close
// the result to remove the file.
func OpenSQLite(r io.Reader, lim SQLiteLimits) (*SQLiteDB, error) {
	lim = lim.normalized()

	f, err := os.CreateTemp(lim.TempDir, "repodata-*.sqlite")
	if err != nil {
		return nil, fmt.Errorf("repodata: spooling the database: %w", err)
	}

	path := f.Name()
	remove := func() { _ = os.Remove(path) }

	_, err = io.Copy(f, limitio.Capped(r, lim.MaxBytes+1, ErrTooLarge))
	if cerr := f.Close(); err == nil {
		err = cerr
	}

	if err != nil {
		remove()

		return nil, fmt.Errorf("repodata: spooling the database: %w", err)
	}

	d, err := openSQLiteFile(path, lim, true)
	if err != nil {
		remove()

		return nil, err
	}

	d.cleanup = remove

	return d, nil
}

// OpenSQLiteFile opens a decompressed database file that is not modified while
// it is open.
func OpenSQLiteFile(path string, lim SQLiteLimits) (*SQLiteDB, error) {
	lim = lim.normalized()

	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("repodata: opening the database: %w", err)
	}

	if st.Size() > lim.MaxBytes {
		return nil, fmt.Errorf("%w: the database is %d bytes, over %d", ErrTooLarge, st.Size(), lim.MaxBytes)
	}

	return openSQLiteFile(path, lim, false)
}

func openSQLiteFile(path string, lim SQLiteLimits, immutable bool) (*SQLiteDB, error) {
	extra := "mode=ro&_pragma=query_only(1)&_pragma=trusted_schema(0)"
	if immutable {
		extra += "&immutable=1"
	}

	db, err := sql.Open("sqlite", sqliteDSN(path, extra))
	if err != nil {
		return nil, fmt.Errorf("repodata: opening the database: %w", err)
	}

	// A read holds a connection while the nested queries of one package run.
	db.SetMaxOpenConns(4)

	d := &SQLiteDB{db: db, lim: lim}

	if err := d.probe(); err != nil {
		_ = db.Close()

		return nil, err
	}

	return d, nil
}

// probe tells which database it is and reads db_info.
func (d *SQLiteDB) probe() error {
	rows, err := d.db.Query("SELECT name FROM sqlite_master WHERE type = 'table'")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDatabase, err)
	}

	tables := make(map[string]bool)

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()

			return fmt.Errorf("%w: %w", ErrInvalidDatabase, err)
		}

		tables[name] = true
	}

	if err := rows.Close(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDatabase, err)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDatabase, err)
	}

	switch {
	case tables["db_info"] && tables["packages"] && tables["files"] && tables["requires"]:
		d.kind = DocPrimary
	case tables["db_info"] && tables["packages"] && tables["filelist"]:
		d.kind = DocFilelists
	case tables["db_info"] && tables["packages"] && tables["changelog"]:
		d.kind = DocOther
	default:
		return fmt.Errorf("%w: no primary, filelists or other tables", ErrInvalidDatabase)
	}

	var checksum sql.NullString

	err = d.db.QueryRow("SELECT dbversion, checksum FROM db_info LIMIT 1").Scan(&d.info.Version, &checksum)
	if err != nil {
		return fmt.Errorf("%w: db_info: %w", ErrInvalidDatabase, err)
	}

	d.info.Checksum = checksum.String

	if d.info.Version != DatabaseVersion {
		return fmt.Errorf("%w: %d, want %d", ErrDatabaseVersion, d.info.Version, DatabaseVersion)
	}

	return nil
}

// Kind returns which document the database is of: DocPrimary, DocFilelists or
// DocOther.
func (d *SQLiteDB) Kind() DocKind { return d.kind }

// Info returns the db_info of the database.
func (d *SQLiteDB) Info() SQLiteInfo { return d.info }

// Close closes the database and removes the file [OpenSQLite] spooled.
func (d *SQLiteDB) Close() error {
	err := d.db.Close()

	if d.cleanup != nil {
		d.cleanup()
	}

	return err
}

func (d *SQLiteDB) need(kind DocKind) error {
	if d.kind != kind {
		return fmt.Errorf("%w: the database is of kind %d, not %d", ErrDatabaseKind, int(d.kind), int(kind))
	}

	return nil
}

// invalid reports err as a malformed database, unless it is nil or a limit.
func invalid(err error) error {
	if err == nil || errors.Is(err, ErrTooLarge) {
		return err
	}

	return fmt.Errorf("%w: %w", ErrInvalidDatabase, err)
}

func (d *SQLiteDB) tooLong(s string) error {
	if len(s) > d.lim.MaxFieldBytes {
		return fmt.Errorf("%w: a text field of a package exceeds %d bytes", ErrTooLarge, d.lim.MaxFieldBytes)
	}

	return nil
}

// primaryRow is a row of the packages table of a primary database.
type primaryRow struct {
	key                                          int64
	pkgID, name, arch, version, epoch, release   sql.NullString
	summary, description, url                    sql.NullString
	timeFile, timeBuild                          sql.NullInt64
	license, vendor, group, buildHost, sourceRPM sql.NullString
	headerStart, headerEnd                       sql.NullInt64
	packager                                     sql.NullString
	sizePackage, sizeInstalled, sizeArchive      sql.NullInt64
	locationHref, locationBase, checksumType     sql.NullString
}

const sqlSelectPackages = "SELECT pkgKey, pkgId, name, arch, version, epoch, release, summary, description, url," +
	" time_file, time_build, rpm_license, rpm_vendor, rpm_group, rpm_buildhost, rpm_sourcerpm," +
	" rpm_header_start, rpm_header_end, rpm_packager, size_package, size_installed, size_archive," +
	" location_href, location_base, checksum_type FROM packages ORDER BY pkgKey"

// Primary calls fn for every package of a primary database in pkgKey order.
// Like [ReadPrimary], it skips a package without a name or an architecture
// and one with a malformed or negative number; a limit exceeded
// ([ErrTooLarge]) or an error of fn stops the read and is returned. The
// dependencies come with the filtering primary.xml applied.
func (d *SQLiteDB) Primary(fn func(*PrimaryPackage) error) error {
	if err := d.need(DocPrimary); err != nil {
		return err
	}

	stmts, err := d.prepareDeps()
	if err != nil {
		return err
	}

	defer stmts.close()

	rows, err := d.db.Query(sqlSelectPackages)
	if err != nil {
		return invalid(err)
	}

	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var r primaryRow

		err := rows.Scan(&r.key, &r.pkgID, &r.name, &r.arch, &r.version, &r.epoch, &r.release,
			&r.summary, &r.description, &r.url, &r.timeFile, &r.timeBuild,
			&r.license, &r.vendor, &r.group, &r.buildHost, &r.sourceRPM,
			&r.headerStart, &r.headerEnd, &r.packager, &r.sizePackage, &r.sizeInstalled, &r.sizeArchive,
			&r.locationHref, &r.locationBase, &r.checksumType)
		if err != nil {
			return invalid(err)
		}

		pkg, ok, err := d.primaryPackage(stmts, &r)
		if err != nil {
			return err
		}

		if !ok {
			continue
		}

		if err := fn(pkg); err != nil {
			return err
		}
	}

	return invalid(rows.Err())
}

func (d *SQLiteDB) primaryPackage(stmts *depStmts, r *primaryRow) (*PrimaryPackage, bool, error) {
	p := &PrimaryPackage{}
	p.Name = strings.TrimSpace(r.name.String)
	p.Arch = strings.TrimSpace(r.arch.String)
	p.Version = r.version.String
	p.Release = r.release.String
	p.Summary = r.summary.String
	p.Description = r.description.String
	p.URL = strings.TrimSpace(r.url.String)
	p.License = r.license.String
	p.Vendor = r.vendor.String
	p.Group = r.group.String
	p.BuildHost = r.buildHost.String
	p.SourceRPM = r.sourceRPM.String
	p.Packager = r.packager.String
	p.Location = r.locationHref.String
	p.Base = r.locationBase.String
	p.Checksum = strings.TrimSpace(r.pkgID.String)
	p.ChecksumType = r.checksumType.String

	for _, s := range []string{p.Summary, p.Description, p.License, p.Vendor, p.Group, p.BuildHost, p.SourceRPM, p.Packager, p.Location} {
		if err := d.tooLong(s); err != nil {
			return nil, false, err
		}
	}

	if strings.EqualFold(p.ChecksumType, "sha256") {
		p.SHA256 = p.Checksum
	}

	if p.Name == "" || p.Arch == "" {
		return nil, false, nil
	}

	if e := strings.TrimSpace(r.epoch.String); e != "" {
		n, err := strconv.ParseUint(e, 10, 32)
		if err != nil {
			return nil, false, nil //nolint:nilerr // a malformed number skips the package, as in ReadPrimary
		}

		p.Epoch = uint32(n)
	}

	nums := []struct {
		dst *int64
		src sql.NullInt64
	}{
		{&p.FileTime, r.timeFile}, {&p.BuildTime, r.timeBuild},
		{&p.HeaderStart, r.headerStart}, {&p.HeaderEnd, r.headerEnd},
		{&p.PackageSize, r.sizePackage}, {&p.InstalledSize, r.sizeInstalled}, {&p.ArchiveSize, r.sizeArchive},
	}

	for _, n := range nums {
		if n.src.Int64 < 0 {
			return nil, false, nil
		}

		*n.dst = n.src.Int64
	}

	lists := []*[]rpm.Dependency{&p.Requires, &p.Provides, &p.Conflicts, &p.Obsoletes, &p.Suggests, &p.Enhances, &p.Recommends, &p.Supplements}

	for i, dst := range lists {
		deps, ok, err := d.dependencies(stmts.byTable[depTables[i].name], r.key, depTables[i].name == "requires")
		if err != nil {
			return nil, false, err
		}

		if !ok {
			return nil, false, nil
		}

		*dst = deps
	}

	files, err := d.primaryFiles(stmts.files, r.key)
	if err != nil {
		return nil, false, err
	}

	p.Files = files

	return p, true, nil
}

// depSelectSQL reads the rows of a dependency table of one package; only
// requires has the pre column.
var depSelectSQL = map[string]string{
	"requires":    "SELECT name, flags, epoch, version, release, pre FROM requires WHERE pkgKey = ? ORDER BY rowid LIMIT ?",
	"provides":    "SELECT name, flags, epoch, version, release, 0 FROM provides WHERE pkgKey = ? ORDER BY rowid LIMIT ?",
	"conflicts":   "SELECT name, flags, epoch, version, release, 0 FROM conflicts WHERE pkgKey = ? ORDER BY rowid LIMIT ?",
	"obsoletes":   "SELECT name, flags, epoch, version, release, 0 FROM obsoletes WHERE pkgKey = ? ORDER BY rowid LIMIT ?",
	"suggests":    "SELECT name, flags, epoch, version, release, 0 FROM suggests WHERE pkgKey = ? ORDER BY rowid LIMIT ?",
	"enhances":    "SELECT name, flags, epoch, version, release, 0 FROM enhances WHERE pkgKey = ? ORDER BY rowid LIMIT ?",
	"recommends":  "SELECT name, flags, epoch, version, release, 0 FROM recommends WHERE pkgKey = ? ORDER BY rowid LIMIT ?",
	"supplements": "SELECT name, flags, epoch, version, release, 0 FROM supplements WHERE pkgKey = ? ORDER BY rowid LIMIT ?",
}

// depStmts are the prepared per-package queries of a primary read.
type depStmts struct {
	byTable map[string]*sql.Stmt
	files   *sql.Stmt
}

func (s *depStmts) close() {
	for _, st := range s.byTable {
		_ = st.Close()
	}

	if s.files != nil {
		_ = s.files.Close()
	}
}

func (d *SQLiteDB) prepareDeps() (*depStmts, error) {
	s := &depStmts{byTable: make(map[string]*sql.Stmt, len(depTables))}

	for _, t := range depTables {
		st, err := d.db.Prepare(depSelectSQL[t.name])
		if err != nil {
			s.close()

			return nil, invalid(err)
		}

		s.byTable[t.name] = st
	}

	st, err := d.db.Prepare("SELECT name, type FROM files WHERE pkgKey = ? ORDER BY rowid LIMIT ?")
	if err != nil {
		s.close()

		return nil, invalid(err)
	}

	s.files = st

	return s, nil
}

// dependencies reads the rows of one dependency table of a package. It
// reports false for a package with a malformed epoch.
func (d *SQLiteDB) dependencies(st *sql.Stmt, key int64, isRequires bool) ([]rpm.Dependency, bool, error) {
	rows, err := st.Query(key, d.lim.MaxDependencies+1)
	if err != nil {
		return nil, false, invalid(err)
	}

	defer func() { _ = rows.Close() }()

	var out []rpm.Dependency

	for rows.Next() {
		if len(out) >= d.lim.MaxDependencies {
			return nil, false, fmt.Errorf("%w: a dependency list of a package exceeds %d entries", ErrTooLarge, d.lim.MaxDependencies)
		}

		var name, flags, epoch, version, release, pre sql.NullString

		if err := rows.Scan(&name, &flags, &epoch, &version, &release, &pre); err != nil {
			return nil, false, invalid(err)
		}

		dep := rpm.Dependency{Name: name.String, Version: version.String}

		if release.String != "" {
			dep.Version += "-" + release.String
		}

		if e := epoch.String; e != "" {
			n, err := strconv.ParseUint(e, 10, 32)
			if err != nil {
				return nil, false, nil
			}

			dep.Epoch = uint32(n)
		}

		dep.Flags = senseFromFlags(flags.String)

		if isRequires && strings.EqualFold(pre.String, "TRUE") {
			dep.Flags |= tag.RPMSENSE_PREREQ
		}

		if strings.HasPrefix(dep.Name, "rpmlib(") {
			dep.Flags |= tag.RPMSENSE_RPMLIB
		}

		if err := d.tooLong(dep.Name); err != nil {
			return nil, false, err
		}

		out = append(out, dep)
	}

	if err := rows.Err(); err != nil {
		return nil, false, invalid(err)
	}

	return out, true, nil
}

// senseFromFlags is the inverse of [rpm.SenseFlagsString].
func senseFromFlags(s string) uint32 {
	switch s {
	case "LT":
		return tag.RPMSENSE_LESS
	case "GT":
		return tag.RPMSENSE_GREATER
	case "EQ":
		return tag.RPMSENSE_EQUAL
	case "LE":
		return tag.RPMSENSE_LESS | tag.RPMSENSE_EQUAL
	case "GE":
		return tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL
	default:
		return 0
	}
}

func (d *SQLiteDB) primaryFiles(st *sql.Stmt, key int64) ([]rpm.FileEntry, error) {
	rows, err := st.Query(key, d.lim.MaxFiles+1)
	if err != nil {
		return nil, invalid(err)
	}

	defer func() { _ = rows.Close() }()

	var (
		out   []rpm.FileEntry
		total int
	)

	for rows.Next() {
		var name, typ sql.NullString

		if err := rows.Scan(&name, &typ); err != nil {
			return nil, invalid(err)
		}

		total += len(name.String)
		if len(out) >= d.lim.MaxFiles || total > d.lim.MaxFileBytes {
			return nil, fmt.Errorf("%w: the file list of a package exceeds %d entries or %d bytes",
				ErrTooLarge, d.lim.MaxFiles, d.lim.MaxFileBytes)
		}

		if name.String == "" {
			continue
		}

		out = append(out, fileOfType(name.String, typ.String))
	}

	return out, invalid(rows.Err())
}

// fileOfType builds the entry of a file of the type a database stores: "dir",
// "ghost", or any other value for a plain file.
func fileOfType(path, typ string) rpm.FileEntry {
	f := rpm.FileEntry{Path: path}

	switch typ {
	case "dir", "d":
		f.Mode = 0o040000
	case "ghost", "g":
		f.Flags = tag.RPMFILE_GHOST
	}

	return f
}

// Filelists calls fn for every package of a filelists database in pkgKey
// order. A limit exceeded ([ErrTooLarge]) or an error of fn stops the read and
// is returned.
func (d *SQLiteDB) Filelists(fn func(*FilelistsPackage) error) error {
	if err := d.need(DocFilelists); err != nil {
		return err
	}

	list, err := d.db.Prepare("SELECT dirname, filenames, filetypes FROM filelist WHERE pkgKey = ? ORDER BY rowid")
	if err != nil {
		return invalid(err)
	}

	defer func() { _ = list.Close() }()

	return d.eachPackage(func(key int64, id string) error {
		files, err := d.packageFiles(list, key)
		if err != nil {
			return err
		}

		return fn(&FilelistsPackage{PkgID: id, Files: files})
	})
}

// eachPackage walks the packages table of a filelists or other database.
func (d *SQLiteDB) eachPackage(fn func(key int64, id string) error) error {
	rows, err := d.db.Query("SELECT pkgKey, pkgId FROM packages ORDER BY pkgKey")
	if err != nil {
		return invalid(err)
	}

	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			key int64
			id  sql.NullString
		)

		if err := rows.Scan(&key, &id); err != nil {
			return invalid(err)
		}

		if err := fn(key, strings.TrimSpace(id.String)); err != nil {
			return err
		}
	}

	return invalid(rows.Err())
}

func (d *SQLiteDB) packageFiles(st *sql.Stmt, key int64) ([]rpm.FileEntry, error) {
	rows, err := st.Query(key)
	if err != nil {
		return nil, invalid(err)
	}

	defer func() { _ = rows.Close() }()

	var (
		out   []rpm.FileEntry
		total int
	)

	for rows.Next() {
		var dir, names, types sql.NullString

		if err := rows.Scan(&dir, &names, &types); err != nil {
			return nil, invalid(err)
		}

		if err := d.tooLong(dir.String); err != nil {
			return nil, err
		}

		if err := d.tooLong(names.String); err != nil {
			return nil, err
		}

		for i, name := range splitFilenames(names.String, len(types.String)) {
			total += len(dir.String) + len(name) + 1
			if len(out) >= d.lim.MaxFiles || total > d.lim.MaxFileBytes {
				return nil, fmt.Errorf("%w: the file list of a package exceeds %d entries or %d bytes",
					ErrTooLarge, d.lim.MaxFiles, d.lim.MaxFileBytes)
			}

			typ := "f"
			if i < len(types.String) {
				typ = types.String[i : i+1]
			}

			out = append(out, fileOfType(joinFilelistPath(dir.String, name), typ))
		}
	}

	return out, invalid(rows.Err())
}

// splitFilenames splits the filenames column of a filelist row: the names are
// joined by '/', the root directory's empty name is written "/", and n is the
// number of names the filetypes column declares.
func splitFilenames(s string, n int) []string {
	if s == "" {
		return nil
	}

	out := make([]string, 0, max(n, 1))

	for {
		if strings.HasPrefix(s, "/") {
			// The empty name of the root directory.
			out = append(out, "")
			s = s[1:]
		} else {
			i := strings.IndexByte(s, '/')
			if i < 0 {
				return append(out, s)
			}

			out = append(out, s[:i])
			s = s[i:]
		}

		if s == "" {
			return out
		}

		// The separator before the next name.
		s = s[1:]

		if s == "" {
			return out
		}
	}
}

func joinFilelistPath(dir, name string) string {
	switch dir {
	case ".", "":
		return name
	case "/":
		return "/" + name
	default:
		return dir + "/" + name
	}
}

// Other calls fn for every package of an other database in pkgKey order. A
// limit exceeded ([ErrTooLarge]) or an error of fn stops the read and is
// returned.
func (d *SQLiteDB) Other(fn func(*OtherPackage) error) error {
	if err := d.need(DocOther); err != nil {
		return err
	}

	list, err := d.db.Prepare("SELECT author, date, changelog FROM changelog WHERE pkgKey = ? ORDER BY rowid LIMIT ?")
	if err != nil {
		return invalid(err)
	}

	defer func() { _ = list.Close() }()

	return d.eachPackage(func(key int64, id string) error {
		entries, err := d.changelogs(list, key)
		if err != nil {
			return err
		}

		return fn(&OtherPackage{PkgID: id, Changelogs: entries})
	})
}

func (d *SQLiteDB) changelogs(st *sql.Stmt, key int64) ([]rpm.ChangelogEntry, error) {
	rows, err := st.Query(key, d.lim.MaxChangelogs+1)
	if err != nil {
		return nil, invalid(err)
	}

	defer func() { _ = rows.Close() }()

	var out []rpm.ChangelogEntry

	for rows.Next() {
		if len(out) >= d.lim.MaxChangelogs {
			return nil, fmt.Errorf("%w: the changelog of a package exceeds %d entries", ErrTooLarge, d.lim.MaxChangelogs)
		}

		var (
			author, entry sql.NullString
			date          sql.NullInt64
		)

		if err := rows.Scan(&author, &date, &entry); err != nil {
			return nil, invalid(err)
		}

		if err := d.tooLong(author.String); err != nil {
			return nil, err
		}

		if err := d.tooLong(entry.String); err != nil {
			return nil, err
		}

		out = append(out, rpm.ChangelogEntry{Time: date.Int64, Author: author.String, Description: entry.String})
	}

	if err := rows.Err(); err != nil {
		return nil, invalid(err)
	}

	// The database stores the oldest entry first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}

	return out, nil
}
