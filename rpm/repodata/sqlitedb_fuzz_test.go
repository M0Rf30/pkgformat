package repodata

import (
	"bytes"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
)

// FuzzReadSQLite opens arbitrary bytes as a database and walks whatever it
// holds with small limits: the readers must fail cleanly, not panic or hang.
func FuzzReadSQLite(f *testing.F) {
	pkgs := []rpm.Package{edgePackage()}

	for _, kind := range []DocKind{DocPrimary, DocFilelists, DocOther} {
		var buf bytes.Buffer
		if err := WriteSQLite(&buf, kind, pkgs, SQLiteOptions{}); err != nil {
			f.Fatal(err)
		}

		f.Add(buf.Bytes())
	}

	f.Add([]byte("SQLite format 3\x00"))
	f.Add([]byte{})

	dir := f.TempDir()

	f.Fuzz(func(_ *testing.T, data []byte) {
		db, err := OpenSQLite(bytes.NewReader(data), SQLiteLimits{
			MaxBytes: 1 << 20, TempDir: dir,
			MaxDependencies: 20, MaxFiles: 20, MaxFileBytes: 1 << 10, MaxFieldBytes: 1 << 10, MaxChangelogs: 20,
		})
		if err != nil {
			return
		}

		defer func() { _ = db.Close() }()

		_ = db.Primary(func(*PrimaryPackage) error { return nil })
		_ = db.Filelists(func(*FilelistsPackage) error { return nil })
		_ = db.Other(func(*OtherPackage) error { return nil })
	})
}

func FuzzSplitFilenames(f *testing.F) {
	for _, s := range []string{"", "a/b/c", "/", "a//", "a///b", "//", "a/"} {
		f.Add(s, 3)
	}

	f.Fuzz(func(t *testing.T, s string, n int) {
		names := splitFilenames(s, n%1024)

		// Joining the names back gives the column, up to the separators that
		// trail it.
		total := 0
		for _, name := range names {
			if strings.Contains(name, "/") {
				t.Fatalf("name %q contains a separator", name)
			}

			total += len(name)
		}

		if total > len(s) {
			t.Fatalf("names %q are longer than %q", names, s)
		}
	})
}

// FuzzWriteSQLite writes packages made of arbitrary strings and reads them
// back: the writer accepts any text, and the reader returns what it stored,
// cleaned of what XML cannot carry.
func FuzzWriteSQLite(f *testing.F) {
	f.Add("name", "1.0", "x86_64", "/etc/a/b", "summary \x00 \xff", "dep", "2-3")
	f.Add("", "", "", "/", "", "", "")

	dir := f.TempDir()

	f.Fuzz(func(t *testing.T, name, version, arch, file, summary, dep, depVersion string) {
		pkg := rpm.Package{
			Name: name, Version: version, Release: "1", Arch: arch, Summary: summary, SHA256: "id",
			Requires: []rpm.Dependency{{Name: dep, Flags: 4, Version: depVersion}},
			Files:    []rpm.FileEntry{{Path: file}},
			Changelogs: []rpm.ChangelogEntry{
				{Time: 2, Author: name, Description: summary}, {Time: 2, Author: arch, Description: file},
			},
		}

		for _, kind := range []DocKind{DocPrimary, DocFilelists, DocOther} {
			var buf bytes.Buffer
			if err := WriteSQLite(&buf, kind, []rpm.Package{pkg}, SQLiteOptions{TempDir: dir}); err != nil {
				t.Fatal(err)
			}

			db, err := OpenSQLite(&buf, SQLiteLimits{TempDir: dir})
			if err != nil {
				t.Fatal(err)
			}

			switch kind {
			case DocPrimary:
				err = db.Primary(func(p *PrimaryPackage) error {
					if p.Name != strings.TrimSpace(text(name)) || p.Summary != text(summary) {
						t.Errorf("read %q %q, wrote %q %q", p.Name, p.Summary, name, summary)
					}

					return nil
				})
			case DocFilelists:
				err = db.Filelists(func(*FilelistsPackage) error { return nil })
			default:
				err = db.Other(func(o *OtherPackage) error {
					if len(o.Changelogs) != 2 || o.Changelogs[0].Time != 3 || o.Changelogs[1].Time != 2 {
						t.Errorf("changelog = %+v", o.Changelogs)
					}

					return nil
				})
			}

			_ = db.Close()

			if err != nil {
				t.Fatalf("%v: %v", kind, err)
			}
		}
	})
}
