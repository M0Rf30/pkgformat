package rpmdb_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // the writer of these tests

	"github.com/M0Rf30/pkgformat/rpm/rpmdb"
)

// writer opens the database at path for writing, as rpm would. One connection
// only, so that a transaction stays on it.
func writer(t *testing.T, path string, pragmas ...string) *sql.DB {
	t.Helper()

	dsn := "file:" + path + "?_pragma=busy_timeout(5000)"
	for _, p := range pragmas {
		dsn += "&_pragma=" + p
	}

	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	// Connect now: changing the journal mode needs the file to itself.
	require.NoError(t, db.PingContext(t.Context()))

	return db
}

// listCount opens path and returns how many packages it lists.
func listCount(t *testing.T, path string, opts rpmdb.Options) int {
	t.Helper()

	db, err := rpmdb.Open(path, opts)
	require.NoError(t, err)

	defer db.Close()

	pkgs, err := db.List(t.Context())
	require.NoError(t, err)

	return len(pkgs)
}

// duplicateFirstPackage adds a committed record, a copy of the first one.
func duplicateFirstPackage(t *testing.T, w interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
},
) {
	t.Helper()

	_, err := w.ExecContext(t.Context(),
		"INSERT INTO Packages(hnum, blob) SELECT (SELECT max(hnum) FROM Packages) + 1, blob FROM Packages ORDER BY hnum LIMIT 1")
	require.NoError(t, err)
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}

	return names
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()

	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, data, 0o600))
}

// readOnlyDir makes dir unwritable until the test ends, and skips the test
// for a user to whom permissions mean nothing.
func readOnlyDir(t *testing.T, dir string) {
	t.Helper()

	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}

	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

func TestSQLiteLockedByExclusiveTransaction(t *testing.T) {
	for _, journal := range []string{"DELETE", "WAL"} {
		t.Run(journal, func(t *testing.T) {
			path := copyFixture(t, "rpmdb.sqlite")
			opts := rpmdb.Options{BusyTimeout: 20 * time.Millisecond, LockRetries: 1}

			w := writer(t, path, "journal_mode("+journal+")")
			want := listCount(t, path, opts)

			// An exclusive transaction of the writer, which in WAL mode also
			// takes the file for itself.
			conn, err := w.Conn(t.Context())
			require.NoError(t, err)

			if journal == "WAL" {
				_, err = conn.ExecContext(t.Context(), "PRAGMA locking_mode=EXCLUSIVE")
				require.NoError(t, err)
			}

			_, err = conn.ExecContext(t.Context(), "BEGIN EXCLUSIVE")
			require.NoError(t, err)

			if journal == "WAL" {
				duplicateFirstPackage(t, conn)
			}

			// Opening fails with a typed, matchable error, not as corruption.
			_, err = rpmdb.Open(path, opts)
			require.ErrorIs(t, err, rpmdb.ErrLocked)
			assert.NotErrorIs(t, err, rpmdb.ErrCorrupt)

			_, err = conn.ExecContext(t.Context(), "ROLLBACK")
			require.NoError(t, err)

			if journal == "WAL" {
				// Leave the exclusive mode, which holds the file until then.
				_, err = conn.ExecContext(t.Context(), "PRAGMA locking_mode=NORMAL")
				require.NoError(t, err)

				_, err = conn.ExecContext(t.Context(), "SELECT count(*) FROM Packages")
				require.NoError(t, err)
			}

			require.NoError(t, conn.Close())

			// Once the writer lets go, the database reads as before.
			assert.Equal(t, want, listCount(t, path, opts))
		})
	}
}

func TestSQLiteLockedWhileReading(t *testing.T) {
	path := copyFixture(t, "rpmdb.sqlite")
	w := writer(t, path, "journal_mode(DELETE)")

	db, err := rpmdb.Open(path, rpmdb.Options{BusyTimeout: 10 * time.Millisecond, LockRetries: 1})
	require.NoError(t, err)

	defer db.Close()

	conn, err := w.Conn(t.Context())
	require.NoError(t, err)

	_, err = conn.ExecContext(t.Context(), "BEGIN EXCLUSIVE")
	require.NoError(t, err)

	_, err = db.List(t.Context())
	require.ErrorIs(t, err, rpmdb.ErrLocked)

	// A reader that stops waiting says why.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = db.List(ctx)
	require.ErrorIs(t, err, context.Canceled)

	_, err = conn.ExecContext(t.Context(), "ROLLBACK")
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	pkgs, err := db.List(t.Context())
	require.NoError(t, err)
	assert.NotEmpty(t, pkgs)
}

func TestSQLiteLockRetrySucceeds(t *testing.T) {
	path := copyFixture(t, "rpmdb.sqlite")
	w := writer(t, path, "journal_mode(DELETE)")
	want := listCount(t, path, rpmdb.Options{})

	db, err := rpmdb.Open(path, rpmdb.Options{BusyTimeout: 5 * time.Millisecond, LockRetries: 20})
	require.NoError(t, err)

	defer db.Close()

	conn, err := w.Conn(t.Context())
	require.NoError(t, err)

	_, err = conn.ExecContext(t.Context(), "BEGIN EXCLUSIVE")
	require.NoError(t, err)

	// The writer commits while the reader waits between its retries.
	done := make(chan struct{})

	go func() {
		defer close(done)

		time.Sleep(150 * time.Millisecond)

		_, _ = conn.ExecContext(context.Background(), "COMMIT")
		_ = conn.Close()
	}()

	pkgs, err := db.List(t.Context())
	<-done
	require.NoError(t, err)
	assert.Len(t, pkgs, want)
}

func TestSQLiteConcurrentWriter(t *testing.T) {
	path := copyFixture(t, "rpmdb.sqlite")
	want := listCount(t, path, rpmdb.Options{})

	// rpm writes in WAL mode; the writer here keeps committing transactions
	// to a scratch table, checkpointing as it goes, while readers open the
	// database and list it.
	w := writer(t, path, "journal_mode(WAL)", "wal_autocheckpoint(1)")
	_, err := w.ExecContext(t.Context(), "CREATE TABLE scratch(n INTEGER)")
	require.NoError(t, err)

	stop := make(chan struct{})

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()

		for n := 0; ; n++ {
			select {
			case <-stop:
				return
			default:
			}

			tx, err := w.BeginTx(context.Background(), nil)
			if err != nil {
				return
			}

			for i := range 20 {
				_, _ = tx.ExecContext(context.Background(), "INSERT INTO scratch VALUES (?)", n*20+i)
			}

			_ = tx.Commit()
		}
	}()

	for range 25 {
		assert.Equal(t, want, listCount(t, path, rpmdb.Options{}))
	}

	close(stop)
	wg.Wait()
}

// crashedWriter leaves behind what a writer that died after committing would:
// the database, its -wal with a committed record the main file does not have
// yet, and, as asked, its -shm. It returns the directory.
func crashedWriter(t *testing.T, withWAL, withSHM bool) (dir string, want int) {
	t.Helper()

	live := copyFixture(t, "rpmdb.sqlite")
	want = listCount(t, live, rpmdb.Options{})

	w := writer(t, live, "journal_mode(WAL)", "wal_autocheckpoint(0)")
	duplicateFirstPackage(t, w)

	dir = t.TempDir()
	copyFile(t, live, filepath.Join(dir, "rpmdb.sqlite"))

	if withWAL {
		copyFile(t, live+"-wal", filepath.Join(dir, "rpmdb.sqlite-wal"))
	}

	if withSHM {
		copyFile(t, live+"-shm", filepath.Join(dir, "rpmdb.sqlite-shm"))
	}

	return dir, want
}

func TestSQLiteStaleWAL(t *testing.T) {
	t.Run("log left by a crashed writer", func(t *testing.T) {
		for _, shm := range []bool{false, true} {
			dir, base := crashedWriter(t, true, shm)

			// SQLite recovers the log: the committed record is there.
			assert.Equal(t, base+1, listCount(t, filepath.Join(dir, "rpmdb.sqlite"), rpmdb.Options{}), "shm=%v", shm)
		}
	})

	t.Run("database copied without its log", func(t *testing.T) {
		dir, base := crashedWriter(t, false, false)

		assert.Equal(t, base, listCount(t, filepath.Join(dir, "rpmdb.sqlite"), rpmdb.Options{}))
	})

	t.Run("immutable ignores the log", func(t *testing.T) {
		dir, base := crashedWriter(t, true, false)

		assert.Equal(t, base, listCount(t, filepath.Join(dir, "rpmdb.sqlite"), rpmdb.Options{SQLite: rpmdb.SQLiteImmutable}))
		assert.NotContains(t, dirEntries(t, dir), "rpmdb.sqlite-shm", "immutable creates nothing")
	})
}

func TestSQLiteReadOnlyDirectory(t *testing.T) {
	t.Run("without a log it is read immutable and nothing is created", func(t *testing.T) {
		dir, base := crashedWriter(t, false, false)
		before := dirEntries(t, dir)

		readOnlyDir(t, dir)

		assert.Equal(t, base, listCount(t, filepath.Join(dir, "rpmdb.sqlite"), rpmdb.Options{}))
		assert.Equal(t, before, dirEntries(t, dir))
	})

	t.Run("with a log it is read from a snapshot that is removed on close", func(t *testing.T) {
		dir, base := crashedWriter(t, true, false)
		before := dirEntries(t, dir)
		tmp := t.TempDir()

		readOnlyDir(t, dir)

		db, err := rpmdb.Open(filepath.Join(dir, "rpmdb.sqlite"), rpmdb.Options{TempDir: tmp})
		require.NoError(t, err)

		pkgs, err := db.List(t.Context())
		require.NoError(t, err)
		assert.Len(t, pkgs, base+1, "the log is part of what is read")
		assert.NotEmpty(t, dirEntries(t, tmp), "the copy lives in TempDir")

		require.NoError(t, db.Close())
		assert.Empty(t, dirEntries(t, tmp), "Close removes the copy")
		assert.Equal(t, before, dirEntries(t, dir), "nothing is created next to the original")
	})

	t.Run("in place fails as SQLite does", func(t *testing.T) {
		dir, _ := crashedWriter(t, false, false)

		readOnlyDir(t, dir)

		_, err := rpmdb.Open(filepath.Join(dir, "rpmdb.sqlite"), rpmdb.Options{SQLite: rpmdb.SQLiteInPlace})
		require.Error(t, err)
	})
}

func TestSQLiteSnapshotMode(t *testing.T) {
	dir, base := crashedWriter(t, true, false)
	tmp := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")

	assert.Equal(t, base+1, listCount(t, path, rpmdb.Options{SQLite: rpmdb.SQLiteSnapshot, TempDir: tmp}))
	assert.Empty(t, dirEntries(t, tmp))

	_, err := rpmdb.Open(path, rpmdb.Options{SQLite: rpmdb.SQLiteSnapshot, TempDir: tmp, MaxSnapshotBytes: 1000})
	require.ErrorIs(t, err, rpmdb.ErrTooLarge)
	assert.Empty(t, dirEntries(t, tmp), "a refused snapshot leaves nothing")

	_, err = rpmdb.Open(path, rpmdb.Options{SQLite: rpmdb.SQLiteSnapshot, TempDir: filepath.Join(tmp, "missing")})
	require.Error(t, err)

	_, err = rpmdb.Open(path, rpmdb.Options{SQLite: rpmdb.SQLiteMode(99)})
	require.Error(t, err)
}

func TestSQLiteNotARpmDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other.sqlite")
	w := writer(t, path)
	_, err := w.ExecContext(t.Context(), "CREATE TABLE other(a)")
	require.NoError(t, err)

	_, err = rpmdb.Open(path, rpmdb.Options{})
	require.ErrorIs(t, err, rpmdb.ErrCorrupt)
}

func TestSQLiteModeString(t *testing.T) {
	for mode, want := range map[rpmdb.SQLiteMode]string{
		rpmdb.SQLiteAuto: "auto", rpmdb.SQLiteInPlace: "in-place", rpmdb.SQLiteImmutable: "immutable",
		rpmdb.SQLiteSnapshot: "snapshot", rpmdb.SQLiteMode(7): "unknown",
	} {
		assert.Equal(t, want, mode.String(), fmt.Sprint(int(mode)))
	}
}
