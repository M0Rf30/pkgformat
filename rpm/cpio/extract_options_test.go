package cpio

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// newcEntryFull is newcEntry with a modification time.
func newcEntryFull(name string, mode, nlink, ino int, mtime uint32, data []byte) []byte {
	b := newcEntry(name, mode, nlink, ino, uint32(len(data)), data)
	// the mtime field is the 6th of the 13 hex fields after the magic
	copy(b[6+5*8:], fmt.Sprintf("%08x", mtime))
	return b
}

func TestExtractAppliesModesAndMtimes(t *testing.T) {
	dest := t.TempDir()
	const mtime = 1600000000
	archive := cat(
		newcEntryFull("bin", S_ISDIR|0o755, 1, 1, mtime, nil),
		newcEntryFull("bin/run", S_ISREG|0o755, 1, 2, mtime, []byte("x")),
		newcEntryFull("bin/suid", S_ISREG|S_ISUID|0o755, 1, 3, mtime, []byte("x")),
		newcEntryFull("bin/sgid", S_ISREG|S_ISGID|0o750, 1, 4, mtime, []byte("x")),
		newcEntryFull("bin/ro", S_ISREG|0o444, 1, 5, mtime, []byte("x")),
		newcEntryFull("sticky", S_ISDIR|S_ISVTX|0o777, 1, 6, mtime, nil),
		newcEntryFull("locked", S_ISDIR|0o555, 1, 7, mtime, nil),
		newcEntryFull("locked/f", S_ISREG|0o644, 1, 8, mtime, []byte("x")),
		newcTrailer(),
	)
	require.NoError(t, Extract(bytes.NewReader(archive), dest))

	for name, want := range map[string]os.FileMode{
		"bin":      os.ModeDir | 0o755,
		"bin/run":  0o755,
		"bin/suid": os.ModeSetuid | 0o755,
		"bin/sgid": os.ModeSetgid | 0o750,
		"bin/ro":   0o444,
		"sticky":   os.ModeDir | os.ModeSticky | 0o777,
		"locked":   os.ModeDir | 0o555,
	} {
		fi, err := os.Lstat(filepath.Join(dest, name))
		require.NoError(t, err, name)
		require.Equal(t, want, fi.Mode(), name)
		require.Equal(t, int64(mtime), fi.ModTime().Unix(), name)
	}

	// extracting again over the read-only tree must work
	require.NoError(t, Extract(bytes.NewReader(archive), dest))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dest, "locked"), 0o755) })
}

func TestExtractUmask(t *testing.T) {
	dest := t.TempDir()
	archive := cat(
		newcEntry("d", S_ISDIR|0o777, 1, 1, 0, nil),
		newcEntry("d/suid", S_ISREG|S_ISUID|0o777, 1, 2, 1, []byte("x")),
		newcTrailer(),
	)
	err := ExtractWithOptions(bytes.NewReader(archive), dest, &ExtractOptions{Umask: 07022})
	require.NoError(t, err)
	fi, err := os.Stat(filepath.Join(dest, "d", "suid"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode())
	fi, err = os.Stat(filepath.Join(dest, "d"))
	require.NoError(t, err)
	require.Equal(t, os.ModeDir|0o755, fi.Mode())
}

func TestExtractHardlinks(t *testing.T) {
	t.Run("empty group", func(t *testing.T) {
		// no member carries data: the last one creates the (empty) file
		dest := t.TempDir()
		archive := cat(
			newcEntry("a", S_ISREG|0o644, 3, 7, 0, nil),
			newcEntry("b", S_ISREG|0o644, 3, 7, 0, nil),
			newcEntry("c", S_ISREG|0o644, 3, 7, 0, nil),
			newcTrailer(),
		)
		require.NoError(t, Extract(bytes.NewReader(archive), dest))
		var infos []os.FileInfo
		for _, n := range []string{"a", "b", "c"} {
			fi, err := os.Stat(filepath.Join(dest, n))
			require.NoError(t, err)
			infos = append(infos, fi)
		}
		require.True(t, os.SameFile(infos[0], infos[1]))
		require.True(t, os.SameFile(infos[0], infos[2]))
	})
	t.Run("data first", func(t *testing.T) {
		dest := t.TempDir()
		archive := cat(
			newcEntry("a", S_ISREG|0o644, 2, 7, 3, []byte("abc")),
			newcEntry("b", S_ISREG|0o644, 2, 7, 0, nil),
			newcTrailer(),
		)
		require.NoError(t, Extract(bytes.NewReader(archive), dest))
		got, err := os.ReadFile(filepath.Join(dest, "b"))
		require.NoError(t, err)
		require.Equal(t, "abc", string(got))
	})
	t.Run("incomplete group is an error", func(t *testing.T) {
		archive := cat(
			newcEntry("a", S_ISREG|0o644, 2, 7, 0, nil),
			newcTrailer(),
		)
		require.Error(t, Extract(bytes.NewReader(archive), t.TempDir()))
	})
}

type logCapture struct{ buf strings.Builder }

func (c *logCapture) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&c.buf, nil))
}

func TestExtractSpecialFiles(t *testing.T) {
	archive := cat(
		newcEntry("pipe", modeFifo, 1, 1, 0, nil),
		newcEntry("tty", S_ISCHR|0o666, 1, 2, 0, nil),
		newcEntry("after", modeReg, 1, 3, 1, []byte("x")),
		newcTrailer(),
	)

	t.Run("skipped by default with a warning", func(t *testing.T) {
		dest := t.TempDir()
		var c logCapture
		require.NoError(t, ExtractWithOptions(bytes.NewReader(archive), dest, &ExtractOptions{Logger: c.logger()}))
		for _, n := range []string{"pipe", "tty"} {
			_, err := os.Lstat(filepath.Join(dest, n))
			require.ErrorIs(t, err, os.ErrNotExist, n)
		}
		_, err := os.Stat(filepath.Join(dest, "after"))
		require.NoError(t, err)
		require.Contains(t, c.buf.String(), "path=pipe")
		require.Contains(t, c.buf.String(), "type=fifo")
		require.Contains(t, c.buf.String(), "type=\"character device\"")
	})

	t.Run("fifo created when allowed", func(t *testing.T) {
		dest := t.TempDir()
		fifoOnly := cat(newcEntry("pipe", S_ISFIFO|0o640, 1, 1, 0, nil), newcTrailer())
		require.NoError(t, ExtractWithOptions(bytes.NewReader(fifoOnly), dest, &ExtractOptions{SpecialFiles: true}))
		fi, err := os.Lstat(filepath.Join(dest, "pipe"))
		require.NoError(t, err)
		require.Equal(t, os.ModeNamedPipe|0o640, fi.Mode())
	})

	t.Run("device nodes need privileges", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: mknod would succeed")
		}
		// 4:64 is /dev/ttyS0; the 0:0 device is allowed to unprivileged users
		tty := newcEntry("tty", S_ISCHR|0o666, 1, 1, 0, nil)
		copy(tty[6+9*8:], "00000004")  // rdevmajor
		copy(tty[6+10*8:], "00000040") // rdevminor
		devOnly := cat(tty, newcTrailer())
		err := ExtractWithOptions(bytes.NewReader(devOnly), t.TempDir(), &ExtractOptions{SpecialFiles: true})
		require.ErrorIs(t, err, syscall.EPERM)
	})
}

func TestExtractChownIgnoredWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	var c logCapture
	archive := cat(newcEntry("f", modeReg, 1, 1, 1, []byte("x")), newcTrailer())
	err := ExtractWithOptions(bytes.NewReader(archive), t.TempDir(), &ExtractOptions{Chown: true, Logger: c.logger()})
	require.NoError(t, err)
	require.Contains(t, c.buf.String(), "not running as root")
}

func TestExtractFilesDigest(t *testing.T) {
	sum := sha256.Sum256([]byte("good"))
	good := hex.EncodeToString(sum[:])
	archive := cat(newcEntry("f", modeReg, 1, 1, 4, []byte("good")), newcTrailer())

	t.Run("match", func(t *testing.T) {
		err := ExtractWithOptions(bytes.NewReader(archive), t.TempDir(), &ExtractOptions{
			Files:     []FileMeta{{Name: "./f", Mode: modeReg, Digest: good}},
			NewDigest: sha256.New,
		})
		require.NoError(t, err)
	})
	t.Run("mismatch", func(t *testing.T) {
		dest := t.TempDir()
		bad := strings.Repeat("0", 64)
		err := ExtractWithOptions(bytes.NewReader(archive), dest, &ExtractOptions{
			Files:     []FileMeta{{Name: "/f", Mode: modeReg, Digest: bad}},
			NewDigest: sha256.New,
		})
		require.ErrorIs(t, err, ErrDigestMismatch)
		var dm *DigestMismatchError
		require.True(t, errors.As(err, &dm))
		require.Equal(t, "/f", dm.Path)
		require.Equal(t, bad, dm.Want)
		require.Equal(t, good, dm.Got)
		_, err = os.Lstat(filepath.Join(dest, "f"))
		require.ErrorIs(t, err, os.ErrNotExist, "the tampered file must not stay")
	})
	t.Run("not checked without a hash", func(t *testing.T) {
		err := ExtractWithOptions(bytes.NewReader(archive), t.TempDir(), &ExtractOptions{
			Files: []FileMeta{{Name: "/f", Mode: modeReg, Digest: strings.Repeat("0", 64)}},
		})
		require.NoError(t, err)
	})
}

func TestExtractStrippedWithFiles(t *testing.T) {
	// ../testdata/stripped.cpio holds two entries of 3 and 6 bytes
	raw, err := os.ReadFile("../testdata/stripped.cpio")
	require.NoError(t, err)

	_, err = NewCpioStream(bytes.NewReader(raw)).ReadNextEntry()
	require.ErrorIs(t, err, ErrStrippedHeader)

	dest := t.TempDir()
	err = ExtractWithOptions(bytes.NewReader(raw), dest, &ExtractOptions{Files: []FileMeta{
		{Name: "/dir/a", Mode: S_ISREG | 0o755, Size: 3, UID: -1, GID: -1, Mtime: 1600000000},
		{Name: "/dir/b", Mode: S_ISREG | S_ISUID | 0o755, Size: 6, UID: -1, GID: -1, Mtime: 1600000000},
	}})
	require.NoError(t, err)
	fi, err := os.Stat(filepath.Join(dest, "dir", "a"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode())
	require.Equal(t, int64(3), fi.Size())
	require.Equal(t, int64(1600000000), fi.ModTime().Unix())
	fi, err = os.Stat(filepath.Join(dest, "dir", "b"))
	require.NoError(t, err)
	require.Equal(t, os.ModeSetuid|0o755, fi.Mode())
	require.Equal(t, int64(6), fi.Size())
}
