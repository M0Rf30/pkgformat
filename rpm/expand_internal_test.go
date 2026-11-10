package rpm

import (
	"crypto"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/rpm/cpio"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

func TestDigestFor(t *testing.T) {
	for algo, size := range map[uint32]int{
		tag.HASH_MD5:      crypto.MD5.Size(),
		tag.HASH_SHA1:     crypto.SHA1.Size(),
		tag.HASH_SHA224:   crypto.SHA224.Size(),
		tag.HASH_SHA256:   crypto.SHA256.Size(),
		tag.HASH_SHA384:   crypto.SHA384.Size(),
		tag.HASH_SHA512:   crypto.SHA512.Size(),
		tag.HASH_SHA3_256: 32,
		tag.HASH_SHA3_512: 64,
	} {
		newHash, err := digestFor(algo)
		require.NoError(t, err, algo)
		require.Equal(t, size, newHash().Size(), algo)
	}
	_, err := digestFor(tag.HASH_TIGER192)
	require.ErrorContains(t, err, "unsupported file digest algorithm 6")
}

func fi(name string, mode, dev, ino uint32, size uint64, flags uint32) *fileInfo {
	return &fileInfo{name: name, mode: mode, device: dev, inode: ino, size: size, flags: flags,
		digest: "d-" + name, userName: "user-" + name[1:], groupName: "grp", mtime: 7, rdev: 5}
}

func TestPayloadLayoutAndFileMetas(t *testing.T) {
	link := fi("/l", cpio.S_ISLNK|0o777, 1, 3, 0, 0)
	link.linkName = "target"
	files := []FileInfo{
		fi("/d", cpio.S_ISDIR|0o755, 1, 1, 4096, 0),
		fi("/a", cpio.S_ISREG|0o644, 1, 2, 10, 0),
		link,
		fi("/b", cpio.S_ISREG|0o644, 1, 2, 10, 0), // hard link of /a
		fi("/c", cpio.S_ISREG|0o644, 1, 2, 10, 0), // hard link of /a, carries the data
		fi("/g", cpio.S_ISREG|0o644, 1, 2, 10, tag.RPMFILE_GHOST),
		fi("/n", cpio.S_ISREG|0o600, 1, 9, 5, 0),
	}

	sizes, nlinks, isLink := payloadLayout(files)
	require.Equal(t, []int64{0, 0, 6, 0, 10, 0, 5}, sizes)
	require.Equal(t, []int{0, 3, 0, 3, 3, 0, 0}, nlinks)
	require.Equal(t, []bool{false, true, false, true, false, false, false}, isLink)

	var logged strings.Builder
	o := &ExpandOptions{
		Logger: slog.New(slog.NewTextHandler(&logged, nil)),
		LookupUser: func(n string) (int, error) {
			if n == "user-n" {
				return 0, errors.New("no such user")
			}
			return 1000, nil
		},
		LookupGroup: func(string) (int, error) { return 100, nil },
	}
	metas := o.fileMetas(files, true)
	require.Len(t, metas, len(files))

	require.Equal(t, cpio.FileMeta{
		Name: "/b", Mode: cpio.S_ISREG | 0o644, Size: 0, UID: 1000, GID: 100, Mtime: 7, Rdev: 5,
		Inode: 1<<32 | 2, Nlink: 3, Digest: "d-/b",
	}, metas[3])
	require.Equal(t, int64(10), metas[4].Size)
	require.Empty(t, metas[0].Digest, "directories have no digest")
	require.Empty(t, metas[5].Digest, "ghost files have no digest")
	require.Zero(t, metas[6].Inode, "a file outside link groups has no inode key")
	require.Equal(t, -1, metas[6].UID, "unresolvable owner")
	require.Equal(t, 100, metas[6].GID)
	require.Contains(t, logged.String(), "user-n")

	// without owner resolution nothing is looked up
	for _, m := range (&ExpandOptions{LookupUser: func(string) (int, error) {
		t.Fatal("unexpected lookup")
		return 0, nil
	}}).fileMetas(files, false) {
		require.Equal(t, -1, m.UID)
		require.Equal(t, -1, m.GID)
	}
}
