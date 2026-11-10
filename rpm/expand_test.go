package rpm_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/pack"
)

// entry is what the extraction tests compare between trees.
type entry struct {
	Mode  fs.FileMode
	Size  int64
	Link  string
	Sum   string
	Mtime int64
}

// snapshot describes the tree below root. Hard link groups are returned as
// sorted lists of paths.
func snapshot(t *testing.T, root string) (map[string]entry, []string) {
	t.Helper()
	tree := map[string]entry{}
	regular := map[string]fs.FileInfo{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		e := entry{Mode: fi.Mode()}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			e.Link, _ = os.Readlink(p)
		case fi.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			e.Size, e.Sum, e.Mtime = fi.Size(), hex.EncodeToString(sum[:]), fi.ModTime().Unix()
			regular[rel] = fi
		}
		// directory mtimes are not compared: the reference tool leaves them
		// at the extraction time
		tree[rel] = e
		return nil
	})
	require.NoError(t, err)

	names := make([]string, 0, len(regular))
	for n := range regular {
		names = append(names, n)
	}
	sort.Strings(names)
	var groups []string
	seen := map[string]bool{}
	for i, a := range names {
		if seen[a] {
			continue
		}
		group := []string{a}
		for _, b := range names[i+1:] {
			if os.SameFile(regular[a], regular[b]) {
				group = append(group, b)
				seen[b] = true
			}
		}
		if len(group) > 1 {
			groups = append(groups, strings.Join(group, ","))
		}
	}
	return tree, groups
}

// cpioExtract unpacks rpmPath with rpm2cpio | cpio, the reference
// implementation, into a fresh directory.
func cpioExtract(t *testing.T, rpmPath string) string {
	t.Helper()
	for _, tool := range []string{"rpm2cpio", "cpio"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	abs, err := filepath.Abs(rpmPath)
	require.NoError(t, err)
	dir := t.TempDir()
	cmd := exec.Command("sh", "-c", `rpm2cpio "$1" | cpio -idm --quiet --no-absolute-filenames`, "sh", abs)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	t.Cleanup(func() { chmodTree(dir) })
	return dir
}

// chmodTree makes read-only directories removable again.
func chmodTree(root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o755)
		}
		return nil
	})
}

func expand(t *testing.T, rpmPath string, opts *rpm.ExpandOptions) string {
	t.Helper()
	f, err := os.Open(rpmPath)
	require.NoError(t, err)
	defer f.Close()
	pkg, err := rpm.ReadRpm(f)
	require.NoError(t, err)
	dest := t.TempDir()
	t.Cleanup(func() { chmodTree(dest) })
	require.NoError(t, pkg.ExpandPayloadWithOptions(dest, opts))
	return dest
}

// without drops entries the reference tool creates but that are skipped by
// default (FIFOs).
func without(tree map[string]entry, keep func(string, entry) bool) map[string]entry {
	out := map[string]entry{}
	for k, v := range tree {
		if keep(k, v) {
			out[k] = v
		}
	}
	return out
}

func notFifo(_ string, e entry) bool { return e.Mode&fs.ModeNamedPipe == 0 }

func TestExpandPayloadMatchesRpm2cpio(t *testing.T) {
	for _, name := range []string{"extract-v4.rpm", "extract-v6.rpm"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join("testdata", "extract", name)
			got, gotLinks := snapshot(t, expand(t, p, nil))
			want, wantLinks := snapshot(t, cpioExtract(t, p))
			require.Equal(t, without(want, notFifo), got)
			require.Equal(t, wantLinks, gotLinks)
		})
	}
}

func TestExpandPayloadModes(t *testing.T) {
	const root = "opt/extract-test/"
	const mtime = 1600000000
	for _, name := range []string{"extract-v4.rpm", "extract-v6.rpm"} {
		t.Run(name, func(t *testing.T) {
			dest := expand(t, filepath.Join("testdata", "extract", name), nil)

			for rel, want := range map[string]fs.FileMode{
				"bin/run":   0o755,
				"bin/suid":  fs.ModeSetuid | 0o755,
				"bin/sgid":  fs.ModeSetgid | 0o755,
				"bin/empty": 0o600,
				"bin/hl1":   0o644,
				"ro/file":   0o444,
				"ro":        fs.ModeDir | 0o555,
				"sticky":    fs.ModeDir | fs.ModeSticky | 0o777,
				"empty":     fs.ModeDir | 0o755,
				"bin/link":  fs.ModeSymlink | 0o777,
			} {
				fi, err := os.Lstat(filepath.Join(dest, root, rel))
				require.NoError(t, err, rel)
				require.Equal(t, want, fi.Mode(), rel)
				if fi.Mode()&fs.ModeSymlink == 0 {
					require.Equal(t, int64(mtime), fi.ModTime().Unix(), rel)
				}
			}

			target, err := os.Readlink(filepath.Join(dest, root, "bin/link"))
			require.NoError(t, err)
			require.Equal(t, "run", target)

			// hard links share an inode and the contents
			var infos []os.FileInfo
			for _, n := range []string{"hl1", "hl2", "hl3"} {
				p := filepath.Join(dest, root, "bin", n)
				b, err := os.ReadFile(p)
				require.NoError(t, err)
				require.Equal(t, "shared contents\n", string(b))
				fi, err := os.Stat(p)
				require.NoError(t, err)
				infos = append(infos, fi)
			}
			require.True(t, os.SameFile(infos[0], infos[1]))
			require.True(t, os.SameFile(infos[0], infos[2]))

			// the %ghost file is not in the payload, and the FIFO is skipped
			_, err = os.Lstat(filepath.Join(dest, root, "state"))
			require.ErrorIs(t, err, fs.ErrNotExist)
			_, err = os.Lstat(filepath.Join(dest, root, "bin/pipe"))
			require.ErrorIs(t, err, fs.ErrNotExist)
		})
	}
}

func TestExpandPayloadOptions(t *testing.T) {
	p := filepath.Join("testdata", "extract", "extract-v6.rpm")

	t.Run("umask", func(t *testing.T) {
		dest := expand(t, p, &rpm.ExpandOptions{Umask: 07022})
		fi, err := os.Stat(filepath.Join(dest, "opt/extract-test/bin/suid"))
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0o755), fi.Mode())
		fi, err = os.Stat(filepath.Join(dest, "opt/extract-test/sticky"))
		require.NoError(t, err)
		require.Equal(t, fs.ModeDir|0o755, fi.Mode())
	})

	t.Run("fifo", func(t *testing.T) {
		dest := expand(t, p, &rpm.ExpandOptions{SpecialFiles: true})
		fi, err := os.Lstat(filepath.Join(dest, "opt/extract-test/bin/pipe"))
		require.NoError(t, err)
		require.Equal(t, fs.ModeNamedPipe|0o640, fi.Mode())
	})

	t.Run("skipped special files are logged", func(t *testing.T) {
		var buf strings.Builder
		expand(t, p, &rpm.ExpandOptions{Logger: slog.New(slog.NewTextHandler(&buf, nil))})
		require.Contains(t, buf.String(), "opt/extract-test/bin/pipe")
		require.Contains(t, buf.String(), "type=fifo")
	})

	t.Run("owners are resolved by name", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("needs root")
		}
		dest := expand(t, p, &rpm.ExpandOptions{
			Chown:       true,
			LookupUser:  func(string) (int, error) { return 1234, nil },
			LookupGroup: func(string) (int, error) { return 4321, nil },
		})
		fi, err := os.Stat(filepath.Join(dest, "opt/extract-test/bin/run"))
		require.NoError(t, err)
		require.Equal(t, uint32(1234), statUID(fi))
	})
}

// tamper returns a package whose header describes body "AAAA..." but whose
// payload carries "BBBB...".
func TestExpandPayloadDigestMismatch(t *testing.T) {
	build := func(format int, body string) []byte {
		r, err := pack.NewRPM(pack.RPMMetaData{Name: "t", Version: "1", Release: "1", Arch: "noarch", Format: format})
		require.NoError(t, err)
		r.AddFile(pack.RPMFile{Name: "/opt", Mode: 0o40755})
		r.AddFile(pack.RPMFile{Name: "/opt/f", Body: []byte(body), Mode: 0o644})
		var buf bytes.Buffer
		require.NoError(t, r.Write(&buf))
		return buf.Bytes()
	}
	for _, format := range []int{pack.FormatV4, pack.FormatV6} {
		good := build(format, strings.Repeat("A", 64))
		evil := build(format, strings.Repeat("B", 64))
		hdr, err := rpm.ReadHeader(bytes.NewReader(good))
		require.NoError(t, err)
		end := hdr.GetRange().End
		// header of the good package, payload of the evil one
		mixed := append(append([]byte{}, good[:end]...), evil[end:]...)
		if bytes.Equal(mixed, good) {
			t.Fatal("payloads should differ")
		}

		extract := func(opts *rpm.ExpandOptions) (string, error) {
			pkg, err := rpm.ReadRpm(bytes.NewReader(mixed))
			require.NoError(t, err)
			dest := t.TempDir()
			return dest, pkg.ExpandPayloadWithOptions(dest, opts)
		}

		dest, err := extract(nil)
		require.ErrorIs(t, err, rpm.ErrDigestMismatch)
		var dm *rpm.DigestMismatchError
		require.True(t, errors.As(err, &dm))
		require.Equal(t, "/opt/f", dm.Path)
		_, statErr := os.Lstat(filepath.Join(dest, "opt/f"))
		require.ErrorIs(t, statErr, fs.ErrNotExist)

		// the option to skip the verification
		dest, err = extract(&rpm.ExpandOptions{SkipDigests: true})
		require.NoError(t, err)
		b, err := os.ReadFile(filepath.Join(dest, "opt/f"))
		require.NoError(t, err)
		require.Equal(t, strings.Repeat("B", 64), string(b))
	}
}

func TestExpandPayloadPackWritten(t *testing.T) {
	const mtime = 1600000000
	build := func(format int, compressor string) string {
		r, err := pack.NewRPM(pack.RPMMetaData{
			Name: "packed", Version: "1", Release: "1", Arch: "noarch", Format: format, Compressor: compressor,
		})
		require.NoError(t, err)
		files := []pack.RPMFile{
			{Name: "/opt", Mode: 0o40755, MTime: mtime},
			{Name: "/opt/bin", Mode: 0o40755, MTime: mtime},
			{Name: "/opt/empty", Mode: 0o40750, MTime: mtime},
			{Name: "/opt/bin/run", Body: []byte("#!/bin/sh\n"), Mode: 0o755, MTime: mtime},
			{Name: "/opt/bin/suid", Body: []byte("suid"), Mode: 0o4755, MTime: mtime},
			{Name: "/opt/bin/ro", Body: bytes.Repeat([]byte("ro"), 5000), Mode: 0o444, MTime: mtime},
			{Name: "/opt/bin/none", Body: nil, Mode: 0o600, MTime: mtime},
			{Name: "/opt/bin/link", Body: []byte("run"), Mode: 0o120777, MTime: mtime},
			{Name: "/opt/ghost", Mode: 0o644, Type: pack.GhostFile, MTime: mtime},
		}
		for _, f := range files {
			// as root: cpio drops set-uid when it cannot give the file to its owner
			f.Owner, f.Group = "root", "root"
			r.AddFile(f)
		}
		p := filepath.Join(t.TempDir(), "packed.rpm")
		f, err := os.Create(p)
		require.NoError(t, err)
		require.NoError(t, r.Write(f))
		require.NoError(t, f.Close())
		return p
	}

	for _, format := range []int{pack.FormatV4, pack.FormatV6} {
		for _, compressor := range []string{"gzip", "zstd", "xz"} {
			p := build(format, compressor)
			got, _ := snapshot(t, expand(t, p, nil))
			want, _ := snapshot(t, cpioExtract(t, p))
			require.Equal(t, want, got, "format %d, %s", format, compressor)
			require.Equal(t, fs.ModeSetuid|0o755, got["opt/bin/suid"].Mode)
			require.Equal(t, fs.FileMode(0o755), got["opt/bin/run"].Mode)
			require.NotContains(t, got, "opt/ghost")
		}
	}
}

func TestPayloadReadersOnV6(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "extract", "extract-v6.rpm"))
	require.NoError(t, err)
	defer f.Close()
	pkg, err := rpm.ReadRpm(f)
	require.NoError(t, err)

	// the deprecated reader needs the sizes from the header too
	cr, err := pkg.PayloadReader()
	require.NoError(t, err)
	n := 0
	for {
		h, err := cr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		require.True(t, h.IsStripped())
		_, err = io.Copy(io.Discard, cr)
		require.NoError(t, err)
		n++
	}
	require.Equal(t, 15, n, "every header file but the %%ghost one is in the payload")
}
