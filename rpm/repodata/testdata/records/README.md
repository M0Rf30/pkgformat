# modifyrepo_c corpus

The repository metadata after `modifyrepo_c` registered or removed a file, used
to check `records.go` byte for byte.

- `base/repodata` is `createrepo_c` output (two packages of `../createrepo`,
  `--simple-md-filenames --general-compress-type=gz --revision 1700000000
  --set-timestamp-to-revision`).
- `inputs/` holds the files given to `modifyrepo_c`: an AppStream catalog
  (plain, and gzip compressed), a replacement catalog, an icon tarball and
  `prestodelta.xml` (a copy of `../deltainfo/prestodelta.xml`).
- Every other directory is `base` after one operation, with `repodata/repomd.xml`
  and the files `modifyrepo_c` added:

| directory | command (`modifyrepo_c ... repodata`) |
| --- | --- |
| `add-store` | `--no-compress inputs/appstream.xml` |
| `add-store-simple` | `--no-compress --simple-md-filenames inputs/appstream.xml` |
| `add-gz`, `add-zst`, `add-xz` | `--compress-type gz\|zstd\|xz inputs/appstream.xml` |
| `add-from-gz` | `--compress-type gz inputs/appstream.xml.gz` |
| `add-icons` | `--compress-type gz --mdtype appstream-icons inputs/appstream-icons.tar` |
| `add-prestodelta` | `--compress-type gz inputs/prestodelta.xml` |
| `all` | `add-gz`, `add-icons` and `add-prestodelta` in a row |
| `replace` | `all`, then `--compress-type gz --mdtype appstream inputs/appstream-replacement.xml` |
| `remove` | `all`, then `--remove appstream` |

Tools: createrepo_c and modifyrepo_c 1.2.6 (libz, libzstd, liblzma of the build
host). `generate.sh` rebuilds the directories. The record timestamps are the
time of the run (modifyrepo_c does not take them from the file), so a rerun
changes them and the checksums of the compressed files; the tests read the
timestamp from each fixture. The compressed files are not byte-identical to
the ones Go's compressors write, so for them the tests compare everything but
the compressed bytes (open-checksum, open-size, type, location pattern,
timestamp) and check that both files decompress to the input.
