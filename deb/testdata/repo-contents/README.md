# repo-contents

Fixtures for Contents indexes.

| File | Origin |
| --- | --- |
| `pool/*.deb` | three packages built by `generate.sh` with `dpkg-deb` (`SOURCE_DATE_EPOCH=1700000000`; xz, gzip and zstd members): `alpha` (a symlink, a path with blanks, a path shared with `beta`), `beta` (no Section, a conffile), `gamma` (Section `libs/extra`, a hard link, architecture all) |
| `contents.expected` | `apt-ftparchive contents pool`: locations are bare package names, paths padded with tabs to column 56 plus four blanks |
| `generate.expected` | the `Contents-amd64` `apt-ftparchive generate` writes for a tree holding the same packages: locations are `Section/name` (a package without a Section stays bare) |
| `debian-contents-amd64.head`, `debian-contents-udeb-amd64.head.gz` | the head of Debian stable's Contents indexes (dak: paths padded with blanks, no header), `fetch.sh` |
| `ubuntu-contents-amd64.head` | the head of Ubuntu jammy's `Contents-amd64` (apt-ftparchive layout), `fetch.sh` |
| `apt-file.sh`, `apt-file.expected` | the container script and the output of `apt-file` (Debian bookworm) for a repository whose Contents index `ContentsBuilder` wrote; recorded by `PKGFORMAT_E2E=1 PKGFORMAT_UPDATE=1 go test ./deb/ -run TestContentsReadByAptFile` |

`contents_test.go` builds `contents.expected` and `generate.expected` byte for
byte from the packages and, when `apt-ftparchive` is installed, compares against
a live run. Padding follows apt-ftparchive exactly, including paths of 56
columns or more (`path` + blanks up to column 60, at least one).

## Regenerate

```sh
sh generate.sh   # pool/, contents.expected, generate.expected (dpkg-deb, apt-ftparchive)
sh fetch.sh      # real Debian and Ubuntu heads (network)
```

## apt-file end-to-end

```sh
PKGFORMAT_E2E=1 go test ./deb/ -run TestContentsReadByAptFile -v
```

Needs podman and a network (the container installs `apt-file`); skipped
otherwise. apt only fetches a Contents index whose uncompressed form the
Release lists as well, so the test lists both `Contents-amd64` and
`Contents-amd64.gz`.
