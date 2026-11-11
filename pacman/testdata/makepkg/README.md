# makepkg fixtures

One package built by the host's makepkg 7.1.0 (`generate.sh`, run as a normal
user, `SOURCE_DATE_EPOCH=1700000000`), with the files of the build and what
bsdtar 3.8.11 reports about it. The `PKGBUILD` packs one of every kind of entry
a package can hold: a regular file, a hard link, a symbolic link, a pipe, a
setuid file, a file owned by 1234:5678, a file with a `user.shape` xattr, a
name with a space and an `=`, a directory with the sticky bit and one with mode
750 (the last two are empty and `!emptydirs` drops them). Devices cannot be
made without privilege, so none is packed.

| File | Content |
| --- | --- |
| `PKGBUILD`, `shapes.install`, `ChangeLog` | the inputs |
| `tree-shapes-1.0-1-any.pkg.tar.zst` | the package makepkg wrote |
| `mtree.expected` | its `.MTREE`, decompressed: `/set`, one line per path, `sha256digest` only |
| `buildinfo.expected` | its `.BUILDINFO` (format 2) |
| `tar.expected` | `bsdtar -tvf` with numeric owners |
| `pax.expected` | the xattr records in the extended headers |
| `md5.expected` | the `.MTREE` line of a file with `md5,sha256`: md5 comes first |
| `info.txt` | the makepkg and bsdtar versions |

The tests read the package with `ReadMetadata`, `WalkPackage`, `VerifyPackage`
and `Extract`, and build the same tree with the writer to compare its `.MTREE`
with `mtree.expected` entry by entry (bsdtar chooses where to repeat `/set` and
lists the files of a directory before its subdirectories, which the writer
does not copy; the meaning is the same).
