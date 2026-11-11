# zchunk fixtures

Files in the zchunk format (`.zck`), written by the reference tools, to prove
that the reader accepts what they write and that the writer's chunks, headers
and checksums are theirs. `generate.sh` regenerates all of them but the
Fedora files; the sources are the golden documents of `../createrepo/golden/`.

Tools: createrepo_c 1.2.6 (`--zck`) and zchunk 1.5.5 (`zck`, `unzck`,
`zck_gen_zdict`, `zck_read_header`).

| file | made with | what it checks |
|------|-----------|----------------|
| `createrepo-{primary,filelists,other}.xml.zck` | `createrepo_c --zck` on `../createrepo/Packages` | the files of a repository; chunk per source package, empty dictionary entry, header size and checksum as repomd.xml records them |
| `createrepo-primary-old.xml.zck` | the same, without the systemd, vim, setup and edge packages | the previous version of the primary, for chunk-list deltas (`zck_delta_size` reports 10 chunks and 11457 bytes to fetch for the new one) |
| `zck-filelists.zck` | `zck` | content-defined chunking of a 1.5 MB document (26 chunks) |
| `zck-other-sha256.zck`, `zck-other-sha512.zck` | `zck -h sha256`, `zck -h sha512` | chunk checksum types |
| `zck-other-none.zck` | `zck --compression-format=none` | stored chunks |
| `zck-other-uncompressed-source.zck` | `zck -u` | the uncompressed-source flag: each chunk also lists the checksum of its uncompressed data |
| `zck-other-split.zck` | `zck -s '<package'` | chunks split at a string |
| `primary.zdict` | `zck_gen_zdict` on the chunks of `createrepo-primary.xml.zck` | a zstd dictionary |
| `zck-primary-dict.zck` | `zck -D primary.zdict` | a file with a dictionary chunk |
| `zck-primary-dict.zhr` | `unzck --header` | a detached header (magic `\0ZHR1`: the header, then the compressed dictionary) |
| `fedora43-server-comps.xml.zck`, `fedora43-server-repomd.xml` | fetched from `https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Server/x86_64/os/repodata/` on 2025-11-11 | a file from a real repository and the repomd.xml that lists it (`group_zck`: header size 158, header checksum `2edc0e02…1e56`); it decodes to the document the same repository serves zstd-compressed as `group` (sha256 `17c6cb2f…94b8`) |

All files pass `zck_read_header -f -q` (every checksum verified).
