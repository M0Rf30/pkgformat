# Fixtures

Every `.apk` and `.adb` file here was made by `generate.sh` with apk-tools
3.0.9 (`apk mkpkg`, `apk mkndx`), run in a user namespace (`podman unshare`) so
that apk sees every file as owned by `root:root`. The `.dump` next to each is
the output of `apk adbdump` for it. Nothing in this directory was made by the
code under test.

| File | What it is |
| --- | --- |
| `minimal.apk` | metadata only, no files |
| `tree.apk` | every entry kind apk mkpkg takes: files (setuid, empty, 100 kB), a symbolic link, a hard link, an extended attribute, directories with modes |
| `tree-none.apk`, `tree-deflate9.apk`, `tree-zstd3.apk` | the same tree compressed with `--compression none`, `deflate:9`, `zstd:3` |
| `tree-compat-300pre3.apk`, `tree-compat-300rc9.apk` | the same tree with `--compat 3.0.0_pre3` and `3.0.0_rc9`, which leave out directory nodes |
| `full.apk` | all metadata fields, every dependency operator, seven scripts, triggers, `replaces-priority` |
| `signed-rsa.apk`, `signed-ec.apk` | signed with the throwaway keys behind `rsa.pub` (RSA 2048) and `ec.pub` (P-256) |
| `index.adb`, `index-signed.adb` | `apk mkndx` of `minimal`, `tree` and `full`; the second signed with the RSA key |

The private keys were made by `generate.sh` and deleted with its temporary
directory; only the public keys are kept. The EC signature is randomized, so
`signed-ec.apk` and the signature of `index-signed.adb` change whenever the
script runs; regenerating is only needed to add a case.

The fixtures contain no third-party data. File contents are short strings made
by the script (and 100000 times the letter `x`).

`fixtures_test.go` rebuilds the unsigned packages from the same inputs with the
writer of this package and checks that the ADB block is the one apk made; for
`tree-none.apk` the whole file is identical.

To regenerate: `sh generate.sh` (needs `apk`, `openssl`, `setfattr` and
`podman`).
