# rpm/pack

`pack` writes rpm packages (format v4 and v6) in pure Go. See the package
documentation (`go doc ./rpm/pack`) for the API; this file records what is verified
against the real tools.

## Verified against rpm

`interop_test.go` builds packages with `pack` and checks them with the tools of the
host and, when `PKGFORMAT_RPM_IMAGE` names a container image with rpm, in a
container:

| Check | How |
| --- | --- |
| Main header | every tag of a package built by `rpmbuild` from `testdata/interop/feat.spec` (v4 and v6) is compared byte for byte with the one `pack` writes; the tags that cannot match are listed with their reason in `notCompared` |
| Queries | `rpm -qp --qf`, `--scripts --triggers --filetriggers`, `--requires` and the other dependency queries, `-qplv` give the same output for both packages |
| Digests | `rpm -Kv` reports the header and payload digests of `pack`'s output as OK |
| Execution order | scriptlets, triggers, file triggers and transaction file triggers of `trig` run in the same order as for the `rpmbuild` package (`trigger-order.txt`) |
| Install | the package is installed in a container: hard links share an inode, devices/fifos, owners and `rpm -V` are right |
| File signatures | IMA (`FILESIGNATURES`) and fs-verity signature tags are byte-identical with `rpmsign --signfiles --signverity` on the same package |
| Rich dependencies | `ValidateRich` agrees with the verdicts of the spec parser of rpm on `testdata/interop/richdeps.tsv` |

`testdata/interop/README.md` describes the fixtures and `generate.sh` regenerates them.

## Memory

`TestHugeFileMemory` writes a package of a 3 GiB sparse file (zstd, v6) and
samples `runtime.ReadMemStats` while it runs: the heap peaks at about 16 MiB.
The test is skipped with `-short`.
