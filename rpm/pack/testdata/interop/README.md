# Interoperability fixtures

Everything here is produced by `generate.sh` from the specs in this directory; do not
edit the binaries by hand.

| File | Origin |
| --- | --- |
| `feat.spec` | a spec that uses most features of an rpm; `pack`'s `newFeat` (feat_test.go) builds the same package |
| `ref-feat-v4.rpm`, `ref-feat-v6.rpm` | `rpmbuild -bb` of `feat.spec` with rpm 6.0.1 (`_rpmformat` 4 and 6, gzip payload, `SOURCE_DATE_EPOCH=1700000000`, clamped times) |
| `trig.spec`, `bar.spec`, `ref-trig.rpm`, `ref-bar.rpm` | packages whose scriptlets append their name to `/tmp/order.log` |
| `scenario.sh`, `trigger-order.txt` | installs and removes the packages in a container and prints the log; the output for the `rpmbuild` packages, which `generate.sh` also checks equal for the `pack` ones |
| `signbase-signed.rpm` | the unsigned package `newSignBase` writes, signed with `rpmsign --signfiles --signverity` of rpm 6.1.0 using `sign-key.pem` and `sign-cert.pem` |
| `sign-key.pem`, `sign-cert.pem` | a throw-away RSA key and self-signed certificate made with `openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=pkgformat test only"`. They protect nothing |
| `richdeps.txt`, `richdeps.tsv`, `corpus-gen.sh` | boolean dependencies and the verdict (`ok`/`bad`) of `rpmspec -q --requires` for each as `Requires:` |

The container needs `rpm`, `rpm-sign`, `fsverity-utils` and `ima-evm-utils`; give its
image in `PKGFORMAT_RPM_IMAGE`. The tests that need it are skipped without it, the
tests that need `rpm` on the host are skipped without it.

Main header tags that are not compared with `rpmbuild`'s output, and why:

- `BUILDHOST`, `RPMVERSION`, `OPTFLAGS`, `PLATFORM`: depend on the build machine.
- `FILECLASS`, `CLASSDICT`: output of libmagic on the build root.
- `FILEINODES`: inode numbers of the build root (`pack` numbers files by position).
- `SIZE`, `LONGSIZE`: `rpmbuild` subtracts a file that `feat.spec` lists twice.
- `PREIN`: `rpmbuild` expands the macro `%{name}` in the script.
- Payload digests and sizes: depend on the payload bytes.
- The region trailers: hold the size of the data.
