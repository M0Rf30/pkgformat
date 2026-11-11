# Extraction and writer interop fixtures

`generate.sh` regenerates `listings/` with the apk of an Alpine container
(`alpine:3.24`, apk-tools 3.0.8, rootless podman); the `.apk` files are the
inputs.

| Fixture | Origin | Shows |
| --- | --- | --- |
| `busybox-1.36.1-r31.apk`, `ca-certificates-20261020-r0.apk` | Alpine 3.20 main (`apk fetch`) | symlinks, scripts and triggers, license expressions |
| `iputils-ping-20240117-r0.apk` | Alpine 3.20 main | setuid binary, symlink |
| `iputils-20240117-r0.apk` | Alpine 3.20 main | a package with no file but `.dummy` |
| `libcap-utils-2.78-r0.apk`, `shadow-subids-4.15.1-r0.apk`, `fping-5.2-r0.apk` | Alpine 3.20 main/community | `security.capability` file capabilities (`SCHILY.xattr` records) |
| `bind-tools-9.18.49-r0.apk` | Alpine 3.20 main | hard links (tar type `1`) |
| `interop-1.2.3-r4.apk`, `signed-1.2.3-r4.apk`, `devices-1-r0.apk` | written by this library (`PKGFORMAT_UPDATE=1 go test -run TestInterop_fixtures`, run by `generate.sh`) | hard links, fifo, capability xattr, setuid, symlink checksums, license list, triggers, `replaces_priority`, RSA-SHA256 signature, device nodes |

`keys/pkgformat-test.rsa.pub` is the public half of a throw-away key made when
the fixtures were written; the private key was discarded.

`listings/<package>.listing` is the tree `apk extract` produced (see the header
of `generate.sh` for the columns); `TestExtract_matchesApk` compares the entries
this package reads, and the tree its `Extract` makes, with it.
`listings/devices-*.tarlist` is the listing of GNU tar for the device nodes,
which cannot be created without root. `listings/apk.verdicts` records that
`apk verify` accepts the signed package against `keys/`, refuses the unsigned
one, and that `apk add` installs the signed one.

The Alpine packages are redistributed unmodified as test data under their own
licenses (see the `license` of each `.PKGINFO`).
