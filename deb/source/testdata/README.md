# Test data

All data is real tool output; nothing is hand-written.

- `packages/<name>/`: the source packages of Debian 13 (stable) as
  downloaded by `generate.sh` from the Debian archive: the `.dsc` (with the
  maintainer's signature), the orig tarballs, the debian tarball or
  `.diff.gz`. Their contents are the work of the Debian maintainers and
  upstream authors under their own licenses. Twelve packages: quilt (`hello`
  with an `.asc`, `sl`, `rust-getch`, `node-boolbase` with a component
  tarball, `node-is-node`, `r-cran-bh`, `icingaweb2-module-metapackages`),
  native (`meta-exwm`) and 1.0 (`cl-pipes`, `libtemplate-plugin-utf8decode-perl`,
  `vacation`, `valgrind-if-available`).
- `expected/<name>.manifest`: the tree `dpkg-source --no-check -x` extracts,
  one line per entry: mode, type, path, SHA-256 or link target. Written by
  `generate.sh`.
- `sources/`: `Sources.apt-ftparchive` and `Sources.dpkg-scansources`, the
  indexes `apt-ftparchive sources` and `dpkg-scansources` write for
  `packages/`. Written by `generate-sources.sh`.
- `changes/{full,binary}/`: the `.changes` and `.buildinfo` that
  `dpkg-genchanges` and `dpkg-genbuildinfo` wrote for a build of `hello` in
  a `debian:bookworm` container (`dpkg-buildpackage -us -uc -sa` and `-b`,
  `SOURCE_DATE_EPOCH=1700000000`). Written by `generate-changes.sh`, which
  needs podman and network access.

The scripts need dpkg-dev and apt-utils (and podman for the last one).
