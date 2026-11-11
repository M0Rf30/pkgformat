# pkgformat

[![CI](https://github.com/M0Rf30/pkgformat/actions/workflows/ci.yml/badge.svg)](https://github.com/M0Rf30/pkgformat/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/M0Rf30/pkgformat.svg)](https://pkg.go.dev/github.com/M0Rf30/pkgformat)

A pure-Go library for Linux package formats. It builds, reads, verifies and
signs packages; reads and writes repository indexes; and fetches from
repositories, with dependency resolution. It calls none of the native
packaging tools.

## Install

```sh
go get github.com/M0Rf30/pkgformat
```

Requires Go 1.27 or later.

## Formats

| Format | Package | Packages | Repository index | Repository client |
| --- | --- | --- | --- | --- |
| RPM (format 4 and 6) | [`rpm`](rpm/README.md) | write, read, verify, sign; installed database (`rpm/rpmdb`): read | repodata: write, read, sign, modules | `rpm/dnf` |
| Debian | [`deb`](deb/README.md) | write, read, verify, sign; installed database (`deb.StatusDB`): read | Packages, Release, InRelease, by-hash, Contents, Translations, Packages.diff: write, read, sign, verify | `deb/apt` |
| Debian sources | [`deb/source`](deb/source/README.md) | .dsc, .changes, .buildinfo: write, read, sign, verify; source packages 1.0, 3.0 (quilt), 3.0 (native): unpack, build (3.0) | Sources: write, read | |
| Alpine | [`apk`](apk/README.md) | write, read, verify, sign (RSA SHA-1 and SHA-256); installed database (`apk.InstalledDB`): read | APKINDEX: write, read, sign, verify | `apk.Client` |
| Alpine v3 (ADB) | [`apk/adb`](apk/adb/README.md) | write (`apk mkpkg` compatible), read, verify, sign (RSA, ECDSA), extract; `apk.ParsePackage` reads v3 too; verified against apk-tools 3.0.9 | APKINDEX.adb: write (`apk mkndx` compatible), read, sign, verify | |
| Arch Linux | [`pacman`](pacman/README.md) | write, read, sign; installed database (`pacman.LocalDB`): read | sync database: write, read | `pacman.Client` |

Each format has its own README with its supported features, examples and
security notes for untrusted input.

## Shared packages

| Package | Purpose |
| --- | --- |
| [`gpg`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/gpg) | OpenPGP signing (cleartext, detached armored, detached binary) and verification against a keyring |
| [`httpclient`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/httpclient) | HTTP client with capped bodies and one retry policy and classifier (transport errors, 408/429/5xx) |
| [`download`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/download) | Resumable downloads (`Range` + `If-Range`) with length and checksum checks, atomic rename and bounded concurrency |
| [`safepath`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/safepath) | Containment checks for untrusted archive entry names and symlink targets |
| [`xzlimit`](https://pkg.go.dev/github.com/M0Rf30/pkgformat/xzlimit) | xz decoding that rejects oversized dictionaries before allocating them |

All packages take their settings through options structs. They keep no
package-level state, and they log only through an optional `*slog.Logger`.

## Commands

| Command | Purpose |
| --- | --- |
| [`cmd/tar2rpm`](cmd/tar2rpm) | Turn a tar archive into an rpm package |
| [`cmd/rpmsample`](cmd/rpmsample) | Write a sample rpm package, to test other rpm tools |

## Security

Every parser is written for untrusted input. Sizes and counts are bounded, and
errors are typed. Archive extraction stays inside its target directory. Every
parser has fuzz targets, and CI runs all of them.

## License

Apache License 2.0, see [LICENSE](LICENSE).
