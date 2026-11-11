# repo-translation

Fixtures for Translation files, `Description-md5` and the apt end-to-end test.

| File | Origin |
| --- | --- |
| `debian-Translation-en`, `debian-Translation-de` | the first 12 paragraphs of Debian stable's `main/i18n/Translation-en.xz` and `Translation-de.bz2` (real third-party data), fetched by `fetch.sh` |
| `debian-Packages.head` | the first 8 stanzas of Debian stable's `main/binary-amd64/Packages.xz`; each carries the short `Description` and the `Description-md5` that keys the files above |
| `repo/` | a complete repository (suite `bookworm`) built by `TestTranslationRepoFixture` with this package only: two packages, short-description `Packages` (plain, gz, xz), `Translation-en`/`Translation-de` (plain, xz), `i18n/Index`, the by-hash tree and the `Release` |
| `expected-trusted.txt`, `expected-signed.txt` | what apt 2.6 (Debian bookworm) printed for `repo/` when it was updated with `Acquire::Languages=de` (see `container.sh`) |

`container.sh` runs inside the container: it writes a `sources.list` entry for
`file:///repo` (`trusted=yes`, or `signed-by=/repo/key.asc`), runs
`apt-get update -o Acquire::Languages=de` and prints the lists apt stored plus
`apt-cache show` of both packages. The expected output shows
`Description-de` with the German text, so apt found the `Translation-de` file
through `i18n/Index`/`Release`, matched it by `Description-md5` and, in the
signed variant, accepted the `InRelease` that `SignRelease` wrote (the key is
generated on every run, so the signed repository is not committed).

## Regenerate

```sh
sh fetch.sh      # real Debian data (network)
sh generate.sh   # repo/ and expected-*.txt (go, podman); optional image argument
```

## Run the end-to-end test

```sh
PKGFORMAT_E2E=1 go test ./deb/ -run TestTranslationRepoWithApt -v
```

Without `PKGFORMAT_E2E=1` (or without podman) the test is skipped; the
committed-fixture test `TestTranslationRepoFixture` always runs and checks that
the code still builds `repo/` byte for byte. `PKGFORMAT_E2E_IMAGE` selects the
image (default `docker.io/library/debian:bookworm-slim`; the container needs
no network).
