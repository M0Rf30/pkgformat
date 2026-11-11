# Sources fixtures: list file names recorded from a real `apt-get update`

`listnames/` holds the evidence that `ListFileName`, `ListFileNameFor` and
`BaseURLs` name files the way apt does when it stores them in
`/var/lib/apt/lists`.

| File | What it is |
| --- | --- |
| `listnames/expected.tsv` | One row per list file apt created: the `sources.list` line, the path of the file below the suite directory (`InRelease`, `main/binary-amd64/Packages`, ...), and the name apt gave it. Tab separated. |
| `listnames/MANIFEST` | Image, apt version and capture time of the recording. |
| `listnames/container.sh` | Runs inside the container: builds the repositories, serves them, runs `apt-get update` once per line, classifies the files it finds. |
| `listnames/generate.sh` | Starts the container (`podman`, or `docker` through `CONTAINER_ENGINE`) and copies the results here. |

## Provenance

The recording in this tree was captured on 2026-11-11 with
`docker.io/library/debian:stable-slim` (Debian 13 "trixie", **apt 3.0.4**).
Regenerate it with

```sh
deb/apt/testdata/sources/listnames/generate.sh
```

The container installs `python3`, `openssl`, `gnupg` and `apt-utils` from the
Debian archive (so it needs network access), then:

1. creates a throw-away ed25519 key and a self-signed TLS certificate;
2. serves a document root over http on ports 80 and 8081 (IPv4 and IPv6) and
   https on 8443 with a small Python server;
3. for each case writes a tiny repository (Packages, Sources, Translation-en,
   Contents-amd64), a `Release` made by `apt-ftparchive release`, and signs it
   as `InRelease` (clear-signed), `Release` + `Release.gpg` (detached) or not at
   all (`trusted=yes`);
4. wipes `/var/lib/apt/lists`, writes the case's line to a file of its own and
   runs `apt-get update` with only that file as source list
   (`Dir::Etc::sourcelist`, `Dir::Etc::sourceparts=/dev/null`),
   `Acquire::Languages=en` (so Translation-en is fetched), an extra
   `Contents-deb` index target, and `Acquire::GzipIndexes=false` so that the
   names carry no compression suffix;
5. lists the files in `/var/lib/apt/lists` and records each with its path below
   the suite directory.

Nothing about the names is computed by this repository's code when recording:
the third column of `expected.tsv` is what apt wrote.

## What the cases cover

* plain http path, and a root path (`http://host:8081/`);
* `_` and `~` in the path (`my_repo~1`, written `%5f` and `%7e`), `+` (kept),
  `=`, `!`, `@` (quoted), `$` (quoted), `(`, `)`, `,`, `;` (kept);
* a suite with `+` and `~` (`v1+x~rc`, quoted twice: `%252b`, `%257e`);
* a port, the default port 80 (kept in the name), https with a port 8443, an
  IPv6 literal `[::1]:8081` (`::1:8081_...`), a mixed-case host, credentials in
  the URL (dropped), `%2541` and `%C3%A9` escapes;
* `file:/path`, `file:///path` and `copy:/path` (no host: the name starts with
  `_`);
* flat repositories: suite `./`, suite `/` and a suite below a path (`sid/`);
* `deb-src` (`main/source/Sources`);
* the three signing layouts: `InRelease`, `Release` + `Release.gpg`, `Release`
  alone;
* the targets Packages, Translation-en and Contents-amd64.

A space cannot be a case: ParseQuoteWord decodes `%20` to a blank and apt then
sends a request line the server rejects.

## How the tests use it

* `TestListFileNameForGolden` (always runs) parses every line with
  `ParseSourcesList` and compares `ListFileNameFor(src, relPath)` with the
  recorded name; for non-flat suites it also checks that `BaseURLs` keys the
  name's prefix to the source URL.
* `TestListFileNameAgainstLiveApt` runs `container.sh` again and compares with
  the fresh output. It skips unless `PKGFORMAT_E2E=1` is set and
  `podman` (or `CONTAINER_ENGINE`) is on the PATH.

## apt's rules, as observed

* The file name is the URI without scheme, user and password; host and port are
  kept (a port of 0 is dropped, any other is kept, including the default), the
  path follows; every byte `<= 0x20`, `>= 0x7f`, `%` and any of
  `\|{}[]<>"^~_=!@#$%&*` becomes `%xx` in lower case, then `/` becomes `_`
  (apt's `URItoFileName` and `QuoteString`).
* The suite is quoted once for the request URI (`+`, `~`, blank) and again for
  the name, hence `v1%252bx%257erc`.
* A flat suite replaces `dists/<suite>/` by the suite itself; `/` by nothing.
