# apt pin policy: what real apt does

Fixtures behind `policy_test.go` (`TestPolicyMatchesAptScenarios`) and
`pinmatch_test.go`: the committed answers of real apt 2.6.2 (Debian 12), 3.0.4
(Debian 13) and 3.3.6 (unstable) for 171 preferences scenarios, compared with
`LoadPreferences`, `NewPolicy`, `Policy.Priority` and `Policy.Candidate`.

## What is hand-written, what is recorded

Hand-written inputs (all fictional hosts, no real repository data):

- `lists/`: an apt lists directory: ten `Release` files and their `Packages`
  indexes (stable with main, contrib and i386, testing, unstable, experimental
  (NotAutomatic), backports (NotAutomatic and ButAutomaticUpgrades), a security
  suite, a vendor origin, a local `file:` source, a BAU-only and a minimal
  release with no Origin, Label or Version). Every stanza has Filename, Size and
  SHA256 so that `apt-get -s install` accepts it. The packages cover epochs,
  `+b1` rebuilds, `~` versions, `Multi-Arch: same` and architecture all, and a
  version published by several suites.
- `sources.list`: one line per index above, `[trusted=yes]`.
- `status/{none,old,new,mixed}`: dpkg databases: nothing installed, older
  versions installed, newer ones (so a pin can downgrade) and a mixture
  with the installed version also in an index. Installed stanzas carry the same
  control fields as the index ones, so apt sees one version in two files, as on
  a real system.
- `scenarios/<name>/`: an `/etc/apt/preferences`, an optional
  `preferences.d/` and a `scenario` file of `key: value` lines (`status: <state>`
  picks the dpkg database, `default-release: <release>` is `apt-get -t`). The
  names say what they test: `pin-*` (release terms, origins, patterns), `pkg-*`
  (names, globs, regular expressions, `src:`, architectures), `ver-*` and
  `srcver-*` (version pins), `prio-*` (priorities around 100, 500, 990, 1000
  and 1001, negative, `never`), `target-*` (`-t`), `err-*` (files apt refuses),
  `syntax-*` (spacing, comments, case, CRLF) and `default-*`.
- `matchvec.c`, `matchvec.tsv`: glibc's `fnmatch(FNM_CASEFOLD)` and
  `regcomp(REG_EXTENDED|REG_ICASE)` over about 8000 pattern/string pairs. The
  first three columns of `matchvec.tsv` are the inputs, the fourth is glibc's
  answer (`invalid` for an expression `regcomp` rejects, which matches
  nothing).

Recorded by `generate.sh` into `results/<label>/` (labels `bookworm`, `trixie`,
`unstable`), with a `MANIFEST` naming the image and apt version, and per scenario:

- `files`: the "Package files:" part of `apt-cache policy` (priority of every
  index and of the status file);
- `policy`: `apt-cache policy` of every package: priority of every version,
  candidate, installed version;
- `install.tsv`: what `apt-get -s install <package>` picks (`inst=`, `same=` or
  `error=`) for every package, including `name:i386`;
- `upgrade.tsv`: what `apt-get -s upgrade` installs or downgrades;
- `stderr`, `rc`: apt's complaints, and its exit status. A preferences file
  apt refuses fails every command that plans something (rc 100), but
  `apt-cache policy` still prints the pins read before the bad stanza, which is
  what `ParsePreferences` returns next to its error.

The tests assert every file priority, every version priority and candidate in
`policy`, every `install.tsv` pick, and the `upgrade.tsv` set (without the
`Multi-Arch: same` package, which apt holds back for reasons outside pinning).

## Differences between apt versions the tests encode

- apt before 2.7 (bookworm) does not know `Pin: source-version`: it warns and
  drops the stanza (`PolicyOptions.IgnoreSourceVersionPins`).
- A release pin with more than 19 comma separated terms matches no Release
  file, but does match the dpkg status file (a quirk of apt's constructor).
- `Package: x:*`, `x:any` and `x:linux-any` select architectures by wildcard;
  an architecture-all version belongs to the native architecture's package.

A preferences.d name that ends in a dot (scenario `d-ignored-names`) cannot be
part of a Go module zip, so it is committed as `trailing.DOT`; the test copies
the scenario preferences and `container.sh` renames the file before apt reads
them.

## Regenerating

```
deb/apt/testdata/policy/generate.sh        # needs podman or docker and network
IMAGES="trixie=docker.io/library/debian:stable-slim" SCENARIOS="pin-star prio-991" \
    deb/apt/testdata/policy/generate.sh
cc -o /tmp/matchvec deb/apt/testdata/policy/matchvec.c \
    && cut -f1-3 deb/apt/testdata/policy/matchvec.tsv | /tmp/matchvec >/tmp/matchvec.tsv
```

The scenario inputs are committed, so regenerating only refreshes the answers.
`stable-slim` and `unstable-slim` move; a newer apt can change an answer, which
is what the differential test is for.
