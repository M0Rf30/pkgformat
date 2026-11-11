# comps.xml corpus

Documents for the comps reader and writer (`comps.go`, `comps_read.go`). No
file name contains a colon.

| File | What it is |
| --- | --- |
| `fedora43.xml` | Fedora 43 Everything `comps-Everything.x86_64.xml`, cut down to 9 groups, 2 categories, 2 environments and 3 langpacks (87 KB). Group, category and environment elements are copied line for line, with all their translations. The writer reproduces it byte for byte. |
| `fedora15.xml` | Fedora 15 Everything `comps-f15.xml`, cut down to 5 groups, 3 categories, 3 langpacks, 8 `<blacklist>` and 8 `<whiteout>` entries. It carries `langonly`, `basearchonly`, `<blacklist>`/`<whiteout>` with `arch`, and the attribute order of 2011 (`type` first), so the writer's output is equal to it as canonical XML (C14N) but not byte for byte. |
| `features.xml` | Written by hand: the attributes no published distribution uses today, in the layout the writer produces (so it is byte-identical to the writer's output): `arch` on group, category, environment, `<groupid>` and `<packagereq>`, `biarchonly`, `display_order` on a group, `langonly`, `basearchonly`, `requires`, `default` on `<groupid>`, an empty group, translated names and descriptions, langpacks, blacklist and whiteout. |

## Provenance

| Source | URL | sha256 |
| --- | --- | --- |
| Fedora 43 comps (zstd) | `https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Everything/x86_64/os/repodata/73a6103e51d00abd1abd50eb54f98a07b398a86972555b532af6acdb98565c3d-comps-Everything.x86_64.xml.zst` | `73a6103e51d00abd1abd50eb54f98a07b398a86972555b532af6acdb98565c3d` |
| Fedora 43 comps (decompressed with `zstd -d`) | | `68827506abbd1ff7a0118e1a351883bffe8a0b88fe13eaf43d24448a0cf95a97` |
| Fedora 15 comps | `https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/15/Everything/x86_64/os/repodata/47fcb90b5119c93feaab864c3346f9abed0245fe407bf317e3f7c20c0bef62b8-comps-f15.xml` | `47fcb90b5119c93feaab864c3346f9abed0245fe407bf317e3f7c20c0bef62b8` |

`generate.sh` downloads both, checks the digests and runs `trim.py` with the
selections listed in it. `trim.py` copies whole top-level elements and changes
nothing else, except that the DOCTYPE becomes its single-line form and
`<groupid>` lines that name a group that was cut out are dropped. Running the
script leaves the fixtures unchanged.

The groups were picked to cover the format: `core` and the language groups
(many translations, `langonly`), `kde-mobile*` (groups without translations),
`firefox` (an environment option with `default="true"`), `design-suite`,
`input-methods` and the groups with conditional packages (`requires`: 17 in
`fedora43.xml`, 2 in `fedora15.xml`).

## What was checked with real tools

All three files, and the files the writer makes from them, were checked on the
host (Fedora tooling from the `localhost/s3tools:latest` image: dnf5 5.4.7,
dnf 4, libcomps 0.1.24, python3-libcomps; host: createrepo_c 1.2.6, xmllint
from libxml2):

- `createrepo_c --no-database -g /absolute/path/comps.xml DIR` accepts each
  file without a warning, also with `--compatibility`; the comps file it
  publishes holds the same model (`TestCompsFixturesAcceptedByCreaterepo`).
  An absolute path is needed: a relative `-g` is looked up inside `DIR`.
- A repository written with this package (primary, filelists, other and the
  comps as a `group` record, a `group_gz` record, or both) is read by
  `dnf group list --hidden`, `dnf group info`, `dnf environment list` and
  `dnf environment info` over `file://` (`TestCompsReadByDnf`):

  ```sh
  podman run --rm -v REPO:/repo:ro,z localhost/s3tools:latest sh -c '
    printf "[t]\nname=t\nbaseurl=file:///repo\ngpgcheck=0\n" > /tmp/t.repo
    dnf --setopt=reposdir=/tmp --setopt=cachedir=/tmp/cache group list --hidden
    dnf --setopt=reposdir=/tmp --setopt=cachedir=/tmp/cache group info multilib-tools
    dnf --setopt=reposdir=/tmp --setopt=cachedir=/tmp/cache environment list'
  ```

- dnf 4 shows the German name, description and the language of a group with
  `LANG=de_DE.UTF-8` (the image has no locales; the test compiles one with the
  host's `localedef --no-archive -i de_DE -f UTF-8` and mounts it with
  `LOCPATH`): `Group: Multilib-Werkzeuge` (`TestCompsLocalizedByDnf4`). dnf5
  5.4.7 does not print translated names.
- libcomps reads the original and the written file as the same model:
  `Comps.xml_str()` is equal for both, and the names and descriptions by
  language, `default`, `uservisible`, `biarchonly`, `display_order`,
  `lang_only`, the package types, `requires`, `basearchonly`, the options of an
  environment, the langpacks, the blacklist and the whiteout are the ones in
  the file (`TestCompsReadByLibcomps`). The three real documents give
  libcomps no error.
- `xmllint --c14n` of the original and of the written file are equal
  (`TestCompsFixturesCanonicalWithXmllint`).

The interop tests skip when `createrepo_c`, `xmllint`, `podman`, the image or
`localedef` is missing; the fixtures keep the unit tests valid offline.
