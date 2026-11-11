# Resolver fixtures

Scenarios for `Index.Install` and `Index.Sysupgrade`, with what pacman 7.1.0
(libalpm 16.0.1, the `archlinux:latest` container) did for each of them. The
tests (`TestResolverMatchesPacman`) load the same databases, replay every
scenario and compare the packages pacman would install and the installed set it
ended up with; for a failing scenario they check the error against the one
pacman reported.

Everything here is real tool output: the packages are built by `makepkg`, the
databases by `repo-add`, the installed sets by `pacman -S --dbonly` and the
expectations by `pacman -S --print`, `pacman -Su --print`, a real
`--dbonly` transaction and `pacman -Q`. No network is used. `generate.sh`
rebuilds it all (it needs `makepkg`, `repo-add`, `fakeroot`, `zstd`, `bsdtar`
and podman or docker with `docker.io/library/archlinux:latest` available).

## Files

| File | Content |
| --- | --- |
| `packages.txt` | the packages: `repo\|name\|version\|key=values\|...`, in the order `repo-add` receives them |
| `installed.txt` | the installed sets: `set\|repositories\|packages` |
| `scenarios.txt` | the scenarios: `name\|mode\|set\|options\|targets` |
| `sync/{old,core,extra}.db` | the sync databases `repo-add` wrote; the tests use `core` and `extra`, `old` seeds the installed sets with older versions |
| `local/<set>/` | the local database each installed set left behind (`ALPM_DB_VERSION` and the package directories) |
| `expected/<name>.txt` | the outcome of a scenario: `status ok` with `pkg <repo> <name> <version>` lines (what `--print` listed) and `final <name> <version>` lines (`pacman -Q` after the transaction), or `status error` with pacman's messages |
| `info.txt` | the pacman versions of the host and the container |

## How a scenario is run

`mode` is `S` (`pacman -S targets`) or `Su` (`pacman -Su`). `options` are
`IgnorePkg=`, `IgnoreGroup=` (written to the `[options]` of a generated
`pacman.conf`) and `Usage.<repo>=` (a `Usage` line of that repository), separated
by `;`. Each scenario starts from a copy of its installed set and the sync
databases, and uses `SigLevel = Never` and file:// repositories.

`--print` skips the conflict check, so whether a scenario succeeds is decided by
the real `--dbonly` transaction. Two scenarios where one target provides the
other (`conflict-provided-name`, `conflict-target-provides-target`) therefore
list both packages under `pkg` but only one under `final`; the test accepts the
`--print` list as a superset there.

## What the scenarios show

- `--noconfirm` answers conflict questions with no: a conflict with an
  installed package, or between two targets, fails, unless one target provides
  the name of the other, which is then dropped.
- A package listed in `IgnorePkg` is still installed when asked for, but never
  upgraded, replaced, or picked to satisfy a dependency.
- A repository whose `Usage` has `Install` or `Upgrade` supplies packages for
  `-S`; `Upgrade` alone is enough, `Search` or `Sync` alone are not.
- `replaces` apply in `-Su`, not in `-S`.
- Providers: an exact package name beats a provider; among providers the
  installed one, then the earliest repository, then the lowest name.
