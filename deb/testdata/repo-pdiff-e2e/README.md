# apt end-to-end proof

`run.sh` shows that `apt-get update` consumes the `Packages.diff` that
`deb.PDiffIndexBuilder` publishes.

1. `mkrepo publish` builds a small repository (400+ packages, a handful of
   changed packages per step) with `PDiffIndexBuilder`; the `Release` lists
   `Packages`, `Packages.xz` and `Packages.diff/Index` with their hashes.
2. `mkrepo serve` serves it on the loopback and logs every request.
3. A Debian container (`--network=host`, `/var/lib/apt/lists` kept between runs)
   runs `apt-get update` with `Acquire::PDiffs=true` (`apt-update.sh`).
4. The script publishes more steps and runs it again, and checks the request
   log and that the Packages file apt ends up with is byte-identical to the
   published one:

   | Run | apt must request | Result |
   |---|---|---|
   | first | `Packages.xz` | full download |
   | one step behind | `Packages.diff/Index`, one patch, no `Packages.xz` | patched |
   | three steps behind (unmerged) | Index and three patches | patched |
   | three steps behind (merged, `-merge`) | Index and exactly one `T-...-F-...` patch | patched |

`transcript.txt` is a recorded run on apt 2.6.2 (`localhost/debtools:bookworm`)
and apt 3.0.4 (`docker.io/library/debian:trixie-slim`); `debian:bookworm` passes
too. The Release is unsigned and the source is `[trusted=yes]`; the pdiff checks
(Index digest against the Release, patched file against `SHA256-Current`) are
apt's own and happen regardless.

Requirements: go, podman, a local Debian image with apt (`IMAGE=...`, default
`localhost/debtools:bookworm`). Nothing outside the host is contacted. The Go
test `TestPDiffAptE2E` runs this script; it is skipped unless `PKGFORMAT_E2E=1`
and a podman image are available.
