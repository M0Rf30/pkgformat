# pdiff fixtures

Real files from the Debian archive plus the records that tie this package to
`rred` (apt's patch applier) and GNU `ed`. `generate.sh` documents and repeats
how everything was made:

```
./generate.sh fetch     # download the real files below (network)
./generate.sh record    # apply every patch with rred and ed in podman containers
```

## Real archive files

| Directory | Source | Notes |
|---|---|---|
| `buster-updates/` | `https://snapshot.debian.org/archive/debian/20200101T000000Z/dists/buster-updates/main/binary-amd64/` (`Packages.diff/Index`, three `Packages.diff/*.gz`, `Packages.xz`) | An Index with unmerged patches, SHA-1 and SHA-256 sections, whose history starts from an empty file. |
| `trixie-updates/Index`, `T-*.gz`, `Packages.xz` | `https://deb.debian.org/debian/dists/stable-updates/main/binary-amd64/` (`Packages.diff/Index`, `Packages.diff/*.gz`, `Packages.xz`), fetched 2026-11-11 | A merged Index: `X-Patch-Precedence: merged`, `X-Unmerged-*`, `X-DAK-Older-Patches`. Seven merged patches. |
| `trixie-updates/base-<timestamp>.xz` | `https://snapshot.debian.org/archive/debian/<timestamp>/dists/trixie-updates/main/binary-amd64/Packages.xz` for 20250809T210000Z, 20250910T210000Z, 20260714T150000Z, 20260718T090000Z, 20261022T210000Z, 20261101T000000Z | The file each History entry's patch applies to, found by matching the History digests. The base of the oldest entry (`80a1f6...`, 32757 bytes) is not in the snapshot archive; its patch replaces the whole file and applies to anything. |

The archive's file names are kept, so no name contains a colon.

Known oddity, confirmed with rred: the merged patch `F-2026-10-30-1402.07`
applied to the base of 20261022T210000Z (digest `e162...`) does **not** give the
Current file; the other six merged patches give it from their bases. The test
expects a `*PDiffHashError` (`What == "result"`) for that pair, as apt would
see it.

## Records

* `rred-matrix.txt` -- for each of the 10 real patches on each of 9 real base
  files (the six bases, the two current files and an empty file): the SHA-256 of
  rred's output, or `error`. `TestPDiffRredMatrix` requires this package to give
  the same bytes wherever it succeeds. rred never exits non-zero on these; it
  does not check commands against the length of the file, so on wrong bases it
  gives output where this package reports an error (always an out-of-range
  command, `PDiffError.Line == 0`).
* `interop/` -- 40 small cases, `<id>.old`, `<id>.new`, `<id>.patch`: 20
  hand-written scripts covering the ed semantics (`sem-*`; stacking appends,
  `0a`, ranges, dots in text), 8 shapes (`gen-*`: empty files, dot lines,
  blank lines) and 12 seeded random pairs (`rand-*`), the patches made by
  `GeneratePDiff`.
* `interop-expected.txt` -- per case (these and `real-trixie-N`, the patches
  this package makes between neighbouring archive snapshots): SHA-256 of the
  new file, of the patch, and of what rred and ed made of old + patch. The
  test `TestPDiffInteropAgainstRredAndEd` runs without any tool and requires
  that all four digests agree with this package, and that `GeneratePDiff` still
  makes the same patch (a change of the algorithm shows up as a diff of the
  patch digest; re-run `generate.sh record` after reviewing it).
* `container/` -- the scripts that run inside the containers. rred comes from
  apt 2.6.2 (`localhost/debtools:bookworm`); ed from `docker.io/library/debian:bookworm`
  after `apt-get install ed`. `TestPDiffRredLive` runs the rred part again when
  podman and a local image are present (it never pulls).
