# Solver differential fixtures

The solver is checked against `apk add --simulate` / `apk upgrade --simulate`
(apk-tools 3.0.8 in an `alpine:3.24` container).

* `main.universe`, `edge.universe` are hand-written package lists (one line each);
  `main.index`, `edge.index` are the APKINDEX texts `mkidx.py` makes from them (`generate.sh` runs it), with unique
  SHA-1 based `C:` values. The second repository is tagged `@edge`.
* `cases.txt` has 59 cases (installed packages, world, command); `generate.sh`
  replays each one and writes `expected/<case>`: the sorted install/upgrade/
  downgrade/remove lines apk prints, or `error`.
* `real/` is a reduced real Alpine 3.24 index (main and community), the
  installed database and world file of the image, and the answers of apk for
  the targets of `real/targets.txt`; `real/generate.sh` rebuilds it (needs
  network).

`TestSolve_differential` and `TestSolve_realAlpine` compare as sets of changes.
