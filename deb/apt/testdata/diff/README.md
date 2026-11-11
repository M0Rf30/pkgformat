# Differential fixtures for deb/apt

Everything here was recorded from a real `apt-get -s` (simulate) run in a Debian
container; `MANIFEST` names the image, apt and dpkg versions. `generate.sh`
reproduces all of it (podman, network for the archive part):

    ./generate.sh                 # archive part and worlds
    SKIP_ARCHIVE=1 ./generate.sh  # synthetic worlds only, offline, ~10 s

## Layout

| path | what |
| --- | --- |
| `lists/`, `status`, `targets.txt`, `expected.tsv` | trimmed real archive indexes, the container's dpkg status, and what `apt-get install -s --no-install-recommends` planned for each target (`ResolveDeps` and `Plan` are both compared) |
| `installed/` | the same archive with `preinstall.txt` installed (an MTA, sudo, mailx): `scenarios.txt` lines run `remove`, `upgrade`, `dist-upgrade` and installs that must remove or upgrade installed packages |
| `worlds/<name>/` | synthetic universes: `Packages` (the index), `status` (installed packages), `scenarios.txt`, optional `holds` (one package per line, `dpkg --set-selections`), `extended_states` and `preferences` (`/etc/apt/preferences`), and the recorded `expected.tsv` |
| `record.sh`, `container.sh`, `container-worlds.sh` | the in-container recorders |

Worlds: `conflicts` (Conflicts, Breaks, versioned and virtual conflicts,
Replaces, alternatives, providers, dependency upgrades), `upgrades`
(upgrade, `--with-new-pkgs`, dist-upgrade, kept back packages), `held`,
`pins` (a preferences file: never, below-default and above-1000 pins), `scoring` (the problem resolver's choices between
removing, keeping and upgrading, Pre-Depends, versioned providers) and
`broken` (systems whose installed packages have unmet dependencies, with and
without `-f`), `recommends`, `autoremove`, `statushold`, `ordering` and the
generated `soft1`..`soft6`.

## expected.tsv

`id TAB kind TAB package TAB version`, one line per planned package, in
the order apt prints them (removals, then installs and upgrades). Kinds:
`Inst`, `Upgr`, `Down`, `Remv`; `Kept` for each package named in apt's
"kept back" list (only the upgrade commands print one); `None` when nothing
changes; `Fail` when apt exits with an error (`- -` in the last columns);
`Solver3` when apt's second solver produced the answer (those scenarios
are skipped, `Plan` models the internal solver only).

## What the tests check

`TestPlanAgainstAptWorlds`, `TestPlanAgainstAptInstalled` and
`TestPlanAgainstAptTargets` (deb/apt/diff_plan_test.go) run `Cache.Plan` on
every scenario and require the same rows as apt, in the same order, with the
same versions, including the kept-back set. `TestDifferentialAgainstApt`
(diff_test.go) keeps checking the strict `ResolveDeps` on the targets.
A scenario that cannot match is listed in `aptDivergences` with the reason.

## Plan semantics

`Cache.Plan` ports the decisions of apt's `pkgDepCache::MarkInstall` /
`MarkDelete` and `pkgProblemResolver::Resolve`, and of `upgrade.cc`
(`pkgAllUpgrade`, `pkgDistUpgrade`) and `pkgFixBroken`:

* `PlanRequest.Install` / `Remove` / `Upgrade` / `FixBroken` mirror
  `apt-get install`, `remove`, `upgrade`, `--with-new-pkgs`,
  `dist-upgrade` and `-f`. A removal of a package removes what depends on
  it unless another alternative is installed.
* A candidate that Conflicts with an installed package removes it; one that
  Breaks it upgrades it when a version out of the range exists, else removes
  it. Versioned Conflicts, Conflicts on a virtual package and
  Replaces-with-Conflicts follow apt.
* Candidates come from the `Policy`: a version of priority below 0 is never a
  candidate, a version older than the installed one only with a pin over 1000;
  `name=version` overrides the pin as it does in apt. Without a policy the
  default priorities apply.
* Packages in `PlanOptions.Held` are never changed by the resolver, only by an
  explicit remove.
* `Plan.Held` is what apt lists as "kept back": installed packages with a
  newer candidate when the solver started that end neither upgraded nor
  removed.
* A broken system fails every request, except `-f` without packages, which
  repairs first, as apt's `CheckDeps` does; `-f` with packages has no effect.

## Documented divergences from apt

Only apt-internal quirks or out-of-scope ones; each is also in
`aptDivergences` (the two `soft6` scenarios), recorded as `Solver3`, or in the
godoc of `Plan`:

* Scenarios in which apt falls back to its 3.0 solver after the internal one
  fails (its output starts with `Solving dependencies...`, or `Calculating
  upgrade...` appears twice) are recorded as `Solver3` and skipped: ten of the
  generated ones (`soft1` x18 and x25; `soft2` x04, x18, x39; `soft5` x03,
  x20, x24, x42, x43). Plan models the internal solver only and fails on
  those requests.
* `soft6/x02` and `soft6/x26`: apt prints `Internal Inconsistency in
  pkgDepCache: BrokenCount 2 vs 1` and its answer depends on the corrupted
  count; not reproducible (`brokenCountQuirk`).
* Ties between packages of equal score are broken by package name; apt uses the
  order of its package table. No recorded scenario depends on it.
* Not modelled: the versioned-kernel protection of autoremove
  (`APT::VersionedKernelPackages`: when every provider of a dependency is a
  versioned kernel package apt keeps only the protected kernels, a set read
  from the running system); purge as distinct from remove (`Purg` rows are read
  as `Remv`, configuration-file state is unknown); the Important and Protected
  flags beyond Essential; implicit Breaks and reinstalls.

`scoring/s13` (two packages Pre-Depend on each other) used to be a divergence;
Plan now orders configuration like apt and fails the same way (see below).

## Soft dependencies, automatic marks and generated worlds

Recorded with apt 3.0.4 (the `debian:stable-slim` image) by `SKIP_ARCHIVE=1 ./generate.sh`:

- `worlds/recommends` (30 scenarios): Recommends and Suggests of new, upgraded
  and kept packages, with `--install-recommends` and `--install-suggests`. apt
  removes an installed package that a recommended package conflicts with, so
  Plan does as well.
- `worlds/autoremove` (40 scenarios): `autoremove`, `autopurge`, `install`,
  `remove --auto-remove`, upgrades, metapackages, `oldlibs`, NeverAutoRemove
  names and the `APT::AutoRemove::*Important` options, over an
  `extended_states` file. The rows `Manu` ("set to manually installed") and
  `Auto` ("no longer required") carry those lists; `Purg` rows are read as
  `Remv`.
- `worlds/statushold` (20 scenarios): `Status: hold ok installed` in the dpkg
  status file (with an `extended_states` file), so Plan honours holds without
  `PlanOptions.Held`: held packages stay out of upgrades and dependency
  repairs, and an explicit `install` of a held package overrides the hold, as
  in apt.
- `worlds/ordering` (54 scenarios): Pre-Depends and Depends chains, loops,
  Pre-Depends cycles, removals interleaved with installs, providers swapped
  for a package they conflict with, and upgrades. `scoring/s13` (two
  packages that Pre-Depend on each other) is one: apt fails with `Couldn't
  configure pre1:amd64, probably a dependency cycle`, and Plan returns an
  `*OrderError` (`ErrOrderLoop`, cycle `pre1 -> pre2 -> pre1`).
- `worlds/soft1` to `worlds/soft6` (49 scenarios each) come from
  `softgen` (`go run ./deb/apt/testdata/diff/softgen -seed N -out DIR`), a
  seeded random universe with a consistent installed system, automatic marks
  and a hold. Ten are recorded `Solver3` and skipped, two are in
  `aptDivergences`; see above.

## Order check

The unsorted `Inst`, `Upgr`, `Down` and `Remv` rows of a scenario are compared
with apt's, in order. `Plan` gets that order by replaying apt's own steps:
`resolve_order.go` ports `pkgOrderList`, `pkgPackageManager` (SmartUnPack,
SmartConfigure, early removal, Multi-Arch: same lockstep) and the
`pkgSimulate` replay. The order of the reverse dependencies, which apt takes
from the order in which its cache generator created the dependency records,
is rebuilt over every version of every loaded index (`resolve_revdeps.go`); the
remaining approximation is that the rank of a version string only covers the
loaded indexes, not the whole archive.

Not modelled: see the divergences above.
