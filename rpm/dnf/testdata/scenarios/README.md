# Scenarios against dnf5

Synthetic repositories and installed states, checked against real dnf
(`dnf5` 5.2.18 in the Fedora 43 container image, driven by `dnf_scenarios.sh`).

- `build.py` writes the packages (`PACKAGES`): tiny noarch rpms without files,
  made by rpmbuild, with the dependencies each scenario needs; `createrepo_c`
  writes the metadata. They are committed as `repos/<repo>/`.
- `scenarios.txt` has one scenario per line: the repositories of the
  transaction with their `priority` and `cost`, the packages installed first, the
  `dnf.conf` options (`best`, `install_weak_deps`, `installonly_limit`) and the
  specs to install.
- `installed/<label>/rpmdb.sqlite` is the rpm database dnf5 wrote when it
  installed the first packages into an empty root; the Go test reads it with
  `rpmdb`, so the installed state is what rpm itself recorded.
- `expected/<label>.txt` is what `dnf5 install --assumeno` printed, reduced to
  `+ name arch version repository` (installed or upgraded to) and
  `- name arch version` (replaced, obsoleted or removed, for installonly limits),
  or `error:` lines when dnf cannot solve the transaction. Packages that dnf
  lists as skipped for broken dependencies (`best=0`) are not part of it.

`../../scenarios_test.go` serves `repos/` over HTTP, loads it through the client
with the repositories, options and installed database of each line and compares
`Resolve` with `expected/`. `divergences.txt`, when present, lists the scenarios
that differ and why; a scenario listed there must still differ.

What the scenarios show about dnf, and the resolver follows:

- a repository with a lower `priority` number wins whatever the versions; `cost`
  only decides between equal packages, and a newer version beats a cheaper
  repository;
- an installed package is upgraded together with the installed packages that
  need its exact version, and an obsoleting package replaces the installed one,
  also when the obsoleted name is asked for;
- installonly packages (`installonlypkg(kernel)`, `kernel`) are installed next
  to the old versions; past `installonly_limit` the oldest installed ones are
  removed, and 0 means no limit;
- with `best=1` a package whose newest version cannot be installed fails the
  transaction; with `best=0` the older version is installed. What a package
  needs is chosen from older versions whenever the newest fails;
- weak dependencies add the Recommends of the packages of the transaction and
  the packages whose Supplements (rich ones too) the transaction newly meets;
  with `install_weak_deps=0` neither.

Regenerate with `./generate.sh` (rpmbuild, createrepo_c, python3, podman).
