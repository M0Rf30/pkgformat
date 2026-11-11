# Differential test against dnf

`snapshot/` is a trimmed copy of the Fedora 43 release repository
(`https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Everything/x86_64/os/`,
the `primary.xml` and `filelists.xml` named in `generate.sh`, checked by their
sha256). It holds about a thousand packages: the closure of the targets in
`targets.txt`, with the alternatives of every requirement (at most four) and the
packages that conflict with or obsolete them; packages whose requirements cannot
be met inside the snapshot are dropped, so every package is installable.
`filelists.xml` keeps only the paths some package requires or a target names.
The package data is Fedora's; the trimming is done by `snapshot.py`, with the
version comparison of the rpm python module.

`expected/<label>.txt` is what real dnf (`dnf5` 5.2.18, the Fedora 43 container
image, run by `dnf_expected.sh`) installs for the specs of the target on an empty
system with `--setopt=install_weak_deps=False --assumeno`: one
`name arch epoch:version-release` per line, or `error:` lines when dnf cannot
solve it. The targets cover rich dependencies, file dependencies, capabilities,
obsoletes (`yum`), conflicts (`curl curl-minimal`), multilib (`glibc.i686`,
`glibc glibc.i686`) and virtual providers (`sendmail`, `mailx`).

`../../differential_test.go` serves `snapshot/` over HTTP, loads it through the
client and compares `Resolve` with weak dependencies off to `expected/`.
`divergences.txt` lists the targets that differ and why; such a target must still
differ.

Regenerate everything with `./generate.sh` (needs curl, zstd, python3 with the
rpm module, podman and network access; about 1.2 GB of scratch space).

## Known divergences

- `dnf5`, `yum`: libsolv decides which provider of `/usr/bin/systemd-sysusers`
  to take before the requirement of dnf5 on `coreutils`, picks
  `systemd-standalone-sysusers` and, because it suggests `coreutils-single`,
  that package for `coreutils`. We decide `coreutils` first and take it, as it
  is the name asked for.
- libsolv's order of decisions among alternatives in general is not reproduced,
  nor is its backtracking beyond versions of one package, and `skip_broken` is
  not supported; see the package documentation. The targets here were chosen so that these show only as listed.
