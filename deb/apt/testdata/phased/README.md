# Phased updates: what real apt does

Fixtures behind `phased_test.go` and `phased_draw_test.go`, which check
`PhasedDraw`, `Policy.Phased` and `Policy.PhasedIn` against apt.

## The algorithm

A version with `Phased-Update-Percentage: N` (N below 100) is held back on a
machine unless the machine's draw says it is part of the first N percent.
apt (apt-pkg/policy.cc, `ExcludePhased`) computes it like this:

1. The seed string is `<source package>-<source version>-<machine-id>` where
   the machine id is the first line of `/etc/machine-id`. The source package
   and version are the `Source:` field of the version (or its own name and
   version when it has none).
2. `std::seed_seq` is built from the bytes of the seed string. Each `char` is
   widened to a 32-bit word **with sign extension** (a byte of 0x80 or more
   becomes 0xFFFFFFxx), which matters for non-ASCII source names.
3. `std::minstd_rand` (Lehmer, multiplier 48271, modulus 2^31-1) is seeded
   from it: `seed_seq::generate` fills four 32-bit words (libstdc++'s mixing
   with the constants 0x8b8b8b8b, 1664525 and 1566083941), the fourth is
   reduced modulo 2^31-1 and a result of 0 becomes 1.
4. `std::uniform_int_distribution<unsigned>` draws one value. libstdc++ maps
   the generator range 1..2^31-2 onto the requested range by rejection and two
   divisions, not by a modulo.
5. The version is held back when the draw is above the percentage (apt 2.7.11
   to 3.2) or at least the percentage (apt 3.3 and later); the range is 0..100
   in the former and 0..99 in the latter (`PhasedModel` selects the variant).
   The security rule (versions from a `-security` suite lift the hold) is also
   version dependent.

Not phased at all: no machine id, `APT::Get::Always-Include-Phased-Updates`,
a chroot (`ischroot -t`), `SOURCE_DATE_EPOCH` set, a new installation, the
installed version itself, a percentage of 100 or one that is not 0..100.
`Never-Include-Phased-Updates` holds back every phased version.

## Files

- `draw.cc`, `inputs.txt`, `draw.tsv`: libstdc++ itself on 306 seed triples
  (source, source version, machine id): the four `seed_seq` words and the draws
  over 0..99 and 0..100. Regenerate with
  `g++ -O1 -o /tmp/draw draw.cc && /tmp/draw <inputs.txt >draw.tsv`. The lines
  of `inputs.txt` cover empty and 1-byte fields, long names, non-ASCII bytes
  (sign extension) and 32-hex machine ids. g++ 16 / libstdc++ of the host
  produced them; the libstdc++ algorithms involved are unchanged for years.
- `repo/`, `machine-ids.txt`: the repository the sweeps run against and 320
  machine ids. The packages are named after what they test: `paN` share the
  source `phsrc 1.1-1` and have percentages N=0..100 (so one draw decides all
  of them), `pbN` have a source of their own, `pcN` a source with an epoch,
  `pd-*` an absent, an out-of-range and a textual percentage, `psec-*` the
  security-suite rule (candidate, intermediate and older security versions),
  `pnew` is not installed, `pmulti` has several versions.
- `container.sh`, `generate.sh`: run apt in a Debian container per release and
  write `results/<label>/`:
  - `MANIFEST`: image, apt and libstdc++ versions, and that `ischroot -t`
    answered "not a chroot" (phasing is off in a chroot).
  - `sweep.tsv`: for each of the 320 machine ids, what `apt-get -s upgrade`
    offered; `sweep-phase-policy.tsv` the same with `APT::Get::Phase-Policy`.
  - `options.tsv`: the Never / Always options and a missing machine id.
  - `install.tsv`: `apt-get -s install` is not phased.
  - `policy-phase-policy.txt`: `apt-cache policy` with Phase-Policy, where
    held-back versions show `(phased N%)` and a priority of at most 1.

`results/bookworm` is apt 2.6.2 (`PhasedPre2711`), `results/trixie` apt 3.0.4
(`PhasedPre33`) and `results/unstable` apt 3.3.6 (`PhasedCurrent`).

## Regenerating

```
deb/apt/testdata/phased/generate.sh          # needs podman or docker and network
IMAGES="trixie=docker.io/library/debian:stable-slim" deb/apt/testdata/phased/generate.sh
```

`stable-slim` and `unstable-slim` move: a regenerated trixie or unstable
directory may report newer apt versions than the ones recorded here, in which
case the model each directory is checked against (see `phasedImages` in
`phased_test.go`) has to follow the MANIFEST.
