# repo

Release fixtures: real files from the public archives and the output of the
real `apt-ftparchive`.

| File | Origin |
| --- | --- |
| `debian-stable.Release`, `debian-backports.Release` | Debian's `dists/stable/Release` and `dists/bookworm-backports/Release`, trimmed by `fetch.sh` to the header and a few index lines. dak layout: field order Origin, Label, Suite, Version, Codename, Changelogs, Snapshots, Date, Valid-Until, NotAutomatic, ButAutomaticUpgrades, Acquire-By-Hash, Signed-By, No-Support-for-Architecture-all, Architectures, Components, Description; sizes in 8 columns; `UTC` zone name |
| `ubuntu-jammy.Release`, `ubuntu-backports.Release` | Ubuntu's Release files (apt-ftparchive layout with sorted header fields, `Acquire-By-Hash` after the checksum sections, a blank padded hour in the date) |
| `ubuntu-jammy.i18n.Index` | the head of Ubuntu jammy's `main/i18n/Index` (SHA1 only, sizes in 7 columns). Debian publishes no `i18n/Index` |
| `ftparchive/` | a small `dists/x` tree made by `generate.sh`: `Packages` (plain, gz, xz), `Contents-amd64(.gz)`, `Translation-en(.bz2)`, `Sources(.gz)` |
| `ftparchive.Release` | `apt-ftparchive release` (apt 2.6.2 from Debian bookworm) for that tree with every Release option it knows: sorted header fields, numeric `+0000` zone, sizes in 16 columns |

`ReleaseStyleDebian` (the default of `Release.Marshal`) reproduces the dak
files byte for byte, `ReleaseStyleAptFTPArchive` the apt-ftparchive output;
`release_fields_test.go` checks both, and runs `apt-ftparchive` itself when it
is installed (also with `APT::FTPArchive::DoByHash=true` to compare the
by-hash tree `WriteByHash` writes).

## Regenerate

```sh
sh fetch.sh      # real archive files (network)
sh generate.sh   # ftparchive/ and ftparchive.Release (apt-ftparchive)
```

Real third-party text inside the fixtures is data of the Debian and Ubuntu
archives.
