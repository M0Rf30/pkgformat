# Test local database

Nine package directories of the `/var/lib/pacman/local` of an `archlinux:latest`
container (pacman 7.1.0), taken verbatim with `ALPM_DB_VERSION`: `desc`, `files`
and `mtree` of `acl`, `attr`, `bash`, `binutils`, `ca-certificates-utils`,
`filesystem`, `pacman`, `pacman-mirrorlist` and `tree`. `tree` was installed on
top of the image, so it is the one package installed explicitly; the rest came
with the image as dependencies. `generate.sh` rebuilds the directory; it needs
podman or docker and network access.

`pacman-mirrorlist` has a `%BACKUP%` entry whose checksum is `(null)`, as
pacman writes it for a file it has no digest of. `bash` provides `sh`, `acl`
provides `libacl.so=1-64`, and `pacman` and `binutils` have optional
dependencies.

## Files

| File | Content |
| --- | --- |
| `local/` | the database: `ALPM_DB_VERSION` and `<name>-<version>/{desc,files,mtree}` |
| `Q.expected` | `pacman --dbpath . -Q` for this database |
| `Qi.expected` | `pacman -Qi`, with `LC_ALL=C TZ=UTC` |
| `Ql.expected` | `pacman -Ql` |
| `info.txt` | the pacman version and the image |

The tests decode `local/` and compare each package with what pacman prints.
`mtree` is not read by the package; it is in the directory because it is part
of a real package directory.
