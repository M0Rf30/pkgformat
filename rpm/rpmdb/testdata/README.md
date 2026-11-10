# Test databases

Real rpm databases, one per storage format, each written by the `rpm` of a
distribution. `generate.sh` rebuilds them; it needs podman or docker and network
access.

| File | Format | Written by | Packages |
| --- | --- | --- | --- |
| `Packages.bdb` | BerkeleyDB hash (`Packages`) | rpm 4.14.3, Rocky Linux 8 | setup, basesystem, ncurses-base, gpg-pubkey |
| `Packages.ndb` | ndb (`Packages.db`) | rpm 4.20.1, openSUSE Tumbleweed | filesystem, system-user-root, aaa_base |
| `rpmdb.sqlite` | SQLite (`rpmdb.sqlite`) | rpm 6.1.0, Fedora 45 | setup, ncurses-base, which |

The files carry no path in their name that rpm would recognise; the tests copy
them to the place a root would hold them. `Packages.bdb` is byte for byte what
rpm 4.14 wrote, `Packages.ndb` what rpm 4.20 wrote on a system whose default
`%_db_backend` is `ndb`, and `rpmdb.sqlite` what rpm 6 wrote, in WAL mode like
a live database.

## How they are made

For each format the script starts the distribution's container, downloads the
packages (`dnf download` or `zypper download`) and registers them in an empty
root with

```sh
rpm --root /tmp/r --define '_db_backend <backend>' --initdb
rpm --root /tmp/r --define '_db_backend <backend>' -i --justdb --nodeps --noscripts \
    --nosignature --nodigest /tmp/rpms/*.rpm
```

so that the database holds the headers of real packages, with their file
lists, while nothing is unpacked. On Rocky 8 the distribution's signing key is
imported as well (`rpm --import`), which adds a `gpg-pubkey` record: a header
without an architecture.

## Expected output

`<fixture>.expected` is what the same `rpm` prints for the finished database,
captured at generation time with `rpm --root /tmp/r -qa --qf …`. Each line is
tab separated and starts with a record type:

| Record | Fields |
| --- | --- |
| `P` | name, epoch, version, release, arch (`(none)` for none), install time |
| `D` | package, provide name, flags, version |
| `Q` | package, require name, flags, version |
| `F` | package, path, mode, size, digest, link target, user, group, mtime, flags |

`rpmdb_test.go` decodes each fixture and compares every one of those fields.
`<fixture>.info` holds the rpm version and backend.
