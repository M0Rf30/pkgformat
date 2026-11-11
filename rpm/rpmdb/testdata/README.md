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

## The rich fixture

`rich.sqlite` (rpm 6.0.2, Fedora 43, SQLite, WAL mode) is made by `rich/build.sh`
inside the container, not by the generic recipe above. It holds what the query
and script tests need and the other fixtures lack:

- `qdb-base` 1:1.2.3-1.q1 (noarch): an epoch, every scriptlet (pretrans, pre,
  post, preun, postun, posttrans, preuntrans, postuntrans, verify) with shell,
  Lua and program-only forms and the `-e`/`-q` flags, the four kinds of
  trigger, file triggers and transaction file triggers (with priorities),
  versioned and unversioned provides, requires, recommends, suggests,
  supplements, enhances, conflicts and obsoletes, rich dependencies
  (`(qdb-opt if qdb-x)`, `(qdb-alt >= 2.0 or qdb-other)`), and files of every
  kind: config, ghost, doc, symlink, directories;
- `qdb-lib` in 1.4-1.q1 and 1.5-2.q1 for x86_64 and 1.5-2.q1 for i686, to have
  several versions and architectures of one name;
- `qdb-old` 0.4-1.q1 (conflicts with and is obsoleted by `qdb-base`) and
  `qdb-x` 3.1-1.q1 (versioned requirements on the others);
- the real Fedora packages `bash`, `fontconfig`, `info` and `shared-mime-info`,
  whose scriptlets and transaction file triggers are real-world ones.

The `qdb-*` packages are built by `rpmbuild` from the specs in `rich/` and, like
the packages of the other fixtures, only registered (`rpm -i --justdb --nodeps
--noscripts`): nothing is unpacked.

| File | What |
| --- | --- |
| `rich.sqlite` | the database, as rpm left it |
| `rich.sqlite.expected` | the records of the other fixtures (keys are `%{NEVRA}`), plus `C`, `O`, `W`, `S`, `U`, `E` (conflicts, obsoletes, recommends, suggests, supplements, enhances: package, name, flags, version), `N` (package, path, file state: a file that another package replaced has state 1), `X` (package and the nine scriptlet flag values, in the order pretrans, pre, post, preun, postun, posttrans, preuntrans, postuntrans, verify) and `T` (package, kind of trigger or file trigger, script flags, file trigger priority) |
| `rich.sqlite.scripts` | `rpm -q --scripts --triggers --filetriggers` of each package, under a `### NEVRA` line |
| `rich.sqlite.queries` | `kind`, argument and the sorted NEVRAs rpm answers, tab separated, for the queries of `rich/queries.txt` |
| `rich.sqlite.info` | rpm version and backend |

The answers of `rich.sqlite.queries` are those of `rpm -q <label>`, `rpm -qf`,
`rpm -q --whatprovides|--whatrequires|--whatrecommends|--whatsuggests|
--whatsupplements|--whatenhances|--whatconflicts|--whatobsoletes`. The
`v:<kind>` lines test a versioned capability (`name op [epoch:]version[-release]`)
against the dependencies of that kind of every package with rpm's own
comparison, through rpm's Python bindings (`rich/queries.py`); the command line
cannot express them. Queries that name a rich dependency are in the `what…`
lines only, because the Python bindings do not look inside rich dependencies.
