# SQLite database fixtures

Reference output of `createrepo_c --database` (schema version 10) for the
packages of `../createrepo/Packages` (see that directory's README for the
corpus). `generate.sh` regenerates everything here.

| Tool         | Version |
|--------------|---------|
| createrepo_c | 1.2.6   |
| sqlite3      | 3.54.1  |

Command, file times fixed to 1700000000:

    createrepo_c -q --database --simple-md-filenames --general-compress-type=gz \
        --revision 1700000000 --set-timestamp-to-revision <dir with the packages>

* `repo/` is the `repodata/` directory of that run: `primary`, `filelists` and
  `other` as `.xml.gz` and `.sqlite.gz`, and `repomd.xml`. The `checksum` that
  each database records in `db_info` is the sha256 of the matching `.xml.gz`
  here.
* `schema/<name>.schema` is `sqlite3 <name>.sqlite .schema` of each database.
  The tests compare the statements stored in `sqlite_master` with these files,
  character for character.

The tests also run, when the tools are installed:

* `sqliterepo_c` (createrepo_c 1.2.6) on the XML this package writes, and on a
  repository that already carries its databases (it finds them through
  `repomd.xml`, refuses to overwrite them, and `--force` produces databases with
  the same content). `sqliterepo_c` does not write `database_version` into
  `repomd.xml`; `createrepo_c --database` does, and so does this package.
* `sqlite3` `PRAGMA integrity_check` on the written files.
* dnf5 5.4.7 in `localhost/s3tools:latest` (skipped when podman or the image is
  absent).

## What matches, and what does not

The tables, columns, indexes, trigger and `db_info` row are identical to
createrepo_c's, and so is the content of every table, value by value and with
the SQLite type of each value (`TEXT` epochs, `NULL` for an absent `url`,
`description` or `packager`, `''` for an absent vendor or source rpm,
`'TRUE'`/`'FALSE'` in `requires.pre`, change-log dates made distinct as in
`other.xml`).

The only difference is the order of the rows of the `filelist` table within a
package: createrepo_c writes the directories in the iteration order of a hash
table, this package in the order a directory first appears in the package. The
tests sort rows before comparing them. The rows of every other table are in
the same order. A package value cannot tell an absent string from an
empty one, so an empty summary, description, license, group, build host, url
or packager is stored as `NULL`; a package whose header carries an empty
string for one of these would differ from createrepo_c's `''`.

## dnf

dnf does not read the databases. With a repository that lists the XML
documents and the databases, libdnf5 5.4.7 (Fedora), dnf 4.7.0 (Rocky Linux 8)
and dnf 4.14.0 (Rocky Linux 9) request `repomd.xml`, `primary.xml.gz`, and on
demand `filelists.xml.gz` and `other.xml.gz`, and never a `*.sqlite.*` file; a
repository whose `repomd.xml` lists only the databases is rejected by dnf5
(`"primary" data not present or in unsupported format`). The databases serve
older yum and createrepo_c's own tools; the match with createrepo_c's
databases above is what they are checked against.
