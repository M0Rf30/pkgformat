#!/bin/sh
# Regenerates the reference SQLite databases: createrepo_c --database on the
# packages of ../createrepo/Packages, file times pinned to 1700000000. Keeps the
# repodata of that run (xml, sqlite, repomd.xml) in repo/ and the schema of each
# database, as `sqlite3 .schema` prints it, in schema/.
# Usage: ./generate.sh   (needs createrepo_c >= 1.2 and sqlite3)
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/Packages"
cp ../createrepo/Packages/*.rpm "$work/Packages/"
find "$work/Packages" -name '*.rpm' -exec touch -d @1700000000 {} +
createrepo_c -q --database --simple-md-filenames --general-compress-type=gz \
    --revision 1700000000 --set-timestamp-to-revision "$work"
rm -rf repo schema
mkdir repo schema
cp "$work"/repodata/* repo/
for f in primary filelists other; do
    zcat "repo/$f.sqlite.gz" > "$work/$f.sqlite"
    sqlite3 "$work/$f.sqlite" .schema > "schema/$f.schema"
done
