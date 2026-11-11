#!/bin/sh
# Regenerates the golden createrepo_c output of the corpus in Packages/.
# The packages are real Fedora 45 rpms and rpmbuild 6.0.1 builds with their
# payload removed (strip.go): all that primary, filelists and other consume
# is in the headers. Usage: ./gen.sh  (needs createrepo_c >= 1.2).
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/Packages"
cp Packages/*.rpm "$work/Packages/"
find "$work/Packages" -name '*.rpm' -exec touch -d @1700000000 {} +
createrepo_c -q --simple-md-filenames --general-compress-type=gz --filelists-ext \
    --revision 1700000000 --set-timestamp-to-revision "$work"
mkdir -p golden
for f in primary filelists other filelists-ext; do
    zcat "$work/repodata/$f.xml.gz" | gzip -9n > "golden/$f.xml.gz"
done
