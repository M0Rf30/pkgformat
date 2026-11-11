#!/bin/sh
# Regenerates the fixtures of this directory with createrepo_c and
# modifyrepo_c (>= 1.2): the repository `base` and, for each operation the
# package's record helpers imitate, the repository after modifyrepo_c ran it.
# Only repodata/repomd.xml and the files modifyrepo_c added are kept in the
# result directories; the timestamps of the records are those of the run.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The inputs: an AppStream catalog (plain, and gzip compressed as a
# distribution ships it), an icon tarball and a prestodelta.xml.
[ -f inputs/appstream-icons.tar ] || {
    mkdir "$work/icons"
    printf 'PNG' >"$work/icons/org.example.Demo.png"
    tar --sort=name --mtime=@1700000000 --owner=0 --group=0 --numeric-owner -cf inputs/appstream-icons.tar -C "$work" icons
}
gzip -9n -c inputs/appstream.xml >inputs/appstream.xml.gz

mkdir "$work/pkgs"
cp ../createrepo/Packages/edge-min-0-0.noarch.rpm ../createrepo/Packages/edge-nodeps-1.0~rc1_git2-1.noarch.rpm "$work/pkgs/"
find "$work/pkgs" -name '*.rpm' -exec touch -d @1700000000 {} +
createrepo_c -q --simple-md-filenames --general-compress-type=gz --revision 1700000000 \
    --set-timestamp-to-revision "$work/pkgs"

rm -rf base add-store add-store-simple add-gz add-zst add-xz add-from-gz add-icons add-prestodelta all replace remove
mkdir base
cp -r "$work/pkgs/repodata" base/repodata

# variant <name> <modifyrepo_c arguments...>: base with one more operation.
variant() {
    name=$1
    shift
    rm -rf "$work/v"
    cp -r base "$work/v"
    modifyrepo_c "$@" "$work/v/repodata" >/dev/null
    keep "$name"
}

# keep <name>: the changed files of $work/v as the directory <name>.
keep() {
    mkdir -p "$1/repodata"
    for f in "$work/v/repodata"/*; do
        b=$(basename "$f")
        if [ "$b" = repomd.xml ] || [ ! -e "base/repodata/$b" ]; then
            cp "$f" "$1/repodata/$b"
        fi
    done
}

variant add-store --no-compress inputs/appstream.xml
variant add-store-simple --no-compress --simple-md-filenames inputs/appstream.xml
variant add-gz --compress-type gz inputs/appstream.xml
variant add-zst --compress-type zstd inputs/appstream.xml
variant add-xz --compress-type xz inputs/appstream.xml
variant add-from-gz --compress-type gz inputs/appstream.xml.gz
variant add-icons --compress-type gz --mdtype appstream-icons inputs/appstream-icons.tar
variant add-prestodelta --compress-type gz inputs/prestodelta.xml

# all: the three records in a row; replace and remove work on it.
rm -rf "$work/v"
cp -r base "$work/v"
modifyrepo_c --compress-type gz inputs/appstream.xml "$work/v/repodata" >/dev/null
modifyrepo_c --compress-type gz --mdtype appstream-icons inputs/appstream-icons.tar "$work/v/repodata" >/dev/null
modifyrepo_c --compress-type gz inputs/prestodelta.xml "$work/v/repodata" >/dev/null
keep all
cp -r "$work/v" "$work/all"

modifyrepo_c --compress-type gz --mdtype appstream inputs/appstream-replacement.xml "$work/v/repodata" >/dev/null
keep replace

rm -rf "$work/v"
cp -r "$work/all" "$work/v"
modifyrepo_c --remove appstream "$work/v/repodata" >/dev/null
keep remove
