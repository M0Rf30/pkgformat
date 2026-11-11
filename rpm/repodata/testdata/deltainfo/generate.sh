#!/bin/sh
# Regenerates the fixtures of this directory:
#
#   old/     older versions of the test packages (not part of the repository)
#   repo/    a repository made by `createrepo_c --deltas`: the newest rpms, the
#            delta rpms in drpms/ and repodata/ with prestodelta.xml.gz
#   prestodelta.xml   the uncompressed repo/repodata/prestodelta.xml.gz
#
# The rpms are built in a container ($PODMAN_IMAGE, by default
# localhost/s3tools:latest, a Fedora image with rpmbuild): the
# deltarpm library only accepts packages that carry the legacy header tags,
# which the rpm of the build host (6.0.1) no longer writes. createrepo_c runs
# on the host and needs libdrpm support (`createrepo_c --version` lists
# DeltaRPM). The packages are built reproducibly (SOURCE_DATE_EPOCH), so a
# rerun with the same tools yields the same files.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
image=${PODMAN_IMAGE:-localhost/s3tools:latest}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat >"$work/build.sh" <<'EOF'
set -eu
work=$1
export SOURCE_DATE_EPOCH=1700000000
top="$work/rpmbuild"
mkdir -p "$top/SPECS" "$top/SOURCES" "$work/old" "$work/repo"

# payload: 250 chained sha256 digests, 16000 bytes that hardly compress; the
# newer versions change a few bytes, which is what a delta rpm encodes.
payload() { # <patch-count>
    : >"$top/SOURCES/payload.bin"
    h=seed
    n=0
    while [ "$n" -lt 250 ]; do
        h=$(printf %s "$h" | sha256sum | cut -d" " -f1)
        printf %s "$h" >>"$top/SOURCES/payload.bin"
        n=$((n + 1))
    done
    i=0
    while [ "$i" -lt "$1" ]; do
        printf 'patch %d of the payload\n' "$i" |
            dd of="$top/SOURCES/payload.bin" bs=1 seek=$((4000 + i * 1000)) conv=notrunc 2>/dev/null
        i=$((i + 1))
    done
}

build() { # <name> <epoch|-> <version> <release> <arch> <patches> <destdir>
    payload "$6"
    {
        echo "Name: $1"
        [ "$2" = - ] || echo "Epoch: $2"
        echo "Version: $3"
        echo "Release: $4"
        echo "Summary: delta rpm test package $1"
        echo "License: MIT"
        echo "BuildArch: $5"
        echo "Source0: payload.bin"
        echo "%description"
        echo "Test package of the deltainfo fixtures."
        echo "%install"
        echo "mkdir -p %{buildroot}/usr/share/$1"
        echo "cp %{SOURCE0} %{buildroot}/usr/share/$1/payload.bin"
        echo "%files"
        echo "/usr/share/$1/payload.bin"
    } >"$top/SPECS/$1.spec"
    rpmbuild -bb --quiet --define "_topdir $top" --define 'debug_package %{nil}' \
        --define 'use_source_date_epoch_as_buildtime 1' \
        --define 'build_mtime_policy clamp_to_source_date_epoch' \
        --define '_buildhost localhost' "$top/SPECS/$1.spec"
    cp "$top"/RPMS/*/"$1-$3-$4".*.rpm "$7/"
}

build delta-demo 1 1.0 1 noarch 0 "$work/old"
build delta-demo 1 1.1 1 noarch 1 "$work/old"
build delta-demo 1 1.2 1 noarch 2 "$work/repo"
build delta-lib - 2.3 4.el9 x86_64 0 "$work/old"
build delta-lib - 2.4 1.el9 x86_64 3 "$work/repo"
build delta-solo - 1.0 1 noarch 0 "$work/repo"
EOF

podman run --rm -v "$work:$work:Z" "$image" sh "$work/build.sh" "$work"

find "$work/repo" "$work/old" -name '*.rpm' -exec touch -d @1700000000 {} +
createrepo_c -q --deltas --num-deltas 2 --oldpackagedirs "$work/old" \
    --simple-md-filenames --general-compress-type=gz \
    --revision 1700000000 --set-timestamp-to-revision "$work/repo"

rm -rf "$here/old" "$here/repo"
cp -r "$work/old" "$here/old"
cp -r "$work/repo" "$here/repo"
zcat "$here/repo/repodata/prestodelta.xml.gz" >"$here/prestodelta.xml"
