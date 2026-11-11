#!/bin/sh
# Regenerates repomd.xml: createrepo_c with tags, databases and zchunk on one
# small package, timestamps pinned to the revision.
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp ../../../testdata/hello.rpm "$work/"
createrepo_c -q --zck --database --simple-md-filenames \
    --distro "cpe:/o:fedoraproject:fedora:17,Fedora 17" --content c1 --repo r1 \
    --revision 1700000000 --set-timestamp-to-revision --general-compress-type=zstd "$work"
cp "$work/repodata/repomd.xml" repomd.xml
